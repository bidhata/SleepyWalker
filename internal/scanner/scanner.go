package scanner

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"sleepywalker/internal/config"
)

// EntryPoint represents a single injectable endpoint.
type EntryPoint struct {
	Method       string
	URL          string
	Params       map[string]string
	InjectionLoc string // "query", "body", "header", "json"
}

// CrawlAndDiscover performs recursive crawling from the seed URL up to
// cfg.CrawlDepth levels, then extracts entry points from every discovered page.
func CrawlAndDiscover(cfg *config.Config, seedURL string) ([]EntryPoint, error) {
	depth := cfg.CrawlDepth
	if depth < 0 {
		depth = 0
	}

	client := cfg.BuildHTTPClient(15 * time.Second)

	visited := &sync.Map{}
	var allEPs []EntryPoint
	var mu sync.Mutex

	seedParsed, err := url.Parse(seedURL)
	if err != nil {
		return nil, fmt.Errorf("invalid seed URL: %w", err)
	}
	seedHost := seedParsed.Host

	var crawl func(u string, level int)
	crawl = func(u string, level int) {
		// Normalise
		u = strings.TrimRight(u, "#")
		if _, loaded := visited.LoadOrStore(u, true); loaded {
			return
		}

		log.Printf("[CRAWL] depth=%d  %s", level, u)

		// Rate limiting
		if cfg.RateDelay > 0 {
			time.Sleep(cfg.RateDelay)
		}

		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0 (Security Scanner)")
		cfg.ApplyHeaders(req)

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		// Only parse HTML — drain and discard non-HTML bodies so TCP connections
		// are returned to the pool (fix #11: missing body drain before Close).
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") && ct != "" {
			io.Copy(io.Discard, resp.Body)
			return
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		if err != nil {
			return
		}
		bodyStr := string(bodyBytes)

		doc, err := goquery.NewDocumentFromReader(strings.NewReader(bodyStr))
		if err != nil {
			return
		}

		// Extract entry points from this page
		eps := extractEntryPoints(doc, u)

		// Also create header injection entry points for this page
		headerEPs := buildHeaderEntryPoints(u)

		// Also detect JSON/API endpoints from page
		jsonEPs := detectJSONEndpoints(doc, u)

		mu.Lock()
		allEPs = append(allEPs, eps...)
		allEPs = append(allEPs, headerEPs...)
		allEPs = append(allEPs, jsonEPs...)
		mu.Unlock()

		// Follow same-host links: depth=0 means unlimited, otherwise stop at depth.
		if depth == 0 || level < depth {
			doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
				href, _ := s.Attr("href")
				child, err := url.Parse(href)
				if err != nil {
					return
				}
				base, _ := url.Parse(u)
				full := base.ResolveReference(child)

				// Stay on the same host
				if full.Host != seedHost {
					return
				}
				// Only follow http/https
				if full.Scheme != "http" && full.Scheme != "https" {
					return
				}
				// Strip fragment
				full.Fragment = ""
				crawl(full.String(), level+1)
			})
		}
	}

	crawl(seedURL, 0)

	// ── JS-rendered crawl (optional) ─────────────────────────────────
	if cfg.JSRender {
		jsEPs, err := JSCrawl(seedURL, depth)
		if err != nil {
			log.Printf("[WARN] JS crawl failed: %v", err)
		} else {
			mu.Lock()
			allEPs = append(allEPs, jsEPs...)
			mu.Unlock()
		}
	}

	// ── Swagger/OpenAPI discovery (optional) ─────────────────────────
	if cfg.SwaggerURL != "" {
		swaggerEPs, err := SwaggerDiscover(cfg.SwaggerURL, seedURL)
		if err != nil {
			log.Printf("[WARN] Swagger discovery failed: %v", err)
		} else {
			mu.Lock()
			allEPs = append(allEPs, swaggerEPs...)
			mu.Unlock()
		}
	}

	// Deduplicate
	allEPs = deduplicateEPs(allEPs)
	return allEPs, nil
}

// extractEntryPoints pulls forms and query-parameterised links from a parsed page.
func extractEntryPoints(doc *goquery.Document, pageURL string) []EntryPoint {
	var eps []EntryPoint
	base, _ := url.Parse(pageURL)

	// Forms
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		method, _ := s.Attr("method")
		if method == "" {
			method = "GET"
		}
		action, exists := s.Attr("action")
		if !exists || strings.TrimSpace(action) == "" {
			action = pageURL
		}
		actionURL, err := url.Parse(action)
		if err != nil {
			return
		}
		fullURL := base.ResolveReference(actionURL).String()

		params := make(map[string]string)
		s.Find("input[name], textarea[name], select[name]").Each(func(j int, inp *goquery.Selection) {
			name, _ := inp.Attr("name")
			val, _ := inp.Attr("value")
			params[name] = val
		})

		loc := "query"
		if strings.EqualFold(method, "POST") {
			loc = "body"
		}
		eps = append(eps, EntryPoint{
			Method:       strings.ToUpper(method),
			URL:          fullURL,
			Params:       params,
			InjectionLoc: loc,
		})
	})

	// Links with query parameters
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		u, err := url.Parse(href)
		if err != nil {
			return
		}
		full := base.ResolveReference(u)
		if full.RawQuery != "" {
			qMap := make(map[string]string)
			for key, vals := range full.Query() {
				v := ""
				if len(vals) > 0 {
					v = vals[0]
				}
				qMap[key] = v
			}
			eps = append(eps, EntryPoint{
				Method:       "GET",
				URL:          full.String(),
				Params:       qMap,
				InjectionLoc: "query",
			})
		}
	})

	return eps
}

// buildHeaderEntryPoints creates synthetic entry points for header-based injection.
func buildHeaderEntryPoints(pageURL string) []EntryPoint {
	headers := []string{"User-Agent", "Referer", "X-Forwarded-For", "Cookie"}
	var eps []EntryPoint
	for _, h := range headers {
		eps = append(eps, EntryPoint{
			Method:       "GET",
			URL:          pageURL,
			Params:       map[string]string{h: ""},
			InjectionLoc: "header",
		})
	}
	return eps
}

// detectJSONEndpoints looks for AJAX/fetch calls in inline scripts
// and creates JSON-body entry points for them.
func detectJSONEndpoints(doc *goquery.Document, pageURL string) []EntryPoint {
	var eps []EntryPoint
	base, _ := url.Parse(pageURL)

	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		// Simple pattern matching for fetch/axios/XMLHttpRequest URLs
		patterns := []string{
			`fetch("`, `fetch('`,
			`axios.post("`, `axios.post('`,
			`axios.get("`, `axios.get('`,
			`.open("POST","`, `.open("GET","`,
			`$.ajax({url:"`, `$.ajax({url:'`,
			`$.post("`, `$.post('`,
			`$.get("`, `$.get('`,
		}
		for _, pat := range patterns {
			idx := strings.Index(text, pat)
			if idx < 0 {
				continue
			}
			rest := text[idx+len(pat):]
			// Extract URL until closing quote
			endChar := byte('"')
			if strings.HasSuffix(pat, "'") {
				endChar = '\''
			}
			endIdx := strings.IndexByte(rest, endChar)
			if endIdx <= 0 || endIdx > 500 {
				continue
			}
			apiURL := rest[:endIdx]
			parsed, err := url.Parse(apiURL)
			if err != nil {
				continue
			}
			full := base.ResolveReference(parsed)

			method := "POST"
			if strings.Contains(pat, "get") || strings.Contains(pat, "GET") {
				method = "GET"
			}

			eps = append(eps, EntryPoint{
				Method:       method,
				URL:          full.String(),
				Params:       map[string]string{"id": "", "query": "", "search": ""},
				InjectionLoc: "json",
			})
		}
	})
	return eps
}

// deduplicateEPs removes duplicate entry points by Method+URL+InjectionLoc.
func deduplicateEPs(eps []EntryPoint) []EntryPoint {
	seen := make(map[string]bool)
	var unique []EntryPoint
	for _, ep := range eps {
		key := fmt.Sprintf("%s|%s|%s", ep.Method, ep.URL, ep.InjectionLoc)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, ep)
		}
	}
	return unique
}

// ── Legacy wrapper (backwards compat) ─────────────────────────────────

// DiscoverEntryPoints is a simple single-page discovery (no crawling).
// Prefer CrawlAndDiscover for full functionality.
func DiscoverEntryPoints(target string) ([]EntryPoint, error) {
	cfg := &config.Config{CrawlDepth: 0}
	return CrawlAndDiscover(cfg, target)
}
