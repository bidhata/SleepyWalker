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
	InjectionLoc string // "query", "body", "multipart", "header", "json", "path"
	PathSegments []string // ordered list of path segments that are numeric/injectable
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
			errMsg := err.Error()
			if strings.Contains(errMsg, "x509") || strings.Contains(errMsg, "tls") {
				log.Printf("[CRAWL] ✗ TLS error for %s: %v", u, err)
				log.Printf("[CRAWL]   Hint: re-run with -insecure to skip certificate verification")
			} else {
				log.Printf("[CRAWL] ✗ Failed to fetch %s: %v", u, err)
			}
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

	// ── Hidden resource discovery (robots.txt, sitemap.xml) ───────────
	robotsEPs := discoverFromRobots(client, seedParsed, visited, crawl, depth)
	mu.Lock()
	allEPs = append(allEPs, robotsEPs...)
	mu.Unlock()

	sitemapEPs := discoverFromSitemap(client, seedParsed, visited, crawl, depth)
	mu.Lock()
	allEPs = append(allEPs, sitemapEPs...)
	mu.Unlock()

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

	// ── Parameter fuzzing for pages with no listed params ────────────
	fuzzEPs := parameterFuzz(client, cfg, seedParsed, visited)
	mu.Lock()
	allEPs = append(allEPs, fuzzEPs...)
	mu.Unlock()

	// Deduplicate
	allEPs = deduplicateEPs(allEPs)

	// Filter to same-host entry points only. The crawler restricts link-following
	// to seedHost, but extractEntryPoints also creates EPs from external links
	// (e.g. YouTube video links with query params) found on crawled pages.
	var sameHostEPs []EntryPoint
	for _, ep := range allEPs {
		epParsed, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		// Allow same host, or header EPs (which use the page URL, already same-host).
		if epParsed.Host == seedHost || ep.InjectionLoc == "header" {
			sameHostEPs = append(sameHostEPs, ep)
		}
	}
	return sameHostEPs, nil
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
		// Strip fragment: action="#" is a common pattern meaning "submit to current page".
		// url.ResolveReference keeps the fragment; HTTP clients strip it, but we
		// clean it here so probe URLs don't carry a trailing #.
		resolved := base.ResolveReference(actionURL)
		resolved.Fragment = ""
		fullURL := resolved.String()

		params := make(map[string]string)
		s.Find("input[name], textarea[name], select[name]").Each(func(j int, inp *goquery.Selection) {
			name, _ := inp.Attr("name")
			val, _ := inp.Attr("value")
			params[name] = val
		})

		// Detect enctype to distinguish form-encoded vs multipart.
		enctype, _ := s.Attr("enctype")
		loc := "query"
		if strings.EqualFold(method, "POST") {
			if strings.Contains(strings.ToLower(enctype), "multipart") {
				loc = "multipart"
			} else {
				loc = "body"
			}
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

		// Extract path segment entry points (e.g. /api/users/123/orders).
		if pathEP, ok := extractPathSegmentEP(full); ok {
			eps = append(eps, pathEP)
		}
	})

	return eps
}

// extractPathSegmentEP returns an EntryPoint for URLs that have numeric or
// UUID-like path segments that are likely injectable (e.g. /api/users/123).
func extractPathSegmentEP(u *url.URL) (EntryPoint, bool) {
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	var injectableSegments []string
	for _, seg := range segments {
		if isInjectableSegment(seg) {
			injectableSegments = append(injectableSegments, seg)
		}
	}
	if len(injectableSegments) == 0 {
		return EntryPoint{}, false
	}
	// Strip fragment, keep query as-is for the base URL.
	base := *u
	base.Fragment = ""
	return EntryPoint{
		Method:       "GET",
		URL:          base.String(),
		Params:       map[string]string{},
		InjectionLoc: "path",
		PathSegments: injectableSegments,
	}, true
}

// isInjectableSegment returns true for path segments that look like data values
// rather than route names: pure integers, UUIDs, or short alphanumeric IDs.
func isInjectableSegment(seg string) bool {
	if len(seg) == 0 {
		return false
	}
	// Pure integer: /users/123
	allDigits := true
	for _, c := range seg {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits && len(seg) <= 12 {
		return true
	}
	// UUID: /orders/550e8400-e29b-41d4-a716-446655440000
	if len(seg) == 36 && strings.Count(seg, "-") == 4 {
		return true
	}
	return false
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

// ═══════════════════════════════════════════════════════════════════════
// Hidden Resource Discovery
// ═══════════════════════════════════════════════════════════════════════

// discoverFromRobots fetches /robots.txt and extracts Disallow/Allow paths,
// feeding them back into the crawl queue to discover otherwise-hidden pages.
func discoverFromRobots(client *http.Client, seed *url.URL, visited *sync.Map, crawl func(string, int), depth int) []EntryPoint {
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", seed.Scheme, seed.Host)

	resp, err := client.Get(robotsURL)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}

	var eps []EntryPoint
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		var path string
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path = strings.TrimSpace(line[len("disallow:"):])
		} else if strings.HasPrefix(strings.ToLower(line), "allow:") {
			path = strings.TrimSpace(line[len("allow:"):])
		} else if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
			// Sitemap directives in robots.txt are handled by discoverFromSitemap.
			continue
		} else {
			continue
		}
		if path == "" || path == "/" || strings.Contains(path, "*") {
			continue
		}

		fullURL := fmt.Sprintf("%s://%s%s", seed.Scheme, seed.Host, path)
		// Feed into the existing crawl queue.
		crawl(fullURL, 1)
		log.Printf("[CRAWL] robots.txt → discovered %s", fullURL)

		// If the path has query params, create an entry point.
		parsed, err := url.Parse(fullURL)
		if err == nil && parsed.RawQuery != "" {
			qMap := make(map[string]string)
			for key, vals := range parsed.Query() {
				v := ""
				if len(vals) > 0 {
					v = vals[0]
				}
				qMap[key] = v
			}
			eps = append(eps, EntryPoint{
				Method:       "GET",
				URL:          fullURL,
				Params:       qMap,
				InjectionLoc: "query",
			})
		}
	}

	if len(eps) > 0 {
		log.Printf("[CRAWL] robots.txt: found %d entry point(s)", len(eps))
	}
	return eps
}

// discoverFromSitemap fetches /sitemap.xml and extracts <loc> URLs,
// feeding them into the crawl queue.
func discoverFromSitemap(client *http.Client, seed *url.URL, visited *sync.Map, crawl func(string, int), depth int) []EntryPoint {
	sitemapURL := fmt.Sprintf("%s://%s/sitemap.xml", seed.Scheme, seed.Host)

	resp, err := client.Get(sitemapURL)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	// Simple <loc>...</loc> extraction without a full XML parser.
	content := string(body)
	var eps []EntryPoint
	count := 0
	for {
		start := strings.Index(content, "<loc>")
		if start < 0 {
			break
		}
		content = content[start+5:]
		end := strings.Index(content, "</loc>")
		if end < 0 {
			break
		}
		locURL := strings.TrimSpace(content[:end])
		content = content[end+6:]

		if locURL == "" {
			continue
		}

		// Only follow same-host URLs.
		parsed, err := url.Parse(locURL)
		if err != nil || parsed.Host != seed.Host {
			continue
		}

		// Feed into the crawl queue.
		crawl(locURL, 1)
		count++

		// Create entry point if it has query params.
		if parsed.RawQuery != "" {
			qMap := make(map[string]string)
			for key, vals := range parsed.Query() {
				v := ""
				if len(vals) > 0 {
					v = vals[0]
				}
				qMap[key] = v
			}
			eps = append(eps, EntryPoint{
				Method:       "GET",
				URL:          locURL,
				Params:       qMap,
				InjectionLoc: "query",
			})
		}
	}

	if count > 0 {
		log.Printf("[CRAWL] sitemap.xml: discovered %d URL(s), %d entry point(s)", count, len(eps))
	}
	return eps
}

// ═══════════════════════════════════════════════════════════════════════
// Parameter Fuzzing
// ═══════════════════════════════════════════════════════════════════════

// parameterFuzz tries common parameter names against pages that were crawled
// but had no query parameters. If adding a parameter changes the response
// (status != 404, body length differs), it is treated as an implicit parameter.
func parameterFuzz(client *http.Client, cfg *config.Config, seed *url.URL, visited *sync.Map) []EntryPoint {
	commonParams := []string{"id", "page", "search", "q", "query", "user", "cat", "item", "file", "debug", "action", "type", "sort", "order", "limit", "offset", "uuid"}

	var eps []EntryPoint
	var fuzzedURLs []string

	visited.Range(func(key, value interface{}) bool {
		rawURL, ok := key.(string)
		if !ok {
			return true
		}
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host != seed.Host {
			return true
		}
		// Only fuzz pages with no existing query params.
		if parsed.RawQuery != "" {
			return true
		}
		// Only fuzz up to 20 pages to keep request count manageable.
		if len(fuzzedURLs) >= 20 {
			return false
		}
		fuzzedURLs = append(fuzzedURLs, rawURL)
		return true
	})

	for _, rawURL := range fuzzedURLs {
		// Get baseline response length.
		baseReq, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			continue
		}
		baseReq.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(baseReq)
		}
		baseResp, err := client.Do(baseReq)
		if err != nil {
			continue
		}
		baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 256*1024))
		baseResp.Body.Close()
		baseLen := len(baseBody)

		for _, param := range commonParams {
			testURL := rawURL + "?" + param + "=1"
			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "SleepyWalker/1.0")
			if cfg != nil {
				cfg.ApplyHeaders(req)
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			testBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			resp.Body.Close()

			// The param is "live" if the response is not 404 and its
			// length differs meaningfully from the baseline.
			if resp.StatusCode != 404 && resp.StatusCode < 500 {
				lenDiff := len(testBody) - baseLen
				if lenDiff < 0 {
					lenDiff = -lenDiff
				}
				if lenDiff > 10 || resp.StatusCode != baseResp.StatusCode {
					eps = append(eps, EntryPoint{
						Method:       "GET",
						URL:          rawURL,
						Params:       map[string]string{param: "1"},
						InjectionLoc: "query",
					})
					log.Printf("[FUZZ] Discovered implicit param: %s?%s=1 (Δlen=%d)", rawURL, param, lenDiff)
				}
			}
		}
	}

	if len(eps) > 0 {
		log.Printf("[FUZZ] Parameter fuzzing: discovered %d implicit parameter(s)", len(eps))
	}
	return eps
}
