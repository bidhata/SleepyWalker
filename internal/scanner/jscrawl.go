package scanner

import (
	"context"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
)

// JSCrawl uses a headless Chrome browser to render the page and extract
// entry points from JS-rendered content (SPAs, React/Angular apps, etc.).
// The depth parameter is reserved for future multi-page JS crawling.
// Returns additional entry points not visible in static HTML.
func JSCrawl(seedURL string, _ int) ([]EntryPoint, error) {
	log.Printf("[JS-CRAWL] Rendering %s with headless browser…", seedURL)

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	ctx, cancel := context.WithTimeout(browserCtx, 30*time.Second)
	defer cancel()

	var renderedHTML string
	var currentURL string

	err := chromedp.Run(ctx,
		chromedp.Navigate(seedURL),
		chromedp.WaitReady("body"),
		chromedp.Sleep(2*time.Second), // let JS frameworks render
		chromedp.OuterHTML("html", &renderedHTML),
		chromedp.Location(&currentURL),
	)
	if err != nil {
		return nil, err
	}

	log.Printf("[JS-CRAWL] Rendered page (%d bytes), extracting endpoints…", len(renderedHTML))

	// Parse the rendered HTML with goquery to extract entry points
	eps := parseRenderedHTML(renderedHTML, currentURL)

	// Also extract XHR/fetch URLs intercepted from inline scripts
	apiEPs := extractAPIEndpointsFromRendered(renderedHTML, currentURL)
	eps = append(eps, apiEPs...)

	eps = deduplicateEPs(eps)
	log.Printf("[JS-CRAWL] Found %d entry point(s) from JS-rendered content", len(eps))
	return eps, nil
}

// parseRenderedHTML extracts entry points from fully rendered HTML (post-JS execution).
func parseRenderedHTML(html, pageURL string) []EntryPoint {
	doc, err := goqueryFromString(html)
	if err != nil {
		return nil
	}
	return extractEntryPoints(doc, pageURL)
}

// extractAPIEndpointsFromRendered scans rendered HTML for dynamic API patterns
// that JS frameworks commonly use (data attributes, ng-href, vue router links, etc.).
func extractAPIEndpointsFromRendered(html, pageURL string) []EntryPoint {
	var eps []EntryPoint
	base, _ := url.Parse(pageURL)

	doc, err := goqueryFromString(html)
	if err != nil {
		return nil
	}

	// Extract data-url, data-action, data-api attributes
	dataAttrs := []string{"data-url", "data-action", "data-api", "data-endpoint", "data-href"}
	for _, attr := range dataAttrs {
		doc.Find("[" + attr + "]").Each(func(i int, s *goquery.Selection) {
			val, exists := s.Attr(attr)
			if !exists || val == "" {
				return
			}
			parsed, err := url.Parse(val)
			if err != nil {
				return
			}
			full := base.ResolveReference(parsed)
			if full.Scheme != "http" && full.Scheme != "https" {
				return
			}

			method := "GET"
			if m, ok := s.Attr("data-method"); ok {
				method = strings.ToUpper(m)
			}

			params := map[string]string{}
			if full.RawQuery != "" {
				for key, vals := range full.Query() {
					v := ""
					if len(vals) > 0 {
						v = vals[0]
					}
					params[key] = v
				}
			}
			if len(params) == 0 {
				params["id"] = ""
			}

			loc := "query"
			if method == "POST" {
				loc = "json"
			}

			eps = append(eps, EntryPoint{
				Method:       method,
				URL:          full.String(),
				Params:       params,
				InjectionLoc: loc,
			})
		})
	}

	// Extract Angular/Vue router links (ng-href, :href, v-bind:href, router-link to)
	routerAttrs := []string{"ng-href", "routerlink", "to"}
	for _, attr := range routerAttrs {
		doc.Find("[" + attr + "]").Each(func(i int, s *goquery.Selection) {
			val, exists := s.Attr(attr)
			if !exists || val == "" || strings.HasPrefix(val, "#") {
				return
			}
			parsed, err := url.Parse(val)
			if err != nil {
				return
			}
			full := base.ResolveReference(parsed)
			if full.RawQuery != "" {
				qMap := map[string]string{}
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
	}

	return eps
}

// goqueryFromString creates a goquery document from a raw HTML string.
func goqueryFromString(html string) (*goquery.Document, error) {
	return goquery.NewDocumentFromReader(strings.NewReader(html))
}
