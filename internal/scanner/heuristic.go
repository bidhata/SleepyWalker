package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"sleepywalker/internal/config"
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
func probeEntryPoint(client *http.Client, cfg *config.Config, ep EntryPoint, rl *utils.RateLimiter) HeuristicResult {
	for _, payload := range testPayloads {
		if !rl.Wait() {
			log.Printf("[HEURISTIC] Request budget exhausted, stopping probes for %s", ep.URL)
			break
		}
		body, statusCode, err := sendProbeRequestWithStatus(client, cfg, ep, payload)
		rl.RecordResponse(statusCode)
		if err != nil {
			continue
		}
		matched := matchErrorSignatures(body)
		if len(matched) > 0 {
			return HeuristicResult{
				Entry:         ep,
				Suspicious:    true,
				MatchedErrors: matched,
				TestPayload:   payload,
			}
		}
	}
	return HeuristicResult{Entry: ep, Suspicious: false}
}

// sendProbeRequestWithStatus dispatches the request and returns body, HTTP status, and error.
func sendProbeRequestWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	switch ep.InjectionLoc {
	case "header":
		body, code, err := sendHeaderProbeWithStatus(client, cfg, ep, payload)
		return body, code, err
	case "json":
		body, code, err := sendJSONProbeWithStatus(client, cfg, ep, payload)
		return body, code, err
	default:
		switch ep.Method {
		case "POST":
			body, code, err := sendPOSTProbeWithStatus(client, cfg, ep, payload)
			return body, code, err
		default:
			body, code, err := sendGETProbeWithStatus(client, cfg, ep, payload)
			return body, code, err
		}
	}
}

// sendProbeRequest is kept for compatibility — delegates to the status variant.
func sendProbeRequest(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, error) {
	body, _, err := sendProbeRequestWithStatus(client, cfg, ep, payload)
	return body, err
}

// sendGETProbeWithStatus appends the payload to each query parameter, returns body + status.
func sendGETProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return "", 0, err
	}
	q := u.Query()
	for key := range ep.Params {
		q.Set(key, payload)
	}
	if len(ep.Params) == 0 {
		q.Set("id", payload)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "SleepyWalker/1.0")
	cfg.ApplyHeaders(req)
	return doRequestWithStatus(client, req)
}

func sendGETProbe(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, error) {
	body, _, err := sendGETProbeWithStatus(client, cfg, ep, payload)
	return body, err
}

// sendPOSTProbeWithStatus sends a form-encoded POST, returns body + status.
func sendPOSTProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	form := url.Values{}
	for key := range ep.Params {
		form.Set(key, payload)
	}
	if len(ep.Params) == 0 {
		form.Set("id", payload)
	}
	req, err := http.NewRequest("POST", ep.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "SleepyWalker/1.0")
	cfg.ApplyHeaders(req)
	return doRequestWithStatus(client, req)
}

func sendPOSTProbe(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, error) {
	body, _, err := sendPOSTProbeWithStatus(client, cfg, ep, payload)
	return body, err
}

// sendHeaderProbeWithStatus injects payload into HTTP headers, returns body + status.
func sendHeaderProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
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

func sendHeaderProbe(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, error) {
	body, _, err := sendHeaderProbeWithStatus(client, cfg, ep, payload)
	return body, err
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

func sendJSONProbe(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, error) {
	body, _, err := sendJSONProbeWithStatus(client, cfg, ep, payload)
	return body, err
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
