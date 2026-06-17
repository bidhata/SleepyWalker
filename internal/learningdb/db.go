// Package learningdb provides a persistent learning database that accumulates
// knowledge across SleepyWalker scans. Every confirmed finding enriches the DB;
// every scan loads and benefits from prior knowledge.
//
// Storage layout (default: ~/.sleepywalker/learningdb.json):
//
//	{
//	  "version": 1,
//	  "error_signatures": [...],     ← new DB error patterns found in the wild
//	  "successful_payloads": [...],  ← payloads that confirmed SQLi, scored by hit rate
//	  "waf_fingerprints": [...],     ← WAF patterns discovered during scans
//	  "host_profiles": {...},        ← per-host: known injectable params, DB engine, WAF
//	  "false_positive_patterns": [...] ← URL/response patterns that were noise
//	}
package learningdb

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const dbVersion = 1

// DB is the in-memory learning database. All methods are safe for concurrent use.
type DB struct {
	mu sync.RWMutex
	path string
	data *dbData
}

type dbData struct {
	Version              int                     `json:"version"`
	ErrorSignatures      []LearnedSignature      `json:"error_signatures"`
	SuccessfulPayloads   []LearnedPayload        `json:"successful_payloads"`
	WAFFingerprints      []LearnedWAFFingerprint `json:"waf_fingerprints"`
	HostProfiles         map[string]*HostProfile `json:"host_profiles"`
	FalsePositivePatterns []FalsePositivePattern `json:"false_positive_patterns"`
	LastUpdated          string                  `json:"last_updated"`
}

// LearnedSignature is a DB error pattern discovered during a real scan.
type LearnedSignature struct {
	Engine    string `json:"engine"`
	Pattern   string `json:"pattern"`
	HitCount  int    `json:"hit_count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// LearnedPayload is a payload that has confirmed SQLi, with a success score.
type LearnedPayload struct {
	Payload      string  `json:"payload"`
	Context      string  `json:"context"`       // "query", "body", "header", "json", "path"
	DBEngine     string  `json:"db_engine"`
	HitCount     int     `json:"hit_count"`
	AttemptCount int     `json:"attempt_count"`
	SuccessRate  float64 `json:"success_rate"`  // hit_count / attempt_count
	FirstSeen    string  `json:"first_seen"`
	LastSeen     string  `json:"last_seen"`
}

// LearnedWAFFingerprint is a WAF signature pattern seen in the wild.
type LearnedWAFFingerprint struct {
	WAFName     string `json:"waf_name"`
	HeaderKey   string `json:"header_key,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`
	BodyPattern string `json:"body_pattern,omitempty"`
	HitCount    int    `json:"hit_count"`
	FirstSeen   string `json:"first_seen"`
}

// HostProfile records what was learned about a specific host across scans.
type HostProfile struct {
	Host             string            `json:"host"`
	DBEngine         string            `json:"db_engine,omitempty"`
	WAFName          string            `json:"waf_name,omitempty"`
	InjectableParams []InjectableParam `json:"injectable_params,omitempty"`
	CleanURLs        []string          `json:"clean_urls,omitempty"` // confirmed non-injectable
	LastSeen         string            `json:"last_seen"`
}

// InjectableParam records a confirmed injectable parameter on a host.
type InjectableParam struct {
	URL          string  `json:"url"`
	Param        string  `json:"param"`
	InjectionLoc string  `json:"injection_loc"`
	BestPayload  string  `json:"best_payload"`
	Confidence   float64 `json:"confidence"`
	Techniques   []string `json:"techniques"`
	ConfirmedAt  string  `json:"confirmed_at"`
}

// FalsePositivePattern records URL/response characteristics that triggered
// heuristics but were not actually injectable — used to skip faster next time.
type FalsePositivePattern struct {
	URLPattern      string `json:"url_pattern"`       // hostname or path prefix
	ParamName       string `json:"param_name"`
	FalsePositiveType string `json:"fp_type"`         // "boolean-diff", "timing", etc.
	Count           int    `json:"count"`
	LastSeen        string `json:"last_seen"`
}

var globalDB *DB

// DefaultPath returns the default path for the learning DB file.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			home = appData
		}
	}
	return filepath.Join(home, ".sleepywalker", "learningdb.json")
}

// Load reads the DB from disk (or creates a fresh one) and sets the global instance.
func Load(path string) *DB {
	if path == "" {
		path = DefaultPath()
	}

	db := &DB{path: path, data: &dbData{
		Version:      dbVersion,
		HostProfiles: make(map[string]*HostProfile),
	}}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[LEARNINGDB] Warning: could not read %s: %v — starting fresh", path, err)
		}
		globalDB = db
		return db
	}

	if err := json.Unmarshal(data, db.data); err != nil {
		log.Printf("[LEARNINGDB] Warning: could not parse %s: %v — starting fresh", path, err)
		db.data = &dbData{Version: dbVersion, HostProfiles: make(map[string]*HostProfile)}
	}
	if db.data.HostProfiles == nil {
		db.data.HostProfiles = make(map[string]*HostProfile)
	}

	total := len(db.data.ErrorSignatures) + len(db.data.SuccessfulPayloads)
	log.Printf("[LEARNINGDB] Loaded %d signatures, %d payloads, %d host profiles from %s",
		len(db.data.ErrorSignatures), len(db.data.SuccessfulPayloads),
		len(db.data.HostProfiles), path)

	// Warn if the DB is contributing zero learned items (first run).
	if total == 0 {
		log.Printf("[LEARNINGDB] Fresh database — will populate as scans complete")
	}

	globalDB = db
	return db
}

// Global returns the global DB instance (nil if Load was never called).
func Global() *DB {
	return globalDB
}

// Save writes the DB to disk atomically (write temp → rename).
func (db *DB) Save() error {
	db.mu.Lock()
	db.data.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	nSigs := len(db.data.ErrorSignatures)
	nPayloads := len(db.data.SuccessfulPayloads)
	nHosts := len(db.data.HostProfiles)
	data, err := json.MarshalIndent(db.data, "", "  ")
	db.mu.Unlock()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(db.path), 0750); err != nil {
		return err
	}

	tmp := db.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	// Fix: on Windows os.Rename fails if target exists. Remove first.
	if runtime.GOOS == "windows" {
		os.Remove(db.path)
	}
	if err := os.Rename(tmp, db.path); err != nil {
		os.Remove(tmp) // clean up temp file on rename failure
		return err
	}
	log.Printf("[LEARNINGDB] Saved to %s (%d signatures, %d payloads, %d hosts)",
		db.path, nSigs, nPayloads, nHosts)
	return nil
}

// ═══════════════════════════════════════════════════════════════════════
// Read methods — used during scanning to enrich detection
// ═══════════════════════════════════════════════════════════════════════

// ErrorSignatures returns all learned error signatures, sorted by hit count descending.
// The caller merges these with the built-in signatures.
func (db *DB) ErrorSignatures() []LearnedSignature {
	db.mu.RLock()
	defer db.mu.RUnlock()
	out := make([]LearnedSignature, len(db.data.ErrorSignatures))
	copy(out, db.data.ErrorSignatures)
	sort.Slice(out, func(i, j int) bool { return out[i].HitCount > out[j].HitCount })
	return out
}

// TopPayloads returns the highest-success-rate payloads for a given injection context.
// Returns up to maxN payloads, prioritising those with the highest SuccessRate × HitCount score.
func (db *DB) TopPayloads(injectionCtx string, maxN int) []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	type scored struct {
		payload string
		score   float64
	}
	var candidates []scored
	for _, p := range db.data.SuccessfulPayloads {
		if p.Context != "" && p.Context != injectionCtx {
			continue
		}
		if p.AttemptCount < 3 {
			continue // require at least 3 attempts for reliable scoring
		}
		candidates = append(candidates, scored{p.Payload, p.SuccessRate * float64(p.HitCount)})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })

	var out []string
	for i, c := range candidates {
		if i >= maxN {
			break
		}
		out = append(out, c.payload)
	}
	return out
}

// GetHostProfile returns the profile for a given host (by hostname), or nil.
// Returns a deep copy to prevent callers from mutating internal state.
func (db *DB) GetHostProfile(host string) *HostProfile {
	db.mu.RLock()
	defer db.mu.RUnlock()
	p, ok := db.data.HostProfiles[host]
	if !ok {
		return nil
	}
	// Deep copy slices to prevent shared backing arrays.
	cp := *p
	cp.InjectableParams = make([]InjectableParam, len(p.InjectableParams))
	copy(cp.InjectableParams, p.InjectableParams)
	cp.CleanURLs = make([]string, len(p.CleanURLs))
	copy(cp.CleanURLs, p.CleanURLs)
	return &cp
}

// IsFalsePositive returns true if the given host+param+fpType combination has
// been marked as a false positive more than threshold times.
// Uses exact hostname match to prevent prefix collisions (e.g. "evil.com" matching "notevil.com").
func (db *DB) IsFalsePositive(host, param, fpType string, threshold int) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	for _, fp := range db.data.FalsePositivePatterns {
		if fp.URLPattern == host &&
			(fp.ParamName == "" || fp.ParamName == param) &&
			(fp.FalsePositiveType == "" || fp.FalsePositiveType == fpType) &&
			fp.Count >= threshold {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════
// Write methods — called after scan to record what was learned
// ═══════════════════════════════════════════════════════════════════════

// maxDBEntries caps the number of entries in each learning DB slice to
// prevent unbounded growth across many scans against noisy targets.
const (
	maxErrorSignatures      = 500
	maxSuccessfulPayloads   = 200
	maxWAFFingerprints      = 100
	maxFalsePositivePatterns = 1000
	maxCleanURLsPerHost     = 500
)

// RecordErrorSignature adds or increments a new error pattern.
// Call this when a response body contains an error string not in the built-in list.
func (db *DB) RecordErrorSignature(engine, pattern string) {
	if pattern == "" {
		return
	}
	patternLower := strings.ToLower(strings.TrimSpace(pattern))

	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	for i := range db.data.ErrorSignatures {
		if db.data.ErrorSignatures[i].Pattern == patternLower {
			db.data.ErrorSignatures[i].HitCount++
			db.data.ErrorSignatures[i].LastSeen = now
			return
		}
	}
	db.data.ErrorSignatures = append(db.data.ErrorSignatures, LearnedSignature{
		Engine:    engine,
		Pattern:   patternLower,
		HitCount:  1,
		FirstSeen: now,
		LastSeen:  now,
	})
	// Fix: sort by hit count before truncating to evict lowest-value entries.
	if len(db.data.ErrorSignatures) > maxErrorSignatures {
		sort.Slice(db.data.ErrorSignatures, func(i, j int) bool {
			return db.data.ErrorSignatures[i].HitCount > db.data.ErrorSignatures[j].HitCount
		})
		db.data.ErrorSignatures = db.data.ErrorSignatures[:maxErrorSignatures]
	}
}

// RecordPayloadAttempt records that a payload was tried. fired=true means it confirmed SQLi.
func (db *DB) RecordPayloadAttempt(payload, injectionCtx, dbEngine string, fired bool) {
	if payload == "" {
		return
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	for i := range db.data.SuccessfulPayloads {
		p := &db.data.SuccessfulPayloads[i]
		if p.Payload == payload && p.Context == injectionCtx {
			p.AttemptCount++
			if fired {
				p.HitCount++
				p.LastSeen = now
				if dbEngine != "" {
					p.DBEngine = dbEngine
				}
			}
			p.SuccessRate = float64(p.HitCount) / float64(p.AttemptCount)
			return
		}
	}

	// New payload — only add to DB if it actually fired.
	if !fired {
		return
	}
	db.data.SuccessfulPayloads = append(db.data.SuccessfulPayloads, LearnedPayload{
		Payload:      payload,
		Context:      injectionCtx,
		DBEngine:     dbEngine,
		HitCount:     1,
		AttemptCount: 1,
		SuccessRate:  1.0,
		FirstSeen:    now,
		LastSeen:     now,
	})
	// Cap to prevent unbounded growth.
	if len(db.data.SuccessfulPayloads) > maxSuccessfulPayloads {
		db.data.SuccessfulPayloads = db.data.SuccessfulPayloads[:maxSuccessfulPayloads]
	}
}

// RecordConfirmedInjection records a fully confirmed injection point on a host.
func (db *DB) RecordConfirmedInjection(host, targetURL, param, injectionLoc, bestPayload, dbEngine string, confidence float64, techniques []string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	profile, ok := db.data.HostProfiles[host]
	if !ok {
		profile = &HostProfile{Host: host, LastSeen: now}
		db.data.HostProfiles[host] = profile
	}
	if dbEngine != "" {
		profile.DBEngine = dbEngine
	}
	profile.LastSeen = now

	// Avoid duplicating the same confirmed param.
	for _, ip := range profile.InjectableParams {
		if ip.URL == targetURL && ip.Param == param {
			return
		}
	}
	profile.InjectableParams = append(profile.InjectableParams, InjectableParam{
		URL:          targetURL,
		Param:        param,
		InjectionLoc: injectionLoc,
		BestPayload:  bestPayload,
		Confidence:   confidence,
		Techniques:   techniques,
		ConfirmedAt:  now,
	})
}

// RecordWAF records a WAF fingerprint for future reference.
func (db *DB) RecordWAF(host, wafName, headerKey, headerValue, bodyPattern string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)

	// Update host profile.
	profile, ok := db.data.HostProfiles[host]
	if !ok {
		profile = &HostProfile{Host: host, LastSeen: now}
		db.data.HostProfiles[host] = profile
	}
	profile.WAFName = wafName
	profile.LastSeen = now

	// Record fingerprint.
	for i := range db.data.WAFFingerprints {
		if db.data.WAFFingerprints[i].WAFName == wafName &&
			db.data.WAFFingerprints[i].HeaderKey == headerKey {
			db.data.WAFFingerprints[i].HitCount++
			return
		}
	}
	db.data.WAFFingerprints = append(db.data.WAFFingerprints, LearnedWAFFingerprint{
		WAFName:     wafName,
		HeaderKey:   headerKey,
		HeaderValue: headerValue,
		BodyPattern: bodyPattern,
		HitCount:    1,
		FirstSeen:   now,
	})
}

// RecordFalsePositive records that a detection fired but was not confirmed as SQLi.
func (db *DB) RecordFalsePositive(host, param, fpType string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	for i := range db.data.FalsePositivePatterns {
		fp := &db.data.FalsePositivePatterns[i]
		if fp.URLPattern == host && fp.ParamName == param && fp.FalsePositiveType == fpType {
			fp.Count++
			fp.LastSeen = now
			return
		}
	}
	db.data.FalsePositivePatterns = append(db.data.FalsePositivePatterns, FalsePositivePattern{
		URLPattern:        host,
		ParamName:         param,
		FalsePositiveType: fpType,
		Count:             1,
		LastSeen:          now,
	})
	// Cap to prevent unbounded growth.
	if len(db.data.FalsePositivePatterns) > maxFalsePositivePatterns {
		db.data.FalsePositivePatterns = db.data.FalsePositivePatterns[:maxFalsePositivePatterns]
	}
}

// RecordCleanURL marks a URL as confirmed non-injectable on a host.
func (db *DB) RecordCleanURL(host, targetURL string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	profile, ok := db.data.HostProfiles[host]
	if !ok {
		profile = &HostProfile{Host: host, LastSeen: now}
		db.data.HostProfiles[host] = profile
	}
	for _, u := range profile.CleanURLs {
		if u == targetURL {
			return
		}
	}
	profile.CleanURLs = append(profile.CleanURLs, targetURL)
	// Cap per-host clean URL list.
	if len(profile.CleanURLs) > maxCleanURLsPerHost {
		profile.CleanURLs = profile.CleanURLs[len(profile.CleanURLs)-maxCleanURLsPerHost:]
	}
	profile.LastSeen = now
}

// Stats returns a summary string for logging.
func (db *DB) Stats() string {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return fmt.Sprintf("signatures=%d payloads=%d hosts=%d fps=%d",
		len(db.data.ErrorSignatures),
		len(db.data.SuccessfulPayloads),
		len(db.data.HostProfiles),
		len(db.data.FalsePositivePatterns))
}
