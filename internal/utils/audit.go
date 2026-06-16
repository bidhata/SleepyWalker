package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditLogger records all scan activity for compliance and defensibility.
type AuditLogger struct {
	file       *os.File
	mu         sync.Mutex
	startTime  time.Time
	eventCount int64 // counts audit events (not HTTP requests)
	operator   string
	engagement string
	closed     bool
}

// AuditEntry represents a single logged action.
type AuditEntry struct {
	Timestamp  string `json:"timestamp"`
	Action     string `json:"action"`
	URL        string `json:"url,omitempty"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Payload    string `json:"payload,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

var globalAudit *AuditLogger

// InitAuditLogger creates the audit log file and writes the session header.
func InitAuditLogger(logDir, operator, engagementID, targetURL string) {
	if logDir == "" {
		return
	}

	if err := os.MkdirAll(logDir, 0750); err != nil {
		log.Printf("[WARN] Cannot create log dir %s: %v", logDir, err)
		return
	}

	filename := fmt.Sprintf("audit_%s.jsonl", time.Now().Format("20060102_150405"))
	path := filepath.Join(logDir, filename)
	f, err := os.Create(path)
	if err != nil {
		log.Printf("[WARN] Cannot create audit log %s: %v", path, err)
		return
	}

	globalAudit = &AuditLogger{
		file:      f,
		startTime: time.Now(),
		operator:  operator,
		engagement: engagementID,
	}

	header := map[string]string{
		"event":         "session_start",
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"operator":      operator,
		"engagement_id": engagementID,
		"target":        targetURL,
		"tool_version":  "SleepyWalker/2.0",
	}
	data, _ := json.Marshal(header)
	f.Write(data)
	f.WriteString("\n")

	log.Printf("[AUDIT] Logging to %s", path)
}

// AuditLog writes an entry to the audit trail.
// Note: the internal counter tracks audit events, not HTTP requests.
// Use RateLimiter.RequestCount() for HTTP request counts.
func AuditLog(entry AuditEntry) {
	if globalAudit == nil {
		return
	}
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)

	// Fix #4: hold the mutex for the entire write, including the closed check,
	// to prevent a race between AuditLog and CloseAuditLogger.
	globalAudit.mu.Lock()
	defer globalAudit.mu.Unlock()

	if globalAudit.closed {
		return
	}

	globalAudit.eventCount++
	data, _ := json.Marshal(entry)
	globalAudit.file.Write(data)
	globalAudit.file.WriteString("\n")
}

// AuditRequestCount returns total audit events recorded this session.
func AuditRequestCount() int64 {
	if globalAudit == nil {
		return 0
	}
	globalAudit.mu.Lock()
	defer globalAudit.mu.Unlock()
	return globalAudit.eventCount
}

// CloseAuditLogger writes session footer and closes the file.
// Safe to call multiple times — subsequent calls are no-ops.
func CloseAuditLogger() {
	if globalAudit == nil {
		return
	}

	// Fix #4: acquire mutex before checking or writing state.
	globalAudit.mu.Lock()
	defer globalAudit.mu.Unlock()

	if globalAudit.closed {
		return
	}
	globalAudit.closed = true

	footer := map[string]interface{}{
		"event":        "session_end",
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"total_events": globalAudit.eventCount,
		"duration_sec": time.Since(globalAudit.startTime).Seconds(),
	}
	data, _ := json.Marshal(footer)
	globalAudit.file.Write(data)
	globalAudit.file.WriteString("\n")
	globalAudit.file.Close()
}

// GetAuditMeta returns operator and engagement info for reports.
func GetAuditMeta() (operator, engagement string, start time.Time, eventCount int64) {
	if globalAudit == nil {
		return "", "", time.Time{}, 0
	}
	globalAudit.mu.Lock()
	defer globalAudit.mu.Unlock()
	return globalAudit.operator, globalAudit.engagement, globalAudit.startTime, globalAudit.eventCount
}
