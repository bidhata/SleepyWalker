package utils

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CreateTargetDir creates a ./dumps/<sanitized-host> directory and returns
// its absolute path.
func CreateTargetDir(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		sum := sha256.Sum256([]byte(targetURL))
		dir := filepath.Join(".", "dumps", fmt.Sprintf("%x", sum[:8]))
		os.MkdirAll(dir, 0755)
		return dir
	}
	safe := sanitize(u.Host)
	if safe == "" {
		sum := sha256.Sum256([]byte(targetURL))
		safe = fmt.Sprintf("%x", sum[:8])
	}
	dir := filepath.Join(".", "dumps", safe)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[WARN] Could not create target dir %s: %v", dir, err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		log.Printf("[WARN] Could not resolve absolute path for %s: %v", dir, err)
		return dir // return relative path as fallback
	}
	return abs
}

// sanitize replaces characters that are unsafe for directory names.
var unsafeChars = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

func sanitize(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	return unsafeChars.ReplaceAllString(s, "_")
}
