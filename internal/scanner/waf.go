package scanner

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"sleepywalker/internal/config"
)

// WAFResult holds WAF detection findings.
type WAFResult struct {
	Detected    bool
	WAFName     string
	Fingerprint string
	Bypass      []string // suggested bypass techniques
}

// wafSignature maps response characteristics to known WAF products.
type wafSignature struct {
	Name          string
	HeaderKey     string
	HeaderPattern string
	BodyPattern   string
	StatusCode    int
	Bypasses      []string
}

var wafSignatures = []wafSignature{
	{
		Name:          "Cloudflare",
		HeaderKey:     "Server",
		HeaderPattern: "cloudflare",
		BodyPattern:   "attention required! | cloudflare",
		Bypasses:      []string{"URL encoding", "double URL encoding", "Unicode normalization", "HPP (HTTP Parameter Pollution)"},
	},
	{
		Name:          "AWS WAF",
		HeaderKey:     "X-Amzn-Requestid",
		HeaderPattern: "",
		BodyPattern:   "aws waf",
		StatusCode:    403,
		Bypasses:      []string{"case variation", "comment injection (/*!*/)", "URL encoding"},
	},
	{
		Name:          "ModSecurity",
		HeaderKey:     "Server",
		HeaderPattern: "mod_security",
		BodyPattern:   "modsecurity",
		Bypasses:      []string{"inline comments (/**/) ", "case alternation", "chunk transfer encoding", "HPP"},
	},
	{
		Name:          "Imperva/Incapsula",
		HeaderKey:     "X-CDN",
		HeaderPattern: "incapsula",
		BodyPattern:   "incapsula incident",
		Bypasses:      []string{"URL encoding", "multipart form encoding", "parameter fragment"},
	},
	{
		Name:          "Akamai",
		HeaderKey:     "Server",
		HeaderPattern: "akamaighost",
		BodyPattern:   "access denied",
		Bypasses:      []string{"tab characters between keywords", "URL encoding", "case alternation"},
	},
	{
		Name:          "F5 BIG-IP ASM",
		HeaderKey:     "Server",
		HeaderPattern: "big-ip",
		BodyPattern:   "the requested url was rejected",
		Bypasses:      []string{"HPP", "URL encoding", "comment injection"},
	},
	{
		Name:          "Sucuri",
		HeaderKey:     "Server",
		HeaderPattern: "sucuri",
		BodyPattern:   "sucuri website firewall",
		Bypasses:      []string{"URL encoding", "case variation", "alternative syntax"},
	},
	{
		Name:          "Barracuda",
		HeaderKey:     "Server",
		HeaderPattern: "barracuda",
		BodyPattern:   "barracuda",
		Bypasses:      []string{"URL encoding", "comment injection", "HPP"},
	},
	// Generic detection for unknown WAFs
	{
		Name:          "Generic WAF",
		HeaderKey:     "",
		HeaderPattern: "",
		BodyPattern:   "web application firewall",
		StatusCode:    403,
		Bypasses:      []string{"URL encoding", "case variation", "inline comments", "HPP"},
	},
}

// DetectWAF sends a known-bad payload to the target and analyses the response
// to determine if a WAF is present.
func DetectWAF(cfg *config.Config, targetURL string) WAFResult {
	client := cfg.BuildHTTPClient(10 * time.Second)

	// Send a clean request first to get baseline
	baseReq, _ := http.NewRequest("GET", targetURL, nil)
	baseReq.Header.Set("User-Agent", "SleepyWalker/1.0 (Security Scanner)")
	cfg.ApplyHeaders(baseReq)
	baseResp, baseErr := client.Do(baseReq)
	baseStatus := 0
	if baseErr == nil {
		baseStatus = baseResp.StatusCode
		io.Copy(io.Discard, baseResp.Body)
		baseResp.Body.Close()
	}

	// Now send an obviously malicious request
	maliciousURL := targetURL
	sep := "?"
	if strings.Contains(targetURL, "?") {
		sep = "&"
	}
	maliciousURL = fmt.Sprintf("%s%stest=1'+OR+1=1--+UNION+SELECT+NULL--+<script>alert(1)</script>", maliciousURL, sep)

	req, err := http.NewRequest("GET", maliciousURL, nil)
	if err != nil {
		return WAFResult{Detected: false}
	}
	req.Header.Set("User-Agent", "SleepyWalker/1.0 (Security Scanner)")
	cfg.ApplyHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return WAFResult{Detected: false}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	bodyLower := strings.ToLower(string(bodyBytes))

	// Check each WAF signature
	for _, sig := range wafSignatures {
		matched := false
		fingerprint := ""

		// Header match
		if sig.HeaderKey != "" {
			headerVal := strings.ToLower(resp.Header.Get(sig.HeaderKey))
			if sig.HeaderPattern != "" && strings.Contains(headerVal, sig.HeaderPattern) {
				matched = true
				fingerprint = fmt.Sprintf("Header %s: %s", sig.HeaderKey, headerVal)
			} else if sig.HeaderPattern == "" && headerVal != "" {
				// Just checking existence of the header
				matched = true
				fingerprint = fmt.Sprintf("Header %s present", sig.HeaderKey)
			}
		}

		// Body match
		if sig.BodyPattern != "" && strings.Contains(bodyLower, sig.BodyPattern) {
			matched = true
			fingerprint = fmt.Sprintf("Body contains %q", sig.BodyPattern)
		}

		// Status code check: if baseline was 200 and now we get 403/406
		if sig.StatusCode > 0 && resp.StatusCode == sig.StatusCode && baseStatus == 200 {
			if matched || sig.Name == "Generic WAF" {
				matched = true
				fingerprint += fmt.Sprintf(" | Status %d (was %d)", resp.StatusCode, baseStatus)
			}
		}

		if matched {
			log.Printf("[WAF] 🛡️  Detected: %s (%s)", sig.Name, fingerprint)
			return WAFResult{
				Detected:    true,
				WAFName:     sig.Name,
				Fingerprint: fingerprint,
				Bypass:      sig.Bypasses,
			}
		}
	}

	// Generic: if baseline was 200 and malicious got 403/406/429
	if baseStatus == 200 && (resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429) {
		log.Printf("[WAF] 🛡️  Possible WAF detected (status changed from %d to %d)", baseStatus, resp.StatusCode)
		return WAFResult{
			Detected:    true,
			WAFName:     "Unknown WAF",
			Fingerprint: fmt.Sprintf("Status changed from %d to %d on malicious payload", baseStatus, resp.StatusCode),
			Bypass:      []string{"URL encoding", "case alternation", "inline comments", "HPP", "chunked encoding"},
		}
	}

	log.Println("[WAF] ✓ No WAF detected")
	return WAFResult{Detected: false}
}
