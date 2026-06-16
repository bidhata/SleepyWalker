package config

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// Config holds all runtime settings for SleepyWalker.
type Config struct {
	OpenRouterAPIKey string
	AIProvider       string        // "openrouter", "bedrock", "local"
	Threads          int
	SQLMapPath       string        // optional: path to sqlmap.py or binary; empty = auto-detect
	Cookies          string        // raw cookie header value
	ExtraHeaders     []string      // additional headers in "Key: Value" format
	ProxyURL         string        // HTTP(S)/SOCKS5 proxy URL
	CrawlDepth       int           // recursive crawl depth (0 = single page)
	RateDelay        time.Duration // delay between requests
	MaxRequests      int           // max total requests (0 = unlimited)
	DryRun           bool          // stop after Phase 2, no exploitation
	OutputFormat     string        // "html", "json", "sarif"

	// Scope control
	ScopeRegex string   // regex pattern for allowed URLs
	ScopeCIDRs []string // CIDR ranges for allowed targets

	// sqlmap tuning
	SQLMapRisk  int // --risk (1-3)
	SQLMapLevel int // --level (1-5)

	// Audit trail
	Operator     string // operator name/ID
	EngagementID string // engagement/authorization reference
	LogDir       string // directory for audit logs

	// JS rendering
	JSRender bool // use headless browser for crawling

	// Swagger
	SwaggerURL string // OpenAPI spec URL for additional endpoint discovery

	// TLS
	Insecure bool // skip TLS certificate verification
}

// NeedsAPIKey returns true when the configured AI provider requires an API key prompt.
// Fix #7: avoid prompting for an API key when provider is "local" or "bedrock".
func (c *Config) NeedsAPIKey() bool {
	return c.AIProvider == "" || c.AIProvider == "openrouter"
}

// PromptAPIKey reads the OpenRouter API key securely from terminal (no echo).
// Returns empty string if the user presses Enter without input (enables offline mode).
func PromptAPIKey() string {
	fmt.Print("Enter OpenRouter API key (press Enter to skip for offline mode): ")

	if term.IsTerminal(int(os.Stdin.Fd())) {
		key, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err == nil {
			return strings.TrimSpace(string(key))
		}
	}

	// Fallback for non-terminal (pipe, CI)
	reader := bufio.NewReader(os.Stdin)
	key, _ := reader.ReadString('\n')
	return strings.TrimSpace(key)
}

// ValidateScope checks whether a target URL is within the configured scope.
// Returns nil if in scope, error with reason if out of scope.
func (c *Config) ValidateScope(targetURL string) error {
	if c.ScopeRegex == "" && len(c.ScopeCIDRs) == 0 {
		return nil
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("cannot parse URL: %w", err)
	}

	if c.ScopeRegex != "" {
		re, err := regexp.Compile(c.ScopeRegex)
		if err != nil {
			return fmt.Errorf("invalid scope regex: %w", err)
		}
		if !re.MatchString(targetURL) {
			return fmt.Errorf("URL %q does not match scope regex %q", targetURL, c.ScopeRegex)
		}
	}

	if len(c.ScopeCIDRs) > 0 {
		host := parsed.Hostname()
		ips, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("cannot resolve host %q: %w", host, err)
		}

		inCIDR := false
		for _, ip := range ips {
			for _, cidr := range c.ScopeCIDRs {
				_, network, err := net.ParseCIDR(cidr)
				if err != nil {
					continue
				}
				if network.Contains(ip) {
					inCIDR = true
					break
				}
			}
			if inCIDR {
				break
			}
		}
		if !inCIDR {
			return fmt.Errorf("host %q (resolved IPs: %v) is not within allowed CIDRs %v", host, ips, c.ScopeCIDRs)
		}
	}

	return nil
}

// BuildHTTPClient creates an *http.Client pre-configured with proxy and redirect policy.
// The TLS warning is logged once per process when -insecure is set.
var insecureWarningOnce sync.Once

func (c *Config) BuildHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{}

	if c.Insecure {
		insecureWarningOnce.Do(func() {
			log.Println("[WARN] TLS certificate verification disabled (-insecure). Do not use on untrusted networks.")
		})
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	if c.ProxyURL != "" {
		proxyURL, err := url.Parse(c.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ApplyHeaders sets Cookie and custom headers on an http.Request.
func (c *Config) ApplyHeaders(req *http.Request) {
	if c.Cookies != "" {
		req.Header.Set("Cookie", c.Cookies)
	}
	for _, h := range c.ExtraHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}
