package config

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"sleepywalker/internal/hooks"
)

// FileConfig represents the TOML configuration file structure.
type FileConfig struct {
	Target   TargetSection `toml:"target"`
	Scan     ScanSection   `toml:"scan"`
	Auth     AuthSection   `toml:"auth"`
	AI       AISection     `toml:"ai"`
	SQLMap   SQLMapSection `toml:"sqlmap"`
	Output   OutputSection `toml:"output"`
	Audit    AuditSection  `toml:"audit"`
	Scope    ScopeSection  `toml:"scope"`
	Hooks    []hooks.Hook  `toml:"hooks"`
	HooksDir string        `toml:"hooks_dir"`
}

type TargetSection struct {
	URL string `toml:"url"`
}

type ScanSection struct {
	Depth       int    `toml:"depth"`
	Threads     int    `toml:"threads"`
	DelayMs     int    `toml:"delay_ms"`
	MaxRequests int    `toml:"max_requests"`
	DryRun      bool   `toml:"dry_run"`
	JSRender    bool   `toml:"js_render"`
	SwaggerURL  string `toml:"swagger_url"`
	Insecure    bool   `toml:"insecure"`
}

type AuthSection struct {
	Cookie  string   `toml:"cookie"`
	Headers []string `toml:"headers"`
	Proxy   string   `toml:"proxy"`
}

type AISection struct {
	Provider string `toml:"provider"`
	// API key is NEVER stored in config file — always prompted at runtime.
}

type SQLMapSection struct {
	Path  string `toml:"path"`
	Risk  int    `toml:"risk"`
	Level int    `toml:"level"`
}

type OutputSection struct {
	Format string `toml:"format"`
}

type AuditSection struct {
	Operator     string `toml:"operator"`
	EngagementID string `toml:"engagement_id"`
	LogDir       string `toml:"log_dir"`
}

type ScopeSection struct {
	Regex string   `toml:"regex"`
	CIDRs []string `toml:"cidrs"`
}

// CLIOverrides carries the set of flags that were explicitly provided on the
// command line. Used by MergeWithCLI to distinguish "user passed this flag"
// from "this is just the zero/default value".
// Fix #8: avoids the sentinel-value anti-pattern in MergeWithCLI.
type CLIOverrides struct {
	URL          bool
	Threads      bool
	Depth        bool
	Delay        bool
	MaxRequests  bool
	Risk         bool
	Level        bool
	OutputFormat bool
	AIProvider   bool
	Scope        bool
	ScopeCIDRs   bool
	Operator     bool
	EngagementID bool
	LogDir       bool
	Cookie       bool
	Proxy        bool
	SQLMapPath   bool
	SwaggerURL   bool
	DryRun       bool
	JSRender     bool
	Insecure     bool
	Headers      bool
}

// LoadConfigFile reads a TOML config file and returns a populated Config.
func LoadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file %s: %w", path, err)
	}

	var fc FileConfig
	if err := toml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("cannot parse config file %s: %w", path, err)
	}

	cfg := &Config{
		AIProvider:   fc.AI.Provider,
		Threads:      fc.Scan.Threads,
		SQLMapPath:   fc.SQLMap.Path,
		Cookies:      fc.Auth.Cookie,
		ExtraHeaders: fc.Auth.Headers,
		ProxyURL:     fc.Auth.Proxy,
		CrawlDepth:   fc.Scan.Depth,
		RateDelay:    time.Duration(fc.Scan.DelayMs) * time.Millisecond,
		MaxRequests:  fc.Scan.MaxRequests,
		DryRun:       fc.Scan.DryRun,
		OutputFormat: fc.Output.Format,
		ScopeRegex:   fc.Scope.Regex,
		ScopeCIDRs:   fc.Scope.CIDRs,
		SQLMapRisk:   fc.SQLMap.Risk,
		SQLMapLevel:  fc.SQLMap.Level,
		Operator:     fc.Audit.Operator,
		EngagementID: fc.Audit.EngagementID,
		LogDir:       fc.Audit.LogDir,
		JSRender:     fc.Scan.JSRender,
		SwaggerURL:   fc.Scan.SwaggerURL,
		Insecure:     fc.Scan.Insecure,
	}

	// Apply defaults for unset values.
	if cfg.Threads == 0 {
		cfg.Threads = 4
	}
	if cfg.SQLMapRisk == 0 {
		cfg.SQLMapRisk = 2
	}
	if cfg.SQLMapLevel == 0 {
		cfg.SQLMapLevel = 3
	}
	if cfg.OutputFormat == "" {
		cfg.OutputFormat = "html"
	}
	if cfg.AIProvider == "" {
		cfg.AIProvider = "openrouter"
	}

	if len(fc.Hooks) > 0 {
		hooks.RegisterAll(fc.Hooks)
		log.Printf("[CONFIG] Registered %d hook(s) from config file", len(fc.Hooks))
	}
	if fc.HooksDir != "" {
		if err := hooks.LoadHooksFromDir(fc.HooksDir); err != nil {
			log.Printf("[WARN] Failed to load hooks from %s: %v", fc.HooksDir, err)
		}
	}

	return cfg, nil
}

// MergeWithCLI overlays explicitly-set CLI values onto the file-based config.
// Fix #8: uses CLIOverrides to know which flags were actually set, so any
// value (including defaults like 4 threads or "html" format) can override the file.
func MergeWithCLI(base *Config, cli *Config, overrides CLIOverrides) *Config {
	if base == nil {
		return cli
	}
	if cli == nil {
		return base
	}

	if cli.OpenRouterAPIKey != "" {
		base.OpenRouterAPIKey = cli.OpenRouterAPIKey
	}
	if overrides.AIProvider {
		base.AIProvider = cli.AIProvider
	}
	if overrides.Threads {
		base.Threads = cli.Threads
	}
	if overrides.SQLMapPath {
		base.SQLMapPath = cli.SQLMapPath
	}
	if overrides.Cookie {
		base.Cookies = cli.Cookies
	}
	if overrides.Headers {
		base.ExtraHeaders = cli.ExtraHeaders
	}
	if overrides.Proxy {
		base.ProxyURL = cli.ProxyURL
	}
	if overrides.Depth {
		base.CrawlDepth = cli.CrawlDepth
	}
	if overrides.Delay {
		base.RateDelay = cli.RateDelay
	}
	if overrides.MaxRequests {
		base.MaxRequests = cli.MaxRequests
	}
	if overrides.DryRun {
		base.DryRun = true
	}
	if overrides.OutputFormat {
		base.OutputFormat = cli.OutputFormat
	}
	if overrides.Scope {
		base.ScopeRegex = cli.ScopeRegex
	}
	if overrides.ScopeCIDRs {
		base.ScopeCIDRs = cli.ScopeCIDRs
	}
	if overrides.Risk {
		base.SQLMapRisk = cli.SQLMapRisk
	}
	if overrides.Level {
		base.SQLMapLevel = cli.SQLMapLevel
	}
	if overrides.Operator {
		base.Operator = cli.Operator
	}
	if overrides.EngagementID {
		base.EngagementID = cli.EngagementID
	}
	if overrides.LogDir {
		base.LogDir = cli.LogDir
	}
	if overrides.JSRender {
		base.JSRender = true
	}
	if overrides.SwaggerURL {
		base.SwaggerURL = cli.SwaggerURL
	}
	if overrides.Insecure {
		base.Insecure = true
	}

	return base
}
