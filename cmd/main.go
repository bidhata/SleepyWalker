package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sleepywalker/internal/ai"
	"sleepywalker/internal/config"
	"sleepywalker/internal/hooks"
	"sleepywalker/internal/reporter"
	"sleepywalker/internal/scanner"
	"sleepywalker/internal/sqlmap"
	"sleepywalker/internal/utils"
)

const banner = `
   _____ _                        _    _       _ _
  / ____| |                      | |  | |     | | |
 | (___ | | ___  ___ _ __  _   _ | |  | | __ _| | | _____ _ __
  \___ \| |/ _ \/ _ \ '_ \| | | || |/\| |/ _' | | |/ / _ \ '__|
  ____) | |  __/  __/ |_) | |_| |\  /\  / (_| | |   <  __/ |
 |_____/|_|\___|\___| .__/ \__, | \/  \/ \__,_|_|_|\_\___|_|
                     | |     __/ |
                     |_|    |___/
              SQL Injection Scanner — Red Team Edition v2.0
`

func main() {
	fmt.Print(banner)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var (
		targetURL    string
		sqlmapPath   string
		cookies      string
		proxyURL     string
		headers      []string
		threads      = 4
		crawlDepth   = 2
		rateDelayMs  = 0
		maxRequests  = 0
		dryRun       = false
		outputFormat = "html"
		scopeRegex   string
		scopeCIDRs   []string
		operator     string
		engagementID string
		logDir       string
		sqlmapRisk   = 2
		sqlmapLevel  = 3
		aiProvider   = "openrouter"
		swaggerURL   string
		jsRender     = false
		insecure     = false
		configFile   string
		hooksDir     string
		ov           config.CLIOverrides // tracks which flags were explicitly set
	)

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-url":
			if i+1 < len(os.Args) {
				targetURL = os.Args[i+1]
				i++
			}
		case "-threads":
			if i+1 < len(os.Args) {
				fmt.Sscanf(os.Args[i+1], "%d", &threads)
				ov.Threads = true
				i++
			}
		case "-sqlmap-path":
			if i+1 < len(os.Args) {
				sqlmapPath = os.Args[i+1]
				ov.SQLMapPath = true
				i++
			}
		case "-cookie":
			if i+1 < len(os.Args) {
				cookies = os.Args[i+1]
				ov.Cookie = true
				i++
			}
		case "-header":
			if i+1 < len(os.Args) {
				headers = append(headers, os.Args[i+1])
				ov.Headers = true
				i++
			}
		case "-proxy":
			if i+1 < len(os.Args) {
				proxyURL = os.Args[i+1]
				ov.Proxy = true
				i++
			}
		case "-depth":
			if i+1 < len(os.Args) {
				fmt.Sscanf(os.Args[i+1], "%d", &crawlDepth)
				ov.Depth = true
				i++
			}
		case "-delay":
			if i+1 < len(os.Args) {
				fmt.Sscanf(os.Args[i+1], "%d", &rateDelayMs)
				ov.Delay = true
				i++
			}
		case "-max-requests":
			if i+1 < len(os.Args) {
				fmt.Sscanf(os.Args[i+1], "%d", &maxRequests)
				ov.MaxRequests = true
				i++
			}
		case "-dry-run":
			dryRun = true
			ov.DryRun = true
		case "-insecure":
			insecure = true
			ov.Insecure = true
		case "-output-format":
			if i+1 < len(os.Args) {
				outputFormat = os.Args[i+1]
				ov.OutputFormat = true
				i++
			}
		case "-scope":
			if i+1 < len(os.Args) {
				scopeRegex = os.Args[i+1]
				ov.Scope = true
				i++
			}
		case "-scope-cidr":
			if i+1 < len(os.Args) {
				scopeCIDRs = append(scopeCIDRs, os.Args[i+1])
				ov.ScopeCIDRs = true
				i++
			}
		case "-operator":
			if i+1 < len(os.Args) {
				operator = os.Args[i+1]
				ov.Operator = true
				i++
			}
		case "-engagement-id":
			if i+1 < len(os.Args) {
				engagementID = os.Args[i+1]
				ov.EngagementID = true
				i++
			}
		case "-log-dir":
			if i+1 < len(os.Args) {
				logDir = os.Args[i+1]
				ov.LogDir = true
				i++
			}
		case "-risk":
			if i+1 < len(os.Args) {
				fmt.Sscanf(os.Args[i+1], "%d", &sqlmapRisk)
				ov.Risk = true
				i++
			}
		case "-level":
			if i+1 < len(os.Args) {
				fmt.Sscanf(os.Args[i+1], "%d", &sqlmapLevel)
				ov.Level = true
				i++
			}
		case "-ai-provider":
			if i+1 < len(os.Args) {
				aiProvider = os.Args[i+1]
				ov.AIProvider = true
				i++
			}
		case "-swagger-url":
			if i+1 < len(os.Args) {
				swaggerURL = os.Args[i+1]
				ov.SwaggerURL = true
				i++
			}
		case "-js-render":
			jsRender = true
			ov.JSRender = true
		case "-config":
			if i+1 < len(os.Args) {
				configFile = os.Args[i+1]
				i++
			}
		case "-hooks-dir":
			if i+1 < len(os.Args) {
				hooksDir = os.Args[i+1]
				i++
			}
		case "-help", "--help", "-h":
			printUsage()
			os.Exit(0)
		}
	}

	if targetURL == "" {
		fmt.Println("Error: -url is required.")
		printUsage()
		os.Exit(1)
	}

	// ── Configuration (file + CLI merge) ──────────────────────────────
	var cfg *config.Config

	if configFile != "" {
		fileCfg, err := config.LoadConfigFile(configFile)
		if err != nil {
			log.Fatalf("[ERROR] %v", err)
		}
		cfg = fileCfg
	}

	if hooksDir != "" {
		if err := hooks.LoadHooksFromDir(hooksDir); err != nil {
			log.Printf("[WARN] Failed to load hooks from %s: %v", hooksDir, err)
		}
	}

	// Fix #7: only prompt for API key when the effective provider needs one.
	// Determine provider from CLI override first, then config file.
	effectiveProvider := aiProvider
	if !ov.AIProvider && cfg != nil && cfg.AIProvider != "" {
		effectiveProvider = cfg.AIProvider
	}

	apiKey := ""
	offlineMode := true
	tmpCfg := &config.Config{AIProvider: effectiveProvider}
	if tmpCfg.NeedsAPIKey() {
		apiKey = config.PromptAPIKey()
		offlineMode = apiKey == ""
	} else {
		offlineMode = false // local/bedrock doesn't need offline fallback
	}
	if offlineMode {
		fmt.Println("⚡ Offline mode: using deep local validation instead of AI.")
	}

	cliCfg := &config.Config{
		OpenRouterAPIKey: apiKey,
		AIProvider:       aiProvider,
		Threads:          threads,
		SQLMapPath:       sqlmapPath,
		Cookies:          cookies,
		ExtraHeaders:     headers,
		ProxyURL:         proxyURL,
		CrawlDepth:       crawlDepth,
		RateDelay:        time.Duration(rateDelayMs) * time.Millisecond,
		MaxRequests:      maxRequests,
		DryRun:           dryRun,
		OutputFormat:     outputFormat,
		ScopeRegex:       scopeRegex,
		ScopeCIDRs:       scopeCIDRs,
		Operator:         operator,
		EngagementID:     engagementID,
		LogDir:           logDir,
		SQLMapRisk:       sqlmapRisk,
		SQLMapLevel:      sqlmapLevel,
		JSRender:         jsRender,
		SwaggerURL:       swaggerURL,
		Insecure:         insecure,
	}

	// Merge: file config as base, CLI overrides using explicit override flags.
	cfg = config.MergeWithCLI(cfg, cliCfg, ov)
	if cfg == nil {
		cfg = cliCfg
	}
	if apiKey != "" {
		cfg.OpenRouterAPIKey = apiKey
	}
	offlineMode = cfg.OpenRouterAPIKey == "" && cfg.NeedsAPIKey()

	// ── Scope Validation ──────────────────────────────────────────────
	if err := cfg.ValidateScope(targetURL); err != nil {
		fmt.Printf("❌ SCOPE VIOLATION: %v\n", err)
		fmt.Println("Target is outside the authorized scope. Aborting.")
		os.Exit(1)
	}

	// ── Initialize ────────────────────────────────────────────────────
	utils.InitLogger()
	utils.InitAuditLogger(logDir, operator, engagementID, targetURL)

	// Graceful shutdown: flush audit log on interrupt
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("\n[INFO] Interrupt received — shutting down gracefully…")
		utils.AuditLog(utils.AuditEntry{Action: "interrupted", Detail: "operator signal"})
		utils.CloseAuditLogger()
		cancel()
		os.Exit(130)
	}()
	_ = ctx // passed to future context-aware functions

	defer utils.CloseAuditLogger()

	outputDir := utils.CreateTargetDir(targetURL)

	// Initialize the shared rate limiter
	rateLimiter := utils.NewRateLimiter(cfg.RateDelay, cfg.MaxRequests)

	utils.AuditLog(utils.AuditEntry{
		Action: "scan_start",
		URL:    targetURL,
		Detail: fmt.Sprintf("threads=%d depth=%d dry_run=%v max_requests=%d", cfg.Threads, cfg.CrawlDepth, cfg.DryRun, cfg.MaxRequests),
	})

	// ── Pre-scan hooks ───────────────────────────────────────────────
	hooks.Run(hooks.PhasePreScan, hooks.HookContext{
		TargetURL:    targetURL,
		Operator:     cfg.Operator,
		EngagementID: cfg.EngagementID,
	})

	// ══════════════════════════════════════════════════════════════════
	// PRE-SCAN — WAF Detection
	// ══════════════════════════════════════════════════════════════════
	log.Println("═══════════════════════════════════════════════════════")
	log.Println("  PRE-SCAN ▸ WAF Detection")
	log.Println("═══════════════════════════════════════════════════════")

	wafResult := scanner.DetectWAF(cfg, targetURL)
	if wafResult.Detected {
		log.Printf("[WAF] 🛡️  %s detected — suggested bypasses: %s",
			wafResult.WAFName, strings.Join(wafResult.Bypass, ", "))
		utils.AuditLog(utils.AuditEntry{
			Action: "waf_detected",
			URL:    targetURL,
			Detail: wafResult.WAFName,
		})
	}

	// ══════════════════════════════════════════════════════════════════
	// PHASE 1 — Recursive Crawl + Discovery + Local Heuristic Scan
	// ══════════════════════════════════════════════════════════════════
	log.Println("═══════════════════════════════════════════════════════")
	log.Printf("  PHASE 1 ▸ Crawling (depth=%d) & heuristic scan", crawlDepth)
	log.Println("═══════════════════════════════════════════════════════")

	eps, err := scanner.CrawlAndDiscover(cfg, targetURL)
	if err != nil {
		log.Fatalf("[ERROR] Discovery failed: %v", err)
	}
	log.Printf("[INFO] Discovered %d unique entry point(s)", len(eps))
	if len(eps) == 0 {
		log.Println("[INFO] No entry points found. Nothing to scan.")
		return
	}

	// ── Post-discovery hooks ─────────────────────────────────────────
	hooks.Run(hooks.PhasePostDiscovery, hooks.HookContext{
		TargetURL:    targetURL,
		Operator:     cfg.Operator,
		EngagementID: cfg.EngagementID,
		Data:         map[string]interface{}{"entry_points": len(eps)},
	})

	locCounts := map[string]int{}
	for _, ep := range eps {
		locCounts[ep.InjectionLoc]++
	}
	for loc, count := range locCounts {
		log.Printf("[INFO]   %s: %d endpoint(s)", loc, count)
	}

	// Check budget before heuristic scan
	if rateLimiter.BudgetExhausted() {
		log.Println("[WARN] Request budget exhausted during crawl. Generating partial report.")
		writeReports(cfg, targetURL, nil, outputDir)
		return
	}

	heuristicResults := scanner.HeuristicScan(cfg, eps)

	var suspicious []scanner.HeuristicResult
	for _, hr := range heuristicResults {
		if hr.Suspicious {
			suspicious = append(suspicious, hr)
		}
	}
	log.Printf("[PHASE 1 COMPLETE] %d / %d entry points flagged as suspicious",
		len(suspicious), len(eps))

	if len(suspicious) == 0 {
		log.Println("[INFO] No suspicious endpoints detected. Generating clean report.")
		results := buildCleanResults(heuristicResults, wafResult)
		writeReports(cfg, targetURL, results, outputDir)
		return
	}

	// ══════════════════════════════════════════════════════════════════
	// PHASE 2 — Confirmation (AI or Deep Local Validation)
	// ══════════════════════════════════════════════════════════════════
	type confirmedEntry struct {
		hr         scanner.HeuristicResult
		suggestion string
		confidence float64
		method     string
	}
	var confirmed []confirmedEntry

	if offlineMode {
		log.Println("═══════════════════════════════════════════════════════")
		log.Printf("  PHASE 2 ▸ Deep local validation on %d suspicious endpoint(s)", len(suspicious))
		log.Println("═══════════════════════════════════════════════════════")

		deepResults := scanner.DeepValidate(suspicious)
		for i, dr := range deepResults {
			if dr.Confirmed {
				confirmed = append(confirmed, confirmedEntry{
					hr:         suspicious[i],
					suggestion: dr.BestPayload,
					confidence: dr.Confidence,
					method:     "deep-local",
				})
			}
		}
	} else {
		log.Println("═══════════════════════════════════════════════════════")
		log.Printf("  PHASE 2 ▸ AI analysis on %d suspicious endpoint(s)", len(suspicious))
		log.Println("═══════════════════════════════════════════════════════")

		for _, hr := range suspicious {
			vulnerable, suggestion, err := ai.AnalyzeEndpoint(*cfg, hr.Entry)
			if err != nil {
				log.Printf("[WARN] AI analysis error for %s: %v", hr.Entry.URL, err)
				continue
			}
			if vulnerable {
				log.Printf("[AI] ✓ Confirmed: %s", hr.Entry.URL)
				confirmed = append(confirmed, confirmedEntry{
					hr:         hr,
					suggestion: suggestion,
					confidence: 0.85,
					method:     "AI",
				})
			} else {
				log.Printf("[AI] ✗ Not confirmed: %s", hr.Entry.URL)
			}
		}
	}

	log.Printf("[PHASE 2 COMPLETE] Confirmed %d / %d suspicious endpoint(s)",
		len(confirmed), len(suspicious))

	if len(confirmed) == 0 {
		log.Println("[INFO] No vulnerabilities confirmed. Generating report.")
		results := buildCleanResults(heuristicResults, wafResult)
		writeReports(cfg, targetURL, results, outputDir)
		return
	}

	// ── Dry-run check ─────────────────────────────────────────────────
	if cfg.DryRun {
		log.Println("═══════════════════════════════════════════════════════")
		log.Println("  DRY-RUN MODE — Skipping Phase 3 (exploitation)")
		log.Println("═══════════════════════════════════════════════════════")
		log.Printf("[DRY-RUN] %d confirmed endpoints would be exploited:", len(confirmed))
		for _, c := range confirmed {
			log.Printf("[DRY-RUN]   %s %s [%s] (confidence: %.0f%%, method: %s)",
				c.hr.Entry.Method, c.hr.Entry.URL, c.hr.Entry.InjectionLoc, c.confidence*100, c.method)
		}

		var results []reporter.ScanResult
		for _, hr := range heuristicResults {
			results = append(results, reporter.ScanResult{
				Entry:           hr.Entry,
				Vulnerable:      false,
				HeuristicMatch:  hr.Suspicious,
				HeuristicErrors: hr.MatchedErrors,
				WAFDetected:     wafResult.Detected,
				WAFName:         wafResult.WAFName,
			})
		}
		for _, c := range confirmed {
			results = append(results, reporter.ScanResult{
				Entry:           c.hr.Entry,
				Vulnerable:      true,
				Payload:         c.suggestion,
				HeuristicMatch:  true,
				HeuristicErrors: c.hr.MatchedErrors,
				AIConfirmed:     true,
				ConfirmMethod:   c.method,
				Confidence:      c.confidence,
				WAFDetected:     wafResult.Detected,
				WAFName:         wafResult.WAFName,
				ExploitError:    "dry-run: exploitation skipped",
			})
		}
		writeReports(cfg, targetURL, results, outputDir)
		return
	}

	// ── Confirmation prompt before exploitation ───────────────────────
	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Printf("  ⚠️  PHASE 3 will exploit %d confirmed endpoint(s):\n", len(confirmed))
	for _, c := range confirmed {
		fmt.Printf("     • %s %s [%s]\n", c.hr.Entry.Method, c.hr.Entry.URL, c.hr.Entry.InjectionLoc)
	}
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Print("  Proceed with exploitation? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "y" && answer != "yes" {
		log.Println("[INFO] Exploitation aborted by operator.")
		utils.AuditLog(utils.AuditEntry{Action: "exploitation_aborted", Detail: "operator declined"})
		results := buildCleanResults(heuristicResults, wafResult)
		writeReports(cfg, targetURL, results, outputDir)
		return
	}

	utils.AuditLog(utils.AuditEntry{Action: "exploitation_approved", Detail: fmt.Sprintf("%d endpoints", len(confirmed))})

	// ── Post-confirm hooks ───────────────────────────────────────────
	hooks.Run(hooks.PhasePostConfirm, hooks.HookContext{
		TargetURL:    targetURL,
		Operator:     cfg.Operator,
		EngagementID: cfg.EngagementID,
		Data:         map[string]interface{}{"confirmed": len(confirmed)},
	})

	// ══════════════════════════════════════════════════════════════════
	// PHASE 3 — sqlmap Exploitation
	// ══════════════════════════════════════════════════════════════════
	log.Println("═══════════════════════════════════════════════════════")
	log.Printf("  PHASE 3 ▸ Running sqlmap on %d confirmed endpoint(s)", len(confirmed))
	log.Println("═══════════════════════════════════════════════════════")

	var results []reporter.ScanResult

	for _, hr := range heuristicResults {
		isConfirmed := false
		for _, c := range confirmed {
			if c.hr.Entry.URL == hr.Entry.URL && c.hr.Entry.Method == hr.Entry.Method &&
				c.hr.Entry.InjectionLoc == hr.Entry.InjectionLoc {
				isConfirmed = true
				break
			}
		}
		if !isConfirmed {
			results = append(results, reporter.ScanResult{
				Entry:           hr.Entry,
				Vulnerable:      false,
				HeuristicMatch:  hr.Suspicious,
				HeuristicErrors: hr.MatchedErrors,
				WAFDetected:     wafResult.Detected,
				WAFName:         wafResult.WAFName,
			})
		}
	}

	wafName := ""
	if wafResult.Detected {
		wafName = wafResult.WAFName
	}

	for _, c := range confirmed {
		log.Printf("[SQLMAP] Attacking %s %s [%s] …", c.hr.Entry.Method, c.hr.Entry.URL, c.hr.Entry.InjectionLoc)
		utils.AuditLog(utils.AuditEntry{
			Action:  "sqlmap_attack",
			URL:     c.hr.Entry.URL,
			Method:  c.hr.Entry.Method,
			Payload: c.suggestion,
		})

		dumpPaths, err := sqlmap.RunSQLMap(*cfg, c.hr.Entry, c.suggestion, outputDir, wafName)
		if err != nil {
			log.Printf("[WARN] sqlmap failed for %s: %v", c.hr.Entry.URL, err)
			results = append(results, reporter.ScanResult{
				Entry:           c.hr.Entry,
				Vulnerable:      true,
				Payload:         c.suggestion,
				ExploitError:    err.Error(),
				HeuristicMatch:  true,
				HeuristicErrors: c.hr.MatchedErrors,
				AIConfirmed:     true,
				ConfirmMethod:   c.method,
				Confidence:      c.confidence,
				WAFDetected:     wafResult.Detected,
				WAFName:         wafResult.WAFName,
			})
			continue
		}
		log.Printf("[SQLMAP] ✓ Dumped %d file(s) for %s", len(dumpPaths), c.hr.Entry.URL)
		results = append(results, reporter.ScanResult{
			Entry:           c.hr.Entry,
			Vulnerable:      true,
			DumpPaths:       dumpPaths,
			Payload:         c.suggestion,
			HeuristicMatch:  true,
			HeuristicErrors: c.hr.MatchedErrors,
			AIConfirmed:     true,
			ConfirmMethod:   c.method,
			Confidence:      c.confidence,
			WAFDetected:     wafResult.Detected,
			WAFName:         wafResult.WAFName,
		})
	}

	log.Println("[PHASE 3 COMPLETE]")

	// ── Post-exploit hooks ──────────────────────────────────────────
	hooks.Run(hooks.PhasePostExploit, hooks.HookContext{
		TargetURL:    targetURL,
		Operator:     cfg.Operator,
		EngagementID: cfg.EngagementID,
		Data:         map[string]interface{}{"results": len(results)},
	})

	writeReports(cfg, targetURL, results, outputDir)
}

func buildCleanResults(hrs []scanner.HeuristicResult, waf scanner.WAFResult) []reporter.ScanResult {
	var out []reporter.ScanResult
	for _, hr := range hrs {
		out = append(out, reporter.ScanResult{
			Entry:           hr.Entry,
			Vulnerable:      false,
			HeuristicMatch:  hr.Suspicious,
			HeuristicErrors: hr.MatchedErrors,
			WAFDetected:     waf.Detected,
			WAFName:         waf.WAFName,
		})
	}
	return out
}

func writeReports(cfg *config.Config, targetURL string, results []reporter.ScanResult, outputDir string) {
	var paths []string

	switch cfg.OutputFormat {
	case "json":
		p, err := reporter.GenerateJSONReport(targetURL, results, outputDir)
		if err != nil {
			log.Fatalf("[ERROR] JSON report failed: %v", err)
		}
		paths = append(paths, p)
	case "sarif":
		p, err := reporter.GenerateSARIFReport(targetURL, results, outputDir)
		if err != nil {
			log.Fatalf("[ERROR] SARIF report failed: %v", err)
		}
		paths = append(paths, p)
	case "all":
		if p, err := reporter.GenerateHTMLReport(targetURL, results, outputDir); err == nil {
			paths = append(paths, p)
		}
		if p, err := reporter.GenerateJSONReport(targetURL, results, outputDir); err == nil {
			paths = append(paths, p)
		}
		if p, err := reporter.GenerateSARIFReport(targetURL, results, outputDir); err == nil {
			paths = append(paths, p)
		}
	default:
		p, err := reporter.GenerateHTMLReport(targetURL, results, outputDir)
		if err != nil {
			log.Fatalf("[ERROR] HTML report failed: %v", err)
		}
		paths = append(paths, p)
	}

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════")
	for _, p := range paths {
		fmt.Printf("  Report saved → %s\n", p)
	}
	fmt.Printf("  Total requests: %d\n", utils.AuditRequestCount())
	fmt.Println("══════════════════════════════════════════════════════════")

	utils.AuditLog(utils.AuditEntry{
		Action: "scan_complete",
		Detail: fmt.Sprintf("reports: %v", paths),
	})

	// ── Post-report hooks ───────────────────────────────────────────
	hooks.Run(hooks.PhasePostReport, hooks.HookContext{
		TargetURL:    targetURL,
		Operator:     cfg.Operator,
		EngagementID: cfg.EngagementID,
		Data:         map[string]interface{}{"reports": paths, "output_dir": outputDir},
	})
}

func printUsage() {
	fmt.Println(`Usage: sleepywalker [flags]

Required:
  -url <target-url>        Target URL to scan

Configuration:
  -config <path>           TOML config file (CLI flags override file values)

Scope & Safety:
  -scope <regex>           Regex to restrict allowed target URLs
  -scope-cidr <cidr>       Allowed CIDR range (repeatable, e.g. "10.0.0.0/8")
  -dry-run                 Stop after Phase 2 — report findings without exploitation
  -max-requests <N>        Maximum total HTTP requests (0 = unlimited)

Scanning:
  -depth <N>               Recursive crawl depth (default: 2; 0 = unlimited)
  -threads <N>             Concurrent scan threads (default: 4)
  -delay <ms>              Base delay between requests in ms (default: 0)
  -js-render               Enable headless browser for JS-rendered pages
  -swagger-url <url>       OpenAPI/Swagger spec URL for endpoint discovery
  -insecure                Skip TLS certificate verification (self-signed certs)

Authentication:
  -cookie <value>          Cookie header value (e.g. "session=abc; token=xyz")
  -header <value>          Additional header (repeatable)

Proxy:
  -proxy <url>             HTTP/SOCKS5 proxy URL

AI Configuration:
  -ai-provider <name>      AI provider: openrouter (default), bedrock, local

sqlmap:
  -sqlmap-path <path>      Path to sqlmap binary (auto-detected if omitted)
  -risk <1-3>              sqlmap --risk value (default: 2)
  -level <1-5>             sqlmap --level value (default: 3)

Output:
  -output-format <fmt>     Report format: html (default), json, sarif, all

Audit Trail:
  -operator <name>         Operator name/ID for audit trail
  -engagement-id <id>      Engagement/authorization reference number
  -log-dir <path>          Directory for full request/response audit logs

Hooks:
  -hooks-dir <path>        Directory containing hook scripts (auto-registered by filename)

Examples:
  sleepywalker -url https://target.internal -config engagement.toml
  sleepywalker -url https://target.internal -scope ".*\.internal$" -operator "jsmith"
  sleepywalker -url https://target.internal -dry-run -output-format json
  sleepywalker -url https://target.internal -hooks-dir ./hooks/`)
}
