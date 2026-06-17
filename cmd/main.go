package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sleepywalker/internal/ai"
	"sleepywalker/internal/config"
	"sleepywalker/internal/hooks"
	"sleepywalker/internal/learningdb"
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
		crawlDepth   = 0
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
		ldbPath      string
		ov           config.CLIOverrides // tracks which flags were explicitly set
	)

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		// Support both "-flag value" and "-flag=value" forms.
		var key, val string
		var hasVal bool
		if idx := strings.IndexByte(arg, '='); idx >= 0 {
			key = arg[:idx]
			val = arg[idx+1:]
			hasVal = true
		} else {
			key = arg
		}
		nextArg := func() (string, bool) {
			if hasVal {
				return val, true
			}
			if i+1 < len(os.Args) {
				i++
				return os.Args[i], true
			}
			return "", false
		}
		switch key {
		case "-url":
			if v, ok := nextArg(); ok {
				targetURL = v
			}
		case "-threads":
			if v, ok := nextArg(); ok {
				fmt.Sscanf(v, "%d", &threads)
				ov.Threads = true
			}
		case "-sqlmap-path":
			if v, ok := nextArg(); ok {
				sqlmapPath = v
				ov.SQLMapPath = true
			}
		case "-cookie":
			if v, ok := nextArg(); ok {
				cookies = v
				ov.Cookie = true
			}
		case "-header":
			if v, ok := nextArg(); ok {
				headers = append(headers, v)
				ov.Headers = true
			}
		case "-proxy":
			if v, ok := nextArg(); ok {
				proxyURL = v
				ov.Proxy = true
			}
		case "-depth":
			if v, ok := nextArg(); ok {
				fmt.Sscanf(v, "%d", &crawlDepth)
				ov.Depth = true
			}
		case "-delay":
			if v, ok := nextArg(); ok {
				fmt.Sscanf(v, "%d", &rateDelayMs)
				ov.Delay = true
			}
		case "-max-requests":
			if v, ok := nextArg(); ok {
				fmt.Sscanf(v, "%d", &maxRequests)
				ov.MaxRequests = true
			}
		case "-dry-run":
			dryRun = true
			ov.DryRun = true
		case "-insecure":
			insecure = true
			ov.Insecure = true
		case "-output-format":
			if v, ok := nextArg(); ok {
				outputFormat = v
				ov.OutputFormat = true
			}
		case "-scope":
			if v, ok := nextArg(); ok {
				scopeRegex = v
				ov.Scope = true
			}
		case "-scope-cidr":
			if v, ok := nextArg(); ok {
				scopeCIDRs = append(scopeCIDRs, v)
				ov.ScopeCIDRs = true
			}
		case "-operator":
			if v, ok := nextArg(); ok {
				operator = v
				ov.Operator = true
			}
		case "-engagement-id":
			if v, ok := nextArg(); ok {
				engagementID = v
				ov.EngagementID = true
			}
		case "-log-dir":
			if v, ok := nextArg(); ok {
				logDir = v
				ov.LogDir = true
			}
		case "-risk":
			if v, ok := nextArg(); ok {
				fmt.Sscanf(v, "%d", &sqlmapRisk)
				ov.Risk = true
			}
		case "-level":
			if v, ok := nextArg(); ok {
				fmt.Sscanf(v, "%d", &sqlmapLevel)
				ov.Level = true
			}
		case "-ai-provider":
			if v, ok := nextArg(); ok {
				aiProvider = v
				ov.AIProvider = true
			}
		case "-swagger-url":
			if v, ok := nextArg(); ok {
				swaggerURL = v
				ov.SwaggerURL = true
			}
		case "-js-render":
			jsRender = true
			ov.JSRender = true
		case "-config":
			if v, ok := nextArg(); ok {
				configFile = v
			}
		case "-hooks-dir":
			if v, ok := nextArg(); ok {
				hooksDir = v
			}
		case "-ldb-path":
			if v, ok := nextArg(); ok {
				ldbPath = v
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
	offlineMode := !(&config.Config{AIProvider: effectiveProvider}).NeedsAPIKey()
	if !offlineMode {
		apiKey = config.PromptAPIKey()
		offlineMode = apiKey == ""
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

	// Load learning DB — enriches signatures and payloads from prior scans.
	ldb := learningdb.Load(ldbPath)
	defer func() {
		if err := ldb.Save(); err != nil {
			log.Printf("[WARN] Learning DB save failed: %v", err)
		}
	}()
	log.Printf("[LEARNINGDB] Stats: %s", ldb.Stats())

	// Graceful shutdown: flush audit log on interrupt
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("\n[INFO] Interrupt received — shutting down gracefully…")
		utils.AuditLog(utils.AuditEntry{Action: "interrupted", Detail: "operator signal"})
		utils.CloseAuditLogger()
		if err := ldb.Save(); err != nil {
			log.Printf("[WARN] Learning DB save failed on interrupt: %v", err)
		}
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
		// Record WAF in learning DB for future scans.
		if ldb != nil {
			ldb.RecordWAF(extractURLHost(targetURL), wafResult.WAFName, "", "", wafResult.Fingerprint)
		}
		// Profile individual blocked tokens for smarter tamper selection.
		scanner.ProfileWAFTokens(cfg, targetURL, &wafResult)
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

	log.Println("═══════════════════════════════════════════════════════")
	if offlineMode {
		log.Printf("  PHASE 2 ▸ Deep local validation on %d suspicious endpoint(s)", len(suspicious))

		deepResults := scanner.DeepValidate(cfg, suspicious)
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
		log.Printf("  PHASE 2 ▸ AI analysis on %d suspicious endpoint(s)", len(suspicious))

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
				continue
			}
			log.Printf("[AI] ✗ Not confirmed: %s", hr.Entry.URL)
		}
	}
	log.Println("═══════════════════════════════════════════════════════")

	log.Printf("[PHASE 2 COMPLETE] Confirmed %d / %d suspicious endpoint(s)",
		len(confirmed), len(suspicious))

	// Record Phase 2 outcomes in the learning DB.
	if ldb != nil {
		host := extractURLHost(targetURL)
		// Record confirmed injections.
		for _, c := range confirmed {
			// Extract DB engine from matched error strings regardless of confirmation method.
			dbEngine := ""
			for _, e := range c.hr.MatchedErrors {
				el := strings.ToLower(e)
				switch {
				case strings.Contains(el, "mysql") || strings.Contains(el, "mariadb"):
					dbEngine = "MySQL"
				case strings.Contains(el, "postgresql") || strings.Contains(el, "pg_"):
					dbEngine = "PostgreSQL"
				case strings.Contains(el, "mssql") || strings.Contains(el, "microsoft"):
					dbEngine = "MSSQL"
				case strings.Contains(el, "oracle") || strings.Contains(el, "ora-"):
					dbEngine = "Oracle"
				case strings.Contains(el, "sqlite"):
					dbEngine = "SQLite"
				}
				if dbEngine != "" {
					break
				}
			}
			param := pickMainParam(c.hr.Entry)
			ldb.RecordConfirmedInjection(host, c.hr.Entry.URL, param,
				c.hr.Entry.InjectionLoc, c.suggestion, dbEngine, c.confidence, nil)
			if c.suggestion != "" {
				ldb.RecordPayloadAttempt(c.suggestion, c.hr.Entry.InjectionLoc, dbEngine, true)
			}
		}
		// Record false positives: suspicious but unconfirmed.
		for _, hr := range suspicious {
			wasConfirmed := false
			for _, c := range confirmed {
				if c.hr.Entry.URL == hr.Entry.URL && c.hr.Entry.InjectionLoc == hr.Entry.InjectionLoc {
					wasConfirmed = true
					break
				}
			}
			if !wasConfirmed {
				// Derive a meaningful FP type category rather than storing the raw payload string,
				// so IsFalsePositive lookups can match by category.
				fpType := "error-based"
				switch hr.TestPayload {
				case "boolean-differential":
					fpType = "boolean-diff"
				case "time-based":
					fpType = "time-based"
				}
				ldb.RecordFalsePositive(host, pickMainParam(hr.Entry), fpType)
			}
		}
	}

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

// extractURLHost returns the hostname from a URL string.
func extractURLHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Hostname()
}

// pickMainParam returns the most likely injectable parameter name from an EntryPoint.
func pickMainParam(ep scanner.EntryPoint) string {
	priority := []string{"id", "uid", "user", "username", "search", "query", "q", "page"}
	for _, p := range priority {
		if _, ok := ep.Params[p]; ok {
			return p
		}
	}
	for k := range ep.Params {
		return k
	}
	return ""
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
