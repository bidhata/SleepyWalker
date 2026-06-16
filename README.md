<div align="center">

# 🛡️ SleepyWalker

### *The SQL Injection Scanner That Never Sleeps*

**Discover. Confirm. Exploit. Report.**

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blueviolet?style=for-the-badge)]()
[![sqlmap](https://img.shields.io/badge/Powered%20by-sqlmap-red?style=for-the-badge)](https://sqlmap.org)

<br>

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=22&pause=1000&color=6C5CE7&center=true&vCenter=true&width=600&lines=AI-Powered+SQLi+Detection;10+Deep+Validation+Techniques;Zero+False+Positive+Philosophy;From+Discovery+to+Database+Dump;Built+for+Red+Teams+%F0%9F%94%B4" alt="Typing SVG" />

<br>

```
 You give it a URL. It gives you the database.
```

<br>

[Getting Started](#-quick-start) •
[How It Works](#-how-it-works) •
[Features](#-features) •
[Config](#-configuration) •
[Hooks](#-plugin-system)

</div>

---

<br>

## 💀 What Is This?

SleepyWalker is a **fully autonomous SQL injection pipeline** that chains crawling, heuristic analysis, AI-powered confirmation, and sqlmap exploitation into a single command.

It's what happens when you give a penetration tester's brain to a Go binary.

```bash
sleepywalker -url https://target.internal -operator "you" -engagement-id "PT-2024-042"
```

That's it. It crawls. It probes. It thinks. It confirms. It dumps. It reports.

<br>

## ⚡ Quick Start

```bash
# Clone & build (10 seconds)
git clone https://github.com/bidhata/SleepyWalker.git
cd SleepyWalker
go build -o sleepywalker ./cmd/

# Run your first scan
./sleepywalker -url https://target.example.com -dry-run
```

> **Requirements:** Go 1.23+ • sqlmap in PATH • (Optional) OpenRouter API key for AI mode

<br>

## 🧠 How It Works

```
                    ┌─────────────────────────────────────────┐
                    │           YOU RUN ONE COMMAND            │
                    └────────────────────┬────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │         PRE-SCAN: WAF Detection          │
                    │    Fingerprints Cloudflare, AWS WAF,     │
                    │    ModSecurity, Imperva, Akamai...       │
                    └────────────────────┬────────────────────┘
                                         │
          ┌──────────────────────────────▼──────────────────────────────┐
          │                    PHASE 1: Discovery                        │
          │                                                              │
          │  🕷️ Recursive HTML Crawl    🌐 JS-Rendered (chromedp)        │
          │  📋 OpenAPI/Swagger Import   📡 Header/JSON/Body injection   │
          │                                                              │
          │  → Injects 10+ SQLi payloads per entry point                │
          │  → Matches against 30+ DB error signatures                  │
          │  → Flags suspicious endpoints                               │
          └──────────────────────────────┬──────────────────────────────┘
                                         │
          ┌──────────────────────────────▼──────────────────────────────┐
          │                 PHASE 2: Confirmation                        │
          │                                                              │
          │  🤖 AI Mode (OpenRouter/gpt-4o-mini)                         │
          │     → Structured JSON verdict with confidence score          │
          │     → Retry with exponential backoff                         │
          │                                                              │
          │  🔬 Offline Deep Validation (10 techniques)                  │
          │     → Boolean-blind (Jaccard similarity)                     │
          │     → Time-blind (multi-round statistical median)            │
          │     → Error-based, UNION-based, DB-specific probes           │
          │     → Content-length delta, status correlation               │
          │     → Second-order detection                                 │
          │                                                              │
          │  Composite weighted confidence score → 0.0 – 1.0            │
          └──────────────────────────────┬──────────────────────────────┘
                                         │
                              ┌───────────▼───────────┐
                              │   OPERATOR CONFIRMS   │
                              │     [y/N] prompt      │
                              └───────────┬───────────┘
                                          │
          ┌───────────────────────────────▼─────────────────────────────┐
          │                  PHASE 3: Exploitation                       │
          │                                                              │
          │  🗡️ sqlmap --batch --dump                                     │
          │     → Auto-selects tamper scripts per WAF                   │
          │     → Forwards cookies, headers, proxy                      │
          │     → Configurable --risk and --level                       │
          │                                                              │
          └───────────────────────────────┬─────────────────────────────┘
                                          │
                    ┌─────────────────────▼─────────────────────┐
                    │              📊 REPORTING                  │
                    │                                            │
                    │   HTML   •   JSON   •   SARIF 2.1.0       │
                    │   CWE-89  •  CVSS 9.8  •  Remediation     │
                    │                                            │
                    │   → GitHub Code Scanning compatible        │
                    │   → Jira / Azure DevOps importable         │
                    └───────────────────────────────────────────┘
```

<br>

## 🔥 Features

### What Makes It Different

| Feature | SleepyWalker | Basic Scanners |
|---|:---:|:---:|
| AI-powered false positive elimination | ✅ | ❌ |
| 10-technique deep validation (no AI needed) | ✅ | ❌ |
| WAF-aware tamper script auto-selection | ✅ | ❌ |
| Full audit trail (JSONL) for compliance | ✅ | ❌ |
| Scope control (regex + CIDR) | ✅ | ❌ |
| JS-rendered page crawling | ✅ | ❌ |
| OpenAPI/Swagger endpoint import | ✅ | ❌ |
| SARIF output for CI/CD integration | ✅ | ❌ |
| Plugin/hook system | ✅ | ❌ |
| Interactive exploitation consent | ✅ | ❌ |
| Adaptive rate limiting with backoff | ✅ | ❌ |
| TOML config file support | ✅ | ❌ |
| Single binary, zero runtime deps | ✅ | ❌ |

<br>

### 🛡️ Safety First

This isn't a script kiddie toy. It's built for **authorized red team operations** with guardrails:

- **Scope enforcement** — regex and CIDR whitelist; blocks out-of-scope targets at startup
- **Dry-run mode** — full pipeline minus exploitation; perfect for reporting without risk
- **Exploitation consent** — interactive `[y/N]` prompt listing every target before Phase 3
- **Request budget** — hard cap on total HTTP requests to prevent accidental DoS
- **Adaptive throttling** — auto-backs off on 429/503, exponential backoff with recovery
- **Graceful shutdown** — Ctrl+C flushes audit logs, no data loss
- **Full audit trail** — every action logged as JSONL with operator identity

<br>

## 📋 Configuration

### CLI Flags

```bash
sleepywalker -url https://target.internal \
  -scope ".*\.internal$" \
  -operator "jsmith" \
  -engagement-id "PT-2024-042" \
  -depth 3 \
  -threads 8 \
  -delay 200 \
  -max-requests 5000 \
  -output-format all \
  -log-dir ./logs
```

### TOML Config File

```bash
sleepywalker -config engagement.toml
```

```toml
[scope]
regex = ".*\\.internal$"
cidrs = ["10.0.0.0/8"]

[scan]
depth       = 3
threads     = 8
delay_ms    = 200
max_requests = 5000

[auth]
cookie  = "session=abc123"
headers = ["Authorization: Bearer <token>"]

[output]
format = "all"

[audit]
operator      = "jsmith"
engagement_id = "PT-2024-042"
log_dir       = "./logs"

[[hooks]]
name    = "notify-slack"
phase   = "post-report"
command = "python3 scripts/notify_slack.py"
timeout = 15
```

> Full example: [`examples/engagement.toml`](examples/engagement.toml)

<br>

### All Flags

| Flag | Default | Description |
|---|---|---|
| `-url` | *(required)* | Target URL |
| `-config` | | TOML config file path |
| `-scope` | | Regex scope restriction |
| `-scope-cidr` | | CIDR whitelist (repeatable) |
| `-dry-run` | `false` | Report without exploitation |
| `-max-requests` | `0` | Request budget (0 = unlimited) |
| `-depth` | `2` | Crawl depth (0 = unlimited) |
| `-threads` | `4` | Concurrency |
| `-delay` | `0` | Request delay (ms) |
| `-js-render` | `false` | Headless browser crawl |
| `-swagger-url` | | OpenAPI spec URL |
| `-insecure` | `false` | Skip TLS verification |
| `-cookie` | | Cookie header |
| `-header` | | Custom header (repeatable) |
| `-proxy` | | HTTP/SOCKS5 proxy |
| `-ai-provider` | `openrouter` | AI: openrouter, bedrock, local |
| `-sqlmap-path` | *(auto)* | sqlmap binary path |
| `-risk` | `2` | sqlmap risk (1-3) |
| `-level` | `3` | sqlmap level (1-5) |
| `-output-format` | `html` | html, json, sarif, all |
| `-operator` | | Operator ID |
| `-engagement-id` | | Engagement reference |
| `-log-dir` | | Audit log directory |
| `-hooks-dir` | | Hook scripts directory |

<br>

## 🔌 Plugin System

Extend SleepyWalker without touching source code. Hooks execute at 5 lifecycle phases:

```
pre-scan → post-discovery → post-confirm → post-exploit → post-report
```

### Auto-Registration (by filename)

```
hooks/
├── pre-scan_validate-engagement.sh
├── post-discovery_count-endpoints.py
├── post-report_notify-slack.py
└── post-report_upload-s3.sh
```

```bash
sleepywalker -url https://target.internal -hooks-dir ./hooks/
```

### Context Passed to Hooks

Every hook receives full scan context as **JSON on stdin**:

```json
{
  "phase": "post-report",
  "target_url": "https://target.internal",
  "operator": "jsmith",
  "engagement_id": "PT-2024-042",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "reports": ["./dumps/target_internal/report.html"],
    "output_dir": "./dumps/target_internal"
  }
}
```

**Ideas for hooks:**
- Slack/Teams/Discord notifications
- Upload reports to S3/GCS
- Auto-create Jira tickets for findings
- Validate engagement authorization against internal API
- Trigger remediation workflows
- Send metrics to Datadog/Prometheus

<br>

## 📊 Output Formats

| Format | Use Case | Integration |
|---|---|---|
| **HTML** | Human-readable report with dark UI | Email, browser |
| **JSON** | Machine processing, dashboards | SIEM, custom tooling |
| **SARIF 2.1.0** | CI/CD security gates | GitHub Code Scanning, Azure DevOps, Jira |

```bash
# Generate all formats at once
sleepywalker -url https://target.internal -output-format all
```

Output lands in `./dumps/<target-host>/`:
```
dumps/target_internal/
├── report.html
├── report.json
├── report.sarif.json
└── <hash>/
    └── *.sql, *.csv
```

<br>

## 🏗️ Architecture

```
SleepyWalker/
├── cmd/main.go                      # CLI + pipeline orchestration
├── internal/
│   ├── config/
│   │   ├── config.go                # Runtime config, scope validation, TLS
│   │   └── configfile.go            # TOML config loader + CLI merge
│   ├── hooks/hooks.go               # Plugin/hook lifecycle system
│   ├── scanner/
│   │   ├── scanner.go               # Crawl engine (HTML + recursive)
│   │   ├── jscrawl.go               # Headless browser (chromedp)
│   │   ├── swagger.go               # OpenAPI/Swagger parser
│   │   ├── heuristic.go             # Phase 1: payload injection
│   │   ├── deepvalidate.go          # Phase 2: 10-technique validation
│   │   └── waf.go                   # WAF fingerprinting
│   ├── ai/ai.go                     # Phase 2: AI analysis (multi-provider)
│   ├── sqlmap/sqlmap.go             # Phase 3: sqlmap wrapper
│   ├── reporter/
│   │   ├── reporter.go              # HTML report
│   │   └── jsonreport.go            # JSON + SARIF
│   └── utils/
│       ├── audit.go                 # JSONL audit trail
│       ├── ratelimit.go             # Adaptive rate limiter
│       ├── logger.go                # Logging
│       └── fileutils.go             # Output dirs
├── examples/
│   ├── engagement.toml              # Sample config
│   └── post-report_notify-slack.py  # Sample hook
├── .gitignore
├── go.mod
└── README.md
```

<br>

## 🚀 Real-World Usage

```bash
# Internal pentest with full audit trail
sleepywalker -url https://app.corp.internal \
  -config pentest.toml \
  -operator "krish" \
  -engagement-id "RT-2024-087" \
  -log-dir ./audit-logs

# CI/CD gate (dry-run + SARIF for GitHub)
sleepywalker -url https://staging.myapp.com \
  -dry-run \
  -output-format sarif \
  -max-requests 1000

# Aggressive internal scan through proxy
sleepywalker -url https://legacy-app.internal \
  -proxy socks5://127.0.0.1:9050 \
  -risk 3 -level 5 \
  -depth 5 -threads 16 \
  -insecure

# JavaScript-heavy SPA with API spec
sleepywalker -url https://spa.internal \
  -js-render \
  -swagger-url https://spa.internal/api/docs/openapi.json \
  -output-format all
```

<br>

## 🤝 Contributing

This is an internal red team tool, but contributions are welcome:

1. Fork it
2. Create your feature branch (`git checkout -b feat/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

**Areas where help is appreciated:**
- Additional WAF bypass techniques
- New deep validation heuristics
- Integration hooks for more platforms
- Documentation & examples

<br>

## ⚠️ Legal Disclaimer

> **This tool is intended EXCLUSIVELY for authorized penetration testing.**
>
> Unauthorized use against systems you do not own or have explicit written permission to test is **illegal** and **unethical**. Always obtain proper authorization before scanning any target. The author accepts no liability for misuse.
>
> By using this tool, you agree that you have legal authorization to test the target systems.

<br>

---

<div align="center">

**Built with obsessive attention to detail by [Krish Paul](https://krishnendu.com)**

[![Website](https://img.shields.io/badge/Website-krishnendu.com-6C5CE7?style=for-the-badge&logo=google-chrome&logoColor=white)](https://krishnendu.com)
[![Email](https://img.shields.io/badge/Email-me@krishnendu.com-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:me@krishnendu.com)
[![GitHub](https://img.shields.io/badge/GitHub-bidhata-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/bidhata/SleepyWalker)

<br>

*If this tool saved your red team hours of manual testing, consider giving it a ⭐*

<br>

**Go** • **OpenRouter AI** • **sqlmap** • **chromedp**

</div>
