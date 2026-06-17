<div align="center">

# 🛡️ SleepyWalker

### *The SQL Injection Scanner That Never Sleeps*

**Discover. Confirm. Exploit. Report. Learn.**

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blueviolet?style=for-the-badge)]()
[![sqlmap](https://img.shields.io/badge/Powered%20by-sqlmap-red?style=for-the-badge)](https://sqlmap.org)

<br>

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=22&pause=1000&color=6C5CE7&center=true&vCenter=true&width=600&lines=AI-Powered+SQLi+Detection;11+Deep+Validation+Techniques;Zero+False+Positive+Philosophy;From+Discovery+to+Database+Dump;Self-Learning+Pattern+Database;Built+for+Red+Teams+%F0%9F%94%B4" alt="Typing SVG" />

<br>

```
 You give it a URL. It gives you the database.
 And it gets smarter every time it runs.
```

<br>

[Getting Started](#-quick-start) •
[How It Works](#-how-it-works) •
[Features](#-features) •
[Config](#-configuration) •
[Learning DB](#-learning-database) •
[Hooks](#-plugin-system)

</div>

---

<br>

## 💀 What Is This?

SleepyWalker is a **fully autonomous SQL injection pipeline** that chains crawling, heuristic analysis, AI-powered confirmation, and sqlmap exploitation into a single command — and gets smarter with every scan through a persistent learning database.

```bash
sleepywalker -url https://target.internal -operator "you" -engagement-id "PT-2024-042"
```

That's it. It crawls. It probes. It confirms. It dumps. It reports. It **learns**.

<br>

## ⚡ Quick Start

```bash
# Clone & build
git clone https://github.com/bidhata/SleepyWalker.git
cd SleepyWalker
go build -o sleepywalker ./cmd/

# Run your first scan (dry-run = no exploitation)
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
                    │    Learning DB loaded from prior scans   │
                    │  → enriches payloads & error signatures  │
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
          │  🔗 Path segment injection   📎 Multipart forms              │
          │                                                              │
          │  → Built-in + learned payloads per injection context        │
          │  → Built-in + learned DB error signatures                   │
          │  → Phase 1a: error-based  1b: boolean-blind  1c: time-based │
          └──────────────────────────────┬──────────────────────────────┘
                                         │
          ┌──────────────────────────────▼──────────────────────────────┐
          │                 PHASE 2: Confirmation                        │
          │                                                              │
          │  🤖 AI Mode (OpenRouter/gpt-4o-mini)                         │
          │     → Structured JSON verdict with confidence score          │
          │     → Retry with exponential backoff                         │
          │                                                              │
          │  🔬 Offline Deep Validation (11 techniques)                  │
          │     → Boolean-blind (Jaccard similarity)                     │
          │     → Time-blind (multi-round statistical median)            │
          │     → Error-based, UNION-based, DB-specific probes           │
          │     → Content-length delta, status correlation               │
          │     → Second-order, Out-of-band DNS resolution              │
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
          └───────────────────────────────┬─────────────────────────────┘
                                          │
                    ┌─────────────────────▼─────────────────────┐
                    │              📊 REPORTING                  │
                    │                                            │
                    │   HTML   •   JSON   •   SARIF 2.1.0       │
                    │   CWE-89  •  CVSS 9.8  •  Remediation     │
                    └─────────────────────┬─────────────────────┘
                                          │
                    ┌─────────────────────▼─────────────────────┐
                    │         🧠 LEARNING DB UPDATED             │
                    │  Confirmed payloads scored  •  FPs noted  │
                    │  Host profiles  •  WAF fingerprints       │
                    │  Next scan is faster and more accurate    │
                    └───────────────────────────────────────────┘
```


## 🔥 Features

### What Makes It Different

| Feature | SleepyWalker | Basic Scanners |
|---|:---:|:---:|
| AI-powered false positive elimination | ✅ | ❌ |
| 11-technique deep validation (no AI needed) | ✅ | ❌ |
| Self-learning pattern database | ✅ | ❌ |
| WAF-aware tamper script auto-selection | ✅ | ❌ |
| Full audit trail (JSONL) for compliance | ✅ | ❌ |
| Scope control (regex + CIDR) | ✅ | ❌ |
| JS-rendered page crawling | ✅ | ❌ |
| OpenAPI/Swagger endpoint import | ✅ | ❌ |
| Multipart form + path segment injection | ✅ | ❌ |
| SARIF output for CI/CD integration | ✅ | ❌ |
| Plugin/hook system (5 lifecycle phases) | ✅ | ❌ |
| Interactive exploitation consent | ✅ | ❌ |
| Adaptive rate limiting with backoff | ✅ | ❌ |
| TOML config file support | ✅ | ❌ |
| MCP server for AI agent integration | ✅ | ❌ |
| Single binary, zero runtime deps | ✅ | ❌ |

<br>

### 🔍 Injection Coverage

| Location | Methods | Detection |
|---|---|---|
| Query parameters | GET, DELETE | Error, Boolean, Time |
| Form body | POST, PUT, PATCH | Error, Boolean, Time |
| JSON body | POST, PUT, PATCH | Error, Boolean, Time |
| HTTP headers | User-Agent, Referer, X-Forwarded-For, Cookie | Error, Boolean, Time |
| Multipart fields | POST | Error |
| URL path segments | GET (integers, UUIDs) | Error |

<br>

### 🛡️ Safety First

Built for **authorized red team operations** with guardrails:

- **Scope enforcement** — regex and CIDR whitelist; blocks out-of-scope targets at startup
- **Dry-run mode** — full pipeline minus exploitation; perfect for CI/CD gates
- **Exploitation consent** — interactive `[y/N]` prompt listing every target before Phase 3
- **Request budget** — hard cap on total HTTP requests to prevent accidental DoS
- **Adaptive throttling** — auto-backs off on 429/503, exponential backoff with recovery
- **Graceful shutdown** — Ctrl+C flushes audit logs, no data loss
- **Full audit trail** — every action logged as JSONL with operator identity

<br>

## 🧠 Learning Database

SleepyWalker maintains a persistent learning database at `~/.sleepywalker/learningdb.json` that gets smarter with every scan.

### What It Learns

| Category | What's Stored | Impact |
|---|---|---|
| **Error signatures** | New DB error patterns not in the built-in list | Detected on future scans automatically |
| **Successful payloads** | Payloads that confirmed SQLi, scored by success rate | Prioritised in future probes |
| **WAF fingerprints** | WAF header/body patterns seen in the wild | Faster WAF detection |
| **Host profiles** | Per-host: DB engine, WAF, injectable params | Skip known-clean endpoints on rescan |
| **False positives** | Host+param combos that fired but weren't injectable | Skipped after 5 false hits |

### How It Enriches Scanning

```
First scan:   Built-in 10 payloads → 1 confirmed → DB records the winning payload
Second scan:  11 payloads (built-in + learned) → winning payload tried first
Tenth scan:   Learned payloads with >80% hit rate sorted to front → faster detection
```

### Controlling the DB

```bash
# Use a custom DB path (useful for team-shared DBs)
sleepywalker -url https://target.internal -ldb-path /shared/team-learningdb.json

# Default path
~/.sleepywalker/learningdb.json   (Linux/macOS)
%APPDATA%\.sleepywalker\learningdb.json   (Windows)
```

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
depth        = 3
threads      = 8
delay_ms     = 200
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
command = "python3"
args    = "scripts/notify_slack.py"
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
| `-depth` | `0` | Crawl depth (0 = unlimited) |
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
| `-ldb-path` | `~/.sleepywalker/learningdb.json` | Learning DB path |

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

<br>

## 📊 Output Formats

| Format | Use Case | Integration |
|---|---|---|
| **HTML** | Human-readable report with dark UI | Email, browser |
| **JSON** | Machine processing, dashboards | SIEM, custom tooling |
| **SARIF 2.1.0** | CI/CD security gates | GitHub Code Scanning, Azure DevOps, Jira |

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

## 🤖 MCP Server

SleepyWalker ships a Model Context Protocol server so AI agents (Claude, Amazon Q, etc.) can invoke scan capabilities as tools.

```bash
go build -o sleepywalker-mcp ./mcp/
```

Register in your MCP client config:

```json
{
  "mcpServers": {
    "sleepywalker": {
      "command": "/path/to/sleepywalker-mcp"
    }
  }
}
```

**Tools exposed:** `sleepywalker_scan` • `sleepywalker_discover` • `sleepywalker_waf_detect` • `sleepywalker_validate` • `sleepywalker_report`

<br>

## 🏗️ Architecture

```
SleepyWalker/
├── cmd/main.go                      # CLI + pipeline orchestration
├── mcp/main.go                      # MCP server for AI agent integration
├── internal/
│   ├── config/
│   │   ├── config.go                # Runtime config, scope validation, TLS
│   │   └── configfile.go            # TOML config loader + CLI merge
│   ├── hooks/hooks.go               # Plugin/hook lifecycle system
│   ├── learningdb/db.go             # Persistent learning database
│   ├── scanner/
│   │   ├── scanner.go               # Crawl engine (HTML + recursive)
│   │   ├── jscrawl.go               # Headless browser (chromedp)
│   │   ├── swagger.go               # OpenAPI/Swagger parser
│   │   ├── heuristic.go             # Phase 1: payload injection + learning
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

# Team-shared learning DB
sleepywalker -url https://target.internal \
  -ldb-path /team-share/sleepywalker-learningdb.json
```

<br>

## 🤝 Contributing

1. Fork it
2. Create your feature branch (`git checkout -b feat/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

**Areas where help is appreciated:**
- Additional WAF bypass techniques
- New deep validation heuristics
- Integration hooks for more platforms
- Learning DB export/import tooling

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

**Go** • **OpenRouter AI** • **sqlmap** • **chromedp** • **MCP**

</div>
