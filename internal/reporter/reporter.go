package reporter

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sleepywalker/internal/scanner"
	"sleepywalker/internal/utils"
)

// ScanResult holds the final verdict for a single entry point across all phases.
type ScanResult struct {
	Entry           scanner.EntryPoint
	Vulnerable      bool
	DumpPaths       []string
	Payload         string
	ExploitError    string
	HeuristicMatch  bool
	HeuristicErrors []string
	AIConfirmed     bool
	ConfirmMethod   string  // "AI" or "deep-local"
	Confidence      float64 // 0.0–1.0 confidence score
	WAFDetected     bool
	WAFName         string
}

// templateData is passed to the HTML template.
type templateData struct {
	TargetURL    string
	GeneratedAt  string
	TotalEPs     int
	Suspicious   int
	AIConfirmed  int
	Exploited    int
	Results      []ScanResult
	Operator     string
	EngagementID string
	TotalReqs    int64
	Duration     string
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SleepyWalker Report — {{.TargetURL}}</title>
<style>
  :root {
    --bg: #0f1117;
    --card: #1a1d27;
    --border: #2a2d3a;
    --text: #e4e6f0;
    --muted: #8b8fa3;
    --accent: #6c5ce7;
    --green: #00b894;
    --red: #ff6b6b;
    --orange: #fdcb6e;
    --blue: #74b9ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
  }
  .container { max-width: 1100px; margin: 0 auto; }
  header {
    text-align: center;
    margin-bottom: 2.5rem;
    padding: 2rem;
    background: linear-gradient(135deg, #1a1d27 0%, #2d1b69 100%);
    border-radius: 16px;
    border: 1px solid var(--border);
  }
  header h1 {
    font-size: 2rem;
    background: linear-gradient(90deg, #a29bfe, #6c5ce7, #fd79a8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0.25rem;
  }
  header .target {
    color: var(--muted);
    font-size: 0.95rem;
    word-break: break-all;
  }
  header .timestamp {
    color: var(--muted);
    font-size: 0.8rem;
    margin-top: 0.5rem;
  }

  /* Summary cards */
  .summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .stat-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem;
    text-align: center;
    transition: transform 0.2s, box-shadow 0.2s;
  }
  .stat-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 24px rgba(108, 92, 231, 0.15);
  }
  .stat-card .number {
    font-size: 2.5rem;
    font-weight: 700;
  }
  .stat-card .label {
    font-size: 0.85rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .stat-card.total .number { color: var(--blue); }
  .stat-card.suspicious .number { color: var(--orange); }
  .stat-card.confirmed .number { color: var(--red); }
  .stat-card.exploited .number { color: var(--green); }

  /* Phase badges */
  .phase-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin: 2rem 0 1rem 0;
    font-size: 1.1rem;
    font-weight: 600;
  }
  .phase-badge {
    display: inline-block;
    padding: 0.2rem 0.7rem;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .phase-badge.heuristic { background: rgba(253, 203, 110, 0.15); color: var(--orange); }
  .phase-badge.ai        { background: rgba(108, 92, 231, 0.15); color: var(--accent); }
  .phase-badge.exploit    { background: rgba(255, 107, 107, 0.15); color: var(--red); }

  /* Results table */
  table {
    width: 100%;
    border-collapse: collapse;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    margin-bottom: 1.5rem;
  }
  th, td {
    padding: 0.85rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }
  th {
    background: rgba(108, 92, 231, 0.08);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--muted);
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(108, 92, 231, 0.04); }

  /* Status pills */
  .pill {
    display: inline-block;
    padding: 0.15rem 0.6rem;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
  }
  .pill.safe    { background: rgba(0, 184, 148, 0.12); color: var(--green); }
  .pill.suspect { background: rgba(253, 203, 110, 0.12); color: var(--orange); }
  .pill.vuln    { background: rgba(255, 107, 107, 0.12); color: var(--red); }
  .pill.error   { background: rgba(255, 107, 107, 0.08); color: #e17055; }

  .mono { font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.85rem; }
  .dump-list { list-style: none; padding: 0; }
  .dump-list li {
    padding: 0.25rem 0;
    font-size: 0.82rem;
    color: var(--muted);
    word-break: break-all;
  }
  .dump-list li::before { content: '📄 '; }

  footer {
    text-align: center;
    color: var(--muted);
    font-size: 0.8rem;
    margin-top: 3rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
  }

  /* Recommendation section */
  .recommendations {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    margin-top: 2rem;
  }
  .recommendations h2 {
    font-size: 1.1rem;
    margin-bottom: 1rem;
    color: var(--accent);
  }
  .recommendations ul {
    padding-left: 1.25rem;
    color: var(--muted);
  }
  .recommendations li { margin-bottom: 0.5rem; }
</style>
</head>
<body>
<div class="container">

<header>
  <h1>🛡️ SleepyWalker Scan Report</h1>
  <div class="target">Target: {{.TargetURL}}</div>
  <div class="timestamp">Generated: {{.GeneratedAt}}</div>
  {{if .Operator}}<div class="timestamp">Operator: {{.Operator}} | Engagement: {{.EngagementID}}</div>{{end}}
  {{if .TotalReqs}}<div class="timestamp">Requests: {{.TotalReqs}} | Duration: {{.Duration}}</div>{{end}}
</header>

<div class="summary">
  <div class="stat-card total">
    <div class="number">{{.TotalEPs}}</div>
    <div class="label">Entry Points</div>
  </div>
  <div class="stat-card suspicious">
    <div class="number">{{.Suspicious}}</div>
    <div class="label">Heuristic Flags</div>
  </div>
  <div class="stat-card confirmed">
    <div class="number">{{.AIConfirmed}}</div>
    <div class="label">AI Confirmed</div>
  </div>
  <div class="stat-card exploited">
    <div class="number">{{.Exploited}}</div>
    <div class="label">Exploited</div>
  </div>
</div>

<div class="phase-header">
  <span class="phase-badge heuristic">Phase 1</span> Local Heuristic Scan →
  <span class="phase-badge ai">Phase 2</span> AI Analysis →
  <span class="phase-badge exploit">Phase 3</span> sqlmap Exploitation
</div>

<table>
  <thead>
    <tr>
      <th>Method</th>
      <th>URL</th>
      <th>Params</th>
      <th>Heuristic</th>
      <th>AI</th>
      <th>Status</th>
      <th>Details</th>
    </tr>
  </thead>
  <tbody>
    {{range .Results}}
    <tr>
      <td class="mono">{{.Entry.Method}}</td>
      <td class="mono" style="max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="{{.Entry.URL}}">{{.Entry.URL}}</td>
      <td class="mono">{{joinParams .Entry.Params}}</td>
      <td>
        {{if .HeuristicMatch}}<span class="pill suspect">Flagged</span>
        {{else}}<span class="pill safe">Clean</span>{{end}}
      </td>
      <td>
        {{if .AIConfirmed}}<span class="pill vuln">Confirmed</span>
        {{else if .HeuristicMatch}}<span class="pill safe">Not Confirmed</span>
        {{else}}—{{end}}
      </td>
      <td>
        {{if and .Vulnerable (gt (len .DumpPaths) 0)}}<span class="pill vuln">Exploited</span>
        {{else if and .Vulnerable (ne .ExploitError "")}}<span class="pill error">Failed</span>
        {{else if .Vulnerable}}<span class="pill vuln">Vulnerable</span>
        {{else}}<span class="pill safe">Safe</span>{{end}}
      </td>
      <td>
        {{if .Payload}}<strong>Payload:</strong> <span class="mono">{{.Payload}}</span><br>{{end}}
        {{if .ExploitError}}<strong>Error:</strong> {{.ExploitError}}<br>{{end}}
        {{if .DumpPaths}}
          <strong>Dumps:</strong>
          <ul class="dump-list">
            {{range .DumpPaths}}<li>{{.}}</li>{{end}}
          </ul>
        {{end}}
        {{if .HeuristicErrors}}
          <strong>Signatures:</strong> {{joinErrors .HeuristicErrors}}
        {{end}}
      </td>
    </tr>
    {{end}}
  </tbody>
</table>

{{if hasVulnerables .Results}}
<div class="recommendations">
  <h2>🔧 Recommendations</h2>
  <ul>
    <li>Use <strong>parameterised queries</strong> (prepared statements) for all database interactions.</li>
    <li>Apply <strong>input validation</strong> and whitelist-based filtering on all user-supplied data.</li>
    <li>Implement a <strong>Web Application Firewall (WAF)</strong> to catch common injection patterns.</li>
    <li>Run the application's database user with <strong>least-privilege</strong> permissions.</li>
    <li>Conduct regular <strong>code reviews</strong> focusing on dynamic query construction.</li>
    <li>Enable <strong>SQL error suppression</strong> in production — do not expose raw database errors to users.</li>
  </ul>
</div>
{{end}}

<footer>
  SleepyWalker — Internal Red Team SQL Injection Scanner<br>
  For authorized penetration testing only.
</footer>

</div>
</body>
</html>`

// GenerateHTMLReport renders the scan results into a polished HTML file.
func GenerateHTMLReport(targetURL string, results []ScanResult, outputDir string) (string, error) {
	funcMap := template.FuncMap{
		"joinParams": func(params map[string]string) string {
			keys := make([]string, 0, len(params))
			for k := range params {
				keys = append(keys, k)
			}
			return strings.Join(keys, ", ")
		},
		"joinErrors": func(errs []string) string {
			return strings.Join(errs, "; ")
		},
		"hasVulnerables": func(rs []ScanResult) bool {
			for _, r := range rs {
				if r.Vulnerable {
					return true
				}
			}
			return false
		},
		"gt": func(a, b int) bool { return a > b },
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse report template: %w", err)
	}

	// Compute summary stats.
	suspicious, aiConfirmed, exploited := 0, 0, 0
	for _, r := range results {
		if r.HeuristicMatch {
			suspicious++
		}
		if r.AIConfirmed {
			aiConfirmed++
		}
		if r.Vulnerable && len(r.DumpPaths) > 0 {
			exploited++
		}
	}

	operator, engagement, startTime, reqCount := utils.GetAuditMeta()
	duration := ""
	if !startTime.IsZero() {
		duration = time.Since(startTime).Round(time.Second).String()
	}

	data := templateData{
		TargetURL:    targetURL,
		GeneratedAt:  time.Now().Format("2006-01-02 15:04:05 MST"),
		TotalEPs:     len(results),
		Suspicious:   suspicious,
		AIConfirmed:  aiConfirmed,
		Exploited:    exploited,
		Results:      results,
		Operator:     operator,
		EngagementID: engagement,
		TotalReqs:    reqCount,
		Duration:     duration,
	}

	reportPath := filepath.Join(outputDir, "report.html")
	f, err := os.Create(reportPath)
	if err != nil {
		return "", fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return "", fmt.Errorf("failed to execute report template: %w", err)
	}
	return reportPath, nil
}
