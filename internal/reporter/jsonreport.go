package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sleepywalker/internal/utils"
)

// JSONReport is the machine-readable report format.
type JSONReport struct {
	Meta     ReportMeta       `json:"meta"`
	Summary  ReportSummary    `json:"summary"`
	Findings []JSONFinding    `json:"findings"`
}

type ReportMeta struct {
	ToolName     string `json:"tool_name"`
	ToolVersion  string `json:"tool_version"`
	TargetURL    string `json:"target_url"`
	Operator     string `json:"operator,omitempty"`
	EngagementID string `json:"engagement_id,omitempty"`
	StartTime    string `json:"start_time"`
	EndTime      string `json:"end_time"`
	TotalReqs    int64  `json:"total_requests"`
}

type ReportSummary struct {
	TotalEndpoints int `json:"total_endpoints"`
	Suspicious     int `json:"suspicious"`
	Confirmed      int `json:"confirmed"`
	Exploited      int `json:"exploited"`
}

type JSONFinding struct {
	Method          string   `json:"method"`
	URL             string   `json:"url"`
	Params          []string `json:"params"`
	InjectionLoc    string   `json:"injection_location"`
	Vulnerable      bool     `json:"vulnerable"`
	HeuristicMatch  bool     `json:"heuristic_match"`
	AIConfirmed     bool     `json:"ai_confirmed"`
	ConfirmMethod   string   `json:"confirm_method,omitempty"`
	Confidence      float64  `json:"confidence,omitempty"`
	Payload         string   `json:"payload,omitempty"`
	DumpPaths       []string `json:"dump_paths,omitempty"`
	ExploitError    string   `json:"exploit_error,omitempty"`
	HeuristicErrors []string `json:"heuristic_errors,omitempty"`
	WAFDetected     bool     `json:"waf_detected"`
	WAFName         string   `json:"waf_name,omitempty"`
	CWE             string   `json:"cwe"`
	CVSS            float64  `json:"cvss_score"`
	Severity        string   `json:"severity"`
}

// GenerateJSONReport produces a machine-readable JSON report.
func GenerateJSONReport(targetURL string, results []ScanResult, outputDir string) (string, error) {
	operator, engagement, startTime, reqCount := utils.GetAuditMeta()

	suspicious, confirmed, exploited := 0, 0, 0
	var findings []JSONFinding
	for _, r := range results {
		if r.HeuristicMatch {
			suspicious++
		}
		if r.AIConfirmed {
			confirmed++
		}
		if r.Vulnerable && len(r.DumpPaths) > 0 {
			exploited++
		}

		params := make([]string, 0, len(r.Entry.Params))
		for k := range r.Entry.Params {
			params = append(params, k)
		}

		f := JSONFinding{
			Method:          r.Entry.Method,
			URL:             r.Entry.URL,
			Params:          params,
			InjectionLoc:    r.Entry.InjectionLoc,
			Vulnerable:      r.Vulnerable,
			HeuristicMatch:  r.HeuristicMatch,
			AIConfirmed:     r.AIConfirmed,
			ConfirmMethod:   r.ConfirmMethod,
			Confidence:      r.Confidence,
			Payload:         r.Payload,
			DumpPaths:       r.DumpPaths,
			ExploitError:    r.ExploitError,
			HeuristicErrors: r.HeuristicErrors,
			WAFDetected:     r.WAFDetected,
			WAFName:         r.WAFName,
			CWE:             "CWE-89",
			CVSS:            9.8,
			Severity:        "Critical",
		}
		if !r.Vulnerable {
			f.CWE = ""
			f.CVSS = 0
			f.Severity = "None"
		}
		findings = append(findings, f)
	}

	startStr := ""
	if !startTime.IsZero() {
		startStr = startTime.Format(time.RFC3339)
	}

	report := JSONReport{
		Meta: ReportMeta{
			ToolName:     "SleepyWalker",
			ToolVersion:  "2.0",
			TargetURL:    targetURL,
			Operator:     operator,
			EngagementID: engagement,
			StartTime:    startStr,
			EndTime:      time.Now().UTC().Format(time.RFC3339),
			TotalReqs:    reqCount,
		},
		Summary: ReportSummary{
			TotalEndpoints: len(results),
			Suspicious:     suspicious,
			Confirmed:      confirmed,
			Exploited:      exploited,
		},
		Findings: findings,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON marshal failed: %w", err)
	}

	reportPath := filepath.Join(outputDir, "report.json")
	if err := os.WriteFile(reportPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write JSON report: %w", err)
	}
	return reportPath, nil
}

// SARIFReport is the OASIS SARIF v2.1.0 format for tool integration.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription SARIFMessage        `json:"shortDescription"`
	Properties       SARIFRuleProperties `json:"properties,omitempty"`
}

type SARIFRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifact `json:"artifactLocation"`
}

type SARIFArtifact struct {
	URI string `json:"uri"`
}

// GenerateSARIFReport produces a SARIF 2.1.0 report for CI/CD integration.
func GenerateSARIFReport(targetURL string, results []ScanResult, outputDir string) (string, error) {
	rules := []SARIFRule{
		{
			ID:               "CWE-89",
			Name:             "SQL Injection",
			ShortDescription: SARIFMessage{Text: "SQL Injection vulnerability detected"},
			Properties:       SARIFRuleProperties{Tags: []string{"security", "sql-injection", "CWE-89"}},
		},
	}

	var sarifResults []SARIFResult
	for _, r := range results {
		if !r.Vulnerable {
			continue
		}
		msg := fmt.Sprintf("SQL Injection confirmed at %s %s [%s]", r.Entry.Method, r.Entry.URL, r.Entry.InjectionLoc)
		if r.Payload != "" {
			msg += fmt.Sprintf(" — payload: %s", r.Payload)
		}
		sarifResults = append(sarifResults, SARIFResult{
			RuleID:  "CWE-89",
			Level:   "error",
			Message: SARIFMessage{Text: msg},
			Locations: []SARIFLocation{
				{PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifact{URI: r.Entry.URL},
				}},
			},
		})
	}

	report := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{Driver: SARIFDriver{
					Name:    "SleepyWalker",
					Version: "2.0",
					Rules:   rules,
				}},
				Results: sarifResults,
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("SARIF marshal failed: %w", err)
	}

	reportPath := filepath.Join(outputDir, "report.sarif.json")
	if err := os.WriteFile(reportPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write SARIF report: %w", err)
	}
	return reportPath, nil
}
