package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sleepywalker/internal/config"
	"sleepywalker/internal/scanner"
)

// ═══════════════════════════════════════════════════════════════════════
// MCP Protocol Types (JSON-RPC 2.0 over stdio)
// ═══════════════════════════════════════════════════════════════════════

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
}

type Capabilities struct {
	Tools *ToolsCapability `json:"tools,omitempty"`
}

type ToolsCapability struct{}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
	Required   []string            `json:"required,omitempty"`
}

type Property struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Default     interface{} `json:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
}

type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

type CallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type ToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ═══════════════════════════════════════════════════════════════════════
// Tool Definitions
// ═══════════════════════════════════════════════════════════════════════

var tools = []Tool{
	{
		Name:        "sleepywalker_scan",
		Description: "Run a full SleepyWalker SQL injection scan against a target URL. Defaults to dry-run (no exploitation). Set dry_run=false only for authorized engagements.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"url":           {Type: "string", Description: "Target URL to scan for SQL injection"},
				"depth":         {Type: "integer", Description: "Crawl depth (0 = single page)", Default: 0},
				"threads":       {Type: "integer", Description: "Concurrent scan threads", Default: 4},
				"dry_run":       {Type: "boolean", Description: "If true, stops after Phase 2 (no exploitation)", Default: true},
				"output_format": {Type: "string", Description: "Report format", Default: "json", Enum: []string{"html", "json", "sarif", "all"}},
				"max_requests":  {Type: "integer", Description: "Maximum HTTP requests (0 = unlimited)", Default: 1000},
				"scope":         {Type: "string", Description: "Regex scope restriction for allowed URLs"},
			},
			Required: []string{"url"},
		},
	},
	{
		Name:        "sleepywalker_discover",
		Description: "Crawl a target URL and discover injectable entry points. Does NOT inject payloads — safe for reconnaissance.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"url":       {Type: "string", Description: "Target URL to crawl"},
				"depth":     {Type: "integer", Description: "Crawl depth (0 = single page)", Default: 1},
				"js_render": {Type: "boolean", Description: "Use headless browser for JS-heavy pages", Default: false},
			},
			Required: []string{"url"},
		},
	},
	{
		Name:        "sleepywalker_waf_detect",
		Description: "Detect WAF protecting a target URL. Returns WAF name, fingerprint, and suggested bypass techniques.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"url": {Type: "string", Description: "Target URL to fingerprint for WAF"},
			},
			Required: []string{"url"},
		},
	},
	{
		Name:        "sleepywalker_validate",
		Description: "Deep offline validation on a specific endpoint parameter using 10 techniques (boolean-blind, time-blind, error-based, UNION, etc.).",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"url":           {Type: "string", Description: "Target endpoint URL"},
				"method":        {Type: "string", Description: "HTTP method", Default: "GET", Enum: []string{"GET", "POST"}},
				"param":         {Type: "string", Description: "Parameter name to test (e.g. 'id', 'search')"},
				"injection_loc": {Type: "string", Description: "Injection location", Default: "query", Enum: []string{"query", "body", "header", "json"}},
			},
			Required: []string{"url", "param"},
		},
	},
	{
		Name:        "sleepywalker_report",
		Description: "Read and return the JSON report from a previous scan.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"target_url": {Type: "string", Description: "Target URL that was scanned"},
			},
			Required: []string{"target_url"},
		},
	},
}

// ═══════════════════════════════════════════════════════════════════════
// MCP Server
// ═══════════════════════════════════════════════════════════════════════

func main() {
	log.SetOutput(os.Stderr)
	log.Println("[MCP] SleepyWalker MCP server starting (stdio transport)")

	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}
		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		resp := handleRequest(req)
		if resp != nil {
			data, _ := json.Marshal(resp)
			fmt.Fprintf(os.Stdout, "%s\n", data)
		}
	}
}

func handleRequest(req JSONRPCRequest) *JSONRPCResponse {
	switch req.Method {
	case "initialize":
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: InitializeResult{
				ProtocolVersion: "2024-11-05",
				Capabilities:    Capabilities{Tools: &ToolsCapability{}},
				ServerInfo:      ServerInfo{Name: "sleepywalker-mcp", Version: "2.0.0"},
			},
		}
	case "notifications/initialized":
		log.Println("[MCP] Client initialized")
		return nil
	case "tools/list":
		return &JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: ToolsListResult{Tools: tools}}
	case "tools/call":
		var params CallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return errorResponse(req.ID, -32602, "Invalid params")
		}
		return &JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: executeTool(params)}
	default:
		return errorResponse(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func errorResponse(id interface{}, code int, msg string) *JSONRPCResponse {
	return &JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &RPCError{Code: code, Message: msg}}
}

// ═══════════════════════════════════════════════════════════════════════
// Tool Execution
// ═══════════════════════════════════════════════════════════════════════

func executeTool(params CallToolParams) ToolResult {
	switch params.Name {
	case "sleepywalker_scan":
		return execScan(params.Arguments)
	case "sleepywalker_discover":
		return execDiscover(params.Arguments)
	case "sleepywalker_waf_detect":
		return execWAFDetect(params.Arguments)
	case "sleepywalker_validate":
		return execValidate(params.Arguments)
	case "sleepywalker_report":
		return execReport(params.Arguments)
	default:
		return toolError(fmt.Sprintf("Unknown tool: %s", params.Name))
	}
}

func execScan(args map[string]interface{}) ToolResult {
	targetURL, _ := args["url"].(string)
	if targetURL == "" {
		return toolError("url is required")
	}

	// Fix #14: build args as a proper slice — never use strings.Fields on
	// user-supplied values, which enables command injection via URL metacharacters.
	cliArgs := []string{"-url", targetURL, "-output-format", "json"}

	if depth, ok := args["depth"].(float64); ok && depth > 0 {
		cliArgs = append(cliArgs, "-depth", fmt.Sprintf("%d", int(depth)))
	}
	if threads, ok := args["threads"].(float64); ok && threads > 0 {
		cliArgs = append(cliArgs, "-threads", fmt.Sprintf("%d", int(threads)))
	}
	if maxReq, ok := args["max_requests"].(float64); ok && maxReq > 0 {
		cliArgs = append(cliArgs, "-max-requests", fmt.Sprintf("%d", int(maxReq)))
	}
	// scope is a regex string — passed as its own argument, never shell-expanded.
	if scope, ok := args["scope"].(string); ok && scope != "" {
		cliArgs = append(cliArgs, "-scope", scope)
	}
	// Default to dry-run for safety; only disable if caller explicitly passes false.
	dryRun := true
	if v, ok := args["dry_run"].(bool); ok {
		dryRun = v
	}
	if dryRun {
		cliArgs = append(cliArgs, "-dry-run")
	}

	// Fix #3: support OPENROUTER_API_KEY env var so MCP callers can pass a key
	// without triggering the interactive terminal prompt.
	exe := findSleepyWalker()
	scanCtx, scanCancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer scanCancel()
	cmd := exec.CommandContext(scanCtx, exe, cliArgs...)
	cmd.Env = os.Environ() // inherit env, including OPENROUTER_API_KEY if set
	cmd.Stdin = strings.NewReader("\n")

	log.Printf("[MCP] Running scan: sleepywalker %s", strings.Join(cliArgs, " "))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return toolError(fmt.Sprintf("Scan failed: %v\nOutput: %s", err, string(output)))
	}

	if content := readReportForTarget(targetURL); content != "" {
		return toolText(content)
	}
	return toolText(string(output))
}

func execDiscover(args map[string]interface{}) ToolResult {
	targetURL, _ := args["url"].(string)
	if targetURL == "" {
		return toolError("url is required")
	}

	depth := 1
	if d, ok := args["depth"].(float64); ok {
		depth = int(d)
	}

	cfg := &config.Config{CrawlDepth: depth, Threads: 4, RateDelay: 100 * time.Millisecond}
	eps, err := scanner.CrawlAndDiscover(cfg, targetURL)
	if err != nil {
		return toolError(fmt.Sprintf("Discovery failed: %v", err))
	}

	type epOut struct {
		Method       string   `json:"method"`
		URL          string   `json:"url"`
		Params       []string `json:"params"`
		InjectionLoc string   `json:"injection_location"`
	}
	var results []epOut
	for _, ep := range eps {
		params := make([]string, 0, len(ep.Params))
		for k := range ep.Params {
			params = append(params, k)
		}
		results = append(results, epOut{ep.Method, ep.URL, params, ep.InjectionLoc})
	}

	data, _ := json.MarshalIndent(map[string]interface{}{
		"target":       targetURL,
		"entry_points": len(results),
		"endpoints":    results,
	}, "", "  ")
	return toolText(string(data))
}

func execWAFDetect(args map[string]interface{}) ToolResult {
	targetURL, _ := args["url"].(string)
	if targetURL == "" {
		return toolError("url is required")
	}

	cfg := &config.Config{Threads: 4}
	result := scanner.DetectWAF(cfg, targetURL)

	data, _ := json.MarshalIndent(map[string]interface{}{
		"target":      targetURL,
		"detected":    result.Detected,
		"waf_name":    result.WAFName,
		"fingerprint": result.Fingerprint,
		"bypasses":    result.Bypass,
	}, "", "  ")
	return toolText(string(data))
}

func execValidate(args map[string]interface{}) ToolResult {
	targetURL, _ := args["url"].(string)
	param, _ := args["param"].(string)
	if targetURL == "" || param == "" {
		return toolError("url and param are required")
	}

	method := "GET"
	if m, ok := args["method"].(string); ok && m != "" {
		method = strings.ToUpper(m)
	}
	injLoc := "query"
	if loc, ok := args["injection_loc"].(string); ok && loc != "" {
		injLoc = loc
	}

	ep := scanner.EntryPoint{
		Method:       method,
		URL:          targetURL,
		Params:       map[string]string{param: "1"},
		InjectionLoc: injLoc,
	}

	cfg := &config.Config{Threads: 1, RateDelay: 200 * time.Millisecond}
	hResults := scanner.HeuristicScan(cfg, []scanner.EntryPoint{ep}, nil)

	var suspicious []scanner.HeuristicResult
	for _, hr := range hResults {
		if hr.Suspicious {
			suspicious = append(suspicious, hr)
		}
	}

	if len(suspicious) == 0 {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"target": targetURL, "param": param,
			"confirmed": false,
			"message":   "No SQL error signatures detected in heuristic probe",
		}, "", "  ")
		return toolText(string(data))
	}

	deepResults := scanner.DeepValidate(context.Background(), cfg, suspicious, nil)
	if len(deepResults) == 0 {
		return toolText(`{"confirmed": false, "message": "Deep validation returned no results"}`)
	}

	dr := deepResults[0]
	data, _ := json.MarshalIndent(map[string]interface{}{
		"target":       targetURL,
		"param":        param,
		"confirmed":    dr.Confirmed,
		"confidence":   dr.Confidence,
		"techniques":   dr.Techniques,
		"best_payload": dr.BestPayload,
		"db_engine":    dr.DBEngine,
	}, "", "  ")
	return toolText(string(data))
}

func execReport(args map[string]interface{}) ToolResult {
	targetURL, _ := args["target_url"].(string)
	if targetURL == "" {
		return toolError("target_url is required")
	}
	content := readReportForTarget(targetURL)
	if content == "" {
		return toolError(fmt.Sprintf("No JSON report found for target: %s", targetURL))
	}
	return toolText(content)
}

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

func toolText(text string) ToolResult {
	return ToolResult{Content: []ContentBlock{{Type: "text", Text: text}}}
}

func toolError(msg string) ToolResult {
	return ToolResult{Content: []ContentBlock{{Type: "text", Text: msg}}, IsError: true}
}

func findSleepyWalker() string {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	for _, c := range []string{
		filepath.Join(dir, "sleepywalker.exe"),
		filepath.Join(dir, "sleepywalker"),
		"sleepywalker",
	} {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
	}
	return "sleepywalker"
}

// sanitizeHost replicates the logic in fileutils.CreateTargetDir so the MCP
// server finds the report in the same directory that the scanner created.
// Fix #1: colons (ports) are replaced with underscores, matching fileutils.sanitize.
var unsafeChars = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

func sanitizeHost(host string) string {
	host = strings.ReplaceAll(host, ":", "_")
	return unsafeChars.ReplaceAllString(host, "_")
}

func readReportForTarget(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	host := sanitizeHost(u.Host)
	if host == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(".", "dumps", host, "report.json"))
	if err != nil {
		return ""
	}
	return string(data)
}
