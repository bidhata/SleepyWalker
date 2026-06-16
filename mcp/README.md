# SleepyWalker MCP Server

Model Context Protocol (MCP) server that exposes SleepyWalker's SQL injection scanning capabilities as tools for LLMs.

## Setup

### Build

```bash
cd SleepyWalker
go build -o sleepywalker-mcp ./mcp/
```

### Register with your MCP client

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "sleepywalker": {
      "command": "/path/to/sleepywalker-mcp"
    }
  }
}
```

**Amazon Q Developer** (`.amazonq/mcp.json`):
```json
{
  "mcpServers": {
    "sleepywalker": {
      "command": "/path/to/sleepywalker-mcp",
      "transportType": "stdio"
    }
  }
}
```

## Tools Exposed

| Tool | Description | Safe? |
|---|---|---|
| `sleepywalker_discover` | Crawl and discover injectable endpoints | ✅ Read-only |
| `sleepywalker_waf_detect` | Fingerprint WAF protecting target | ✅ Passive |
| `sleepywalker_validate` | Deep offline validation (10 techniques) | ⚠️ Active probing |
| `sleepywalker_scan` | Full scan pipeline (defaults to dry-run) | ⚠️ Active (dry-run safe) |
| `sleepywalker_report` | Read a previous scan's JSON report | ✅ Local file read |

## Tool Details

### sleepywalker_discover

Crawls a URL and returns all discovered entry points (forms, query params, headers, JSON endpoints). Does NOT inject any payloads.

```
Input: { "url": "https://target.internal", "depth": 2 }
Output: JSON with entry points, methods, params, injection locations
```

### sleepywalker_waf_detect

Sends a test request to fingerprint WAF presence. Returns WAF name and bypass suggestions.

```
Input: { "url": "https://target.internal" }
Output: { "detected": true, "waf_name": "Cloudflare", "bypasses": [...] }
```

### sleepywalker_validate

Performs deep offline validation against a specific parameter. Uses boolean-blind, time-blind, error-based, UNION, and 6 other techniques.

```
Input: { "url": "https://target.internal/api?id=1", "param": "id" }
Output: { "confirmed": true, "confidence": 0.87, "techniques": [...], "db_engine": "MySQL" }
```

### sleepywalker_scan

Runs the full SleepyWalker pipeline. **Defaults to dry-run mode** when invoked via MCP for safety — no exploitation occurs unless explicitly set.

```
Input: { "url": "https://target.internal", "dry_run": true, "max_requests": 500 }
Output: Full JSON report with findings
```

### sleepywalker_report

Reads a previously generated JSON report from disk.

```
Input: { "target_url": "https://target.internal" }
Output: Full JSON report content
```

## Security Notes

- The MCP server **defaults to dry-run mode** for scan operations
- Exploitation (Phase 3) requires `dry_run: false` to be explicitly set
- All operations respect scope restrictions if configured
- The MCP server logs to stderr for debugging

## Example Conversation

> "Discover all injectable endpoints on https://staging.myapp.com"

The LLM invokes `sleepywalker_discover` and returns a structured list of forms, query parameters, and API endpoints.

> "Check if the `id` parameter on /api/users is vulnerable to SQL injection"

The LLM invokes `sleepywalker_validate` with the URL and param, gets back a confidence score and technique breakdown.

> "Is there a WAF on production.myapp.com?"

The LLM invokes `sleepywalker_waf_detect` and reports the WAF type with bypass suggestions.
