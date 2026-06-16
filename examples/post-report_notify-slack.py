#!/usr/bin/env python3
"""
Example post-report hook: Send scan summary to Slack webhook.

Hook scripts receive the HookContext as JSON on stdin:
{
  "phase": "post-report",
  "target_url": "https://target.internal",
  "operator": "jsmith",
  "engagement_id": "PT-2024-042",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {"reports": ["./dumps/.../report.html"], "output_dir": "..."}
}

Place this in your hooks directory as: post-report_notify-slack.py
Or reference it in your TOML config under [[hooks]].
"""

import json
import sys
import urllib.request

SLACK_WEBHOOK = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

def main():
    ctx = json.load(sys.stdin)
    
    reports = ctx.get("data", {}).get("reports", [])
    msg = {
        "text": f":shield: *SleepyWalker Scan Complete*\n"
                f"• Target: `{ctx['target_url']}`\n"
                f"• Operator: {ctx['operator']}\n"
                f"• Engagement: {ctx['engagement_id']}\n"
                f"• Reports: {len(reports)} file(s) generated\n"
                f"• Timestamp: {ctx['timestamp']}"
    }
    
    req = urllib.request.Request(
        SLACK_WEBHOOK,
        data=json.dumps(msg).encode(),
        headers={"Content-Type": "application/json"}
    )
    
    try:
        urllib.request.urlopen(req)
        print("[hook] Slack notification sent")
    except Exception as e:
        print(f"[hook] Slack notification failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
