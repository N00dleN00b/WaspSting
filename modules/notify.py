"""
modules/notify.py — Live notifications + GitHub Issues integration

Slack/Discord: post findings as they're discovered (webhook, no OAuth)
GitHub Issues: auto-create issues from findings (requires PAT)

Configure via environment variables or --config flag.
"""

import os
import json
import requests
from datetime import datetime

SEVERITY_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠",
    "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"
}
SEVERITY_COLORS = {
    "CRITICAL": 0xEF4444, "HIGH": 0xF97316,
    "MEDIUM":   0xEAB308, "LOW":  0x3B82F6, "INFO": 0x6B7280
}


# ── Slack ────────────────────────────────────────────────────────────────────

def notify_slack(webhook_url: str, finding: dict, session_id: str = ""):
    """Post a finding to a Slack channel via webhook."""
    sev = finding.get("severity", "INFO")
    emoji = SEVERITY_EMOJI.get(sev, "⚪")

    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *{sev}* — {finding.get('title', 'Finding')}\n"
                        f"*OWASP:* {finding.get('owasp_id', '?')} {finding.get('owasp_name', '')}\n"
                        f"*Module:* {finding.get('module', '?')}  |  "
                        f"*Session:* `{session_id}`"
                    )
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Description:*\n{finding.get('description', '')[:200]}"},
                    {"type": "mrkdwn", "text": f"*Fix:*\n{finding.get('fix', '')[:200]}"},
                ]
            }
        ]
    }

    if finding.get("evidence"):
        payload["blocks"].append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Evidence:*\n```{str(finding.get('evidence', ''))[:300]}```"
            }
        })

    try:
        r = requests.post(webhook_url, json=payload, timeout=8)
        return r.status_code == 200
    except Exception:
        return False


# ── Discord ──────────────────────────────────────────────────────────────────

def notify_discord(webhook_url: str, finding: dict, session_id: str = ""):
    """Post a finding to a Discord channel via webhook."""
    sev = finding.get("severity", "INFO")
    emoji = SEVERITY_EMOJI.get(sev, "⚪")
    color = SEVERITY_COLORS.get(sev, 0x6B7280)

    embed = {
        "title": f"{emoji} {sev} — {finding.get('title', 'Finding')[:200]}",
        "color": color,
        "fields": [
            {"name": "OWASP",
             "value": f"{finding.get('owasp_id','?')} {finding.get('owasp_name','')}",
             "inline": True},
            {"name": "Module",
             "value": finding.get("module", "?"),
             "inline": True},
            {"name": "Session",
             "value": f"`{session_id}`",
             "inline": True},
            {"name": "Description",
             "value": finding.get("description", "")[:300] or "—",
             "inline": False},
            {"name": "Fix",
             "value": finding.get("fix", "")[:300] or "—",
             "inline": False},
        ],
        "footer": {"text": "WaspSting by N00dleN00b"},
        "timestamp": finding.get("timestamp", datetime.now().isoformat())
    }

    if finding.get("evidence"):
        embed["fields"].append({
            "name": "Evidence",
            "value": f"```{str(finding.get('evidence',''))[:800]}```"[:1024],
            "inline": False
        })

    payload = {"embeds": [embed]}

    try:
        r = requests.post(webhook_url, json=payload, timeout=8)
        return r.status_code in (200, 204)
    except Exception:
        return False


# ── GitHub Issues ────────────────────────────────────────────────────────────

def create_github_issue(token: str, repo: str, finding: dict,
                         session_id: str = "") -> dict | None:
    """
    Create a GitHub issue from a finding.
    repo format: 'owner/repo-name'
    token: GitHub Personal Access Token with 'repo' scope
    """
    sev = finding.get("severity", "INFO")
    emoji = SEVERITY_EMOJI.get(sev, "⚪")

    title = f"{emoji} [{sev}] {finding.get('title', 'Security Finding')}"

    evidence_block = ""
    if finding.get("evidence"):
        evidence_block = f"""
## Evidence
```
{str(finding.get('evidence',''))[:1500]}
```"""

    doc_block = ""
    if finding.get("doc_template"):
        doc_block = f"""
## Documentation Template
```json
{json.dumps(finding.get('doc_template', {}), indent=2)[:800]}
```"""

    body = f"""## {emoji} {finding.get('owasp_id', '?')} — {finding.get('owasp_name', '')}

| Field | Value |
|-------|-------|
| **Severity** | {sev} |
| **Module** | {finding.get('module', '?')} |
| **Session** | `{session_id}` |
| **CWE** | {finding.get('cwe', '—')} |
| **File/URL** | `{finding.get('file') or finding.get('url', '—')}` |
| **Timestamp** | {finding.get('timestamp', '?')} |

## Description
{finding.get('description', '')}
{evidence_block}

## Remediation
{finding.get('fix', 'See OWASP guidelines')}
{doc_block}

---
*Generated by [WaspSting](https://github.com/N00dleN00b/waspsting) — Created by N00dleN00b*"""

    # Labels based on severity
    label_map = {
        "CRITICAL": ["security", "critical", "waspsting"],
        "HIGH":     ["security", "high-priority", "waspsting"],
        "MEDIUM":   ["security", "waspsting"],
        "LOW":      ["security", "waspsting"],
        "INFO":     ["security", "waspsting"],
    }

    payload = {
        "title": title[:256],
        "body": body[:65536],
        "labels": label_map.get(sev, ["security", "waspsting"])
    }

    try:
        r = requests.post(
            f"https://api.github.com/repos/{repo}/issues",
            json=payload,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "WaspSting/1.4"
            },
            timeout=10
        )
        if r.status_code == 201:
            return r.json()
    except Exception:
        pass
    return None


def ensure_github_labels(token: str, repo: str):
    """Create WaspSting labels in the repo if they don't exist."""
    labels = [
        {"name": "waspsting",     "color": "f9a825", "description": "WaspSting security finding"},
        {"name": "security",      "color": "e11d48", "description": "Security issue"},
        {"name": "critical",      "color": "7f1d1d", "description": "Critical severity"},
        {"name": "high-priority", "color": "dc2626", "description": "High severity"},
    ]
    for label in labels:
        try:
            requests.post(
                f"https://api.github.com/repos/{repo}/labels",
                json=label,
                headers={"Authorization": f"token {token}",
                         "Accept": "application/vnd.github.v3+json"},
                timeout=5
            )
        except Exception:
            pass


# ── Deduplication ────────────────────────────────────────────────────────────

def deduplicate_findings(new_findings: list[dict],
                          history_path: str) -> tuple[list[dict], list[dict]]:
    """
    Compare new findings against saved history.
    Returns: (truly_new, duplicates)
    History file: JSON array of finding fingerprints.
    """
    history_file = Path(history_path)
    seen_fingerprints: set[str] = set()

    if history_file.exists():
        try:
            data = json.loads(history_file.read_text())
            seen_fingerprints = set(data.get("fingerprints", []))
        except Exception:
            pass

    def fingerprint(f: dict) -> str:
        return (
            f"{f.get('owasp_id','?')}|"
            f"{f.get('title','')[:60]}|"
            f"{(f.get('file') or f.get('url',''))[:80]}"
        )

    truly_new = []
    duplicates = []
    new_fps = set()

    for finding in new_findings:
        fp = fingerprint(finding)
        if fp in seen_fingerprints:
            duplicates.append(finding)
        else:
            truly_new.append(finding)
            new_fps.add(fp)

    # Update history
    all_fps = list(seen_fingerprints | new_fps)
    history_file.parent.mkdir(parents=True, exist_ok=True)
    history_file.write_text(json.dumps({
        "fingerprints": all_fps,
        "last_updated": datetime.now().isoformat(),
        "total_seen": len(all_fps)
    }, indent=2))

    return truly_new, duplicates


# ── Notifier class — wraps all channels ──────────────────────────────────────

class Notifier:
    def __init__(self, config: dict, session_id: str = ""):
        self.slack_url    = config.get("slack_webhook") or os.environ.get("WASPSTING_SLACK_WEBHOOK")
        self.discord_url  = config.get("discord_webhook") or os.environ.get("WASPSTING_DISCORD_WEBHOOK")
        self.github_token = config.get("github_token") or os.environ.get("WASPSTING_GITHUB_TOKEN")
        self.github_repo  = config.get("github_repo") or os.environ.get("WASPSTING_GITHUB_REPO")
        self.session_id   = session_id
        self.min_severity = config.get("notify_min_severity", "MEDIUM")
        self._sev_order   = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self._sent_count  = 0

    def should_notify(self, finding: dict) -> bool:
        sev = finding.get("severity", "INFO")
        return (self._sev_order.get(sev, 4) <=
                self._sev_order.get(self.min_severity, 2))

    def notify(self, finding: dict):
        if not self.should_notify(finding):
            return

        if self.slack_url:
            notify_slack(self.slack_url, finding, self.session_id)

        if self.discord_url:
            notify_discord(self.discord_url, finding, self.session_id)

        if self.github_token and self.github_repo:
            # Only create issues for HIGH+ to avoid spam
            sev = finding.get("severity", "INFO")
            if self._sev_order.get(sev, 4) <= 1:
                create_github_issue(
                    self.github_token, self.github_repo,
                    finding, self.session_id
                )

        self._sent_count += 1

    def send_summary(self, findings: list[dict], score: int, score_label: str):
        """Send a scan completion summary."""
        from collections import defaultdict
        sev_counts = defaultdict(int)
        for f in findings:
            sev_counts[f.get("severity", "INFO")] += 1

        text = (
            f"🐝 *WaspSting Scan Complete* — Session `{self.session_id}`\n"
            f"Risk: *{score}/100 — {score_label}*\n"
            f"Total findings: *{len(findings)}*\n"
        )
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev_counts[sev]:
                text += f"{SEVERITY_EMOJI[sev]} {sev}: {sev_counts[sev]}\n"

        if self.slack_url:
            try:
                requests.post(self.slack_url,
                              json={"text": text}, timeout=8)
            except Exception:
                pass

        if self.discord_url:
            try:
                color = (0xEF4444 if score >= 75 else
                         0xEAB308 if score >= 25 else 0x4ADE80)
                requests.post(self.discord_url, json={
                    "embeds": [{
                        "title": "🐝 WaspSting Scan Complete",
                        "description": text,
                        "color": color,
                        "footer": {"text": "WaspSting by N00dleN00b"}
                    }]
                }, timeout=8)
            except Exception:
                pass

    @property
    def active_channels(self) -> list[str]:
        channels = []
        if self.slack_url:    channels.append("Slack")
        if self.discord_url:  channels.append("Discord")
        if self.github_token: channels.append("GitHub Issues")
        return channels
