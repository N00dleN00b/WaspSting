"""
modules/nuclei_runner.py — Nuclei Template Runner

Invokes Nuclei as a subprocess, parses JSONL output, converts findings
into WaspSting finding dicts, and returns them for merging into the
main report plus a dedicated Nuclei section.

Requirements:
    nuclei must be installed and in PATH.
    Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    Or:      https://github.com/projectdiscovery/nuclei/releases

Default template categories: cves, vulnerabilities, misconfiguration
Override with: --nuclei-tags cves,lfi,ssrf
Custom templates: --nuclei-templates /path/to/templates/

Usage in waspsting.py:
    python3 waspsting.py --target https://target.com --mode nuclei --confirm
    python3 waspsting.py --target https://target.com --mode full --confirm
"""

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Defaults ──────────────────────────────────────────────────────────────────

DEFAULT_TAGS       = ["cves", "vulnerabilities", "misconfiguration"]
HTTP_TIMEOUT_SECS  = 600        # 10 min max for full nuclei run
NUCLEI_RATE_LIMIT  = 150        # requests/sec — safe default
NUCLEI_CONCURRENCY = 25         # parallel templates

# ── OWASP mapping ─────────────────────────────────────────────────────────────
# Maps Nuclei template tags/categories to OWASP Top 10:2025 IDs

_TAG_TO_OWASP: list[tuple[set, str, str]] = [
    ({"sqli", "sql-injection"},              "A05", "Injection"),
    ({"xss", "reflected-xss", "stored-xss"}, "A05", "Injection"),
    ({"ssti"},                               "A05", "Injection"),
    ({"ssrf"},                               "A05", "Injection"),
    ({"lfi", "path-traversal"},              "A05", "Injection"),
    ({"rce", "command-injection"},           "A05", "Injection"),
    ({"xxe"},                                "A05", "Injection"),
    ({"idor", "bola"},                       "A01", "Broken Access Control"),
    ({"auth-bypass", "broken-auth"},         "A07", "Authentication Failures"),
    ({"jwt"},                                "A07", "Authentication Failures"),
    ({"misconfig", "misconfiguration"},      "A02", "Security Misconfiguration"),
    ({"exposure", "exposures"},              "A02", "Security Misconfiguration"),
    ({"cve"},                                "A03", "Software Supply Chain Failures"),
    ({"ssl", "tls", "crypto"},               "A04", "Cryptographic Failures"),
    ({"takeover"},                           "A01", "Broken Access Control"),
    ({"cors"},                               "A02", "Security Misconfiguration"),
    ({"open-redirect"},                      "A05", "Injection"),
    ({"default-login"},                      "A07", "Authentication Failures"),
    ({"info-disclosure"},                    "A02", "Security Misconfiguration"),
]

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
    "unknown":  "INFO",
}


def _owasp_for_tags(tags: list[str]) -> tuple[str, str]:
    """Return (owasp_id, owasp_name) for a list of Nuclei template tags."""
    tag_set = {t.lower() for t in tags}
    for keywords, oid, oname in _TAG_TO_OWASP:
        if keywords & tag_set:
            return oid, oname
    # CVE in template ID is a strong signal
    return "A03", "Software Supply Chain Failures"


# ── Nuclei presence check ─────────────────────────────────────────────────────

def check_nuclei() -> Optional[str]:
    """
    Return the path to the nuclei binary, or None if not found.
    Prints a clear install message when missing.
    """
    path = shutil.which("nuclei")
    return path


def _nuclei_not_found(console) -> None:
    console.print(
        "\n[bold red]✗ nuclei not found in PATH.[/bold red]\n\n"
        "  Install nuclei (requires Go 1.21+):\n"
        "    [bold]go install github.com/projectdiscovery/nuclei/v3/"
        "cmd/nuclei@latest[/bold]\n\n"
        "  Or download a pre-built binary:\n"
        "    [bold]https://github.com/projectdiscovery/nuclei/releases[/bold]\n\n"
        "  After installing, update templates:\n"
        "    [bold]nuclei -update-templates[/bold]\n"
    )


# ── Output parser ─────────────────────────────────────────────────────────────

def _parse_nuclei_jsonl(jsonl_path: str) -> list[dict]:
    """
    Parse Nuclei's JSONL output file into raw result dicts.
    Nuclei writes one JSON object per line when using -json flag.
    Skips malformed lines silently.
    """
    results = []
    try:
        with open(jsonl_path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return results


def _nuclei_result_to_finding(result: dict, target: str) -> dict:
    """
    Convert a single Nuclei JSONL result into a WaspSting finding dict.

    Nuclei result structure (key fields):
    {
      "template-id":   "CVE-2021-44228",
      "info": {
        "name":        "Apache Log4j RCE",
        "severity":    "critical",
        "description": "...",
        "tags":        ["cve", "rce", "log4j"],
        "reference":   ["https://..."],
        "remediation": "..."
      },
      "matcher-name":  "...",
      "type":          "http",
      "host":          "https://target.com",
      "matched-at":    "https://target.com/path?param=value",
      "extracted-results": ["..."],
      "curl-command":  "curl ...",
      "timestamp":     "2026-03-22T19:00:00Z"
    }
    """
    info        = result.get("info", {})
    template_id = result.get("template-id", "unknown")
    name        = info.get("name", template_id)
    severity    = _SEVERITY_MAP.get(
                    info.get("severity", "info").lower(), "INFO"
                  )
    description = info.get("description", "").strip()
    tags        = info.get("tags", [])
    references  = info.get("reference", [])
    remediation = info.get("remediation", "").strip()
    matched_at  = result.get("matched-at", target)
    extracted   = result.get("extracted-results", [])
    curl_cmd    = result.get("curl-command", "")

    owasp_id, owasp_name = _owasp_for_tags(tags + [template_id])

    # Build evidence block
    evidence_parts = [f"Template: {template_id}"]
    if matched_at:
        evidence_parts.append(f"Matched at: {matched_at}")
    if extracted:
        evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")
    if curl_cmd:
        evidence_parts.append(f"Reproduce:\n{curl_cmd}")
    evidence = "\n".join(evidence_parts)

    # Build fix
    fix_parts = []
    if remediation:
        fix_parts.append(remediation)
    if references:
        fix_parts.append("References: " + ", ".join(references[:3]))
    fix = "\n".join(fix_parts) if fix_parts else "Refer to Nuclei template documentation."

    return {
        "module":      "nuclei",
        "source":      "nuclei",
        "template_id": template_id,
        "owasp_id":    owasp_id,
        "owasp_name":  owasp_name,
        "category":    f"Nuclei [{', '.join(tags[:3])}]",
        "severity":    severity,
        "title":       f"{name} [{template_id}]",
        "description": description or f"Nuclei template {template_id} matched.",
        "evidence":    evidence,
        "fix":         fix,
        "url":         matched_at or target,
        "tags":        tags,
        "references":  references,
        "timestamp":   result.get("timestamp", datetime.now().isoformat()),
        # Raw result preserved for the dedicated Nuclei section
        "_nuclei_raw": result,
    }


# ── Runner ────────────────────────────────────────────────────────────────────

def run_nuclei(
    target:     str,
    tags:       Optional[list[str]],
    templates:  Optional[str],
    output_dir: str,
    console,
    notify_fn=None,
) -> dict:
    """
    Run Nuclei against target and return findings.

    Args:
        target:      URL to scan (e.g. https://target.com)
        tags:        Template tags to use (default: DEFAULT_TAGS)
        templates:   Path to custom template dir (overrides tags if set)
        output_dir:  WaspSting output directory
        console:     Rich console
        notify_fn:   Optional callable(finding) for live notifications

    Returns:
        {
          "findings":       list[dict],   # merged into main findings
          "nuclei_results": list[dict],   # raw for dedicated section
          "stats":          dict,
        }
    """
    from rich.table import Table
    from rich import box

    console.print(f"\n[bold cyan]═══ NUCLEI RUNNER[/bold cyan] → {target}\n")

    # ── Check nuclei is available ─────────────────────────────────────────────
    nuclei_bin = check_nuclei()
    if not nuclei_bin:
        _nuclei_not_found(console)
        return {"findings": [], "nuclei_results": [], "stats": {}}

    console.print(f"[green]✓ nuclei found:[/green] {nuclei_bin}")

    # ── Resolve tags / templates ──────────────────────────────────────────────
    active_tags = tags or DEFAULT_TAGS

    if templates:
        template_path = Path(templates)
        if not template_path.exists():
            console.print(
                f"[bold red]ERROR:[/bold red] Template path not found: {templates}"
            )
            return {"findings": [], "nuclei_results": [], "stats": {}}
        console.print(f"[dim]Custom templates: {templates}[/dim]")
    else:
        console.print(
            f"[dim]Template categories: {', '.join(active_tags)}[/dim]"
        )

    # ── Build command ─────────────────────────────────────────────────────────
    session    = datetime.now().strftime("%Y%m%d_%H%M%S")
    jsonl_file = Path(output_dir) / f"nuclei_{session}.jsonl"
    jsonl_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        nuclei_bin,
        "-u",           target,
        "-json",                        # JSONL output (one result per line)
        "-o",           str(jsonl_file),
        "-rate-limit",  str(NUCLEI_RATE_LIMIT),
        "-c",           str(NUCLEI_CONCURRENCY),
        "-silent",                      # suppress banner/progress to stdout
        "-no-color",                    # clean output for parsing
        "-stats",                       # print stats summary to stderr
    ]

    if templates:
        cmd += ["-t", templates]
    else:
        # -tags accepts comma-separated values
        cmd += ["-tags", ",".join(active_tags)]

    console.print(
        f"[dim]Command: {' '.join(cmd[:6])} ...[/dim]\n"
    )
    console.print(
        "[yellow]⚠  Nuclei is making real HTTP requests. "
        "Authorized targets only.[/yellow]\n"
    )

    # ── Execute ───────────────────────────────────────────────────────────────
    start_time = datetime.now()
    console.print("[bold]Running Nuclei...[/bold] (this may take several minutes)")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=HTTP_TIMEOUT_SECS,
        )
    except subprocess.TimeoutExpired:
        console.print(
            f"[bold red]✗ Nuclei timed out after "
            f"{HTTP_TIMEOUT_SECS // 60} minutes.[/bold red]\n"
            "  Results up to the timeout have been saved."
        )
    except FileNotFoundError:
        console.print(
            "[bold red]✗ nuclei binary disappeared during execution.[/bold red]"
        )
        return {"findings": [], "nuclei_results": [], "stats": {}}
    except Exception as e:
        console.print(f"[bold red]✗ Nuclei execution error:[/bold red] {e}")
        return {"findings": [], "nuclei_results": [], "stats": {}}

    elapsed = (datetime.now() - start_time).seconds

    # Print nuclei's stderr stats if available
    if proc.stderr:
        for line in proc.stderr.splitlines():
            if any(k in line.lower() for k in
                   ["template", "target", "request", "found", "error"]):
                console.print(f"  [dim]{line.strip()}[/dim]")

    # ── Parse results ─────────────────────────────────────────────────────────
    raw_results = _parse_nuclei_jsonl(str(jsonl_file))
    console.print(
        f"\n[green]✓ Nuclei complete[/green] — "
        f"{len(raw_results)} result(s) in {elapsed}s"
    )

    if not raw_results:
        console.print("[dim]No findings from Nuclei for this target.[/dim]")
        return {
            "findings":       [],
            "nuclei_results": [],
            "stats": {"elapsed": elapsed, "total": 0},
        }

    # ── Convert to WaspSting findings ─────────────────────────────────────────
    findings = []
    for result in raw_results:
        finding = _nuclei_result_to_finding(result, target)
        findings.append(finding)
        if notify_fn:
            sev = finding.get("severity", "INFO")
            if sev in ("CRITICAL", "HIGH", "MEDIUM"):
                notify_fn(finding)

    # ── Severity breakdown ────────────────────────────────────────────────────
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "INFO")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # ── Terminal summary table ────────────────────────────────────────────────
    table = Table(
        box=box.SIMPLE,
        title=f"Nuclei Findings ({len(findings)} total)",
        header_style="bold magenta",
    )
    table.add_column("Severity",    width=10)
    table.add_column("Template",    width=35)
    table.add_column("Title",       width=45)
    table.add_column("Matched At",  style="dim")

    SEV_COLOR = {
        "CRITICAL": "bold red",   "HIGH":   "bold orange1",
        "MEDIUM":   "bold yellow","LOW":    "bold blue",
        "INFO":     "dim",
    }
    SEV_EMOJI = {
        "CRITICAL": "🔴", "HIGH": "🟠",
        "MEDIUM":   "🟡", "LOW":  "🔵", "INFO": "⚪",
    }

    for f in findings:
        sev   = f.get("severity", "INFO")
        col   = SEV_COLOR.get(sev, "white")
        emoji = SEV_EMOJI.get(sev, "⚪")
        table.add_row(
            f"[{col}]{emoji} {sev}[/{col}]",
            f.get("template_id", "")[:34],
            f.get("title", "")[:44],
            f.get("url", "")[:40],
        )

    console.print(table)

    # Severity summary line
    sev_line = "  ".join(
        f"{SEV_EMOJI.get(s,'⚪')} {s}: {c}"
        for s, c in sorted(
            sev_counts.items(),
            key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x[0])
            if x[0] in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99
        )
    )
    console.print(f"\n[bold]Nuclei severity breakdown:[/bold] {sev_line}\n")
    console.print(
        f"[dim]Raw JSONL saved: {jsonl_file}[/dim]\n"
    )

    return {
        "findings":       findings,
        "nuclei_results": raw_results,
        "stats": {
            "elapsed":    elapsed,
            "total":      len(findings),
            "by_severity": sev_counts,
            "jsonl_path": str(jsonl_file),
            "tags_used":  active_tags if not templates else [],
            "templates":  templates or None,
        },
    }


# ── Markdown section renderer ─────────────────────────────────────────────────

def nuclei_section_markdown(
    findings: list[dict],
    stats:    dict,
) -> str:
    """
    Render a dedicated Nuclei section for the markdown report.
    Placed after the main findings section.
    """
    if not findings:
        return ""

    SEV_EMOJI = {
        "CRITICAL": "🔴", "HIGH": "🟠",
        "MEDIUM":   "🟡", "LOW":  "🔵", "INFO": "⚪",
    }

    lines = [
        "\n---\n",
        "## 🔫 Nuclei Scan Results\n",
    ]

    # Stats header
    elapsed  = stats.get("elapsed", 0)
    tags     = stats.get("tags_used", [])
    tpl_path = stats.get("templates")
    source   = f"templates: {tpl_path}" if tpl_path \
               else f"tags: {', '.join(tags)}"

    lines.append(
        f"**Scan source:** {source}  \n"
        f"**Duration:** {elapsed}s  \n"
        f"**Total findings:** {len(findings)}\n"
    )

    # Severity summary table
    by_sev = stats.get("by_severity", {})
    if by_sev:
        lines += [
            "| Severity | Count |",
            "|----------|------:|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = by_sev.get(sev, 0)
            if count:
                emoji = SEV_EMOJI.get(sev, "⚪")
                lines.append(f"| {emoji} {sev} | {count} |")
        lines.append("")

    # Individual findings
    lines.append("### Findings\n")
    for idx, f in enumerate(findings, 1):
        sev      = f.get("severity", "INFO")
        emoji    = SEV_EMOJI.get(sev, "⚪")
        title    = f.get("title", "")
        owasp    = f.get("owasp_id", "")
        desc     = f.get("description", "")
        evidence = f.get("evidence", "")
        fix      = f.get("fix", "")
        refs     = f.get("references", [])
        tags_str = ", ".join(f.get("tags", [])[:5])

        lines += [
            f"#### [{idx}] {emoji} {sev} — {title}\n",
            f"**OWASP:** {owasp}  ",
            f"**Tags:** `{tags_str}`\n",
        ]
        if desc:
            lines.append(f"{desc}\n")

        if evidence:
            lines += [
                "**Evidence:**",
                "```",
                evidence[:800],
                "```\n",
            ]
        if fix:
            lines.append(f"**Remediation:** {fix}\n")
        if refs:
            lines.append(
                "**References:** " +
                " | ".join(f"[{i+1}]({r})" for i, r in enumerate(refs[:3]))
                + "\n"
            )
        lines.append("---\n")

    return "\n".join(lines)


# ── CLI self-test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    console = Console()

    console.print("\n[bold]WaspSting — Nuclei runner self-test[/bold]")

    nuclei_bin = check_nuclei()
    if not nuclei_bin:
        _nuclei_not_found(console)
        sys.exit(1)

    console.print(f"[green]✓ nuclei found at:[/green] {nuclei_bin}")

    # Version check
    try:
        ver = subprocess.run(
            [nuclei_bin, "-version"],
            capture_output=True, text=True, timeout=5,
        )
        version_line = (ver.stdout + ver.stderr).strip().splitlines()
        if version_line:
            console.print(f"[dim]{version_line[0]}[/dim]")
    except Exception:
        pass

    console.print("\n[green]✓ Nuclei runner ready.[/green]")
    console.print(
        f"[dim]Default tags: {', '.join(DEFAULT_TAGS)}[/dim]\n"
        "[dim]Run a scan with:[/dim]\n"
        "  [bold]python3 waspsting.py --target https://target.com "
        "--mode nuclei --confirm[/bold]\n"
    )