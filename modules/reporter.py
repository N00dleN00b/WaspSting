"""
modules/reporter.py — Rich terminal output + Markdown pentest report + JSON

Auto-documentation feature: generates a structured pentest report as you go,
including evidence, test steps taken, findings, and remediation guidance.
"""

import json
import os
from datetime import datetime
from collections import defaultdict
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.rule import Rule
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from knowledge_base import (
    OWASP_TOP_10_2025, PENTEST_CHECKS,
    SEVERITY_ORDER, SEVERITY_COLORS, SEVERITY_EMOJI
)


def sort_findings(findings: list) -> list:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 4))


def calc_score(findings: list) -> tuple[int, str]:
    weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}
    score = min(100, sum(weights.get(f.get("severity", "INFO"), 0) for f in findings))
    if score >= 75: label = "CRITICAL RISK"
    elif score >= 50: label = "HIGH RISK"
    elif score >= 25: label = "MEDIUM RISK"
    elif score > 0:  label = "LOW RISK"
    else:             label = "MINIMAL RISK"
    return score, label


def print_summary(console, findings, score, score_label, session_id):
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.get("severity", "INFO")] += 1

    modules_hit = set(f.get("module", "?") for f in findings)
    ai_count = sum(1 for f in findings if f.get("ai_specific") or f.get("source") == "ollama_ai")
    owasp_hit = len(set(f.get("owasp_id") for f in findings if f.get("owasp_id")))

    score_color = "red" if score >= 75 else "yellow" if score >= 25 else "green"
    t = Text()
    t.append(f"  Session: {session_id}\n", style="dim")
    t.append(f"  Risk Score: ", style="bold")
    t.append(f"{score}/100 — {score_label}\n", style=f"bold {score_color}")
    t.append(f"  Total Findings: {len(findings)}  |  OWASP Categories: {owasp_hit}/10  |  AI Issues: {ai_count}\n\n")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = sev_counts.get(sev, 0)
        if c:
            t.append(f"  {SEVERITY_EMOJI[sev]} {sev}: {c}\n", style=SEVERITY_COLORS[sev])
    t.append(f"\n  Modules run: {', '.join(sorted(modules_hit))}")
    console.print(Panel(t, title="[bold]WaspSting — Scan Summary[/bold]", border_style="bright_black"))
    console.print()


def print_findings_table(console, findings):
    if not findings:
        console.print("[bold green]✅ No findings.[/bold green]")
        return

    t = Table(title="🐝 WaspSting Findings", box=box.ROUNDED,
              show_lines=True, header_style="bold magenta", border_style="bright_black")
    t.add_column("Sev",      width=10)
    t.add_column("OWASP",    width=8, style="cyan")
    t.add_column("Category", width=22, style="bold white")
    t.add_column("Title",    width=35)
    t.add_column("Module",   width=12, style="dim")
    t.add_column("File/URL", width=30, style="dim")

    for f in sort_findings(findings):
        sev = f.get("severity", "INFO")
        t.add_row(
            Text(f"{SEVERITY_EMOJI[sev]} {sev}", style=SEVERITY_COLORS[sev]),
            f.get("owasp_id", "—"),
            f.get("owasp_name", f.get("category", "—"))[:22],
            f.get("title", "")[:45],
            f.get("module", "?"),
            (f.get("file") or f.get("url", ""))[-30:]
        )
    console.print(t)
    console.print()


def print_detailed(console, findings):
    if not findings:
        return
    console.print(Rule("[bold]Detailed Findings[/bold]", style="bright_black"))
    console.print()

    for i, f in enumerate(sort_findings(findings), 1):
        sev = f.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, "white")
        ai_badge = " [yellow]🤖 AI[/yellow]" if f.get("source") in ("ollama_ai",) or f.get("ai_specific") else ""

        console.print(f"[{color}]▶ [{i}] {SEVERITY_EMOJI[sev]} {sev} — {f.get('title')}{ai_badge}[/{color}]")
        console.print(f"   [cyan]OWASP:[/cyan] {f.get('owasp_id', '—')} {f.get('owasp_name', f.get('category', ''))}")
        console.print(f"   [cyan]Module:[/cyan] {f.get('module', '?')}  |  "
                      f"[cyan]File/URL:[/cyan] {f.get('file') or f.get('url', '—')} "
                      f"(line {f.get('line_hint', '?')})")
        if f.get("cwe"):
            console.print(f"   [cyan]CWE:[/cyan] {f.get('cwe')}")
        console.print()
        console.print(f"   [bold]Description:[/bold] {f.get('description', '')}")
        console.print()

        if f.get("evidence"):
            console.print("   [bold]Evidence:[/bold]")
            border = "red" if sev == "CRITICAL" else "yellow"
            console.print(Panel(str(f.get("evidence", ""))[:400],
                                border_style=border, padding=(0, 2)))

        if f.get("doc_template"):
            console.print("   [bold dim]📋 Documentation template:[/bold dim]")
            console.print(Panel(
                json.dumps(f["doc_template"], indent=2),
                border_style="dim", padding=(0, 2)
            ))

        console.print(f"   [bold green]Fix:[/bold green] {f.get('fix', 'See OWASP guidelines')}")
        console.print()
        console.print(Rule(style="bright_black"))
        console.print()


def print_owasp_map(console, findings):
    console.print(Rule("[bold]OWASP Top 10:2025 Coverage[/bold]", style="bright_black"))
    console.print()
    hit_ids = set(f.get("owasp_id") for f in findings)
    for oid, vuln in OWASP_TOP_10_2025.items():
        count = sum(1 for f in findings if f.get("owasp_id") == oid)
        status = f"[red]⚠ {count} finding(s)[/red]" if oid in hit_ids else "[green]✓ Clear[/green]"
        console.print(f"  {vuln['id']} {vuln['name']:<40} {status}")
    console.print()


def generate_markdown(results: dict, score: int, score_label: str) -> str:
    findings = results.get("findings", [])
    target = results.get("target", "unknown")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.get("severity", "INFO")] += 1

    lines = [
        "# 🐝 WaspSting Pentest Report",
        "",
        f"**Target:** `{target}`  ",
        f"**Session:** `{results.get('session_id', '')}`  ",
        f"**Date:** {ts}  ",
        f"**Risk Score:** {score}/100 — {score_label}  ",
        f"**Modules Run:** {results.get('mode', 'full')}  ",
        "",
        "> ⚠️ **AUTHORIZED USE ONLY.** This report is generated from authorized security testing only.",
        "",
        "---", "",
        "## Executive Summary", "",
        f"Total findings: **{len(findings)}**  ",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = sev_counts.get(sev, 0)
        if c:
            lines.append(f"- {SEVERITY_EMOJI[sev]} **{sev}**: {c}")

    lines += ["", "---", "", "## Findings", ""]

    for i, f in enumerate(sort_findings(findings), 1):
        ai_badge = " 🤖 *(AI-detected)*" if f.get("source") == "ollama_ai" or f.get("ai_specific") else ""
        lines += [
            f"### [{i}] {SEVERITY_EMOJI[f.get('severity','INFO')]} {f.get('severity')} — {f.get('title')}{ai_badge}",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **OWASP** | {f.get('owasp_id','—')} {f.get('owasp_name', f.get('category',''))} |",
            f"| **Module** | {f.get('module','?')} |",
            f"| **File/URL** | `{f.get('file') or f.get('url','—')}` |",
            f"| **Line** | {f.get('line_hint','?')} |",
            f"| **CWE** | {f.get('cwe','—')} |",
            f"| **Source** | {f.get('source','manual')} |",
            "",
            f"**Description:** {f.get('description','')}",
            "",
        ]

        if f.get("evidence"):
            lines += ["**Evidence:**", "```", str(f["evidence"])[:400], "```", ""]

        if f.get("doc_template"):
            lines += [
                "**📋 Documentation Template:**",
                "```json",
                json.dumps(f["doc_template"], indent=2),
                "```",
                ""
            ]

        if f.get("test_ids"):
            lines += [f"**Test IDs walked:** {f['test_ids']}", ""]

        lines += [f"**Remediation:** {f.get('fix', 'See OWASP guidelines')}", "", "---", ""]

    # OWASP coverage table
    lines += ["## OWASP Top 10:2025 Coverage", "",
              "| ID | Category | Status |", "|----|----------|--------|"]
    hit_ids = set(f.get("owasp_id") for f in findings)
    for oid, v in OWASP_TOP_10_2025.items():
        count = sum(1 for f in findings if f.get("owasp_id") == oid)
        status = f"⚠ {count} finding(s)" if oid in hit_ids else "✓ Clear"
        lines.append(f"| {v['id']} | {v['name']} | {status} |")

    # Pentest checklist appendix
    lines += [
        "", "---", "",
        "## Appendix — Pentest Methodology Checklist", "",
        "Use this checklist to track manual testing steps:", "",
    ]
    for check_id, check in PENTEST_CHECKS.items():
        lines += [f"### {check['name']}", "", f"_{check['description']}_", ""]
        for step in check["test_steps"]:
            lines.append(f"- [ ] {step}")
        lines.append("")

    lines += [
        "---",
        "",
        "*Generated by [WaspSting](https://github.com/yourusername/waspsting) — "
        "Authorized Pentest Documentation Tool*"
    ]

    return "\n".join(lines)


def generate_report(results: dict, output_dir: str, session_id: str, console):
    findings = results.get("findings", [])
    score, score_label = calc_score(findings)

    if not HAS_RICH:
        print(json.dumps(results, indent=2, default=str))
        return

    print_summary(console, findings, score, score_label, session_id)
    print_findings_table(console, findings)
    print_detailed(console, findings)
    print_owasp_map(console, findings)

    # Save reports
    base = os.path.join(output_dir, f"waspsting_{session_id}")

    # Markdown
    md = generate_markdown(results, score, score_label)
    md_path = base + ".md"
    Path(md_path).write_text(md, encoding="utf-8")

    # JSON
    json_path = base + ".json"
    Path(json_path).write_text(
        json.dumps({**results, "risk_score": score, "risk_label": score_label,
                    "findings": sort_findings(findings)}, indent=2, default=str),
        encoding="utf-8"
    )

    console.print(f"[bold green]📄 Reports saved:[/bold green]")
    console.print(f"   Markdown → [cyan]{md_path}[/cyan]")
    console.print(f"   JSON     → [cyan]{json_path}[/cyan]")


def regenerate_report(results_path: str, output_dir: str, console):
    """Re-generate reports from a saved JSON file."""
    if not results_path or not Path(results_path).exists():
        console.print(f"[red]✗ Results file not found: {results_path}[/red]")
        return
    with open(results_path) as f:
        results = json.load(f)
    session_id = results.get("session_id", datetime.now().strftime("%Y%m%d_%H%M%S"))
    generate_report(results, output_dir, session_id, console)
