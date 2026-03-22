#!/usr/bin/env python3
"""
WaspSting v1.5 - Authorized Pentest Documentation & Analysis Tool
=================================================================
Created by N00dleN00b

LEGAL NOTICE: For authorized security testing ONLY.

Usage:
    python waspsting.py --target https://example.com --mode full --confirm
    python waspsting.py --repo https://github.com/org/repo --mode sast
    python waspsting.py --mode bounty --scope scope.json
    python waspsting.py --target https://t.com --mode enum --confirm     # subdomain enum
    python waspsting.py --target https://t.com --mode fuzz --confirm     # payload fuzzer
    python waspsting.py --help
"""

import argparse
import os
import sys
import json
from datetime import datetime
from pathlib import Path

VERSION = "1.5"
AUTHOR  = "N00dleN00b"

MODES = {
    "full":    "All modules — SAST + recon + auth + BOLA + API + enum + fuzz",
    "sast":    "Static GitHub repo analysis",
    "recon":   "Passive recon: headers, CVE lookup, CORS",
    "auth":    "Login endpoint audit with wordlist",
    "bola":    "BOLA/IDOR endpoint walking",
    "api":     "API security: rate limit, CORS, injection",
    "enum":    "Subdomain enumeration (crt.sh + DNS brute force)",
    "fuzz":    "Custom payload fuzzer against endpoints",
    "bounty":  "Bug bounty scope ingestion → AI test plan",
    "report":  "Re-generate reports from saved JSON",
}


def check_deps():
    missing = []
    for pkg in ["rich", "requests"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[!] Missing: pip install {' '.join(missing)}")
        sys.exit(1)


def get_ollama_status() -> bool:
    try:
        import requests as req
        r = req.get("http://localhost:11434/api/tags", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def load_notify_config(config_path: str | None) -> dict:
    """Load notification config from file or environment."""
    cfg = {}
    if config_path and Path(config_path).exists():
        try:
            cfg = json.loads(Path(config_path).read_text())
        except Exception:
            pass
    # Env overrides
    for key in ["slack_webhook", "discord_webhook", "github_token",
                 "github_repo", "notify_min_severity"]:
        env_val = os.environ.get(f"WASPSTING_{key.upper()}")
        if env_val:
            cfg[key] = env_val
    return cfg


def main():
    check_deps()

    parser = argparse.ArgumentParser(
        prog="waspsting",
        description=f"WaspSting v{VERSION} — Authorized Pentest Documentation & Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Modes:\n" + "\n".join(f"  {k:<8} {v}" for k, v in MODES.items())
    )
    # Core
    parser.add_argument("--target",    "-t",  help="Target URL (https://example.com)")
    parser.add_argument("--repo",      "-r",  help="GitHub repo URL for SAST")
    parser.add_argument("--mode",      "-m",  default="full", choices=list(MODES.keys()))
    parser.add_argument("--output",    "-o",  default="./output", help="Output directory")
    parser.add_argument("--confirm",          action="store_true",
                                              help="Confirm authorization to test")
    # Modules
    parser.add_argument("--wordlist",  "-w",  help="Wordlist for auth audit")
    parser.add_argument("--fuzz-list",        help="Custom payload file for fuzzer")
    parser.add_argument("--fuzz-cats",        help="Comma-separated fuzz categories: sqli,xss,ssti,ssrf,cmdi,path_traversal,prompt_injection")
    parser.add_argument("--scope",            help="Bug bounty scope file (JSON/text)")
    parser.add_argument("--results",          help="Previous JSON results (--mode report)")
    parser.add_argument("--screenshot",       action="store_true",
                                              help="Capture asset gallery from discovered subdomains")
    # Enrichment
    parser.add_argument("--burp",             action="store_true",
                                              help="Generate Burp Suite config JSON")
    parser.add_argument("--cve",              action="store_true",
                                              help="Lookup CVEs for detected tech")
    parser.add_argument("--html",             action="store_true",
                                              help="Generate executive HTML report with charts")
    # Notifications
    parser.add_argument("--slack",            help="Slack webhook URL for live findings")
    parser.add_argument("--discord",          help="Discord webhook URL for live findings")
    parser.add_argument("--github-token",     help="GitHub PAT for auto issue creation")
    parser.add_argument("--github-repo",      help="GitHub repo (owner/name) for issues")
    parser.add_argument("--notify-config",    help="JSON config file for notifications")
    parser.add_argument("--notify-severity",  default="HIGH",
                                              help="Minimum severity to notify (default: HIGH)")
    # Session
    parser.add_argument("--dedup",            action="store_true",
                                              help="Skip findings seen in previous sessions")
    parser.add_argument("--dedup-db",         default="output/.waspsting_history.json",
                                              help="Path to dedup history file")
    # Misc
    parser.add_argument("--no-ai",            action="store_true")
    parser.add_argument("--fast",             action="store_true",
                                              help="Skip banner animation")
    parser.add_argument("--threads",          type=int, default=5)
    parser.add_argument("--delay",            type=float, default=0.5)

    args = parser.parse_args()

    # ── Banner ──
    from banner import print_banner, print_scan_start
    print_banner(fast=args.fast)

    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    console = Console()

    # ── Auth gate ──
    live_modes = {"full", "recon", "auth", "bola", "api", "enum", "fuzz"}
    if args.mode in live_modes and args.target and not args.confirm:
        console.print(Panel(
            "[bold yellow]⚠  AUTHORIZATION REQUIRED[/bold yellow]\n\n"
            "Live modules make real HTTP requests to the target.\n"
            "Only proceed with [bold]explicit written authorization[/bold].\n\n"
            f"  Target: [cyan]{args.target}[/cyan]\n\n"
            "Add [bold]--confirm[/bold] to proceed.",
            border_style="yellow", title="WaspSting — Authorization Check"
        ))
        sys.exit(0)

    if not args.target and not args.repo and args.mode not in ("report", "bounty"):
        parser.print_help()
        sys.exit(0)

    os.makedirs(args.output, exist_ok=True)

    # ── AI check ──
    ai_available = not args.no_ai and get_ollama_status()
    if not args.no_ai:
        status = "[bold green][+] Ollama: ONLINE[/bold green]" if ai_available \
                 else "[dim yellow][-] Ollama not detected (run: ollama serve)[/dim yellow]"
        console.print(status)

    # ── Notifications setup ──
    notify_cfg = load_notify_config(args.notify_config)
    if args.slack:         notify_cfg["slack_webhook"]    = args.slack
    if args.discord:       notify_cfg["discord_webhook"]  = args.discord
    if args.github_token:  notify_cfg["github_token"]     = args.github_token
    if args.github_repo:   notify_cfg["github_repo"]      = args.github_repo
    notify_cfg["notify_min_severity"] = args.notify_severity

    from modules.notify import Notifier
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    notifier   = Notifier(notify_cfg, session_id)

    if notifier.active_channels:
        console.print(f"[green][+] Notifications → {', '.join(notifier.active_channels)}[/green]")

    # ── Scan header ──
    if args.target and args.mode != "bounty":
        print_scan_start(args.target, args.mode)
    elif args.repo:
        print_scan_start(args.repo, "sast")

    # ── Mode table ──
    mode_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    mode_table.add_column(style="dim green")
    mode_table.add_column(style="bold bright_green")
    mode_table.add_row("Mode",    f"[{args.mode.upper()}]")
    mode_table.add_row("Target",  args.target or args.repo or args.scope or "(interactive)")
    mode_table.add_row("Output",  args.output)
    mode_table.add_row("Burp",    "ON" if args.burp else "—")
    mode_table.add_row("CVE",     "ON" if args.cve  else "—")
    mode_table.add_row("HTML",    "ON" if args.html else "—")
    mode_table.add_row("Notify",  ", ".join(notifier.active_channels) or "—")
    mode_table.add_row("Dedup",   "ON" if args.dedup else "—")
    mode_table.add_row("AI",      "Ollama" if ai_available else "—")
    mode_table.add_row("Author",  AUTHOR)
    console.print(mode_table)
    console.print()

    # ── Results container ──
    all_results = {
        "session_id":   session_id,
        "target":       args.target or args.repo,
        "mode":         args.mode,
        "findings":     [],
        "burp_items":   [],
        "author":       AUTHOR,
        "version":      VERSION,
    }

    def add_findings(new_findings: list):
        """Add findings, deduplicate if enabled, notify live."""
        if args.dedup and new_findings:
            from modules.notify import deduplicate_findings
            truly_new, dupes = deduplicate_findings(new_findings, args.dedup_db)
            if dupes:
                console.print(f"[dim]ℹ Dedup: skipped {len(dupes)} previously seen findings[/dim]")
            new_findings = truly_new

        for f in new_findings:
            notifier.notify(f)

        all_results["findings"].extend(new_findings)

    # ── Special modes ────────────────────────────────────────────────────────

    if args.mode == "report":
        from modules.reporter import regenerate_report
        regenerate_report(args.results, args.output, console)
        return

    if args.mode == "bounty":
        from modules.bugbounty import run_bugbounty
        run_bugbounty(args.scope, args.output, ai_available, console)
        return

    # ── Standard scan modules ─────────────────────────────────────────────────

    if args.mode in ("sast", "full") and args.repo:
        from modules.sast import run_sast
        r = run_sast(args.repo, args.output, ai_available, console)
        add_findings(r.get("findings", []))

    if args.mode in ("recon", "full") and args.target:
        from modules.recon import run_recon
        r = run_recon(args.target, args.cve, ai_available, console)
        add_findings(r.get("findings", []))
        all_results["tech_stack"] = r.get("tech_stack", {})

    if args.mode in ("auth", "full") and args.target:
        from modules.auth_audit import run_auth_audit
        r = run_auth_audit(
            args.target,
            args.wordlist or "wordlists/common.txt",
            args.delay, args.threads, console
        )
        add_findings(r.get("findings", []))

    if args.mode in ("bola", "full") and args.target:
        from modules.bola import run_bola
        r = run_bola(args.target, args.delay, console)
        add_findings(r.get("findings", []))

    if args.mode in ("api", "full") and args.target:
        from modules.api_checks import run_api_checks
        r = run_api_checks(args.target, args.delay, console)
        add_findings(r.get("findings", []))

    # ── New modules ───────────────────────────────────────────────────────────

    live_subdomains = []

    if args.mode in ("enum", "full") and args.target:
        from modules.subdomain import run_subdomain
        r = run_subdomain(
            args.target, args.output, console,
            notify_fn=notifier.notify
        )
        add_findings(r.get("findings", []))
        live_subdomains = r.get("live_subdomains", [])
        all_results["live_subdomains"] = live_subdomains

    if args.mode in ("fuzz", "full") and args.target:
        from modules.fuzzer import run_fuzzer
        cats = args.fuzz_cats.split(",") if args.fuzz_cats else None
        r = run_fuzzer(
            args.target,
            args.fuzz_list,
            cats,
            args.delay,
            console,
            notify_fn=notifier.notify
        )
        add_findings(r.get("findings", []))

    # ── Screenshots ───────────────────────────────────────────────────────────

    if args.screenshot and live_subdomains:
        from modules.screenshot import run_screenshot
        targets = [s["url"] for s in live_subdomains[:30]]
        run_screenshot(targets, args.output,
                       program_name=args.target or "WaspSting",
                       console=console)

    # ── Burp config ───────────────────────────────────────────────────────────

    if args.burp:
        from modules.burp_export import generate_burp_config
        burp_path = os.path.join(args.output, f"burp_config_{session_id}.json")
        generate_burp_config(
            all_results.get("burp_items", []),
            args.target or "", burp_path
        )
        console.print(f"[green][+] Burp config → [cyan]{burp_path}[/cyan][/green]")

    # ── Reports ───────────────────────────────────────────────────────────────

    from modules.reporter import generate_report, calc_score
    generate_report(all_results, args.output, session_id, console)

    score, score_label = calc_score(all_results["findings"])

    if args.html:
        from modules.html_report import save_html_report
        html_path = os.path.join(args.output, f"waspsting_{session_id}.html")
        save_html_report(all_results, score, score_label, html_path)
        console.print(f"[green][+] HTML report → [cyan]{html_path}[/cyan][/green]")
        console.print(f"[dim]    Open in browser for charts & interactive findings[/dim]")

    # ── Completion notification ───────────────────────────────────────────────

    notifier.send_summary(all_results["findings"], score, score_label)

    console.print(
        f"\n[bold bright_green][ WaspSting complete ][/bold bright_green]  "
        f"Session: [cyan]{session_id}[/cyan]  |  "
        f"Score: [{('red' if score >= 75 else 'yellow' if score >= 25 else 'green')}]"
        f"{score}/100 {score_label}[/]  |  "
        f"[dim]by {AUTHOR}[/dim]"
    )


if __name__ == "__main__":
    main()
