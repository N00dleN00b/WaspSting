#!/usr/bin/env python3
"""
WaspSting v1.4 - Authorized Pentest Documentation & Analysis Tool
=================================================================
Created by N00dleN00b

LEGAL NOTICE: This tool is intended for authorized security testing ONLY.
Only use against systems you own or have explicit written permission to test.
Unauthorized access to computer systems is illegal and unethical.

Usage:
    python waspsting.py --target https://example.com --mode full --confirm
    python waspsting.py --target https://example.com --mode recon --cve --confirm
    python waspsting.py --repo https://github.com/user/repo --mode sast
    python waspsting.py --mode bounty                          # bug bounty planner
    python waspsting.py --mode bounty --scope scope.json       # load scope from file
    python waspsting.py --help
"""

import argparse
import os
import sys
import time
import json
from datetime import datetime
from pathlib import Path

VERSION = "1.4"
AUTHOR  = "N00dleN00b"

MODES = {
    "full":    "Run all modules (SAST + recon + auth audit + BOLA + API checks)",
    "sast":    "Static analysis of a GitHub repo (no live requests)",
    "recon":   "Passive recon: headers, CVE lookup, CORS, security.txt",
    "auth":    "Login endpoint audit with wordlist (authorized targets only)",
    "bola":    "BOLA/IDOR endpoint walking & documentation",
    "api":     "API security checks: rate limit, data exposure, mass assignment",
    "bounty":  "Bug bounty scope ingestion & AI-powered test plan generator",
    "report":  "Re-generate reports from a previous JSON results file",
}


def check_deps():
    missing = []
    for pkg in ["rich", "requests"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[!] Missing dependencies. Run: pip install {' '.join(missing)}")
        sys.exit(1)


def get_ollama_status() -> bool:
    try:
        import requests as req
        r = req.get("http://localhost:11434/api/tags", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def main():
    check_deps()

    parser = argparse.ArgumentParser(
        prog="waspsting",
        description=f"WaspSting v{VERSION} — Authorized Pentest Documentation & Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Modes:\n" + "\n".join(f"  {k:<8} {v}" for k, v in MODES.items())
    )
    parser.add_argument("--target",   "-t", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--repo",     "-r", help="GitHub repo URL for SAST")
    parser.add_argument("--mode",     "-m", default="full", choices=list(MODES.keys()))
    parser.add_argument("--wordlist", "-w", help="Wordlist path for auth audit")
    parser.add_argument("--output",   "-o", default="./output", help="Output directory")
    parser.add_argument("--threads",  type=int, default=5)
    parser.add_argument("--delay",    type=float, default=0.5)
    parser.add_argument("--burp",     action="store_true", help="Generate Burp Suite config JSON")
    parser.add_argument("--cve",      action="store_true", help="Lookup CVEs for detected tech")
    parser.add_argument("--no-ai",    action="store_true", help="Skip Ollama AI analysis")
    parser.add_argument("--fast",     action="store_true", help="Skip banner animation")
    parser.add_argument("--results",  help="Path to previous results JSON (for --mode report)")
    parser.add_argument("--scope",    help="Bug bounty scope file (JSON or text) for --mode bounty")
    parser.add_argument("--confirm",  action="store_true",
                        help="Confirm authorization to test this target")

    args = parser.parse_args()

    # Animated banner
    from banner import print_banner, print_scan_start
    print_banner(fast=args.fast)

    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    console = Console()

    # Authorization gate for live testing modes
    live_modes = {"full", "recon", "auth", "bola", "api"}
    if args.mode in live_modes and args.target and not args.confirm:
        console.print(Panel(
            "[bold yellow]⚠  AUTHORIZATION REQUIRED[/bold yellow]\n\n"
            "Live modules make real HTTP requests to the target.\n"
            "Only proceed with [bold]explicit written authorization[/bold].\n\n"
            f"  Target: [cyan]{args.target}[/cyan]\n\n"
            "Re-run with [bold]--confirm[/bold] to proceed.\n"
            "[dim]Example: python waspsting.py --target https://example.com --mode recon --confirm[/dim]",
            border_style="yellow", title="WaspSting — Authorization Check"
        ))
        sys.exit(0)

    if not args.target and not args.repo and args.mode not in ("report", "bounty"):
        parser.print_help()
        sys.exit(0)

    os.makedirs(args.output, exist_ok=True)

    # Ollama check
    ai_available = not args.no_ai and get_ollama_status()
    if not args.no_ai:
        if ai_available:
            console.print("[bold green][+] Ollama AI engine: ONLINE[/bold green]")
        else:
            console.print("[dim yellow][-] Ollama not detected — AI disabled (run: ollama serve)[/dim yellow]")

    # Scan header animation
    if args.target and args.mode != "bounty":
        print_scan_start(args.target, args.mode)
    elif args.repo:
        print_scan_start(args.repo, "sast")

    # Mode info table
    mode_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    mode_table.add_column(style="dim green")
    mode_table.add_column(style="bold bright_green")
    mode_table.add_row("Mode",    f"[{args.mode.upper()}]")
    mode_table.add_row("Target",  args.target or args.repo or args.scope or "(interactive)")
    mode_table.add_row("Output",  args.output)
    mode_table.add_row("Burp",    "ENABLED" if args.burp else "—")
    mode_table.add_row("CVE",     "ENABLED" if args.cve else "—")
    mode_table.add_row("AI",      "Ollama ONLINE" if ai_available else "—")
    mode_table.add_row("Author",  f"Created by {AUTHOR}")
    console.print(mode_table)
    console.print()

    # Route to modules
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    all_results = {
        "session_id": session_id,
        "target": args.target or args.repo,
        "mode": args.mode,
        "findings": [],
        "burp_items": [],
        "author": AUTHOR,
        "version": VERSION
    }

    if args.mode == "report":
        from modules.reporter import regenerate_report
        regenerate_report(args.results, args.output, console)
        return

    if args.mode == "bounty":
        from modules.bugbounty import run_bugbounty
        run_bugbounty(args.scope, args.output, ai_available, console)
        return

    if args.mode in ("sast", "full") and args.repo:
        from modules.sast import run_sast
        sast_results = run_sast(args.repo, args.output, ai_available, console)
        all_results["findings"].extend(sast_results.get("findings", []))

    if args.mode in ("recon", "full") and args.target:
        from modules.recon import run_recon
        recon_results = run_recon(args.target, args.cve, ai_available, console)
        all_results["findings"].extend(recon_results.get("findings", []))
        all_results["tech_stack"] = recon_results.get("tech_stack", {})

    if args.mode in ("auth", "full") and args.target:
        from modules.auth_audit import run_auth_audit
        wordlist = args.wordlist or "wordlists/common.txt"
        auth_results = run_auth_audit(args.target, wordlist, args.delay, args.threads, console)
        all_results["findings"].extend(auth_results.get("findings", []))

    if args.mode in ("bola", "full") and args.target:
        from modules.bola import run_bola
        bola_results = run_bola(args.target, args.delay, console)
        all_results["findings"].extend(bola_results.get("findings", []))

    if args.mode in ("api", "full") and args.target:
        from modules.api_checks import run_api_checks
        api_results = run_api_checks(args.target, args.delay, console)
        all_results["findings"].extend(api_results.get("findings", []))

    if args.burp:
        from modules.burp_export import generate_burp_config
        burp_path = os.path.join(args.output, f"burp_config_{session_id}.json")
        generate_burp_config(all_results.get("burp_items", []), args.target or "", burp_path)
        console.print(f"[bold green][+] Burp config → [cyan]{burp_path}[/cyan][/bold green]")

    from modules.reporter import generate_report
    generate_report(all_results, args.output, session_id, console)

    console.print(
        f"\n[bold bright_green][ WaspSting scan complete ][/bold bright_green]  "
        f"Session: [cyan]{session_id}[/cyan]  |  "
        f"[dim]Created by {AUTHOR}[/dim]"
    )


if __name__ == "__main__":
    main()
