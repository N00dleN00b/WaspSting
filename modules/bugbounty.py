"""
modules/bugbounty.py — Bug Bounty Scope Analyzer & Test Plan Generator

Ingests bug bounty program details (scope, out-of-scope, rules, rewards)
and generates a prioritized, structured testing plan with:
- Scope map (in/out)
- Attack surface breakdown
- Prioritized test checklist by impact
- Ollama AI analysis (optional)
- Markdown test plan export
"""

import json
import re
import os
import sys
import requests
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


# ──────────────────────────────────────────────
# Scope input templates / parsers
# ──────────────────────────────────────────────

SCOPE_TEMPLATE = {
    "program_name": "",
    "platform": "",          # HackerOne, Bugcrowd, Intigriti, etc.
    "in_scope": [],          # list of domains/apps/IPs
    "out_of_scope": [],      # list of exclusions
    "vulnerability_types": [],  # accepted vuln types
    "excluded_vuln_types": [],
    "reward_range": "",
    "special_rules": [],
    "notes": ""
}

# Common vulnerability types for bounty programs
VULN_PRIORITY = {
    "RCE":                  {"score": 10, "owasp": "A05", "test_module": "api_checks"},
    "SQL Injection":         {"score": 10, "owasp": "A05", "test_module": "api_checks"},
    "SSRF":                  {"score": 9,  "owasp": "A05", "test_module": "api_checks"},
    "Authentication Bypass": {"score": 9,  "owasp": "A07", "test_module": "auth_audit"},
    "IDOR/BOLA":             {"score": 8,  "owasp": "A01", "test_module": "bola"},
    "XSS (Stored)":          {"score": 8,  "owasp": "A05", "test_module": "api_checks"},
    "XXE":                   {"score": 7,  "owasp": "A05", "test_module": "api_checks"},
    "Privilege Escalation":  {"score": 7,  "owasp": "A01", "test_module": "auth_audit"},
    "Business Logic":        {"score": 7,  "owasp": "A06", "test_module": "api_checks"},
    "CSRF":                  {"score": 6,  "owasp": "A06", "test_module": "api_checks"},
    "XSS (Reflected)":       {"score": 5,  "owasp": "A05", "test_module": "api_checks"},
    "Open Redirect":         {"score": 4,  "owasp": "A01", "test_module": "recon"},
    "Info Disclosure":       {"score": 3,  "owasp": "A09", "test_module": "recon"},
    "Missing Headers":       {"score": 2,  "owasp": "A02", "test_module": "recon"},
    "Rate Limiting":         {"score": 2,  "owasp": "A06", "test_module": "api_checks"},
}

# Attack surface categories
SURFACE_PATTERNS = {
    "web_app":      [r"https?://", r"www\.", r"\.com$", r"\.io$", r"\.net$"],
    "api":          [r"/api", r"api\.", r"rest\.", r"graphql", r"\.json$"],
    "mobile":       [r"android", r"ios", r"mobile\.", r"app\.", r"\.apk", r"\.ipa"],
    "admin_panel":  [r"admin\.", r"/admin", r"dashboard\.", r"console\."],
    "auth_system":  [r"auth\.", r"login\.", r"sso\.", r"oauth", r"id\."],
    "cdn_assets":   [r"cdn\.", r"static\.", r"assets\.", r"media\."],
    "cloud_infra":  [r"s3\.amazonaws", r"storage\.googleapis", r"blob\.core\.windows"],
    "subdomains":   [r"\*\.", r"[a-z]+\.[a-z]+\.[a-z]+"],
}

# Test plan template per surface type
TEST_PLANS = {
    "web_app": [
        "Enumerate all endpoints via crawl / sitemap.xml / robots.txt",
        "Run WaspSting recon module: headers, tech stack, CVE lookup",
        "Test authentication flows: login, registration, password reset",
        "Map all forms and test for XSS (stored > reflected > DOM)",
        "Test all input fields for SQL injection",
        "Check CORS configuration with evil.example.com origin",
        "Test CSRF on state-changing operations",
        "Check for forced browsing to admin/debug endpoints",
        "Review JavaScript files for API keys, endpoints, logic",
        "Test file upload endpoints for dangerous extensions",
    ],
    "api": [
        "Run WaspSting API checks module",
        "Test all endpoints for BOLA/IDOR with sequential IDs",
        "Check for missing authentication on API endpoints",
        "Test rate limiting on all sensitive endpoints",
        "Look for mass assignment via extra POST parameters",
        "Test for excessive data exposure in responses",
        "Check GraphQL introspection for hidden fields",
        "Test for HTTP verb tampering (GET vs POST vs PUT)",
        "Fuzz parameter types (string→int, int→string, null, array)",
        "Check API versioning — test deprecated versions",
    ],
    "auth_system": [
        "Run WaspSting auth audit module",
        "Test account lockout policy (brute force protection)",
        "Test JWT tokens: alg:none, HS256/RS256 confusion, weak secret",
        "Test OAuth flows for state CSRF, open redirect, token leakage",
        "Check password reset: token expiry, predictability, account enum",
        "Test MFA bypass techniques: backup codes, race conditions",
        "Check session invalidation on logout",
        "Test account takeover via email change flow",
        "Check for username enumeration via response timing/content",
        "Test SSO/SAML for signature bypass",
    ],
    "admin_panel": [
        "Test default credentials (admin/admin, admin/password)",
        "Check for unauthenticated access to admin routes",
        "Test vertical privilege escalation from user to admin",
        "Look for IDOR in admin functions referencing user objects",
        "Test admin API endpoints without admin JWT",
        "Check for reflected/stored XSS in admin dashboard inputs",
        "Test CSV/export functionality for injection",
        "Check for unrestricted file read/write in admin file manager",
    ],
    "mobile": [
        "Decompile APK/IPA and search for hardcoded secrets",
        "Intercept traffic via Burp proxy (install CA cert)",
        "Check SSL pinning implementation",
        "Test for insecure data storage (SharedPreferences, SQLite, logs)",
        "Test deep links for open redirect and parameter injection",
        "Check exported activities/content providers",
        "Test for intent hijacking",
        "Analyze JavaScript in WebView for XSS",
    ],
    "cloud_infra": [
        "Test S3 bucket for public read/write access",
        "Check bucket enumeration via common naming patterns",
        "Test for Azure blob / GCS bucket misconfigurations",
        "Look for exposed cloud credentials in JS / config files",
        "Test metadata service access (169.254.169.254) via SSRF",
    ],
}


# ──────────────────────────────────────────────
# Interactive scope input
# ──────────────────────────────────────────────

def interactive_scope_input(console) -> dict:
    """Walk the user through entering bug bounty scope interactively."""
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm

    console.print(Panel(
        "[bold green]Bug Bounty Scope Analyzer[/bold green]\n\n"
        "Enter your target's bug bounty program details.\n"
        "Paste scope items one per line, press [bold]Enter twice[/bold] when done.\n"
        "Or provide a [bold]--scope[/bold] JSON file directly.",
        border_style="green", title="[bold]🎯 N00dleN00b // WaspSting[/bold]"
    ))

    scope = dict(SCOPE_TEMPLATE)

    scope["program_name"] = Prompt.ask("\n[cyan]Program name[/cyan] (e.g. HackerOne - Acme Corp)")
    scope["platform"] = Prompt.ask("[cyan]Platform[/cyan] (HackerOne/Bugcrowd/Intigriti/Private)", default="HackerOne")
    scope["reward_range"] = Prompt.ask("[cyan]Reward range[/cyan] (e.g. $100-$10,000)", default="unknown")

    console.print("\n[bold]In-scope targets[/bold] (one per line, blank line to finish):")
    console.print("[dim]Examples: *.example.com | https://app.example.com | 192.168.1.0/24 | iOS app[/dim]")
    while True:
        line = input("  > ").strip()
        if not line:
            break
        scope["in_scope"].append(line)

    console.print("\n[bold]Out-of-scope[/bold] (one per line, blank to finish):")
    console.print("[dim]Examples: blog.example.com | /api/internal | staging.example.com[/dim]")
    while True:
        line = input("  > ").strip()
        if not line:
            break
        scope["out_of_scope"].append(line)

    console.print("\n[bold]Accepted vulnerability types[/bold] (one per line, blank to skip):")
    console.print("[dim]Leave blank to include all. Examples: XSS | SQLi | IDOR | RCE[/dim]")
    while True:
        line = input("  > ").strip()
        if not line:
            break
        scope["vulnerability_types"].append(line)

    console.print("\n[bold]Special rules / notes[/bold] (one per line, blank to finish):")
    console.print("[dim]Examples: No automated scanning | Do not test payment flows | Rate limit: 10 req/s[/dim]")
    while True:
        line = input("  > ").strip()
        if not line:
            break
        scope["special_rules"].append(line)

    return scope


def load_scope_from_file(path: str) -> dict:
    """Load scope from a JSON file."""
    data = json.loads(Path(path).read_text())
    scope = dict(SCOPE_TEMPLATE)
    scope.update(data)
    return scope


def parse_scope_text(text: str) -> dict:
    """
    Parse a raw pasted bug bounty scope text block.
    Handles common formats from HackerOne, Bugcrowd, etc.
    """
    scope = dict(SCOPE_TEMPLATE)
    lines = [l.strip() for l in text.strip().split("\n") if l.strip()]

    in_section = None
    for line in lines:
        lower = line.lower()

        # Section headers
        if any(w in lower for w in ["in scope", "in-scope", "targets:"]):
            in_section = "in_scope"
            continue
        elif any(w in lower for w in ["out of scope", "out-of-scope", "exclusions"]):
            in_section = "out_of_scope"
            continue
        elif any(w in lower for w in ["vulnerability types", "accepted vulns", "bounty types"]):
            in_section = "vulnerability_types"
            continue
        elif any(w in lower for w in ["rules", "restrictions", "notes"]):
            in_section = "special_rules"
            continue

        # URL/domain patterns → likely scope items
        if re.search(r"https?://|www\.|^\*\.", line) and in_section in (None, "in_scope"):
            scope["in_scope"].append(line.lstrip("•-* "))
        elif in_section and in_section in scope and isinstance(scope[in_section], list):
            scope[in_section].append(line.lstrip("•-* "))

    return scope


# ──────────────────────────────────────────────
# Attack surface analysis
# ──────────────────────────────────────────────

def classify_surface(scope_items: list) -> dict:
    """Classify scope items into attack surface categories."""
    surfaces = {k: [] for k in SURFACE_PATTERNS}

    for item in scope_items:
        matched = False
        for surface, patterns in SURFACE_PATTERNS.items():
            if any(re.search(p, item, re.IGNORECASE) for p in patterns):
                surfaces[surface].append(item)
                matched = True
                break
        if not matched:
            surfaces["web_app"].append(item)  # default

    return {k: v for k, v in surfaces.items() if v}


def prioritize_vulns(scope: dict) -> list:
    """Return prioritized vulnerability list based on scope."""
    accepted = [v.lower() for v in scope.get("vulnerability_types", [])]
    excluded = [v.lower() for v in scope.get("excluded_vuln_types", [])]

    results = []
    for vuln, meta in VULN_PRIORITY.items():
        # Filter by accepted types if specified
        if accepted and not any(a in vuln.lower() for a in accepted):
            continue
        if any(e in vuln.lower() for e in excluded):
            continue
        results.append({"vuln": vuln, **meta})

    return sorted(results, key=lambda x: x["score"], reverse=True)


def analyze_with_ollama(scope: dict) -> str:
    """Use local Ollama to generate insights from scope."""
    prompt = f"""You are an expert bug bounty hunter and penetration tester.

Analyze this bug bounty program scope and provide:
1. Top 3 highest-value attack vectors to focus on first
2. Any unusual or interesting scope items worth deep investigation
3. Common mistakes hunters make on this type of program
4. One creative/non-obvious test approach specific to this scope

Bug Bounty Program:
{json.dumps(scope, indent=2)}

Be concise, practical, and specific to the actual scope items provided."""

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "llama3", "prompt": prompt, "stream": False},
            timeout=60
        )
        if r.status_code == 200:
            return r.json().get("response", "").strip()
    except Exception:
        pass
    return ""


# ──────────────────────────────────────────────
# Test plan generation
# ──────────────────────────────────────────────

def generate_test_plan(scope: dict, surfaces: dict, prioritized_vulns: list) -> dict:
    """Build a structured test plan from scope analysis."""
    plan = {
        "program": scope.get("program_name", "Unknown"),
        "platform": scope.get("platform", ""),
        "generated_at": datetime.now().isoformat(),
        "phases": [],
        "waspsting_commands": [],
        "scope_summary": {
            "in_scope_count": len(scope.get("in_scope", [])),
            "out_of_scope_count": len(scope.get("out_of_scope", [])),
            "surfaces_detected": list(surfaces.keys()),
            "top_vuln_priorities": [v["vuln"] for v in prioritized_vulns[:5]]
        }
    }

    # Phase 1: Recon
    plan["phases"].append({
        "phase": 1,
        "name": "Passive Recon & Fingerprinting",
        "priority": "FIRST",
        "steps": [
            f"Run: waspsting --target <target> --mode recon --cve --confirm",
            "Map all in-scope subdomains via subfinder/amass/crt.sh",
            "Screenshot all discovered assets with aquatone/eyewitness",
            "Check Wayback Machine for old endpoints / leaked params",
            "Google dork: site:target.com (inurl:api | inurl:admin | ext:json)",
            "Search GitHub/GitLab for exposed secrets: org:targetcorp",
            "Check Shodan/Censys for exposed ports and services",
        ],
        "targets": scope.get("in_scope", [])[:10]
    })

    # Phase 2 onward — by detected surface
    phase_num = 2
    surface_priority = ["auth_system", "api", "admin_panel", "web_app", "mobile", "cloud_infra"]

    for surface in surface_priority:
        if surface not in surfaces:
            continue

        steps = TEST_PLANS.get(surface, [])
        if not steps:
            continue

        # Map relevant waspsting modules
        module_map = {
            "auth_system": "auth",
            "api":         "api",
            "admin_panel": "bola",
            "web_app":     "full",
        }
        ws_module = module_map.get(surface, "recon")

        plan["phases"].append({
            "phase": phase_num,
            "name": f"{surface.replace('_', ' ').title()} Testing",
            "priority": "HIGH" if surface in ("auth_system", "api", "admin_panel") else "MEDIUM",
            "steps": steps,
            "targets": surfaces[surface],
            "waspsting_cmd": f"waspsting --target {{target}} --mode {ws_module} --confirm"
        })
        phase_num += 1

    # Phase: High-value vulns checklist
    plan["phases"].append({
        "phase": phase_num,
        "name": "High-Value Vulnerability Checklist",
        "priority": "HIGH",
        "steps": [
            f"[ ] {v['vuln']} (OWASP {v['owasp']}) — score {v['score']}/10"
            for v in prioritized_vulns[:10]
        ],
        "note": "Prioritized by typical payout value and program acceptance"
    })

    # WaspSting commands
    for target in scope.get("in_scope", [])[:5]:
        if re.search(r"https?://", target):
            plan["waspsting_commands"].extend([
                f"python waspsting.py --target {target} --mode recon --cve --confirm",
                f"python waspsting.py --target {target} --mode bola --confirm",
                f"python waspsting.py --target {target} --mode api --confirm",
                f"python waspsting.py --target {target} --mode auth --confirm",
                f"python waspsting.py --target {target} --mode full --burp --confirm",
            ])
        elif re.search(r"github\.com", target):
            plan["waspsting_commands"].append(
                f"python waspsting.py --repo {target} --mode sast"
            )

    return plan


# ──────────────────────────────────────────────
# Rich display
# ──────────────────────────────────────────────

def display_test_plan(plan: dict, scope: dict, surfaces: dict,
                       prioritized_vulns: list, ai_note: str, console):
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    from rich import box

    console.print(Rule("[bold green]🎯 Bug Bounty Test Plan[/bold green]", style="green"))
    console.print()

    # Program overview
    overview = (
        f"[bold]Program:[/bold] {scope.get('program_name', '?')}\n"
        f"[bold]Platform:[/bold] {scope.get('platform', '?')}  |  "
        f"[bold]Rewards:[/bold] {scope.get('reward_range', '?')}\n"
        f"[bold]In-scope:[/bold] {len(scope.get('in_scope', []))} targets  |  "
        f"[bold]Out-of-scope:[/bold] {len(scope.get('out_of_scope', []))} exclusions\n"
        f"[bold]Surfaces detected:[/bold] {', '.join(surfaces.keys()) or 'web_app'}"
    )
    console.print(Panel(overview, title="[bold]Program Overview[/bold]", border_style="cyan"))
    console.print()

    # Scope table
    if scope.get("in_scope"):
        console.print("[bold]✅ In Scope:[/bold]")
        for item in scope["in_scope"]:
            console.print(f"  [green]→[/green] {item}")
    if scope.get("out_of_scope"):
        console.print("\n[bold]❌ Out of Scope:[/bold]")
        for item in scope["out_of_scope"]:
            console.print(f"  [red]✗[/red] {item}")
    if scope.get("special_rules"):
        console.print("\n[bold]⚠ Special Rules:[/bold]")
        for rule in scope["special_rules"]:
            console.print(f"  [yellow]![/yellow] {rule}")
    console.print()

    # Prioritized vulnerabilities
    console.print("[bold]🎯 Vulnerability Priorities (by impact):[/bold]")
    vuln_table = Table(box=box.SIMPLE, header_style="bold magenta")
    vuln_table.add_column("Priority", width=4)
    vuln_table.add_column("Vulnerability", style="cyan", width=25)
    vuln_table.add_column("Score", width=7)
    vuln_table.add_column("OWASP", width=6)
    vuln_table.add_column("WaspSting Module", width=15)
    vuln_table.add_column("Status", width=10)

    for i, v in enumerate(prioritized_vulns[:10], 1):
        excluded_names = [x.lower() for x in scope.get("excluded_vuln_types", [])]
        is_excluded = any(e in v["vuln"].lower() for e in excluded_names)
        status = "[red]Excluded[/red]" if is_excluded else "[green]In scope[/green]"
        vuln_table.add_row(
            str(i), v["vuln"], f"{v['score']}/10",
            v["owasp"], v["test_module"], status
        )
    console.print(vuln_table)
    console.print()

    # Test phases
    for phase in plan["phases"]:
        priority_color = {
            "FIRST": "bold red", "HIGH": "red", "MEDIUM": "yellow"
        }.get(phase.get("priority", "MEDIUM"), "white")

        header = (
            f"Phase {phase['phase']}: {phase['name']}  "
            f"[{priority_color}][{phase.get('priority','MEDIUM')}][/{priority_color}]"
        )
        if phase.get("targets"):
            header += f"\n[dim]Targets: {', '.join(phase['targets'][:3])}"
            if len(phase["targets"]) > 3:
                header += f" (+{len(phase['targets'])-3} more)"
            header += "[/dim]"

        steps_text = "\n".join(
            f"  {'[dim]' if step.startswith('[') else '[green]▸[/green] '}"
            f"{step}"
            f"{'[/dim]' if step.startswith('[') else ''}"
            for step in phase["steps"]
        )

        if phase.get("waspsting_cmd"):
            steps_text += f"\n\n  [dim]WaspSting:[/dim] [cyan]{phase['waspsting_cmd']}[/cyan]"

        console.print(Panel(
            steps_text, title=f"[bold]{header}[/bold]",
            border_style="bright_black"
        ))
        console.print()

    # WaspSting commands
    if plan.get("waspsting_commands"):
        console.print("[bold]🐝 Ready-to-run WaspSting Commands:[/bold]")
        for cmd in plan["waspsting_commands"][:8]:
            console.print(f"  [cyan]$[/cyan] {cmd}")
        console.print()

    # AI insights
    if ai_note:
        console.print(Panel(
            ai_note, title="[yellow]🤖 Ollama AI — Bounty Hunter Insights[/yellow]",
            border_style="yellow"
        ))
        console.print()


# ──────────────────────────────────────────────
# Save reports
# ──────────────────────────────────────────────

def save_plan_markdown(plan: dict, scope: dict, surfaces: dict,
                        prioritized_vulns: list, ai_note: str, path: str):
    lines = [
        f"# 🎯 WaspSting Bug Bounty Test Plan",
        f"",
        f"**Program:** {scope.get('program_name', '?')}  ",
        f"**Platform:** {scope.get('platform', '?')}  ",
        f"**Rewards:** {scope.get('reward_range', '?')}  ",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
        f"**Created by:** N00dleN00b // WaspSting  ",
        f"", "---", "",
        "## Scope", "",
        "### ✅ In Scope", ""
    ]
    for item in scope.get("in_scope", []):
        lines.append(f"- `{item}`")
    lines += ["", "### ❌ Out of Scope", ""]
    for item in scope.get("out_of_scope", []):
        lines.append(f"- `{item}`")
    if scope.get("special_rules"):
        lines += ["", "### ⚠ Special Rules", ""]
        for rule in scope["special_rules"]:
            lines.append(f"- {rule}")

    lines += ["", "---", "", "## Surfaces Detected", ""]
    for surface, items in surfaces.items():
        lines.append(f"- **{surface.replace('_',' ').title()}**: {', '.join(items[:3])}")

    lines += ["", "---", "", "## Vulnerability Priorities", "",
              "| # | Vulnerability | Score | OWASP | Module |",
              "|---|--------------|-------|-------|--------|"]
    for i, v in enumerate(prioritized_vulns[:10], 1):
        lines.append(f"| {i} | {v['vuln']} | {v['score']}/10 | {v['owasp']} | {v['test_module']} |")

    lines += ["", "---", "", "## Test Plan", ""]
    for phase in plan["phases"]:
        lines += [f"### Phase {phase['phase']}: {phase['name']} [{phase.get('priority','')}]", ""]
        if phase.get("targets"):
            lines.append(f"**Targets:** {', '.join(phase['targets'][:5])}")
            lines.append("")
        for step in phase["steps"]:
            prefix = "" if step.startswith("[") else "- [ ] "
            lines.append(f"{prefix}{step}")
        if phase.get("waspsting_cmd"):
            lines.append(f"\n```bash\n{phase['waspsting_cmd']}\n```")
        lines.append("")

    if plan.get("waspsting_commands"):
        lines += ["", "---", "", "## 🐝 WaspSting Commands", "", "```bash"]
        lines.extend(plan["waspsting_commands"][:10])
        lines += ["```", ""]

    if ai_note:
        lines += ["", "---", "", "## 🤖 AI Analysis", "", ai_note, ""]

    lines += [
        "---",
        "",
        "*Generated by [WaspSting](https://github.com/N00dleN00b/waspsting) — "
        "Created by N00dleN00b*"
    ]

    Path(path).write_text("\n".join(lines), encoding="utf-8")


# ──────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────

def run_bugbounty(scope_file: str | None, output_dir: str,
                   ai_available: bool, console) -> dict:
    """Main bug bounty analysis runner."""
    from rich.panel import Panel
    from rich.rule import Rule

    console.print(f"\n[bold cyan]═══ BUG BOUNTY SCOPE ANALYZER[/bold cyan]\n")

    # Load or collect scope
    if scope_file and Path(scope_file).exists():
        ext = Path(scope_file).suffix.lower()
        if ext == ".json":
            scope = load_scope_from_file(scope_file)
            console.print(f"[green]✓ Scope loaded from JSON: {scope_file}[/green]")
        else:
            # Treat as raw text
            raw = Path(scope_file).read_text()
            scope = parse_scope_text(raw)
            console.print(f"[green]✓ Scope parsed from text file: {scope_file}[/green]")
    else:
        scope = interactive_scope_input(console)

    if not scope.get("in_scope"):
        console.print("[yellow]⚠ No in-scope targets defined. Add targets to get a useful plan.[/yellow]")

    # Analyze
    surfaces = classify_surface(scope.get("in_scope", []))
    prioritized_vulns = prioritize_vulns(scope)

    # AI analysis
    ai_note = ""
    if ai_available and scope.get("in_scope"):
        console.print("[dim yellow]🤖 Asking Ollama for bounty hunter insights...[/dim yellow]")
        ai_note = analyze_with_ollama(scope)

    # Generate plan
    plan = generate_test_plan(scope, surfaces, prioritized_vulns)

    # Display
    display_test_plan(plan, scope, surfaces, prioritized_vulns, ai_note, console)

    # Save
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(output_dir, exist_ok=True)

    md_path = os.path.join(output_dir, f"bugbounty_plan_{session_id}.md")
    json_path = os.path.join(output_dir, f"bugbounty_scope_{session_id}.json")

    save_plan_markdown(plan, scope, surfaces, prioritized_vulns, ai_note, md_path)
    Path(json_path).write_text(json.dumps({
        "scope": scope, "plan": plan,
        "surfaces": surfaces,
        "prioritized_vulns": prioritized_vulns
    }, indent=2), encoding="utf-8")

    console.print(f"[bold green]📄 Bug bounty plan saved:[/bold green]")
    console.print(f"   Markdown → [cyan]{md_path}[/cyan]")
    console.print(f"   JSON     → [cyan]{json_path}[/cyan]")
    console.print()

    # Save scope template for reuse
    template_path = os.path.join(output_dir, f"scope_template_{session_id}.json")
    Path(template_path).write_text(json.dumps(scope, indent=2), encoding="utf-8")
    console.print(f"[dim]Scope saved for reuse → {template_path}[/dim]\n")

    return {"plan": plan, "scope": scope, "findings": []}
