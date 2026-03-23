"""
modules/bugcrowd.py — Bugcrowd API Scope Importer

Pulls program scope from the Bugcrowd API and saves it as a
WaspSting-compatible scope JSON file ready for --mode bounty.

Authentication (env vars only — never put tokens in code):
    export BUGCROWD_API_TOKEN=your_token_here

Usage:
    python3 waspsting.py --mode import-scope --bugcrowd-program <slug>
    python3 waspsting.py --mode import-scope --bugcrowd-list

Output:
    ./output/scope_<program_slug>_<session>.json
    Ready to pass to: python3 waspsting.py --mode bounty --scope <file>

API reference:
    https://docs.bugcrowd.com/api/getting-started/
"""

import os
import json
import time
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[bugcrowd] ERROR: 'requests' not installed. Run: pip install requests")
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────

BUGCROWD_API_BASE = "https://api.bugcrowd.com"
BUGCROWD_API_VER  = "2021-10-28"   # Bugcrowd requires an API version header
HTTP_TIMEOUT      = 15
RATE_LIMIT_DELAY  = 0.5            # seconds between paginated requests

# Bugcrowd target types we care about for web scanning
WEB_TARGET_TYPES = {
    "website", "api", "url", "web", "wildcard",
}

# ── Credential loader ─────────────────────────────────────────────────────────

def _get_token() -> str:
    """
    Load Bugcrowd API token from environment.
    Exits with a clear message if not set — never falls back to prompting.
    """
    token = os.environ.get("BUGCROWD_API_TOKEN", "").strip()
    if not token:
        print(
            "\n[bugcrowd] ERROR: BUGCROWD_API_TOKEN environment variable not set.\n"
            "  Set it with:\n"
            "    export BUGCROWD_API_TOKEN=your_token_here\n"
            "  Generate a token at: https://bugcrowd.com/settings/api\n"
        )
        sys.exit(1)
    return token


def _headers(token: str) -> dict:
    return {
        "Authorization":    f"Token {token}",
        "Accept":           "application/vnd.bugcrowd+json",
        "Bugcrowd-Version": BUGCROWD_API_VER,
        "User-Agent":       "WaspSting/1.4 (authorized-pentest-tool)",
    }


# ── API client ────────────────────────────────────────────────────────────────

def _get(path: str, token: str, params: dict = None) -> dict:
    """
    Make a GET request to the Bugcrowd API.
    Handles rate limiting (429) with a single retry.
    Raises RuntimeError on non-2xx responses.
    """
    url = f"{BUGCROWD_API_BASE}{path}"
    try:
        r = requests.get(
            url,
            headers=_headers(token),
            params=params or {},
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as e:
        raise RuntimeError(f"Network error reaching Bugcrowd API: {e}")

    if r.status_code == 401:
        raise RuntimeError(
            "Bugcrowd API returned 401 Unauthorized.\n"
            "  Check your BUGCROWD_API_TOKEN is valid and not expired."
        )
    if r.status_code == 403:
        raise RuntimeError(
            "Bugcrowd API returned 403 Forbidden.\n"
            "  Your token may not have permission to access this program."
        )
    if r.status_code == 404:
        raise RuntimeError(
            f"Bugcrowd API returned 404 Not Found for: {path}\n"
            "  Check the program slug is correct (--bugcrowd-list to see all)."
        )
    if r.status_code == 429:
        # Rate limited — wait and retry once
        retry_after = int(r.headers.get("Retry-After", 10))
        print(f"[bugcrowd] Rate limited. Waiting {retry_after}s...")
        time.sleep(retry_after)
        return _get(path, token, params)
    if not r.ok:
        raise RuntimeError(
            f"Bugcrowd API error {r.status_code}: {r.text[:200]}"
        )

    return r.json()


def _get_paginated(path: str, token: str, data_key: str) -> list:
    """
    Fetch all pages of a Bugcrowd API endpoint.
    Bugcrowd uses offset pagination: ?page[limit]=25&page[offset]=0
    """
    results = []
    offset  = 0
    limit   = 25

    while True:
        data = _get(path, token, params={
            "page[limit]":  limit,
            "page[offset]": offset,
        })
        page_items = data.get(data_key, [])
        results.extend(page_items)

        # Check if there are more pages
        meta  = data.get("meta", {})
        total = meta.get("total_hits", len(results))
        offset += limit
        time.sleep(RATE_LIMIT_DELAY)

        if offset >= total or not page_items:
            break

    return results


# ── Scope parsing ─────────────────────────────────────────────────────────────

def _normalise_target(target: dict) -> Optional[dict]:
    """
    Convert a Bugcrowd target object into a clean WaspSting scope entry.
    Returns None if the target is not web-relevant.

    Bugcrowd target structure:
    {
      "name": "https://app.example.com",
      "category": "website",
      "description": "Main web application",
      "uri": "https://app.example.com",
      ...
    }
    """
    category = (target.get("category") or "").lower()
    name     = (target.get("name") or "").strip()
    uri      = (target.get("uri")  or name).strip()

    # Skip non-web targets (mobile apps, executables, hardware, etc.)
    if category and category not in WEB_TARGET_TYPES:
        return None

    # Try to infer if it's web even without explicit category
    if not uri:
        return None

    is_wildcard = uri.startswith("*.") or "*." in uri

    # Convert wildcard to apex for scanning, flag it clearly
    scan_uri = uri
    if is_wildcard:
        # *.example.com → https://example.com (apex, not wildcard)
        apex = uri.lstrip("*.").lstrip(".")
        if not apex.startswith("http"):
            apex = f"https://{apex}"
        scan_uri = apex

    elif not uri.startswith("http"):
        scan_uri = f"https://{uri}"

    parsed = urlparse(scan_uri)
    if not parsed.netloc:
        return None

    return {
        "uri":         uri,          # original as listed on Bugcrowd
        "scan_uri":    scan_uri,     # safe to pass to --target
        "category":    category or "website",
        "is_wildcard": is_wildcard,
        "description": (target.get("description") or "").strip(),
    }


def _parse_target_groups(groups: list) -> tuple[list, list]:
    """
    Parse Bugcrowd target groups into in_scope and out_of_scope lists.

    Bugcrowd organises targets into named groups, each with an
    in_scope boolean and a list of targets.
    """
    in_scope     = []
    out_of_scope = []

    for group in groups:
        group_in_scope = group.get("in_scope", True)
        targets        = group.get("targets", {}).get("data", [])

        for t in targets:
            attrs      = t.get("attributes", t)   # handle both nested and flat
            normalised = _normalise_target(attrs)
            if not normalised:
                continue
            if group_in_scope:
                in_scope.append(normalised)
            else:
                out_of_scope.append(normalised)

    return in_scope, out_of_scope


# ── Public API ────────────────────────────────────────────────────────────────

def list_programs(console) -> list[dict]:
    """
    Fetch all Bugcrowd programs the token has access to.
    Prints a summary table and returns the raw program list.
    """
    token = _get_token()
    console.print("\n[bold cyan]Fetching Bugcrowd programs...[/bold cyan]")

    try:
        programs = _get_paginated("/bounty_briefs", token, "data")
    except RuntimeError as e:
        console.print(f"[bold red]ERROR:[/bold red] {e}")
        return []

    if not programs:
        console.print("[yellow]No programs found for this token.[/yellow]")
        return []

    from rich.table import Table
    from rich import box

    table = Table(box=box.SIMPLE, header_style="bold cyan",
                  title=f"Bugcrowd Programs ({len(programs)} found)")
    table.add_column("Slug",        style="cyan", width=30)
    table.add_column("Name",        width=40)
    table.add_column("Max Reward",  justify="right", width=12)
    table.add_column("Targets",     justify="right", width=8)

    for p in programs:
        attrs = p.get("attributes", p)
        table.add_row(
            attrs.get("code", "—"),
            attrs.get("name", "—")[:39],
            f"${attrs.get('max_payout', 0):,}" if attrs.get("max_payout") else "—",
            str(attrs.get("target_count", "?")),
        )

    console.print(table)
    console.print(
        "\n[dim]Use the Slug with:[/dim] "
        "[bold]--bugcrowd-program <slug>[/bold]\n"
    )
    return programs


def import_scope(program_slug: str, output_dir: str, console) -> Optional[str]:
    """
    Import scope for a specific Bugcrowd program and save as WaspSting
    scope JSON. Returns the path to the saved file, or None on failure.

    Args:
        program_slug: The program's code/slug from Bugcrowd (e.g. 'acme-corp')
        output_dir:   Directory to save the scope file (default: ./output)
        console:      Rich console for output
    """
    token = _get_token()

    console.print(
        f"\n[bold cyan]Importing Bugcrowd scope:[/bold cyan] {program_slug}"
    )

    # ── 1. Fetch program metadata ─────────────────────────────────────────────
    try:
        program_data = _get(f"/bounty_briefs/{program_slug}", token)
    except RuntimeError as e:
        console.print(f"[bold red]ERROR:[/bold red] {e}")
        return None

    attrs = program_data.get("data", {}).get("attributes",
            program_data.get("attributes", {}))

    program_name   = attrs.get("name", program_slug)
    max_payout     = attrs.get("max_payout", 0)
    min_payout     = attrs.get("min_payout", 0)
    program_url    = f"https://bugcrowd.com/{program_slug}"

    console.print(f"  [green]✓[/green] Program: {program_name}")
    console.print(
        f"  [green]✓[/green] Reward range: "
        f"${min_payout:,} – ${max_payout:,}"
        if max_payout else "  [dim]Reward range: not disclosed[/dim]"
    )

    # ── 2. Fetch target groups (scope) ────────────────────────────────────────
    try:
        groups_data = _get(
            f"/bounty_briefs/{program_slug}/target_groups", token
        )
    except RuntimeError as e:
        console.print(f"[bold red]ERROR fetching scope:[/bold red] {e}")
        return None

    raw_groups = groups_data.get("data", [])
    if not raw_groups:
        console.print(
            "[yellow]Warning: No target groups found. "
            "The program may have no scope defined yet.[/yellow]"
        )

    in_scope, out_of_scope = _parse_target_groups(raw_groups)

    web_in_scope = [t for t in in_scope]   # already filtered to web in _normalise_target
    wildcards    = [t for t in web_in_scope if t["is_wildcard"]]
    direct       = [t for t in web_in_scope if not t["is_wildcard"]]

    console.print(f"  [green]✓[/green] In-scope web targets: {len(web_in_scope)}")
    if wildcards:
        console.print(
            f"  [yellow]⚠[/yellow]  Wildcard targets: {len(wildcards)} "
            f"(converted to apex domain for scanning)"
        )
    console.print(f"  [dim]Out-of-scope entries: {len(out_of_scope)}[/dim]")

    # ── 3. Build WaspSting scope JSON ─────────────────────────────────────────
    scope = {
        "program_name":    program_name,
        "platform":        "Bugcrowd",
        "program_url":     program_url,
        "imported_at":     datetime.now().isoformat(),
        "reward_range":    (
            f"${min_payout:,} – ${max_payout:,}" if max_payout else "Not disclosed"
        ),
        "in_scope": [t["scan_uri"] for t in web_in_scope],
        "out_of_scope": [t["uri"] for t in out_of_scope],
        "vulnerability_types": [
            "XSS", "SQLi", "IDOR", "RCE", "SSRF",
            "Auth Bypass", "SSTI", "Path Traversal",
        ],
        "excluded_vuln_types": [],
        "special_rules": [
            "Imported via Bugcrowd API — verify rules at program page before testing",
            f"Program URL: {program_url}",
        ],
        "notes": (
            f"Auto-imported from Bugcrowd. "
            f"{len(wildcards)} wildcard target(s) converted to apex domain. "
            f"Always verify scope at {program_url} before testing."
        ),
        # Extra metadata — not used by bounty planner but useful for reference
        "_meta": {
            "raw_in_scope":     in_scope,
            "raw_out_of_scope": out_of_scope,
            "wildcard_targets": [t["uri"] for t in wildcards],
            "direct_targets":   [t["uri"] for t in direct],
        },
    }

    # ── 4. Save to file ───────────────────────────────────────────────────────
    session   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_slug = "".join(c if c.isalnum() or c in "-_" else "_"
                        for c in program_slug)
    filename  = f"scope_{safe_slug}_{session}.json"
    out_path  = Path(output_dir) / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)

    out_path.write_text(json.dumps(scope, indent=2))

    console.print(f"\n[bold green]✓ Scope saved:[/bold green] {out_path}")
    console.print(
        f"\n[dim]Run the bug bounty planner with:[/dim]\n"
        f"  [bold]python3 waspsting.py --mode bounty --scope {out_path}[/bold]\n"
    )

    # ── 5. Print scope summary ────────────────────────────────────────────────
    if web_in_scope:
        from rich.table import Table
        from rich import box

        table = Table(
            box=box.SIMPLE,
            title="In-Scope Web Targets",
            header_style="bold cyan",
        )
        table.add_column("Original URI",  style="cyan", width=45)
        table.add_column("Scan Target",   width=45)
        table.add_column("Type",          width=10)
        table.add_column("Wildcard",      width=9)

        for t in web_in_scope:
            wc = "[yellow]YES ⚠[/yellow]" if t["is_wildcard"] else "[dim]no[/dim]"
            table.add_row(
                t["uri"][:44],
                t["scan_uri"][:44],
                t["category"],
                wc,
            )

        console.print(table)

    if wildcards:
        console.print(
            "[yellow]⚠  Wildcard note:[/yellow] Wildcard targets (*.example.com) "
            "have been converted to their apex domain (https://example.com).\n"
            "   Manually enumerate subdomains with [bold]--mode enum[/bold] "
            "before running a full scan.\n"
        )

    return str(out_path)


# ── CLI self-test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """
    Quick smoke test — lists programs if token is set.
    Does not import any scope (read-only).
    """
    from rich.console import Console
    console = Console()

    console.print("\n[bold]WaspSting — Bugcrowd API self-test[/bold]")
    console.print("[dim]Checking BUGCROWD_API_TOKEN...[/dim]")

    token = os.environ.get("BUGCROWD_API_TOKEN", "")
    if not token:
        console.print(
            "[red]BUGCROWD_API_TOKEN not set.[/red]\n"
            "  export BUGCROWD_API_TOKEN=your_token_here"
        )
        sys.exit(1)

    console.print("[green]✓ Token found[/green]")
    list_programs(console)