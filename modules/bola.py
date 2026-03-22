"""
modules/bola.py — BOLA/IDOR endpoint walking and documentation

Broken Object Level Authorization (BOLA) testing:
- Identifies numeric/sequential IDs in API endpoints
- Documents test cases for manual verification
- Walks adjacent IDs and records responses
"""

import requests
import re
import json
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin

# Common API endpoint patterns to probe for IDOR
OBJECT_PATTERNS = [
    r"/(?:user|users)/(\d+)",
    r"/(?:account|accounts)/(\d+)",
    r"/(?:order|orders)/(\d+)",
    r"/(?:item|items)/(\d+)",
    r"/(?:post|posts)/(\d+)",
    r"/(?:product|products)/(\d+)",
    r"/(?:invoice|invoices)/(\d+)",
    r"/(?:ticket|tickets)/(\d+)",
    r"/(?:document|documents)/(\d+)",
    r"/(?:file|files)/(\d+)",
    r"/(?:message|messages)/(\d+)",
    r"/(?:comment|comments)/(\d+)",
    r"/(?:report|reports)/(\d+)",
    r"/(?:profile|profiles)/(\d+)",
    r"/api/v\d+/\w+/(\d+)",
]

COMMON_ENDPOINTS = [
    "/api/v1/users/1", "/api/v1/users/2",
    "/api/users/1", "/api/users/2",
    "/api/v1/orders/1", "/api/v1/profile",
    "/api/v1/account", "/api/me",
    "/api/v1/me", "/user/profile/1",
    "/api/v1/invoices/1", "/api/v1/tickets/1",
]


def probe_endpoints(base_url: str, delay: float) -> list[dict]:
    """Probe common endpoints and record responses for BOLA analysis."""
    results = []
    session = requests.Session()
    session.headers["User-Agent"] = "WaspSting-BOLA/1.0"

    for path in COMMON_ENDPOINTS:
        url = base_url.rstrip("/") + path
        try:
            r = session.get(url, timeout=5)
            results.append({
                "url": url, "status": r.status_code,
                "size": len(r.content),
                "content_type": r.headers.get("Content-Type", ""),
                "has_json": "json" in r.headers.get("Content-Type", ""),
                "snippet": r.text[:200] if r.status_code == 200 else ""
            })
            time.sleep(delay)
        except requests.RequestException:
            pass

    return results


def test_id_walking(base_url: str, endpoint: str, original_id: int,
                    delay: float) -> list[dict]:
    """Walk adjacent IDs from a known endpoint."""
    results = []
    test_ids = [original_id - 2, original_id - 1, original_id + 1, original_id + 2]

    session = requests.Session()

    for test_id in test_ids:
        if test_id <= 0:
            continue
        url = base_url.rstrip("/") + endpoint.replace(str(original_id), str(test_id))
        try:
            r = session.get(url, timeout=5,
                           headers={"User-Agent": "WaspSting-BOLA/1.0"})
            results.append({
                "tested_id": test_id,
                "url": url,
                "status": r.status_code,
                "response_size": len(r.content),
                "accessible": r.status_code == 200,
                "content_preview": r.text[:150] if r.status_code == 200 else ""
            })
            time.sleep(delay)
        except requests.RequestException:
            pass

    return results


def generate_bola_test_cases(target: str, endpoints: list[dict]) -> list[dict]:
    """Generate documented BOLA test cases from discovered endpoints."""
    test_cases = []

    for ep in endpoints:
        if ep["status"] != 200:
            continue

        url_path = urlparse(ep["url"]).path
        for pattern in OBJECT_PATTERNS:
            m = re.search(pattern, url_path)
            if m:
                obj_id = int(m.group(1))
                test_cases.append({
                    "endpoint": url_path,
                    "object_type": re.sub(r"/(\d+).*", "", url_path).split("/")[-1],
                    "original_id": obj_id,
                    "test_ids": [obj_id - 1, obj_id + 1, obj_id + 100],
                    "technique": "Sequential ID walking",
                    "full_url": ep["url"],
                    "doc_template": {
                        "endpoint": url_path,
                        "original_id": obj_id,
                        "tested_ids": [obj_id - 1, obj_id + 1],
                        "expected": "403 Forbidden or redirect to own resource",
                        "actual": "TBD — verify manually",
                        "severity": "HIGH if other user data returned",
                        "evidence": "FILL: Screenshot / response body showing other user data",
                        "cvss": "8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)"
                    }
                })
                break

    return test_cases


def run_bola(target: str, delay: float, console) -> dict:
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    console.print(f"\n[bold cyan]═══ BOLA/IDOR MODULE[/bold cyan] → {target}\n")

    findings = []

    # Probe endpoints
    console.print("[dim]Probing common API endpoints...[/dim]")
    endpoints = probe_endpoints(target, delay)

    accessible = [e for e in endpoints if e["status"] == 200]
    console.print(f"[green]✓ {len(accessible)} accessible endpoints found of {len(endpoints)} probed[/green]\n")

    if accessible:
        ep_table = Table(box=box.SIMPLE, header_style="bold magenta")
        ep_table.add_column("Endpoint", style="cyan")
        ep_table.add_column("Status")
        ep_table.add_column("Size")
        ep_table.add_column("JSON")

        for ep in endpoints[:15]:
            status_style = "green" if ep["status"] == 200 else "dim"
            ep_table.add_row(
                ep["url"].replace(target, ""),
                f"[{status_style}]{ep['status']}[/{status_style}]",
                str(ep["size"]),
                "✓" if ep["has_json"] else "—"
            )
        console.print(ep_table)

    # Generate test cases
    test_cases = generate_bola_test_cases(target, accessible)

    if test_cases:
        console.print(f"\n[bold yellow]⚠ {len(test_cases)} potential BOLA targets identified:[/bold yellow]\n")

        for tc in test_cases:
            console.print(Panel(
                f"[cyan]Endpoint:[/cyan]  {tc['endpoint']}\n"
                f"[cyan]Object:[/cyan]    {tc['object_type']} (ID: {tc['original_id']})\n"
                f"[cyan]Test IDs:[/cyan]  {tc['test_ids']}\n"
                f"[cyan]Technique:[/cyan] {tc['technique']}\n\n"
                f"[dim]Manual step: GET {tc['endpoint'].replace(str(tc['original_id']), str(tc['test_ids'][1]))}\n"
                f"Expected: 403 Forbidden. If 200 with other user data → BOLA confirmed.[/dim]",
                title=f"[yellow]BOLA Test Case — {tc['object_type']}[/yellow]",
                border_style="yellow"
            ))

            findings.append({
                "module": "bola",
                "category": "Broken Object Level Authorization",
                "owasp_id": "A01", "owasp_name": "Broken Access Control",
                "pentest_check": "BOLA",
                "severity": "HIGH",
                "title": f"BOLA test case: {tc['object_type']} endpoint with sequential IDs",
                "description": (
                    f"Endpoint '{tc['endpoint']}' uses sequential numeric IDs. "
                    f"BOLA vulnerability requires manual verification by testing adjacent IDs "
                    f"with a different authenticated user session."
                ),
                "evidence": f"Accessible endpoint with object ID {tc['original_id']}",
                "test_ids": tc["test_ids"],
                "fix": (
                    "Use non-sequential UUIDs for object identifiers. "
                    "Verify ownership/authorization server-side on every object access request."
                ),
                "doc_template": tc["doc_template"],
                "timestamp": datetime.now().isoformat()
            })
    else:
        console.print("[dim]No obvious sequential ID patterns detected in probed endpoints.[/dim]")
        console.print("[dim]Manual BOLA testing recommended against authenticated endpoints.[/dim]")

    # Parameter pollution doc
    console.print("\n[bold]Other BOLA/IDOR Techniques to Document:[/bold]")
    techniques = [
        ("Parameter pollution",   "?id=123&id=456", "Try sending duplicate params"),
        ("Header injection",      "X-User-Id: 456", "Override user context via header"),
        ("JSON body swap",        '{"user_id": 456}', "Swap IDs in POST body"),
        ("Path traversal",        "../456/profile", "Navigate up/across object tree"),
        ("Wildcard ID",           "* or null or 0", "Test edge case IDs"),
        ("GraphQL IDOR",          "{user(id:456){email}}", "Query other users in GraphQL"),
    ]

    tech_table = Table(box=box.SIMPLE, header_style="bold")
    tech_table.add_column("Technique", style="cyan", width=22)
    tech_table.add_column("Example payload", width=28)
    tech_table.add_column("Notes")
    for t, p, n in techniques:
        tech_table.add_row(t, p, n)
    console.print(tech_table)

    console.print(f"\n[green]✓ BOLA module complete — {len(findings)} test cases documented[/green]\n")
    return {"findings": findings}
