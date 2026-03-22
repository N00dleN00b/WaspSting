"""
modules/subdomain.py — Subdomain enumeration
Combines: DNS brute force, crt.sh certificate transparency, HackerTarget API (free)
No external tools required — pure Python.
"""

import re
import json
import time
import socket
import requests
import concurrent.futures
from datetime import datetime
from pathlib import Path

MAX_WORKERS   = 20
DNS_TIMEOUT   = 3
HTTP_TIMEOUT  = 6

WORDLIST_PATHS = [
    "wordlists/subdomains.txt",
    "/usr/share/wordlists/subdomains.txt",
]

BUILTIN_SUBDOMAINS = [
    "www", "api", "app", "admin", "mail", "dev", "staging", "test",
    "beta", "portal", "dashboard", "auth", "login", "sso", "oauth",
    "cdn", "static", "assets", "media", "img", "images",
    "blog", "docs", "help", "support", "status", "monitor",
    "shop", "store", "pay", "payment", "checkout", "billing",
    "vpn", "remote", "citrix", "rdp", "smtp", "ftp", "ssh",
    "git", "gitlab", "github", "ci", "jenkins", "jira", "confluence",
    "api-v1", "api-v2", "v1", "v2", "v3", "graphql", "rest",
    "internal", "intranet", "corp", "private", "secure", "ssl",
    "m", "mobile", "ios", "android", "wap",
    "old", "legacy", "backup", "bk", "archive",
    "db", "database", "mysql", "postgres", "redis", "elastic",
    "s3", "storage", "files", "upload", "uploads",
    "stg", "uat", "qa", "preprod", "pre-prod",
    "metrics", "grafana", "kibana", "prometheus",
    "mx", "mail2", "smtp", "imap", "pop", "webmail",
    "ns1", "ns2", "dns", "cpanel", "whm", "plesk",
    "forum", "community", "wiki", "kb",
    "jobs", "careers", "hr", "training",
    "aws", "azure", "gcp", "cloud",
    "chat", "slack", "teams", "meet",
]


def load_wordlist() -> list[str]:
    for path in WORDLIST_PATHS:
        try:
            words = Path(path).read_text(errors="ignore").splitlines()
            return [w.strip() for w in words if w.strip() and not w.startswith("#")]
        except OSError:
            continue
    return BUILTIN_SUBDOMAINS


def resolve_subdomain(subdomain: str) -> dict | None:
    """Try to resolve a subdomain via DNS."""
    try:
        ips = socket.gethostbyname_ex(subdomain)[2]
        return {"subdomain": subdomain, "ips": ips, "alive": True}
    except (socket.gaierror, socket.timeout):
        return None


def check_http(subdomain: str) -> dict:
    """Check if subdomain responds over HTTP/S."""
    result = {"http": False, "https": False, "status": None,
              "title": "", "server": "", "redirect": ""}
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True,
                             headers={"User-Agent": "WaspSting-Subdomain/1.0"})
            result[scheme] = True
            result["status"] = r.status_code
            result["server"] = r.headers.get("Server", "")
            # Extract title
            m = re.search(r"<title[^>]*>([^<]{1,80})</title>", r.text, re.IGNORECASE)
            if m:
                result["title"] = m.group(1).strip()
            if r.url != url:
                result["redirect"] = r.url
            break
        except Exception:
            continue
    return result


def crtsh_enum(domain: str) -> list[str]:
    """Query crt.sh certificate transparency logs — free, no key."""
    found = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15, headers={"User-Agent": "WaspSting/1.0"}
        )
        if r.status_code == 200:
            for entry in r.json():
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") and "*" not in name:
                        found.add(name)
    except Exception:
        pass
    return list(found)


def hackertarget_enum(domain: str) -> list[str]:
    """Query HackerTarget API — free tier, no key."""
    found = []
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=10, headers={"User-Agent": "WaspSting/1.0"}
        )
        if r.status_code == 200 and "error" not in r.text.lower()[:30]:
            for line in r.text.strip().splitlines():
                sub = line.split(",")[0].strip()
                if sub.endswith(f".{domain}"):
                    found.append(sub)
    except Exception:
        pass
    return found


def dns_bruteforce(domain: str, wordlist: list[str]) -> list[dict]:
    """Concurrent DNS brute force."""
    candidates = [f"{word}.{domain}" for word in wordlist]
    resolved = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(resolve_subdomain, sub): sub for sub in candidates}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                resolved.append(result)

    return resolved


def run_subdomain(target: str, output_dir: str, console,
                  notify_fn=None) -> dict:
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    # Extract base domain
    domain = re.sub(r"https?://", "", target).split("/")[0].split(":")[0]
    # Strip subdomains to get root
    parts = domain.split(".")
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    console.print(f"\n[bold cyan]═══ SUBDOMAIN ENUM[/bold cyan] → {root_domain}\n")

    all_subdomains = set()
    findings = []

    # 1. crt.sh
    console.print("[dim]Querying crt.sh certificate transparency...[/dim]")
    crt = crtsh_enum(root_domain)
    all_subdomains.update(crt)
    console.print(f"  [green]+{len(crt)}[/green] from crt.sh")

    # 2. HackerTarget
    console.print("[dim]Querying HackerTarget API...[/dim]")
    ht = hackertarget_enum(root_domain)
    all_subdomains.update(ht)
    console.print(f"  [green]+{len(ht)}[/green] from HackerTarget")

    # 3. DNS brute force
    console.print("[dim]Loading wordlist for DNS brute force...[/dim]")
    wordlist = load_wordlist()
    console.print(f"[dim]Brute forcing {len(wordlist)} subdomains...[/dim]")
    brute = dns_bruteforce(root_domain, wordlist)
    for r in brute:
        all_subdomains.add(r["subdomain"])
    console.print(f"  [green]+{len(brute)}[/green] from DNS brute force")

    console.print(f"\n[bold]Total unique subdomains to probe: {len(all_subdomains)}[/bold]\n")

    # 4. HTTP probe all discovered subdomains
    live_subs = []
    console.print("[dim]Probing subdomains for HTTP/S...[/dim]")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_http, sub): sub for sub in all_subdomains}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            sub = futures[future]
            http_info = future.result()
            if http_info["https"] or http_info["http"]:
                scheme = "https" if http_info["https"] else "http"
                entry = {
                    "subdomain": sub,
                    "url": f"{scheme}://{sub}",
                    "status": http_info["status"],
                    "title": http_info["title"],
                    "server": http_info["server"],
                    "redirect": http_info["redirect"],
                }
                live_subs.append(entry)
                console.print(
                    f"  [green][LIVE][/green] {sub:<45} "
                    f"[dim]{http_info['status']} {http_info['title'][:30]}[/dim]"
                )

                # Flag interesting subdomains
                interesting_patterns = [
                    ("admin", "CRITICAL", "Admin panel discovered"),
                    ("staging", "HIGH", "Staging environment — may have weaker security"),
                    ("dev", "HIGH", "Dev environment — may have debug mode enabled"),
                    ("internal", "HIGH", "Internal endpoint exposed publicly"),
                    ("api", "MEDIUM", "API endpoint — test for auth and rate limiting"),
                    ("jenkins", "HIGH", "CI/CD panel — check for unauthenticated access"),
                    ("grafana", "MEDIUM", "Monitoring dashboard — check default creds"),
                    ("kibana", "MEDIUM", "Kibana exposed — potential data exposure"),
                    ("gitlab", "HIGH", "GitLab instance — check for public repos"),
                    ("backup", "HIGH", "Backup subdomain — test for data exposure"),
                ]
                for pattern, sev, desc in interesting_patterns:
                    if pattern in sub.lower():
                        finding = {
                            "module": "subdomain",
                            "category": "Attack Surface",
                            "owasp_id": "A01",
                            "owasp_name": "Broken Access Control",
                            "severity": sev,
                            "title": f"Interesting subdomain: {sub}",
                            "description": desc,
                            "evidence": f"URL: {scheme}://{sub} — Status: {http_info['status']}",
                            "fix": f"Review {sub} for misconfigurations and access controls",
                            "timestamp": datetime.now().isoformat(),
                            "url": f"{scheme}://{sub}",
                        }
                        findings.append(finding)
                        if notify_fn:
                            notify_fn(finding)

    # Display results table
    if live_subs:
        table = Table(box=box.ROUNDED, header_style="bold magenta",
                      title=f"🌐 Live Subdomains ({len(live_subs)})")
        table.add_column("Subdomain", style="cyan")
        table.add_column("Status", width=7)
        table.add_column("Title", width=35)
        table.add_column("Server", width=20)

        for sub in sorted(live_subs, key=lambda x: x["status"] or 999):
            status = sub["status"] or "?"
            status_color = "green" if status == 200 else "yellow" if status in (301, 302) else "red"
            table.add_row(
                sub["subdomain"],
                f"[{status_color}]{status}[/{status_color}]",
                sub["title"][:35] or "[dim]—[/dim]",
                sub["server"][:20] or "[dim]—[/dim]",
            )
        console.print(table)

    console.print(f"\n[green]✓ Subdomain enum complete — {len(live_subs)} live, "
                  f"{len(findings)} flagged findings[/green]\n")

    return {
        "findings": findings,
        "live_subdomains": live_subs,
        "all_discovered": list(all_subdomains),
    }
