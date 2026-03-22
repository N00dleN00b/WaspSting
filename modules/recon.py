"""
modules/recon.py — Passive reconnaissance: headers, tech stack, CVE lookup
"""

import requests
import re
import json
from urllib.parse import urlparse
from datetime import datetime

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS missing — downgrade attacks possible", "HIGH"),
    ("Content-Security-Policy", "CSP missing — XSS risk increased", "HIGH"),
    ("X-Frame-Options", "Clickjacking protection missing", "MEDIUM"),
    ("X-Content-Type-Options", "MIME sniffing not prevented", "MEDIUM"),
    ("Referrer-Policy", "Referrer-Policy not set", "LOW"),
    ("Permissions-Policy", "Permissions-Policy not set", "LOW"),
    ("X-XSS-Protection", "Legacy XSS protection header missing (minor)", "INFO"),
]

TECH_SIGNATURES = {
    "Django":    ["csrfmiddlewaretoken", "django", "X-Django"],
    "Rails":     ["X-Runtime", "_rails_session", "rails"],
    "Laravel":   ["laravel_session", "XSRF-TOKEN", "laravel"],
    "Express":   ["X-Powered-By: Express", "connect.sid"],
    "Flask":     ["flask", "Werkzeug", "session="],
    "WordPress": ["wp-content", "wp-login", "WordPress"],
    "Nginx":     ["Server: nginx"],
    "Apache":    ["Server: Apache"],
    "IIS":       ["Server: Microsoft-IIS", "X-Powered-By: ASP.NET"],
    "Next.js":   ["__NEXT_DATA__", "x-nextjs"],
    "FastAPI":   ["fastapi", "uvicorn"],
}

# Known CVEs mapped to tech — supplemented by NVD API
STATIC_CVE_MAP = {
    "Django":    [("CVE-2023-41164", "HIGH", "Potential denial of service via internationalized emails"),
                  ("CVE-2024-27351", "HIGH", "Regular expression denial of service in EmailValidator")],
    "WordPress": [("CVE-2023-2745", "MEDIUM", "Directory traversal via translation files"),
                  ("CVE-2024-4439", "HIGH", "Stored XSS via avatar block")],
    "Laravel":   [("CVE-2021-3129", "CRITICAL", "Debug mode RCE via Ignition")],
    "Rails":     [("CVE-2024-26143", "HIGH", "XSS via 'allow_other_host' redirect")],
    "Express":   [("CVE-2024-29180", "HIGH", "webpack-dev-middleware path traversal")],
    "Nginx":     [("CVE-2024-24989", "MEDIUM", "HTTP/3 null pointer dereference")],
}


def lookup_nvd_cves(tech: str, console=None) -> list:
    """Query NIST NVD API for recent CVEs (free, no key required for basic)."""
    findings = []
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech}&resultsPerPage=5"
        r = requests.get(url, timeout=8, headers={"User-Agent": "WaspSting-SecurityScanner/1.0"})
        if r.status_code == 200:
            data = r.json()
            for item in data.get("vulnerabilities", [])[:5]:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                desc = cve.get("descriptions", [{}])[0].get("value", "")[:120]
                metrics = cve.get("metrics", {})
                score = 0.0
                severity = "MEDIUM"
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        score = metrics[key][0].get("cvssData", {}).get("baseScore", 0)
                        severity = metrics[key][0].get("cvssData", {}).get("baseSeverity", "MEDIUM")
                        break
                if cve_id:
                    findings.append({
                        "cve_id": cve_id, "description": desc,
                        "cvss_score": score, "severity": severity,
                        "source": "NVD"
                    })
    except Exception:
        pass
    return findings


def analyze_with_ollama(content: str, task: str) -> str:
    """Send to local Ollama for AI-assisted analysis."""
    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "llama3", "prompt": f"{task}\n\n{content}", "stream": False},
            timeout=30
        )
        if r.status_code == 200:
            return r.json().get("response", "")
    except Exception:
        pass
    return ""


def detect_tech(headers: dict, body: str) -> dict:
    detected = {}
    headers_str = " ".join(f"{k}: {v}" for k, v in headers.items())
    combined = headers_str + " " + body[:3000]
    for tech, sigs in TECH_SIGNATURES.items():
        if any(sig.lower() in combined.lower() for sig in sigs):
            detected[tech] = True
    return detected


def check_security_txt(target: str) -> dict:
    """Check for security.txt at /.well-known/security.txt"""
    findings = {}
    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            r = requests.get(target.rstrip("/") + path, timeout=5)
            if r.status_code == 200 and "contact" in r.text.lower():
                findings["has_security_txt"] = True
                findings["security_txt_content"] = r.text[:500]
                return findings
        except Exception:
            pass
    findings["has_security_txt"] = False
    return findings


def run_recon(target: str, do_cve: bool, ai_available: bool, console) -> dict:
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from knowledge_base import SEVERITY_EMOJI, SEVERITY_COLORS

    console.print(f"\n[bold cyan]═══ RECON MODULE[/bold cyan] → {target}\n")

    findings = []
    tech_stack = {}

    # --- HTTP request ---
    try:
        r = requests.get(target, timeout=10, allow_redirects=True,
                         headers={"User-Agent": "WaspSting-SecurityScanner/1.0"})
    except requests.RequestException as e:
        console.print(f"[red]✗ Could not reach target: {e}[/red]")
        return {"findings": [], "tech_stack": {}}

    headers = dict(r.headers)
    body = r.text

    # --- Security headers ---
    console.print("[bold]Security Headers:[/bold]")
    header_table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
    header_table.add_column("Header", style="cyan", width=35)
    header_table.add_column("Status", width=10)
    header_table.add_column("Severity", width=10)
    header_table.add_column("Detail")

    for header_name, issue, sev in SECURITY_HEADERS:
        present = any(h.lower() == header_name.lower() for h in headers)
        status_text = "[green]✓ Present[/green]" if present else f"[{SEVERITY_COLORS[sev]}]✗ Missing[/{SEVERITY_COLORS[sev]}]"
        header_table.add_row(header_name, status_text, sev if not present else "", issue if not present else "")
        if not present:
            findings.append({
                "module": "recon", "category": "Security Headers",
                "owasp_id": "A02", "owasp_name": "Security Misconfiguration",
                "severity": sev, "title": f"Missing {header_name}",
                "description": issue, "evidence": f"Header absent from response",
                "fix": f"Add {header_name} to server/application responses",
                "timestamp": datetime.now().isoformat()
            })

    console.print(header_table)

    # --- Server header leakage ---
    server = headers.get("Server", "")
    if server:
        console.print(f"\n[yellow]⚠ Server header reveals: [bold]{server}[/bold] — consider removing[/yellow]")
        findings.append({
            "module": "recon", "category": "Information Disclosure",
            "owasp_id": "A02", "owasp_name": "Security Misconfiguration",
            "severity": "LOW", "title": "Server version disclosure",
            "description": f"Server header exposes: {server}",
            "evidence": f"Server: {server}",
            "fix": "Remove or obscure the Server header in web server config",
            "timestamp": datetime.now().isoformat()
        })

    # --- Tech detection ---
    tech_stack = detect_tech(headers, body)
    if tech_stack:
        console.print(f"\n[bold]Detected Tech:[/bold] {', '.join(tech_stack.keys())}")

    # --- HTTPS check ---
    if target.startswith("http://"):
        findings.append({
            "module": "recon", "category": "Cryptographic Failures",
            "owasp_id": "A04", "owasp_name": "Cryptographic Failures",
            "severity": "HIGH", "title": "No HTTPS — plaintext transport",
            "description": "Target is served over HTTP, exposing traffic to interception.",
            "evidence": f"URL scheme: http://",
            "fix": "Configure TLS and redirect HTTP to HTTPS with HSTS",
            "timestamp": datetime.now().isoformat()
        })
        console.print("[bold red]🔴 CRITICAL: No HTTPS detected[/bold red]")

    # --- security.txt ---
    sec_txt = check_security_txt(target)
    if sec_txt.get("has_security_txt"):
        console.print("[green]✓ security.txt found[/green]")
    else:
        console.print("[dim]ℹ No security.txt found (recommended for bug bounty programs)[/dim]")

    # --- CVE lookup ---
    if do_cve and tech_stack:
        console.print(f"\n[bold]CVE Lookup (NVD):[/bold]")
        for tech in tech_stack:
            # Static known CVEs
            static = STATIC_CVE_MAP.get(tech, [])
            for cve_id, sev, desc in static:
                console.print(f"  [{SEVERITY_COLORS[sev]}]{SEVERITY_EMOJI[sev]} {cve_id}[/] [{tech}] {desc}")
                findings.append({
                    "module": "recon", "category": "Known CVE",
                    "owasp_id": "A03", "owasp_name": "Software Supply Chain Failures",
                    "severity": sev, "title": f"{cve_id} affecting {tech}",
                    "description": desc, "evidence": f"Tech detected: {tech}",
                    "fix": f"Check https://nvd.nist.gov/vuln/detail/{cve_id} and update {tech}",
                    "cve_id": cve_id, "timestamp": datetime.now().isoformat()
                })
            # Live NVD query
            nvd_results = lookup_nvd_cves(tech)
            for cve in nvd_results:
                sev = cve.get("severity", "MEDIUM")
                console.print(f"  [dim]{cve['cve_id']} (CVSS {cve['cvss_score']}) {cve['description'][:80]}[/dim]")

    # --- AI analysis ---
    if ai_available and findings:
        console.print("\n[dim yellow]🤖 Ollama analyzing recon results...[/dim yellow]")
        summary = json.dumps([f["title"] for f in findings], indent=2)
        ai_note = analyze_with_ollama(summary,
            "You are a pentest expert. Briefly summarize the key risks in 3 bullet points and suggest priority fixes:")
        if ai_note:
            console.print(Panel(ai_note, title="[yellow]🤖 AI Risk Summary[/yellow]", border_style="yellow"))

    console.print(f"\n[green]✓ Recon complete — {len(findings)} findings[/green]\n")
    return {"findings": findings, "tech_stack": tech_stack}
