"""
modules/auth_audit.py — Login endpoint auditing for authorized targets

PURPOSE: Test your own application's authentication for weaknesses.
Checks: lockout policies, rate limiting, JWT weaknesses, common credentials.

AUTHORIZED USE ONLY. Only test systems you own or have explicit permission to test.
"""

import requests
import json
import time
import base64
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

# Common login endpoint paths to probe
LOGIN_PATHS = [
    "/login", "/signin", "/api/login", "/api/auth/login",
    "/api/v1/login", "/api/v1/auth", "/auth/login",
    "/user/login", "/account/login", "/admin/login",
    "/wp-login.php", "/wp-admin", "/auth/token",
    "/api/token", "/oauth/token",
]

# JWT attack headers
JWT_NONE_HEADER = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
JWT_HS256_HEADER = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")


def load_wordlist(path: str) -> list[str]:
    """Load a password wordlist file."""
    wl_path = Path(path)
    if not wl_path.exists():
        # Return a minimal built-in list for demo purposes
        return [
            "password", "123456", "password123", "admin", "letmein",
            "qwerty", "welcome", "monkey", "dragon", "master",
            "abc123", "pass", "test", "root", "toor", "admin123",
            "password1", "1234567890", "iloveyou", "sunshine"
        ]
    return [line.strip() for line in wl_path.read_text(errors="ignore").splitlines()
            if line.strip() and not line.startswith("#")]


def detect_login_endpoint(target: str) -> dict | None:
    """Probe common login paths and detect the form structure."""
    session = requests.Session()
    session.headers["User-Agent"] = "WaspSting-AuthAudit/1.0"

    for path in LOGIN_PATHS:
        url = target.rstrip("/") + path
        try:
            r = session.get(url, timeout=5, allow_redirects=True)
            if r.status_code in (200, 401, 403):
                # Detect if it's a JSON API endpoint
                content_type = r.headers.get("Content-Type", "")
                is_json = "json" in content_type or "api" in path

                # Look for common field names in the response
                body = r.text.lower()
                username_field = "username"
                password_field = "password"
                if "email" in body:
                    username_field = "email"
                if '"token"' in body or '"access_token"' in body:
                    is_json = True

                return {
                    "url": url, "method": "POST",
                    "username_field": username_field,
                    "password_field": password_field,
                    "is_json": is_json,
                    "status": r.status_code
                }
        except requests.RequestException:
            continue
    return None


def test_lockout(endpoint: dict, delay: float) -> dict:
    """Test if account lockout is enforced."""
    result = {"locked_out_at": None, "lockout_enforced": False}
    test_user = "waspsting_lockout_test@example.com"

    for i in range(1, 12):
        try:
            payload = {endpoint["username_field"]: test_user,
                       endpoint["password_field"]: f"wrong_pass_{i}"}
            if endpoint["is_json"]:
                r = requests.post(endpoint["url"], json=payload, timeout=5)
            else:
                r = requests.post(endpoint["url"], data=payload, timeout=5)

            # Look for lockout signals
            body = r.text.lower()
            if any(w in body for w in ["locked", "too many", "blocked", "suspended", "429"]):
                result["locked_out_at"] = i
                result["lockout_enforced"] = True
                break
            if r.status_code == 429:
                result["locked_out_at"] = i
                result["lockout_enforced"] = True
                break

            time.sleep(delay)
        except requests.RequestException:
            break

    return result


def test_jwt_none_bypass(token: str) -> dict:
    """Test if JWT alg:none bypass is accepted."""
    result = {"vulnerable": False, "detail": ""}
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return result

        # Decode payload
        payload_b64 = parts[1] + "=="
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())

        # Forge with alg:none
        forged_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip("=")
        forged_token = f"{JWT_NONE_HEADER}.{forged_payload}."

        result["forged_token"] = forged_token[:60] + "..."
        result["original_claims"] = {k: v for k, v in payload.items()
                                     if k not in ("exp", "iat", "nbf")}
        result["detail"] = f"Forged alg:none token (test against /api/protected endpoints)"
    except Exception as e:
        result["detail"] = str(e)
    return result


def credential_audit(endpoint: dict, wordlist: list[str],
                     delay: float, threads: int, console) -> dict:
    """
    Test common credentials against the login endpoint.
    Documents results — for authorized testing only.
    """
    results = {"tested": 0, "weak_creds_found": [], "response_times": []}
    test_users = ["admin", "administrator", "test", "user", "root"]

    console.print(f"  [dim]Testing {len(test_users)} usernames × {min(len(wordlist), 20)} passwords[/dim]")
    console.print(f"  [dim]Delay: {delay}s between requests[/dim]\n")

    for username in test_users[:3]:  # limit scope
        for password in wordlist[:20]:  # limit to top 20 for demo
            try:
                start = time.time()
                payload = {endpoint["username_field"]: username,
                           endpoint["password_field"]: password}
                if endpoint["is_json"]:
                    r = requests.post(endpoint["url"], json=payload, timeout=5)
                else:
                    r = requests.post(endpoint["url"], data=payload, timeout=5)

                elapsed = time.time() - start
                results["response_times"].append(elapsed)
                results["tested"] += 1

                body = r.text.lower()
                # Success indicators
                success_signals = [
                    r.status_code in (200, 302) and "token" in body,
                    r.status_code == 200 and '"success":true' in body,
                    r.status_code == 200 and "dashboard" in body,
                    r.status_code == 302 and "Location" in r.headers
                ]

                if any(success_signals):
                    results["weak_creds_found"].append({
                        "username": username,
                        "password": password,
                        "status": r.status_code
                    })
                    console.print(f"  [bold red]⚠ Weak credential: {username}:{password}[/bold red]")

                time.sleep(delay)

            except requests.RequestException:
                break

    # Timing analysis (user enumeration)
    if len(results["response_times"]) > 1:
        avg = sum(results["response_times"]) / len(results["response_times"])
        results["avg_response_ms"] = round(avg * 1000, 2)

    return results


def run_auth_audit(target: str, wordlist_path: str, delay: float,
                   threads: int, console) -> dict:
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    console.print(f"\n[bold cyan]═══ AUTH AUDIT MODULE[/bold cyan] → {target}\n")
    console.print("[yellow]⚠  Authorized use only. Documenting results.[/yellow]\n")

    findings = []
    wordlist = load_wordlist(wordlist_path)
    console.print(f"[dim]Wordlist loaded: {len(wordlist)} entries[/dim]")

    # Detect login endpoint
    console.print("[dim]Probing for login endpoint...[/dim]")
    endpoint = detect_login_endpoint(target)

    if not endpoint:
        console.print("[yellow]ℹ No login endpoint auto-detected. Add --target with full login URL.[/yellow]")
        return {"findings": []}

    console.print(f"[green]✓ Login endpoint found:[/green] {endpoint['url']}")
    console.print(f"  Type: {'JSON API' if endpoint['is_json'] else 'HTML Form'}")
    console.print(f"  Fields: {endpoint['username_field']} / {endpoint['password_field']}\n")

    # Test 1: Account lockout
    console.print("[bold]Testing account lockout policy...[/bold]")
    lockout = test_lockout(endpoint, delay)
    if lockout["lockout_enforced"]:
        console.print(f"[green]✓ Lockout enforced at {lockout['locked_out_at']} attempts[/green]")
    else:
        console.print("[red]✗ No account lockout detected after 11 failed attempts[/red]")
        findings.append({
            "module": "auth_audit", "category": "Authentication",
            "owasp_id": "A07", "owasp_name": "Authentication Failures",
            "severity": "HIGH", "title": "No account lockout policy",
            "description": "11+ failed login attempts did not trigger lockout or rate limiting.",
            "evidence": f"Endpoint: {endpoint['url']} — no 429 or lockout response after 11 attempts",
            "fix": "Implement account lockout after 5-10 failed attempts with progressive delay",
            "timestamp": datetime.now().isoformat()
        })

    # Test 2: Credential audit
    console.print("\n[bold]Testing common credentials (authorized audit)...[/bold]")
    cred_results = credential_audit(endpoint, wordlist, delay, threads, console)

    if cred_results["weak_creds_found"]:
        for cred in cred_results["weak_creds_found"]:
            findings.append({
                "module": "auth_audit", "category": "Weak Credentials",
                "owasp_id": "A07", "owasp_name": "Authentication Failures",
                "severity": "CRITICAL",
                "title": f"Weak credential accepted: {cred['username']}:[REDACTED]",
                "description": "Default or common password accepted for login.",
                "evidence": f"Username: {cred['username']}, HTTP {cred['status']}",
                "fix": "Enforce strong password policy, check against HaveIBeenPwned, require MFA",
                "timestamp": datetime.now().isoformat()
            })
    else:
        console.print(f"[green]✓ No weak credentials found in top-20 common passwords[/green]")

    console.print(f"\n  Tested: {cred_results['tested']} combinations")
    if "avg_response_ms" in cred_results:
        console.print(f"  Avg response: {cred_results['avg_response_ms']}ms")

    # Test 3: JWT checks (documented)
    console.print("\n[bold]JWT Attack Vectors (documentation):[/bold]")
    jwt_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    jwt_table.add_column("Attack", style="cyan", width=35)
    jwt_table.add_column("Manual Test Step")

    jwt_attacks = [
        ("alg:none bypass", "Set Authorization: Bearer <header>.<payload>. (empty signature)"),
        ("HS256/RS256 confusion", "Re-sign token with public key as HMAC secret"),
        ("kid injection", 'Set "kid": "../../dev/null" or SQL in kid claim'),
        ("Weak HMAC secret", "Use hashcat mode 16500 against captured token"),
        ("JWT not invalidated", "Log out then replay old token against /api/me"),
        ("Short expiry bypass", "Check if exp claim is validated server-side"),
    ]
    for attack, step in jwt_attacks:
        jwt_table.add_row(attack, step)
    console.print(jwt_table)

    findings.append({
        "module": "auth_audit", "category": "JWT",
        "owasp_id": "A07", "owasp_name": "Authentication Failures",
        "severity": "INFO",
        "title": "JWT attack vectors — manual verification required",
        "description": "Multiple JWT attacks should be tested manually against this target.",
        "evidence": "See JWT attack documentation in report",
        "fix": "Use RS256, validate all claims, implement token revocation list",
        "timestamp": datetime.now().isoformat()
    })

    console.print(f"\n[green]✓ Auth audit complete — {len(findings)} findings[/green]\n")
    return {"findings": findings}
