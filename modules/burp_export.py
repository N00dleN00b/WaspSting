"""
modules/burp_export.py — Generate Burp Suite Community Edition config JSON

Generates a Burp Suite project configuration that:
- Pre-configures scope for the target
- Creates scan configurations for known endpoints
- Sets up match/replace rules for common auth bypass tests
- Generates repeater requests for manual testing

Compatible with Burp Suite Community Edition (manual import).
"""

import json
from datetime import datetime
from urllib.parse import urlparse


def build_scope_config(target: str) -> dict:
    """Build Burp Suite scope configuration."""
    parsed = urlparse(target)
    host = parsed.netloc or parsed.path
    scheme = parsed.scheme or "https"
    port = 443 if scheme == "https" else 80

    return {
        "target": {
            "scope": {
                "advanced_mode": True,
                "exclude": [
                    {"enabled": True, "file": "\\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|css)$",
                     "host": host, "port": str(port), "protocol": "any"}
                ],
                "include": [
                    {"enabled": True, "file": "",
                     "host": host.replace(".", "\\."),
                     "port": str(port), "protocol": scheme}
                ]
            }
        }
    }


def build_match_replace_rules() -> list[dict]:
    """Common match/replace rules for auth testing."""
    return [
        {
            "comment": "JWT alg:none bypass — replaces alg in JWT header",
            "enabled": False,
            "is_simple_match": False,
            "match_condition": "AND",
            "match_type": "request_header",
            "regex_match": True,
            "replace_string": "Authorization: Bearer \\1.\\3.",
            "rule_type": "request_header",
            "string_match": "(Authorization: Bearer )([A-Za-z0-9+/=]+)\\.([A-Za-z0-9+/=]+)\\.[A-Za-z0-9+/=]*"
        },
        {
            "comment": "Add X-Forwarded-For to bypass IP-based rate limits",
            "enabled": False,
            "is_simple_match": True,
            "match_type": "request_header",
            "regex_match": False,
            "replace_string": "X-Forwarded-For: 127.0.0.1",
            "rule_type": "request_header",
            "string_match": ""
        },
        {
            "comment": "Override role via header (mass assignment test)",
            "enabled": False,
            "is_simple_match": True,
            "match_type": "request_header",
            "regex_match": False,
            "replace_string": "X-User-Role: admin",
            "rule_type": "request_header",
            "string_match": ""
        },
        {
            "comment": "Remove Cookie header (test unauthenticated access)",
            "enabled": False,
            "is_simple_match": True,
            "match_type": "request_header",
            "regex_match": False,
            "replace_string": "",
            "rule_type": "request_header",
            "string_match": "Cookie:"
        }
    ]


def build_intruder_payloads() -> dict:
    """Payload lists for Burp Intruder."""
    return {
        "bola_ids": {
            "description": "Sequential IDs for BOLA/IDOR testing",
            "type": "simple_list",
            "payloads": [str(i) for i in range(1, 51)]
        },
        "common_passwords": {
            "description": "Common passwords for auth audit (authorized testing only)",
            "type": "simple_list",
            "payloads": [
                "password", "123456", "password123", "admin", "letmein",
                "qwerty", "welcome", "monkey", "dragon", "master",
                "abc123", "pass", "test", "root", "admin123"
            ]
        },
        "sqli_basic": {
            "description": "Basic SQLi probes",
            "type": "simple_list",
            "payloads": [
                "'", "''", "`", "``", ",", "\"", "\"\"",
                "/", "//", "\\", "//\\\\", ";", "' or '1'='1",
                "' OR 1=1--", "' UNION SELECT 1--",
                "1; DROP TABLE users--"
            ]
        },
        "xss_basic": {
            "description": "Basic XSS payloads",
            "type": "simple_list",
            "payloads": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "'\"><svg onload=alert(1)>",
                "javascript:alert(1)",
                "<iframe src=javascript:alert(1)>",
                "{{7*7}}",  # SSTI too
            ]
        },
        "mass_assignment_fields": {
            "description": "Fields to inject for mass assignment testing",
            "type": "simple_list",
            "payloads": [
                "isAdmin", "is_admin", "admin", "role",
                "verified", "email_verified", "balance",
                "credits", "user_id", "account_type",
                "permissions", "access_level"
            ]
        }
    }


def build_repeater_requests(target: str, findings: list) -> list[dict]:
    """Generate pre-built repeater requests from scan findings."""
    parsed = urlparse(target)
    host = parsed.netloc
    scheme = parsed.scheme

    requests_list = []

    # Standard auth test requests
    requests_list.append({
        "name": "Auth — Login endpoint probe",
        "request": f"POST /api/v1/login HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\r\n{{\"username\":\"admin\",\"password\":\"admin\"}}"
    })
    requests_list.append({
        "name": "BOLA — Sequential ID test",
        "request": f"GET /api/v1/users/1 HTTP/1.1\r\nHost: {host}\r\n\r\n"
    })
    requests_list.append({
        "name": "Mass Assignment — Extra field injection",
        "request": f"POST /api/v1/users/me HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"test\",\"isAdmin\":true,\"role\":\"admin\"}}"
    })
    requests_list.append({
        "name": "CORS — Cross-origin probe",
        "request": f"GET / HTTP/1.1\r\nHost: {host}\r\nOrigin: https://evil.example.com\r\n\r\n"
    })
    requests_list.append({
        "name": "JWT — alg:none test (fill in token)",
        "request": f"GET /api/v1/me HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer REPLACE_WITH_FORGED_TOKEN\r\n\r\n"
    })

    return requests_list


def generate_burp_config(burp_items: list, target: str, output_path: str):
    """
    Generate a Burp Suite Community Edition compatible JSON config.
    Import via: Burp → Project → Open project → Load config file
    """
    config = {
        "_waspsting_meta": {
            "generated_by": "WaspSting",
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "burp_version": "community",
            "import_instructions": [
                "1. Open Burp Suite Community Edition",
                "2. Go to Project Options > Misc > Load project options",
                "3. Select this JSON file",
                "4. Scope will be pre-configured for the target",
                "5. Match/replace rules are disabled by default — enable as needed",
                "6. Use Repeater requests for manual testing"
            ]
        },
        "scope": build_scope_config(target),
        "proxy": {
            "intercept_client_requests": {
                "do_intercept": False,
                "rules": [
                    {"description": "Don't intercept static assets", "enabled": True,
                     "match_condition": "OR", "match_type": "url",
                     "regex_match": True,
                     "string_match": "\\.(png|jpg|gif|ico|css|woff2?)$",
                     "tool_flag": 4}
                ]
            },
            "match_replace_rules": build_match_replace_rules()
        },
        "scanner": {
            "live_active_audit": {"scan_everything_after_breakpoint": False},
            "active_audit_checks": {
                "scan_for_sql_injection": True,
                "scan_for_xss": True,
                "scan_for_path_traversal": True,
                "scan_for_os_command_injection": True,
            }
        },
        "intruder": {
            "payload_sets": build_intruder_payloads()
        },
        "repeater": {
            "pre_built_requests": build_repeater_requests(target, burp_items)
        },
        "waspsting_findings_summary": burp_items[:20]
    }

    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)

    return output_path
