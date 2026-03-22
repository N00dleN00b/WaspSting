"""
knowledge_base.py — OWASP Top 10:2025 + Pentest methodology knowledge base
"""

OWASP_TOP_10_2025 = {
    "A01": {
        "id": "A01:2025", "name": "Broken Access Control", "severity": "CRITICAL",
        "description": "Restrictions on authenticated users are not properly enforced.",
        "test_steps": [
            "Test horizontal privilege escalation (access other users' resources)",
            "Test vertical privilege escalation (access admin functions as regular user)",
            "Test IDOR by manipulating object identifiers in URLs/params",
            "Test force browsing to restricted pages",
            "Test CORS misconfiguration with cross-origin requests",
            "Check JWT claims can't be manipulated to gain elevated access",
        ],
        "indicators": [
            "missing authorization checks", "IDOR", "path traversal", "force browsing",
            "CORS misconfiguration", "privilege escalation", "JWT manipulation",
            "missing @login_required", "no permission check", "direct object reference"
        ],
        "ai_gaps": [
            "LLM endpoints exposed without auth",
            "Vector DB / embedding endpoints unprotected",
            "Admin AI model config routes accessible to users",
        ],
        "patterns": [
            r"@app\.route.*\n(?!.*@login_required)",
            r"os\.path\.join.*request\.",
            r"open\(.*request\.",
        ],
        "cwe": ["CWE-22", "CWE-284", "CWE-285", "CWE-639"],
        "cvss_base": 9.1
    },
    "A02": {
        "id": "A02:2025", "name": "Security Misconfiguration", "severity": "HIGH",
        "description": "Missing security hardening, unnecessary features enabled, default credentials.",
        "test_steps": [
            "Check for DEBUG mode enabled in production",
            "Enumerate default credentials on admin panels",
            "Check security headers (CSP, HSTS, X-Frame-Options)",
            "Test for verbose error messages exposing stack traces",
            "Check for unnecessary HTTP methods (PUT, DELETE, TRACE)",
            "Review CORS policy for overly permissive origins",
        ],
        "indicators": [
            "DEBUG=True", "default credentials", "verbose errors",
            "missing security headers", "ALLOWED_HOSTS = *", "SECRET_KEY in code"
        ],
        "ai_gaps": [
            "AI API keys hardcoded or committed to repo",
            "Ollama/LM Studio exposed on 0.0.0.0 without auth",
            "Model config/temperature exposed via API endpoint",
        ],
        "patterns": [
            r"DEBUG\s*=\s*True",
            r"SECRET_KEY\s*=\s*['\"][^'\"]{1,40}['\"]",
            r"ALLOWED_HOSTS\s*=\s*\[.*\*",
            r"api_key\s*=\s*['\"]sk-",
        ],
        "cwe": ["CWE-16", "CWE-209", "CWE-732"],
        "cvss_base": 7.5
    },
    "A03": {
        "id": "A03:2025", "name": "Software Supply Chain Failures", "severity": "HIGH",
        "description": "Vulnerable or outdated components, unverified dependencies.",
        "test_steps": [
            "Run dependency audit (pip audit, npm audit)",
            "Check for unpinned dependency versions",
            "Verify no abandoned/unmaintained libraries",
            "Check for known CVEs in requirements.txt / package.json",
            "Verify integrity of downloaded packages",
        ],
        "indicators": [
            "outdated dependencies", "unpinned versions", "no lockfile",
            "requirements.txt without hashes", "abandoned libraries"
        ],
        "ai_gaps": [
            "AI/ML libraries pinned to vulnerable versions",
            "No integrity checks on model weights downloads",
            "Langchain/LlamaIndex older versions with known prompt injection bugs",
        ],
        "patterns": [r">=\s*\d+", r"requests\s*$"],
        "cwe": ["CWE-1104", "CWE-494"],
        "cvss_base": 7.4
    },
    "A04": {
        "id": "A04:2025", "name": "Cryptographic Failures", "severity": "HIGH",
        "description": "Failures related to cryptography leading to sensitive data exposure.",
        "test_steps": [
            "Check for use of MD5/SHA1 for password hashing",
            "Verify TLS configuration (no TLS 1.0/1.1)",
            "Check for ECB mode cipher usage",
            "Test for weak random number generation",
            "Verify sensitive data encrypted at rest",
            "Check for hardcoded encryption keys or IVs",
        ],
        "indicators": ["MD5", "SHA1", "weak cipher", "ECB mode", "HTTP not HTTPS",
                       "weak random", "no encryption at rest", "plaintext passwords"],
        "ai_gaps": [
            "AI conversation history stored unencrypted",
            "User prompt logs in plaintext databases",
            "Embedding vectors stored without access control",
        ],
        "patterns": [
            r"hashlib\.md5", r"hashlib\.sha1",
            r"random\.random\(\)", r"AES\.MODE_ECB",
            r"http://(?!localhost|127\.0\.0\.1)",
        ],
        "cwe": ["CWE-261", "CWE-326", "CWE-327", "CWE-330"],
        "cvss_base": 7.5
    },
    "A05": {
        "id": "A05:2025", "name": "Injection", "severity": "CRITICAL",
        "description": "User-supplied data is not validated, filtered, or sanitized.",
        "test_steps": [
            "Test SQL injection with ' OR '1'='1 payloads",
            "Test NoSQL injection with $where, $gt operators",
            "Test OS command injection via semicolons, pipes",
            "Test XSS with <script>alert(1)</script>",
            "Test template injection with {{7*7}}",
            "Test LDAP injection with *)(uid=*))(|(uid=*",
            "Test prompt injection in AI-powered endpoints",
        ],
        "indicators": ["SQL injection", "NoSQL injection", "command injection",
                       "XSS", "template injection", "eval()", "exec()"],
        "ai_gaps": [
            "Prompt injection — user input in LLM prompts without sanitization",
            "System prompt leakage via injection",
            "RAG poisoning via malicious document retrieval",
            "LLM output rendered as HTML without escaping",
        ],
        "patterns": [
            r"eval\s*\(.*request\.", r"exec\s*\(.*request\.",
            r"cursor\.execute\(.*f['\"].*{",
            r"os\.system\(.*request\.",
            r"render_template_string\(.*request\.",
        ],
        "cwe": ["CWE-74", "CWE-77", "CWE-89", "CWE-79"],
        "cvss_base": 9.8
    },
    "A06": {
        "id": "A06:2025", "name": "Insecure Design", "severity": "HIGH",
        "description": "Missing or ineffective security controls at the design level.",
        "test_steps": [
            "Test for missing rate limiting on auth endpoints",
            "Test for business logic flaws (negative prices, quantity manipulation)",
            "Test password reset flow for token predictability",
            "Test for race conditions in critical operations",
            "Verify MFA cannot be bypassed",
            "Test for mass assignment via extra POST parameters",
        ],
        "indicators": ["no rate limiting", "business logic flaws", "no MFA",
                       "insecure password reset", "predictable tokens"],
        "ai_gaps": [
            "No rate limiting on AI inference (cost amplification attack)",
            "No max token limits per user/session",
            "AI outputs not reviewed before high-stakes actions",
            "No content moderation on AI-generated output",
        ],
        "patterns": [],
        "cwe": ["CWE-654", "CWE-799", "CWE-841"],
        "cvss_base": 7.5
    },
    "A07": {
        "id": "A07:2025", "name": "Authentication Failures", "severity": "CRITICAL",
        "description": "Incorrectly implemented authentication allowing session/credential compromise.",
        "test_steps": [
            "Test for account lockout after N failed attempts",
            "Test JWT with 'alg: none' bypass",
            "Test JWT with HS256 vs RS256 confusion",
            "Check session tokens for entropy and predictability",
            "Test for session fixation",
            "Test OAuth flow for state parameter CSRF",
            "Check for credential stuffing protection",
        ],
        "indicators": ["weak passwords", "no account lockout", "exposed session tokens",
                       "broken JWT", "no MFA", "session fixation"],
        "ai_gaps": [
            "API keys for AI services shared across tenants",
            "JWT with 'none' algorithm accepted",
            "AI chatbot sessions not isolated between users",
            "Shared AI memory leaking between sessions",
        ],
        "patterns": [
            r"algorithm\s*=\s*['\"]none['\"]",
            r"jwt\.decode.*verify\s*=\s*False",
        ],
        "cwe": ["CWE-287", "CWE-384", "CWE-613"],
        "cvss_base": 9.1
    },
    "A08": {
        "id": "A08:2025", "name": "Software or Data Integrity Failures", "severity": "HIGH",
        "description": "Code and infrastructure not protecting against integrity violations.",
        "test_steps": [
            "Check for insecure deserialization (pickle, yaml.load)",
            "Verify webhook signatures are validated",
            "Test CI/CD pipeline for untrusted input injection",
            "Verify auto-update mechanisms check signatures",
            "Check CDN resources have SRI hashes",
        ],
        "indicators": ["insecure deserialization", "unverified webhooks",
                       "pickle.loads untrusted", "yaml.load unsafe"],
        "ai_gaps": [
            "Model weights loaded without checksum verification",
            "pickle.loads used to deserialize AI model artifacts",
            "Webhook from AI provider not signature-verified",
        ],
        "patterns": [
            r"pickle\.loads\(",
            r"yaml\.load\((?!.*Loader=yaml\.SafeLoader)",
            r"marshal\.loads\(",
        ],
        "cwe": ["CWE-345", "CWE-494", "CWE-502"],
        "cvss_base": 8.1
    },
    "A09": {
        "id": "A09:2025", "name": "Security Logging and Alerting Failures", "severity": "MEDIUM",
        "description": "Insufficient logging and monitoring enabling undetected attacks.",
        "test_steps": [
            "Verify failed logins are logged with IP/timestamp",
            "Verify audit trail exists for privilege changes",
            "Test that high-value transactions are logged",
            "Check logs don't contain sensitive data (passwords, tokens)",
            "Verify alerting exists for anomalous patterns",
        ],
        "indicators": ["no logging", "logs with PII", "no audit trail",
                       "swallowed exceptions", "no alerting"],
        "ai_gaps": [
            "AI prompt/response not logged for abuse detection",
            "No monitoring on AI API cost spikes",
            "No audit trail for AI-assisted decisions",
        ],
        "patterns": [
            r"except.*:\s*\n\s*pass",
            r"except Exception:\s*pass",
        ],
        "cwe": ["CWE-117", "CWE-223", "CWE-778"],
        "cvss_base": 6.5
    },
    "A10": {
        "id": "A10:2025", "name": "Mishandling of Exceptional Conditions", "severity": "MEDIUM",
        "description": "Applications not properly handling errors may expose info or enter unsafe states.",
        "test_steps": [
            "Send malformed input and observe error responses",
            "Test for verbose stack traces in production",
            "Test timeout handling on slow endpoints",
            "Test behavior when dependencies are unavailable",
            "Send edge case inputs: empty strings, nulls, very large values",
        ],
        "indicators": ["bare except clauses", "swallowed exceptions",
                       "stack traces to users", "fail open on errors"],
        "ai_gaps": [
            "AI API timeout not handled — app hangs",
            "LLM returning malformed JSON crashes parser",
            "AI content filter error causes fail-open",
        ],
        "patterns": [
            r"except:\s*\n\s*pass",
            r"except Exception:\s*\n\s*pass",
        ],
        "cwe": ["CWE-390", "CWE-391", "CWE-755"],
        "cvss_base": 5.9
    }
}

# Additional pentest checks beyond OWASP
PENTEST_CHECKS = {
    "BOLA": {
        "name": "Broken Object Level Authorization (BOLA/IDOR)",
        "description": "Manipulation of object identifiers to access unauthorized resources",
        "test_steps": [
            "Identify numeric/sequential IDs in API endpoints",
            "Attempt to access adjacent IDs (user/123 → user/124, user/122)",
            "Test with IDs belonging to different user accounts",
            "Try GUIDs/UUIDs by harvesting from other responses",
            "Test nested resources: /users/123/orders/456",
            "Try parameter pollution: ?id=123&id=456",
        ],
        "doc_template": "Endpoint: {endpoint}\nOriginal ID: {original}\nTested ID: {tested}\nResult: {result}\nData Exposed: {data}"
    },
    "MASS_ASSIGN": {
        "name": "Mass Assignment",
        "description": "Sending extra parameters to overwrite protected fields",
        "test_steps": [
            "Identify all writable fields from API documentation / source",
            "Add extra fields to POST/PUT requests: isAdmin, role, verified",
            "Try nested object injection: user[role]=admin",
            "Check GraphQL mutations for unpublished fields",
        ],
        "doc_template": "Endpoint: {endpoint}\nPayload sent: {payload}\nField affected: {field}\nResult: {result}"
    },
    "RATE_LIMIT": {
        "name": "Rate Limiting & Resource Abuse",
        "description": "Test for missing rate limiting on sensitive endpoints",
        "test_steps": [
            "Send 100+ requests to login endpoint in 60 seconds",
            "Test API endpoints without auth for rate limits",
            "Try to bypass limits with X-Forwarded-For header rotation",
            "Test password reset endpoint for account enumeration",
            "Check if AI inference endpoints have per-user limits",
        ],
        "doc_template": "Endpoint: {endpoint}\nRequests sent: {count}\nTime window: {window}s\nLimited at: {limit}\nBypass tested: {bypass}"
    },
    "DATA_EXPOSURE": {
        "name": "Excessive Data Exposure",
        "description": "API responses returning more data than necessary",
        "test_steps": [
            "Inspect all API responses for PII not shown in UI",
            "Check for internal fields: created_by, internal_id, deleted_at",
            "Look for sensitive fields: ssn, credit_card, password_hash",
            "Test GraphQL introspection for hidden fields",
            "Compare mobile app traffic vs web app for hidden endpoints",
        ],
        "doc_template": "Endpoint: {endpoint}\nSensitive fields found: {fields}\nSample (redacted): {sample}"
    },
    "JWT_ATTACKS": {
        "name": "JWT Attack Vectors",
        "description": "JWT token manipulation and bypass techniques",
        "test_steps": [
            "Test alg:none — remove signature and set algorithm to none",
            "Test HS256/RS256 confusion — sign with public key as HMAC secret",
            "Test kid injection — set kid to point to attacker-controlled file",
            "Test jwks_uri spoofing in JWT header",
            "Test for weak HMAC secrets via brute force",
            "Check JWT expiry is enforced",
            "Test JWT not invalidated on logout",
        ],
        "doc_template": "Token obtained: {token_redacted}\nAlgorithm: {alg}\nTechnique: {technique}\nResult: {result}"
    }
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "bold red", "HIGH": "red",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"
}
SEVERITY_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"
}
