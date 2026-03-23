"""
modules/custom_rules.py — Custom OWASP Pattern Rules Engine

Loads user-defined YAML rules and evaluates them against:
  - HTTP response bodies
  - HTTP response headers / status codes
  - Source code files (SAST)

Rule files are loaded from two locations (merged, repo takes priority):
  1. ./rules/*.yaml          — project/team rules (commit to repo)
  2. ~/.waspsting/rules/*.yaml — user-global rules (personal, not committed)

Usage:
    python3 waspsting.py --target https://target.com --mode recon --rules --confirm
    python3 waspsting.py --repo https://github.com/org/app --mode sast --rules

Rule schema (YAML):
---------------------------------------------------------------------------
- id: aws-key-exposure
  name: AWS Access Key Exposed
  owasp: A02
  owasp_name: Security Misconfiguration     # optional, auto-filled if omitted
  severity: CRITICAL                        # CRITICAL HIGH MEDIUM LOW INFO
  description: AWS access key found in response or source code
  tags: [secrets, aws, exposure]            # optional

  match:
    # All fields are optional — include only what you need
    response_body:  'AKIA[0-9A-Z]{16}'      # regex matched against HTTP body
    source_code:    'AKIA[0-9A-Z]{16}'      # regex matched against file content
    header_present: 'X-Powered-By'          # header name must be present
    header_absent:  'Strict-Transport-Security'  # header name must be absent
    header_value:   'X-Powered-By: PHP.*'   # regex matched against "Name: Value"
    status_code:    [500, 503]              # list of status codes to flag

  fix: Rotate the key immediately and audit IAM permissions.
  reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
---------------------------------------------------------------------------

Multiple match fields in one rule are OR'd by default.
Set match_all: true to require ALL fields to match (AND logic).
"""

import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    print(
        "[custom_rules] ERROR: PyYAML not installed.\n"
        "  Run: pip install pyyaml"
    )
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────

REPO_RULES_DIR   = Path("rules")
GLOBAL_RULES_DIR = Path.home() / ".waspsting" / "rules"

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

# Auto-fill owasp_name from owasp ID if not provided
OWASP_NAMES = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

# Source code file extensions to scan in SAST mode
SAST_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
    ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".rs",
    ".yaml", ".yml", ".json", ".env", ".toml", ".ini",
    ".conf", ".config", ".xml", ".sh", ".bash", ".zsh",
    ".tf", ".tfvars", ".dockerfile", ".Dockerfile",
}

# Directories to skip in SAST
SAST_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".idea", ".vscode", "vendor",
}


# ── Rule dataclass ────────────────────────────────────────────────────────────

@dataclass
class MatchConfig:
    response_body:  Optional[str]       = None   # regex
    source_code:    Optional[str]       = None   # regex
    header_present: Optional[str]       = None   # header name
    header_absent:  Optional[str]       = None   # header name
    header_value:   Optional[str]       = None   # regex on "Name: Value"
    status_code:    list[int]           = field(default_factory=list)
    match_all:      bool                = False   # AND vs OR logic


@dataclass
class Rule:
    id:          str
    name:        str
    owasp:       str
    owasp_name:  str
    severity:    str
    description: str
    match:       MatchConfig
    fix:         str          = ""
    reference:   str          = ""
    tags:        list[str]    = field(default_factory=list)
    source_file: str          = ""   # which .yaml file this came from

    # Compiled regex objects (populated after loading)
    _re_body:   Optional[re.Pattern] = field(default=None, repr=False)
    _re_source: Optional[re.Pattern] = field(default=None, repr=False)
    _re_hval:   Optional[re.Pattern] = field(default=None, repr=False)

    def compile(self) -> "Rule":
        """Compile regex fields. Call after loading."""
        flags = re.IGNORECASE | re.MULTILINE
        if self.match.response_body:
            self._re_body   = re.compile(self.match.response_body, flags)
        if self.match.source_code:
            self._re_source = re.compile(self.match.source_code, flags)
        if self.match.header_value:
            self._re_hval   = re.compile(self.match.header_value, flags)
        return self


# ── YAML loader ───────────────────────────────────────────────────────────────

def _parse_rule(raw: dict, source_file: str) -> Optional[Rule]:
    """
    Parse a single raw YAML rule dict into a Rule object.
    Returns None and prints a warning if the rule is invalid.
    """
    rid  = str(raw.get("id", "")).strip()
    name = str(raw.get("name", "")).strip()

    if not rid:
        print(f"[custom_rules] WARNING: Rule missing 'id' in {source_file} — skipped")
        return None
    if not name:
        print(f"[custom_rules] WARNING: Rule '{rid}' missing 'name' in {source_file} — skipped")
        return None

    owasp    = str(raw.get("owasp", "A02")).upper().strip()
    owasp_nm = str(raw.get("owasp_name", OWASP_NAMES.get(owasp, ""))).strip()
    severity = str(raw.get("severity", "MEDIUM")).upper().strip()

    if severity not in VALID_SEVERITIES:
        print(
            f"[custom_rules] WARNING: Rule '{rid}' has invalid severity "
            f"'{severity}'. Defaulting to MEDIUM."
        )
        severity = "MEDIUM"

    # Parse match block
    raw_match = raw.get("match", {}) or {}
    sc_raw    = raw_match.get("status_code", [])
    if isinstance(sc_raw, int):
        sc_raw = [sc_raw]

    match_cfg = MatchConfig(
        response_body  = raw_match.get("response_body"),
        source_code    = raw_match.get("source_code"),
        header_present = raw_match.get("header_present"),
        header_absent  = raw_match.get("header_absent"),
        header_value   = raw_match.get("header_value"),
        status_code    = [int(s) for s in sc_raw],
        match_all      = bool(raw.get("match_all", False)),
    )

    # Warn if rule has no matchers at all
    has_matcher = any([
        match_cfg.response_body, match_cfg.source_code,
        match_cfg.header_present, match_cfg.header_absent,
        match_cfg.header_value, match_cfg.status_code,
    ])
    if not has_matcher:
        print(
            f"[custom_rules] WARNING: Rule '{rid}' has no match conditions "
            f"— it will never fire. Check {source_file}."
        )

    return Rule(
        id          = rid,
        name        = name,
        owasp       = owasp,
        owasp_name  = owasp_nm,
        severity    = severity,
        description = str(raw.get("description", "")).strip(),
        match       = match_cfg,
        fix         = str(raw.get("fix", "")).strip(),
        reference   = str(raw.get("reference", "")).strip(),
        tags        = list(raw.get("tags", [])),
        source_file = source_file,
    ).compile()


def _load_yaml_file(path: Path) -> list[Rule]:
    """Load all rules from a single YAML file."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        raw     = yaml.safe_load(content)
    except yaml.YAMLError as e:
        print(f"[custom_rules] ERROR parsing {path}: {e}")
        return []
    except OSError as e:
        print(f"[custom_rules] ERROR reading {path}: {e}")
        return []

    if not raw:
        return []

    # Support both a list of rules or a single rule dict
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        print(f"[custom_rules] WARNING: {path} is not a list of rules — skipped")
        return []

    rules = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        rule = _parse_rule(item, str(path))
        if rule:
            rules.append(rule)
    return rules


def load_rules(
    extra_paths: Optional[list[str]] = None,
    console=None,
) -> list[Rule]:
    """
    Load all rules from:
      1. ./rules/*.yaml              (repo rules)
      2. ~/.waspsting/rules/*.yaml   (user-global rules)
      3. Any paths in extra_paths    (--rules-dir CLI override)

    Repo rules take priority — if two rules share the same ID,
    the repo version wins.

    Returns deduplicated list of compiled Rule objects.
    """
    search_dirs = []

    # User-global first (lowest priority)
    if GLOBAL_RULES_DIR.exists():
        search_dirs.append(GLOBAL_RULES_DIR)

    # Repo rules (higher priority)
    if REPO_RULES_DIR.exists():
        search_dirs.append(REPO_RULES_DIR)

    # CLI override (highest priority)
    if extra_paths:
        for p in extra_paths:
            path = Path(p)
            if path.is_dir():
                search_dirs.append(path)
            elif path.is_file():
                # Single file passed directly
                search_dirs.append(path.parent)

    all_rules:  list[Rule]     = []
    seen_ids:   dict[str, str] = {}   # id → source_file

    for rules_dir in search_dirs:
        yaml_files = sorted(rules_dir.glob("*.yaml")) + \
                     sorted(rules_dir.glob("*.yml"))

        for yaml_file in yaml_files:
            file_rules = _load_yaml_file(yaml_file)
            for rule in file_rules:
                if rule.id in seen_ids:
                    if console:
                        console.print(
                            f"[dim][custom_rules] Rule '{rule.id}' from "
                            f"{yaml_file.name} overrides "
                            f"{seen_ids[rule.id]}[/dim]"
                        )
                seen_ids[rule.id] = yaml_file.name
                # Replace if already exists (later = higher priority)
                all_rules = [r for r in all_rules if r.id != rule.id]
                all_rules.append(rule)

    if console and all_rules:
        console.print(
            f"[green]✓ Custom rules loaded:[/green] "
            f"{len(all_rules)} rule(s) from "
            f"{len(set(r.source_file for r in all_rules))} file(s)"
        )
    elif console:
        console.print(
            "[dim]No custom rules found. "
            "Create rules/*.yaml to add your own patterns.[/dim]"
        )

    return all_rules


# ── Matching engine ───────────────────────────────────────────────────────────

def _make_finding(rule: Rule, context: str, evidence: str, url: str) -> dict:
    """Build a WaspSting finding dict from a matched rule."""
    return {
        "module":      "custom_rules",
        "source":      "custom_rules",
        "rule_id":     rule.id,
        "owasp_id":    rule.owasp,
        "owasp_name":  rule.owasp_name,
        "category":    f"Custom Rule [{rule.owasp}]",
        "severity":    rule.severity,
        "title":       rule.name,
        "description": rule.description,
        "evidence":    f"Context: {context}\n{evidence}",
        "fix":         rule.fix,
        "reference":   rule.reference,
        "tags":        rule.tags,
        "url":         url,
        "timestamp":   datetime.now().isoformat(),
    }


def evaluate_response(
    rules:   list[Rule],
    url:     str,
    body:    str,
    headers: dict,
    status:  int,
) -> list[dict]:
    """
    Evaluate all rules against an HTTP response.
    Returns list of WaspSting finding dicts for any matches.

    Args:
        rules:   Loaded Rule objects
        url:     Request URL
        body:    Response body text
        headers: Response headers dict (case-insensitive keys)
        status:  HTTP status code
    """
    findings  = []
    # Normalise headers to "Name: Value" strings for regex matching
    hdr_lines = "\n".join(f"{k}: {v}" for k, v in headers.items())
    hdr_lower = {k.lower(): v for k, v in headers.items()}

    for rule in rules:
        m   = rule.match
        hits = []
        misses = []

        # ── response_body ─────────────────────────────────────────────────────
        if m.response_body and rule._re_body:
            match = rule._re_body.search(body)
            if match:
                hits.append(
                    f"response_body matched: '{match.group()[:80]}'"
                )
            else:
                misses.append("response_body")

        # ── header_present ────────────────────────────────────────────────────
        if m.header_present:
            hname = m.header_present.lower()
            if hname in hdr_lower:
                hits.append(f"header present: {m.header_present}")
            else:
                misses.append("header_present")

        # ── header_absent ─────────────────────────────────────────────────────
        if m.header_absent:
            hname = m.header_absent.lower()
            if hname not in hdr_lower:
                hits.append(f"header absent: {m.header_absent}")
            else:
                misses.append("header_absent")

        # ── header_value ──────────────────────────────────────────────────────
        if m.header_value and rule._re_hval:
            match = rule._re_hval.search(hdr_lines)
            if match:
                hits.append(
                    f"header_value matched: '{match.group()[:80]}'"
                )
            else:
                misses.append("header_value")

        # ── status_code ───────────────────────────────────────────────────────
        if m.status_code:
            if status in m.status_code:
                hits.append(f"status code: {status}")
            else:
                misses.append("status_code")

        # ── AND vs OR logic ───────────────────────────────────────────────────
        triggered = bool(hits) and (not m.match_all or not misses)

        if triggered:
            evidence = "\n".join(hits)
            findings.append(
                _make_finding(rule, "HTTP Response", evidence, url)
            )

    return findings


def evaluate_source_file(
    rules:     list[Rule],
    file_path: str,
    content:   str,
) -> list[dict]:
    """
    Evaluate source_code rules against a single file's content.
    Returns list of WaspSting finding dicts for any matches.
    """
    findings = []

    for rule in rules:
        if not rule.match.source_code or not rule._re_source:
            continue

        matches = list(rule._re_source.finditer(content))
        if not matches:
            continue

        # Collect up to 3 match snippets with line numbers
        lines   = content.splitlines()
        samples = []
        for m in matches[:3]:
            # Find line number
            line_no = content[:m.start()].count("\n") + 1
            snippet = m.group()[:80].replace("\n", "\\n")
            samples.append(f"  Line {line_no}: {snippet}")

        evidence = (
            f"File: {file_path}\n"
            f"Pattern: {rule.match.source_code}\n"
            f"Matches ({len(matches)} total):\n" +
            "\n".join(samples)
        )

        finding = _make_finding(
            rule, f"Source: {file_path}", evidence, file_path
        )
        finding["file"] = file_path
        findings.append(finding)

    return findings


def scan_directory(
    rules:    list[Rule],
    root_dir: str,
    console,
) -> list[dict]:
    """
    Walk a directory tree and evaluate source_code rules against
    every matching file. Used by --mode sast --rules.

    Skips SAST_SKIP_DIRS and non-code file extensions.
    """
    findings  = []
    root      = Path(root_dir)
    scanned   = 0

    # Only load rules that have source_code matchers
    sast_rules = [r for r in rules if r.match.source_code]
    if not sast_rules:
        return []

    console.print(
        f"[dim]Custom SAST rules: {len(sast_rules)} pattern(s) "
        f"scanning {root_dir}[/dim]"
    )

    for path in root.rglob("*"):
        # Skip unwanted directories
        if any(skip in path.parts for skip in SAST_SKIP_DIRS):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in SAST_EXTENSIONS:
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        scanned += 1
        file_findings = evaluate_source_file(
            sast_rules, str(path), content
        )
        findings.extend(file_findings)

    console.print(
        f"[dim]Custom SAST: {scanned} files scanned, "
        f"{len(findings)} finding(s)[/dim]"
    )
    return findings


# ── Example rules file writer ─────────────────────────────────────────────────

EXAMPLE_RULES_YAML = """\
# WaspSting custom OWASP rules — rules/example_rules.yaml
#
# Copy this file to rules/my_rules.yaml and customise.
# All fields except id, name, owasp, severity, and at least one
# match condition are optional.
#
# match fields available:
#   response_body:  regex   — matched against HTTP response body
#   source_code:    regex   — matched against source code files
#   header_present: string  — header name that must exist
#   header_absent:  string  — header name that must be missing
#   header_value:   regex   — matched against "Header-Name: value"
#   status_code:    [int]   — list of status codes to flag
#
# Set match_all: true to require ALL conditions (default is OR).
# ──────────────────────────────────────────────────────────────────────────────

- id: aws-key-exposure
  name: AWS Access Key Exposed
  owasp: A02
  severity: CRITICAL
  description: >
    An AWS access key ID matching the AKIA/ASIA/AROA prefix pattern was
    found in the response body or source code. Exposed keys can allow
    full AWS account compromise.
  tags: [secrets, aws, cloud, exposure]
  match:
    response_body: 'AKIA[0-9A-Z]{16}'
    source_code:   '(AKIA|ASIA|AROA)[0-9A-Z]{16}'
  fix: >
    Rotate the key immediately in AWS IAM. Audit CloudTrail for
    unauthorised usage. Remove from source and use IAM roles or
    environment variables instead.
  reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

- id: private-key-in-source
  name: Private Key Material in Source Code
  owasp: A04
  severity: CRITICAL
  description: >
    A PEM-encoded private key block was found in source code.
    Private keys should never be committed to version control.
  tags: [secrets, crypto, pki]
  match:
    source_code: '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
  fix: >
    Rotate the key immediately. Remove from git history using
    git-filter-repo or BFG. Use a secrets manager (Vault, AWS Secrets
    Manager) or environment variables for key material.

- id: debug-mode-enabled
  name: Application Debug Mode Enabled
  owasp: A02
  severity: HIGH
  description: >
    The application appears to be running in debug mode, which may
    expose stack traces, internal paths, environment variables,
    and source code snippets to unauthenticated users.
  tags: [debug, misconfiguration, information-disclosure]
  match:
    response_body: '(Traceback \\(most recent call last\\)|DEBUG = True|display_errors = On|phpinfo\\(\\))'
  fix: >
    Disable debug mode in production. Set DEBUG=False (Django),
    app.debug=False (Flask), or display_errors=Off (PHP).

- id: sql-error-in-response
  name: SQL Error Exposed in Response
  owasp: A05
  severity: HIGH
  description: >
    A database error message was returned in the HTTP response,
    indicating the application may be vulnerable to SQL injection
    and is leaking internal database details.
  tags: [sqli, error-disclosure, injection]
  match:
    response_body: >
      (You have an error in your SQL syntax|
      ORA-[0-9]{5}|
      Microsoft OLE DB Provider for SQL Server|
      PostgreSQL.*ERROR|
      SQLite.*exception|
      Warning.*mysql_)
  fix: >
    Implement parameterised queries. Suppress database error messages
    in production. Use a generic error page.

- id: server-version-disclosure
  name: Server Version Disclosed in Header
  owasp: A02
  severity: LOW
  description: >
    The Server header reveals the web server software and version,
    which helps attackers identify known CVEs.
  tags: [information-disclosure, headers]
  match:
    header_value: 'Server: (Apache|nginx|IIS|LiteSpeed)/[0-9]'
  fix: >
    Configure the server to omit or obscure the Server header.
    Apache: ServerTokens Prod. Nginx: server_tokens off.

- id: missing-x-frame-options
  name: Clickjacking — X-Frame-Options Absent
  owasp: A02
  severity: MEDIUM
  description: >
    The X-Frame-Options header is missing, allowing the page to be
    embedded in an iframe by an attacker for clickjacking attacks.
  tags: [clickjacking, headers, misconfiguration]
  match:
    header_absent: X-Frame-Options
  fix: >
    Add: X-Frame-Options: DENY
    Or use Content-Security-Policy: frame-ancestors 'none'

- id: internal-ip-in-response
  name: Internal IP Address Leaked in Response
  owasp: A02
  severity: MEDIUM
  description: >
    A private/internal IP address was found in the HTTP response,
    revealing internal network topology.
  tags: [information-disclosure, ssrf, recon]
  match:
    response_body: '(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})'
  fix: >
    Strip internal IP addresses from API responses, error messages,
    and HTTP headers before returning to clients.

- id: hardcoded-password-source
  name: Hardcoded Password in Source Code
  owasp: A07
  severity: HIGH
  description: >
    A hardcoded password assignment was found in source code.
    Hardcoded credentials are a critical security risk.
  tags: [secrets, auth, hardcoded-credentials]
  match:
    source_code: "(password|passwd|pwd|secret)\\s*=\\s*[\"'][^\"']{4,}[\"']"
  fix: >
    Remove hardcoded credentials. Use environment variables,
    a secrets manager, or a vault solution.

- id: error-500-on-fuzz
  name: Internal Server Error Triggered
  owasp: A10
  severity: MEDIUM
  description: >
    The application returned HTTP 500, indicating an unhandled
    exception. This may reveal injection points or logic errors.
  tags: [error-handling, stability]
  match:
    status_code: [500, 502, 503]
  fix: >
    Implement global exception handling. Return generic error pages
    in production. Log exceptions server-side for investigation.
"""


def write_example_rules(output_path: str = "rules/example_rules.yaml") -> str:
    """Write the bundled example rules file to disk."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(EXAMPLE_RULES_YAML, encoding="utf-8")
    return str(path)


# ── Terminal summary ──────────────────────────────────────────────────────────

def print_rules_summary(rules: list[Rule], console) -> None:
    """Print a table of all loaded custom rules to the terminal."""
    if not rules:
        return

    from rich.table import Table
    from rich import box

    SEV_COLOR = {
        "CRITICAL": "bold red",   "HIGH":   "bold orange1",
        "MEDIUM":   "bold yellow","LOW":    "bold blue",
        "INFO":     "dim",
    }

    table = Table(
        box=box.SIMPLE,
        title=f"Custom Rules ({len(rules)} loaded)",
        header_style="bold cyan",
    )
    table.add_column("ID",       style="cyan", width=28)
    table.add_column("Name",     width=35)
    table.add_column("OWASP",    width=6)
    table.add_column("Severity", width=10)
    table.add_column("Matchers", style="dim")

    for r in rules:
        matchers = []
        if r.match.response_body:  matchers.append("response")
        if r.match.source_code:    matchers.append("source")
        if r.match.header_present: matchers.append("hdr-present")
        if r.match.header_absent:  matchers.append("hdr-absent")
        if r.match.header_value:   matchers.append("hdr-value")
        if r.match.status_code:    matchers.append(f"status{r.match.status_code}")

        col = SEV_COLOR.get(r.severity, "white")
        table.add_row(
            r.id[:27],
            r.name[:34],
            r.owasp,
            f"[{col}]{r.severity}[/{col}]",
            ", ".join(matchers),
        )

    console.print(table)


# ── CLI self-test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from rich.console import Console
    console = Console()

    console.print("\n[bold]WaspSting — Custom Rules self-test[/bold]\n")

    # Write example file if rules/ doesn't exist
    if not REPO_RULES_DIR.exists() or not any(REPO_RULES_DIR.glob("*.yaml")):
        path = write_example_rules()
        console.print(f"[green]✓ Example rules written:[/green] {path}\n")

    rules = load_rules(console=console)
    print_rules_summary(rules, console)

    if not rules:
        console.print("[yellow]No rules loaded — check rules/ directory.[/yellow]")
        sys.exit(0)

    # Smoke-test against a synthetic HTTP response
    console.print("\n[bold]Smoke test — synthetic HTTP response:[/bold]")
    test_body    = "AKIA1234567890ABCDEF and some SQL error: Warning: mysql_fetch"
    test_headers = {"Server": "Apache/2.4.51", "Content-Type": "text/html"}
    test_status  = 200

    hits = evaluate_response(rules, "http://test.example.com",
                             test_body, test_headers, test_status)
    if hits:
        for h in hits:
            console.print(
                f"  [bold red]HIT[/bold red] [{h['rule_id']}] "
                f"{h['severity']} — {h['title']}"
            )
    else:
        console.print("  [dim]No hits on synthetic test.[/dim]")

    # Smoke-test SAST on current directory
    console.print("\n[bold]Smoke test — SAST on ./:[/bold]")
    sast_hits = scan_directory(rules, ".", console)
    console.print(
        f"  {len(sast_hits)} finding(s) in current directory."
    )
    console.print("\n[green]✓ Custom rules engine ready.[/green]\n")