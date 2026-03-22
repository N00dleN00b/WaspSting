# Usage Reference

## Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--target URL` | `-t` | Target URL for live testing |
| `--repo URL` | `-r` | GitHub repo URL for SAST |
| `--mode MODE` | `-m` | Module to run (see below) |
| `--output DIR` | `-o` | Output directory (default: `./output`) |
| `--confirm` | | **Required** for live testing — confirms authorization |
| `--burp` | | Generate Burp Suite Community config JSON |
| `--cve` | | Query NVD CVE database for detected tech |
| `--no-ai` | | Skip Ollama AI analysis |
| `--fast` | | Skip banner animation |
| `--delay SECS` | | Delay between requests (default: 0.5) |
| `--threads N` | | Concurrent threads (default: 5) |
| `--wordlist PATH` | `-w` | Custom wordlist for auth module |
| `--scope PATH` | | Scope file for bug bounty mode |

---

## Modes

### `sast` — Static Code Analysis
Clones a GitHub repo and scans for OWASP Top 10:2025 vulnerabilities.
No live requests. No `--confirm` needed.

```bash
python waspsting.py --repo https://github.com/target/app --mode sast
python waspsting.py --repo https://github.com/target/app --mode sast --no-ai
```

**What it does:**
- Clones repo with `git clone --depth=1`
- Regex pattern scan across all code files
- Ollama AI deep code review (if running)
- Framework detection (Django, Flask, Next.js, etc.)
- Maps findings to OWASP categories + CWE references

---

### `recon` — Passive Reconnaissance
```bash
python waspsting.py --target https://example.com --mode recon --confirm
python waspsting.py --target https://example.com --mode recon --cve --confirm
```

**What it does:**
- Security header audit (CSP, HSTS, X-Frame-Options, etc.)
- Server version disclosure check
- Tech stack fingerprinting
- HTTPS / TLS check
- `security.txt` detection
- NVD CVE lookup for detected technologies (`--cve`)
- Ollama summary of risk priorities

---

### `auth` — Authentication Audit
**Authorized targets only.** Tests your own app's login security.

```bash
python waspsting.py --target https://example.com --mode auth --confirm
python waspsting.py --target https://example.com --mode auth --wordlist wordlists/common.txt --confirm
```

**What it does:**
- Auto-detects login endpoints
- Tests account lockout policy
- Common credential audit (top-20 passwords vs common usernames)
- JWT attack vector documentation
- Response timing analysis (user enumeration)

---

### `bola` — BOLA/IDOR Testing
```bash
python waspsting.py --target https://example.com --mode bola --confirm
```

**What it does:**
- Probes 20+ common API endpoint patterns
- Identifies sequential numeric IDs
- Generates documented test cases with evidence templates
- Documents: parameter pollution, header injection, GraphQL IDOR

---

### `api` — API Security Checks
```bash
python waspsting.py --target https://example.com --mode api --confirm
python waspsting.py --target https://example.com --mode api --burp --confirm
```

**What it does:**
- Rate limiting detection (20 rapid requests)
- CORS misconfiguration test
- Data exposure scan (sensitive fields in responses)
- Injection probes (SQLi, XSS, SSTI, NoSQL, command, prompt)
- Mass assignment documentation guide

---

### `bounty` — Bug Bounty Planner ⭐
```bash
# Interactive wizard
python waspsting.py --mode bounty

# Load from JSON scope file
python waspsting.py --mode bounty --scope examples/example_scope.json

# Load from raw text (pasted from HackerOne/Bugcrowd)
python waspsting.py --mode bounty --scope my_scope.txt
```

**What it does:**
- Ingests in-scope targets, out-of-scope, rules, reward range
- Classifies attack surface (web app, API, auth system, admin panel, mobile, cloud)
- Generates prioritized vulnerability checklist by payout value
- Creates phased test plan (Recon → Auth → API → BOLA → ...)
- Generates ready-to-run WaspSting commands for each target
- Ollama AI adds bounty-hunter-specific insights
- Saves Markdown checklist + JSON for reuse

**Scope file format (JSON):**
```json
{
  "program_name": "Acme Corp — HackerOne",
  "platform": "HackerOne",
  "reward_range": "$100 - $10,000",
  "in_scope": ["https://app.acmecorp.com", "*.acmecorp.com"],
  "out_of_scope": ["blog.acmecorp.com"],
  "vulnerability_types": ["XSS", "SQLi", "IDOR", "RCE"],
  "excluded_vuln_types": ["Self-XSS", "Missing headers"],
  "special_rules": ["No automated scanning", "Max 10 req/s"],
  "notes": "React frontend, Node.js API, PostgreSQL"
}
```

---

### `full` — All Modules
```bash
python waspsting.py \
  --target https://example.com \
  --repo https://github.com/target/app \
  --mode full \
  --cve \
  --burp \
  --confirm
```

---

### `report` — Regenerate Reports
Re-run the reporter on a saved JSON results file:
```bash
python waspsting.py --mode report --results output/waspsting_20250101_120000.json
```

---

## Output Files

Every scan produces files in `./output/` (or `--output` dir):

| File | Description |
|------|-------------|
| `waspsting_SESSION.md` | Markdown pentest report with evidence templates |
| `waspsting_SESSION.json` | Machine-readable results (CI/CD, Jira, Slack) |
| `burp_config_SESSION.json` | Burp Suite Community Edition config |
| `bugbounty_plan_SESSION.md` | Bug bounty test plan (--mode bounty) |
| `bugbounty_scope_SESSION.json` | Scope data for reuse |

---

## CI/CD Integration

WaspSting exits with meaningful codes:

| Code | Meaning |
|------|---------|
| `0` | No significant findings |
| `1` | Findings present |
| `2` | Critical risk — immediate action required |

```yaml
# GitHub Actions example
- name: WaspSting SAST
  run: python waspsting.py --repo ${{ github.repositoryUrl }} --mode sast --fast
  # Fails the build on critical findings (exit 2)
```
