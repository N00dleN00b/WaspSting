<div align="center">

```
 ██╗    ██╗ █████╗ ███████╗██████╗ ███████╗████████╗██╗███╗   ██╗ ██████╗
 ██║    ██║██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝
 ██║ █╗ ██║███████║███████╗██████╔╝███████╗   ██║   ██║██╔██╗ ██║██║  ███╗
 ██║███╗██║██╔══██║╚════██║██╔═══╝ ╚════██║   ██║   ██║██║╚██╗██║██║   ██║
 ╚███╔███╔╝██║  ██║███████║██║     ███████║   ██║   ██║██║ ╚████║╚██████╔╝
  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝
```

**Authorized Pentest Documentation & Analysis Tool**

*Created by N00dleN00b*

[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen?style=flat-square&logo=python)](https://python.org)
[![Version](https://img.shields.io/badge/Version-1.5-brightgreen?style=flat-square)](CHANGELOG.md)
[![License](https://img.shields.io/badge/License-MIT-brightgreen?style=flat-square)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%3A2025-red?style=flat-square)](https://owasp.org/Top10/)
[![Ollama](https://img.shields.io/badge/AI-Ollama%20Local-yellow?style=flat-square)](https://ollama.ai)
[![Burp](https://img.shields.io/badge/Burp%20Suite-Community-orange?style=flat-square)](https://portswigger.net)

> ⚠️ **FOR AUTHORIZED USE ONLY.** This tool is for security professionals testing systems they own or have explicit written permission to test. Unauthorized access to computer systems is illegal and unethical.

</div>

---

## What is WaspSting?

WaspSting is a Python CLI security tool for **authorized penetration testing, bug bounty hunting, and security research**. It solves one of the most tedious parts of pentesting — **documentation** — by auto-generating structured reports, evidence templates, and test plans as you work.

**Key differentiators:**
- 📋 **Auto-documentation** — fill-in evidence templates per finding, report writes itself
- 🎯 **Bug bounty scope ingestion** — paste a program's scope, get a full phased test plan
- 🌐 **Subdomain enumeration** — crt.sh + HackerTarget + DNS brute force, all free
- 🖼️ **Asset gallery** — screenshots + metadata of every discovered subdomain
- 💣 **Payload fuzzer** — SQLi, XSS, SSTI, SSRF, prompt injection, path traversal + custom wordlists
- 🔔 **Live notifications** — Slack/Discord webhooks + GitHub Issues auto-created from findings
- 🤖 **Local AI via Ollama** — code review + bounty insights, no API key, nothing leaves your machine
- 📊 **Executive HTML report** — risk gauge, severity charts, filterable findings table
- 🎯 **Burp Suite Community config** — pre-built scope, payloads, and Repeater requests
- 🔗 **NVD CVE lookup** — free, no key required

---

## Features

| Module | Flag | Description |
|--------|------|-------------|
| 🔬 **SAST** | `--mode sast` | Clone a GitHub repo and scan for OWASP Top 10:2025 vulnerabilities |
| 🌐 **Recon** | `--mode recon` | Security headers, tech fingerprint, CVE lookup |
| 🔐 **Auth Audit** | `--mode auth` | Login lockout testing, JWT attack docs, credential audit |
| 🎭 **BOLA/IDOR** | `--mode bola` | Sequential ID walking, documented test cases |
| 🔧 **API Checks** | `--mode api` | Rate limiting, CORS, data exposure, injection probes |
| 🌍 **Subdomain Enum** | `--mode enum` | crt.sh + HackerTarget + DNS brute force |
| 💣 **Fuzzer** | `--mode fuzz` | Custom payload fuzzer — 9 categories + your own wordlists |
| 🎯 **Bug Bounty** | `--mode bounty` | Ingest scope → AI-powered phased test plan |
| 🔫 **Full Scan** | `--mode full` | Run all modules |

**Flags that work with any mode:**

| Flag | Description |
|------|-------------|
| `--html` | Generate executive HTML report with charts |
| `--screenshot` | Capture asset gallery from discovered subdomains |
| `--burp` | Generate Burp Suite Community Edition config JSON |
| `--cve` | Query NVD CVE database for detected tech |
| `--slack URL` | Post findings live to Slack |
| `--discord URL` | Post findings live to Discord |
| `--github-token / --github-repo` | Auto-create GitHub Issues from findings |
| `--dedup` | Skip findings seen in previous scan sessions |
| `--no-ai` | Skip Ollama analysis |
| `--fast` | Skip banner animation (CI/CD mode) |

---

## Quick Start

```bash
git clone https://github.com/N00dleN00b/waspsting.git
cd waspsting
pip install -r requirements.txt
python waspsting.py --help
```

```bash
# Static code analysis — no target, no authorization needed
python waspsting.py --repo https://github.com/your-org/your-app --mode sast

# Recon + CVE lookup on your own app
python waspsting.py --target https://your-app.com --mode recon --cve --confirm

# Subdomain enum → screenshot gallery
python waspsting.py --target https://your-app.com --mode enum --screenshot --confirm

# Bug bounty planner — interactive wizard
python waspsting.py --mode bounty

# Everything at once
python waspsting.py \
  --target https://target.com \
  --repo https://github.com/org/app \
  --mode full --cve --burp --html --screenshot \
  --discord https://discord.com/api/webhooks/... \
  --dedup --confirm
```

> `--confirm` is required for all live testing. It's your acknowledgement that you have authorization.

---

## Installation

### Requirements

| | Version | Notes |
|-|---------|-------|
| Python | 3.10+ | `python --version` |
| git | Any | Must be in PATH for SAST |
| Ollama | Any | Optional — local AI |
| gowitness / chromium | Any | Optional — real screenshots |

```bash
# 1. Clone
git clone https://github.com/N00dleN00b/waspsting.git
cd waspsting

# 2. Virtual environment (recommended)
python -m venv venv
source venv/bin/activate       # Linux/macOS
# venv\Scripts\activate        # Windows

# 3. Install
pip install -r requirements.txt

# 4. Optional: Local AI (no API key needed)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3
ollama serve

# 5. Optional: Real screenshots
# Kali/Ubuntu:  sudo apt install chromium
# macOS:        brew install --cask chromium
# Or:           go install github.com/sensepost/gowitness@latest
```

See [docs/installation.md](docs/installation.md) for platform-specific notes.

---

## Usage

```bash
# ── SAST (no live requests) ────────────────────────────────────────
python waspsting.py --repo https://github.com/org/repo --mode sast

# ── Recon ──────────────────────────────────────────────────────────
python waspsting.py -t https://target.com --mode recon --cve --confirm

# ── Auth audit ─────────────────────────────────────────────────────
python waspsting.py -t https://target.com --mode auth \
  --wordlist wordlists/common.txt --confirm

# ── BOLA/IDOR ──────────────────────────────────────────────────────
python waspsting.py -t https://target.com --mode bola --confirm

# ── API security + Burp config ────────────────────────────────────
python waspsting.py -t https://target.com --mode api --burp --confirm

# ── Subdomain enum + screenshots ──────────────────────────────────
python waspsting.py -t https://target.com --mode enum --screenshot --confirm

# ── Payload fuzzer (built-in categories) ──────────────────────────
python waspsting.py -t https://target.com --mode fuzz --confirm

# ── Fuzzer with custom wordlist + specific categories ─────────────
python waspsting.py -t https://target.com --mode fuzz \
  --fuzz-list wordlists/fuzz/my_payloads.txt \
  --fuzz-cats sqli,xss,ssrf --confirm

# ── Bug bounty planner ────────────────────────────────────────────
python waspsting.py --mode bounty
python waspsting.py --mode bounty --scope examples/example_scope.json

# ── Full scan — everything ─────────────────────────────────────────
python waspsting.py \
  --target https://target.com \
  --repo https://github.com/org/app \
  --mode full --cve --burp --html --screenshot \
  --slack https://hooks.slack.com/... \
  --discord https://discord.com/api/webhooks/... \
  --github-token ghp_xxx --github-repo yourname/bounty-notes \
  --dedup --notify-severity HIGH \
  --confirm

# ── CI/CD (skip animation, exit 2 on CRITICAL) ────────────────────
python waspsting.py --fast --mode sast --repo https://github.com/org/repo

# ── Regenerate report from saved JSON ─────────────────────────────
python waspsting.py --mode report --results output/waspsting_20250101.json
```

Full reference: [docs/usage.md](docs/usage.md)

---

## Subdomain Enumeration

`--mode enum` runs three layers automatically:

1. **crt.sh** — certificate transparency logs (passive, free, no key)
2. **HackerTarget API** — free subdomain lookup
3. **DNS brute force** — concurrent resolution against `wordlists/subdomains.txt`

Every live subdomain gets HTTP probed. Interesting patterns (`admin.`, `staging.`, `jenkins.`, `backup.`, `grafana.`) auto-generate OWASP findings.

Add `--screenshot` to build a self-contained HTML asset gallery with page titles, tech stack, status codes, and screenshots (if gowitness/chromium installed).

---

## Payload Fuzzer

`--mode fuzz` tests endpoints with 9 built-in payload categories:

| Category | Detects |
|----------|---------|
| `sqli` | SQL syntax errors, MySQL/PostgreSQL messages |
| `xss` | Reflected payloads, script execution |
| `ssti` | Template evaluation (Jinja2, Twig, Freemarker) |
| `path_traversal` | `/etc/passwd`, `win.ini` in responses |
| `command_injection` | `uid=`, `root:` in responses |
| `ssrf` | AWS metadata, internal service responses |
| `nosql` | MongoDB operator injection |
| `prompt_injection` | LLM instruction override indicators |
| `open_redirect` | Redirects to evil.com |

Use your own payloads with `--fuzz-list path/to/payloads.txt`. Target specific categories with `--fuzz-cats sqli,xss,ssrf`.

---

## Live Notifications

Findings are posted as they're discovered — no waiting for the scan to finish.

**Slack:**
```bash
python waspsting.py --target https://target.com --mode full \
  --slack https://hooks.slack.com/services/xxx --confirm
```

**Discord:**
```bash
python waspsting.py --target https://target.com --mode full \
  --discord https://discord.com/api/webhooks/xxx/yyy --confirm
```

**GitHub Issues** (auto-created for HIGH+ findings):
```bash
python waspsting.py --target https://target.com --mode full \
  --github-token ghp_yourtoken --github-repo yourname/repo --confirm
```

**Or use environment variables** to avoid putting secrets in your shell history:
```bash
export WASPSTING_SLACK_WEBHOOK=https://hooks.slack.com/...
export WASPSTING_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
export WASPSTING_GITHUB_TOKEN=ghp_xxx
export WASPSTING_GITHUB_REPO=yourname/repo
```

**Control minimum severity for notifications** (default: HIGH):
```bash
--notify-severity CRITICAL   # only critical findings
--notify-severity MEDIUM     # medium and above
```

---

## Deduplication

`--dedup` tracks finding fingerprints across sessions so you're only alerted to genuinely new findings:

```bash
python waspsting.py --target https://target.com --mode full --dedup --confirm
# Skips anything seen in previous scans — great for recurring scheduled scans
```

History is stored at `output/.waspsting_history.json` (configurable with `--dedup-db`).

---

## Bug Bounty Planner

`--mode bounty` turns a bug bounty program's scope page into a structured, prioritized test plan.

```
Ingest scope → Classify surfaces → Prioritize vulns by payout
→ Phased test plan → Ready-to-run WaspSting commands → AI insights
```

**Scope file** (`scope.json`):

```json
{
  "program_name": "Acme Corp — HackerOne",
  "platform": "HackerOne",
  "reward_range": "$100 - $10,000",
  "in_scope": [
    "https://app.acmecorp.com",
    "https://api.acmecorp.com",
    "*.acmecorp.com"
  ],
  "out_of_scope": ["blog.acmecorp.com", "Third-party integrations"],
  "vulnerability_types": ["XSS", "SQLi", "IDOR", "RCE", "SSRF"],
  "excluded_vuln_types": ["Self-XSS", "Missing headers"],
  "special_rules": ["No automated scanning", "Rate limit: 10 req/s"],
  "notes": "React frontend, Node.js API, PostgreSQL"
}
```

Or paste raw text from HackerOne/Bugcrowd — WaspSting auto-parses it. See `examples/scope_template.txt`.

---

## OWASP Top 10:2025 Coverage

Every finding maps to OWASP Top 10:2025 with CWE references and AI-specific checks:

| ID | Category | AI-Specific Gaps |
|----|----------|-----------------|
| A01 | Broken Access Control | LLM endpoints without auth, unprotected vector DBs |
| A02 | Security Misconfiguration | AI API keys in repos, Ollama exposed on 0.0.0.0 |
| A03 | Supply Chain Failures | AI/ML libs on vulnerable versions |
| A04 | Cryptographic Failures | Prompt logs in plaintext, embeddings unencrypted |
| A05 | Injection | **Prompt injection**, RAG poisoning, LLM output XSS |
| A06 | Insecure Design | No rate limiting on AI endpoints (cost amplification) |
| A07 | Authentication Failures | JWT alg:none, shared AI API keys across tenants |
| A08 | Data Integrity Failures | pickle.loads on model artifacts |
| A09 | Logging Failures | No AI abuse / spend monitoring |
| A10 | Exception Handling | LLM timeout/error fail-open |

---

## Output

Every scan saves to `./output/`:

```
output/
├── waspsting_SESSION.md             ← Pentest report with evidence templates
├── waspsting_SESSION.json           ← Machine-readable (CI/CD, Jira, Slack)
├── waspsting_SESSION.html           ← Executive HTML report with charts  (--html)
├── burp_config_SESSION.json         ← Burp Suite Community config         (--burp)
├── asset_gallery_SESSION.html       ← Subdomain screenshot gallery        (--screenshot)
├── bugbounty_plan_SESSION.md        ← Bug bounty test plan                (--mode bounty)
├── bugbounty_scope_SESSION.json     ← Scope data for reuse
└── .waspsting_history.json          ← Dedup fingerprint database          (--dedup)
```

---

## Project Structure

```
waspsting/
├── waspsting.py             ← CLI entry point
├── banner.py                ← Animated hacker terminal banner
├── knowledge_base.py        ← OWASP Top 10:2025 + pentest methodology KB
├── requirements.txt         ← rich, requests (that's it)
│
├── modules/
│   ├── recon.py             ← Headers, fingerprinting, NVD CVE lookup
│   ├── auth_audit.py        ← Login audit, lockout, JWT documentation
│   ├── bola.py              ← BOLA/IDOR test case generation
│   ├── api_checks.py        ← Rate limit, CORS, injection probes
│   ├── sast.py              ← Static analysis + Ollama AI code review
│   ├── subdomain.py         ← Subdomain enumeration (crt.sh + DNS)
│   ├── fuzzer.py            ← Payload fuzzer — 9 categories + custom
│   ├── screenshot.py        ← Asset gallery HTML generator
│   ├── notify.py            ← Slack, Discord, GitHub Issues
│   ├── html_report.py       ← Executive HTML report with Chart.js
│   ├── bugbounty.py         ← Scope ingestion + test plan
│   ├── burp_export.py       ← Burp Community config generator
│   └── reporter.py          ← Rich terminal + Markdown + JSON
│
├── wordlists/
│   ├── common.txt           ← Common passwords (auth audit)
│   ├── subdomains.txt       ← Subdomain brute force list
│   └── fuzz/                ← Drop custom payload files here
│
├── examples/
│   ├── example_scope.json   ← Sample bug bounty scope (JSON)
│   └── scope_template.txt   ← Sample scope (raw text format)
│
├── docs/
│   ├── installation.md      ← Detailed install + troubleshooting
│   └── usage.md             ← Full flag reference
│
├── .github/
│   └── workflows/
│       └── security.yml     ← GitHub Actions SAST workflow
│
├── .gitignore
├── LICENSE                  ← MIT
├── CHANGELOG.md
└── CONTRIBUTING.md
```

---

## CI/CD

```yaml
# .github/workflows/security.yml
name: WaspSting Security Scan
on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: python waspsting.py --fast --mode sast --repo ${{ github.server_url }}/${{ github.repository }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: output/
```

| Exit Code | Meaning | CI/CD |
|-----------|---------|-------|
| `0` | Clean | ✅ Pass |
| `1` | Findings present | ⚠️ Warning |
| `2` | Critical risk | ❌ Fail build |

---

## Roadmap

- [x] Subdomain enumeration
- [x] Asset screenshot gallery
- [x] Payload fuzzer
- [x] Slack / Discord notifications
- [x] GitHub Issues integration
- [x] Executive HTML report with charts
- [x] Finding deduplication across sessions
- [ ] Docker image
- [ ] HackerOne / Bugcrowd API — auto-import scope
- [ ] Nuclei template runner
- [ ] CVSS v3.1 score calculator per finding
- [ ] Custom OWASP pattern rules (user-defined regex)

---

## Dependencies

```
rich>=13.0.0       # Terminal UI
requests>=2.31.0   # HTTP client
```

Two dependencies. No bloated dependency tree. `git` must be in PATH for SAST. Everything else is stdlib or optional external tools.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome — especially new modules, wordlists, and OWASP patterns.

---

## Legal

MIT License — see [LICENSE](LICENSE).

By using WaspSting you agree to only test systems you own or have explicit written authorization to test. The author assumes no liability for any misuse or damage.

---

<div align="center">

Made with 🐝 by **N00dleN00b**

*If WaspSting helped you find a bug — star the repo!*

</div>
