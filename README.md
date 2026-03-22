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
- 📋 **Auto-generates fill-in evidence templates** per finding — your report writes itself
- 🎯 **Bug bounty scope ingestion** — paste a program's scope and get a full phased test plan
- 🤖 **Local AI via Ollama** — code review + bounty insights, no API key, no data leaves your machine
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
| 🎯 **Bug Bounty** | `--mode bounty` | Ingest scope → AI-powered phased test plan |
| 🔫 **Full Scan** | `--mode full` | Run all modules |

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

# Recon your own app
python waspsting.py --target https://your-app.com --mode recon --cve --confirm

# Bug bounty planner — interactive
python waspsting.py --mode bounty

# Bug bounty planner — load scope file
python waspsting.py --mode bounty --scope examples/example_scope.json
```

> `--confirm` is required for all live testing. It confirms you have authorization to test the target.

---

## Installation

### Requirements

| | Version | Notes |
|-|---------|-------|
| Python | 3.10+ | `python --version` |
| git | Any | Must be in PATH for SAST |
| Ollama | Any | Optional — local AI |

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
```

See [docs/installation.md](docs/installation.md) for platform-specific notes and troubleshooting.

---

## Usage

```bash
# ── Static analysis ────────────────────────────────────────────────
python waspsting.py --repo https://github.com/org/repo --mode sast

# ── Recon with CVE lookup ─────────────────────────────────────────
python waspsting.py -t https://target.com --mode recon --cve --confirm

# ── Auth audit with custom wordlist ───────────────────────────────
python waspsting.py -t https://target.com --mode auth \
  --wordlist wordlists/common.txt --confirm

# ── BOLA/IDOR documentation ───────────────────────────────────────
python waspsting.py -t https://target.com --mode bola --confirm

# ── API security checks + Burp config ─────────────────────────────
python waspsting.py -t https://target.com --mode api --burp --confirm

# ── Full scan ─────────────────────────────────────────────────────
python waspsting.py \
  --target https://target.com \
  --repo https://github.com/org/repo \
  --mode full --cve --burp --confirm

# ── Bug bounty planner ────────────────────────────────────────────
python waspsting.py --mode bounty
python waspsting.py --mode bounty --scope my_scope.json

# ── CI/CD (skip animation) ────────────────────────────────────────
python waspsting.py --fast --mode sast --repo https://github.com/org/repo
```

Full reference: [docs/usage.md](docs/usage.md)

---

## Bug Bounty Planner

`--mode bounty` turns a bug bounty program's scope page into a structured, prioritized test plan.

**How it works:**

```
Ingest scope → Classify attack surfaces → Prioritize vulnerabilities
→ Generate phased test plan → Output WaspSting commands → AI insights
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

Or paste raw text from HackerOne/Bugcrowd — WaspSting auto-parses it.

**Output:** Phased test checklist + prioritized vuln list + ready-to-run commands + Ollama AI insights, saved as Markdown and JSON.

---

## OWASP Top 10:2025 Coverage

Every finding maps to OWASP Top 10:2025 with CWE references and AI-specific checks:

| ID | Category | AI-Specific Gaps |
|----|----------|-----------------|
| A01 | Broken Access Control | LLM endpoints without auth, unprotected vector DBs |
| A02 | Security Misconfiguration | AI API keys in repos, Ollama on 0.0.0.0 |
| A03 | Supply Chain Failures | AI/ML libs on vulnerable versions |
| A04 | Cryptographic Failures | Prompt logs in plaintext |
| A05 | Injection | **Prompt injection**, RAG poisoning, LLM output XSS |
| A06 | Insecure Design | No rate limiting on AI (cost amplification attacks) |
| A07 | Authentication Failures | JWT alg:none, shared AI keys across tenants |
| A08 | Data Integrity Failures | pickle.loads on model artifacts |
| A09 | Logging Failures | No AI abuse / spend monitoring |
| A10 | Exception Handling | LLM timeout/error fail-open |

---

## Burp Suite Integration

```bash
python waspsting.py --target https://target.com --mode full --burp --confirm
# → output/burp_config_TIMESTAMP.json
```

**Import:** Burp Suite → Project Options → Misc → Load project options

Config includes pre-built:
- Target scope
- Match/replace rules (JWT bypass, IP spoofing, role header injection)
- Intruder payloads (BOLA IDs, SQLi, XSS, mass assignment fields)
- Repeater requests for common manual tests

---

## Output

```
output/
├── waspsting_20250101_120000.md        ← Pentest report (fill-in evidence templates)
├── waspsting_20250101_120000.json      ← Machine-readable (CI/CD / Jira / Slack)
├── burp_config_20250101_120000.json    ← Burp Suite Community config
├── bugbounty_plan_20250101_120000.md   ← Bug bounty test plan
└── bugbounty_scope_20250101_120000.json
```

---

## Project Structure

```
waspsting/
├── waspsting.py          ← CLI entry point
├── banner.py             ← Animated hacker terminal banner
├── knowledge_base.py     ← OWASP Top 10:2025 knowledge base
├── requirements.txt      ← rich, requests (that's it)
│
├── modules/
│   ├── recon.py          ← Headers, fingerprinting, NVD CVE
│   ├── auth_audit.py     ← Login audit, lockout, JWT
│   ├── bola.py           ← BOLA/IDOR test case generation
│   ├── api_checks.py     ← Rate limit, CORS, injection
│   ├── sast.py           ← Static analysis + Ollama AI
│   ├── bugbounty.py      ← Scope ingestion + test plan
│   ├── burp_export.py    ← Burp Community config generator
│   └── reporter.py       ← Rich terminal + Markdown + JSON
│
├── wordlists/
│   └── common.txt        ← Common passwords (auth audit)
│
├── examples/
│   ├── example_scope.json
│   └── scope_template.txt
│
└── docs/
    ├── installation.md
    └── usage.md
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
        # Exit 2 = critical findings → fails the build
```

| Exit Code | Meaning |
|-----------|---------|
| `0` | Clean |
| `1` | Findings present |
| `2` | Critical risk — fails build |

---

## Roadmap

- [ ] Subdomain enumeration module
- [ ] Docker image
- [ ] HackerOne / Bugcrowd API — auto-import scope
- [ ] Nuclei template integration
- [ ] Slack/Discord webhook for live findings
- [ ] Custom OWASP pattern rules (user-defined regex)
- [ ] CVSS v3.1 score calculator per finding

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs welcome — especially new modules, wordlists, and OWASP patterns.

---

## Legal

MIT License — see [LICENSE](LICENSE).

By using WaspSting you agree to only test systems you own or have explicit written authorization to test. The author assumes no liability for misuse.

---

<div align="center">

Made with 🐝 by **N00dleN00b**

*If WaspSting helped you find a bug — star the repo!*

</div>
