# Changelog

All notable changes to WaspSting are documented here.

---

## [1.4.0] — 2025

### Added
- 🎯 **Bug Bounty Planner** (`--mode bounty`) — ingest scope from JSON/text, generate phased test plans
- 🐝 **Animated hacker banner** — green-on-black terminal boot sequence with typewriter effect and glitch animation
- 🤖 **Ollama AI integration** — local LLM for code review and bounty insights, no API key required
- `--fast` flag to skip banner animation (useful for scripting/CI)
- `example_scope.json` template for bug bounty scope ingestion
- `Created by N00dleN00b` attribution throughout

### Changed
- Updated to v1.4 with improved module routing
- Banner now uses raw ANSI (no Rich dependency) for boot sequence authenticity
- Scan start sequence now mimics real terminal workflow

---

## [1.3.0] — 2025

### Added
- 🔍 **SAST module** — clone GitHub repos and analyze for OWASP Top 10:2025
- 🌐 **Recon module** — security headers, tech fingerprinting, NVD CVE lookup (free, no key)
- 🔐 **Auth Audit module** — lockout testing, JWT attack documentation, credential audit
- 🎭 **BOLA/IDOR module** — sequential ID walking, test case documentation
- 🔧 **API Checks module** — rate limiting, CORS, data exposure, injection probes
- 🎯 **Burp Suite export** — auto-generate Community Edition config JSON
- 📄 **Auto-documentation** — fill-in evidence templates per finding

### Added (Knowledge Base)
- Full OWASP Top 10:2025 (A01–A10) with test steps, patterns, CWE references
- AI-webapp-specific vulnerability checks (prompt injection, model exposure, etc.)
- BOLA, JWT, Mass Assignment, Rate Limiting methodology docs

---

## [1.0.0] — Initial Release

- Basic OWASP Top 10:2025 static scanner (OWASPy prototype)
- Rich terminal output
- Markdown + JSON report export
