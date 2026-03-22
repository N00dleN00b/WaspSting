# Contributing to WaspSting

Thanks for your interest in contributing. WaspSting is a community security research tool — contributions are welcome.

## Ground Rules

- All contributions must be for **authorized, ethical security testing** use cases only
- No weaponized automation, no targeting infrastructure you don't own
- Keep the tool in the spirit of documentation, research, and authorized bug bounty work

## How to Contribute

### Reporting Bugs
Open an issue with:
- Your OS and Python version
- The exact command you ran
- The full error output
- Steps to reproduce

### Adding Features
1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature-name`
3. Follow the module pattern in `modules/` (see below)
4. Add your feature to `CHANGELOG.md`
5. Submit a pull request with a clear description

### Module Pattern
Each module lives in `modules/` and exports a `run_<name>()` function:

```python
def run_yourmodule(target: str, ..., console) -> dict:
    """
    Returns: {"findings": [...], ...}
    Each finding must have: module, owasp_id, owasp_name, severity,
                            title, description, evidence, fix, timestamp
    """
```

Wire it into `waspsting.py` by adding a mode and routing block.

### Wordlists
Additional wordlists go in `wordlists/`. Keep file sizes reasonable (under 10MB).
Include a comment header explaining the source and intended use.

### Knowledge Base
To add OWASP/pentest methodology — edit `knowledge_base.py`.
Each entry needs: `id`, `name`, `severity`, `description`, `test_steps`, `indicators`, `patterns`, `cwe`, `cvss_base`.

## Code Style
- Python 3.10+
- Type hints where practical
- Docstrings on all public functions
- No external API keys required for core functionality
- Keep the green-on-black hacker aesthetic 🐝

## Questions?
Open a discussion on GitHub.
