# Installation Guide

## Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | `python --version` to check |
| git | Any | Must be in PATH for SAST module |
| Ollama | Any | Optional — for AI features |

## Quick Install

```bash
# 1. Clone the repo
git clone https://github.com/N00dleN00b/waspsting.git
cd waspsting

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify install
python waspsting.py --help
```

## Optional: Ollama (Local AI)

Ollama runs LLMs locally — no API key, no data leaves your machine.

```bash
# Install Ollama (Linux/macOS)
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model (llama3 recommended, ~4GB)
ollama pull llama3

# Start the server
ollama serve
```

WaspSting auto-detects Ollama at `localhost:11434` and uses it for:
- AI-assisted code review in SAST module
- Bounty hunter insights in bug bounty mode
- Recon findings summarization

Other supported models: `llama3.2`, `codellama`, `mistral`, `gemma2`

## Platform Notes

### Linux / macOS
Works out of the box. Animated banner uses ANSI escape codes (supported in all modern terminals).

### Windows
Use Windows Terminal or WSL2 for best results. CMD may not render ANSI colors — use `--fast` flag if needed:
```bash
python waspsting.py --fast --target https://example.com --mode recon --confirm
```

### Kali Linux / Parrot OS
Pre-installed Python 3 + git. Just clone and install requirements.

## Troubleshooting

**Banner looks garbled:**
```bash
python waspsting.py --fast   # disables animation
```

**`git` not found (SAST fails):**
```bash
# Ubuntu/Debian
sudo apt install git

# macOS
xcode-select --install
```

**Ollama not detected:**
```bash
# Check it's running
curl http://localhost:11434/api/tags

# If not, start it
ollama serve
```

**Permission denied on output directory:**
```bash
python waspsting.py --output ~/waspsting_output ...
```
