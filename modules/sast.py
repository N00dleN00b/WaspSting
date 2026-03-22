"""
modules/sast.py — Static Application Security Testing
Clones a GitHub repo and analyzes code for OWASP Top 10:2025 vulnerabilities.
Optionally uses Ollama for AI-assisted code review.
"""

import re
import os
import json
import time
import shutil
import subprocess
import tempfile
import requests
from pathlib import Path
from datetime import datetime
from knowledge_base import OWASP_TOP_10_2025, SEVERITY_ORDER

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java",
    ".rb", ".go", ".cs", ".env", ".yml", ".yaml", ".toml",
    ".cfg", ".ini", ".conf", ".html", ".sh"
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "vendor", "migrations"
}

MAX_FILE_SIZE_KB = 200
MAX_FILES = 120


def clone_repo(url: str, dest: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", "--single-branch", url, dest],
            capture_output=True, text=True, timeout=120
        )
        return result.returncode == 0
    except Exception:
        return False


def walk_repo(repo_path: str):
    repo_root = Path(repo_path)
    count = 0
    for path in sorted(repo_root.rglob("*")):
        if count >= MAX_FILES:
            break
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        try:
            if path.stat().st_size / 1024 > MAX_FILE_SIZE_KB:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
            if content.strip():
                yield str(path.relative_to(repo_root)), content
                count += 1
        except OSError:
            continue


def static_scan(file_path: str, content: str) -> list[dict]:
    findings = []
    lines = content.split("\n")
    for owasp_id, vuln in OWASP_TOP_10_2025.items():
        for pattern in vuln.get("patterns", []):
            try:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "module": "sast", "source": "static",
                            "owasp_id": owasp_id, "owasp_name": vuln["name"],
                            "severity": vuln["severity"],
                            "title": f"{vuln['name']} — pattern match",
                            "description": vuln["description"],
                            "evidence": line.strip()[:200],
                            "file": file_path, "line_hint": str(i),
                            "fix": f"Review against {vuln['id']} guidelines. See: https://owasp.org/Top10/",
                            "cwe": ", ".join(vuln.get("cwe", [])),
                            "timestamp": datetime.now().isoformat()
                        })
                        break
            except re.error:
                continue
    return findings


def analyze_with_ollama(file_path: str, content: str, framework: str) -> list[dict]:
    """Send code chunk to local Ollama for AI analysis."""
    findings = []

    owasp_context = "\n".join([
        f"- {v['id']} {v['name']}: {', '.join(v['indicators'][:5])}"
        for v in OWASP_TOP_10_2025.values()
    ])

    prompt = f"""You are an expert security code reviewer. Analyze this {framework} code file for OWASP Top 10:2025 vulnerabilities.
    
File: {file_path}

OWASP Top 10:2025 reference:
{owasp_context}

Code:
```
{content[:2000]}
```

Return ONLY a JSON array of findings. Each finding must have:
{{"owasp_id": "A01", "owasp_name": "...", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "title": "...", "description": "...", "evidence": "specific code line", "fix": "...", "ai_specific": false}}

If no issues found, return []. Return only valid JSON, no markdown."""

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "llama3", "prompt": prompt, "stream": False},
            timeout=60
        )
        if r.status_code == 200:
            raw = r.json().get("response", "").strip()
            # Strip markdown fences
            raw = re.sub(r"```(?:json)?\n?", "", raw).strip("` \n")
            # Extract JSON array
            m = re.search(r"\[.*\]", raw, re.DOTALL)
            if m:
                items = json.loads(m.group())
                for item in items:
                    item["module"] = "sast"
                    item["source"] = "ollama_ai"
                    item["file"] = file_path
                    item["timestamp"] = datetime.now().isoformat()
                    findings.extend([item])
    except Exception:
        pass

    return findings


def detect_framework(files: dict) -> str:
    all_content = " ".join(list(files.values())[:20]).lower()
    paths = " ".join(files.keys()).lower()
    if "django" in all_content: return "Django"
    if "fastapi" in all_content: return "FastAPI"
    if "flask" in all_content: return "Flask"
    if "express" in all_content: return "Express.js"
    if "_app.tsx" in paths or "next.js" in all_content: return "Next.js"
    if "laravel" in all_content: return "Laravel"
    if "spring" in all_content: return "Spring"
    return "Unknown"


def run_sast(repo_url: str, output_dir: str, ai_available: bool, console) -> dict:
    from rich.table import Table
    from rich import box

    console.print(f"\n[bold cyan]═══ SAST MODULE[/bold cyan] → {repo_url}\n")

    findings = []
    temp_dir = tempfile.mkdtemp(prefix="waspsting_")
    repo_dir = os.path.join(temp_dir, "repo")

    try:
        console.print("[dim]Cloning repository...[/dim]")
        if not clone_repo(repo_url, repo_dir):
            console.print("[red]✗ Clone failed[/red]")
            return {"findings": []}

        files = {rp: ct for rp, ct in walk_repo(repo_dir)}
        framework = detect_framework(files)
        console.print(f"[green]✓ Cloned — {len(files)} files | Framework: {framework}[/green]\n")

        priority_exts = {".py", ".js", ".ts", ".php", ".rb", ".java"}

        for i, (file_path, content) in enumerate(files.items()):
            ext = Path(file_path).suffix.lower()
            console.print(f"  [dim]({i+1}/{len(files)}) {file_path[-55:]}[/dim]", end="\r")

            # Static scan every file
            static = static_scan(file_path, content)
            findings.extend(static)

            # AI scan for priority code files
            if ai_available and ext in priority_exts and len(content) > 50:
                ai = analyze_with_ollama(file_path, content, framework)
                # Deduplicate vs static
                for af in ai:
                    if not any(sf["owasp_id"] == af.get("owasp_id") and
                               sf["file"] == af.get("file") for sf in static):
                        findings.append(af)

        console.print()  # newline after progress

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("file"), f.get("owasp_id"), f.get("evidence", "")[:40])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        # Summary table
        sev_counts = {}
        for f in unique:
            s = f.get("severity", "INFO")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
        table.add_column("Severity"); table.add_column("Count")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in sev_counts:
                table.add_row(sev, str(sev_counts[sev]))
        console.print(table)
        console.print(f"\n[green]✓ SAST complete — {len(unique)} findings across {len(files)} files[/green]\n")

        return {"findings": unique, "framework": framework, "files_scanned": len(files)}

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
