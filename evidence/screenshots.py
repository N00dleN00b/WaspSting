"""
modules/screenshot.py — Asset screenshot capture

Uses the free screenshotone.com API (no key for basic) or
falls back to saving an HTML thumbnail gallery using
response metadata + favicon fetching.

For full screenshots: optionally uses `cutycapt`, `gowitness`,
or `aquatone` if installed — auto-detected.
"""

import os
import re
import time
import base64
import shutil
import subprocess
import requests
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


HTTP_TIMEOUT = 8
SCREENSHOT_DIR = "screenshots"

# Free screenshot APIs (no key required for basic usage)
FREE_APIS = [
    "https://api.screenshotone.com/take?url={url}&format=jpg&viewport_width=1280&viewport_height=800",
    "https://shot.screenshotapi.net/screenshot?token=free&url={url}&output=image&file_type=jpg&wait_for_event=load",
]


def detect_screenshot_tool() -> str | None:
    """Check for locally installed headless screenshot tools."""
    tools = ["gowitness", "cutycapt", "chromium-browser", "google-chrome", "chromium"]
    for tool in tools:
        if shutil.which(tool):
            return tool
    return None


def fetch_favicon(url: str) -> str:
    """Fetch favicon as base64 for HTML gallery."""
    parsed = urlparse(url)
    favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
    try:
        r = requests.get(favicon_url, timeout=4,
                         headers={"User-Agent": "WaspSting/1.0"})
        if r.status_code == 200 and len(r.content) > 0:
            b64 = base64.b64encode(r.content).decode()
            ct = r.headers.get("Content-Type", "image/x-icon").split(";")[0]
            return f"data:{ct};base64,{b64}"
    except Exception:
        pass
    return ""


def get_page_metadata(url: str) -> dict:
    """Fetch page metadata for the gallery card."""
    meta = {
        "url": url, "status": None, "title": "",
        "server": "", "tech": [], "favicon": "",
        "screenshot_b64": "", "error": ""
    }
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 WaspSting/1.0"})
        meta["status"] = r.status_code
        meta["server"] = r.headers.get("Server", "")

        # Title
        m = re.search(r"<title[^>]*>([^<]{1,100})</title>", r.text, re.IGNORECASE)
        if m:
            meta["title"] = m.group(1).strip()

        # Quick tech detection
        body = r.text.lower()
        headers_str = str(r.headers).lower()
        tech_map = {
            "React": "react", "Next.js": "__next_data__",
            "Vue": "vue.js", "Angular": "ng-version",
            "WordPress": "wp-content", "Django": "csrfmiddlewaretoken",
            "Laravel": "laravel_session", "Rails": "x-runtime",
        }
        for tech, sig in tech_map.items():
            if sig in body or sig in headers_str:
                meta["tech"].append(tech)

    except Exception as e:
        meta["error"] = str(e)[:60]

    meta["favicon"] = fetch_favicon(url)
    return meta


def try_screenshot_api(url: str) -> str:
    """Try free screenshot APIs, return base64 JPEG or empty string."""
    for api_template in FREE_APIS:
        api_url = api_template.format(url=requests.utils.quote(url, safe=""))
        try:
            r = requests.get(api_url, timeout=20,
                             headers={"User-Agent": "WaspSting/1.0"})
            if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("image"):
                return base64.b64encode(r.content).decode()
        except Exception:
            continue
    return ""


def try_local_screenshot(url: str, output_path: str, tool: str) -> bool:
    """Use a locally installed tool to take a screenshot."""
    try:
        if tool == "gowitness":
            result = subprocess.run(
                ["gowitness", "single", "--url", url, "--screenshot-path", output_path],
                capture_output=True, timeout=30
            )
            return result.returncode == 0

        elif tool in ("chromium-browser", "google-chrome", "chromium"):
            result = subprocess.run([
                tool, "--headless", "--disable-gpu",
                "--no-sandbox", "--disable-dev-shm-usage",
                f"--screenshot={output_path}",
                "--window-size=1280,800", url
            ], capture_output=True, timeout=30)
            return result.returncode == 0 and Path(output_path).exists()

    except Exception:
        pass
    return False


def build_html_gallery(assets: list[dict], output_path: str,
                        program_name: str = "WaspSting"):
    """Generate a self-contained HTML gallery of discovered assets."""

    cards = ""
    for asset in assets:
        status = asset.get("status", "?")
        status_color = (
            "#4ade80" if status == 200
            else "#facc15" if status in (301, 302, 403)
            else "#f87171" if status and status >= 400
            else "#6b7280"
        )
        tech_badges = "".join(
            f'<span style="background:#1e3a5f;color:#60a5fa;padding:2px 6px;'
            f'border-radius:3px;font-size:10px;margin-right:3px">{t}</span>'
            for t in asset.get("tech", [])
        )
        favicon_html = (
            f'<img src="{asset["favicon"]}" style="width:16px;height:16px;'
            f'margin-right:6px;vertical-align:middle" onerror="this.style.display=\'none\'">'
            if asset.get("favicon") else ""
        )
        screenshot_html = (
            f'<img src="data:image/jpeg;base64,{asset["screenshot_b64"]}" '
            f'style="width:100%;height:160px;object-fit:cover;border-radius:4px;'
            f'margin-bottom:8px;border:1px solid #1e3a5f">'
            if asset.get("screenshot_b64")
            else f'<div style="width:100%;height:160px;background:#0a1628;border-radius:4px;'
                 f'margin-bottom:8px;display:flex;align-items:center;justify-content:center;'
                 f'border:1px solid #1e3a5f;color:#374151;font-size:12px">'
                 f'{"⚠ " + asset["error"] if asset.get("error") else "No screenshot"}</div>'
        )
        url_display = asset["url"][:55] + "…" if len(asset["url"]) > 55 else asset["url"]

        cards += f"""
        <div style="background:#0d1f35;border:1px solid #1e3a5f;border-radius:8px;
                    padding:14px;break-inside:avoid">
          {screenshot_html}
          <div style="display:flex;align-items:center;margin-bottom:6px">
            {favicon_html}
            <a href="{asset['url']}" target="_blank"
               style="color:#60a5fa;text-decoration:none;font-size:13px;font-weight:600;
                      word-break:break-all">{url_display}</a>
          </div>
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <span style="background:{status_color};color:#000;padding:2px 8px;
                         border-radius:3px;font-size:11px;font-weight:700">{status}</span>
            <span style="color:#6b7280;font-size:11px">{asset.get('server','')[:25]}</span>
          </div>
          <div style="color:#d1d5db;font-size:12px;margin-bottom:6px;
                      white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
            {asset.get('title','') or '<span style="color:#6b7280">No title</span>'}
          </div>
          <div>{tech_badges}</div>
        </div>"""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    live_count = sum(1 for a in assets if a.get("status") == 200)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WaspSting — Asset Gallery</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0 }}
    body {{ background: #060d1a; color: #e5e7eb; font-family: 'Courier New', monospace;
            padding: 24px }}
    h1 {{ color: #4ade80; font-size: 20px; margin-bottom: 4px }}
    .meta {{ color: #6b7280; font-size: 12px; margin-bottom: 24px }}
    .stats {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap }}
    .stat {{ background: #0d1f35; border: 1px solid #1e3a5f; border-radius: 6px;
             padding: 10px 18px; text-align: center }}
    .stat-n {{ color: #4ade80; font-size: 24px; font-weight: 700 }}
    .stat-l {{ color: #9ca3af; font-size: 11px }}
    .grid {{ columns: 350px; gap: 16px }}
    .filter {{ margin-bottom: 20px }}
    input {{ background: #0d1f35; border: 1px solid #1e3a5f; color: #e5e7eb;
             padding: 8px 12px; border-radius: 4px; width: 300px; font-family: inherit }}
    input::placeholder {{ color: #374151 }}
  </style>
</head>
<body>
  <h1>🐝 WaspSting — Asset Gallery</h1>
  <div class="meta">Program: {program_name} &nbsp;|&nbsp; Generated: {timestamp} &nbsp;|&nbsp; Created by N00dleN00b</div>

  <div class="stats">
    <div class="stat"><div class="stat-n">{len(assets)}</div><div class="stat-l">Total Assets</div></div>
    <div class="stat"><div class="stat-n" style="color:#4ade80">{live_count}</div><div class="stat-l">Live (200)</div></div>
    <div class="stat"><div class="stat-n" style="color:#facc15">{sum(1 for a in assets if a.get('status') in (301,302))}</div><div class="stat-l">Redirects</div></div>
    <div class="stat"><div class="stat-n" style="color:#f87171">{sum(1 for a in assets if a.get('error'))}</div><div class="stat-l">Errors</div></div>
  </div>

  <div class="filter">
    <input type="text" id="search" placeholder="Filter by URL, title, tech..."
           oninput="filterCards()">
  </div>

  <div class="grid" id="grid">
    {cards}
  </div>

  <script>
    function filterCards() {{
      const q = document.getElementById('search').value.toLowerCase();
      document.querySelectorAll('#grid > div').forEach(card => {{
        card.style.display = card.innerText.toLowerCase().includes(q) ? '' : 'none';
      }});
    }}
  </script>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")


def run_screenshot(targets: list[str], output_dir: str,
                   program_name: str, console) -> dict:
    from rich.table import Table
    from rich import box

    console.print(f"\n[bold cyan]═══ SCREENSHOT / ASSET GALLERY[/bold cyan]\n")
    console.print(f"[dim]Capturing {len(targets)} assets...[/dim]\n")

    screenshots_dir = Path(output_dir) / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    local_tool = detect_screenshot_tool()
    if local_tool:
        console.print(f"[green]✓ Local screenshot tool: {local_tool}[/green]")
    else:
        console.print("[dim yellow]ℹ No local screenshot tool — using metadata gallery mode[/dim yellow]")
        console.print("[dim]  (Install gowitness or chromium for real screenshots)[/dim]\n")

    assets = []
    for i, url in enumerate(targets, 1):
        console.print(f"  [{i}/{len(targets)}] {url[:60]}", end=" ")
        meta = get_page_metadata(url)

        # Try screenshot
        if local_tool:
            ss_path = str(screenshots_dir / f"shot_{i:03d}.jpg")
            if try_local_screenshot(url, ss_path, local_tool):
                try:
                    meta["screenshot_b64"] = base64.b64encode(
                        Path(ss_path).read_bytes()
                    ).decode()
                except Exception:
                    pass
        else:
            meta["screenshot_b64"] = try_screenshot_api(url)

        status_str = f"[green]{meta['status']}[/green]" if meta["status"] == 200 \
                     else f"[yellow]{meta['status']}[/yellow]" if meta["status"] \
                     else f"[red]ERR[/red]"
        console.print(f"→ {status_str} {meta['title'][:30]}")

        assets.append(meta)
        time.sleep(0.3)

    # Build HTML gallery
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    gallery_path = str(Path(output_dir) / f"asset_gallery_{ts}.html")
    build_html_gallery(assets, gallery_path, program_name)

    live_count = sum(1 for a in assets if a.get("status") == 200)
    console.print(f"\n[bold green]✓ Gallery saved → [cyan]{gallery_path}[/cyan][/bold green]")
    console.print(f"  {live_count}/{len(assets)} assets live  |  Open in browser to view\n")

    return {
        "assets": assets,
        "gallery_path": gallery_path,
        "findings": []
    }
