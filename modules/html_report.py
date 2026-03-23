"""
modules/html_report.py — Executive-ready HTML report with charts

Self-contained single HTML file with:
- Risk score gauge
- Severity breakdown doughnut chart
- OWASP coverage bar chart
- Findings timeline
- Filterable findings table
- All charts via Chart.js CDN
"""

import json
from datetime import datetime
from collections import defaultdict
from pathlib import Path


SEVERITY_HEX = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#3b82f6",
    "INFO":     "#6b7280",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def build_html_report(results: dict, score: int, score_label: str) -> str:
    findings   = sorted(results.get("findings", []),
                        key=lambda f: SEVERITY_ORDER.get(f.get("severity","INFO"), 4))
    target     = results.get("target", "Unknown")
    session_id = results.get("session_id", "")
    timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.get("severity", "INFO")] += 1

    owasp_counts = defaultdict(int)
    for f in findings:
        oid = f.get("owasp_id")
        if oid:
            owasp_counts[oid] += 1

    modules_hit = sorted(set(f.get("module", "?") for f in findings))
    score_color = ("#ef4444" if score >= 75 else
                   "#f97316" if score >= 50 else
                   "#eab308" if score >= 25 else "#4ade80")

    # ── Chart data ────────────────────────────────────────────────────────────
    sev_chart_labels = json.dumps(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    sev_chart_data   = json.dumps([sev_counts.get(s, 0) for s in
                                   ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]])
    sev_chart_colors = json.dumps([SEVERITY_HEX[s] for s in
                                   ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]])

    owasp_all = [f"A{i:02d}" for i in range(1, 11)]
    owasp_names = [
        "Broken Access Control", "Security Misconfiguration",
        "Supply Chain Failures", "Cryptographic Failures",
        "Injection", "Insecure Design",
        "Authentication Failures", "Data Integrity Failures",
        "Logging Failures", "Exception Handling",
    ]
    owasp_chart_labels = json.dumps([f"A{i:02d}" for i in range(1, 11)])
    owasp_chart_data   = json.dumps([owasp_counts.get(f"A{i:02d}", 0) for i in range(1, 11)])

    # ── Findings rows ─────────────────────────────────────────────────────────
    finding_rows = ""
    for i, f in enumerate(findings, 1):
        sev   = f.get("severity", "INFO")
        color = SEVERITY_HEX.get(sev, "#6b7280")
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        evidence_esc = (str(f.get("evidence",""))[:400]
                        .replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))
        fix_esc = f.get("fix","")[:300].replace("&","&amp;").replace("<","&lt;")

        finding_rows += f"""
        <tr class="finding-row" data-sev="{sev}" data-mod="{f.get('module','?')}">
          <td style="color:{color};font-weight:700">{emoji} {sev}</td>
          <td style="color:#60a5fa">{f.get('owasp_id','—')}</td>
          <td>{f.get('module','?')}</td>
          <td style="font-weight:600">{f.get('title','')[:70]}</td>
          <td style="color:#9ca3af;font-size:11px">{(f.get('file') or f.get('url','—'))[-40:]}</td>
          <td>
            <button onclick="toggleDetail(this)" style="background:#1e3a5f;color:#60a5fa;
              border:none;border-radius:4px;padding:3px 10px;cursor:pointer;font-size:11px">
              Details
            </button>
            <div class="detail-panel" style="display:none;background:#060d1a;padding:12px;
              border-radius:6px;margin-top:8px;border:1px solid #1e3a5f">
              <p style="color:#d1d5db;margin-bottom:8px">{f.get('description','')}</p>
              {"<pre style='background:#0d1f35;padding:8px;border-radius:4px;font-size:11px;overflow-x:auto;color:#fbbf24;margin-bottom:8px'>" + evidence_esc + "</pre>" if evidence_esc else ""}
              <p style="color:#4ade80"><strong>Fix:</strong> {fix_esc}</p>
            </div>
          </td>
        </tr>"""

    # ── OWASP coverage rows ───────────────────────────────────────────────────
    owasp_rows = ""
    for i, (oid, name) in enumerate(zip(owasp_all, owasp_names), 1):
        count = owasp_counts.get(oid, 0)
        status_html = (
            f'<span style="color:#ef4444;font-weight:700">⚠ {count} finding(s)</span>'
            if count else '<span style="color:#4ade80">✓ Clear</span>'
        )
        owasp_rows += f"<tr><td style='color:#60a5fa'>{oid}</td><td>{name}</td><td>{status_html}</td></tr>"

    # ── Full HTML ─────────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WaspSting Report — {target}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#060d1a;color:#e5e7eb;font-family:'Courier New',monospace;padding:0}}
  .header{{background:linear-gradient(135deg,#0d1f35,#0a1628);padding:32px 40px;
           border-bottom:2px solid #1e3a5f}}
  .ascii{{color:#4ade80;font-size:11px;line-height:1.3;white-space:pre;margin-bottom:16px}}
  h1{{color:#4ade80;font-size:22px;margin-bottom:4px}}
  .meta{{color:#6b7280;font-size:12px;margin-bottom:8px}}
  .content{{padding:32px 40px}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:32px}}
  .stat{{background:#0d1f35;border:1px solid #1e3a5f;border-radius:8px;padding:16px;text-align:center}}
  .stat-n{{font-size:28px;font-weight:700;margin-bottom:4px}}
  .stat-l{{color:#9ca3af;font-size:12px}}
  .charts{{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:32px}}
  .chart-card{{background:#0d1f35;border:1px solid #1e3a5f;border-radius:8px;padding:20px}}
  .chart-card h3{{color:#60a5fa;margin-bottom:16px;font-size:14px}}
  .gauge-wrap{{position:relative;display:flex;flex-direction:column;align-items:center}}
  .gauge-score{{position:absolute;top:55%;font-size:36px;font-weight:700;color:{score_color}}}
  .gauge-label{{margin-top:8px;color:{score_color};font-weight:700;font-size:14px}}
  h2{{color:#60a5fa;font-size:16px;margin-bottom:16px;padding-bottom:8px;
      border-bottom:1px solid #1e3a5f}}
  .filters{{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}}
  .filters input,.filters select{{background:#0d1f35;border:1px solid #1e3a5f;color:#e5e7eb;
    padding:7px 12px;border-radius:4px;font-family:inherit;font-size:12px}}
  table{{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:32px}}
  th{{background:#0d1f35;color:#9ca3af;padding:10px 12px;text-align:left;
      border-bottom:1px solid #1e3a5f;font-size:11px;text-transform:uppercase}}
  td{{padding:10px 12px;border-bottom:1px solid #0d1f35;vertical-align:top}}
  tr:hover td{{background:#0d1f3520}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:3px;
          font-size:10px;font-weight:700;background:#1e3a5f;color:#60a5fa}}
  @media(max-width:768px){{.charts{{grid-template-columns:1fr}}.content{{padding:16px}}}}
</style>
</head>
<body>

<div class="header">
<div class="ascii"> ██╗    ██╗ █████╗ ███████╗██████╗ ███████╗████████╗██╗███╗   ██╗ ██████╗
 ██║    ██║██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝
 ██║ █╗ ██║███████║███████╗██████╔╝███████╗   ██║   ██║██╔██╗ ██║██║  ███╗
 ██║███╗██║██╔══██║╚════██║██╔═══╝ ╚════██║   ██║   ██║██║╚██╗██║██║   ██║
 ╚███╔███╔╝██║  ██║███████║██║     ███████║   ██║   ██║██║ ╚████║╚██████╔╝
  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝</div>
<h1>Security Assessment Report</h1>
<div class="meta">
  <strong style="color:#e5e7eb">Target:</strong> {target} &nbsp;|&nbsp;
  <strong style="color:#e5e7eb">Session:</strong> {session_id} &nbsp;|&nbsp;
  <strong style="color:#e5e7eb">Generated:</strong> {timestamp} &nbsp;|&nbsp;
  <strong style="color:#e5e7eb">Mode:</strong> {results.get('mode','?').upper()}
</div>
<div class="meta" style="margin-top:4px">
  <span style="color:#6b7280">Created by</span>
  <strong style="color:#4ade80">N00dleN00b</strong> &nbsp;|&nbsp;
  Modules: {', '.join(modules_hit) or '—'}
</div>
</div>

<div class="content">

<!-- Stats -->
<div class="stats">
  <div class="stat">
    <div class="stat-n" style="color:{score_color}">{score}</div>
    <div class="stat-l">Risk Score /100</div>
  </div>
  <div class="stat">
    <div class="stat-n">{len(findings)}</div>
    <div class="stat-l">Total Findings</div>
  </div>
  {"".join(f'<div class="stat"><div class="stat-n" style="color:{SEVERITY_HEX[s]}">{sev_counts.get(s,0)}</div><div class="stat-l">{s}</div></div>' for s in ["CRITICAL","HIGH","MEDIUM","LOW"] if sev_counts.get(s,0))}
  <div class="stat">
    <div class="stat-n">{len(set(f.get('owasp_id') for f in findings if f.get('owasp_id')))}</div>
    <div class="stat-l">OWASP Categories Hit</div>
  </div>
</div>

<!-- Charts -->
<div class="charts">
  <div class="chart-card">
    <h3>Risk Score</h3>
    <div class="gauge-wrap">
      <canvas id="gaugeChart" height="180"></canvas>
      <span class="gauge-score">{score}</span>
      <span class="gauge-label">{score_label}</span>
    </div>
  </div>
  <div class="chart-card">
    <h3>Severity Breakdown</h3>
    <canvas id="sevChart" height="180"></canvas>
  </div>
  <div class="chart-card" style="grid-column:1/-1">
    <h3>OWASP Top 10:2025 Hit Map</h3>
    <canvas id="owaspChart" height="100"></canvas>
  </div>
</div>

<!-- Findings Table -->
<h2>🔍 Findings ({len(findings)})</h2>
<div class="filters">
  <input type="text" id="searchInput" placeholder="Search findings..."
         oninput="filterTable()">
  <select id="sevFilter" onchange="filterTable()">
    <option value="">All Severities</option>
    <option>CRITICAL</option><option>HIGH</option>
    <option>MEDIUM</option><option>LOW</option><option>INFO</option>
  </select>
  <select id="modFilter" onchange="filterTable()">
    <option value="">All Modules</option>
    {"".join(f"<option>{m}</option>" for m in modules_hit)}
  </select>
</div>
<table id="findingsTable">
  <thead>
    <tr>
      <th>Severity</th><th>OWASP</th><th>Module</th>
      <th>Title</th><th>File / URL</th><th>Details</th>
    </tr>
  </thead>
  <tbody>{finding_rows}</tbody>
</table>

<!-- OWASP Coverage -->
<h2>OWASP Top 10:2025 Coverage</h2>
<table>
  <thead><tr><th>ID</th><th>Category</th><th>Status</th></tr></thead>
  <tbody>{owasp_rows}</tbody>
</table>

</div><!-- /content -->

<script>
// Gauge
new Chart(document.getElementById('gaugeChart'), {{
  type: 'doughnut',
  data: {{
    datasets: [{{
      data: [{score}, {100-score}],
      backgroundColor: ['{score_color}', '#1e3a5f'],
      borderWidth: 0, circumference: 180, rotation: 270
    }}]
  }},
  options: {{ cutout: '75%', plugins: {{ legend: {{ display: false }} }} }}
}});

// Severity doughnut
new Chart(document.getElementById('sevChart'), {{
  type: 'doughnut',
  data: {{
    labels: {sev_chart_labels},
    datasets: [{{ data: {sev_chart_data}, backgroundColor: {sev_chart_colors}, borderWidth: 2, borderColor: '#060d1a' }}]
  }},
  options: {{
    plugins: {{ legend: {{ labels: {{ color: '#9ca3af', font: {{ size: 11 }} }} }} }},
    cutout: '60%'
  }}
}});

// OWASP bar
new Chart(document.getElementById('owaspChart'), {{
  type: 'bar',
  data: {{
    labels: {owasp_chart_labels},
    datasets: [{{
      label: 'Findings',
      data: {owasp_chart_data},
      backgroundColor: '#3b82f6',
      borderRadius: 4
    }}]
  }},
  options: {{
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#9ca3af' }}, grid: {{ color: '#1e3a5f' }} }},
      y: {{ ticks: {{ color: '#9ca3af', stepSize: 1 }}, grid: {{ color: '#1e3a5f' }} }}
    }}
  }}
}});

// Filter
function filterTable() {{
  const q   = document.getElementById('searchInput').value.toLowerCase();
  const sev = document.getElementById('sevFilter').value;
  const mod = document.getElementById('modFilter').value;
  document.querySelectorAll('.finding-row').forEach(row => {{
    const matchQ   = !q   || row.innerText.toLowerCase().includes(q);
    const matchSev = !sev || row.dataset.sev === sev;
    const matchMod = !mod || row.dataset.mod === mod;
    row.style.display = (matchQ && matchSev && matchMod) ? '' : 'none';
  }});
}}

// Toggle detail panels
function toggleDetail(btn) {{
  const panel = btn.nextElementSibling;
  const open  = panel.style.display === 'none';
  panel.style.display = open ? 'block' : 'none';
  btn.textContent = open ? 'Hide' : 'Details';
}}
</script>
</body>
</html>"""


def save_html_report(results: dict, score: int, score_label: str, output_path: str):
    html = build_html_report(results, score, score_label)
    Path(output_path).write_text(html, encoding="utf-8")
    return output_path
