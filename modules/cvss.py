"""
modules/cvss.py — CVSS v3.1 Score Calculator

Pure Python implementation of CVSS v3.1 base score calculation.
No external dependencies.

Auto-scores findings from category/title mapping.
Supports per-finding manual override via --cvss-override flag or
interactive prompt when running in interactive mode.

Output: terminal summary table + markdown report only.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

import math
import re
from dataclasses import dataclass
from typing import Optional

# ── CVSS v3.1 metric weights ──────────────────────────────────────────────────

AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS = {
    "N": {"U": 0.85, "C": 0.85},
    "L": {"U": 0.62, "C": 0.68},
    "H": {"U": 0.27, "C": 0.50},
}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
C_WEIGHTS  = {"N": 0.00, "L": 0.22, "H": 0.56}
I_WEIGHTS  = {"N": 0.00, "L": 0.22, "H": 0.56}
A_WEIGHTS  = {"N": 0.00, "L": 0.22, "H": 0.56}

VALID = {
    "AV": set(AV_WEIGHTS),
    "AC": set(AC_WEIGHTS),
    "PR": {"N", "L", "H"},
    "UI": set(UI_WEIGHTS),
    "S":  {"U", "C"},
    "C":  set(C_WEIGHTS),
    "I":  set(I_WEIGHTS),
    "A":  set(A_WEIGHTS),
}


# ── Vector dataclass ──────────────────────────────────────────────────────────

@dataclass
class CVSSVector:
    """CVSS v3.1 base metric vector."""
    AV: str = "N"   # Attack Vector:          N A L P
    AC: str = "L"   # Attack Complexity:      L H
    PR: str = "N"   # Privileges Required:    N L H
    UI: str = "N"   # User Interaction:       N R
    S:  str = "U"   # Scope:                  U C
    C:  str = "N"   # Confidentiality Impact: N L H
    I:  str = "N"   # Integrity Impact:       N L H
    A:  str = "N"   # Availability Impact:    N L H

    def to_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}"
            f"/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"
        )

    @classmethod
    def from_string(cls, vector: str) -> "CVSSVector":
        """
        Parse a CVSS v3.1 vector string.
        Accepts: CVSS:3.1/AV:N/AC:L/...  or  AV:N/AC:L/...
        Raises ValueError on invalid metric values.
        """
        cleaned = vector.strip().replace("CVSS:3.1/", "")
        parts = {}
        for part in cleaned.split("/"):
            if ":" in part:
                k, v = part.split(":", 1)
                k, v = k.strip().upper(), v.strip().upper()
                if k in VALID and v not in VALID[k]:
                    raise ValueError(
                        f"Invalid value '{v}' for metric '{k}'. "
                        f"Valid: {sorted(VALID[k])}"
                    )
                parts[k] = v

        missing = [m for m in VALID if m not in parts]
        if missing:
            raise ValueError(f"Vector missing metrics: {missing}")

        return cls(
            AV=parts["AV"], AC=parts["AC"], PR=parts["PR"], UI=parts["UI"],
            S=parts["S"],   C=parts["C"],   I=parts["I"],   A=parts["A"],
        )


# ── Score calculation ─────────────────────────────────────────────────────────

def calculate_score(vector: CVSSVector) -> float:
    """
    Compute CVSS v3.1 base score.
    Returns float rounded UP to 1 decimal (0.0 – 10.0) per CVSS spec.
    """
    av = AV_WEIGHTS[vector.AV]
    ac = AC_WEIGHTS[vector.AC]
    pr = PR_WEIGHTS[vector.PR][vector.S]
    ui = UI_WEIGHTS[vector.UI]
    c  = C_WEIGHTS[vector.C]
    i  = I_WEIGHTS[vector.I]
    a  = A_WEIGHTS[vector.A]

    iss = 1 - (1 - c) * (1 - i) * (1 - a)

    if vector.S == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    raw = min(impact + exploitability, 10) if vector.S == "U" \
          else min(1.08 * (impact + exploitability), 10)

    return math.ceil(raw * 10) / 10


def score_to_severity(score: float) -> str:
    if score == 0.0:   return "NONE"
    elif score <= 3.9: return "LOW"
    elif score <= 6.9: return "MEDIUM"
    elif score <= 8.9: return "HIGH"
    else:              return "CRITICAL"


# ── Auto-vector map ───────────────────────────────────────────────────────────

_VECTOR_MAP: list[tuple[tuple, CVSSVector]] = [
    (("A05", "sqli"),       CVSSVector("N","L","N","N","C","H","H","H")),
    (("A05", "xss"),        CVSSVector("N","L","N","R","C","L","L","N")),
    (("A05", "ssti"),       CVSSVector("N","L","N","N","C","H","H","H")),
    (("A05", "command"),    CVSSVector("N","L","N","N","C","H","H","H")),
    (("A05", "path"),       CVSSVector("N","L","N","N","U","H","N","N")),
    (("A05", "ssrf"),       CVSSVector("N","L","N","N","C","H","L","N")),
    (("A05", "xxe"),        CVSSVector("N","L","N","N","U","H","L","N")),
    (("A05", "nosql"),      CVSSVector("N","L","N","N","U","H","H","N")),
    (("A05", "prompt"),     CVSSVector("N","L","N","N","U","L","L","N")),
    (("A05", "redirect"),   CVSSVector("N","L","N","R","U","L","L","N")),
    (("A02", "hsts"),       CVSSVector("N","H","N","R","U","L","L","N")),
    (("A02", "csp"),        CVSSVector("N","L","N","R","C","L","L","N")),
    (("A02", "misconfig"),  CVSSVector("N","L","N","N","U","L","N","N")),
    (("A04", "https"),      CVSSVector("N","H","N","N","U","H","L","N")),
    (("A01", "bola"),       CVSSVector("N","L","L","N","U","H","H","N")),
    (("A01", "idor"),       CVSSVector("N","L","L","N","U","H","H","N")),
    (("A01", "access"),     CVSSVector("N","L","L","N","U","H","H","N")),
    (("A07", "credential"), CVSSVector("N","L","N","N","U","H","H","N")),
    (("A07", "jwt"),        CVSSVector("N","L","N","N","U","H","H","N")),
    (("A06", "rate"),       CVSSVector("N","L","N","N","U","N","L","H")),
    (("A03", "supply"),     CVSSVector("N","H","N","N","U","H","H","H")),
    (("A08", "integrity"),  CVSSVector("N","L","N","N","U","H","H","H")),
    (("A09", "log"),        CVSSVector("N","L","N","N","U","L","N","N")),
]


def _auto_vector(owasp_id: str, category: str, title: str) -> CVSSVector:
    haystack = f"{category} {title}".lower()
    for (oid, keyword), vector in _VECTOR_MAP:
        if owasp_id.startswith(oid) and keyword in haystack:
            return vector
    for (oid, keyword), vector in _VECTOR_MAP:
        if keyword in haystack:
            return vector
    # Generic fallback
    return CVSSVector("N", "L", "N", "N", "U", "L", "L", "N")


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class CVSSResult:
    score:      float
    severity:   str
    vector:     CVSSVector
    overridden: bool = False

    @property
    def vector_string(self) -> str:
        return self.vector.to_string()

    def __str__(self) -> str:
        tag = " [MANUAL]" if self.overridden else ""
        return f"{self.score} ({self.severity}){tag} [{self.vector_string}]"


SEVERITY_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠",
    "MEDIUM":   "🟡", "LOW":  "🔵", "NONE": "⚪",
}


def cvss_badge(result: CVSSResult) -> str:
    emoji = SEVERITY_EMOJI.get(result.severity, "⚪")
    tag   = " ✎" if result.overridden else ""
    return f"{emoji} {result.score} {result.severity}{tag}"


# ── Core scoring ──────────────────────────────────────────────────────────────

def score_finding(
    finding: dict,
    override_vector: Optional[str] = None,
) -> CVSSResult:
    """
    Score a single finding dict.

    Args:
        finding:         WaspSting finding dict — mutated in-place.
        override_vector: Optional CVSS v3.1 vector string. If valid,
                         takes precedence over auto-mapping.

    Stamps finding with: cvss_score, cvss_severity, cvss_vector, cvss_overridden
    """
    owasp_id   = finding.get("owasp_id", "")
    category   = finding.get("category", "")
    title      = finding.get("title", "")
    overridden = False

    if override_vector:
        try:
            vector     = CVSSVector.from_string(override_vector)
            overridden = True
        except ValueError as e:
            print(f"[cvss] Warning: invalid override ({e}). Using auto.")
            vector = _auto_vector(owasp_id, category, title)
    else:
        vector = _auto_vector(owasp_id, category, title)

    score  = calculate_score(vector)
    sev    = score_to_severity(score)
    result = CVSSResult(score=score, severity=sev,
                        vector=vector, overridden=overridden)

    finding["cvss_score"]      = score
    finding["cvss_severity"]   = sev
    finding["cvss_vector"]     = result.vector_string
    finding["cvss_overridden"] = overridden

    return result


def score_all_findings(
    findings: list[dict],
    overrides: Optional[dict[int, str]] = None,
) -> list[dict]:
    """
    Score every finding. Optionally apply per-index vector overrides.

    Args:
        findings:  List of finding dicts (mutated in-place).
        overrides: {finding_index: vector_string} — from prompt_overrides()
                   or parsed from --cvss-override CLI arg.
    """
    overrides = overrides or {}
    for idx, f in enumerate(findings):
        score_finding(f, override_vector=overrides.get(idx))
    return findings


# ── Interactive override prompt ───────────────────────────────────────────────

def prompt_overrides(findings: list[dict], console) -> dict[int, str]:
    """
    Show auto-scored table, then let the user override any finding's
    vector interactively. Called when --cvss-override is passed.

    Returns {index: vector_string} to feed into score_all_findings().
    """
    from rich.table import Table
    from rich import box

    # Auto-score first so we can show current values
    score_all_findings(findings)

    table = Table(
        box=box.SIMPLE,
        title="Auto CVSS Scores — enter index to override",
        header_style="bold cyan",
    )
    table.add_column("#",      style="dim", width=4)
    table.add_column("Title",  width=44)
    table.add_column("Score",  justify="right", width=6)
    table.add_column("Sev",    width=10)
    table.add_column("Vector", style="dim")

    for idx, f in enumerate(findings):
        sev   = f["cvss_severity"]
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        table.add_row(
            str(idx),
            f.get("title", "")[:43],
            str(f["cvss_score"]),
            f"{emoji} {sev}",
            f["cvss_vector"],
        )
    console.print(table)

    console.print(
        "\n[dim]To override, type:  <index> <vector>  then Enter.[/dim]\n"
        "[dim]Example: 0 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H[/dim]\n"
        "[dim]Press Enter with no input to finish.[/dim]\n"
    )

    overrides: dict[int, str] = {}
    while True:
        try:
            raw = input("Override> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not raw:
            break
        parts = raw.split(None, 1)
        if len(parts) != 2:
            console.print("[red]Format: <index> <CVSS vector>[/red]")
            continue
        try:
            idx = int(parts[0])
            if not (0 <= idx < len(findings)):
                console.print(f"[red]Index out of range (0–{len(findings)-1})[/red]")
                continue
            CVSSVector.from_string(parts[1])   # validate before accepting
            overrides[idx] = parts[1]
            console.print(f"[green]✓ Override queued for finding {idx}[/green]")
        except ValueError as e:
            console.print(f"[red]Invalid vector: {e}[/red]")

    # Re-score with overrides applied
    score_all_findings(findings, overrides)
    return overrides


# ── Output: terminal ──────────────────────────────────────────────────────────

def print_cvss_summary(findings: list[dict], console) -> None:
    """
    Print a rich CVSS summary table to the terminal after scanning.
    Only shows findings that have been scored.
    """
    from rich.table import Table
    from rich import box

    scored = [f for f in findings if "cvss_score" in f]
    if not scored:
        return

    COLOR = {
        "CRITICAL": "bold red",   "HIGH":   "bold orange1",
        "MEDIUM":   "bold yellow","LOW":    "bold blue",
        "NONE":     "dim",
    }

    table = Table(
        box=box.SIMPLE,
        title="CVSS v3.1 Scores",
        header_style="bold cyan",
    )
    table.add_column("#",        style="dim", width=4)
    table.add_column("Title",    width=42)
    table.add_column("Score",    justify="right", width=6)
    table.add_column("Severity", width=12)
    table.add_column("Vector",   style="dim")

    for idx, f in enumerate(scored, 1):
        score  = f["cvss_score"]
        sev    = f["cvss_severity"]
        vector = f["cvss_vector"]
        title  = f.get("title", "")[:41]
        emoji  = SEVERITY_EMOJI.get(sev, "⚪")
        manual = " [dim]✎[/dim]" if f.get("cvss_overridden") else ""
        col    = COLOR.get(sev, "white")

        table.add_row(
            str(idx), title,
            f"[bold]{score}[/bold]{manual}",
            f"[{col}]{emoji} {sev}[/{col}]",
            vector,
        )

    console.print(table)


# ── Output: markdown ──────────────────────────────────────────────────────────

def finding_cvss_markdown(finding: dict) -> str:
    """
    Single-finding CVSS block for insertion inside each finding section.

    **CVSS v3.1:** 🟠 8.1 HIGH
    **Vector:** `CVSS:3.1/AV:N/...`
    """
    score  = finding.get("cvss_score")
    sev    = finding.get("cvss_severity", "")
    vector = finding.get("cvss_vector", "")
    manual = finding.get("cvss_overridden", False)

    if score is None:
        return ""

    emoji = SEVERITY_EMOJI.get(sev, "⚪")
    label = f"{emoji} {score} {sev}"
    if manual:
        label += " _(manual override)_"

    return (
        f"**CVSS v3.1:** {label}  \n"
        f"**Vector:** `{vector}`\n"
    )


def summary_cvss_markdown(findings: list[dict]) -> str:
    """
    Full CVSS summary table for the top of the markdown report.

    ## CVSS v3.1 Summary
    | # | Title | Score | Severity | Vector |
    """
    scored = [f for f in findings if "cvss_score" in f]
    if not scored:
        return ""

    lines = [
        "## CVSS v3.1 Summary\n",
        "| # | Title | Score | Severity | Vector |",
        "|---|-------|------:|----------|--------|",
    ]
    for idx, f in enumerate(scored, 1):
        score  = f["cvss_score"]
        sev    = f["cvss_severity"]
        vector = f["cvss_vector"]
        title  = f.get("title", "")[:50]
        emoji  = SEVERITY_EMOJI.get(sev, "⚪")
        manual = " ✎" if f.get("cvss_overridden") else ""
        lines.append(
            f"| {idx} | {title} | {score}{manual} | {emoji} {sev} | `{vector}` |"
        )

    lines.append("")
    return "\n".join(lines)


# ── CLI self-test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_findings = [
        {"owasp_id": "A05", "category": "Injection (SQLI)",         "title": "SQLi in login param",        "severity": "HIGH"},
        {"owasp_id": "A05", "category": "Injection (XSS)",          "title": "XSS reflected search param", "severity": "MEDIUM"},
        {"owasp_id": "A02", "category": "Security Misconfiguration", "title": "Missing HSTS",               "severity": "HIGH"},
        {"owasp_id": "A04", "category": "Cryptographic Failures",   "title": "No HTTPS",                   "severity": "HIGH"},
        {"owasp_id": "A07", "category": "Authentication Failures",   "title": "JWT alg:none bypass",        "severity": "HIGH"},
        {"owasp_id": "A01", "category": "Broken Access Control",    "title": "BOLA on /api/user/1",        "severity": "HIGH"},
    ]

    # Override finding 0 with a manually specified critical vector
    overrides = {0: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}
    score_all_findings(test_findings, overrides)

    print(f"\n{'#':<4} {'Title':<42} {'Score':>6}  {'Severity':<10}  M  Vector")
    print("─" * 115)
    for i, f in enumerate(test_findings):
        manual = "✎" if f["cvss_overridden"] else " "
        print(
            f"{i:<4} {f['title']:<42} {f['cvss_score']:>6.1f}  "
            f"{f['cvss_severity']:<10}  {manual}  {f['cvss_vector']}"
        )

    print("\n── Markdown summary ──\n")
    print(summary_cvss_markdown(test_findings))