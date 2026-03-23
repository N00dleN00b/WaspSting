"""
banner.py — WaspSting animated terminal banner
Hacker aesthetic: green on black, typewriter boot sequence
"""

import sys
import time
import os
import random

VERSION = "1.5"

# ── ANSI codes — all defined cleanly, no raw escape leakage ──────────────────
GREEN      = "\033[92m"
BRIGHT_GRN = "\033[1;92m"
DIM_GREEN  = "\033[2;32m"
YELLOW     = "\033[93m"
RED        = "\033[91m"
DIM        = "\033[2m"
BOLD       = "\033[1m"
RESET      = "\033[0m"


def _write(text, delay=0.0, end="\n"):
    sys.stdout.write(text + end)
    sys.stdout.flush()
    if delay:
        time.sleep(delay)


def _typewrite(text, delay=0.03, newline=True):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay + random.uniform(0, delay * 0.4))
    if newline:
        sys.stdout.write("\n")
        sys.stdout.flush()


def _glitch_line(text, cycles=3):
    """Briefly glitch a line with random chars before resolving."""
    glitch_chars = "!@#$%^&*<>?/|\\~`"
    # Strip ANSI for glitch so we don't corrupt escape sequences
    plain = ""
    in_esc = False
    for ch in text:
        if ch == "\033":
            in_esc = True
        elif in_esc and ch == "m":
            in_esc = False
        elif not in_esc:
            plain += ch

    for _ in range(cycles):
        glitched = "".join(
            random.choice(glitch_chars) if random.random() < 0.25 else c
            for c in plain
        )
        sys.stdout.write(f"\r{BRIGHT_GRN}{glitched}{RESET}")
        sys.stdout.flush()
        time.sleep(0.05)
    sys.stdout.write(f"\r{text}\n")
    sys.stdout.flush()


# ── Logo — 6 lines of text ────────────────────────────────────────────────────
LOGO_LINES = [
    r" ██╗    ██╗ █████╗ ███████╗██████╗ ███████╗████████╗██╗███╗   ██╗ ██████╗",
    r" ██║    ██║██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝",
    r" ██║ █╗ ██║███████║███████╗██████╔╝███████╗   ██║   ██║██╔██╗ ██║██║  ███╗",
    r" ██║███╗██║██╔══██║╚════██║██╔═══╝ ╚════██║   ██║   ██║██║╚██╗██║██║   ██║",
    r" ╚███╔███╔╝██║  ██║███████║██║     ███████║   ██║   ██║██║ ╚████║╚██████╔╝",
    r"  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝",
]

# ── Wasp ASCII art — 6 lines to sit beside the logo ──────────────────────────
WASP_LINES = [
    r"    ( \_/ )",
    r"   =(0 w 0)=",
    r"  /|  | |  |\  ",
    r" / | /|=|\ | \ ",
    r"   |/ | | \|   ",
    r"   `--' '--'   ",
]


def _print_logo_with_wasp(fast: bool):
    """Print the text logo with wasp art aligned to the right."""
    for i, logo_line in enumerate(LOGO_LINES):
        wasp_part = WASP_LINES[i] if i < len(WASP_LINES) else ""
        # Pad logo line to fixed width so wasp stays aligned
        padded_logo = f"{logo_line:<74}"
        full_line = f"{BRIGHT_GRN}{padded_logo}{RESET}  {YELLOW}{wasp_part}{RESET}"
        if fast:
            print(full_line)
        else:
            if i == 0:
                _glitch_line(full_line)
            else:
                _write(full_line, delay=0.04)


def print_banner(fast: bool = False):
    """Print the full WaspSting banner."""
    if not fast:
        os.system("clear" if os.name != "nt" else "cls")

    border_text = f"[ WaspSting v{VERSION} - PENETRATION TESTING SUITE ]"
    border_line = "═" * len(border_text)

    # ── Top border ────────────────────────────────────────────────────────────
    if fast:
        print(f"{BRIGHT_GRN}{border_line}{RESET}")
        print(f"{BRIGHT_GRN}{border_text}{RESET}")
        print(f"{BRIGHT_GRN}{border_line}{RESET}")
    else:
        _write(f"{BRIGHT_GRN}{border_line}{RESET}", delay=0)
        time.sleep(0.1)
        _typewrite(f"{BRIGHT_GRN}{border_text}{RESET}", delay=0.025)
        _write(f"{BRIGHT_GRN}{border_line}{RESET}", delay=0)
        time.sleep(0.2)

    # ── Logo + wasp ───────────────────────────────────────────────────────────
    _print_logo_with_wasp(fast)

    if not fast:
        time.sleep(0.1)

    # ── Tagline ───────────────────────────────────────────────────────────────
    tagline = f"  🐝  v{VERSION} | OWASP Top 10:2025 | Bug Bounty | SAST | BOLA | CVE  🐝"
    if fast:
        print(f"{YELLOW}{tagline}{RESET}")
    else:
        _typewrite(f"{YELLOW}{tagline}{RESET}", delay=0.018)

    # ── Boot sequence ─────────────────────────────────────────────────────────
    if not fast:
        time.sleep(0.15)
        boot_lines = [
            (f"{DIM_GREEN}[{RESET}{GREEN}+{RESET}{DIM_GREEN}]{RESET} Initializing OWASP knowledge base...",        0.08),
            (f"{DIM_GREEN}[{RESET}{GREEN}+{RESET}{DIM_GREEN}]{RESET} Loading CVE correlation engine...",            0.08),
            (f"{DIM_GREEN}[{RESET}{GREEN}+{RESET}{DIM_GREEN}]{RESET} Mounting pentest methodology modules...",      0.08),
            (f"{DIM_GREEN}[{RESET}{GREEN}+{RESET}{DIM_GREEN}]{RESET} Bug bounty scope analyzer: {GREEN}READY{RESET}", 0.08),
            (f"{DIM_GREEN}[{RESET}{YELLOW}*{RESET}{DIM_GREEN}]{RESET} Checking Ollama AI engine...",                0.1),
        ]
        for line, d in boot_lines:
            _write(line, delay=d)

    # ── Warning ───────────────────────────────────────────────────────────────
    warn = "  ⚠   FOR AUTHORIZED USE ONLY — OWN SYSTEMS / BUG BOUNTY / CTF   ⚠"
    if fast:
        print(f"{BOLD}{RED}{warn}{RESET}")
    else:
        time.sleep(0.1)
        _write(f"{BRIGHT_GRN}{border_line}{RESET}", delay=0)
        _typewrite(f"{BOLD}{RED}{warn}{RESET}", delay=0.015)
        _write(f"{BRIGHT_GRN}{border_line}{RESET}", delay=0)

    # ── Credits ───────────────────────────────────────────────────────────────
    credit = "  Created by N00dleN00b  |  github.com/N00dleN00b/waspsting"
    if fast:
        print(f"{DIM_GREEN}{credit}{RESET}")
    else:
        _write(f"{DIM_GREEN}{credit}{RESET}", delay=0)
        time.sleep(0.05)

    print()


def print_scan_start(target: str, mode: str):
    """Print animated scan-start sequence."""
    cwd = os.path.basename(os.getcwd())

    lines = [
        (f"{GREEN}user@sting{RESET}:{YELLOW}~/{cwd}{RESET}$ waspsting --target {target} --mode {mode}", 0.03),
        (f"{GREEN}[+]{RESET} Scanning Target: {YELLOW}{target}{RESET}...",   0.06),
        (f"{GREEN}[+]{RESET} Resolving host...",                              0.08),
        (f"{GREEN}[+]{RESET} Identifying open ports...",                      0.10),
        (f"{GREEN}[+]{RESET} Loading module: {YELLOW}{mode.upper()}{RESET}", 0.08),
        (f"{GREEN}[*]{RESET} {DIM}WaspSting engine: {RESET}{GREEN}[RUNNING]{RESET}", 0.06),
    ]

    for line, d in lines:
        _typewrite(line, delay=0.012)
        time.sleep(d)

    print()


def print_finding_live(severity: str, title: str, source: str = ""):
    """Print a finding live as it's discovered."""
    sev_colors = {
        "CRITICAL": "\033[1;91m",
        "HIGH":     "\033[91m",
        "MEDIUM":   "\033[93m",
        "LOW":      "\033[96m",
        "INFO":     "\033[2m",
    }
    sev_tags = {
        "CRITICAL": "!", "HIGH": "!",
        "MEDIUM": "*",  "LOW":  "+", "INFO": "-",
    }
    color = sev_colors.get(severity, RESET)
    tag   = sev_tags.get(severity, "*")
    src   = f" {DIM}[{source}]{RESET}" if source else ""
    print(f"{color}[{tag}]{RESET} {title}{src}")


if __name__ == "__main__":
    print_banner(fast="--fast" in sys.argv)
    print_scan_start("http://localhost:3000", "recon")