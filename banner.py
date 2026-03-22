"""
banner.py — WaspSting animated terminal banner
Hacker aesthetic: green on black, typewriter boot sequence, scan lines
"""

import sys
import time
import os
import random


def _write(text, delay=0.0, end="\n", flush=True):
    sys.stdout.write(text + end)
    if flush:
        sys.stdout.flush()
    if delay:
        time.sleep(delay)


def _typewrite(text, delay=0.03, style_prefix="", newline=True):
    """Print text character by character."""
    sys.stdout.write(style_prefix)
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay + random.uniform(0, delay * 0.4))
    if newline:
        sys.stdout.write("\n")
        sys.stdout.flush()


def _glitch_line(text, cycles=3):
    """Briefly glitch a line before resolving."""
    glitch_chars = "!@#$%^&*<>?/|\\~`±§"
    for _ in range(cycles):
        glitched = "".join(
            random.choice(glitch_chars) if random.random() < 0.25 else c
            for c in text
        )
        sys.stdout.write(f"\r{glitched}")
        sys.stdout.flush()
        time.sleep(0.05)
    sys.stdout.write(f"\r{text}\n")
    sys.stdout.flush()


# ANSI color codes (no Rich dependency for banner — raw ANSI for speed)
GREEN       = "\033[92m"
BRIGHT_GRN  = "\033[1;92m"
DIM_GREEN   = "\033[2;32m"
YELLOW      = "\033[93m"
BRIGHT_YEL  = "\033[1;93m"
CYAN        = "\033[96m"
RED         = "\033[91m"
DIM         = "\033[2m"
BOLD        = "\033[1m"
RESET       = "\033[0m"
BLINK       = "\033[5m"
BLACK_BG    = "\033[40m"

WASP_ASCII = r"""
 ██╗    ██╗ █████╗ ███████╗██████╗ ███████╗████████╗██╗███╗   ██╗ ██████╗
 ██║    ██║██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝
 ██║ █╗ ██║███████║███████╗██████╔╝███████╗   ██║   ██║██╔██╗ ██║██║  ███╗
 ██║███╗██║██╔══██║╚════██║██╔═══╝ ╚════██║   ██║   ██║██║╚██╗██║██║   ██║
 ╚███╔███╔╝██║  ██║███████║██║     ███████║   ██║   ██║██║ ╚████║╚██████╔╝
  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝ """

WASP_ICON = r"""
        /\    /\
       (  \  /  )
        \  \/  /
    ~~~~[======]~~~~
        |  ||  |
        |  ||  |
        \  ||  /
         '----'  """


def print_banner(fast=False):
    """Print the full animated WaspSting banner."""
    delay = 0.0 if fast else 1.0

    # Clear and set up
    if not fast:
        os.system("clear" if os.name != "nt" else "cls")

    # Top border — typewrite
    border = "[ WaspSting v1.4 - PENETRATION TESTING SUITE ]"
    border_line = "═" * len(border)

    if fast:
        print(f"{BRIGHT_GRN}{border_line}{RESET}")
        print(f"{BRIGHT_GRN}{border}{RESET}")
        print(f"{BRIGHT_GRN}{border_line}{RESET}")
    else:
        _write(f"{BRIGHT_GRN}{border_line}{RESET}", delay=0)
        time.sleep(0.1)
        _typewrite(f"{BRIGHT_GRN}{border}{RESET}", delay=0.025, newline=True)
        _write(f"{BRIGHT_GRN}{border_line}{RESET}", delay=0)
        time.sleep(0.2)

    # Main ASCII logo — print line by line with flicker
    logo_lines = WASP_ASCII.strip("\n").split("\n")
    for i, line in enumerate(logo_lines):
        if fast:
            print(f"{BRIGHT_GRN}{line}{RESET}")
        else:
            if i == 0:
                _glitch_line(f"{BRIGHT_GRN}{line}{RESET}")
            else:
                _write(f"{BRIGHT_GRN}{line}{RESET}", delay=0.04)

    # Wasp icon on the right side (simulate)
    if not fast:
        time.sleep(0.1)

    # Tagline
    tagline = "  🐝  v1.4 | OWASP Top 10:2025 | Bug Bounty | SAST | BOLA | CVE  🐝"
    if fast:
        print(f"{YELLOW}{tagline}{RESET}")
    else:
        _typewrite(f"{YELLOW}{tagline}{RESET}", delay=0.018, newline=True)

    # Boot sequence
    if not fast:
        time.sleep(0.15)
        boot_lines = [
            (f"{DIM_GREEN}[{RESET}{GREEN}+{RESET}{DIM_GREEN}]{RESET} Initializing OWASP knowledge base...",       0.08),
            (f"{DIM_GREEN}[{RESET}{GREEN}+{RESET}{DIM_GREEN}]{RESET} Loading CVE correlation engine...",           0.08),
            (f"{DIM_GREEN}[{RESET}{GREEN}+{RESET}{DIM_GREEN}]{RESET} Mounting pentest methodology modules...",     0.08),
            (f"{DIM_GREEN}[{RESET}{GREEN}+{RESET}{DIM_GREEN}]{RESET} Bug bounty scope analyzer: {GREEN}READY{RESET}",0.08),
            (f"{DIM_GREEN}[{RESET}{YELLOW}*{RESET}{DIM_GREEN}]{RESET} Checking Ollama AI engine...",               0.1),
        ]
        for line, d in boot_lines:
            _write(line, delay=d)

    # Warning line
    warn = "  ⚠   FOR AUTHORIZED USE ONLY — OWN SYSTEMS / BUG BOUNTY / CTF   ⚠"
    if fast:
        print(f"{BOLD}{RED}{warn}{RESET}")
    else:
        time.sleep(0.1)
        _write(f"{BRIGHT_GRN}{'═' * len(border)}{RESET}", delay=0)
        _typewrite(f"{BOLD}{RED}{warn}{RESET}", delay=0.015, newline=True)
        _write(f"{BRIGHT_GRN}{'═' * len(border)}{RESET}", delay=0)

    # Credits
    credit = "  Created by N00dleN00b  |  github.com/N00dleN00b/waspsting"
    if fast:
        print(f"{DIM_GREEN}{credit}{RESET}")
    else:
        _write(f"{DIM_GREEN}{credit}{RESET}", delay=0)
        time.sleep(0.05)

    print()


def print_scan_start(target: str, mode: str):
    """Print a scan-start sequence like the reference image."""
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RED = "\033[91m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    user = os.environ.get("USER", "user")
    cwd  = os.path.basename(os.getcwd())

    lines = [
        (f"{GREEN}user@sting{RESET}:{CYAN}~/{cwd}{RESET}$ waspsting --target {target} --mode {mode}", 0.03),
        (f"{GREEN}[+]{RESET} Scanning Target: {CYAN}{target}{RESET}...",                               0.06),
        (f"{GREEN}[+]{RESET} Resolving host...",                                                        0.08),
        (f"{GREEN}[+]{RESET} Identifying open ports...",                                                0.1),
        (f"{GREEN}[+]{RESET} Loading module: {YELLOW}{mode.upper()}{RESET}",                           0.08),
        (f"{GREEN}[*]{RESET} {DIM}WaspSting engine: {RESET}{GREEN}[RUNNING]{RESET}",                   0.06),
    ]

    for line, d in lines:
        _typewrite(line, delay=0.012, newline=True)
        time.sleep(d)

    print()


def print_finding_live(severity: str, title: str, source: str = ""):
    """Print a finding as it's discovered — live feed style."""
    BRIGHT_GRN = "\033[1;92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    DIM = "\033[2m"

    sev_colors = {
        "CRITICAL": f"\033[1;91m",
        "HIGH":     f"\033[91m",
        "MEDIUM":   f"\033[93m",
        "LOW":      f"\033[96m",
        "INFO":     f"\033[2m",
    }
    sev_tags = {
        "CRITICAL": "!",
        "HIGH":     "!",
        "MEDIUM":   "*",
        "LOW":      "+",
        "INFO":     "-",
    }

    color = sev_colors.get(severity, RESET)
    tag = sev_tags.get(severity, "*")
    src = f" {DIM}[{source}]{RESET}" if source else ""

    print(f"{color}[{tag}]{RESET} {title}{src}")


if __name__ == "__main__":
    # Test banner standalone
    print_banner(fast="--fast" in sys.argv)
    print_scan_start("192.168.1.100", "full")
