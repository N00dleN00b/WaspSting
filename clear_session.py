"""
clear_session.py — WaspSting Session Cleaner

Safely clears output/ so you can start a fresh engagement.
Warns the user to save reports first, shows what will be deleted,
and requires explicit confirmation before wiping anything.

Usage:
    python3 clear_session.py
    python3 clear_session.py --output ./output
    python3 clear_session.py --force   (skip prompts — CI/CD use only)
"""

import argparse
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    RICH = True
except ImportError:
    RICH = False


def sizeof_fmt(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"


def scan_output_dir(output_dir: Path) -> list[dict]:
    """Return a list of files in output_dir with metadata."""
    files = []
    if not output_dir.exists():
        return files
    for f in sorted(output_dir.iterdir()):
        if f.is_file():
            stat = f.stat()
            files.append({
                "path":     f,
                "name":     f.name,
                "size":     stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime(
                    "%Y-%m-%d %H:%M"
                ),
                "ext":      f.suffix.lower(),
            })
    return files


def run_clear(output_dir: Path, force: bool = False, console=None) -> None:
    if console is None:
        class _FallbackConsole:
            def print(self, *a, **kw): print(*a)
        console = _FallbackConsole()

    files = scan_output_dir(output_dir)

    # ── Nothing to clear ──────────────────────────────────────────────────────
    if not files:
        console.print(
            f"\n[dim]Output directory is already empty: {output_dir}[/dim]\n"
        )
        return

    # ── Show what exists ──────────────────────────────────────────────────────
    total_size = sum(f["size"] for f in files)

    if RICH:
        table = Table(
            box=box.SIMPLE,
            title=f"Output directory: {output_dir}  ({len(files)} files, {sizeof_fmt(total_size)})",
            header_style="bold cyan",
        )
        table.add_column("File",      width=48)
        table.add_column("Size",      justify="right", width=10)
        table.add_column("Modified",  width=17)
        table.add_column("Type",      style="dim", width=8)

        TYPE_COLOR = {
            ".md":   "green", ".html": "cyan",
            ".json": "yellow", ".jsonl": "dim yellow",
        }

        for f in files:
            col   = TYPE_COLOR.get(f["ext"], "white")
            ftype = f["ext"].lstrip(".").upper() or "—"
            table.add_row(
                f"[{col}]{f['name']}[/{col}]",
                sizeof_fmt(f["size"]),
                f["modified"],
                ftype,
            )
        console.print(table)
    else:
        print(f"\nFiles in {output_dir}:")
        for f in files:
            print(f"  {f['name']:<50} {sizeof_fmt(f['size']):>10}  {f['modified']}")

    # ── Safety warning ────────────────────────────────────────────────────────
    report_files = [f for f in files if f["ext"] in (".md", ".html", ".json")]

    if RICH:
        console.print(Panel(
            "[bold yellow]⚠  SAVE YOUR REPORTS BEFORE CLEARING[/bold yellow]\n\n"
            f"  Found [bold]{len(report_files)}[/bold] report file(s) that will be "
            f"permanently deleted.\n\n"
            "  Recommended: copy important files to your Desktop or\n"
            "  a dedicated engagement folder before continuing.\n\n"
            "[dim]  .md  → open in any Markdown viewer or VS Code\n"
            "  .html → open in browser for the full executive report\n"
            "  .json → machine-readable, useful for re-running --mode report[/dim]",
            border_style="yellow",
            title="WaspSting — Clear Session",
        ))
    else:
        print(
            "\n⚠  SAVE YOUR REPORTS BEFORE CLEARING\n"
            f"   {len(report_files)} report file(s) will be permanently deleted.\n"
            "   Copy important files to your Desktop before continuing.\n"
        )

    if force:
        console.print("[dim]--force flag set — skipping confirmation.[/dim]")
    else:
        # ── First confirmation ────────────────────────────────────────────────
        try:
            ans = input(
                "\n  Have you saved all reports you need? (yes/no): "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Cancelled.[/yellow]\n")
            return

        if ans not in ("yes", "y"):
            console.print(
                "\n[green]Good call. Go save your reports first.[/green]\n"
                "[dim]Run again when you're ready.[/dim]\n"
            )
            return

        # ── Second confirmation ───────────────────────────────────────────────
        if RICH:
            console.print(
                f"\n[bold red]This will permanently delete all "
                f"{len(files)} files in {output_dir}.[/bold red]"
            )
        try:
            ans2 = input(
                f"  Type DELETE to confirm: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Cancelled.[/yellow]\n")
            return

        if ans2 != "DELETE":
            console.print("\n[yellow]Cancelled — nothing was deleted.[/yellow]\n")
            return

    # ── Clear ─────────────────────────────────────────────────────────────────
    deleted   = 0
    errors    = 0
    dedup_db  = output_dir / ".waspsting_history.json"

    for f in files:
        try:
            f["path"].unlink()
            deleted += 1
        except OSError as e:
            console.print(f"[red]Could not delete {f['name']}: {e}[/red]")
            errors += 1

    # Reset dedup history
    if dedup_db.exists():
        try:
            dedup_db.write_text("{}")
            console.print("[dim]✓ Dedup history reset[/dim]")
        except OSError:
            pass

    # ── Result ────────────────────────────────────────────────────────────────
    if RICH:
        console.print(
            f"\n[bold green]✓ Session cleared[/bold green] — "
            f"{deleted} file(s) deleted"
            + (f", {errors} error(s)" if errors else "")
            + f"  ({sizeof_fmt(total_size)} freed)\n"
        )
        console.print(
            "[dim]Output directory is clean. "
            "Start your next engagement with:[/dim]\n"
            "  [bold]python3 waspsting.py --target https://target.com "
            "--mode full --confirm[/bold]\n"
        )
    else:
        print(
            f"\n✓ Session cleared — {deleted} file(s) deleted "
            f"({sizeof_fmt(total_size)} freed)\n"
        )


def main():
    parser = argparse.ArgumentParser(
        prog="clear_session",
        description="WaspSting — Clear output directory for a fresh engagement",
    )
    parser.add_argument(
        "--output", "-o", default="./output",
        help="Output directory to clear (default: ./output)",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Skip confirmation prompts (CI/CD use only)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output)

    if RICH:
        from rich.console import Console
        console = Console()
    else:
        console = None

    run_clear(output_dir, force=args.force, console=console)


if __name__ == "__main__":
    main()