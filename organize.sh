#!/usr/bin/env bash
# ── WaspSting directory organizer ─────────────────────────────────────────────
# Run once from the WaspSting/ root to put every file in the right place.
# Safe to re-run — skips moves if source doesn't exist.
#
# Usage:
#   chmod +x organize.sh
#   ./organize.sh
# ─────────────────────────────────────────────────────────────────────────────

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo ""
echo "🐝  WaspSting directory organizer"
echo "    Working in: $ROOT"
echo ""

move_if_exists() {
    local src="$1"
    local dst="$2"
    if [ -f "$src" ]; then
        mkdir -p "$(dirname "$dst")"
        mv "$src" "$dst"
        echo "  ✓ moved  $src → $dst"
    else
        echo "  —        $src (not found, skipping)"
    fi
}

# ── 1. Docker files belong in repo root, not modules/ ─────────────────────────
echo "[ Docker files ]"
move_if_exists "modules/Dockerfile"        "Dockerfile"
move_if_exists "modules/docker-compose.yml" "docker-compose.yml"
move_if_exists "modules/dockercompose.yml"  "docker-compose.yml"
move_if_exists "modules/docker.yml"         ".github/workflows/docker.yml"

# ── 2. GitHub Actions ─────────────────────────────────────────────────────────
echo ""
echo "[ GitHub Actions ]"
mkdir -p .github/workflows
move_if_exists "docker.yml"  ".github/workflows/docker.yml"

# ── 3. New modules — ensure they're in modules/ ───────────────────────────────
echo ""
echo "[ Module files ]"
move_if_exists "cvss.py"           "modules/cvss.py"
move_if_exists "CVSS.py"           "modules/cvss.py"
move_if_exists "bugcrowd.py"       "modules/bugcrowd.py"
move_if_exists "nuclei_runner.py"  "modules/nuclei_runner.py"
move_if_exists "custom_rules.py"   "modules/custom_rules.py"

# ── 4. Rules directory ────────────────────────────────────────────────────────
echo ""
echo "[ Rules directory ]"
mkdir -p rules
move_if_exists "example_rules.yaml" "rules/example_rules.yaml"

# ── 5. clear_session.py belongs in repo root ──────────────────────────────────
echo ""
echo "[ Utility scripts ]"
move_if_exists "modules/clear_session.py" "clear_session.py"

# ── 6. Misplaced docs files ───────────────────────────────────────────────────
echo ""
echo "[ Docs cleanup ]"
move_if_exists "docs/HTMLreport.py"    "modules/html_report.py"
move_if_exists "evidence/screenshots.py" "modules/screenshot.py"

# ── 7. Output directory ───────────────────────────────────────────────────────
echo ""
echo "[ Output directory ]"
mkdir -p output
echo "  ✓ output/ exists"

# ── 8. Final structure check ──────────────────────────────────────────────────
echo ""
echo "[ Final structure ]"
echo ""
echo "  WaspSting/"
echo "  ├── waspsting.py"
echo "  ├── banner.py"
echo "  ├── knowledge_base.py"
echo "  ├── notify.py"
echo "  ├── clear_session.py          ← new"
echo "  ├── requirements.txt"
echo "  ├── Dockerfile                ← new"
echo "  ├── docker-compose.yml        ← new"
echo "  ├── .github/workflows/"
echo "  │   └── docker.yml            ← new"
echo "  ├── modules/"
echo "  │   ├── cvss.py               ← new"
echo "  │   ├── bugcrowd.py           ← new"
echo "  │   ├── nuclei_runner.py      ← new"
echo "  │   ├── custom_rules.py       ← new"
echo "  │   ├── recon.py"
echo "  │   ├── fuzzer.py"
echo "  │   ├── auth_audit.py"
echo "  │   ├── bola.py"
echo "  │   ├── api_checks.py"
echo "  │   ├── sast.py"
echo "  │   ├── subdomain.py"
echo "  │   ├── screenshot.py"
echo "  │   ├── html_report.py"
echo "  │   ├── reporter.py"
echo "  │   ├── notify.py"
echo "  │   ├── bugbounty.py"
echo "  │   └── burp_export.py"
echo "  ├── rules/"
echo "  │   └── example_rules.yaml    ← new"
echo "  ├── wordlists/"
echo "  ├── docs/"
echo "  └── output/"
echo ""

# ── 9. Verify critical files exist ────────────────────────────────────────────
echo "[ Verification ]"
CRITICAL=(
    "waspsting.py"
    "modules/cvss.py"
    "modules/custom_rules.py"
    "modules/bugcrowd.py"
    "modules/nuclei_runner.py"
    "modules/fuzzer.py"
    "modules/recon.py"
    "clear_session.py"
    "rules/example_rules.yaml"
    "Dockerfile"
    "docker-compose.yml"
)

ALL_OK=true
for f in "${CRITICAL[@]}"; do
    if [ -f "$f" ]; then
        echo "  ✓ $f"
    else
        echo "  ✗ MISSING: $f"
        ALL_OK=false
    fi
done

echo ""
if [ "$ALL_OK" = true ]; then
    echo "🐝  All files in place. WaspSting is ready."
else
    echo "⚠   Some files are missing — check the list above."
fi
echo ""