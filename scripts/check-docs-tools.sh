#!/bin/bash
# Tool reference freshness check
#
# docs/tools.md carries one table per expose group between generated markers.
# A tool added to tool_metadata.rs without a group assignment would otherwise
# be unreachable under --expose with nothing to say so; this fails the build
# instead.
#
# Usage:
#   scripts/check-docs-tools.sh          # verify docs/tools.md is current
#   scripts/check-docs-tools.sh --write  # regenerate the block in place

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DOC="docs/tools.md"
BEGIN='<!-- BEGIN GENERATED: narsil-xref tools list --format markdown -->'
END='<!-- END GENERATED -->'

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

WRITE=0
[ "${1:-}" = "--write" ] && WRITE=1

BIN="${NARSIL_BIN:-}"
if [ -z "$BIN" ]; then
    echo -e "${YELLOW}Building narsil-xref...${NC}"
    cargo build --quiet
    BIN="target/debug/narsil-xref"
fi

generated=$("$BIN" tools list --format markdown)

# Splice the generated block between the markers, leaving the hand-written
# prose either side untouched.
spliced=$(awk -v begin="$BEGIN" -v end="$END" -v gen="$generated" '
    $0 == begin { print; print gen; skip = 1; next }
    $0 == end   { print; skip = 0; next }
    !skip
' "$DOC")

if [ "$WRITE" = "1" ]; then
    printf '%s\n' "$spliced" > "$DOC"
    echo -e "${GREEN}✓${NC} regenerated the tool tables in $DOC"
    exit 0
fi

if ! diff -u <(cat "$DOC") <(printf '%s\n' "$spliced") > /tmp/docs-tools.diff; then
    echo -e "${RED}✗${NC} $DOC is out of date with the tool registry:"
    cat /tmp/docs-tools.diff
    echo
    echo "Run: scripts/check-docs-tools.sh --write"
    exit 1
fi

echo -e "${GREEN}✓${NC} $DOC matches the tool registry"
