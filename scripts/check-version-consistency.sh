#!/bin/bash
# Version Consistency Check
# Validates that all package files have matching versions

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Extract version from Cargo.toml
CARGO_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
echo -e "${YELLOW}Checking version consistency...${NC}"
echo "Cargo.toml version: $CARGO_VERSION"

# If binary exists, check its --version output
if [ -f "target/release/narsil-mcp" ]; then
    BINARY_VERSION=$(./target/release/narsil-mcp --version 2>/dev/null | awk '{print $2}')
    echo "Binary --version output: $BINARY_VERSION"
    if [ "$BINARY_VERSION" != "$CARGO_VERSION" ]; then
        echo -e "${RED}ERROR: Binary version ($BINARY_VERSION) != Cargo version ($CARGO_VERSION)${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ All versions consistent: $CARGO_VERSION${NC}"
exit 0
