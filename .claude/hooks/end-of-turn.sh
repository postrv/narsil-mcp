#!/bin/bash
# End of turn verification
MODIFIED=$(git diff --name-only HEAD 2>/dev/null || echo "")
if [ -z "$MODIFIED" ]; then
    exit 0
fi

# Run quick narsil-mcp scan if available
if command -v narsil-mcp &> /dev/null; then
    SCAN=$(narsil-mcp scan_security 2>&1) || true
    if echo "$SCAN" | grep -qE "CRITICAL"; then
        echo "CRITICAL security issue found" >&2
        echo "$SCAN" | grep -A2 "CRITICAL" >&2
        exit 2
    fi
fi

# Log to analytics
mkdir -p .ralph
TIMESTAMP=$(date -Iseconds)
FILE_COUNT=$(echo "$MODIFIED" | wc -l | tr -d ' ')
echo "{\"event\":\"turn_complete\",\"timestamp\":\"$TIMESTAMP\",\"files\":$FILE_COUNT}" >> .ralph/analytics.jsonl
