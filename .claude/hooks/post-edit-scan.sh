#!/bin/bash
# Post-edit scan - check for secrets in modified files
MODIFIED=$(git diff --name-only HEAD 2>/dev/null | head -5)
if [ -n "$MODIFIED" ]; then
    if echo "$MODIFIED" | xargs grep -l -E "(api_key|password|secret|token).*=" 2>/dev/null; then
        echo "Warning: Potential secret detected in modified files" >&2
    fi
fi
