#!/bin/bash
# Session initialization hook for Ralph automation suite
# This hook runs once at the start of each session

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     Ralph Automation Suite - Session Initialization        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Create analytics directory
mkdir -p .ralph

# ============================================================================
# Environment Verification
# ============================================================================

ERRORS=0
WARNINGS=0

# Check git
if ! command -v git &> /dev/null; then
    echo "ERROR: git not installed"
    ERRORS=$((ERRORS + 1))
else
    echo "✓ git installed"
fi

# Check gh CLI (REQUIRED)
if ! command -v gh &> /dev/null; then
    echo "ERROR: gh CLI not installed - required for GitHub operations"
    echo "       Install from: https://cli.github.com/"
    ERRORS=$((ERRORS + 1))
else
    echo "✓ gh CLI installed"

    # Check gh authentication
    if gh auth status &> /dev/null; then
        echo "✓ gh CLI authenticated"
        GH_USER=$(gh api user -q '.login' 2>/dev/null || echo "unknown")
        echo "  └─ Logged in as: $GH_USER"
    else
        echo "ERROR: gh CLI not authenticated"
        echo "       Run: gh auth login"
        ERRORS=$((ERRORS + 1))
    fi
fi

# Check for narsil-mcp (optional but recommended)
if command -v narsil-mcp &> /dev/null; then
    echo "✓ narsil-mcp available"
else
    echo "⚠ narsil-mcp not found (optional - install for enhanced code intelligence)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check for SSH agent (warning - prefer gh CLI)
if [ -n "$SSH_AUTH_SOCK" ]; then
    echo "⚠ SSH agent detected - Ralph prefers gh CLI for GitHub operations"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

# ============================================================================
# Project State Checks
# ============================================================================

echo "Project State:"

# Check git repository
if [ -d .git ]; then
    echo "✓ Git repository initialized"

    # Check for uncommitted changes
    UNCOMMITTED=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')
    if [ "$UNCOMMITTED" -gt 0 ]; then
        echo "⚠ $UNCOMMITTED uncommitted changes detected"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "✓ Working directory clean"
    fi

    # Show current branch
    BRANCH=$(git branch --show-current 2>/dev/null || echo "detached")
    echo "  └─ Current branch: $BRANCH"
else
    echo "⚠ Not a git repository - some features may not work"
    WARNINGS=$((WARNINGS + 1))
fi

# Check for IMPLEMENTATION_PLAN.md
if [ -f IMPLEMENTATION_PLAN.md ]; then
    echo "✓ IMPLEMENTATION_PLAN.md found"

    # Count tasks
    TOTAL_TASKS=$(grep -c '^\s*- \[' IMPLEMENTATION_PLAN.md 2>/dev/null || echo "0")
    DONE_TASKS=$(grep -c '^\s*- \[x\]' IMPLEMENTATION_PLAN.md 2>/dev/null || echo "0")
    echo "  └─ Tasks: $DONE_TASKS/$TOTAL_TASKS complete"
else
    echo "⚠ IMPLEMENTATION_PLAN.md not found"
    echo "  └─ Run 'ralph bootstrap' to create it"
    WARNINGS=$((WARNINGS + 1))
fi

# Check for stale docs
if [ -d docs ]; then
    STALE_COUNT=$(find docs -name "*.md" -mtime +90 2>/dev/null | wc -l | tr -d ' ')
    if [ "$STALE_COUNT" -gt 0 ]; then
        echo "⚠ $STALE_COUNT stale documentation files detected (>90 days old)"
        WARNINGS=$((WARNINGS + 1))
    fi
fi

echo ""

# ============================================================================
# Summary
# ============================================================================

if [ "$ERRORS" -gt 0 ]; then
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  SESSION BLOCKED: $ERRORS error(s) found                         ║"
    echo "║  Fix the errors above before continuing                    ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    exit 1
fi

if [ "$WARNINGS" -gt 0 ]; then
    echo "⚠ Session started with $WARNINGS warning(s)"
else
    echo "✓ Session started successfully"
fi

# Log session start
TIMESTAMP=$(date -Iseconds)
echo "{\"event\":\"session_start\",\"timestamp\":\"$TIMESTAMP\",\"warnings\":$WARNINGS}" >> .ralph/analytics.jsonl

echo ""
echo "Ready to run automation. Use:"
echo "  ralph loop build --max-iterations 50"
echo ""
