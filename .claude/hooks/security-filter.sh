#!/bin/bash
# shellcheck disable=SC2016
# Security filter hook - blocks dangerous and SSH commands
# This hook runs before every tool use to validate commands
# SC2016 disabled: Single quotes intentionally prevent expansion for pattern matching

# Read input from stdin
INPUT=$(cat)

# Extract command from JSON input
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || echo "")

# If no command found, try alternate formats
if [ -z "$CMD" ]; then
    CMD=$(echo "$INPUT" | jq -r '.command // empty' 2>/dev/null || echo "$INPUT")
fi

# ============================================================================
# Dangerous Command Patterns (Always Blocked)
# ============================================================================

DANGEROUS_PATTERNS=(
    # Destructive filesystem operations
    "rm -rf /"
    "rm -rf ~"
    "rm -rf /*"
    'rm -rf $HOME'
    'rm -rf ${HOME}'

    # Disk operations
    "dd if=/dev/zero"
    "mkfs."
    "> /dev/sd"

    # Permission escalation
    "chmod 777"
    "chmod -R 777"
    "sudo rm"
    "sudo dd"
    "sudo -s"
    "sudo su"

    # Fork bombs and resource exhaustion
    ":(){:|:&};:"

    # Network piping (potential RCE)
    "curl.*|.*sh"
    "curl.*|.*bash"
    "wget.*|.*sh"
    "wget.*|.*bash"

    # Code execution from encoded content
    "base64 -d | sh"
    "base64 -d | bash"
)

for pattern in "${DANGEROUS_PATTERNS[@]}"; do
    if [[ "$CMD" == *"$pattern"* ]]; then
        echo "BLOCKED: Dangerous command pattern detected: $pattern" >&2
        echo '{"blocked": true, "reason": "Dangerous command: '"$pattern"'"}' >&2
        exit 2
    fi
done

# ============================================================================
# SSH Blocking (Enforce gh CLI)
# ============================================================================

SSH_PATTERNS=(
    # SSH key operations
    "ssh-keygen"
    "ssh-add"
    "ssh-agent"
    "eval \$(ssh-agent"

    # SSH key file access
    "$HOME/.ssh/"
    "/home/*/.ssh/"
    ".ssh/id_"
    "cat.*id_rsa"
    "cat.*id_ed25519"
    "cat.*id_ecdsa"
    "cat.*known_hosts"
    "cat.*authorized_keys"

    # Git SSH URLs (should use gh CLI)
    "git@github.com:"
    "git clone git@"
    "git remote add.*git@"
    "git remote set-url.*git@"
)

for pattern in "${SSH_PATTERNS[@]}"; do
    if [[ "$CMD" == *"$pattern"* ]]; then
        echo "BLOCKED: SSH operation detected - use gh CLI instead" >&2
        echo "" >&2

        # Provide helpful alternative
        if [[ "$CMD" == *"git clone git@github.com:"* ]]; then
            # Extract repo from command
            REPO=$(echo "$CMD" | sed -n 's/.*git@github.com:\([^.]*\).*/\1/p')
            echo "Alternative: gh repo clone $REPO" >&2
        elif [[ "$CMD" == *"ssh-keygen"* ]] || [[ "$CMD" == *"ssh-add"* ]]; then
            echo "Alternative: gh CLI handles authentication - run 'gh auth login'" >&2
        else
            echo "Alternative: Use gh CLI for GitHub operations" >&2
        fi

        echo "" >&2
        echo '{"blocked": true, "reason": "SSH operation blocked - use gh CLI"}' >&2
        exit 2
    fi
done

# ============================================================================
# Warning Patterns (Log but allow)
# ============================================================================

WARNING_PATTERNS=(
    "rm -rf"           # General recursive delete (may be intentional)
    "chmod"            # Permission changes
    "curl.*|"          # Piping curl (if not to shell)
    "eval"             # Dynamic evaluation
)

for pattern in "${WARNING_PATTERNS[@]}"; do
    if [[ "$CMD" == *"$pattern"* ]]; then
        echo "WARNING: Potentially risky command pattern: $pattern" >&2
        # Don't block, just warn
    fi
done

# ============================================================================
# Pass Through
# ============================================================================

# If we get here, the command is allowed
echo "$INPUT"
