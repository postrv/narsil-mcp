# Cursor Integration

Set up narsil-xref with Cursor IDE for enhanced AI-powered development.

## Prerequisites

- Cursor IDE installed ([download](https://cursor.sh))
- narsil-xref installed (see [INSTALL.md](../../INSTALL.md))

## Configuration

Create `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", ".",
        "--git",
        "--call-graph"
      ]
    }
  }
}
```

## Global Configuration

For all projects, create `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", ".",
        "--git",
        "--call-graph"
      ]
    }
  }
}
```

## With Persistence

For faster startup:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", ".",
        "--git",
        "--call-graph",
        "--persist",
        "--index-path", ".cursor/narsil-cache"
      ]
    }
  }
}
```

Add `.cursor/narsil-cache/` to `.gitignore`.

## Multiple Repositories

For monorepos or multi-project setups:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", "./packages/frontend",
        "--repos", "./packages/backend",
        "--repos", "./packages/shared",
        "--git",
        "--call-graph"
      ]
    }
  }
}
```

## Usage

1. Open your project in Cursor
2. Open the AI chat (Cmd/Ctrl + L)
3. Ask questions naturally:

```
What does this project do?

Find the authentication implementation

What calls processOrder()?

Are there any security vulnerabilities?

Who last modified auth.py?
```

## Verify Setup

Ask Cursor:

```
List the repositories indexed by narsil-xref
```

You should see your project.

## Example Session

```
You: How does the payment flow work?

Cursor: [Uses narsil-xref tools]
Let me trace the payment flow through your codebase...

The payment flow:

1. **API Entry** (`src/api/payments.py:34`)
   - POST /payments/process endpoint
   - Validates request body with PaymentSchema

2. **Service Layer** (`src/services/payment.py:67`)
   - PaymentService.process_payment()
   - Checks user balance
   - Calls payment gateway

3. **Gateway Integration** (`src/gateways/stripe.py:23`)
   - StripeGateway.charge()
   - Handles Stripe API communication
   - Returns PaymentResult

4. **Database Update** (`src/models/transaction.py:45`)
   - Creates Transaction record
   - Updates user balance

Call chain:
handle_payment_request() → PaymentService.process_payment()
  → StripeGateway.charge() → Transaction.create()
```

## Using with Cursor Features

### Composer Mode

When using Cursor's Composer for multi-file edits, narsil-xref helps by:
- Understanding code relationships before edits
- Identifying all files that need changes
- Checking for breaking changes

### @ Mentions

Combine with file mentions:

```
@auth.py What functions in this file are called from other modules?
```

Cursor uses narsil-xref's `get_callers` to find cross-module usage.

## Tips

- **Project-level config:** Keep `.cursor/mcp.json` in version control for team consistency
- **Use persistence:** Add `--persist` for large codebases
- **Full features:** Enable `--git --call-graph` for maximum capability

## Troubleshooting

### MCP server not connecting

1. Check Cursor's developer console for errors
2. Verify narsil-xref path: `which narsil-xref`
3. Restart Cursor after config changes

### Slow performance

Enable caching:
```json
"args": ["--repos", ".", "--persist", "--index-path", ".cursor/cache"]
```

### "Repository not indexed"

Ensure you're in the project directory and the path `.` resolves correctly.
