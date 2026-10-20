# VS Code with Copilot Integration

Set up narsil-xref with Visual Studio Code and GitHub Copilot.

## Prerequisites

- VS Code with MCP support
- GitHub Copilot extension
- narsil-xref installed (see [INSTALL.md](../../INSTALL.md))

## Configuration

Create `.vscode/mcp.json` in your workspace root:

```json
{
  "servers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", "${workspaceFolder}",
        "--git",
        "--call-graph"
      ]
    }
  }
}
```

The `${workspaceFolder}` variable automatically expands to your current workspace.

## Multi-Root Workspaces

For multi-root workspaces, index all roots:

```json
{
  "servers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", "${workspaceFolder:frontend}",
        "--repos", "${workspaceFolder:backend}",
        "--git",
        "--call-graph"
      ]
    }
  }
}
```

## Global Configuration

For all workspaces, add to VS Code settings (`settings.json`):

```json
{
  "mcp.servers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": ["--repos", "${workspaceFolder}", "--git", "--call-graph"]
    }
  }
}
```

## With Persistence

For faster startup on large projects:

```json
{
  "servers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", "${workspaceFolder}",
        "--git",
        "--call-graph",
        "--persist",
        "--index-path", "${workspaceFolder}/.vscode/narsil-cache"
      ]
    }
  }
}
```

Add `.vscode/narsil-cache/` to your `.gitignore`.

## Usage

1. Open your project in VS Code
2. Open Copilot Chat (Ctrl/Cmd + Shift + I)
3. Ask questions about your codebase:

```
@workspace What's the structure of this project?

@workspace Find all API endpoints

@workspace What calls the handlePayment function?

@workspace Are there any security issues?
```

## Verify Setup

In Copilot Chat:

```
@workspace List the indexed repositories
```

You should see your workspace listed.

## Example Interaction

```
You: @workspace How does error handling work in this project?

Copilot: [Uses narsil-xref tools]
Looking at the error handling patterns in your codebase...

This project uses a centralized error handling approach:

1. **Custom Error Classes** (`src/errors/index.ts`)
   - `ApiError` base class with status code
   - `ValidationError`, `NotFoundError`, `AuthError` extend it

2. **Error Middleware** (`src/middleware/error.ts:45`)
   - Catches all errors from route handlers
   - Formats response based on error type
   - Logs errors to monitoring service

3. **Async Wrapper** (`src/utils/async-handler.ts`)
   - Wraps route handlers to catch promise rejections
   - Forwards to error middleware

Key files:
- src/errors/index.ts (error classes)
- src/middleware/error.ts (centralized handler)
- src/utils/async-handler.ts (async error catching)
```

## Tips

- **Workspace-relative paths:** Use `${workspaceFolder}` for portability
- **Cache locally:** Use `--persist` with `.vscode/` path for project-specific caching
- **Team sharing:** Commit `.vscode/mcp.json` so teammates get the same setup

## Troubleshooting

### Tools not available

1. Check MCP server logs in VS Code output panel
2. Verify narsil-xref is in PATH
3. Reload VS Code window after config changes

### Slow for large projects

Add persistence:
```json
"args": ["--repos", "${workspaceFolder}", "--persist"]
```

### "Repository not found"

Ensure `${workspaceFolder}` resolves correctly. Try hardcoding the path to test.
