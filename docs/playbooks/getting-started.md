# Getting Started with narsil-xref

Get code intelligence working in 5 minutes.

## 1. Install

Linux only. Choose one:

```bash
# Install script, downloads the latest release
curl -fsSL https://raw.githubusercontent.com/bsbernd/narsil-xref/main/install.sh | bash

# From a clone of the repository
bash setup.sh
```

Verify installation:
```bash
narsil-xref --version
# narsil-xref 1.1.4
```

## 2. Configure Your AI Tool

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": ["--repos", "/path/to/your/project", "--git", "--call-graph"]
    }
  }
}
```

Restart Claude Desktop.

### Claude Code (CLI)

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": ["--repos", ".", "--git", "--call-graph"]
    }
  }
}
```

### VS Code with Copilot

Create `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": ["--repos", "${workspaceFolder}", "--git", "--call-graph"]
    }
  }
}
```

### Cursor

Create `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": ["--repos", ".", "--git", "--call-graph"]
    }
  }
}
```

## 3. Verify It's Working

Ask your AI assistant:

> "List the repositories that narsil-xref has indexed"

You should see your project listed. If not, check:
- The path in `--repos` is correct
- The server is running (check logs)
- You restarted the AI tool after config changes

## 4. Try Your First Queries

Now ask questions about your code:

```
"What's the structure of this project?"
→ Claude calls get_project_structure

"Find all functions related to authentication"
→ Claude calls find_symbols and search_code

"What calls the handleLogin function?"
→ Claude calls get_callers

"Show me the git history for config.py"
→ Claude calls get_file_history
```

## Command-Line Flags

Enable features with flags:

| Flag | What it enables |
|------|-----------------|
| `--git` | Git blame, history, contributors, hotspots |
| `--call-graph` | Call graph analysis, callers/callees, complexity |
| `--persist` | Save index to disk for faster startup |
| `--watch` | Auto-reindex when files change |
| `--lsp` | LSP integration for precise type info |

Recommended starter config:
```bash
narsil-xref --repos /path/to/project --git --call-graph --persist
```

## Troubleshooting

### "Server not found" or connection errors

1. Verify the binary is in your PATH:
   ```bash
   which narsil-xref
   ```

2. Check the config path is correct for your platform

3. Look for server logs (enable with `--verbose`)

### "Repository not indexed"

1. Verify the path exists and contains code
2. Check file permissions
3. Try explicit indexing:
   ```bash
   narsil-xref --repos /path/to/project --reindex
   ```

### Tool calls failing

Enable debug logging:
```bash
RUST_LOG=debug narsil-xref --repos /path/to/project
```

## Next Steps

- [Understand a Codebase](workflows/understand-codebase.md) - Explore an unfamiliar project
- [Fix a Bug](workflows/fix-a-bug.md) - Debug with call graphs
