# IDE Configuration Templates

Ready-to-use MCP configuration files for popular AI coding assistants.

## Quick Setup

### Claude Desktop

Copy `claude-desktop.json` to your Claude Desktop config location:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**Linux:** `~/.config/Claude/claude_desktop_config.json`

```bash
# macOS example
cp claude-desktop.json ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

### Cursor

Copy `cursor-mcp.json` to `.cursor/mcp.json` in your project root:

```bash
mkdir -p .cursor
cp cursor-mcp.json .cursor/mcp.json
```

### VS Code (GitHub Copilot)

Copy `vscode-mcp.json` to `.vscode/mcp.json` in your workspace:

```bash
mkdir -p .vscode
cp vscode-mcp.json .vscode/mcp.json
```

**Note:** MCP support in VS Code requires version 1.102+ and may need to be enabled by your organization administrator for Copilot Enterprise.

### Continue.dev

Merge the `mcpServers` array from `continue-config.json` into your Continue configuration:

**Location:** `~/.continue/config.json`

## Configuration Options

All configs support these command-line arguments:

| Argument | Description | Recommended |
|----------|-------------|-------------|
| `--repos <path>` | Repository path(s) to index | Required |
| `--git` | Enable git blame/history | Yes |
| `--call-graph` | Enable call graph analysis | Yes |
| `--persist` | Save index to disk | For large repos |
| `--watch` | Auto-reindex on file changes | For development |
| `--streaming` | Stream large results | For huge repos |

## Full-Featured Configuration

For maximum capability, use this configuration:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", "${workspaceFolder}",
        "--git",
        "--call-graph",
        "--persist",
        "--watch",
        "--streaming"
      ],
      "env": {
        "RUST_LOG": "warn",
        "VOYAGE_API_KEY": "your-key-here"
      }
    }
  }
}
```

## Troubleshooting

### "narsil-xref not found"

Ensure the binary is in your PATH:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$PATH:/path/to/narsil-xref/target/release"
```

Or use the full path in your config:

```json
{
  "command": "/path/to/narsil-xref/target/release/narsil-xref"
}
```

### Slow indexing

For large repositories (>10k files):
1. Add `--persist` to save the index
2. Add `--streaming` for incremental results
3. Consider using `--watch` instead of re-indexing

### Memory usage

narsil-xref is designed to be memory-efficient, but for very large codebases:
- Use `--streaming` to avoid loading all results at once
- Index only the directories you need with specific `--repos` paths
