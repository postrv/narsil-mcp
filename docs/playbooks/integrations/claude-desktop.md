# Claude Desktop Integration

Set up narsil-xref with Claude Desktop for code-aware conversations.

## Prerequisites

- Claude Desktop installed ([download](https://claude.ai/download))
- narsil-xref installed (see [INSTALL.md](../../INSTALL.md))

## Configuration

### macOS

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", "/Users/yourname/projects/myproject",
        "--git",
        "--call-graph",
        "--persist"
      ]
    }
  }
}
```

### Windows

Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", "C:\\Users\\yourname\\projects\\myproject",
        "--git",
        "--call-graph",
        "--persist"
      ]
    }
  }
}
```

### Linux

Edit `~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", "/home/yourname/projects/myproject",
        "--git",
        "--call-graph",
        "--persist"
      ]
    }
  }
}
```

## Multiple Repositories

Index multiple projects:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", "/path/to/project1",
        "--repos", "/path/to/project2",
        "--repos", "/path/to/project3",
        "--git",
        "--call-graph"
      ]
    }
  }
}
```

Or auto-discover repositories:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--discover", "/path/to/all/my/projects",
        "--git",
        "--call-graph"
      ]
    }
  }
}
```

## Recommended Flags

| Flag | Description | Recommended? |
|------|-------------|--------------|
| `--git` | Enable git blame, history, contributors | Yes |
| `--call-graph` | Enable call graph analysis | Yes |
| `--persist` | Save index to disk for faster startup | Yes |
| `--watch` | Auto-reindex on file changes | Optional (uses more memory) |
| `--neural` | Neural embeddings (requires API key) | Optional |

## Verify Setup

After restarting Claude Desktop:

1. Start a new conversation
2. Ask: "List the repositories that narsil-xref has indexed"
3. You should see your project(s) listed

## Example Session

```
You: "What does this project do?"

Claude: [Calls get_project_structure, find_symbols, search_code]
"This is a Python web API built with Flask. The main components are:
- API routes in src/api/ handling user and order endpoints
- Services in src/services/ for payment and email
- Models in src/models/ using SQLAlchemy ORM
..."
```

## Troubleshooting

### "Server not found"

1. Verify narsil-xref is in your PATH:
   ```bash
   which narsil-xref
   ```

2. Try using absolute path in config:
   ```json
   "command": "/usr/local/bin/narsil-xref"
   ```

### "Repository not indexed"

1. Check the path exists and contains code files
2. Verify file permissions
3. Check Claude Desktop logs for errors

### Server disconnects

Enable persistent index to avoid re-indexing:
```json
"args": ["--repos", "/path/to/project", "--persist"]
```

## Tips

- **Start fresh:** Restart Claude Desktop after config changes
- **Use persist:** Add `--persist` for faster startup on subsequent sessions
- **Watch mode:** Add `--watch` if you want live updates as you edit code
- **Full features:** Add all flags for maximum capability: `--git --call-graph --persist`
