# Claude Code (CLI) Integration

Set up narsil-mcp with Claude Code for enhanced terminal-based code intelligence.

## Prerequisites

- Claude Code installed (`npm install -g @anthropic-ai/claude-code`)
- narsil-mcp installed (see [INSTALL.md](../../INSTALL.md))

## Configuration

### Global Configuration

Edit `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
      "args": [
        "--repos", ".",
        "--git",
        "--call-graph"
      ]
    }
  }
}
```

Using `.` for `--repos` means it will index the current working directory when you start Claude Code.

### Project-Specific Configuration

Create `.claude/settings.json` in your project root:

```json
{
  "mcpServers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
      "args": [
        "--repos", ".",
        "--git",
        "--call-graph",
        "--persist",
        "--index-path", ".claude/narsil-cache"
      ]
    }
  }
}
```

This keeps the index cached in the project directory for faster startup.

## Usage

Start Claude Code in your project:

```bash
cd /path/to/project
claude
```

Claude now has access to 90 code intelligence tools. Ask questions naturally:

```
> What's the structure of this project?

> Find all functions that handle authentication

> What calls the processPayment function?

> Are there any security vulnerabilities?

> Show me the git history for auth.py
```

## Multiple Repositories

For multi-repo setups:

```json
{
  "mcpServers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
      "args": [
        "--repos", "/path/to/frontend",
        "--repos", "/path/to/backend",
        "--repos", "/path/to/shared-lib",
        "--git",
        "--call-graph"
      ]
    }
  }
}
```

## Environment Variables

Set these in your shell for additional features:

```bash
# Enable neural embeddings (optional)
export VOYAGE_API_KEY="your-key"
# or
export OPENAI_API_KEY="your-key"

# Enable GitHub remote repos (optional)
export GITHUB_TOKEN="your-token"
```

Then add flags:
```json
"args": ["--repos", ".", "--git", "--call-graph", "--neural", "--remote"]
```

## Verify Setup

```bash
cd /path/to/project
claude

> List the repositories indexed by narsil-mcp

# Should show your project
```

## Example Session

```
$ cd ~/projects/myapp
$ claude

> How does the authentication flow work?

Claude: [Calls find_symbols, get_callers, get_file]
Looking at the authentication implementation...

The auth flow in this project:
1. Login request hits `POST /auth/login` in `src/routes/auth.js:45`
2. Calls `AuthService.authenticate()` at `src/services/auth.js:23`
3. Validates credentials against the database
4. Returns a JWT token signed with the secret from config

Key files:
- `src/routes/auth.js` - API endpoints
- `src/services/auth.js` - Core auth logic
- `src/middleware/auth.js` - Token verification middleware
```

## Tips

- **Use `.` for repos:** Let it index the current directory dynamically
- **Cache the index:** Add `--persist --index-path .claude/narsil-cache`
- **Auto-update:** Add `--watch` to reindex when files change
- **Debug issues:** Run with `RUST_LOG=debug` to see what's happening

## Troubleshooting

### "Command not found: narsil-mcp"

Ensure narsil-mcp is in your PATH or use absolute path:
```json
"command": "/usr/local/bin/narsil-mcp"
```

### Slow startup

Enable persistence to cache the index:
```json
"args": ["--repos", ".", "--persist", "--index-path", ".claude/cache"]
```

### Missing git features

Ensure `--git` flag is included and you're in a git repository.
