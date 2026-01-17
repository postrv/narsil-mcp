# Narsil Plugin for Claude Code

A Claude Code plugin that provides code intelligence capabilities through the narsil-mcp server. Includes slash commands for common workflows, a skill for effective tool usage, and MCP server configuration.

## Features

### Slash Commands

| Command | Description |
|---------|-------------|
| `/narsil:security-scan [repo]` | Run a comprehensive security audit |
| `/narsil:explore [repo]` | Explore and understand an unfamiliar codebase |
| `/narsil:analyze-function <function>` | Deep dive analysis of a specific function |
| `/narsil:find-feature <description>` | Find where a feature is implemented |
| `/narsil:supply-chain [repo]` | Analyze supply chain security |

### Skill

The plugin includes a skill that helps Claude effectively use narsil-mcp's 79 tools:

- **Parameter naming** - Corrects common mistakes (use `repo`, not `repo_path`)
- **Tool selection** - Picks the right tool for each task
- **Feature awareness** - Knows which tools require `--git`, `--call-graph`, etc.
- **Workflow patterns** - Common multi-step analysis patterns

### MCP Server Configuration

The plugin includes an `.mcp.json` that configures narsil-mcp with sensible defaults:
- Current directory as repository
- Git integration enabled
- Call graph analysis enabled
- Persistent index

## Prerequisites

**narsil-mcp must be installed** before using this plugin. The server binary must be in your PATH:

```bash
# Install from crates.io
cargo install narsil-mcp

# Or build from source
git clone https://github.com/postrv/narsil-mcp
cd narsil-mcp
cargo build --release
# Add target/release to your PATH
```

**Claude Code 1.0.33+** is required. Check with `claude --version`.

## Installation

Choose one of the following methods:

### Option 1: Via Marketplace (Recommended)

Add the narsil-mcp marketplace, then install the plugin:

```shell
# Add the marketplace
/plugin marketplace add postrv/narsil-mcp

# Install the plugin
/plugin install narsil@narsil-mcp
```

To update later:
```shell
/plugin marketplace update narsil-mcp
/plugin update narsil@narsil-mcp
```

### Option 2: Direct GitHub Install

Install directly from the GitHub repository without adding a marketplace:

```shell
/plugin install github:postrv/narsil-mcp/narsil-plugin
```

### Option 3: Local Development

For testing or development, load directly from a local directory:

```bash
# Clone the repo
git clone https://github.com/postrv/narsil-mcp
cd narsil-mcp

# Run Claude Code with the plugin loaded
claude --plugin-dir ./narsil-plugin
```

### Option 4: Manual Installation

Copy the plugin to your personal plugins directory:

```bash
mkdir -p ~/.claude/plugins/narsil
git clone https://github.com/postrv/narsil-mcp
cp -r narsil-mcp/narsil-plugin/* ~/.claude/plugins/narsil/
```

## Usage

### Quick Start

1. Start Claude Code in your project directory
2. The narsil-mcp server starts automatically (via `.mcp.json`)
3. Use slash commands or ask naturally:

```shell
/narsil:explore
/narsil:security-scan
/narsil:find-feature authentication
```

Or just ask:
```
Search for where authentication is implemented
Run a security scan on this codebase
Show me what calls the process_payment function
```

### Example Workflows

**Security Audit:**
```shell
/narsil:security-scan myproject
```
Runs OWASP Top 10, CWE Top 25, dependency checks, and license compliance.

**Understand a New Codebase:**
```shell
/narsil:explore
```
Shows project structure, main components, and architectural issues.

**Find Feature Implementation:**
```shell
/narsil:find-feature user authentication
```
Semantically searches for where authentication is implemented.

**Analyze Complex Function:**
```shell
/narsil:analyze-function process_payment
```
Shows callers, callees, complexity metrics, and refactoring suggestions.

**Supply Chain Analysis:**
```shell
/narsil:supply-chain
```
Generates SBOM, checks for CVEs, and audits licenses.

## Configuration

### Customize MCP Server Options

Edit `.mcp.json` in the plugin directory to change server options:

```json
{
  "mcpServers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
      "args": [
        "--repos", "~/projects/myrepo",
        "--git",
        "--call-graph",
        "--neural",
        "--persist",
        "--watch"
      ],
      "env": {
        "VOYAGE_API_KEY": "your-key-here"
      }
    }
  }
}
```

### Available Flags

| Flag | Description |
|------|-------------|
| `--repos <path>` | Repository paths to index (can specify multiple) |
| `--git` | Enable git blame/history tools |
| `--call-graph` | Enable call graph analysis |
| `--lsp` | Enable LSP integration |
| `--neural` | Enable neural embeddings (requires API key) |
| `--persist` | Save index to disk |
| `--watch` | Auto-reindex on file changes |

## Troubleshooting

### "narsil-mcp not found"

Ensure the binary is installed and in your PATH:
```bash
which narsil-mcp
# Should output the path to the binary
```

If not found, install it:
```bash
cargo install narsil-mcp
```

### Empty Results from Git/Call Graph Tools

Check that the features are enabled:
```
Ask Claude: "Use get_index_status to see enabled features"
```

If git or call-graph is disabled, edit the `.mcp.json` to add the flags.

### Slow Performance

For large codebases, use `file_pattern` to narrow searches:
```
search_code(query="auth", file_pattern="src/**/*.py")
```

### Plugin Not Loading

1. Verify installation: `/plugin list`
2. Check for errors: `claude --debug`
3. Reinstall: `/plugin uninstall narsil@narsil-mcp && /plugin install narsil@narsil-mcp`

## Plugin Structure

```
narsil-plugin/
├── .claude-plugin/
│   └── plugin.json         # Plugin manifest
├── commands/
│   ├── security-scan.md    # /narsil:security-scan
│   ├── explore.md          # /narsil:explore
│   ├── analyze-function.md # /narsil:analyze-function
│   ├── find-feature.md     # /narsil:find-feature
│   └── supply-chain.md     # /narsil:supply-chain
├── skills/
│   └── narsil/
│       ├── SKILL.md        # Main skill
│       └── WORKFLOWS.md    # Detailed workflows
├── .mcp.json               # MCP server config
└── README.md
```

## License

MIT OR Apache-2.0

## Links

- [narsil-mcp Repository](https://github.com/postrv/narsil-mcp)
- [Claude Code Documentation](https://code.claude.com/docs)
- [Claude Code Plugins Guide](https://code.claude.com/docs/en/plugins)
- [MCP Protocol](https://modelcontextprotocol.io)
