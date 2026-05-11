# narsil-mcp

A blazingly fast MCP (Model Context Protocol) server for comprehensive code intelligence.

## Installation

```bash
npm install -g narsil-mcp
```

## Quick Start with Claude Code

Create `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "narsil-mcp": {
      "command": "npx",
      "args": ["narsil-mcp", "--repos", ".", "--git", "--call-graph"]
    }
  }
}
```

Then start Claude Code in your project directory.

## Features

- **90 MCP tools** for code intelligence
- **32 languages** supported via tree-sitter
- **Multi-mode search**: BM25, TF-IDF, hybrid, neural embeddings
- **Call graph analysis**: callers, callees, paths, hotspots
- **Security scanning**: OWASP Top 10, CWE Top 25, secrets detection
- **Git integration**: blame, history, contributors, hotspots
- **Static analysis**: CFG, DFG, type inference, taint analysis

## CLI Usage

```bash
# Index current directory
narsil-mcp --repos . --git --call-graph

# Index multiple repositories
narsil-mcp --repos ~/project1 ~/project2

# Enable all features
narsil-mcp --repos . --git --call-graph --persist --watch
```

## Documentation

Full documentation: https://github.com/postrv/narsil-mcp

## Alternative Installation

```bash
# Shell installer (recommended for non-Node.js users)
curl -fsSL https://raw.githubusercontent.com/postrv/narsil-mcp/main/install.sh | bash

# Build from source
cargo install narsil-mcp

# Homebrew (macOS)
brew install postrv/tap/narsil-mcp
```

## License

MIT OR Apache-2.0
