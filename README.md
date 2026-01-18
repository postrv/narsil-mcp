# narsil-mcp

> The blazing-fast, privacy-first MCP server for deep code intelligence

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Tests](https://img.shields.io/badge/tests-1615%2B%20passed-brightgreen.svg)](https://github.com/postrv/narsil-mcp)
[![MCP](https://img.shields.io/badge/MCP-compatible-blue.svg)](https://modelcontextprotocol.io)

A Rust-powered MCP (Model Context Protocol) server providing AI assistants with deep code understanding through 79 specialized tools.

## Why narsil-mcp?

| Feature | narsil-mcp | XRAY | Serena | GitHub MCP |
|---------|------------|------|--------|------------|
| **Languages** | 32 | 4 | 30+ (LSP) | N/A |
| **Neural Search** | Yes | No | No | No |
| **Taint Analysis** | Yes | No | No | No |
| **SBOM/Licenses** | Yes | No | No | Partial |
| **Offline/Local** | Yes | Yes | Yes | No |
| **WASM/Browser** | Yes | No | No | No |
| **Call Graphs** | Yes | Partial | No | No |
| **Type Inference** | Yes | No | No | No |

## Key Features

- **Code Intelligence** - Symbol extraction, semantic search, call graph analysis
- **Neural Semantic Search** - Find similar code using embeddings (Voyage AI, OpenAI)
- **Security Analysis** - Taint analysis, vulnerability scanning, OWASP/CWE coverage
- **Supply Chain Security** - SBOM generation, dependency auditing, license compliance
- **Advanced Analysis** - Control flow graphs, data flow analysis, dead code detection

### Why Choose narsil-mcp?

- **Written in Rust** - Blazingly fast, memory-safe, single binary (~30MB)
- **Tree-sitter powered** - Accurate, incremental parsing for 32 languages
- **Zero config** - Point at repos and go
- **MCP compliant** - Works with Claude, Cursor, VS Code Copilot, Zed, and any MCP client
- **Privacy-first** - Fully local, no data leaves your machine
- **Parallel indexing** - Uses all cores via Rayon
- **Smart excerpts** - Expands to complete syntactic scopes
- **Security-first** - Built-in vulnerability detection and taint analysis
- **Neural embeddings** - Optional semantic search with Voyage AI or OpenAI
- **WASM support** - Run in browser with WebAssembly build
- **Real-time streaming** - Results as indexing progresses for large repos

## Supported Languages

| Language | Extensions | Symbols Extracted |
|----------|------------|-------------------|
| Rust | `.rs` | functions, structs, enums, traits, impls, mods |
| Python | `.py`, `.pyi` | functions, classes |
| JavaScript | `.js`, `.jsx`, `.mjs` | functions, classes, methods, variables |
| TypeScript | `.ts`, `.tsx` | functions, classes, interfaces, types, enums |
| Go | `.go` | functions, methods, types |
| C | `.c`, `.h` | functions, structs, enums, typedefs |
| C++ | `.cpp`, `.cc`, `.hpp` | functions, classes, structs, namespaces |
| Java | `.java` | methods, classes, interfaces, enums |
| C# | `.cs` | methods, classes, interfaces, structs, enums, delegates, namespaces |
| **Bash** | `.sh`, `.bash`, `.zsh` | functions, variables |
| **Ruby** | `.rb`, `.rake`, `.gemspec` | methods, classes, modules |
| **Kotlin** | `.kt`, `.kts` | functions, classes, objects, interfaces |
| **PHP** | `.php`, `.phtml` | functions, methods, classes, interfaces, traits |
| **Swift** | `.swift` | classes, structs, enums, protocols, functions |
| **Verilog/SystemVerilog** | `.v`, `.vh`, `.sv`, `.svh` | modules, tasks, functions, interfaces, classes |
| **Scala** | `.scala`, `.sc` | classes, objects, traits, functions, vals |
| **Lua** | `.lua` | functions, methods |
| **Haskell** | `.hs`, `.lhs` | functions, data types, type classes |
| **Elixir** | `.ex`, `.exs` | modules, functions |
| **Clojure** | `.clj`, `.cljs`, `.cljc`, `.edn` | lists (basic AST) |
| **Dart** | `.dart` | functions, classes, methods |
| **Julia** | `.jl` | functions, modules, structs |
| **R** | `.R`, `.r`, `.Rmd` | functions |
| **Perl** | `.pl`, `.pm`, `.t` | functions, packages |
| **Zig** | `.zig` | functions, variables |
| **Erlang** | `.erl`, `.hrl` | functions, modules, records |
| **Elm** | `.elm` | functions, types |
| **Fortran** | `.f90`, `.f95`, `.f03`, `.f08` | programs, subroutines, functions, modules |
| **PowerShell** | `.ps1`, `.psm1`, `.psd1` | functions, classes, enums |
| **Nix** | `.nix` | bindings |
| **Groovy** | `.groovy`, `.gradle` | methods, classes, interfaces, enums, functions |

## Installation

### Via Package Managers (Recommended)

**macOS / Linux (Homebrew):**
```bash
brew tap postrv/narsil
brew install narsil-mcp
```

**Windows (Scoop):**
```powershell
scoop bucket add narsil https://github.com/postrv/scoop-narsil
scoop install narsil-mcp
```

**Arch Linux (AUR):**
```bash
yay -S narsil-mcp-bin  # Binary release (faster)
# or
yay -S narsil-mcp      # Build from source
```

**Rust/Cargo (all platforms):**
```bash
cargo install narsil-mcp
```

**Node.js/npm (all platforms):**
```bash
npm install -g narsil-mcp
# or
yarn global add narsil-mcp
# or
pnpm add -g narsil-mcp
```

**Nix:**
```bash
# Run directly without installing
nix run github:postrv/narsil-mcp -- --repos ./my-project

# Install to profile
nix profile install github:postrv/narsil-mcp

# With web visualization frontend
nix profile install github:postrv/narsil-mcp#with-frontend

# Development shell
nix develop github:postrv/narsil-mcp
```

### One-Click Install Script

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/postrv/narsil-mcp/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/postrv/narsil-mcp/main/install.ps1 | iex
```

**Windows (Git Bash / MSYS2):**
```bash
curl -fsSL https://raw.githubusercontent.com/postrv/narsil-mcp/main/install.sh | bash
```

> **Note for Windows users:** The PowerShell installer provides better error messages and native Windows integration. It will automatically configure your PATH and check for required build tools if building from source.

### From Source

**Prerequisites:**
- Rust 1.70 or later
- On Windows: [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) with "Desktop development with C++"

```bash
# Clone and build
git clone git@github.com:postrv/narsil-mcp.git
cd narsil-mcp
cargo build --release

# Binary will be at:
# - macOS/Linux: target/release/narsil-mcp
# - Windows: target/release/narsil-mcp.exe
```

### Feature Builds

narsil-mcp supports different feature sets for different use cases:

```bash
# Default build - native MCP server (~30MB)
cargo build --release

# With neural vector search (~18MB) - adds TF-IDF similarity
cargo build --release --features neural

# With ONNX model support (~50MB) - adds local neural embeddings
cargo build --release --features neural-onnx

# With embedded visualization frontend (~31MB)
cargo build --release --features frontend

# For browser/WASM usage
cargo build --release --target wasm32-unknown-unknown --features wasm
```

| Feature | Description | Size |
|---------|-------------|------|
| `native` (default) | Full MCP server with all tools | ~30MB |
| `frontend` | + Embedded visualization web UI | ~31MB |
| `neural` | + TF-IDF vector search, API embeddings | ~32MB |
| `neural-onnx` | + Local ONNX model inference | ~50MB |
| `wasm` | Browser build (no file system, git) | ~3MB |

> **For detailed installation instructions, troubleshooting, and platform-specific guides**, see [docs/INSTALL.md](docs/INSTALL.md).

## Usage

### Basic Usage

**macOS / Linux:**
```bash
# Index a single repository
narsil-mcp --repos /path/to/your/project

# Index multiple repositories
narsil-mcp --repos ~/projects/project1 --repos ~/projects/project2

# Enable verbose logging
narsil-mcp --repos /path/to/project --verbose

# Force re-index on startup
narsil-mcp --repos /path/to/project --reindex
```

**Windows (PowerShell / CMD):**
```powershell
# Index a single repository
narsil-mcp --repos C:\Users\YourName\Projects\my-project

# Index multiple repositories
narsil-mcp --repos C:\Projects\project1 --repos C:\Projects\project2

# Enable verbose logging
narsil-mcp --repos C:\Projects\my-project --verbose

# Force re-index on startup
narsil-mcp --repos C:\Projects\my-project --reindex
```

### Full Feature Set

```bash
narsil-mcp \
  --repos ~/projects/my-app \
  --git \           # Enable git blame, history, contributors
  --call-graph \    # Enable function call analysis
  --persist \       # Save index to disk for fast startup
  --watch \         # Auto-reindex on file changes
  --lsp \           # Enable LSP for hover, go-to-definition
  --streaming \     # Stream large result sets
  --remote \        # Enable GitHub remote repo support
  --neural \        # Enable neural semantic embeddings
  --neural-backend api \  # Backend: "api" (Voyage/OpenAI) or "onnx"
  --neural-model voyage-code-2  # Model to use
```

**Note:** Neural embeddings require an API key (or custom endpoint). The easiest way to set this up is with the interactive wizard:

```bash
# Run the neural API key setup wizard
narsil-mcp config init --neural
```

The wizard will:
- Detect your editor (Claude Desktop, Claude Code, Zed, VS Code, JetBrains)
- Prompt for your API provider (Voyage AI, OpenAI, or custom)
- Validate your API key
- Automatically add it to your editor's MCP config

Alternatively, you can manually set one of these environment variables:
- `EMBEDDING_API_KEY` - Generic API key for any provider
- `VOYAGE_API_KEY` - Voyage AI specific API key
- `OPENAI_API_KEY` - OpenAI specific API key
- `EMBEDDING_SERVER_ENDPOINT` - Custom embedding API endpoint URL (optional, allows using self-hosted models)

### Configuration

**v1.1.0+ introduces optional configuration** for fine-grained control over tools and performance. **All existing usage continues to work** - configuration is completely optional!

#### Quick Start

```bash
# Generate default config interactively
narsil-mcp config init

# List available tools
narsil-mcp tools list

# Apply a preset via CLI
narsil-mcp --repos ~/project --preset minimal
```

#### Automatic Editor Detection

narsil-mcp detects your editor and applies an optimal preset automatically:

| Editor | Preset | Tools | Context Tokens | Why |
|--------|--------|-------|----------------|-----|
| **Zed** | Minimal | 26 | ~4,686 | Fast startup, minimal context |
| **VS Code** | Balanced | 51 | ~8,948 | Good feature balance |
| **Claude Desktop** | Full | 75+ | ~12,001 | Maximum capabilities |

**Token Savings:**
- **Minimal preset:** 61% fewer tokens vs Full
- **Balanced preset:** 25% fewer tokens vs Full

#### Presets

Choose a preset based on your use case:

```bash
# Minimal - Fast, lightweight (Zed, Cursor)
narsil-mcp --repos ~/project --preset minimal

# Balanced - Good defaults (VS Code, IntelliJ)
narsil-mcp --repos ~/project --preset balanced --git --call-graph

# Full - All features (Claude Desktop, comprehensive analysis)
narsil-mcp --repos ~/project --preset full --git --call-graph

# Security-focused - Security and supply chain tools
narsil-mcp --repos ~/project --preset security-focused
```

#### Configuration Files

**User config** (`~/.config/narsil-mcp/config.yaml`):

```yaml
version: "1.0"
preset: "balanced"

tools:
  # Disable slow tools
  overrides:
    neural_search:
      enabled: false
      reason: "Too slow for interactive use"

performance:
  max_tool_count: 50  # Limit total tools
```

**Project config** (`.narsil.yaml` in repo root):

```yaml
version: "1.0"
preset: "security-focused"  # Override user preset

tools:
  categories:
    Security:
      enabled: true
    SupplyChain:
      enabled: true
```

**Priority:** CLI flags > Environment vars > Project config > User config > Defaults

#### Environment Variables

```bash
# Apply preset
export NARSIL_PRESET=minimal

# Enable specific categories
export NARSIL_ENABLED_CATEGORIES=Repository,Symbols,Search

# Disable specific tools
export NARSIL_DISABLED_TOOLS=neural_search,generate_sbom
```

#### CLI Commands

```bash
# View effective config
narsil-mcp config show

# Validate config file
narsil-mcp config validate ~/.config/narsil-mcp/config.yaml

# List tools by category
narsil-mcp tools list --category Search

# Search for tools
narsil-mcp tools search "git"

# Export config
narsil-mcp config export > my-config.yaml
```

**Learn More:**
- [Configuration Guide](docs/configuration.md) - Full configuration reference
- [Installation Guide](docs/INSTALL.md) - Platform-specific installation

### Visualization Frontend

Explore call graphs, imports, and code structure interactively in your browser.

```bash
# Build with embedded frontend
cargo build --release --features frontend

# Run with HTTP server
narsil-mcp --repos ~/project --http --call-graph
# Open http://localhost:3000
```

Features: interactive graphs, complexity overlays, security highlighting, multiple layouts.

> **Full documentation:** See [docs/frontend.md](docs/frontend.md) for setup, API endpoints, and development mode.

### Neural Semantic Search

Find similar code using neural embeddings - even when variable names and structure differ.

```bash
# Quick setup with wizard
narsil-mcp config init --neural

# Or manually with Voyage AI
export VOYAGE_API_KEY="your-key"
narsil-mcp --repos ~/project --neural --neural-model voyage-code-2
```

Supports Voyage AI, OpenAI, custom endpoints, and local ONNX models.

> **Full documentation:** See [docs/neural-search.md](docs/neural-search.md) for setup, backends, and use cases.

### Type Inference

Built-in type inference for Python, JavaScript, and TypeScript - no mypy or tsc required.

| Tool | Description |
|------|-------------|
| `infer_types` | Get inferred types for all variables in a function |
| `check_type_errors` | Find potential type mismatches |
| `get_typed_taint_flow` | Enhanced security analysis with type info |

```python
def process(data):
    result = data.split(",")  # result: list[str]
    count = len(result)       # count: int
    return count * 2          # returns: int
```

### MCP Configuration

Add narsil-mcp to your AI assistant by creating a configuration file. Here are the recommended setups:

---

**Claude Code** (`.mcp.json` in project root - Recommended):

Create `.mcp.json` in your project directory for per-project configuration:
```json
{
  "mcpServers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
      "args": ["--repos", ".", "--git", "--call-graph"]
    }
  }
}
```

Then start Claude Code in your project:
```bash
cd /path/to/project
claude
```

Using `.` for `--repos` automatically indexes the current directory. Claude now has access to 76 code intelligence tools.

> **Tip**: Add `--persist --index-path .claude/cache` for faster startup on subsequent runs.

For global configuration, edit `~/.claude/settings.json` instead. See [Claude Code Integration](docs/playbooks/integrations/claude-code.md) for advanced setups.

---

**Cursor** (`.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
      "args": ["--repos", ".", "--git", "--call-graph"]
    }
  }
}
```

---

**VS Code + GitHub Copilot** (`.vscode/mcp.json`):
```json
{
  "servers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
      "args": ["--repos", ".", "--git", "--call-graph"]
    }
  }
}
```

> **Note for Copilot Enterprise**: MCP support requires VS Code 1.102+ and must be enabled by your organization administrator.

---

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
      "args": ["--repos", "/path/to/your/projects", "--git"]
    }
  }
}
```

---

**Zed** (`settings.json` → Context Servers):
```json
{
  "context_servers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
      "args": ["--repos", ".", "--git"]
    }
  }
}
```

> **Note for Zed**: narsil-mcp starts immediately and indexes in the background, preventing initialization timeouts.

---

### Claude Code Plugin

For **Claude Code** users, we provide a plugin with slash commands and a skill for effective tool usage.

**Install via Marketplace (Recommended):**
```shell
# Add the narsil-mcp marketplace
/plugin marketplace add postrv/narsil-mcp

# Install the plugin
/plugin install narsil@narsil-mcp
```

**Or install directly from GitHub:**
```shell
/plugin install github:postrv/narsil-mcp/narsil-plugin
```

**What's included:**

| Component | Description |
|-----------|-------------|
| `/narsil:security-scan` | Run comprehensive security audits |
| `/narsil:explore` | Explore unfamiliar codebases |
| `/narsil:analyze-function` | Deep dive on specific functions |
| `/narsil:find-feature` | Find where features are implemented |
| `/narsil:supply-chain` | Analyze supply chain security |
| **Skill** | Guides Claude on using 79 tools effectively |
| **MCP Config** | Auto-starts narsil-mcp with sensible defaults |

See [narsil-plugin/README.md](narsil-plugin/README.md) for full documentation.

### Ralph Automation Integration

[Ralph](https://github.com/postrv/ralphing-la-vida-locum) is a Claude Code automation suite for autonomous code development. When narsil-mcp is available, Ralph gains enhanced code intelligence capabilities:

| Feature | Without narsil-mcp | With narsil-mcp |
|---------|-------------------|-----------------|
| Security scanning | Basic (clippy) | OWASP/CWE vulnerability detection |
| Code understanding | File-based | Call graphs, symbol references |
| Architecture analysis | Manual | CCG L0/L1/L2 automatic layers |
| Dependency analysis | cargo tree | Import graphs, circular detection |

**Setup:**
```bash
# Install narsil-mcp (Ralph auto-detects it)
cargo install narsil-mcp

# Ralph's quality gates use these tools:
narsil-mcp scan_security --repo <name>
narsil-mcp check_type_errors --repo <name> --path src
narsil-mcp find_injection_vulnerabilities --repo <name>
```

Ralph gracefully degrades when narsil-mcp is unavailable - all core automation features work without it.

> **Documentation:** See [Ralph README](https://github.com/postrv/ralphing-la-vida-locum) for full integration details.

### Playbooks & Tutorials

See **[docs/playbooks](docs/playbooks/)** for practical usage guides:

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/playbooks/getting-started.md) | Quick setup and first tool calls |
| [Understand a Codebase](docs/playbooks/workflows/understand-codebase.md) | Explore unfamiliar projects |
| [Fix a Bug](docs/playbooks/workflows/fix-a-bug.md) | Debug with call graphs and taint analysis |
| [Security Audit](docs/playbooks/workflows/security-audit.md) | Find vulnerabilities with OWASP/CWE scanning |
| [Code Review](docs/playbooks/workflows/code-review.md) | Review changes effectively |

Each playbook shows the exact tool chains Claude uses to answer your questions.

### WebAssembly (Browser) Usage

narsil-mcp can run entirely in the browser via WebAssembly - perfect for browser-based IDEs, code review tools, or educational platforms.

```bash
npm install @narsil-mcp/wasm
```

```typescript
import { CodeIntelClient } from '@narsil-mcp/wasm';

const client = new CodeIntelClient();
await client.init();
client.indexFile('src/main.rs', rustSourceCode);
const symbols = client.findSymbols('Handler');
```

> **Full documentation:** See [docs/wasm.md](docs/wasm.md) for build instructions, React examples, and API reference.

## Available Tools (79)

### Repository & File Management

| Tool | Description |
|------|-------------|
| `list_repos` | List all indexed repositories with metadata |
| `get_project_structure` | Get directory tree with file icons and sizes |
| `get_file` | Get file contents with optional line range |
| `get_excerpt` | Extract code around specific lines with context |
| `reindex` | Trigger re-indexing of repositories |
| `discover_repos` | Auto-discover repositories in a directory |
| `validate_repo` | Check if path is a valid repository |
| `get_index_status` | Show index stats and enabled features |

### Symbol Search & Navigation

| Tool | Description |
|------|-------------|
| `find_symbols` | Find structs, classes, functions by type/pattern |
| `get_symbol_definition` | Get symbol source with surrounding context |
| `find_references` | Find all references to a symbol |
| `get_dependencies` | Analyze imports and dependents |
| `workspace_symbol_search` | Fuzzy search symbols across workspace |
| `find_symbol_usages` | Cross-file symbol usage with imports |
| `get_export_map` | Get exported symbols from a file/module |

### Code Search

| Tool | Description |
|------|-------------|
| `search_code` | Keyword search with relevance ranking |
| `semantic_search` | BM25-ranked semantic search |
| `hybrid_search` | Combined BM25 + TF-IDF with rank fusion |
| `search_chunks` | Search over AST-aware code chunks |
| `find_similar_code` | Find code similar to a snippet (TF-IDF) |
| `find_similar_to_symbol` | Find code similar to a symbol |

### AST-Aware Chunking

| Tool | Description |
|------|-------------|
| `get_chunks` | Get AST-aware chunks for a file |
| `get_chunk_stats` | Statistics about code chunks |
| `get_embedding_stats` | Embedding index statistics |

### Neural Semantic Search (requires `--neural`)

| Tool | Description |
|------|-------------|
| `neural_search` | Semantic search using neural embeddings (finds similar code even with different names) |
| `find_semantic_clones` | Find Type-3/4 semantic clones of a function |
| `get_neural_stats` | Neural embedding index statistics |

### Call Graph Analysis (requires `--call-graph`)

| Tool | Description |
|------|-------------|
| `get_call_graph` | Get call graph for repository/function |
| `get_callers` | Find functions that call a function |
| `get_callees` | Find functions called by a function |
| `find_call_path` | Find path between two functions |
| `get_complexity` | Get cyclomatic/cognitive complexity |
| `get_function_hotspots` | Find highly connected functions |

### Control Flow Analysis

| Tool | Description |
|------|-------------|
| `get_control_flow` | Get CFG showing basic blocks and branches |
| `find_dead_code` | Find unreachable code blocks |

### Data Flow Analysis

| Tool | Description |
|------|-------------|
| `get_data_flow` | Variable definitions and uses |
| `get_reaching_definitions` | Which assignments reach each point |
| `find_uninitialized` | Variables used before initialization |
| `find_dead_stores` | Assignments that are never read |

### Type Inference (Python/JavaScript/TypeScript)

| Tool | Description |
|------|-------------|
| `infer_types` | Infer types for variables in a function without external type checkers |
| `check_type_errors` | Find potential type errors without running mypy/tsc |
| `get_typed_taint_flow` | Enhanced taint analysis combining data flow with type inference |

### Import/Dependency Graph

| Tool | Description |
|------|-------------|
| `get_import_graph` | Build and analyze import graph |
| `find_circular_imports` | Detect circular dependencies |
| `get_incremental_status` | Merkle tree and change statistics |

### Security Analysis - Taint Tracking

| Tool | Description |
|------|-------------|
| `find_injection_vulnerabilities` | Find SQL injection, XSS, command injection, path traversal |
| `trace_taint` | Trace tainted data flow from a source |
| `get_taint_sources` | List taint sources (user input, files, network) |
| `get_security_summary` | Comprehensive security risk assessment |

### Security Analysis - Rules Engine

| Tool | Description |
|------|-------------|
| `scan_security` | Scan with security rules (OWASP, CWE, crypto, secrets) |
| `check_owasp_top10` | Scan for OWASP Top 10 2021 vulnerabilities |
| `check_cwe_top25` | Scan for CWE Top 25 weaknesses |
| `explain_vulnerability` | Get detailed vulnerability explanation |
| `suggest_fix` | Get remediation suggestions for findings |

### Supply Chain Security

| Tool | Description |
|------|-------------|
| `generate_sbom` | Generate SBOM (CycloneDX/SPDX/JSON) |
| `check_dependencies` | Check for known vulnerabilities (OSV database) |
| `check_licenses` | Analyze licenses for compliance issues |
| `find_upgrade_path` | Find safe upgrade paths for vulnerable deps |

### Git Integration (requires `--git`)

| Tool | Description |
|------|-------------|
| `get_blame` | Git blame for file |
| `get_file_history` | Commit history for file |
| `get_recent_changes` | Recent commits in repository |
| `get_hotspots` | Files with high churn and complexity |
| `get_contributors` | Repository/file contributors |
| `get_commit_diff` | Diff for specific commit |
| `get_symbol_history` | Commits that changed a symbol |
| `get_branch_info` | Current branch and status |
| `get_modified_files` | Working tree changes |

### LSP Integration (requires `--lsp`)

| Tool | Description |
|------|-------------|
| `get_hover_info` | Type info and documentation |
| `get_type_info` | Precise type information |
| `go_to_definition` | Find definition location |

### Remote Repository Support (requires `--remote`)

| Tool | Description |
|------|-------------|
| `add_remote_repo` | Clone and index GitHub repository |
| `list_remote_files` | List files via GitHub API |
| `get_remote_file` | Fetch file via GitHub API |

### Metrics

| Tool | Description |
|------|-------------|
| `get_metrics` | Performance stats and timing |

## Security Rules

narsil-mcp includes built-in security rules in `rules/`:

- **`owasp-top10.yaml`** - OWASP Top 10 2021 vulnerability patterns
- **`cwe-top25.yaml`** - CWE Top 25 Most Dangerous Weaknesses
- **`crypto.yaml`** - Cryptographic issues (weak algorithms, hardcoded keys)
- **`secrets.yaml`** - Secret detection (API keys, passwords, tokens)

Custom rules can be loaded with `scan_security --ruleset /path/to/rules.yaml`.

## Architecture

```
+-----------------------------------------------------------------+
|                         MCP Server                               |
|  +-----------------------------------------------------------+  |
|  |                   JSON-RPC over stdio                      |  |
|  +-----------------------------------------------------------+  |
|                              |                                   |
|  +---------------------------v-------------------------------+  |
|  |                   Code Intel Engine                        |  |
|  |  +------------+ +------------+ +------------------------+  |  |
|  |  |  Symbol    | |   File     | |    Search Engine       |  |  |
|  |  |  Index     | |   Cache    | |  (Tantivy + TF-IDF)    |  |  |
|  |  | (DashMap)  | | (DashMap)  | +------------------------+  |  |
|  |  +------------+ +------------+                              |  |
|  |  +------------+ +------------+ +------------------------+  |  |
|  |  | Call Graph | |  Taint     | |   Security Rules       |  |  |
|  |  |  Analysis  | |  Tracker   | |   Engine               |  |  |
|  |  +------------+ +------------+ +------------------------+  |  |
|  +-----------------------------------------------------------+  |
|                              |                                   |
|  +---------------------------v-------------------------------+  |
|  |                Tree-sitter Parser                          |  |
|  |  +------+ +------+ +------+ +------+ +------+             |  |
|  |  | Rust | |Python| |  JS  | |  TS  | | Go   | ...         |  |
|  |  +------+ +------+ +------+ +------+ +------+             |  |
|  +-----------------------------------------------------------+  |
|                              |                                   |
|  +---------------------------v-------------------------------+  |
|  |                Repository Walker                           |  |
|  |           (ignore crate - respects .gitignore)             |  |
|  +-----------------------------------------------------------+  |
+-----------------------------------------------------------------+
```

## Performance

Benchmarked on Apple M1 (criterion.rs):

### Parsing Throughput

| Language | Input Size | Time | Throughput |
|----------|------------|------|------------|
| Rust (large file) | 278 KB | 131 µs | **1.98 GiB/s** |
| Rust (medium file) | 27 KB | 13.5 µs | 1.89 GiB/s |
| Python | ~4 KB | 16.7 µs | - |
| TypeScript | ~5 KB | 13.9 µs | - |
| Mixed (5 files) | ~15 KB | 57 µs | - |

### Search Latency

| Operation | Corpus Size | Time |
|-----------|-------------|------|
| Symbol exact match | 1,000 symbols | **483 ns** |
| Symbol prefix match | 1,000 symbols | 2.7 µs |
| Symbol fuzzy match | 1,000 symbols | 16.5 µs |
| BM25 full-text | 1,000 docs | 80 µs |
| TF-IDF similarity | 1,000 docs | 130 µs |
| Hybrid (BM25+TF-IDF) | 1,000 docs | 151 µs |

### End-to-End Indexing

| Repository | Files | Symbols | Time | Memory |
|------------|-------|---------|------|--------|
| narsil-mcp (this repo) | 53 | 1,733 | 220 ms | ~50 MB |
| rust-analyzer | 2,847 | ~50K | 2.1s | 89 MB |
| linux kernel | 78,000+ | ~500K | 45s | 2.1 GB |

**Key metrics:**
- Tree-sitter parsing: **~2 GiB/s** sustained throughput
- Symbol lookup: **<1µs** for exact match
- Full-text search: **<1ms** for most queries
- Hybrid search runs BM25 + TF-IDF in parallel via rayon

## Development

```bash
# Run tests (1615+ tests)
cargo test

# Run benchmarks (criterion.rs)
cargo bench

# Run with debug logging
RUST_LOG=debug cargo run -- --repos ./test-fixtures

# Format code
cargo fmt

# Lint
cargo clippy

# Test with MCP Inspector
npx @modelcontextprotocol/inspector ./target/release/narsil-mcp --repos ./path/to/repo
```

## Troubleshooting

### Tree-sitter Build Errors

If you see errors about missing C compilers or tree-sitter during build:

```bash
# macOS
xcode-select --install

# Ubuntu/Debian
sudo apt install build-essential

# For WASM builds
brew install emscripten  # macOS
```

### Neural Search API Errors

```bash
# Check your API key is set
echo $VOYAGE_API_KEY  # or $OPENAI_API_KEY

# Common issue: wrong key format
export VOYAGE_API_KEY="pa-..."  # Voyage keys start with "pa-"
export OPENAI_API_KEY="sk-..."  # OpenAI keys start with "sk-"
```

### Index Not Finding Files

```bash
# Check .gitignore isn't excluding files
narsil-mcp --repos /path --verbose  # Shows skipped files

# Force reindex
narsil-mcp --repos /path --reindex
```

### Memory Issues with Large Repos

```bash
# For very large repos (>50K files), increase stack size
RUST_MIN_STACK=8388608 narsil-mcp --repos /path/to/huge-repo

# Or index specific subdirectories
narsil-mcp --repos /path/to/repo/src --repos /path/to/repo/lib
```

## Roadmap

### Completed

- [x] Multi-language symbol extraction (32 languages)
- [x] Full-text search with Tantivy (BM25 ranking)
- [x] Hybrid search (BM25 + TF-IDF with RRF)
- [x] AST-aware code chunking
- [x] Git blame/history integration
- [x] Call graph analysis with complexity metrics
- [x] Control flow graph (CFG) analysis
- [x] Data flow analysis (DFG) with reaching definitions
- [x] Dead code and dead store detection
- [x] Taint analysis for injection vulnerabilities
- [x] Security rules engine (OWASP, CWE, crypto, secrets)
- [x] SBOM generation (CycloneDX, SPDX)
- [x] Dependency vulnerability checking (OSV)
- [x] License compliance analysis
- [x] Import graph with circular dependency detection
- [x] Cross-language symbol resolution
- [x] Incremental indexing with Merkle trees
- [x] Index persistence
- [x] Watch mode for file changes
- [x] LSP integration
- [x] Remote repository support
- [x] Streaming responses

## What's New

### v1.1.x (Current)

- **Multi-platform distribution** - Install via Homebrew, Scoop, npm, Cargo, or direct download
- **Configurable tool presets** - Minimal, balanced, full, and security-focused presets
- **Automatic editor detection** - Optimal defaults for Zed, VS Code, Claude Desktop
- **Interactive setup wizard** - `narsil-mcp config init` for easy configuration
- **32 language support** - Added Dart, Julia, R, Perl, Zig, Erlang, Elm, Fortran, PowerShell, Nix, Groovy, and more
- **Improved performance** - Faster startup with background indexing

### v1.0.x

- **Neural semantic search** - Find similar code using Voyage AI or OpenAI embeddings
- **Type inference** - Infer types in Python/JavaScript/TypeScript without external tools
- **Multi-language taint analysis** - Security scanning for PHP, Java, C#, Ruby, Kotlin
- **WASM build** - Run in browser for code playgrounds and educational tools
- **111 bundled security rules** - OWASP, CWE, crypto, secrets detection
- **IDE configs included** - Claude Desktop, Cursor, VS Code, Zed templates

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Credits

Built with:
- [tree-sitter](https://tree-sitter.github.io/) - Incremental parsing
- [tantivy](https://github.com/quickwit-oss/tantivy) - Full-text search
- [tokio](https://tokio.rs/) - Async runtime
- [rayon](https://github.com/rayon-rs/rayon) - Data parallelism
- [serde](https://serde.rs/) - Serialization
