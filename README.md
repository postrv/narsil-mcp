# narsil-mcp

> The blazing-fast, privacy-first MCP server for deep code intelligence

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/postrv/narsil-mcp)
[![MCP](https://img.shields.io/badge/MCP-compatible-blue.svg)](https://modelcontextprotocol.io)

A Rust-powered MCP (Model Context Protocol) server providing AI assistants with deep code understanding through 90 specialized tools.

## Why narsil-mcp?

| Feature | narsil-mcp | XRAY | Serena | GitHub MCP |
|---------|------------|------|--------|------------|
| **Languages** | 32 | 4 | 30+ (LSP) | N/A |
| **Offline/Local** | Yes | Yes | Yes | No |
| **Call Graphs** | Yes | Partial | No | No |

## Key Features

- **Code Intelligence** - Symbol extraction, semantic search, call graph analysis
- **Analysis** - Control flow graphs, data flow analysis, complexity and hotspots

### Why Choose narsil-mcp?

- **Written in Rust** - Blazingly fast, memory-safe, single binary (~30MB)
- **Tree-sitter powered** - Accurate, incremental parsing for 32 languages
- **Zero config** - Point at repos and go
- **MCP compliant** - Works with Claude, Cursor, VS Code Copilot, Zed, and any MCP client
- **Privacy-first** - Fully local, no data leaves your machine
- **Parallel indexing** - Uses all cores via Rayon
- **Smart excerpts** - Expands to complete syntactic scopes
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
| **Fortran** | `.f90`, `.f95`, `.f03`, `.f08`, `.f`, `.for`, `.fpp` | programs, subroutines, functions, modules |
| **PowerShell** | `.ps1`, `.psm1`, `.psd1` | functions, classes, enums |
| **Nix** | `.nix` | bindings |
| **Groovy** | `.groovy`, `.gradle` | methods, classes, interfaces, enums, functions |

## Installation

Prebuilt binaries are released for Linux only, on x86_64 and aarch64.

### Install Script

```bash
curl -fsSL https://raw.githubusercontent.com/postrv/narsil-mcp/main/install.sh | bash
```

### From Source

```bash
# Clone, build and install to ~/.local/bin
git clone git@github.com:postrv/narsil-mcp.git
cd narsil-mcp
bash setup.sh
```

### Feature Builds

narsil-mcp supports different feature sets for different use cases:

```bash
# Default build - native MCP server (~30MB)
cargo build --release

# With embedded visualization frontend (~31MB)
cargo build --release --features frontend
```

| Feature | Description | Size |
|---------|-------------|------|
| `native` (default) | Full MCP server with all tools | ~30MB |
| `frontend` | + Embedded visualization web UI | ~31MB |

> **For detailed installation instructions, troubleshooting, and platform-specific guides**, see [docs/INSTALL.md](docs/INSTALL.md).

## Usage

### Basic Usage

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

### Full Feature Set

```bash
narsil-mcp \
  --repos ~/projects/my-app \
  --git \           # Enable git blame, history, contributors
  --call-graph \    # Enable function call analysis
  --persist \       # Save index to disk for fast startup
  --watch \         # Auto-reindex on file changes
  --lsp \           # Enable LSP for hover, go-to-definition
  --streaming       # Stream large result sets
```

### Configuration

**v1.1.0+ introduces optional configuration** for fine-grained control over tools and performance. **All existing usage continues to work** - configuration is completely optional!

#### Quick Start

```bash
# List available tools
narsil-mcp tools list

# Expose only the code and git tool groups
narsil-mcp --repos ~/project --expose code,git
```

#### Configuration Files

**User config** (`~/.config/narsil-mcp/config.yaml`):

```yaml
version: "1.0"
expose: [code, git]

tools:
  # Disable slow tools
  overrides:
    semantic_search:
      enabled: false
      reason: "Too slow for interactive use"
```

**Project config** (`.narsil.yaml` in repo root):

```yaml
version: "1.0"
expose: [code, git, analysis]  # Override the user config's groups
```

**Named repository profiles** are useful for multi-repo workspaces:

```yaml
version: "1.0"
profiles:
  platform:
    repos:
      - ~/src/api
      - ~/src/web
    git: true
    call_graph: true
    persist: true
    expose: [code, git]
```

```bash
narsil-mcp --profile platform
narsil-mcp config profiles
```

**Priority:** CLI flags > Environment vars > Project config > User config > Defaults

#### Environment Variables

```bash
# Select repos/profile
export NARSIL_REPOS=~/src/api,~/src/web
export NARSIL_PROFILE=platform

# Expose only these tool groups
export NARSIL_EXPOSE=code,git

# Disable specific tools
export NARSIL_DISABLED_TOOLS=semantic_search,get_call_graph
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

# List named repository profiles
narsil-mcp config profiles
```

**Learn More:**
- [Tool Reference](docs/tools.md) - All 71 tools, the `--expose` groups, and known caveats
- [Configuration Guide](docs/configuration.md) - Full configuration reference
- [Installation Guide](docs/INSTALL.md) - Platform-specific installation

### Visualization Frontend

Explore call graphs, imports, symbol references, and control flow interactively in your browser.

```bash
# Build with embedded frontend
cargo build --release --features frontend

# Run with HTTP server
narsil-mcp --repos ~/project --http --call-graph
# Open http://localhost:3000
```

**Five graph views:**

| View | Description |
|------|-------------|
| **Call Graph** | Function call relationships with depth control and direction filtering |
| **Import Graph** | File-level import dependencies across the codebase |
| **Symbol Graph** | All references to a symbol, with file clustering |
| **Hybrid** | Combined call + import graph with split budget |
| **Control Flow** | Real CFG with basic blocks, branches, and loop back-edges |

**Features:**
- Interactive Cytoscape.js graphs with drag, zoom, and double-click drill-down
- Complexity metrics overlay with color coding (green/yellow/orange/red)
- Six layout algorithms (dagre, force-directed, breadthfirst, concentric, circle, grid)
- File tree sidebar with syntax-highlighted code viewer
- URL-driven state (shareable links, browser back/forward)
- Dark mode support
- Node detail panel with code excerpts and navigation to source

> **Full documentation:** See [docs/frontend.md](docs/frontend.md) for setup, API endpoints, and development mode.

### Forgemax Integration (Experimental)

For large-scale agentic workflows, narsil-mcp can be used through [Forgemax](https://github.com/postrv/forgemax) — a Code Mode MCP gateway that collapses all 90 tools into just 2 (`search` + `execute`), reducing tool schema overhead from ~12,000 tokens to ~1,000.

```bash
# Install Forgemax
cargo install forgemax

# Run narsil-mcp through Forgemax (uses forge.toml in repo root)
forgemax
```

The included `forge.toml` configures narsil-mcp with sensible defaults:

```toml
[servers.narsil]
command = "narsil-mcp"
args = ["--repos", ".", "--git", "--call-graph", "--persist", "--watch"]
transport = "stdio"

[sandbox]
timeout_secs = 10
max_heap_mb = 64
max_concurrent = 8
```

The LLM writes JavaScript that calls through typed proxy objects inside a sandboxed V8 isolate — credentials, file paths, and internal state never leave the host. This approach is particularly useful when working with multiple MCP servers simultaneously, as it keeps the total tool context small and predictable.

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

Using `.` for `--repos` automatically indexes the current directory. Claude now has access to 90 code intelligence tools.

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

### Playbooks & Tutorials

See **[docs/playbooks](docs/playbooks/)** for practical usage guides:

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/playbooks/getting-started.md) | Quick setup and first tool calls |
| [Understand a Codebase](docs/playbooks/workflows/understand-codebase.md) | Explore unfamiliar projects |
| [Fix a Bug](docs/playbooks/workflows/fix-a-bug.md) | Debug with call graphs |
| [Code Review](docs/playbooks/workflows/code-review.md) | Review changes effectively |

Each playbook shows the exact tool chains Claude uses to answer your questions.

## Available Tools (42)

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
| `find_symbol_usages` | Cross-file symbol usage with imports |
| `get_export_map` | Get exported symbols from a file/module |

### Code Search

| Tool | Description |
|------|-------------|
| `search_code` | Keyword search with relevance ranking |
| `semantic_search` | BM25-ranked semantic search |
| `hybrid_search` | Combined BM25 + TF-IDF with rank fusion |

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

### Data Flow Analysis

| Tool | Description |
|------|-------------|
| `get_data_flow` | Variable definitions and uses |
| `get_reaching_definitions` | Which assignments reach each point |

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

### Metrics

| Tool | Description |
|------|-------------|
| `get_metrics` | Performance stats and timing |

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
|  |  +------------+ +------------+                              |  |
|  |  | Call Graph | |  CFG/DFG   |                              |  |
|  |  |  Analysis  | |  Analysis  |                              |  |
|  |  +------------+ +------------+                              |  |
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
# Run the full test suite
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
- [x] Git blame/history integration
- [x] Call graph analysis with complexity metrics
- [x] Control flow graph (CFG) analysis
- [x] Data flow analysis (DFG) with reaching definitions
- [x] Cross-language symbol resolution
- [x] Incremental indexing with Merkle trees
- [x] Index persistence
- [x] Watch mode for file changes
- [x] LSP integration
- [x] Streaming responses

## What's New

### v1.6.x (Current)

- **Crash-proof chunking** - Fixed unsafe byte-level string slicing in `chunk_file()` and `extract_signature()` that caused `hybrid_search`, `search_chunks`, and `get_chunk_stats` to crash when processing files with multi-byte UTF-8 characters (emoji, CJK, accented chars). All byte slicing now uses safe `content.get()` with fallback.
- **NaN-safe sort operations** - Fixed 5 locations across search, embeddings, git, index, and extract modules where `partial_cmp().unwrap()` would panic on NaN float values. All sorts now use `unwrap_or(Ordering::Equal)`.
- **Defense-in-depth chunking** - Added `catch_unwind` wrappers around all repo-wide `chunk_file()` loops so a panic in one file skips it instead of crashing the entire MCP server.
- **Visualization frontend overhaul** - Full SPA with HashRouter routing, file tree sidebar, syntax-highlighted code viewer, dashboard, and per-repo overview pages
- **Graph view performance** - Import graph now uses cached index data instead of filesystem walks; symbol graph iterates file cache directly instead of markdown round-trips; all views respect `max_nodes` for early termination
- **Real control flow graphs** - Flow view now uses the real CFG builder (`cfg::analyze_function`) with proper basic blocks, branch conditions, and loop back-edges instead of the single-block stub
- **Hybrid graph budget splitting** - Hybrid view allocates 60/40 node budget between call and import graphs for balanced results
- **Fix [#14](https://github.com/postrv/narsil-mcp/issues/14): configurable embedding dimensions** - Added `--neural-dimension` CLI arg and `default_dimension_for_model()` lookup so models like `text-embedding-3-large` use correct dimensions (3072) instead of hardcoded 1536
- **Fix [#13](https://github.com/postrv/narsil-mcp/issues/13): Nix frontend build** - Added `frontendDist` derivation in `flake.nix` using `buildNpmPackage` so `nix profile install github:postrv/narsil-mcp#with-frontend` works
- **Rust security rules** - 18 new rules (RUST-004 to RUST-021) covering command injection, transmute, FFI boundaries, TOCTOU, ReDoS, static mut, SSRF, and more
- **Elixir security rules** - 18 new rules (EX-001 to EX-018) covering atom exhaustion, binary_to_term deserialization, Code.eval injection, Ecto SQL injection, Phoenix XSS, Erlang distribution security
- **Migrated from `serde_yaml` to `serde-saphyr`** - Deprecated `serde_yaml` replaced with actively maintained, panic-free YAML library
- **Custom favicon** - Frontend now uses narsil-mcp branding icon instead of default Vite logo
- **Dependency security** - Updated `time` to 0.3.47 (RUSTSEC-2026-0009), `bytes` to 1.11.1 (RUSTSEC-2026-0007)
- **Test count** increased from 1,611 to 1,763 (+152 tests)

### v1.5.x

- **Deterministic call graph resolution** - Scope-hint propagation disambiguates callee resolution (e.g., `App::run()` correctly resolves to `src/app/mod.rs::run`)
- **8 graph analysis fixes** - Qualified node keys, hotspot filtering, CFG expression handling, import path parsing
- **Nix flake improvements** - DRY `mkPkg` helper, removed unnecessary macOS frameworks, `--lib` test strategy for sandbox builds

### v1.4.x

- **SPARQL / RDF Knowledge Graph** - Query code intelligence data with SPARQL via Oxigraph
- **Code Context Graph (CCG)** - 12 tools for standardized, AI-consumable codebase representations with tiered layers (L0-L3)
- **Type-aware security analysis** - Enhanced taint tracking with type inference and trait implementations
- **Multi-language CFG/DFG** - Control flow and data flow analysis extended to Go, Java, C#, Kotlin
- **Infrastructure as Code scanning** - New `iac.yaml` rules for Terraform, CloudFormation, Kubernetes
- **Language-specific security rules** - New rules for Go, Java, C#, Kotlin, Bash
- **6 new languages** - Erlang, Elm, Fortran, PowerShell, Nix, Groovy
- **90 tools total** - Up from 79 with new SPARQL, CCG, and analysis capabilities

### v1.2.x

- **`exclude_tests` parameter** - 22 tools support filtering out test files
- **npm package** - Install via `npm install -g narsil-mcp`

### v1.1.x

- **Multi-platform distribution** - Install via Homebrew, Scoop, npm, Cargo, or direct download
- **Configurable tool presets** - Minimal, balanced, full, and security-focused presets
- **Automatic editor detection** - Optimal defaults for Zed, VS Code, Claude Desktop
- **Interactive setup wizard** - `narsil-mcp config init` for easy configuration
- **32 language support** - Added Dart, Julia, R, Perl, Zig, and more
- **Improved performance** - Faster startup with background indexing

### v1.0.x

- **Neural semantic search** - Find similar code using Voyage AI or OpenAI embeddings
- **Type inference** - Infer types in Python/JavaScript/TypeScript without external tools
- **Multi-language taint analysis** - Security scanning for PHP, Java, C#, Ruby, Kotlin
- **WASM build** - Run in browser for code playgrounds and educational tools
- **147 bundled security rules** - OWASP, CWE, crypto, secrets, Rust, Elixir detection
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
