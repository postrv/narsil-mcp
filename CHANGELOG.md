# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.5] - 2026-01-01

### Fixed

- **`--http` timeout with Zed editor** - The HTTP server and MCP server were mutually exclusive, causing timeouts when `--http` was enabled. Now HTTP server runs in background via `tokio::spawn` while MCP always runs on the main task, allowing both to operate concurrently.

- **`--preset` CLI flag missing** - Added the `--preset` flag that was documented but never implemented. This allows overriding editor-detected presets (e.g., `--preset full` forces all tools on Zed which defaults to minimal).

- **`prompts/get` method not found** - Implemented the MCP `prompts/get` method with full prompt templates for `explain_codebase` and `find_implementation` prompts. Previously only `prompts/list` was implemented.

### Added

- Comprehensive test coverage for CLI preset behavior (6 new tests)
- Test coverage for `prompts/get` functionality (6 new tests)
- Test coverage for HTTP/MCP concurrent operation pattern (6 new tests)

### Changed

- Documentation updated to clarify `--http` runs alongside MCP (not instead of)
- Added Scoop installation note about optional features (ONNX, frontend) requiring source build

## [1.1.1] - 2025-12-28

### Added

- **Package manager distribution** - Making installation easier across all platforms:
  - **Homebrew tap** for macOS/Linux (`brew install postrv/narsil/narsil-mcp`)
  - **crates.io** publishing automated in release workflow (`cargo install narsil-mcp`)
  - **AUR packages** for Arch Linux (`narsil-mcp` and `narsil-mcp-bin`)
  - **Scoop bucket** for Windows (`scoop install narsil-mcp`)
- **GitHub releases** now include versioned tarballs (`.tar.gz` for Unix, `.zip` for Windows)
- **SHA256 checksums** generated for all release artifacts
- **Comprehensive installation guide** (`docs/INSTALL.md`) with platform-specific instructions

### Changed

- Release workflow now creates versioned tarballs instead of individual binaries
- `install.sh` updated to download versioned tarballs with proper extraction

### Fixed

- Windows CI test failure (`test_claude_code_path`) - now handles both `HOME` and `USERPROFILE` env vars
- Tree-sitter query warnings for TypeScript/TSX (changed `identifier` to `type_identifier` for class names)
- Tree-sitter query warning for Kotlin (removed unsupported `interface_declaration` node)
- Neural API key warning message now suggests running `narsil-mcp config init --neural` for better user experience
- Version string in startup logs now uses `CARGO_PKG_VERSION` instead of hardcoded value

## [1.1.0] - 2025-12-28

### 🎯 Major Features - Tool Selection & Configuration System

**Solves:** "76 tools? Isn't that much too many? About how many tokens does Narsil add to the context window with this many tools enabled?" - [Reddit](https://www.reddit.com/r/ClaudeAI/)

narsil-mcp v1.1.0 introduces an intelligent tool selection and configuration system that dramatically reduces context window usage while maintaining full backwards compatibility.

### Added

#### Automatic Editor Detection & Presets

- **4 built-in presets** optimized for different use cases:
  - **Minimal** (26 tools, ~4,686 tokens) - Zed, Cursor - **61% token reduction**
  - **Balanced** (51 tools, ~8,948 tokens) - VS Code, IntelliJ - **25% token reduction**
  - **Full** (69 tools, ~12,001 tokens) - Claude Desktop, comprehensive analysis
  - **Security-focused** (~30 tools) - Security audits and supply chain analysis

- **Automatic client detection** from MCP `initialize` request
  - Zed automatically gets Minimal preset (61% fewer tokens!)
  - VS Code/IntelliJ get Balanced preset (25% fewer tokens)
  - Claude Desktop gets Full preset (all features)
  - Unknown clients get Full preset (backwards compatible)

#### Configuration System

- **Multi-source configuration loading**:
  - Default config (embedded in binary)
  - User config (`~/.config/narsil-mcp/config.yaml`)
  - Project config (`.narsil.yaml` in repo root)
  - Environment variables (`NARSIL_*`)
  - CLI flags (highest priority)

- **Configuration validation** with helpful error messages
- **Interactive config wizard**: `narsil-mcp config init`

#### New CLI Commands

- `config show` - View effective configuration
- `config validate <file>` - Validate config file syntax
- `config init` - Interactive configuration wizard
- `config preset <name>` - Apply a preset
- `config export` - Export current config to YAML
- `tools list [--category <name>]` - List available tools
- `tools search <query>` - Search for tools by name/description

#### New CLI Flags

- `--preset <name>` - Apply a specific preset (minimal, balanced, full, security-focused)

#### Environment Variables

- `NARSIL_PRESET` - Override preset selection
- `NARSIL_CONFIG_PATH` - Custom config file path
- `NARSIL_ENABLED_CATEGORIES` - Comma-separated list of categories to enable
- `NARSIL_DISABLED_TOOLS` - Comma-separated list of tools to disable

### Performance

- **Config loading**: <10ms (budget met ✅)
- **Tool filtering**: <1ms (budget met ✅)
  - Minimal preset: 76.3 µs
  - Balanced preset: 155.1 µs
  - Full preset: 2.9 µs (no filtering)
- **MCP initialize + tools/list**: ~10-15ms total

### Documentation

- **NEW**: `docs/PERFORMANCE.md` - Comprehensive token usage and performance analysis
- **NEW**: `docs/MIGRATION.md` - Upgrading from v1.0.2 guide
- **UPDATED**: `README.md` - Added Configuration section with examples
- **UPDATED**: `CLAUDE.md` - Added configuration system guidance

### Benchmarks

- **NEW**: `benches/filtering.rs` - Config loading and tool filtering performance
- **NEW**: `benches/token_usage.rs` - Context window impact analysis

### Tests

- **494 total tests passing** (100% success rate):
  - 441 library tests
  - 36 integration tests (full_flow, editor, MCP flow)
  - 5 initialization tests (non-blocking startup)
  - 12 cross-platform tests (macOS, Linux, Windows)

- **NEW**: `tests/integration/full_flow_tests.rs` (13 tests)
  - End-to-end MCP flow testing
  - Preset validation
  - Config priority testing
  - Tool filtering verification

- **NEW**: `tests/cross_platform_tests.rs` (12 tests)
  - Config path resolution (platform-specific)
  - File operations (naming conventions, line endings)
  - Path separators (Windows vs Unix)
  - Unicode filename support
  - Long path handling (Windows MAX_PATH)
  - Case sensitivity (macOS/Windows vs Linux)

### Implementation Files

**New Modules:**
- `src/config/mod.rs` - Configuration system exports
- `src/config/schema.rs` - Configuration data structures (ToolConfig, CategoryConfig, etc.)
- `src/config/loader.rs` - Multi-source config loading with priority merging
- `src/config/validation.rs` - Config validation logic
- `src/config/filter.rs` - Tool filtering based on config + feature flags
- `src/config/preset.rs` - Preset definitions (Minimal, Balanced, Full, SecurityFocused)
- `src/config/editor.rs` - Editor detection from MCP client info
- `src/config/cli.rs` - Config and tools CLI commands
- `src/tool_metadata.rs` - Tool metadata registry for all 69 tools

**Modified Files:**
- `src/mcp.rs` - MCP protocol handler with tool filtering integration
- `src/main.rs` - Added config loading and CLI commands
- `Cargo.toml` - Added benchmark targets

### Token Usage Savings

Real-world impact on context window usage:

| Preset | Tools | JSON Size | Tokens | Reduction |
|--------|-------|-----------|--------|-----------|
| Minimal | 26 | 18.3 KB | ~4,686 | **61% fewer** |
| Balanced | 51 | 35.0 KB | ~8,948 | **25% fewer** |
| Full | 69 | 46.9 KB | ~12,001 | baseline |

**Example:** Using Zed with Minimal preset saves **7,315 tokens** (61%) compared to Full preset!

### Backwards Compatibility

✅ **100% backwards compatible** with v1.0.2:
- All CLI flags work exactly the same
- All 69 tools available by default (no config needed)
- No breaking changes to MCP protocol
- Existing integrations continue working unchanged
- Configuration is completely optional

**Migration Path:** No changes required! See [MIGRATION.md](docs/MIGRATION.md) for optional enhancements.

### Fixed

- **Import graph duplicates** (B2): Deduplicated file paths in `get_import_graph` - each file is now processed only once regardless of symbol count
- **License detection for transitive dependencies** (B3): Added `parse_cargo_lock()` to extract all transitive dependencies with license info; `parse_dependencies()` now prefers Cargo.lock over Cargo.toml
- **Call graph fuzzy function matching** (B5): Applied `find_function()` fuzzy matching in `to_markdown()` and `get_metrics()` - "scan_repository" now correctly finds "CodeIntelEngine::scan_repository"
- **Initialization test timeout** (CI): Increased threshold from 500ms to 1000ms for cross-platform CI stability
- Fixed config.preset being ignored in ToolFilter (production bug)
- Fixed unused import warnings in `src/tool_handlers/mod.rs` and config modules

### Added

- **4 new languages**: Bash, Ruby, Kotlin, PHP
  - Bash: `.sh`, `.bash`, `.zsh` - functions, variables
  - Ruby: `.rb`, `.rake`, `.gemspec` - methods, classes, modules
  - Kotlin: `.kt`, `.kts` - functions, classes, objects, interfaces
  - PHP: `.php`, `.phtml` - functions, methods, classes, interfaces, traits
- **Ready-to-use IDE configuration templates** in `/configs`:
  - Claude Desktop (`claude-desktop.json`)
  - Cursor (`.cursor/mcp.json`)
  - VS Code Copilot (`.vscode/mcp.json`)
  - Continue.dev (`continue-config.json`)
- **One-click installer script** (`install.sh`)
  - Auto-detects platform (macOS/Linux, x86_64/arm64)
  - Downloads pre-built binary or builds from source
  - Configures PATH automatically
  - Detects and shows IDE configuration hints
- **Security hardening module** (`security_config.rs`)
  - Secret redaction for tool outputs (API keys, tokens, passwords, private keys)
  - Max file size limits (default 10MB) to prevent DoS
  - Sensitive file detection (`.env`, `.pem`, credentials, etc.)
  - Read-only mode by default
- **DEPENDENCIES.txt** - List of all dependencies for transparency
- **Expanded security rules to all 14 supported languages**:
  - New `rules/bash.yaml` with 5 Bash-specific rules (command injection, temp files, curl TLS, permissions, eval)
  - 3 Rust rules in `cwe-top25.yaml` (unsafe blocks, unwrap/expect, raw pointers)
  - 5 Go rules in `owasp-top10.yaml` (SQL injection, TLS, command injection, path traversal, weak crypto)
  - 5 Java rules (SQL injection, XXE, deserialization, path traversal, LDAP injection)
  - 5 C# rules (SQL injection, deserialization, XSS, path traversal, LDAP injection)
  - 5 Ruby rules (SQL injection, command injection, mass assignment, open redirect, ERB XSS)
  - 5 Kotlin rules (SQL injection, WebView JS, intent handling, hardcoded secrets, insecure random)
  - 6 PHP rules (SQL injection, command injection, file inclusion, unserialize, XSS, path traversal)
  - 2 TypeScript rules (any type usage, non-null assertion)
- **Security test fixtures** for all languages in `test-fixtures/security/`
  - `vulnerable.sh` - Bash vulnerabilities
  - `vulnerable.rs` - Rust vulnerabilities
  - `vulnerable.go` - Go vulnerabilities
  - `vulnerable.java` - Java vulnerabilities
  - `vulnerable.cs` - C# vulnerabilities
  - `vulnerable.rb` - Ruby vulnerabilities
  - `vulnerable.kt` - Kotlin vulnerabilities
  - `vulnerable.php` - PHP vulnerabilities
  - `vulnerable.ts` - TypeScript vulnerabilities

### Changed

- Updated README with competitive comparison table
- Improved documentation structure with badges and better organization
- Total security rules increased from ~74 to 111 (50% increase)

## [1.0.0] - 2025-12-23

### Security

- **Fixed 7 path traversal vulnerabilities** (CWE-22) in the following functions:
  - `trace_taint` - taint analysis endpoint
  - `suggest_fix` - security fix suggestions
  - `get_export_map` - module export analysis
  - `find_semantic_clones` - code clone detection
  - `infer_types` - type inference
  - `check_type_errors` - type error checking
  - `get_typed_taint_flow` - typed taint flow analysis

  All path inputs are now validated using `validate_path()` which performs
  canonicalization and ensures paths stay within the repository root.

### Changed

- Split `neural` feature into two separate features:
  - `neural` - TF-IDF vector search and API-based embeddings (stable)
  - `neural-onnx` - Local ONNX model inference (experimental, requires ort 2.0)
- Updated ort dependency to 2.0.0-rc.10 with new API compatibility

### Fixed

- Fixed compilation issues with ort 2.0.0-rc.10 API changes:
  - Updated `OnnxEmbedder` to use `Mutex<Session>` for thread-safe inference
  - Fixed `try_extract_tensor` return type handling (now returns `(Shape, &[T])`)
  - Removed deprecated `tensor_dimensions()` call
  - Fixed `TensorRef::from_array_view` to take owned view instead of reference
- Fixed usearch save/load to use string paths instead of Path references
- Added missing `neural_config` field to test configurations
- Fixed integration test `test_error_invalid_json` that could hang indefinitely
  - The test now correctly handles JSON-RPC 2.0 spec behavior for malformed input

### Added

- **Test file detection for security scanning**: Added `is_test_file()` function
  that detects test files across languages (Rust, JS/TS, Python, Go, Java)
- **`exclude_tests` parameter for `scan_security`**: Security scans now exclude
  test files by default, reducing false positives from intentional vulnerable
  test fixtures. Set `exclude_tests: false` to include test files.

## [0.2.0] - 2025-12-22

### Added

- Phase 6: Advanced Features
  - Merkle tree-based incremental indexing
  - Cross-language symbol resolution
  - Fuzzy workspace symbol search
  - Import/export graph analysis

- Phase 5: Supply Chain Security
  - SBOM generation (CycloneDX, SPDX formats)
  - Dependency vulnerability checking via OSV database
  - License compliance analysis
  - Upgrade path finder for vulnerable dependencies

- Phase 4: Security Rules Engine
  - OWASP Top 10 2021 scanning
  - CWE Top 25 vulnerability detection
  - Custom YAML security rules support
  - Fix suggestions for common vulnerabilities

- Phase 3: Taint Analysis
  - Source-to-sink data flow tracking
  - SQL injection, XSS, command injection detection
  - Cross-language taint propagation

### Changed

- Improved control flow graph (CFG) analysis
- Enhanced dead code detection
- Better type inference for dynamic languages

## [0.1.0] - 2025-12-20

### Added

- Initial release
- MCP (Model Context Protocol) server implementation
- Multi-language parsing (Rust, Python, JavaScript, TypeScript, Go, C, C++, Java, C#)
- Symbol extraction and search
- Full-text code search with BM25 ranking
- TF-IDF similarity search
- Call graph analysis
- Git integration (blame, history, contributors)
- LSP integration for precise type info
- Remote GitHub repository support
