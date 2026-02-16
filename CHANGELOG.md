# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2026-02-16

### Fixed

- **Crash-proof chunking** - Fixed unsafe byte-level string slicing in `node_text()`, `extract_signature()`, and `parser.rs` signature extraction that panicked when tree-sitter byte positions landed on multi-byte UTF-8 character boundaries (emoji, CJK, accented characters). All byte slicing now uses safe `content.get()` with fallback. This was the root cause of `hybrid_search`, `search_chunks`, and `get_chunk_stats` crashing the MCP server with "Connection closed" when processing repos with multi-byte content.
- **NaN-safe sort operations** - Fixed 5 locations where `partial_cmp().unwrap()` would panic on NaN float values: `search.rs` (BM25 results), `embeddings.rs` (similarity sort), `git.rs` (churn score sort), `index.rs` (relevance score sort), `extract.rs` (relevance sort). All now use `unwrap_or(std::cmp::Ordering::Equal)`.
- **Defense-in-depth chunking** - Added `catch_unwind` wrappers around all three repo-wide `chunk_file()` loops in `hybrid_search`, `search_chunks`, and `get_chunk_stats` so a panic in one file logs a warning and skips it instead of killing the MCP server process.
- **Dependency security** - Updated `time` crate from 0.3.44 to 0.3.47 to fix RUSTSEC-2026-0009 (DoS via stack exhaustion)

### Added

- **Visualization frontend overhaul** - Full single-page application with HashRouter routing, file tree sidebar with syntax-highlighted code viewer (Prism.js), dashboard page with repo picker, and per-repo overview pages with graph view links
- **Graph view performance** - Import graph now uses cached index data instead of filesystem walks; symbol graph iterates file cache directly instead of markdown round-trips; all graph views respect `max_nodes` parameter for early termination
- **Real control flow graphs** - Flow view now uses the real CFG builder (`cfg::analyze_function`) with proper basic blocks, branch conditions, and loop back-edges instead of the single-block stub
- **Hybrid graph budget splitting** - Hybrid view allocates 60/40 node budget between call and import graphs for balanced results
- **Configurable embedding dimensions** ([#14](https://github.com/postrv/narsil-mcp/issues/14)) - Added `--neural-dimension` CLI arg and `default_dimension_for_model()` lookup so models like `text-embedding-3-large` use correct dimensions (3072) instead of hardcoded 1536
- **Nix frontend build** ([#13](https://github.com/postrv/narsil-mcp/issues/13)) - Added `frontendDist` derivation in `flake.nix` using `buildNpmPackage` so `nix profile install github:postrv/narsil-mcp#with-frontend` works
- **Rust security rules** - 18 new language-specific rules (RUST-004 to RUST-021) in `rules/rust.yaml` covering command injection via `Command::new()`, unsafe transmute, FFI boundary issues, TOCTOU race conditions, ReDoS patterns, static mut usage, SSRF via HTTP clients, and more
- **Elixir security rules** - 18 new language-specific rules (EX-001 to EX-018) in `rules/elixir.yaml` covering atom exhaustion, `binary_to_term` deserialization, `Code.eval` injection, Ecto SQL injection, Phoenix XSS, Erlang distribution security, unsafe NIFs
- **Custom frontend favicon** - Frontend now uses narsil-mcp branding icon (`icon.svg`) instead of default Vite logo

### Changed

- **Migrated from `serde_yaml` to `serde-saphyr`** - Deprecated `serde_yaml` (unmaintained) replaced with actively maintained, panic-free `serde-saphyr` YAML library across all config loading, security rules parsing, and CLI commands
- **Test count** increased from 1,611 to 1,763 (+152 tests)

## [1.5.0] - 2026-02-08

### Added

- **Scope-hint propagation for call graph resolution** - Scoped calls like `App::run()` now extract the scope qualifier (`App`) and use it to disambiguate callees across files. When multiple files define a function with the same name, the scope hint narrows candidates by matching against file paths (e.g., `App` matches `src/app/mod.rs`). Falls back to deterministic alphabetical ordering when ambiguous.

- **Deterministic call graph resolution** - All `find_function()` and `resolve_callee()` methods now collect candidates, sort alphabetically, and pick the first match. Previously, iteration order over `DashMap` was non-deterministic, causing `find_call_path`, `get_callers`, and `get_callees` to return different results across runs.

- **Macro body call extraction** - The call graph builder now extracts function call patterns from inside Rust macro invocations (e.g., `assert!`, `println!`, custom macros), which were previously opaque to analysis.

- **Rust-specific import resolution** - The import graph now correctly resolves `crate::`, `super::`, and `self::` import paths to their corresponding `.rs` or `mod.rs` files, instead of treating them as opaque strings.

### Fixed

- **8 graph analysis bugs** found via real-world testing against the Patina codebase:
  - Call graph nodes now use qualified keys (`file_path::function_name`) instead of bare names, preventing cross-file name collisions
  - `find_function()` returns deterministic results when multiple matches exist
  - `get_hotspots()` filters out generic trait method implementations (`new`, `default`, `from`, `clone`, `fmt`, etc.) that added noise
  - `get_hotspots()` output is capped at 50 results by default to prevent oversized responses
  - `get_code_graph` handler now supports `max_nodes` parameter (default: 200) and truncates with a note when exceeded
  - Import graph node count is capped at 200 to prevent oversized responses
  - CFG builder now correctly handles Rust `expression_statement` nodes wrapping control flow (`if`, `match`, `while`, `for`, `loop`, `return`)
  - CFG builder handles `let` declarations with control-flow RHS (e.g., `let x = if cond { a } else { b }`)
  - Complexity metrics now recognize Rust expression variants (`if_expression`, `for_expression`, `while_expression`, `loop_expression`)
  - Rust `use` import parsing now extracts full module paths instead of truncating at 2 segments

- **Dependency security** - Updated `bytes` crate from 1.11.0 to 1.11.1 to fix RUSTSEC-2026-0007
- **Dependency security** - Updated `time` crate from 0.3.44 to 0.3.47 to fix RUSTSEC-2026-0009 (DoS via stack exhaustion)

### Changed

- **Nix flake improvements** (based on PR #12 by @balaclava-guy):
  - Removed unnecessary macOS framework `buildInputs` (`Security`, `SystemConfiguration`) - stdenv provides these
  - Extracted `mkPkg` helper function to DRY up package definitions
  - Added `cargoTestFlags = ["--lib"]` for nix builds (integration tests require the binary at a fixed path, incompatible with nix sandbox)
  - Added `no-check` and `with-frontend-no-check` package variants
  - Added `git` to devShell packages
  - Updated description to "90 tools across 32 languages"

- **Test count** increased from 1,598 to 1,611

## [1.4.0] - 2025-02-05

### Improved

- **`--graph` flag user experience** - The `--graph` CLI flag now provides clear feedback when used with a binary that wasn't built with `--features graph`:
  - Displays a warning at startup explaining the issue
  - Provides the exact rebuild command needed
  - Logs now accurately report `graph=true` or `graph=false` based on actual feature availability (previously showed `graph=true` even when the feature wasn't compiled)

- **Improved help text** - The `--graph` and `--graph-path` CLI arguments now include notes explaining that the binary must be built with `--features graph` for these flags to have effect

### Documentation

- **README updated** with:
  - Feature Builds section now includes `graph` feature with size estimate (~35MB)
  - New troubleshooting section "Graph Feature Not Working" with clear fix instructions
  - Note in Full Feature Set clarifying `--graph` requires `--features graph` build
  - What's New section updated for v1.4.x

### Technical Details

This change addresses confusion where users would pass `--graph` and the server would appear to start normally, but SPARQL/CCG tools would return errors. The misleading `graph=true` in logs made debugging difficult. Now:
- Users get immediate feedback at startup if there's a mismatch
- The exact fix is provided in the warning message
- Log output accurately reflects what's actually available

## [1.3.1] - 2025-01-23

### Fixed

- **Windows installer**: Fixed binary download URL to match release asset naming (`narsil-mcp-v{VERSION}-windows-{ARCH}.zip`) - PR #10 by @Cognitohazard
- **Windows installer**: Fixed zip extraction to find binary at archive root
- **Windows installer**: Added proper exit code detection for cargo build failures (was falsely reporting success when MSVC was missing)
- **Windows installer**: Added rustup exit code detection
- **Windows installer**: Improved error messages with troubleshooting hints for MSVC/Visual Studio issues

## [1.3.0] - 2025-01-18

### Added

#### SPARQL / RDF Knowledge Graph (`--graph` flag)

- **RDF knowledge graph persistence** using Oxigraph for semantic code queries
- **3 SPARQL tools**:
  - `sparql_query` - Execute SPARQL SELECT/ASK queries against code graph
  - `list_sparql_templates` - List available query templates
  - `run_sparql_template` - Execute predefined templates with parameters

#### Code Context Graph (CCG)

- **12 CCG tools** for standardized, AI-consumable codebase representations:
  - `get_ccg_manifest` - Layer 0 manifest (~1-2KB JSON-LD)
  - `export_ccg_manifest` - Export Layer 0 to file
  - `export_ccg_architecture` - Layer 1 architecture (~10-50KB JSON-LD)
  - `export_ccg_index` - Layer 2 symbol index (~100-500KB N-Quads gzipped)
  - `export_ccg_full` - Layer 3 full detail (~1-20MB N-Quads gzipped)
  - `export_ccg` - Export all layers as bundle
  - `query_ccg` - Query CCG with SPARQL
  - `get_ccg_acl` - Generate WebACL access control
  - `get_ccg_access_info` - Get access tier information
  - `import_ccg` - Import CCG layer from URL/file
  - `import_ccg_from_registry` - Import from codecontextgraph.com registry
- **Triple-Heart Model** for tiered access control (public/authenticated/private)
- **CCG ontology** (`ontology/narsil.ttl`, `ontology/ccg-acl.ttl`)
- **CCG schema** (`schema/ccg-v1.json`)
- **CCG examples** in `examples/ccg/`

#### Type-Aware Security Analysis

- **Enhanced type inference** with trait implementation tracking
- **Type stubs** for Go, Java, Rust standard libraries
- **Public parsing APIs** for Go, Java, and Rust types
- **Type-aware taint flow** combining data flow with type inference

#### Multi-Language Analysis Extensions

- **CFG support** extended to Go, Java, C#, Kotlin
- **DFG support** extended to Go, Java, C#, Kotlin
- **Dead code detection** for additional languages

#### Security Rules

- **`iac.yaml`** - Infrastructure as Code rules (Terraform, CloudFormation, Kubernetes, Docker)
- **`config.yaml`** - Configuration file security rules
- **Language-specific rules**: `go.yaml`, `java.yaml`, `csharp.yaml`, `kotlin.yaml`

#### New Languages (6)

- **Erlang** (`.erl`, `.hrl`) - functions, modules, records
- **Elm** (`.elm`) - functions, types
- **Fortran** (`.f90`, `.f95`, `.f03`, `.f08`) - programs, subroutines, functions, modules
- **PowerShell** (`.ps1`, `.psm1`, `.psd1`) - functions, classes, enums
- **Nix** (`.nix`) - bindings
- **Groovy** (`.groovy`, `.gradle`) - methods, classes, interfaces, enums, functions

#### Other

- **Nix flake** for distribution (`flake.nix`)
- **Configurable taint patterns** with YAML configuration
- **Data structure propagation** in taint analysis

### Changed

- **Tool count** increased from 79 to 90
- **Taint module refactored** from monolithic `taint.rs` to module structure (`taint/analyzer.rs`, `taint/patterns.rs`, `taint/types.rs`)
- Removed `#[allow]` annotations and cleaned up dead code

### Fixed

- Cache concurrent test threshold for CI stability
- Windows CI flaky test (`test_reindex`, `test_concurrent_requests`) - replaced fixed sleep with polling-based `wait_for_repo`

## [1.2.0] - 2025-01-04

### Added

- **`exclude_tests` parameter** - 22 tools now support filtering out test files to reduce noise and token usage:
  - Security tools (5): `check_owasp_top10`, `check_cwe_top25`, `find_injection_vulnerabilities`, `get_taint_sources`, `get_security_summary`
  - Analysis tools (5): `find_dead_code`, `find_uninitialized`, `find_dead_stores`, `check_type_errors`, `find_circular_imports`
  - Symbol tools (3): `find_symbols`, `find_references`, `find_symbol_usages`
  - Search tools (5): `search_code`, `semantic_search`, `hybrid_search`, `search_chunks`, `find_similar_code`
  - CallGraph tools (4): `get_call_graph`, `get_callers`, `get_callees`, `get_function_hotspots`

- **npm package** - Install via `npm install -g narsil-mcp` with automatic binary download
- **Automated npm publishing** - Release workflow now publishes to npm registry

### Changed

- **README restructured** - Claude Code configuration moved to first position, reduced from 1,186 to 951 lines (20% reduction)
- **Documentation reorganized** - WASM, Neural Search, and Frontend docs moved to dedicated files in `docs/`
- **Install script enhanced** - Now shows Claude Code quick-start guide with `.mcp.json` example after installation

### Defaults

- Security/Analysis tools: `exclude_tests` defaults to `true` (excludes tests)
- Symbol/Search tools: `exclude_tests` defaults to `false` (includes tests)
- CallGraph tools: accepts parameter but filtering requires call graph rebuild

## [1.1.6] - 2025-01-03

### Fixed

- **C++ parser** - Fixed tree-sitter query syntax for C++ namespace and class declarations. Previously caused parsing errors on C++ codebases.

## [1.1.5] - 2025-01-01

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
