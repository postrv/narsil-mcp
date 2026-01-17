# Configuration Guide

narsil-mcp supports flexible configuration through multiple layers, allowing you to customize tool availability, presets, and behavior at different levels.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration Levels](#configuration-levels)
- [Configuration File Format](#configuration-file-format)
- [Presets](#presets)
- [Environment Variables](#environment-variables)
- [CLI Commands](#cli-commands)
- [Categories](#categories)
- [Tool Overrides](#tool-overrides)
- [Performance Configuration](#performance-configuration)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Neural API Key Setup

If you want to use neural embeddings for advanced code similarity search, run the interactive wizard:

```bash
# Run the neural API key setup wizard
narsil-mcp config init --neural
```

The wizard will:
1. Detect your editor (Claude Desktop, Claude Code, Zed, VS Code, JetBrains)
2. Prompt for your API provider (Voyage AI recommended for code, or OpenAI)
3. Ask for your API key
4. Optionally validate the key
5. Automatically add the key to your editor's MCP config file

After completing the wizard, restart your editor and run narsil-mcp with `--neural` to enable neural search.

### Using Presets

The fastest way to get started is using a preset:

```bash
# Apply minimal preset (20-30 tools for lightweight editors)
export NARSIL_PRESET=minimal
narsil-mcp --repos ~/project

# Apply balanced preset (40-50 tools for IDEs)
export NARSIL_PRESET=balanced
narsil-mcp --repos ~/project --git --call-graph

# Apply full preset (all 79 tools)
export NARSIL_PRESET=full
narsil-mcp --repos ~/project --git --call-graph --neural
```

### Creating a User Config

For persistent configuration:

```bash
# Create default user config
mkdir -p ~/.config/narsil-mcp
cp examples/configs/balanced.yaml ~/.config/narsil-mcp/config.yaml

# Edit to your preferences
vim ~/.config/narsil-mcp/config.yaml

# Start server (config is automatically loaded)
narsil-mcp --repos ~/project
```

## Configuration Levels

Configurations are loaded and merged with the following priority (highest to lowest):

1. **CLI flags** (`--git`, `--call-graph`, `--neural`, etc.)
   - Highest priority
   - Overrides all other configuration
   - Example: `--git` enables Git category regardless of config files

2. **Environment variables** (`NARSIL_*`)
   - Second highest priority
   - Useful for temporary overrides or CI/CD
   - See [Environment Variables](#environment-variables)

3. **Project config** (`.narsil.yaml` in repository root)
   - Repository-specific settings
   - Overrides user config
   - Useful for team-shared settings

4. **User config** (`~/.config/narsil-mcp/config.yaml`)
   - Your personal preferences
   - Persists across all projects
   - Platform-specific paths:
     - Linux: `~/.config/narsil-mcp/config.yaml`
     - macOS: `~/Library/Application Support/narsil-mcp/config.yaml` or `~/.config/narsil-mcp/config.yaml`
     - Windows: `%APPDATA%\narsil-mcp\config.yaml`

5. **Default config** (built-in)
   - Lowest priority
   - Embedded in the binary
   - Always available as fallback

### Merging Behavior

Configurations are merged hierarchically:
- Category settings merge by category name
- Tool overrides merge by tool name
- Lower priority configs provide defaults
- Higher priority configs override specific values

Example:
```yaml
# User config: Enable Git category
tools:
  categories:
    Git:
      enabled: true

# Project config: Add specific tool override
tools:
  overrides:
    get_blame:
      enabled: false
      reason: "Too slow on this large repo"

# Result: Git category enabled, but get_blame disabled
```

## Configuration File Format

Configuration files use YAML format with the following structure:

```yaml
version: "1.0"

# Optional: Apply a preset (minimal, balanced, full, security-focused)
preset: "balanced"

# Editor-specific settings (optional)
editors:
  vscode:
    preset: "balanced"
  zed:
    preset: "minimal"

# Tool configuration
tools:
  # Category-level settings
  categories:
    Repository:
      enabled: true
      description: "Repository and file operations"

    Git:
      enabled: true
      description: "Git integration"
      required_flags: ["git"]  # Only enabled if --git flag present

    Search:
      enabled: true
      config:
        max_results: 50

    Security:
      enabled: false
      reason: "Not needed for this project"

  # Tool-level overrides
  overrides:
    neural_search:
      enabled: false
      reason: "Too slow for interactive use"

    generate_sbom:
      enabled: true
      reason: "Required for compliance"
      config:
        format: "cyclonedx"

# Performance settings
performance:
  max_tool_count: 50
  startup_latency_ms: 10
  filtering_latency_ms: 1

# Feature requirements (optional)
feature_requirements:
  neural_search:
    api_key_required: true
    env_var: "EMBEDDING_API_KEY"
```

## Presets

Presets are curated tool configurations optimized for different use cases:

### Minimal Preset

**Use case:** Fast, lightweight code intelligence with minimal overhead

**Optimized for:**
- Zed editor
- Vim/Neovim
- Lightweight editors with strict performance requirements

**Includes:**
- Repository and file operations
- Symbol search and navigation
- Basic code search
- LSP integration

**Expected tool count:** 20-30 tools

**Usage:**
```bash
# Environment variable
export NARSIL_PRESET=minimal

# Config file
echo 'preset: "minimal"' > ~/.config/narsil-mcp/config.yaml

# Copy example
cp examples/configs/minimal.yaml ~/.config/narsil-mcp/config.yaml
```

---

### Balanced Preset

**Use case:** Full-featured code intelligence for daily development

**Optimized for:**
- VS Code
- JetBrains IDEs (IntelliJ, PyCharm, WebStorm, RustRover)
- Sublime Text
- Emacs

**Includes:**
- All minimal tools
- Git integration (requires `--git` flag)
- Call graph analysis (requires `--call-graph` flag)
- Security scanning
- Code analysis tools
- Graph visualization

**Expected tool count:** 40-50 tools (30-40 without flags)

**Usage:**
```bash
export NARSIL_PRESET=balanced
narsil-mcp --repos ~/project --git --call-graph
```

---

### Full Preset

**Use case:** Comprehensive code intelligence for deep analysis

**Optimized for:**
- Claude Desktop
- Comprehensive code analysis
- Research and exploration

**Includes:**
- ALL 79 tools
- All search modes (including neural with `--neural`)
- Full security scanning
- Supply chain analysis
- Remote GitHub repository support (with `--remote`)
- All code analysis features

**Expected tool count:** 50-60 tools without flags, 70+ tools with all flags

**Usage:**
```bash
export NARSIL_PRESET=full
narsil-mcp --repos ~/project --git --call-graph --neural --remote
```

---

### Security-Focused Preset

**Use case:** Security auditing and supply chain analysis

**Optimized for:**
- Security researchers
- Compliance teams
- Vulnerability assessment
- Supply chain analysis

**Includes:**
- Repository and file operations
- Symbol search for vulnerable patterns
- Security scanning (OWASP Top 10, CWE Top 25, secrets, crypto)
- Supply chain analysis (SBOM, vulnerabilities, licenses)
- Taint analysis and type checking
- Git integration for tracking vulnerability introduction

**Expected tool count:** ~35 tools

**Usage:**
```bash
export NARSIL_PRESET=security-focused
narsil-mcp --repos ~/project --git
```

## Environment Variables

Environment variables provide quick overrides without editing config files:

### NARSIL_PRESET

Apply a preset configuration:

```bash
export NARSIL_PRESET=minimal
export NARSIL_PRESET=balanced
export NARSIL_PRESET=full
export NARSIL_PRESET=security-focused
```

### NARSIL_CONFIG_PATH

Use a custom config file location:

```bash
export NARSIL_CONFIG_PATH=/path/to/my-config.yaml
narsil-mcp --repos ~/project
```

### NARSIL_ENABLED_CATEGORIES

Enable only specific categories (comma-separated):

```bash
# Enable only Repository, Symbols, and Search categories
export NARSIL_ENABLED_CATEGORIES=Repository,Symbols,Search
narsil-mcp --repos ~/project
```

This will:
- Disable all other categories
- Enable the specified categories
- Override category settings from config files

### NARSIL_DISABLED_TOOLS

Disable specific tools (comma-separated):

```bash
# Disable slow tools
export NARSIL_DISABLED_TOOLS=neural_search,generate_sbom,find_semantic_clones
narsil-mcp --repos ~/project
```

This will:
- Keep all other tools enabled
- Disable only the specified tools
- Override tool settings from config files

### Combining Environment Variables

```bash
# Apply balanced preset but disable slow tools
export NARSIL_PRESET=balanced
export NARSIL_DISABLED_TOOLS=neural_search,generate_sbom

# Enable only core categories
export NARSIL_ENABLED_CATEGORIES=Repository,Symbols,Search,Git

narsil-mcp --repos ~/project --git
```

## CLI Commands

narsil-mcp provides CLI commands for managing configuration:

### Show Current Configuration

Display the effective configuration after merging all sources:

```bash
narsil-mcp config show

# Show as JSON
narsil-mcp config show --format json

# Show configuration for specific repo
narsil-mcp config show --repo ~/project
```

### Validate Configuration

Validate a config file without starting the server:

```bash
# Validate user config
narsil-mcp config validate ~/.config/narsil-mcp/config.yaml

# Validate project config
narsil-mcp config validate .narsil.yaml

# Validate and show errors
narsil-mcp config validate my-config.yaml --verbose
```

### Initialize Configuration

Create a new configuration file interactively:

```bash
# Interactive wizard
narsil-mcp config init

# Initialize with a specific preset
narsil-mcp config init --preset balanced

# Create project config
narsil-mcp config init --project

# Create user config
narsil-mcp config init --user
```

### Apply Preset

Quickly apply a preset to your user config:

```bash
narsil-mcp config preset minimal
narsil-mcp config preset balanced
narsil-mcp config preset full
narsil-mcp config preset security-focused

# Apply to project config
narsil-mcp config preset balanced --project
```

### List Tools

List available tools with filtering:

```bash
# List all tools
narsil-mcp tools list

# List tools in a category
narsil-mcp tools list --category Search

# Search for tools
narsil-mcp tools search "git"

# Show tool details
narsil-mcp tools show get_blame
```

### Export Configuration

Export the current effective configuration:

```bash
# Export to file
narsil-mcp config export > my-config.yaml

# Export current state including resolved presets
narsil-mcp config export --resolved
```

## Categories

narsil-mcp organizes its 79 tools into 12 categories:

### Repository (10 tools)

Repository and file operations:
- `list_repos`, `get_project_structure`, `get_file`, `get_excerpt`
- `reindex`, `discover_repos`, `validate_repo`, `get_index_status`
- `get_incremental_status`, `get_metrics`

**Always enabled by default**

### Symbols (7 tools)

Symbol search and navigation:
- `find_symbols`, `get_symbol_definition`, `find_references`
- `get_dependencies`, `find_symbol_usages`, `get_export_map`
- `workspace_symbol_search`

**Always enabled by default**

### Search (12 tools)

Multi-mode code search:
- `search_code`, `semantic_search`, `hybrid_search`, `neural_search`
- `search_chunks`, `find_similar_code`, `find_similar_to_symbol`
- `find_semantic_clones`, `get_embedding_stats`, `get_neural_stats`
- `get_chunk_stats`, `get_chunks`

**Enabled by default** (except `neural_search` which requires `--neural`)

### Git (9 tools)

Git integration (requires `--git` flag):
- `get_blame`, `get_file_history`, `get_recent_changes`, `get_hotspots`
- `get_contributors`, `get_commit_diff`, `get_symbol_history`
- `get_branch_info`, `get_modified_files`

**Requires `--git` CLI flag**

### CallGraph (6 tools)

Call graph analysis (requires `--call-graph` flag):
- `get_call_graph`, `get_callers`, `get_callees`, `find_call_path`
- `get_complexity`, `get_function_hotspots`

**Requires `--call-graph` CLI flag**

### LSP (3 tools)

LSP integration for enhanced type info:
- `get_hover_info`, `get_type_info`, `go_to_definition`

**Enhanced with `--lsp` flag**

### Security (9 tools)

Security vulnerability scanning:
- `scan_security`, `check_owasp_top10`, `check_cwe_top25`
- `find_injection_vulnerabilities`, `trace_taint`, `get_taint_sources`
- `get_security_summary`, `explain_vulnerability`, `suggest_fix`

**Enabled by default**

### SupplyChain (4 tools)

Supply chain analysis:
- `generate_sbom`, `check_dependencies`, `check_licenses`
- `find_upgrade_path`

**Optional** (can be slow, disabled in minimal/balanced presets)

### Analysis (11 tools)

Code analysis (CFG, DFG, type inference, taint):
- `get_control_flow`, `find_dead_code`, `get_data_flow`
- `get_reaching_definitions`, `find_uninitialized`, `find_dead_stores`
- `infer_types`, `check_type_errors`, `get_typed_taint_flow`
- `get_import_graph`, `find_circular_imports`

**Enabled by default**

### Remote (3 tools)

Remote GitHub repository support (requires `--remote` flag):
- `add_remote_repo`, `list_remote_files`, `get_remote_file`

**Requires `--remote` CLI flag and GITHUB_TOKEN**

### Graph (1 tool)

Graph visualization support:
- `get_code_graph` (HTTP API only)

**Enabled with `--http` flag**

### Experimental (2 tools)

AI-assisted code understanding:
- `explain_codebase`, `find_implementation`

**Experimental** (may change in future versions)

## Tool Overrides

Override specific tools regardless of category settings:

```yaml
tools:
  overrides:
    # Disable slow tool
    neural_search:
      enabled: false
      reason: "Too slow for interactive use - use semantic_search instead"

    # Enable specific tool even if category disabled
    generate_sbom:
      enabled: true
      reason: "Required for compliance"
      config:
        format: "cyclonedx"
        compact: true

    # Configure tool behavior
    search_code:
      enabled: true
      config:
        max_results: 100
        timeout_ms: 5000
```

## Performance Configuration

Tune performance characteristics:

```yaml
performance:
  # Maximum number of tools to advertise (enforced during filtering)
  max_tool_count: 50

  # Maximum acceptable startup latency in milliseconds
  startup_latency_ms: 10

  # Maximum acceptable filtering latency in milliseconds
  filtering_latency_ms: 1
```

## Examples

### Example 1: Minimal Editor Setup (Zed)

Fast, lightweight configuration with only essential tools:

```yaml
# ~/.config/narsil-mcp/config.yaml
version: "1.0"
preset: "minimal"

tools:
  categories:
    Repository:
      enabled: true
    Symbols:
      enabled: true
    Search:
      enabled: true
    LSP:
      enabled: true

    # Disable everything else
    Git:
      enabled: false
    CallGraph:
      enabled: false
    Security:
      enabled: false
    SupplyChain:
      enabled: false
    Analysis:
      enabled: false

performance:
  max_tool_count: 30
  startup_latency_ms: 5
```

Start server:
```bash
narsil-mcp --repos ~/project
```

---

### Example 2: IDE Setup (VS Code)

Full-featured development with Git and code analysis:

```yaml
# ~/.config/narsil-mcp/config.yaml
version: "1.0"
preset: "balanced"

tools:
  categories:
    Repository:
      enabled: true
    Symbols:
      enabled: true
    Search:
      enabled: true
    Git:
      enabled: true
    CallGraph:
      enabled: true
    LSP:
      enabled: true
    Security:
      enabled: true
    Analysis:
      enabled: true
    Graph:
      enabled: true

  overrides:
    # Disable slow tools
    neural_search:
      enabled: false
      reason: "Too slow for IDE - use semantic_search instead"

    find_semantic_clones:
      enabled: false
      reason: "Too slow for interactive use"

    generate_sbom:
      enabled: false
      reason: "Only needed for releases"

performance:
  max_tool_count: 50
```

Start server:
```bash
narsil-mcp --repos ~/project --git --call-graph
```

---

### Example 3: Security Auditing

Focus on security and supply chain tools:

```yaml
# ~/.config/narsil-mcp/config.yaml
version: "1.0"
preset: "security-focused"

tools:
  categories:
    Repository:
      enabled: true
    Symbols:
      enabled: true
    Search:
      enabled: true
    Git:
      enabled: true  # Track when vulnerabilities were introduced
    Security:
      enabled: true
    SupplyChain:
      enabled: true
    Analysis:
      enabled: true  # For taint analysis

  overrides:
    # Enable all security tools
    scan_security:
      enabled: true
      config:
        severity_threshold: "low"
        exclude_tests: true

    check_owasp_top10:
      enabled: true

    check_cwe_top25:
      enabled: true

    generate_sbom:
      enabled: true
      config:
        format: "cyclonedx"

    check_dependencies:
      enabled: true
      config:
        severity_threshold: "medium"
```

Start server:
```bash
narsil-mcp --repos ~/project --git
```

---

### Example 4: Project-Specific Configuration

Team-shared settings in repository:

```yaml
# ~/my-project/.narsil.yaml
version: "1.0"

tools:
  categories:
    # Always enable security scanning for this project
    Security:
      enabled: true

    # This project requires SBOM
    SupplyChain:
      enabled: true

  overrides:
    generate_sbom:
      enabled: true
      reason: "Required for compliance"
      config:
        format: "spdx"

    check_licenses:
      enabled: true
      config:
        project_license: "MIT"
        fail_on_copyleft: true

performance:
  max_tool_count: 60
```

This config applies only to `~/my-project` and overrides your user config.

---

### Example 5: CI/CD Environment

Use environment variables for temporary overrides:

```bash
#!/bin/bash
# ci-security-scan.sh

# Use security-focused preset
export NARSIL_PRESET=security-focused

# Enable only security-relevant categories
export NARSIL_ENABLED_CATEGORIES=Repository,Symbols,Security,SupplyChain

# Ensure Git is available for tracking changes
export NARSIL_DISABLED_TOOLS=""

# Run security scan
narsil-mcp --repos . --git
```

## Troubleshooting

### Tools Not Appearing

**Problem:** Expected tools are not showing up in tools/list

**Solutions:**

1. Check if required CLI flags are present:
   ```bash
   # Git tools require --git flag
   narsil-mcp --repos ~/project --git

   # Call graph tools require --call-graph flag
   narsil-mcp --repos ~/project --call-graph
   ```

2. Check category is enabled:
   ```bash
   # Show current config
   narsil-mcp config show

   # Look for category.enabled = false
   ```

3. Check environment variables:
   ```bash
   # These might be filtering tools
   echo $NARSIL_PRESET
   echo $NARSIL_ENABLED_CATEGORIES
   echo $NARSIL_DISABLED_TOOLS

   # Unset them to reset
   unset NARSIL_PRESET NARSIL_ENABLED_CATEGORIES NARSIL_DISABLED_TOOLS
   ```

4. Check tool-specific overrides:
   ```yaml
   # In config file, look for:
   tools:
     overrides:
       tool_name:
         enabled: false
   ```

### Configuration Not Loading

**Problem:** Config file changes are not taking effect

**Solutions:**

1. Verify config file location:
   ```bash
   # Linux/macOS
   ls -la ~/.config/narsil-mcp/config.yaml

   # macOS (alternative)
   ls -la ~/Library/Application\ Support/narsil-mcp/config.yaml

   # Windows
   dir %APPDATA%\narsil-mcp\config.yaml
   ```

2. Validate config syntax:
   ```bash
   narsil-mcp config validate ~/.config/narsil-mcp/config.yaml
   ```

3. Check for YAML errors:
   - Ensure proper indentation (spaces, not tabs)
   - Check for missing colons
   - Ensure quotes around strings with special characters

4. Check config priority:
   - Environment variables override config files
   - CLI flags override everything
   - Use `narsil-mcp config show` to see effective configuration

### Performance Issues

**Problem:** Server is slow to start or respond

**Solutions:**

1. Reduce tool count:
   ```yaml
   performance:
     max_tool_count: 30  # Reduce from default
   ```

2. Use minimal preset:
   ```bash
   export NARSIL_PRESET=minimal
   ```

3. Disable slow tools:
   ```bash
   export NARSIL_DISABLED_TOOLS=neural_search,generate_sbom,find_semantic_clones
   ```

4. Disable categories you don't need:
   ```bash
   export NARSIL_ENABLED_CATEGORIES=Repository,Symbols,Search
   ```

### Preset Not Working

**Problem:** Applying a preset doesn't seem to work

**Solutions:**

1. Check preset is being applied:
   ```bash
   narsil-mcp config show | grep preset
   ```

2. Ensure preset is spelled correctly:
   - Valid presets: `minimal`, `balanced`, `full`, `security-focused`
   - Case-sensitive

3. Check if config file overrides preset:
   ```yaml
   # This will override preset:
   tools:
     categories:
       Git:
         enabled: true  # Even if preset says false
   ```

4. Use environment variable for highest priority:
   ```bash
   export NARSIL_PRESET=minimal
   ```

### Config File Validation Errors

**Problem:** Config validation fails with errors

**Common errors and fixes:**

1. Missing `version` field:
   ```yaml
   # Add this at the top
   version: "1.0"
   ```

2. Invalid category name:
   ```yaml
   # Valid categories:
   # Repository, Symbols, Search, Git, CallGraph, LSP
   # Security, SupplyChain, Analysis, Remote, Graph
   ```

3. Missing required fields:
   ```yaml
   # Tools must have this structure:
   tools:
     categories: {}
     overrides: {}
   ```

4. Invalid YAML syntax:
   ```bash
   # Use a YAML validator
   yamllint ~/.config/narsil-mcp/config.yaml
   ```

## See Also

- [Migration Guide](./migration.md) - Upgrading from previous versions
- [Example Configurations](../examples/configs/README.md) - Ready-to-use config templates
- [README](../README.md) - Main project documentation
- [Tool Reference](../README.md#mcp-tools-76-total) - Complete tool documentation
