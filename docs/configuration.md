# Configuration Guide

narsil-xref supports flexible configuration through multiple layers, allowing you to customize tool availability and behavior at different levels.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration Levels](#configuration-levels)
- [Configuration File Format](#configuration-file-format)
- [Named Repository Profiles](#named-repository-profiles)
- [Environment Variables](#environment-variables)
- [CLI Commands](#cli-commands)
- [Tool Overrides](#tool-overrides)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Creating a User Config

For persistent configuration:

```bash
# Create default user config
mkdir -p ~/.config/narsil-xref
cp examples/configs/balanced.yaml ~/.config/narsil-xref/config.yaml

# Edit to your preferences
vim ~/.config/narsil-xref/config.yaml

# Start server (config is automatically loaded)
narsil-xref --repos ~/project
```

### Named Repository Profiles

Profiles store reusable workspace definitions in your config file. They are
useful when you regularly switch between multi-repo projects.

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

Start with a profile:

```bash
narsil-xref --profile platform
narsil-xref config profiles
```

CLI flags still win, so `narsil-xref --profile platform --repos ~/src/one-off`
uses the explicit `--repos` value while keeping profile feature defaults.

#### Per-repo and per-group backend tuning

A repo entry can be either a bare path (all defaults) or a map carrying
overrides for that repo alone. Each C/C++ backend — `clangd`, `ccls`, `gtags` —
has its own block, settable on a repo entry **or** as a profile-group default
that every repo in the profile inherits. A repo entry's own value wins field by
field; an unset field falls back to the group default, then the compiled
default. This is how a single large C repo is bounded without affecting the
others in the profile:

```yaml
version: "1.0"
profiles:
  platform:
    lsp: true
    use_compile_commands: true
    # Group defaults: every repo below inherits these unless it overrides them.
    clangd: { jobs: 4, background_index: true }
    ccls:   { enabled: false }            # ccls off across the whole group
    repos:
      # Huge C tree: cap clangd harder and route references through gtags.
      - path: ~/src/bigkernel
        clangd: { jobs: 2, background_index: false }  # overrides the group jobs: 4
        gtags:  { enabled: true, generate: true }
        index_filter: [fs, mm, drivers/block]
        lsp_scope: [fs]
      # Inherits the group clangd (jobs: 4, background index on) and ccls (off).
      - path: ~/src/cpp-engine
      # A bare path uses all defaults.
      - ~/src/liburing
```

- **`clangd`** — `enabled` (default true; `false` skips clangd for this repo),
  `jobs` (clangd `-j N`: async worker count, which also bounds background-index
  parallelism — the main memory/CPU lever), `background_index` (default true;
  `false` adds `--background-index=false`).
- **`ccls`** — `enabled`, `threads` (ccls `index.threads`, the indexer-thread
  analog of clangd `-j`), `retain_in_memory` (ccls `cache.retainInMemory`:
  resident file caches; `0` keeps none — lowest memory, more per-query disk
  reads — versus the ccls default of 2), `background_index`.
- **`gtags`** — `enabled` (override the global `--gtags`/`--no-gtags` intent for
  this repo; a GTAGS database is still required to answer), `generate` (override
  `--gtags-generate`: auto-build GTAGS when absent, writing into the tree).
- Disabling **both** clangd and ccls for a repo indexes it with tree-sitter +
  gtags only — no language server starts for it.
- `index_filter` / `lsp_scope` accept paths **relative to the repo root**
  (absolute paths also work). They override the global `--index-filter` /
  `--lsp-scope` flags for that repo; a repo without its own list falls back to
  those flags.
- ccls always writes its cache under the user cache directory, never a
  `.ccls-cache/` inside the repository.

> **Memory note:** clangd has no hard RSS-cap flag. `clangd.jobs`,
> `ccls.threads`, and `ccls.retain_in_memory` bound parallelism and resident
> cache — they lower peak memory but are not absolute limits. Turning a backend
> off, or `background_index: false`, is the firm lever on a very large tree.

> The pre-split per-repo `lsp:` and `background_index:` keys have been replaced
> by these blocks and are now rejected at startup. Move a `background_index:
> false` to `clangd: { background_index: false }` (plus `ccls: {
> background_index: false }` if ccls runs), and a `lsp: false` to
> `clangd: { enabled: false }` + `ccls: { enabled: false }`.

## Configuration Levels

Configurations are loaded and merged with the following priority (highest to lowest):

1. **CLI flags** (`--git`, `--call-graph`, `--expose`, etc.)
   - Highest priority
   - Overrides all other configuration
   - Example: `--git` enables the git tools regardless of config files

2. **Environment variables** (`NARSIL_*`)
   - Second highest priority
   - Useful for temporary overrides or CI/CD
   - See [Environment Variables](#environment-variables)

3. **Project config** (`.narsil.yaml` in repository root)
   - Repository-specific settings
   - Overrides user config
   - Useful for team-shared settings

4. **User config** (`~/.config/narsil-xref/config.yaml`)
   - Your personal preferences
   - Persists across all projects
   - Platform-specific paths:
     - Linux: `~/.config/narsil-xref/config.yaml`
     - macOS: `~/Library/Application Support/narsil-xref/config.yaml` or `~/.config/narsil-xref/config.yaml`
     - Windows: `%APPDATA%\narsil-xref\config.yaml`

5. **Default config** (built-in)
   - Lowest priority
   - Embedded in the binary
   - Always available as fallback

### Merging Behavior

Configurations are merged hierarchically:
- Tool overrides merge by tool name
- Lower priority configs provide defaults
- Higher priority configs override specific values

Example:
```yaml
# User config: expose the code and git groups
expose: [code, git]

# Project config: Add specific tool override
tools:
  overrides:
    get_blame:
      enabled: false
      reason: "Too slow on this large repo"

# Result: code and git tools exposed, but get_blame disabled
```

## Configuration File Format

Configuration files use YAML format with the following structure:

```yaml
version: "1.0"

# Optional: expose only these tool groups (code, git, analysis). The
# machine-wide default for invocations that do not pass --expose, set
# NARSIL_EXPOSE, or select a profile listing its own groups — useful when the
# command line comes from an editor plugin.
# See docs/tools.md for what each group contains.
expose: [code, git]

# Tool configuration
tools:
  # Tool-level overrides
  overrides:
    semantic_search:
      enabled: false
      reason: "Too slow for interactive use"
```

## Environment Variables

Environment variables provide quick overrides without editing config files:

### NARSIL_CONFIG_PATH

Use a custom config file location:

```bash
export NARSIL_CONFIG_PATH=/path/to/my-config.yaml
narsil-xref --repos ~/project
```

### NARSIL_REPOS and NARSIL_PROFILE

Select repositories without command-line arguments:

```bash
export NARSIL_REPOS=~/src/api,~/src/web
narsil-xref --git

export NARSIL_PROFILE=platform
narsil-xref
```

### NARSIL_DISABLED_TOOLS

Disable specific tools (comma-separated):

```bash
# Disable slow tools
export NARSIL_DISABLED_TOOLS=semantic_search,get_call_graph
narsil-xref --repos ~/project
```

This will:
- Keep all other tools enabled
- Disable only the specified tools
- Override tool settings from config files

## CLI Commands

narsil-xref provides CLI commands for managing configuration:

### Show Current Configuration

Display the effective configuration after merging all sources:

```bash
narsil-xref config show

# Show as JSON
narsil-xref config show --format json

# Show configuration for specific repo
narsil-xref config show --repo ~/project
```

### Validate Configuration

Validate a config file without starting the server:

```bash
# Validate user config
narsil-xref config validate ~/.config/narsil-xref/config.yaml

# Validate project config
narsil-xref config validate .narsil.yaml

# Validate and show errors
narsil-xref config validate my-config.yaml --verbose
```

### List Tools

List available tools with filtering:

```bash
# List all tools
narsil-xref tools list

# List tools in a category
narsil-xref tools list --category Search

# Search for tools
narsil-xref tools search "git"

# Show tool details
narsil-xref tools show get_blame
```

### Export Configuration

Export the current effective configuration:

```bash
# Export to file
narsil-xref config export > my-config.yaml
```

## Tool Overrides

Disable specific tools regardless of the exposed groups:

```yaml
tools:
  overrides:
    # Disable slow tool
    semantic_search:
      enabled: false
      reason: "Too slow for interactive use - use search_code instead"

    # Configure tool behavior
    search_code:
      enabled: true
      config:
        max_results: 100
        timeout_ms: 5000
```

## Troubleshooting

### Tools Not Appearing

**Problem:** Expected tools are not showing up in tools/list

**Solutions:**

1. Check if required CLI flags are present:
   ```bash
   # Git tools require --git flag
   narsil-xref --repos ~/project --git

   # Call graph tools require --call-graph flag
   narsil-xref --repos ~/project --call-graph
   ```

2. Check the exposed groups:
   ```bash
   # Show current config
   narsil-xref config show

   # Look for the expose: line
   ```

3. Check environment variables:
   ```bash
   # These might be filtering tools
   echo $NARSIL_EXPOSE
   echo $NARSIL_DISABLED_TOOLS

   # Unset them to reset
   unset NARSIL_EXPOSE NARSIL_DISABLED_TOOLS
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
   ls -la ~/.config/narsil-xref/config.yaml

   # macOS (alternative)
   ls -la ~/Library/Application\ Support/narsil-xref/config.yaml

   # Windows
   dir %APPDATA%\narsil-xref\config.yaml
   ```

2. Validate config syntax:
   ```bash
   narsil-xref config validate ~/.config/narsil-xref/config.yaml
   ```

3. Check for YAML errors:
   - Ensure proper indentation (spaces, not tabs)
   - Check for missing colons
   - Ensure quotes around strings with special characters

4. Check config priority:
   - Environment variables override config files
   - CLI flags override everything
   - Use `narsil-xref config show` to see effective configuration

### Config File Validation Errors

**Problem:** Config validation fails with errors

**Common errors and fixes:**

1. Missing `version` field:
   ```yaml
   # Add this at the top
   version: "1.0"
   ```

2. Missing required fields:
   ```yaml
   # Tools must have this structure:
   tools:
     overrides: {}
   ```

3. Invalid YAML syntax:
   ```bash
   # Use a YAML validator
   yamllint ~/.config/narsil-xref/config.yaml
   ```

## See Also

- [Migration Guide](./migration.md) - Upgrading from previous versions
- [Example Configurations](../examples/configs/README.md) - Ready-to-use config templates
- [README](../README.md) - Main project documentation
- [Tool Reference](../README.md#mcp-tools-90-total) - Complete tool documentation
