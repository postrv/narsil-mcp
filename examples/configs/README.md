# Example Configurations

This directory contains example configuration files for different use cases.

## Available Presets

### 1. Minimal (`minimal.yaml`)
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
# Copy to user config
cp examples/configs/minimal.yaml ~/.config/narsil-mcp/config.yaml

# Or use environment variable
export NARSIL_PRESET=minimal
```

---

### 2. Balanced (`balanced.yaml`)
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
# Copy to user config
cp examples/configs/balanced.yaml ~/.config/narsil-mcp/config.yaml

# Or use environment variable
export NARSIL_PRESET=balanced

# Run with flags for full feature set
narsil-mcp --repos ~/project --git --call-graph
```

---

### 3. Full (`full.yaml`)
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
# Copy to user config
cp examples/configs/full.yaml ~/.config/narsil-mcp/config.yaml

# Or use environment variable
export NARSIL_PRESET=full

# Run with all flags for complete feature set
narsil-mcp --repos ~/project --git --call-graph --neural --remote
```

---

### 4. Security-Focused (`security-focused.yaml`)
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
# Copy to user config
cp examples/configs/security-focused.yaml ~/.config/narsil-mcp/config.yaml

# Or use environment variable
export NARSIL_PRESET=security-focused

# Run with git flag for tracking vulnerability history
narsil-mcp --repos ~/project --git
```

---

## Configuration Priority

Configurations are loaded with the following priority (highest to lowest):

1. **CLI flags** (`--git`, `--call-graph`, etc.)
2. **Environment variables** (`NARSIL_PRESET`, `NARSIL_DISABLED_TOOLS`, etc.)
3. **Project config** (`.narsil.yaml` in repository root)
4. **User config** (`~/.config/narsil-mcp/config.yaml`)
5. **Default config** (built-in)

## Customization

You can customize any preset by:

1. **Copying the example to your user config:**
   ```bash
   mkdir -p ~/.config/narsil-mcp
   cp examples/configs/balanced.yaml ~/.config/narsil-mcp/config.yaml
   ```

2. **Editing the config to your needs:**
   ```yaml
   # Enable additional tools
   tools:
     overrides:
       neural_search:
         enabled: true
         reason: "I have API key and want neural search"
   ```

3. **Using environment variables for quick overrides:**
   ```bash
   # Disable specific tools
   export NARSIL_DISABLED_TOOLS=neural_search,generate_sbom

   # Enable specific categories only
   export NARSIL_ENABLED_CATEGORIES=Repository,Symbols,Search
   ```

## Project-Specific Configs

Create a `.narsil.yaml` in your repository root for project-specific settings:

```bash
cd ~/my-project
cat > .narsil.yaml <<EOF
version: "1.0"
tools:
  categories:
    Security:
      enabled: true  # Always enable security scanning for this project
  overrides:
    generate_sbom:
      enabled: true  # This project requires SBOM generation
EOF
```

The project config will override your user config, allowing teams to share standard settings while preserving individual preferences.

## See Also

- [Configuration Guide](../../docs/configuration.md) - Full configuration documentation
- [Migration Guide](../../docs/migration.md) - Upgrading from previous versions
- [README](../../README.md) - Main project documentation
