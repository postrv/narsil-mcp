# Example Configurations

This directory contains example configuration files for different use cases.

## Workspace Profiles

The example below demonstrates the `profiles:` block — named,
`--profile`-selectable groups of repositories with per-repo and per-group
backend tuning.

### Per-Repo Backend Tuning (`backend-tuning.yaml`)
**Use case:** A multi-repo workspace where C/C++ indexing memory must be bounded
per repository.

**Demonstrates:**
- Profile-group defaults for the `clangd`, `ccls`, and `gtags` backends,
  inherited by every repo in the profile
- Per-repo overrides that win field by field over the group default
- Disabling both language servers for a huge tree (tree-sitter + gtags only)
- Capping ccls indexer threads and resident caches, and throttling clangd `-j`
- `index_filter` / `lsp_scope` scoping and bare-path inheritance

**Usage:**
```bash
# Copy to user config, then edit the repo paths
cp examples/configs/backend-tuning.yaml ~/.config/narsil-xref/config.yaml

# Select the profile at startup
narsil-xref --profile dev
```

See [Per-repo and per-group backend tuning](../../docs/configuration.md#per-repo-and-per-group-backend-tuning)
for the full field reference.

---

## Configuration Priority

Configurations are loaded with the following priority (highest to lowest):

1. **CLI flags** (`--git`, `--call-graph`, etc.)
2. **Environment variables** (`NARSIL_EXPOSE`, `NARSIL_DISABLED_TOOLS`, etc.)
3. **Project config** (`.narsil.yaml` in repository root)
4. **User config** (`~/.config/narsil-xref/config.yaml`)
5. **Default config** (built-in)

## See Also

- [Configuration Guide](../../docs/configuration.md) - Full configuration documentation
- [Migration Guide](../../docs/migration.md) - Upgrading from previous versions
- [README](../../README.md) - Main project documentation
