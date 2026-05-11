# Installation Guide

narsil-mcp can be installed via multiple package managers depending on your platform.

## Quick Install

### macOS / Linux

**Homebrew** (recommended):
```bash
brew tap postrv/narsil
brew install narsil-mcp
```

**Cargo** (requires Rust):
```bash
cargo install narsil-mcp
```

**npm** (requires Node.js):
```bash
npm install -g narsil-mcp
# or
yarn global add narsil-mcp
```

**Install script** (curl):
```bash
curl -fsSL https://raw.githubusercontent.com/postrv/narsil-mcp/main/install.sh | bash
```

### Windows

**Scoop** (recommended):
```powershell
scoop bucket add narsil https://github.com/postrv/scoop-narsil
scoop install narsil-mcp
```

> **Note:** Scoop installs a pre-built binary without optional features (ONNX neural embeddings, frontend visualization). For full features, build from source with `--all-features` or use Cargo install.

**Cargo** (requires Rust):
```bash
cargo install narsil-mcp
```

**npm** (requires Node.js):
```bash
npm install -g narsil-mcp
```

## Platform-Specific Instructions

### macOS

Supported architectures:
- Intel (x86_64)
- Apple Silicon (aarch64/M1/M2/M3/M4)

The Homebrew formula automatically detects your architecture.

### Linux

Supported distributions:
- Any distro with Homebrew for Linux
- Any distro with Cargo/Rust
- Direct binary install via `install.sh`
- npm on x86_64 and aarch64/ARM64

Supported binary architectures:
- x86_64
- aarch64/ARM64

Use Homebrew, npm, the install script, or Cargo on Linux.

### Windows

Supported architectures:
- x86_64 (64-bit)

Requires Windows 10 or later.

## Verification

After installation, verify it works:

```bash
narsil-mcp --version
# Should output the installed narsil-mcp version
```

## Next Steps

See [README.md](../README.md) for usage instructions and AI assistant configuration.

## Building from Source

If you prefer to build from source:

```bash
# Clone the repository
git clone https://github.com/postrv/narsil-mcp.git
cd narsil-mcp

# Build release binary
cargo build --release

# Install (optional)
cargo install --path .
```

### Build with Features

Optional features can be enabled at build time:

| Feature | Description |
|---------|-------------|
| `graph` | RDF knowledge graph, SPARQL, and CCG tools |
| `frontend` | Embedded web visualization frontend |
| `neural-onnx` | Local ONNX neural embeddings (no API key needed) |

```bash
# Build with SPARQL / Code Context Graph support
cargo build --release --features graph

# Build with frontend visualization
cargo build --release --features frontend

# Build with neural embeddings (ONNX) - local, no API key required
cargo build --release --features neural-onnx

# Build with multiple features
cargo build --release --features "graph frontend neural-onnx"

# Build with all features
cargo build --release --all-features
```

> **Pre-built binaries** (Homebrew, Scoop, npm, releases) include `native` + `graph` so `--graph` can expose SPARQL/CCG tools. For ONNX or frontend features, build from source.

## Troubleshooting

### Homebrew Installation Issues

If `brew install` fails:
1. Verify Homebrew is up to date: `brew update`
2. Check formula syntax: `brew audit narsil-mcp`
3. Try building from source as fallback

### Cargo Installation Issues

If `cargo install` fails:
1. Update Rust: `rustup update stable`
2. Check Rust version: `rustc --version` (requires 1.70+)
3. Clear cargo cache: `cargo clean`

### Windows Installation Issues

If install script fails on Windows:
1. Use the PowerShell version: `irm https://raw.githubusercontent.com/postrv/narsil-mcp/main/install.ps1 | iex`
2. Or use Scoop instead: `scoop install narsil-mcp`
3. Or build from source with cargo

### npm Installation Issues

If `npm install -g` fails:
1. Check Node.js version: `node --version` (requires 16+)
2. Try with sudo on macOS/Linux: `sudo npm install -g narsil-mcp`
3. Or install without global: `npm install narsil-mcp` (then use `npx narsil-mcp`)
4. Check platform support: macOS (Intel/ARM), Linux (x64/ARM64), Windows (x64)

## Updating

### Homebrew
```bash
brew update
brew upgrade narsil-mcp
```

### Scoop
```powershell
scoop update
scoop update narsil-mcp
```

### Cargo
```bash
cargo install narsil-mcp --force
```

### npm
```bash
npm update -g narsil-mcp
```

## Uninstalling

### Homebrew
```bash
brew uninstall narsil-mcp
brew untap postrv/narsil
```

### Scoop
```powershell
scoop uninstall narsil-mcp
scoop bucket rm narsil
```

### Cargo
```bash
cargo uninstall narsil-mcp
```

### npm
```bash
npm uninstall -g narsil-mcp
```
