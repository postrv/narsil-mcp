# Installation Guide

Prebuilt binaries are released for Linux only, on x86_64 and aarch64.

## Quick Install

**Install script** (downloads the latest release into `~/.local/bin`):
```bash
curl -fsSL https://raw.githubusercontent.com/bsbernd/narsil-xref/main/install.sh | bash
```

When no release is found, the script builds from source with cargo.

## Verification

After installation, verify it works:

```bash
narsil-xref --version
# Should output the installed narsil-xref version
```

## Next Steps

See [README.md](../README.md) for usage instructions and AI assistant configuration.

## Building from Source

```bash
# Clone the repository
git clone https://github.com/bsbernd/narsil-xref.git
cd narsil-xref

# Build and install to ~/.local/bin
bash setup.sh

# Also install the systemd user units for the SSE server
bash setup.sh --systemd
```

## Troubleshooting

### Build Issues

If the build fails:
1. Update Rust: `rustup update stable`
2. Check Rust version: `rustc --version`
3. Clear cargo cache: `cargo clean`

## Updating

Run the install script or `bash setup.sh` again.

## Uninstalling

```bash
rm ~/.local/bin/narsil-xref
```
