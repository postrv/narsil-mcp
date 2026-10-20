#!/bin/bash
# Setup script for narsil-mcp
set -e

INSTALL_SYSTEMD=no
if [ "$#" -gt 0 ]; then
    if [ "$1" = "--systemd" ]; then
        INSTALL_SYSTEMD=yes
    else
        echo "usage: $0 [--systemd]" >&2
        exit 1
    fi
fi

install_systemd_units()
{
    config_home="$HOME/.config"
    if [ -n "${XDG_CONFIG_HOME}" ]; then
        config_home="${XDG_CONFIG_HOME}"
    fi
    unit_dir="${config_home}/systemd/user"

    mkdir -p "${unit_dir}"
    cp contrib/systemd/narsil-mcp@.service contrib/systemd/narsil-mcp@.socket "${unit_dir}/"
    systemctl --user daemon-reload

    echo "✅ Installed the systemd user units to ${unit_dir}"
    echo "  # Start the SSE server for a config.yaml profile, e.g. dev, on the first connection:"
    echo "  systemctl --user enable --now narsil-mcp@dev.socket"
    echo "  # Or start it at once:"
    echo "  systemctl --user enable --now narsil-mcp@dev"
    echo "  # Start it at boot instead of at your first login:"
    echo "  loginctl enable-linger $USER"
}

echo "🦀 Setting up narsil-mcp..."

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "📦 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

# Build release binary
echo "🔨 Building release binary..."
cargo build --release

# Create symlink in PATH (optional)
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "⚠️  Adding $INSTALL_DIR to PATH in your shell config..."
    # shellcheck disable=SC2016  # Single quotes intentional - we want $HOME to expand at runtime
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
fi

# delete first to avoid ETXTBSY if narsil-mcp is running
rm -f "$INSTALL_DIR/narsil-mcp" 
cp target/release/narsil-mcp "$INSTALL_DIR/"
echo "✅ Installed to $INSTALL_DIR/narsil-mcp"

if [ "${INSTALL_SYSTEMD}" = yes ]; then
    install_systemd_units
fi

# Print usage
echo ""
echo "🎉 Setup complete! Usage:"
echo ""
echo "  # Index a repository"
echo "  narsil-mcp --repos /path/to/your/project"
echo ""
echo "  # Add to Claude Desktop config:"
cat << EOF
  {
    "mcpServers": {
      "narsil-mcp": {
        "command": "${INSTALL_DIR}/narsil-mcp",
        "args": ["--repos", "/path/to/your/projects"]
      }
    }
  }
EOF
