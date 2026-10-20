#!/bin/bash
# Setup script for narsil-xref
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

CONFIG_HOME="$HOME/.config"
if [ -n "${XDG_CONFIG_HOME}" ]; then
    CONFIG_HOME="${XDG_CONFIG_HOME}"
fi

install_systemd_units()
{
    unit_dir="${CONFIG_HOME}/systemd/user"

    mkdir -p "${unit_dir}"
    cp contrib/systemd/narsil-xref@.service contrib/systemd/narsil-xref@.socket "${unit_dir}/"
    systemctl --user daemon-reload

    echo "✅ Installed the systemd user units to ${unit_dir}"
    echo "  # Start the SSE server for a config.yaml profile, e.g. dev, on the first connection:"
    echo "  systemctl --user enable --now narsil-xref@dev.socket"
    echo "  # Or start it at once:"
    echo "  systemctl --user enable --now narsil-xref@dev"
    echo "  # Start it at boot instead of at your first login:"
    echo "  loginctl enable-linger $USER"
}

print_rename_hints()
{
    if [ -d "${CONFIG_HOME}/narsil-mcp" ] && [ ! -e "${CONFIG_HOME}/narsil-xref" ]; then
        echo "⚠️  Move the old config directory:"
        echo "  mv ${CONFIG_HOME}/narsil-mcp ${CONFIG_HOME}/narsil-xref"
    fi

    old_unit_dir="${CONFIG_HOME}/systemd/user"
    if [ -f "${old_unit_dir}/narsil-mcp@.service" ]; then
        echo "⚠️  The narsil-mcp systemd units are still installed. Disable each instance listed here:"
        if ! systemctl --user list-units --all --plain --no-legend 'narsil-mcp@*'; then
            echo "  (systemctl --user cannot list the instances)"
        fi
        echo "  systemctl --user disable --now <instance>"
        echo "  rm ${old_unit_dir}/narsil-mcp@.service ${old_unit_dir}/narsil-mcp@.socket"
    fi
}

echo "🦀 Setting up narsil-xref..."

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

# delete first to avoid ETXTBSY if narsil-xref is running
rm -f "$INSTALL_DIR/narsil-xref" 
cp target/release/narsil-xref "$INSTALL_DIR/"
echo "✅ Installed to $INSTALL_DIR/narsil-xref"

if [ "${INSTALL_SYSTEMD}" = yes ]; then
    install_systemd_units
fi

print_rename_hints

# Print usage
echo ""
echo "🎉 Setup complete! Usage:"
echo ""
echo "  # Index a repository"
echo "  narsil-xref --repos /path/to/your/project"
echo ""
echo "  # Add to Claude Desktop config:"
cat << EOF
  {
    "mcpServers": {
      "narsil-xref": {
        "command": "${INSTALL_DIR}/narsil-xref",
        "args": ["--repos", "/path/to/your/projects"]
      }
    }
  }
EOF
