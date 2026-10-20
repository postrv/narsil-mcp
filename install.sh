#!/usr/bin/env bash
#
# narsil-xref installer
# One-click installation for narsil-xref MCP server
#
# Usage: curl -fsSL https://raw.githubusercontent.com/bsbernd/narsil-xref/main/install.sh | bash
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="bsbernd/narsil-xref"
BINARY_NAME="narsil-xref"
INSTALL_DIR="${HOME}/.local/bin"

# Detect platform
detect_platform() {
    local os arch

    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    case "$os" in
        linux)
            os="linux"
            ;;
        *)
            echo -e "${RED}Error: Unsupported operating system: $os${NC}"
            echo -e "${YELLOW}Only Linux binaries are released.${NC}"
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64|amd64)
            arch="x86_64"
            ;;
        arm64|aarch64)
            arch="aarch64"
            ;;
        *)
            echo -e "${RED}Error: Unsupported architecture: $arch${NC}"
            exit 1
            ;;
    esac

    echo "${os}-${arch}"
}

# Get latest release version
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | \
        grep '"tag_name"' | \
        sed -E 's/.*"tag_name": "([^"]+)".*/\1/' || echo ""
}

# Download and install
install_binary() {
    local platform="$1"
    local version="$2"
    local tmpdir

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    echo -e "${BLUE}Downloading narsil-xref ${version} for ${platform}...${NC}"

    local download_url="https://github.com/${REPO}/releases/download/${version}/narsil-xref-${version}-${platform}.tar.gz"

    if ! curl -fsSL "$download_url" -o "$tmpdir/narsil-xref.tar.gz" 2>/dev/null; then
        echo -e "${YELLOW}Pre-built binary not available. Building from source...${NC}"
        install_from_source
        return
    fi

    echo -e "${BLUE}Extracting...${NC}"
    tar -xzf "$tmpdir/narsil-xref.tar.gz" -C "$tmpdir"

    # Create install directory if needed
    mkdir -p "$INSTALL_DIR"

    # Install binary
    mv "$tmpdir/${BINARY_NAME}" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/${BINARY_NAME}"

    echo -e "${GREEN}Installed narsil-xref to ${INSTALL_DIR}/${NC}"
}

# Install from source using cargo
install_from_source() {
    local features="${1:-}"
    echo -e "${BLUE}Installing from source...${NC}"

    if ! command -v cargo &> /dev/null; then
        echo -e "${YELLOW}Rust not found. Installing Rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env"
    fi

    echo -e "${BLUE}Building narsil-xref (this may take a few minutes)...${NC}"
    if [ -n "$features" ]; then
        echo -e "${BLUE}Features: ${features}${NC}"
        cargo install --git "https://github.com/${REPO}" --locked --features "$features"
    else
        cargo install --git "https://github.com/${REPO}" --locked
    fi

    echo -e "${GREEN}Installed narsil-xref via cargo${NC}"
}

# Ask about features
ask_features() {
    echo ""
    echo -e "${BLUE}Would you like to include the visualization frontend?${NC}"
    echo "  1) No  - MCP server only (smaller binary, ~30MB)"
    echo "  2) Yes - Include web visualization UI (~31MB)"
    echo ""
    read -rp "Choice [1]: " choice
    case "$choice" in
        2|y|Y|yes|Yes)
            echo "frontend"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Configure shell PATH
configure_path() {
    local shell_rc=""
    local path_line="export PATH=\"\$PATH:${INSTALL_DIR}\""

    case "$SHELL" in
        */bash)
            shell_rc="$HOME/.bashrc"
            ;;
        */zsh)
            shell_rc="$HOME/.zshrc"
            ;;
        */fish)
            shell_rc="$HOME/.config/fish/config.fish"
            path_line="set -gx PATH \$PATH ${INSTALL_DIR}"
            ;;
    esac

    if [ -n "$shell_rc" ] && ! grep -q "narsil-xref" "$shell_rc" 2>/dev/null; then
        {
            echo ""
            echo "# narsil-xref"
            echo "$path_line"
        } >> "$shell_rc"
        echo -e "${BLUE}Added ${INSTALL_DIR} to PATH in ${shell_rc}${NC}"
    fi
}

# Detect and configure IDE
configure_ide() {
    echo ""
    echo -e "${BLUE}Checking for AI coding assistants...${NC}"

    # Claude Desktop
    local claude_config=""
    if [ -d "$HOME/.config/Claude" ]; then
        claude_config="$HOME/.config/Claude/claude_desktop_config.json"
    fi

    if [ -n "$claude_config" ]; then
        echo -e "${GREEN}Found Claude Desktop${NC}"
        if [ ! -f "$claude_config" ] || ! grep -q "narsil-xref" "$claude_config" 2>/dev/null; then
            echo -e "${YELLOW}To configure Claude Desktop, add this to ${claude_config}:${NC}"
            cat << 'EOF'
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": ["--repos", "/path/to/your/projects"]
    }
  }
}
EOF
        else
            echo -e "${GREEN}Claude Desktop already configured!${NC}"
        fi
    fi

    # Cursor
    if command -v cursor &> /dev/null; then
        echo -e "${GREEN}Found Cursor${NC}"
        echo -e "${YELLOW}To configure Cursor, create .cursor/mcp.json in your project:${NC}"
        cat << 'EOF'
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": ["--repos", "."]
    }
  }
}
EOF
    fi

    # VS Code
    if command -v code &> /dev/null; then
        echo -e "${GREEN}Found VS Code${NC}"
        echo -e "${YELLOW}To configure VS Code with Copilot, create .vscode/mcp.json in your workspace:${NC}"
        cat << 'EOF'
{
  "servers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": ["--repos", "${workspaceFolder}"]
    }
  }
}
EOF
    fi
}

# Main installation
main() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       narsil-xref installer                 ║${NC}"
    echo -e "${GREEN}║   Blazing-fast MCP server for code intel   ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
    echo ""

    local platform
    platform=$(detect_platform)
    echo -e "${BLUE}Detected platform: ${platform}${NC}"

    local version
    version=$(get_latest_version)

    if [ -n "$version" ]; then
        echo -e "${BLUE}Latest version: ${version}${NC}"
        install_binary "$platform" "$version"
    else
        echo -e "${YELLOW}No releases found. Building from source...${NC}"
        local features
        features=$(ask_features)
        install_from_source "$features"
    fi

    configure_path
    configure_ide

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║               Installation complete!                          ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}VERIFY INSTALLATION:${NC}"
    echo "  \$ narsil-xref --version"
    echo ""
    echo -e "${BLUE}QUICK START - Claude Code:${NC}"
    echo "  1. Restart your terminal (or run: source ~/.bashrc)"
    echo ""
    echo "  2. Create .mcp.json in your project root:"
    echo '     {"mcpServers":{"narsil-xref":{"command":"narsil-xref","args":["--repos",".","--git"]}}}'
    echo ""
    echo "  3. Start Claude Code in your project:"
    echo "     \$ cd /path/to/project && claude"
    echo ""
    echo -e "${BLUE}ALTERNATIVE - Claude Desktop / Cursor / VS Code:${NC}"
    echo "  See: https://github.com/${REPO}#mcp-configuration"
    echo ""
    echo -e "${BLUE}NEED HELP?${NC}"
    echo "  Documentation: https://github.com/${REPO}"
    echo ""
}

main "$@"
