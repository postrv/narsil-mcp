#!/usr/bin/env bash
#
# narsil-mcp installer
# One-click installation for narsil-mcp MCP server
#
# Usage: curl -fsSL https://raw.githubusercontent.com/postrv/narsil-mcp/main/install.sh | bash
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="postrv/narsil-mcp"
BINARY_NAME="narsil-mcp"
INSTALL_DIR="${HOME}/.local/bin"
IS_WINDOWS=false

# Detect platform
detect_platform() {
    local os arch

    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    case "$os" in
        darwin)
            os="macos"
            ;;
        linux)
            os="linux"
            ;;
        mingw*|msys*|cygwin*)
            os="windows"
            IS_WINDOWS=true
            BINARY_NAME="narsil-mcp.exe"
            INSTALL_DIR="${LOCALAPPDATA}/Programs/narsil-mcp"
            # Fallback if LOCALAPPDATA not set
            if [ -z "$INSTALL_DIR" ] || [ "$INSTALL_DIR" = "/Programs/narsil-mcp" ]; then
                INSTALL_DIR="${HOME}/AppData/Local/Programs/narsil-mcp"
            fi
            ;;
        *)
            echo -e "${RED}Error: Unsupported operating system: $os${NC}"
            echo -e "${YELLOW}Detected: $os${NC}"
            echo -e "${YELLOW}If you're on Windows, use the PowerShell installer:${NC}"
            echo -e "${YELLOW}  irm https://raw.githubusercontent.com/${REPO}/main/install.ps1 | iex${NC}"
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

    echo -e "${BLUE}Downloading narsil-mcp ${version} for ${platform}...${NC}"

    if [ "$IS_WINDOWS" = true ]; then
        # Windows: download .zip
        local artifact_name="narsil-mcp-${version}-windows-x86_64.zip"
        local download_url="https://github.com/${REPO}/releases/download/${version}/${artifact_name}"

        if ! curl -fsSL "$download_url" -o "$tmpdir/${artifact_name}" 2>/dev/null; then
            echo -e "${YELLOW}Pre-built binary not available. Building from source...${NC}"
            install_from_source
            return
        fi

        echo -e "${BLUE}Extracting...${NC}"
        unzip -q "$tmpdir/${artifact_name}" -d "$tmpdir"
    else
        # Unix: download and extract tar.gz
        local download_url="https://github.com/${REPO}/releases/download/${version}/narsil-mcp-${version}-${platform}.tar.gz"

        if ! curl -fsSL "$download_url" -o "$tmpdir/narsil-mcp.tar.gz" 2>/dev/null; then
            echo -e "${YELLOW}Pre-built binary not available. Building from source...${NC}"
            install_from_source
            return
        fi

        echo -e "${BLUE}Extracting...${NC}"
        tar -xzf "$tmpdir/narsil-mcp.tar.gz" -C "$tmpdir"
    fi

    # Create install directory if needed
    mkdir -p "$INSTALL_DIR"

    # Install binary
    mv "$tmpdir/${BINARY_NAME}" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/${BINARY_NAME}"

    echo -e "${GREEN}Installed narsil-mcp to ${INSTALL_DIR}/${NC}"
}

# Check for C compiler on Windows
check_windows_compiler() {
    if [ "$IS_WINDOWS" != true ]; then
        return 0
    fi

    # Check for cl.exe (MSVC) or gcc (MinGW)
    if command -v cl.exe &> /dev/null || command -v gcc &> /dev/null; then
        return 0
    fi

    echo -e "${RED}Error: C++ compiler not found!${NC}"
    echo -e "${YELLOW}You need Visual Studio Build Tools to compile Rust programs on Windows.${NC}"
    echo ""
    echo -e "${YELLOW}Download from:${NC}"
    echo "  https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022"
    echo ""
    echo -e "${YELLOW}In the installer, select 'Desktop development with C++'.${NC}"
    echo -e "${YELLOW}After installation, restart your terminal and run this script again.${NC}"
    echo ""
    echo -e "${YELLOW}Alternatively, use the PowerShell installer which provides better error messages:${NC}"
    echo -e "${YELLOW}  irm https://raw.githubusercontent.com/${REPO}/main/install.ps1 | iex${NC}"
    exit 1
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

    # Check for C compiler on Windows
    check_windows_compiler

    echo -e "${BLUE}Building narsil-mcp (this may take a few minutes)...${NC}"
    if [ -n "$features" ]; then
        echo -e "${BLUE}Features: ${features}${NC}"
        cargo install --git "https://github.com/${REPO}" --locked --features "$features"
    else
        cargo install --git "https://github.com/${REPO}" --locked
    fi

    echo -e "${GREEN}Installed narsil-mcp via cargo${NC}"
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

    if [ -n "$shell_rc" ] && ! grep -q "narsil-mcp" "$shell_rc" 2>/dev/null; then
        {
            echo ""
            echo "# narsil-mcp"
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
    if [ "$IS_WINDOWS" = true ]; then
        # Windows: %APPDATA%\Claude
        if [ -n "$APPDATA" ] && [ -d "$APPDATA/Claude" ]; then
            claude_config="$APPDATA/Claude/claude_desktop_config.json"
        elif [ -d "$HOME/AppData/Roaming/Claude" ]; then
            claude_config="$HOME/AppData/Roaming/Claude/claude_desktop_config.json"
        fi
    elif [ -d "$HOME/Library/Application Support/Claude" ]; then
        # macOS
        claude_config="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
    elif [ -d "$HOME/.config/Claude" ]; then
        # Linux
        claude_config="$HOME/.config/Claude/claude_desktop_config.json"
    fi

    if [ -n "$claude_config" ]; then
        echo -e "${GREEN}Found Claude Desktop${NC}"
        if [ ! -f "$claude_config" ] || ! grep -q "narsil-mcp" "$claude_config" 2>/dev/null; then
            echo -e "${YELLOW}To configure Claude Desktop, add this to ${claude_config}:${NC}"
            cat << 'EOF'
{
  "mcpServers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
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
    "narsil-mcp": {
      "command": "narsil-mcp",
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
    "narsil-mcp": {
      "command": "narsil-mcp",
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
    echo -e "${GREEN}║       narsil-mcp installer                 ║${NC}"
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
    echo "  \$ narsil-mcp --version"
    echo ""
    echo -e "${BLUE}QUICK START - Claude Code:${NC}"
    echo "  1. Restart your terminal (or run: source ~/.bashrc)"
    echo ""
    echo "  2. Create .mcp.json in your project root:"
    echo '     {"mcpServers":{"narsil-mcp":{"command":"narsil-mcp","args":["--repos",".","--git"]}}}'
    echo ""
    echo "  3. Start Claude Code in your project:"
    echo "     \$ cd /path/to/project && claude"
    echo ""
    echo -e "${BLUE}ALTERNATIVE - Claude Desktop / Cursor / VS Code:${NC}"
    echo "  See: https://github.com/${REPO}#mcp-configuration"
    echo ""
    echo -e "${BLUE}NEED HELP?${NC}"
    echo "  Documentation: https://github.com/${REPO}"
    echo "  Plugin: /plugin install github:postrv/narsil-mcp/narsil-plugin"
    echo ""
}

main "$@"
