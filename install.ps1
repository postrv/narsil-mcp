<#
.SYNOPSIS
    narsil-mcp Windows installer

.DESCRIPTION
    One-click installation for narsil-mcp MCP server on Windows.
    Downloads pre-built binary from GitHub releases and configures PATH.

.PARAMETER FromSource
    Build from source instead of downloading pre-built binary

.PARAMETER Force
    Force reinstallation even if already installed

.PARAMETER InstallDir
    Custom installation directory (default: $env:LOCALAPPDATA\Programs\narsil-mcp)

.EXAMPLE
    irm https://raw.githubusercontent.com/postrv/narsil-mcp/main/install.ps1 | iex

.EXAMPLE
    .\install.ps1 -FromSource

.EXAMPLE
    .\install.ps1 -Force -InstallDir "C:\Tools\narsil-mcp"
#>

[CmdletBinding()]
param(
    [switch]$FromSource,
    [switch]$Force,
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\narsil-mcp"
)

$ErrorActionPreference = "Stop"

# Configuration
$Repo = "postrv/narsil-mcp"
$BinaryName = "narsil-mcp.exe"

# Colors for output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-ColorOutput $Message "Green" }
function Write-Info { param([string]$Message) Write-ColorOutput $Message "Cyan" }
function Write-Warning { param([string]$Message) Write-ColorOutput $Message "Yellow" }
function Write-Error { param([string]$Message) Write-ColorOutput $Message "Red" }

# Banner
function Show-Banner {
    Write-Success ""
    Write-Success "╔════════════════════════════════════════════╗"
    Write-Success "║       narsil-mcp installer                 ║"
    Write-Success "║   Blazing-fast MCP server for code intel   ║"
    Write-Success "╚════════════════════════════════════════════╝"
    Write-Success ""
}

# Detect architecture
# NOTE: ARM64 Windows is detected but no pre-built binary exists yet.
# ARM64 users will fall back to source build. To add ARM64 support,
# add aarch64-pc-windows-msvc target to .github/workflows/build-binaries.yml
function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "x86_64" }
        "ARM64" { return "aarch64" }
        default {
            Write-Error "Unsupported architecture: $arch"
            exit 1
        }
    }
}

# Get latest release version
function Get-LatestVersion {
    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -ErrorAction Stop
        return $response.tag_name
    }
    catch {
        Write-Warning "Could not fetch latest version from GitHub API"
        return $null
    }
}

# Cargo bin directory for source installs
$CargoBinDir = "$env:USERPROFILE\.cargo\bin"

# Check if already installed (checks both binary install dir and cargo bin)
function Test-Installed {
    $binaryPath = Join-Path $InstallDir $BinaryName
    $cargoBinaryPath = Join-Path $CargoBinDir $BinaryName
    return (Test-Path $binaryPath) -or (Test-Path $cargoBinaryPath)
}

# Download and install binary
function Install-Binary {
    param(
        [string]$Version,
        [string]$Architecture
    )

    # Release assets are zip files named: narsil-mcp-v{VERSION}-windows-{ARCH}.zip
    $versionNumber = $Version.TrimStart('v')
    $artifactName = "narsil-mcp-v$versionNumber-windows-$Architecture.zip"
    $downloadUrl = "https://github.com/$Repo/releases/download/$Version/$artifactName"
    $tempZip = Join-Path $env:TEMP $artifactName
    $tempExtractDir = Join-Path $env:TEMP "narsil-mcp-extract"

    Write-Info "Downloading narsil-mcp $Version for Windows $Architecture..."
    Write-Info "URL: $downloadUrl"

    try {
        # Download with progress
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -ErrorAction Stop
        $ProgressPreference = 'Continue'
    }
    catch {
        Write-Warning "Pre-built binary not available"
        Write-Info "Error: $_"
        return $false
    }

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Extract zip file
    Write-Info "Extracting archive..."
    if (Test-Path $tempExtractDir) {
        Remove-Item -Path $tempExtractDir -Recurse -Force
    }
    Expand-Archive -Path $tempZip -DestinationPath $tempExtractDir -Force

    # Install binary
    $extractedBinary = Join-Path $tempExtractDir $BinaryName
    $binaryPath = Join-Path $InstallDir $BinaryName
    Move-Item -Path $extractedBinary -Destination $binaryPath -Force

    # Cleanup
    Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $tempExtractDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Success "Installed narsil-mcp to $binaryPath"
    return $true
}

# Check for Visual Studio Build Tools
function Test-MSVCInstalled {
    # Check for vswhere.exe
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vsPath) {
            return $true
        }
    }

    # Check for cl.exe in PATH
    try {
        $null = Get-Command cl.exe -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# Install from source
function Install-FromSource {
    Write-Info "Installing from source..."

    # Check for cargo
    try {
        $null = Get-Command cargo -ErrorAction Stop
    }
    catch {
        Write-Warning "Rust not found. Installing Rust..."
        Write-Info "Downloading rustup-init.exe..."

        $rustupUrl = "https://win.rustup.rs/x86_64"
        $rustupPath = Join-Path $env:TEMP "rustup-init.exe"

        Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupPath

        Write-Info "Running Rust installer..."
        & $rustupPath -y --default-toolchain stable

        # Refresh environment
        $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    }

    # Check for MSVC Build Tools
    if (-not (Test-MSVCInstalled)) {
        Write-Error "Visual Studio Build Tools not found!"
        Write-Warning ""
        Write-Warning "You need to install Visual Studio Build Tools to compile Rust programs."
        Write-Warning ""
        Write-Warning "Download from: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022"
        Write-Warning ""
        Write-Warning "In the installer, select 'Desktop development with C++'."
        Write-Warning "After installation, restart your terminal and run this script again."
        exit 1
    }

    Write-Info "Building narsil-mcp (this may take a few minutes)..."

    try {
        cargo install --git "https://github.com/$Repo" --locked --force
        Write-Success "Installed narsil-mcp via cargo"
        return $true
    }
    catch {
        Write-Error "Failed to build from source: $_"
        return $false
    }
}

# Add to PATH
function Add-ToPath {
    param(
        [switch]$FromSource
    )

    $targetDir = if ($FromSource) { $CargoBinDir } else { $InstallDir }

    # Check if already in PATH
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -like "*$targetDir*") {
        Write-Info "Install directory already in PATH"
        return
    }

    # Add to user PATH
    $newPath = "$userPath;$targetDir"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")

    # Also update current session
    $env:PATH = "$env:PATH;$targetDir"

    Write-Success "Added $targetDir to PATH"
    Write-Info "Restart your terminal to use 'narsil-mcp' command"
}

# Configure Claude Desktop
function Configure-ClaudeDesktop {
    $claudeConfigPath = "$env:APPDATA\Claude\claude_desktop_config.json"

    if (Test-Path $claudeConfigPath) {
        Write-Success "Found Claude Desktop"

        $config = Get-Content $claudeConfigPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue

        if ($config.mcpServers."narsil-mcp") {
            Write-Success "Claude Desktop already configured!"
        }
        else {
            Write-Warning ""
            Write-Warning "To configure Claude Desktop, add this to:"
            Write-Warning $claudeConfigPath
            Write-Info @"
{
  "mcpServers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
      "args": ["--repos", "C:\\path\\to\\your\\projects"]
    }
  }
}
"@
        }
    }
}

# Configure VS Code
function Configure-VSCode {
    if (Get-Command code -ErrorAction SilentlyContinue) {
        Write-Success "Found VS Code"
        Write-Warning ""
        Write-Warning "To configure VS Code with Copilot, create .vscode/mcp.json in your workspace:"
        Write-Info @"
{
  "servers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
      "args": ["--repos", "`${workspaceFolder}"]
    }
  }
}
"@
    }
}

# Configure Cursor
function Configure-Cursor {
    if (Get-Command cursor -ErrorAction SilentlyContinue) {
        Write-Success "Found Cursor"
        Write-Warning ""
        Write-Warning "To configure Cursor, create .cursor/mcp.json in your project:"
        Write-Info @"
{
  "mcpServers": {
    "narsil-mcp": {
      "command": "narsil-mcp",
      "args": ["--repos", "."]
    }
  }
}
"@
    }
}

# Main installation
function Main {
    Show-Banner

    # Check if already installed
    if ((Test-Installed) -and (-not $Force)) {
        Write-Warning "narsil-mcp is already installed at $InstallDir or $CargoBinDir"
        Write-Info "Use -Force to reinstall"
        exit 0
    }

    $arch = Get-Architecture
    Write-Info "Detected architecture: $arch"

    $success = $false
    $installedFromSource = $false

    if ($FromSource) {
        $success = Install-FromSource
        $installedFromSource = $success
    }
    else {
        $version = Get-LatestVersion

        if ($version) {
            Write-Info "Latest version: $version"
            $success = Install-Binary -Version $version -Architecture $arch
        }

        if (-not $success) {
            Write-Warning "Falling back to source build..."
            $success = Install-FromSource
            $installedFromSource = $success
        }
    }

    if (-not $success) {
        Write-Error "Installation failed"
        exit 1
    }

    if ($installedFromSource) {
        Add-ToPath -FromSource
    } else {
        Add-ToPath
    }

    Write-Info ""
    Write-Info "Checking for AI coding assistants..."
    Configure-ClaudeDesktop
    Configure-VSCode
    Configure-Cursor

    Write-Success ""
    Write-Success "╔════════════════════════════════════════════╗"
    Write-Success "║          Installation complete!            ║"
    Write-Success "╚════════════════════════════════════════════╝"
    Write-Success ""
    Write-Info "Quick start:"
    Write-Info "  1. Restart your terminal (or run: `$env:PATH = [System.Environment]::GetEnvironmentVariable('Path','User'))"
    Write-Info "  2. Run: narsil-mcp --repos C:\path\to\your\project"
    Write-Info "  3. Configure your AI assistant (see above)"
    Write-Info ""
    Write-Info "For full documentation, visit:"
    Write-Info "  https://github.com/$Repo"
    Write-Success ""
}

# Run main
try {
    Main
}
catch {
    Write-Error "Installation failed: $_"
    Write-Error $_.ScriptStackTrace
    exit 1
}
