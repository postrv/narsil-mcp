#!/usr/bin/env node

/**
 * Post-install script for narsil-mcp npm package
 * Downloads pre-built binary from GitHub releases
 */

const https = require("https");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const zlib = require("zlib");

const PACKAGE_VERSION = require("./package.json").version;
const REPO = "postrv/narsil-mcp";
const BINARY_NAME = process.platform === "win32" ? "narsil-mcp.exe" : "narsil-mcp";

// Map Node.js platform/arch to Rust target artifacts
function getTargetInfo() {
  const platform = process.platform;
  const arch = process.arch;

  const targets = {
    "darwin-x64": {
      artifact: "macos-x86_64",
      extension: "tar.gz",
    },
    "darwin-arm64": {
      artifact: "macos-aarch64",
      extension: "tar.gz",
    },
    "linux-x64": {
      artifact: "linux-x86_64",
      extension: "tar.gz",
    },
    "linux-arm64": {
      artifact: "linux-aarch64",
      extension: "tar.gz",
    },
    "win32-x64": {
      artifact: "windows-x86_64",
      extension: "zip",
    },
  };

  const key = `${platform}-${arch}`;
  const target = targets[key];

  if (!target) {
    console.error(`Unsupported platform: ${platform}-${arch}`);
    console.error("Supported platforms: darwin-x64, darwin-arm64, linux-x64, linux-arm64, win32-x64");
    console.error("\nYou can build from source instead:");
    console.error("  cargo install narsil-mcp");
    process.exit(1);
  }

  return target;
}

// Download file with redirect handling
function download(url) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { headers: { "User-Agent": "narsil-mcp-npm" } }, (response) => {
      // Handle redirects
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        return download(response.headers.location).then(resolve).catch(reject);
      }

      if (response.statusCode !== 200) {
        reject(new Error(`Download failed: HTTP ${response.statusCode}`));
        return;
      }

      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve(Buffer.concat(chunks)));
      response.on("error", reject);
    });

    request.on("error", reject);
    request.setTimeout(60000, () => {
      request.destroy();
      reject(new Error("Download timeout"));
    });
  });
}

// Extract tar.gz archive
function extractTarGz(buffer, destDir) {
  const gunzip = zlib.createGunzip();
  const tarPath = path.join(destDir, "archive.tar");

  // Write decompressed data
  const decompressed = zlib.gunzipSync(buffer);
  fs.writeFileSync(tarPath, decompressed);

  // Extract using tar command (available on all platforms now)
  try {
    execSync(`tar -xf "${tarPath}" -C "${destDir}"`, { stdio: "pipe" });
    fs.unlinkSync(tarPath);
  } catch (err) {
    // Fallback: manual tar extraction for Node 18+
    const tar = require("child_process");
    throw new Error(`Failed to extract tar: ${err.message}`);
  }
}

// Extract zip archive (Windows)
function extractZip(buffer, destDir) {
  const zipPath = path.join(destDir, "archive.zip");
  fs.writeFileSync(zipPath, buffer);

  try {
    // Use PowerShell on Windows
    execSync(`powershell -Command "Expand-Archive -Force '${zipPath}' '${destDir}'"`, {
      stdio: "pipe",
    });
    fs.unlinkSync(zipPath);
  } catch (err) {
    throw new Error(`Failed to extract zip: ${err.message}`);
  }
}

async function main() {
  console.log(`Installing narsil-mcp v${PACKAGE_VERSION}...`);

  const target = getTargetInfo();
  const binDir = path.join(__dirname, "bin");
  const binaryPath = path.join(binDir, BINARY_NAME);

  // Create bin directory
  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }

  // Build download URL
  const assetName = `narsil-mcp-v${PACKAGE_VERSION}-${target.artifact}.${target.extension}`;
  const downloadUrl = `https://github.com/${REPO}/releases/download/v${PACKAGE_VERSION}/${assetName}`;

  console.log(`Downloading from: ${downloadUrl}`);

  try {
    const buffer = await download(downloadUrl);
    console.log(`Downloaded ${(buffer.length / 1024 / 1024).toFixed(2)} MB`);

    // Extract archive
    console.log("Extracting...");
    if (target.extension === "tar.gz") {
      extractTarGz(buffer, binDir);
    } else {
      extractZip(buffer, binDir);
    }

    // Make binary executable (Unix)
    if (process.platform !== "win32") {
      fs.chmodSync(binaryPath, 0o755);
    }

    // Verify binary works
    console.log("Verifying installation...");
    try {
      const version = execSync(`"${binaryPath}" --version`, { encoding: "utf8" }).trim();
      console.log(`Installed: ${version}`);
    } catch (verifyErr) {
      console.warn("Warning: Could not verify binary version");
    }

    // Print quick start guide
    printQuickStart();
  } catch (err) {
    console.error(`\nInstallation failed: ${err.message}`);
    console.error("\nAlternative installation methods:");
    console.error("  1. Shell installer:  curl -fsSL https://raw.githubusercontent.com/postrv/narsil-mcp/main/install.sh | bash");
    console.error("  2. Build from source: cargo install narsil-mcp");
    console.error("  3. Download manually: https://github.com/postrv/narsil-mcp/releases");
    process.exit(1);
  }
}

function printQuickStart() {
  console.log(`
================================================================================
                        narsil-mcp installed successfully!
================================================================================

QUICK START - Claude Code:

  1. Create .mcp.json in your project root:

     {
       "mcpServers": {
         "narsil-mcp": {
           "command": "npx",
           "args": ["narsil-mcp", "--repos", ".", "--git", "--call-graph"]
         }
       }
     }

  2. Start Claude Code in your project directory

ALTERNATIVE - Claude Desktop / Cursor / Windsurf:

  See: https://github.com/postrv/narsil-mcp#mcp-configuration

DOCUMENTATION: https://github.com/postrv/narsil-mcp
================================================================================
`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
