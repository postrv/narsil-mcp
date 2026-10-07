#!/usr/bin/env node

// This file must be present in the package before npm creates command shims.
const { spawn } = require("node:child_process");
const path = require("node:path");

const binary = path.join(__dirname, "..", "vendor", process.platform === "win32" ? "narsil-mcp.exe" : "narsil-mcp");
const child = spawn(binary, process.argv.slice(2), { stdio: "inherit" });
const forwards = new Map(["SIGINT", "SIGTERM", "SIGHUP"].map((signal) => [signal, () => child.kill(signal)]));
for (const [signal, forward] of forwards) process.on(signal, forward);
let failed = false;

child.on("error", (error) => {
  failed = true;
  console.error(`Unable to start narsil-mcp native executable: ${error.message}`);
  console.error("Reinstall narsil-mcp with npm install scripts enabled.");
  process.exitCode = 1;
});

child.on("close", (code, signal) => {
  for (const [name, forward] of forwards) process.removeListener(name, forward);
  if (failed) {
    process.exitCode = 1;
  } else if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exitCode = code === null ? 1 : code;
  }
});
