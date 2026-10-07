#!/usr/bin/env node
// Test the published package shape and command without network or global installs.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { copyFileSync, chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), "../npm");
const npmCli = process.env.npm_execpath;
assert(npmCli, "Run this check with npm --prefix npm test");
const root = mkdtempSync(join(tmpdir(), "narsil-npm-package-"));
const prefix = join(root, "consumer");
mkdirSync(prefix);
for (const name of ["user.npmrc", "global.npmrc"]) writeFileSync(join(root, name), "");
const config = ["--cache", join(root, "cache"), "--userconfig", join(root, "user.npmrc"),
  "--globalconfig", join(root, "global.npmrc"), "--no-audit", "--no-fund"];
const env = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
  !name.toLowerCase().startsWith("npm_") && !["path", "node_auth_token", "node_options"].includes(name.toLowerCase())));
const executableDirs = [dirname(process.execPath), ...(process.platform === "win32"
  ? [join(process.env.SystemRoot, "System32"), process.env.SystemRoot] : ["/usr/bin", "/bin"])];
env.PATH = executableDirs.join(delimiter);
assert(!executableDirs.some((dir) => ["narsil-mcp", "narsil-mcp.exe", "narsil-mcp.cmd"].some((name) => existsSync(join(dir, name)))), "test PATH must not contain a fallback command");

function run(command, args, cwd = prefix, input) {
  const result = spawnSync(command, args, { cwd, env, encoding: "utf8", input, timeout: 30000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${command} failed: ${result.stderr}\n${result.stdout}`);
  return result.stdout.trim();
}
const npm = (args, cwd) => run(process.execPath, [npmCli, ...config, ...args], cwd);

async function checkForwardedSignal(launcher) {
  const child = spawn(process.execPath, [launcher, "-e", "console.log('ready'); setTimeout(() => process.exit(99), 10000)"], {
    stdio: ["ignore", "pipe", "pipe"], detached: true,
  });
  const completion = once(child, "close");
  let timer;
  try {
    const ready = once(child.stdout, "data");
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("signal check timed out")), 5000); });
    await Promise.race([ready, timeout]);
    child.kill("SIGTERM");
    const [code, signal] = await Promise.race([completion, timeout]);
    assert.equal(code, null);
    assert.equal(signal, "SIGTERM");
  } finally {
    clearTimeout(timer);
    try { process.kill(-child.pid, "SIGKILL"); } catch (error) { if (error.code !== "ESRCH") throw error; }
    if (child.exitCode === null && child.signalCode === null) await completion;
    child.stdout.destroy();
    child.stderr.destroy();
  }
}

try {
  const packed = JSON.parse(npm(["pack", "--ignore-scripts", "--json", "--pack-destination", root], packageDir))[0];
  const manifest = JSON.parse(readFileSync(join(packageDir, "package.json")));
  const binTarget = manifest.bin["narsil-mcp"];
  assert(packed.files.some(({ path }) => path === binTarget), "npm tarball must include its declared bin target before postinstall");
  npm(["install", "--offline", "--ignore-scripts", "--package-lock=false", join(root, packed.filename)]);
  const installed = join(prefix, "node_modules/narsil-mcp");
  const launcher = join(installed, binTarget);
  const entry = join(prefix, "node_modules/.bin", process.platform === "win32" ? "narsil-mcp.cmd" : "narsil-mcp");
  assert(existsSync(entry), "clean npm install must create the command entry");
  const missing = spawnSync(process.execPath, [launcher, "--version"], { encoding: "utf8", timeout: 5000 });
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /native executable/i);

  // Node itself is an inert, cross-platform executable for exercising the shim.
  const vendor = join(installed, "vendor");
  mkdirSync(vendor);
  const binary = join(vendor, process.platform === "win32" ? "narsil-mcp.exe" : "narsil-mcp");
  if (process.platform === "win32") {
    copyFileSync(process.execPath, binary);
  } else {
    // Homebrew Node uses relative dylib paths, so don't relocate its executable.
    const quotedNode = `'${process.execPath.replaceAll("'", "'\\''")}'`;
    writeFileSync(binary, `#!/bin/sh\nexec ${quotedNode} "$@"\n`);
  }
  chmodSync(binary, 0o755);
  assert.equal(npm(["exec", "--offline", "--no", "--", "narsil-mcp", "--version"]), process.version);
  const args = ["space value", "literal;value", "quote'\"value"];
  assert.deepEqual(JSON.parse(run(process.execPath, [launcher, "-e", "console.log(JSON.stringify(process.argv.slice(1)))", "--", ...args])), args);
  assert.equal(run(process.execPath, [launcher, "-e", "process.stdin.pipe(process.stdout)"], prefix, "stdio payload\n"), "stdio payload");
  const nonzero = spawnSync(process.execPath, [launcher, "-e", "process.stderr.write('expected stderr'); process.exit(23)"], { encoding: "utf8", timeout: 5000 });
  assert.equal(nonzero.status, 23);
  assert.equal(nonzero.stderr, "expected stderr");
  if (process.platform !== "win32") {
    const signaled = spawnSync(process.execPath, [launcher, "-e", "process.kill(process.pid, 'SIGTERM')"], { timeout: 5000 });
    assert.equal(signaled.signal, "SIGTERM");
    await checkForwardedSignal(launcher);
  }
  const repacked = JSON.parse(npm(["pack", "--ignore-scripts", "--json", "--pack-destination", root], installed))[0];
  assert(!repacked.files.some(({ path }) => path.startsWith("vendor/")), "npm pack must exclude downloaded platform-specific bytes");
  assert(repacked.files.some(({ path }) => path === binTarget));
  console.log("PASS packed launcher, clean npm command, missing-runtime error, argv/stdio/exit, signals (Unix), and portable repack");
} finally {
  rmSync(root, { recursive: true, force: true });
}
