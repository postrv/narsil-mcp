# SSE Transport

The MCP HTTP+SSE transport lets a single persistent `narsil-mcp` process serve
multiple editor sessions simultaneously. Instead of each session spawning its
own subprocess and re-indexing from scratch, all sessions share one warm index.

## When to use SSE vs stdio

| Scenario | Transport |
|---|---|
| Single editor session, local project | `stdio` (default) |
| Multiple sessions sharing one index | `sse` |
| Remote server (SSH), multiple clients | `sse` |
| Editor only supports stdio | `stdio` (default) |

## Quick start

Start the server once, pointing it at the repositories to index:

```bash
narsil-mcp --transport sse --repos /path/to/project
```

Multiple repos:

```bash
narsil-mcp --transport sse --repos /path/to/repo1 --repos /path/to/repo2
```

`--sse-host` and `--sse-port` also implicitly activate SSE transport, so this
is equivalent:

```bash
narsil-mcp --sse-host localhost --repos /path/to/project
```

The server binds to `127.0.0.1:7557` by default and logs:

```
INFO narsil_mcp: Starting MCP SSE transport on http://127.0.0.1:7557/mcp/sse
```

## Connecting Claude Code

Add the server to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "narsil-mcp": {
      "type": "sse",
      "url": "http://localhost:7557/mcp/sse"
    }
  }
}
```

Or register it from the command line:

```bash
claude mcp add --transport sse narsil-mcp http://localhost:7557/mcp/sse
```

## Connecting Claude Desktop

In `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "narsil-mcp": {
      "type": "sse",
      "url": "http://localhost:7557/mcp/sse"
    }
  }
}
```

## Remote server (SSH)

When `narsil-mcp` runs on a remote host, forward the port locally:

```bash
ssh -L 7557:localhost:7557 user@remote-host
```

Then configure your local client to use `http://localhost:7557/mcp/sse` as
shown above. The tunnel keeps all traffic local on both ends.

Alternatively, run Claude Code on the remote host directly — it can reach the
SSE server at `http://localhost:7557/mcp/sse` without any port forwarding.

## Options reference

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--transport sse` | `NARSIL_TRANSPORT=sse` | `stdio` | Activate SSE transport |
| `--sse-host` | `NARSIL_SSE_HOST` | `127.0.0.1` | Bind address (loopback only) |
| `--sse-port` | `NARSIL_SSE_PORT` | `7557` | TCP port |
| `--sse-keepalive-secs` | `NARSIL_SSE_KEEPALIVE_SECS` | `15` | Keep-alive comment interval |
| `--repos` | `NARSIL_REPOS` | *(required in SSE mode)* | Repositories to index |

`--repos` is required in SSE mode. Passing `--sse-host` or `--sse-port`
without `--repos` will error with a clear message.

Only loopback addresses (`127.0.0.1`, `::1`, `localhost`) are accepted for
`--sse-host`. Network-facing binds are rejected — the SSE transport has no
authentication.

## Persistent indexing

Add `--persist` to save the index to disk so restarts are fast:

```bash
narsil-mcp --transport sse --repos /path/to/project --persist --git --call-graph
```

## Running as a systemd user unit

`bash setup.sh --systemd` installs the template unit `narsil-mcp@.service`,
whose instance name is a profile from `~/.config/narsil-mcp/config.yaml`:

```bash
systemctl --user enable --now narsil-mcp@dev
loginctl enable-linger $USER   # optional: start at boot, not at first login
```

The server logs to `~/.local/state/log/narsil-mcp/<profile>.log`
(`--log-file`). It moves the file to `<profile>.log.1` at every start and when
the file passes `--log-max-size` (default `10M`), and keeps `--log-keep`
(default 5) old files. systemd restarts the server when it exits with an
error. Change the command line with `systemctl --user edit narsil-mcp@dev`;
set `Environment=NARSIL_LOG_MAX_SIZE=...` there for one instance only.

### Socket activation

`narsil-mcp@.socket` makes systemd hold `127.0.0.1:7557`: the first connection
starts `narsil-mcp@<profile>.service`, and a connection during a restart waits
instead of being refused:

```bash
systemctl --user enable --now narsil-mcp@dev.socket
```

The server then serves on the socket systemd passes and ignores `--sse-host`
and `--sse-port`. A second profile needs its own port: run
`systemctl --user edit narsil-mcp@work.socket`, add an empty `ListenStream=`
line, then `ListenStream=127.0.0.1:7558`. `Environment=` does not apply to a
socket unit.

## Memory watchdog

An SSE server checks its RSS every 10 s against two limits:

- `--memory-soft-limit` (default `1.5x`): writes a `memory-<pid>-<time>.diag`
  file next to `--log-file` (else `~/.local/state/narsil-mcp/`), then logs a
  per-subsystem memory summary every `--memory-soft-limit-interval-secs`
  (default 300) while RSS stays above it.
- `--memory-hard-limit` (default `2x`): writes the `.diag` file, shuts the
  server down and exits with code 75; the systemd unit restarts it.

A limit is `off`, `<N>x` (times the RSS after the last full index pass),
`<N>M` or `<N>G`. Before the first full index pass an `<N>x` soft limit is not
checked and an `<N>x` hard limit is half of MemTotal. Set machine-wide values in
`~/.config/narsil-mcp/config.yaml`:

```yaml
memory_soft_limit: 48G
memory_hard_limit: 64G
memory_soft_limit_interval_secs: 300
```

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/mcp/sse` | Open SSE stream (MCP HTTP+SSE spec 2024-11-05) |
| `POST` | `/mcp/message` | Send JSON-RPC request to a session |
| `GET` | `/health` | Health check |
