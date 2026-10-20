//! Integration tests for the MCP HTTP+SSE transport.
//!
//! These tests spawn the narsil-xref binary with `--transport sse`, drive
//! the JSON-RPC protocol over HTTP, and observe responses on the SSE
//! stream. The smoke test covers the spec-required `endpoint` event and
//! one full request/response cycle. The isolation test exercises the
//! per-session `client_info` flow — guarding against a regression where
//! one session's `initialize` could overwrite another's editor identity.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

fn binary_path() -> PathBuf {
    let name = if cfg!(debug_assertions) {
        "target/debug/narsil-xref"
    } else {
        "target/release/narsil-xref"
    };
    PathBuf::from(name)
}

/// Bind ephemeral port and immediately release it. The subprocess that
/// comes up next is racing with anything else on the host; for a test
/// machine this is acceptable.
fn ephemeral_port() -> Result<u16> {
    let sock = TcpListener::bind("127.0.0.1:0")?;
    let port = sock.local_addr()?.port();
    drop(sock);
    Ok(port)
}

/// A spawned narsil-xref subprocess in SSE mode. The temp directory is
/// kept alive for the process lifetime; both are dropped together.
struct SseServer {
    process: Child,
    port: u16,
    _repo: TempDir,
}

impl SseServer {
    fn spawn() -> Result<Self> {
        let port = ephemeral_port()?;
        let repo = TempDir::new()?;
        let process = Command::new(binary_path())
            .args([
                "--transport",
                "sse",
                "--sse-host",
                "127.0.0.1",
                "--sse-port",
                &port.to_string(),
                "--repos",
                repo.path().to_str().expect("temp path is utf-8"),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn narsil-xref; run `cargo build` first")?;

        let server = Self {
            process,
            port,
            _repo: repo,
        };
        server.wait_until_ready()?;
        Ok(server)
    }

    fn wait_until_ready(&self) -> Result<()> {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;
        let url = format!("http://127.0.0.1:{}/health", self.port);
        while Instant::now() < deadline {
            if let Ok(resp) = client.get(&url).send() {
                if resp.status().is_success() {
                    return Ok(());
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        bail!("server did not become ready within {:?}", STARTUP_TIMEOUT);
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for SseServer {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[derive(Debug, Clone)]
struct SseEvent {
    event: Option<String>,
    data: String,
}

/// One SSE session against the server. Opens GET /mcp/sse, parses the
/// initial `endpoint` event to learn the session id, then forwards every
/// subsequent event to a channel for the test to consume.
struct SseClient {
    base_url: String,
    session_id: String,
    rx: Receiver<SseEvent>,
    _reader: thread::JoinHandle<()>,
}

impl SseClient {
    fn open(base_url: &str) -> Result<Self> {
        let url = format!("{}/mcp/sse", base_url);
        let resp = reqwest::blocking::Client::builder()
            // No timeout — the SSE stream is long-lived. The test owns
            // termination by dropping the client.
            .timeout(None)
            .build()?
            .get(&url)
            .send()
            .context("GET /mcp/sse")?;

        let mut reader = BufReader::new(EventReadAdapter::new(resp));

        // The first event must be `endpoint`. Read frames synchronously
        // until we see it.
        let mut endpoint_event: Option<SseEvent> = None;
        for _ in 0..16 {
            match read_one_event(&mut reader)? {
                Some(ev) if ev.event.as_deref() == Some("endpoint") => {
                    endpoint_event = Some(ev);
                    break;
                }
                Some(_) => continue, // keep-alive comment or unrelated
                None => bail!("server closed before sending endpoint event"),
            }
        }
        let endpoint_event =
            endpoint_event.ok_or_else(|| anyhow!("did not see endpoint event in first frames"))?;

        let session_id = parse_session_id(&endpoint_event.data)?;

        // Spawn a thread to drain subsequent events into a channel.
        let (tx, rx) = mpsc::channel();
        let reader_handle = thread::spawn(move || loop {
            match read_one_event(&mut reader) {
                Ok(Some(ev)) => {
                    if tx.send(ev).is_err() {
                        return;
                    }
                }
                Ok(None) => return, // server closed
                Err(_) => return,
            }
        });

        Ok(Self {
            base_url: base_url.to_string(),
            session_id,
            rx,
            _reader: reader_handle,
        })
    }

    fn post(&self, body: &Value) -> Result<u16> {
        let url = format!(
            "{}/mcp/message?sessionId={}",
            self.base_url, self.session_id
        );
        let resp = reqwest::blocking::Client::new()
            .post(&url)
            .json(body)
            .send()
            .context("POST /mcp/message")?;
        Ok(resp.status().as_u16())
    }

    fn next_event(&self, timeout: Duration) -> Result<SseEvent> {
        match self.rx.recv_timeout(timeout) {
            Ok(ev) => Ok(ev),
            Err(RecvTimeoutError::Timeout) => bail!("timeout waiting for SSE event"),
            Err(RecvTimeoutError::Disconnected) => bail!("SSE stream closed"),
        }
    }

    fn try_next_event(&self, timeout: Duration) -> Option<SseEvent> {
        self.rx.recv_timeout(timeout).ok()
    }
}

/// Wraps a reqwest blocking Response so BufReader can pull bytes. The
/// blocking response already implements `Read`; this newtype just lets us
/// move it across threads.
struct EventReadAdapter {
    inner: reqwest::blocking::Response,
}

impl EventReadAdapter {
    fn new(inner: reqwest::blocking::Response) -> Self {
        Self { inner }
    }
}

impl Read for EventReadAdapter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

/// Read one SSE frame. Returns `Ok(None)` on EOF, `Ok(Some(ev))` once a
/// blank line terminates the frame, or an error.
///
/// SSE frame syntax (subset we need): each non-blank line is `field:
/// value` or starts with `:` (comment). Blank line ends the frame. We
/// only recognise `event:` and `data:`; comment lines are ignored.
fn read_one_event<R: BufRead>(reader: &mut R) -> Result<Option<SseEvent>> {
    let mut event = None;
    let mut data: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut got_any_field = false;
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        // Normalize CRLF / LF
        let line = buf.trim_end_matches('\n').trim_end_matches('\r');
        if line.is_empty() {
            if got_any_field {
                return Ok(Some(SseEvent {
                    event,
                    data: data.join("\n"),
                }));
            }
            // Blank line with no fields = keep-alive separator before
            // anything happened; keep reading.
            continue;
        }
        if line.starts_with(':') {
            // Comment / keep-alive; ignore but record we saw activity
            got_any_field = true;
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => continue,
        };
        match field {
            "event" => event = Some(value.to_string()),
            "data" => data.push(value.to_string()),
            _ => {}
        }
        got_any_field = true;
    }
}

fn parse_session_id(endpoint_data: &str) -> Result<String> {
    // Expected: "/mcp/message?sessionId=<uuid>"
    let prefix = "/mcp/message?sessionId=";
    endpoint_data
        .strip_prefix(prefix)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("malformed endpoint event data: {:?}", endpoint_data))
}

fn initialize(id: i64, client_name: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": client_name, "version": "1.0" }
        }
    })
}

fn tools_list(id: i64) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {} })
}

fn tool_call(id: i64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
}

fn tools_count(response_data: &str) -> Result<usize> {
    let v: Value = serde_json::from_str(response_data)?;
    let tools = v
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .ok_or_else(|| anyhow!("response did not contain result.tools array"))?;
    Ok(tools.len())
}

fn response_id(response_data: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(response_data)?;
    Ok(v.get("id").cloned().unwrap_or(Value::Null))
}

fn tool_text(response_data: &str) -> Result<String> {
    let v: Value = serde_json::from_str(response_data)?;
    let text = v
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .and_then(|c| c.get("text"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("response did not contain result.content[0].text"))?;
    Ok(text.to_string())
}

/// Spec smoke test: open SSE, observe `endpoint` event, drive
/// initialize → tools/list → list_repos, assert each response arrives
/// with the matching JSON-RPC id.
#[test]
fn test_sse_smoke_flow() -> Result<()> {
    let server = SseServer::spawn()?;
    let client = SseClient::open(&server.base_url())?;

    assert!(!client.session_id.is_empty(), "session id must be set");

    assert_eq!(client.post(&initialize(1, "test-client"))?, 202);
    let ev = client.next_event(EVENT_TIMEOUT)?;
    assert_eq!(response_id(&ev.data)?, json!(1));

    assert_eq!(client.post(&tools_list(2))?, 202);
    let ev = client.next_event(EVENT_TIMEOUT)?;
    assert_eq!(response_id(&ev.data)?, json!(2));
    assert!(tools_count(&ev.data)? > 0, "tools/list should return tools");

    let call = tool_call(3, "list_repos", json!({}));
    assert_eq!(client.post(&call)?, 202);
    let ev = client.next_event(EVENT_TIMEOUT)?;
    assert_eq!(response_id(&ev.data)?, json!(3));

    Ok(())
}

/// Per-session isolation: two concurrent SSE sessions get distinct
/// session ids and their responses route back to the originating SSE
/// stream. A previous design with a shared `McpServer.client_info`
/// mutex risked cross-session contamination; the SessionState refactor
/// guards against that.
///
/// We assert the strongest property we can observe from outside the
/// process today: each session's POST yields a response with the
/// matching JSON-RPC id, delivered on that session's own SSE channel.
/// Asserting that `tools/list` returns different tool counts per
/// editor would also probe per-session client_info — but the
/// editor-preset mapping is currently broken (tracked separately in
/// the `integration_editor_tests` suite), so doing so would conflate
/// regressions.
#[test]
fn test_sse_per_session_isolation() -> Result<()> {
    let server = SseServer::spawn()?;
    let client_a = SseClient::open(&server.base_url())?;
    let client_b = SseClient::open(&server.base_url())?;

    assert_ne!(
        client_a.session_id, client_b.session_id,
        "each SSE connection must get its own session id"
    );

    // Initialize each with a different editor identity. Interleave the
    // POSTs to maximise the chance a shared-mutex bug would surface.
    assert_eq!(client_a.post(&initialize(101, "claude-desktop"))?, 202);
    assert_eq!(client_b.post(&initialize(202, "zed"))?, 202);

    let ev_a = client_a.next_event(EVENT_TIMEOUT)?;
    let ev_b = client_b.next_event(EVENT_TIMEOUT)?;

    // Each session's initialize response must land on its own SSE
    // stream with its own id.
    assert_eq!(response_id(&ev_a.data)?, json!(101));
    assert_eq!(response_id(&ev_b.data)?, json!(202));

    // tools/list interleaved across both sessions; both must succeed
    // and the responses must route back correctly.
    assert_eq!(client_a.post(&tools_list(102))?, 202);
    assert_eq!(client_b.post(&tools_list(203))?, 202);
    let ev_a = client_a.next_event(EVENT_TIMEOUT)?;
    let ev_b = client_b.next_event(EVENT_TIMEOUT)?;

    assert_eq!(response_id(&ev_a.data)?, json!(102));
    assert_eq!(response_id(&ev_b.data)?, json!(203));
    assert!(tools_count(&ev_a.data)? > 0);
    assert!(tools_count(&ev_b.data)? > 0);

    Ok(())
}

/// POST to a fabricated `sessionId` (i.e., the SSE never opened) must
/// reject with `410 Gone`. This is what the client uses to learn it
/// should reconnect on `/mcp/sse`.
#[test]
fn test_sse_post_to_unknown_session_returns_410() -> Result<()> {
    let server = SseServer::spawn()?;
    let url = format!(
        "{}/mcp/message?sessionId=00000000-0000-0000-0000-000000000000",
        server.base_url()
    );
    let resp = reqwest::blocking::Client::new()
        .post(&url)
        .json(&initialize(1, "test-client"))
        .send()?;
    assert_eq!(resp.status().as_u16(), 410);
    Ok(())
}

/// JSON-RPC notifications (no `id`) must not produce an SSE response.
/// `initialized` is the canonical client-to-server notification in the
/// MCP handshake.
#[test]
fn test_sse_notification_produces_no_response() -> Result<()> {
    let server = SseServer::spawn()?;
    let client = SseClient::open(&server.base_url())?;
    assert_eq!(client.post(&initialize(1, "test-client"))?, 202);
    let _ = client.next_event(EVENT_TIMEOUT)?;

    let notification = json!({
        "jsonrpc": "2.0",
        "method": "initialized",
        "params": {}
    });
    assert_eq!(client.post(&notification)?, 202);

    // Wait briefly; no SSE event should arrive.
    assert!(
        client.try_next_event(Duration::from_millis(500)).is_none(),
        "notification must not generate an SSE response"
    );
    Ok(())
}

/// Non-loopback `Host` headers must be rejected on `/mcp/*` to mitigate
/// DNS rebinding attacks against the local server.
#[test]
fn test_sse_rejects_non_loopback_host_header() -> Result<()> {
    let server = SseServer::spawn()?;
    let url = format!("{}/mcp/sse", server.base_url());
    let resp = reqwest::blocking::Client::new()
        .get(&url)
        .header("Host", "evil.example")
        .send()?;
    assert_eq!(resp.status().as_u16(), 403);
    Ok(())
}

// ── stdio proxy reconnect across SSE server restart ────────────────────────

/// Spawn an SSE server on a fixed `port`, indexing `repo`, registering into
/// the discovery file under `xdg_runtime`. The returned `Child` is managed by
/// the caller (kill + wait) so the same port can be rebound on restart.
fn spawn_sse_on_port(port: u16, repo: &Path, xdg_runtime: &Path) -> Result<Child> {
    Command::new(binary_path())
        .args([
            "--transport",
            "sse",
            "--sse-host",
            "127.0.0.1",
            "--sse-port",
            &port.to_string(),
            "--repos",
            repo.to_str().expect("temp path is utf-8"),
        ])
        .env("XDG_RUNTIME_DIR", xdg_runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn SSE narsil-xref; run `cargo build` first")
}

/// Poll the streamable `/mcp` endpoint with a `ping` until it answers 2xx. A
/// success here means the engine is wired (not a bare 503) and — since the
/// server registers for discovery before it serves — that its discovery entry
/// is already on disk.
fn wait_until_mcp_ready(port: u16) -> Result<()> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let url = format!("http://127.0.0.1:{}/mcp", port);
    while Instant::now() < deadline {
        if let Ok(resp) = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(r#"{"jsonrpc":"2.0","id":0,"method":"ping"}"#)
            .send()
        {
            if resp.status().is_success() {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    bail!("/mcp did not become ready within {:?}", STARTUP_TIMEOUT);
}

/// A stdio narsil-xref child driven as an MCP client. Its stdout (responses)
/// and stderr (logs) are drained on background threads into channels so the
/// test can read responses with a timeout and watch for log markers without
/// risking a full pipe blocking the child.
struct StdioProxy {
    child: Child,
    stdin: ChildStdin,
    stdout_rx: Receiver<String>,
    stderr_rx: Receiver<String>,
    _stdout_reader: thread::JoinHandle<()>,
    _stderr_reader: thread::JoinHandle<()>,
}

impl StdioProxy {
    /// Spawn `narsil-xref --repos <repo>` in stdio mode (the default), sharing
    /// `xdg_runtime` so it discovers the SSE server registered there.
    fn spawn(repo: &Path, xdg_runtime: &Path) -> Result<Self> {
        Self::spawn_with_args(repo, xdg_runtime, &[])
    }

    fn spawn_with_args(repo: &Path, xdg_runtime: &Path, extra_args: &[&str]) -> Result<Self> {
        let mut child = Command::new(binary_path())
            .args(["--repos", repo.to_str().expect("temp path is utf-8")])
            .args(extra_args)
            .env("XDG_RUNTIME_DIR", xdg_runtime)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn stdio narsil-xref")?;

        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");

        let (stdout_tx, stdout_rx) = mpsc::channel();
        let stdout_reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(text) = line else { return };
                if stdout_tx.send(text).is_err() {
                    return;
                }
            }
        });

        let (stderr_tx, stderr_rx) = mpsc::channel();
        let stderr_reader = thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(text) = line else { return };
                if stderr_tx.send(text).is_err() {
                    return;
                }
            }
        });

        Ok(Self {
            child,
            stdin,
            stdout_rx,
            stderr_rx,
            _stdout_reader: stdout_reader,
            _stderr_reader: stderr_reader,
        })
    }

    fn send(&mut self, msg: &Value) -> Result<()> {
        let line = serde_json::to_string(msg)?;
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        Ok(())
    }

    /// Next response line from the proxy's stdout, or an error on timeout.
    fn next_response(&self, timeout: Duration) -> Result<String> {
        self.stdout_rx
            .recv_timeout(timeout)
            .map_err(|_| anyhow!("timeout waiting for proxy stdout response"))
    }

    /// Wait until a stderr line contains `needle`, draining log lines until
    /// then. Used to confirm the process entered proxy (delegate) mode.
    fn wait_for_stderr_contains(&self, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match self
                .stderr_rx
                .recv_timeout(remaining.min(Duration::from_millis(500)))
            {
                Ok(line) if line.contains(needle) => return true,
                Ok(_) | Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return false,
            }
        }
    }

    /// Stderr lines up to the first one containing `needle`, then those of
    /// the next `linger`, for lines a background task logs a little later.
    fn stderr_lines_until(&self, needle: &str, timeout: Duration, linger: Duration) -> Vec<String> {
        let mut lines = Vec::new();
        let mut deadline = Instant::now() + timeout;
        let mut found = false;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return lines;
            }
            match self.stderr_rx.recv_timeout(remaining) {
                Ok(line) => {
                    if !found && line.contains(needle) {
                        found = true;
                        deadline = Instant::now() + linger;
                    }
                    lines.push(line);
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return lines,
            }
        }
    }
}

impl Drop for StdioProxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// End-to-end: a stdio client delegating to a shared SSE server must survive
/// that server restarting mid-session. The proxy is expected to reconnect
/// transparently — rediscover the restarted server, replay the handshake, and
/// replay the request — so the post-restart request returns a valid response
/// instead of the '-32000 Connection closed' the editor used to see.
#[test]
fn test_stdio_proxy_reconnects_after_server_restart() -> Result<()> {
    // Isolated discovery registry shared by both subprocesses, so the test
    // never touches the developer's real $XDG_RUNTIME_DIR/narsil-xref.
    let xdg = TempDir::new()?;
    let repo = TempDir::new()?;
    let repo_path = repo.path().canonicalize()?;
    let port = ephemeral_port()?;

    // Bring up the SSE server; readiness implies it has registered itself.
    let mut server = spawn_sse_on_port(port, &repo_path, xdg.path())?;
    wait_until_mcp_ready(port)?;

    // The stdio process must discover the server and run as a proxy, not
    // build its own local index.
    let mut proxy = StdioProxy::spawn(&repo_path, xdg.path())?;
    assert!(
        proxy.wait_for_stderr_contains("delegating stdio to", STARTUP_TIMEOUT),
        "stdio process did not delegate to the SSE server (proxy mode not entered)"
    );

    // Handshake plus one request that round-trips to the live server.
    proxy.send(&initialize(1, "reconnect-test"))?;
    assert_eq!(response_id(&proxy.next_response(EVENT_TIMEOUT)?)?, json!(1));
    proxy.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))?;

    proxy.send(&tools_list(2))?;
    let before = proxy.next_response(EVENT_TIMEOUT)?;
    assert_eq!(response_id(&before)?, json!(2));
    assert!(
        tools_count(&before)? > 0,
        "pre-restart tools/list must return tools"
    );

    // Restart the server on the SAME port. kill + wait first so the listening
    // socket is fully released before the replacement binds it.
    let _ = server.kill();
    let _ = server.wait();
    server = spawn_sse_on_port(port, &repo_path, xdg.path())?;
    wait_until_mcp_ready(port)?;

    // The next request hits a dead session; the proxy must reconnect and
    // return a valid response. Allow generously for the reconnect backoff.
    proxy.send(&tools_list(3))?;
    let after = proxy.next_response(Duration::from_secs(40))?;
    assert_eq!(
        response_id(&after)?,
        json!(3),
        "post-restart tools/list must return the matching id via reconnect"
    );
    assert!(
        tools_count(&after)? > 0,
        "post-restart tools/list must return tools via reconnect"
    );

    let _ = server.kill();
    let _ = server.wait();
    Ok(())
}

#[test]
fn test_stdio_proxy_translates_dot_repo() -> Result<()> {
    let xdg = TempDir::new()?;
    let repo = TempDir::new()?;
    let repo_path = repo.path().canonicalize()?;
    let port = ephemeral_port()?;

    let mut server = spawn_sse_on_port(port, &repo_path, xdg.path())?;
    wait_until_mcp_ready(port)?;

    let mut proxy = StdioProxy::spawn(&repo_path, xdg.path())?;
    assert!(
        proxy.wait_for_stderr_contains("delegating stdio to", STARTUP_TIMEOUT),
        "stdio process did not delegate to the SSE server (proxy mode not entered)"
    );

    proxy.send(&initialize(1, "dot-repo-test"))?;
    assert_eq!(response_id(&proxy.next_response(EVENT_TIMEOUT)?)?, json!(1));
    proxy.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))?;

    proxy.send(&tool_call(
        2,
        "get_project_structure",
        json!({ "repo": "." }),
    ))?;
    let response = proxy.next_response(EVENT_TIMEOUT)?;
    assert_eq!(response_id(&response)?, json!(2));
    let text = tool_text(&response)?;
    assert!(
        text.contains(&repo_path.display().to_string()),
        "repo='.' should resolve to the stdio proxy's resolved repo path"
    );

    let _ = server.kill();
    let _ = server.wait();
    Ok(())
}

fn spawn_sse_with_log_file(
    port: u16,
    repo: &Path,
    xdg_runtime: &Path,
    log_path: &Path,
    extra_args: &[&str],
) -> Result<Child> {
    let port_text = port.to_string();
    let mut args = vec![
        "--transport",
        "sse",
        "--sse-host",
        "127.0.0.1",
        "--sse-port",
        &port_text,
        "--repos",
        repo.to_str().expect("temp path is utf-8"),
        "--log-file",
        log_path.to_str().expect("temp path is utf-8"),
    ];
    args.extend_from_slice(extra_args);
    Command::new(binary_path())
        .args(&args)
        .env("XDG_RUNTIME_DIR", xdg_runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn SSE narsil-xref; run `cargo build` first")
}

fn wait_for_file_contains(path: &Path, needle: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(path) {
            if text.contains(needle) {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

fn sse_start_line(port: u16) -> String {
    format!("Starting MCP SSE transport on http://127.0.0.1:{}/", port)
}

/// A second start with the same --log-file moves the first run's log to <log>.1.
#[test]
fn test_sse_log_file_rotated_at_startup() -> Result<()> {
    let xdg = TempDir::new()?;
    let repo = TempDir::new()?;
    let logs = TempDir::new()?;
    let log_path = logs.path().join("narsil.log");
    let rotated_path = logs.path().join("narsil.log.1");
    // Different ports tell the two runs' log lines apart.
    let first_port = ephemeral_port()?;
    let second_port = ephemeral_port()?;

    let mut first = spawn_sse_with_log_file(first_port, repo.path(), xdg.path(), &log_path, &[])?;
    let first_ready = wait_until_mcp_ready(first_port);
    let _ = first.kill();
    let _ = first.wait();
    first_ready?;

    let mut second = spawn_sse_with_log_file(second_port, repo.path(), xdg.path(), &log_path, &[])?;
    let second_logged =
        wait_for_file_contains(&log_path, &sse_start_line(second_port), STARTUP_TIMEOUT);
    let _ = second.kill();
    let _ = second.wait();

    assert!(second_logged, "no start line in {}", log_path.display());
    let rotated = std::fs::read_to_string(&rotated_path)?;
    assert!(
        rotated.contains(&sse_start_line(first_port)),
        "{} lacks the first run's start line: {}",
        rotated_path.display(),
        rotated
    );
    Ok(())
}

/// The memory watchdog's `.diag` files go next to `--log-file`.
fn diag_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "diag")
        {
            found.push(path);
        }
    }
    Ok(found)
}

fn assert_full_diagnostics(diag_path: &Path) -> Result<()> {
    let diag = std::fs::read_to_string(diag_path)?;
    for section in [
        "VmRSS:",
        "== /proc/self/smaps_rollup",
        "== threads by name",
        "== memory_report",
        "== malloc_info",
    ] {
        assert!(
            diag.contains(section),
            "{} lacks {}",
            diag_path.display(),
            section
        );
    }
    Ok(())
}

#[test]
fn test_sse_memory_hard_limit_exits_with_diagnostics() -> Result<()> {
    let xdg = TempDir::new()?;
    let repo = TempDir::new()?;
    let logs = TempDir::new()?;
    let log_path = logs.path().join("narsil.log");
    let port = ephemeral_port()?;
    let limits = ["--memory-soft-limit", "off", "--memory-hard-limit", "1M"];

    let mut server = spawn_sse_with_log_file(port, repo.path(), xdg.path(), &log_path, &limits)?;
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut exit_status = None;
    while Instant::now() < deadline {
        exit_status = server.try_wait()?;
        if exit_status.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let Some(exit_status) = exit_status else {
        let _ = server.kill();
        let _ = server.wait();
        bail!("server still running above a 1M hard limit");
    };

    assert_eq!(exit_status.code(), Some(75), "hard limit exit code");
    let log = std::fs::read_to_string(&log_path)?;
    assert!(log.contains("above the memory hard limit"), "{}", log);
    assert!(
        !log.contains("Shutdown did not finish"),
        "the graceful shutdown did not end the server: {}",
        log
    );
    let diags = diag_files(logs.path())?;
    assert_eq!(diags.len(), 1, "one .diag file: {:?}", diags);
    assert_full_diagnostics(&diags[0])
}

#[test]
fn test_sse_memory_soft_limit_keeps_serving() -> Result<()> {
    let xdg = TempDir::new()?;
    let repo = TempDir::new()?;
    let logs = TempDir::new()?;
    let log_path = logs.path().join("narsil.log");
    let port = ephemeral_port()?;
    let limits = ["--memory-soft-limit", "1M", "--memory-hard-limit", "off"];

    let mut server = spawn_sse_with_log_file(port, repo.path(), xdg.path(), &log_path, &limits)?;
    let reported =
        wait_for_file_contains(&log_path, "above the memory soft limit", STARTUP_TIMEOUT);
    let answered = wait_until_mcp_ready(port);
    let still_running = server.try_wait()?.is_none();
    let _ = server.kill();
    let _ = server.wait();

    assert!(reported, "no soft limit line in {}", log_path.display());
    answered?;
    assert!(still_running, "the soft limit must not end the server");
    let diags = diag_files(logs.path())?;
    assert_eq!(diags.len(), 1, "one .diag file: {:?}", diags);
    assert_full_diagnostics(&diags[0])
}

/// An SSE server behind systemd-socket-activate, which stands in for
/// narsil-xref@.socket: it listens on `socket_port` and starts the server on the
/// first connection. None when systemd-socket-activate is not installed.
fn spawn_socket_activated_sse(
    socket_port: u16,
    repo: &Path,
    xdg_runtime: &Path,
    extra_args: &[&str],
) -> Result<Option<Child>> {
    let installed = Command::new("systemd-socket-activate")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !installed {
        eprintln!("skipped: systemd-socket-activate is not installed");
        return Ok(None);
    }
    let listen_address = format!("127.0.0.1:{}", socket_port);
    // systemd-socket-activate passes only the variables named with -E.
    let xdg_setting = format!("XDG_RUNTIME_DIR={}", xdg_runtime.display());
    let binary = std::fs::canonicalize(binary_path())?;
    let activator = Command::new("systemd-socket-activate")
        .args(["--listen", &listen_address])
        .args(["-E", &xdg_setting, "-E", "HOME", "-E", "PATH"])
        .arg(&binary)
        .args([
            "--transport",
            "sse",
            "--repos",
            repo.to_str().expect("temp path is utf-8"),
        ])
        .args(extra_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn systemd-socket-activate")?;
    Ok(Some(activator))
}

#[test]
fn test_sse_serves_on_the_socket_from_systemd() -> Result<()> {
    let xdg = TempDir::new()?;
    let repo = TempDir::new()?;
    let socket_port = ephemeral_port()?;
    // Ignored under socket activation.
    let flag_port = ephemeral_port()?.to_string();
    let extra_args = ["--sse-port", flag_port.as_str()];

    let Some(mut server) =
        spawn_socket_activated_sse(socket_port, repo.path(), xdg.path(), &extra_args)?
    else {
        return Ok(());
    };
    // The first ping is what makes systemd-socket-activate start the server.
    let answered = wait_until_mcp_ready(socket_port);
    let registry = std::fs::read_to_string(xdg.path().join("narsil-xref").join("servers.json"));
    let _ = server.kill();
    let _ = server.wait();

    answered?;
    let registry = registry.context("no servers.json")?;
    assert!(
        registry.contains(&format!("http://127.0.0.1:{}", socket_port)),
        "servers.json lacks the socket's port {}: {}",
        socket_port,
        registry
    );
    assert!(
        !registry.contains(&format!(":{}", flag_port)),
        "servers.json names the --sse-port {}: {}",
        flag_port,
        registry
    );
    Ok(())
}

/// A server registered in another servers.json, reachable only through --sse-url.
#[test]
fn test_stdio_delegates_to_sse_url() -> Result<()> {
    let server_xdg = TempDir::new()?;
    let stdio_xdg = TempDir::new()?;
    let repo = TempDir::new()?;
    let repo_path = repo.path().canonicalize()?;
    let port = ephemeral_port()?;

    let mut server = spawn_sse_on_port(port, &repo_path, server_xdg.path())?;
    wait_until_mcp_ready(port)?;

    let sse_url = format!("http://127.0.0.1:{}", port);
    let mut proxy =
        StdioProxy::spawn_with_args(&repo_path, stdio_xdg.path(), &["--sse-url", &sse_url])?;
    assert!(
        proxy.wait_for_stderr_contains("delegating stdio to", STARTUP_TIMEOUT),
        "stdio process did not delegate to --sse-url {}",
        sse_url
    );

    proxy.send(&initialize(1, "sse-url-test"))?;
    assert_eq!(response_id(&proxy.next_response(EVENT_TIMEOUT)?)?, json!(1));
    proxy.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))?;
    proxy.send(&tools_list(2))?;
    let response = proxy.next_response(EVENT_TIMEOUT)?;
    assert_eq!(response_id(&response)?, json!(2));
    assert!(tools_count(&response)? > 0, "tools/list must return tools");

    let _ = server.kill();
    let _ = server.wait();
    Ok(())
}

/// The --sse-url ping starts a socket-activated server that already has the
/// repo; asking it to adopt the repo would redo the repo's index pass.
#[test]
fn test_stdio_sse_url_does_not_adopt_a_repo_the_server_has() -> Result<()> {
    let xdg = TempDir::new()?;
    let repo = TempDir::new()?;
    let repo_path = repo.path().canonicalize()?;
    let socket_port = ephemeral_port()?;

    let Some(mut server) = spawn_socket_activated_sse(socket_port, &repo_path, xdg.path(), &[])?
    else {
        return Ok(());
    };
    let sse_url = format!("http://127.0.0.1:{}", socket_port);
    let proxy = StdioProxy::spawn_with_args(&repo_path, xdg.path(), &["--sse-url", &sse_url])?;
    // Adoption runs in a background task and may log after the delegation line.
    let lines = proxy.stderr_lines_until(
        "delegating stdio to",
        STARTUP_TIMEOUT,
        Duration::from_secs(2),
    );
    drop(proxy);
    let _ = server.kill();
    let _ = server.wait();

    assert!(
        lines
            .iter()
            .any(|line| line.contains("delegating stdio to")),
        "stdio process did not delegate to {}: {:#?}",
        sse_url,
        lines
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("SSE discovery: asking")),
        "stdio asked the server to adopt a repo it has: {:#?}",
        lines
    );
    Ok(())
}
