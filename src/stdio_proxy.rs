//! Stdio ↔ HTTP proxy for the SSE auto-discovery feature.
//!
//! When the stdio entry-point finds a running SSE narsil-xref that already
//! covers the requested repositories, it skips engine construction and
//! runs this proxy instead. The proxy reads newline-delimited JSON-RPC from
//! stdin, forwards each line as a POST to the streamable HTTP `/mcp`
//! endpoint, captures the `Mcp-Session-Id` header from the first response,
//! and writes successful response bodies back to stdout as new lines.
//!
//! Requests are serialised — one stdin line, one POST, one response
//! written, repeat. The MCP stdio framing technically allows pipelining
//! but the editors that drive narsil-xref do not exercise it, and
//! localhost RTT keeps the latency cost bounded. If a real workload
//! regresses, revisit.

use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info, warn};

// `tokio::io::stdin()` is backed by a blocking thread parked in `read(2)`.
// On shutdown signal, dropping the proxy_loop future cannot unblock that
// thread (only fresh stdin input would, which never arrives once the editor
// has disconnected), so the runtime hangs forever waiting for it. Skip the
// hung shutdown by exiting directly after flushing stdout.
async fn exit_after_flush(code: i32) -> ! {
    let mut stdout = tokio::io::stdout();
    let _ = stdout.flush().await;
    std::process::exit(code);
}

const MCP_SESSION_HEADER: &str = "mcp-session-id";

/// Upper bound on how long a reconnect keeps trying to reach a restarted
/// server before giving up and letting the editor respawn us.
const RECONNECT_WINDOW: Duration = Duration::from_secs(30);
/// Backoff cap between rediscovery attempts during a reconnect.
const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(2);
/// Per-line reconnect budget: a server that keeps rejecting one request
/// terminates the proxy (editor respawns it) rather than looping forever.
const MAX_RECONNECTS: u32 = 5;
/// How long one forwarded request may take before the client gets an error.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);

/// State for one stdio↔SSE proxy session: the upstream endpoint, the captured
/// `Mcp-Session-Id`, and the cached MCP handshake so a server restart can be
/// papered over by re-establishing a fresh session and replaying the request.
struct ProxySession {
    client: reqwest::Client,
    /// `<base_url>/mcp`; updated if rediscovery finds the server on a new URL.
    endpoint: String,
    /// Repos this stdio process serves; used to rediscover the restarted
    /// server, which may have rebound an ephemeral port.
    repos: Vec<PathBuf>,
    /// Repo that a `repo: "."` argument maps to: the served repo containing
    /// this proxy's cwd, else the sole repo. The daemon cannot resolve "."
    /// itself — its cwd is its own, not the client's project.
    default_repo: Option<String>,
    session_header_name: HeaderName,
    /// Session id captured from the first response; cleared on reconnect.
    session_id: Option<HeaderValue>,
    /// The `initialize` request line, replayed verbatim to mint a session on
    /// a new server. Cached as it passes through on the way out.
    init_request: Option<String>,
    /// The `notifications/initialized` line, replayed after `initialize`.
    initialized_notification: Option<String>,
    /// Set when a reconnect re-established the session behind the client's
    /// back. The client never saw a disconnect, so it will not re-read
    /// `tools/list` on its own — and the restarted server may have been
    /// started with a different `--expose`. Drained by the proxy loop, which
    /// owns stdout.
    tools_may_have_changed: bool,
}

/// Emitted to the client after a transparent reconnect. The proxy cannot tell
/// whether the restarted server's tool set actually differs — comparing would
/// cost a full `tools/list` round trip on every reconnect — so this is the
/// "may have changed" signal the MCP capability is defined as.
const TOOLS_LIST_CHANGED: &str = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;

/// Result of forwarding one stdin line upstream.
enum Forward {
    /// Response body to write back to stdout.
    Body(Vec<u8>),
    /// 202 Accepted — a notification with no response to forward.
    Accepted,
}

impl ProxySession {
    fn new(base_url: &str, repos: &[PathBuf]) -> Result<Self> {
        let endpoint = format!("{}/mcp", base_url.trim_end_matches('/'));
        let client = reqwest::Client::builder()
            .timeout(UPSTREAM_TIMEOUT)
            .build()
            .context("Building reqwest client for stdio proxy")?;
        Ok(Self {
            client,
            endpoint,
            repos: repos.to_vec(),
            default_repo: Self::resolve_dot_repo(repos),
            session_header_name: HeaderName::from_static(MCP_SESSION_HEADER),
            session_id: None,
            init_request: None,
            initialized_notification: None,
            tools_may_have_changed: false,
        })
    }

    /// Resolve which served repo a `repo: "."` argument refers to. The proxy
    /// runs in the client's project dir, so its own cwd disambiguates; the
    /// daemon's cwd cannot. Falls back to the sole repo when cwd is outside
    /// every served repo, preserving single-repo behaviour.
    fn resolve_dot_repo(repos: &[PathBuf]) -> Option<String> {
        let cwd = std::env::current_dir()
            .and_then(|cwd| cwd.canonicalize())
            .ok();
        Self::dot_repo_for_cwd(repos, cwd.as_deref())
    }

    /// The served repo a `repo: "."` argument maps to given the proxy's `cwd`:
    /// the most specific served repo enclosing cwd, else the sole repo.
    fn dot_repo_for_cwd(repos: &[PathBuf], cwd: Option<&Path>) -> Option<String> {
        if let Some(cwd) = cwd {
            // Indexed repos are roots; the client's cwd sits inside one. Pick
            // the most specific (longest) enclosing root.
            if let Some(repo) = repos
                .iter()
                .filter(|repo| cwd.starts_with(repo))
                .max_by_key(|repo| repo.as_os_str().len())
            {
                return Some(repo.to_string_lossy().into_owned());
            }
        }
        (repos.len() == 1).then(|| repos[0].to_string_lossy().into_owned())
    }

    fn request_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        if let Some(captured) = &self.session_id {
            headers.insert(self.session_header_name.clone(), captured.clone());
        }
        headers
    }

    /// Remember the handshake lines so a reconnect can replay them. Parses
    /// only until both are cached, so the steady-state cost is one comparison.
    fn observe_handshake(&mut self, line: &str) {
        if self.init_request.is_some() && self.initialized_notification.is_some() {
            return;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => return,
        };
        match value.get("method").and_then(|method| method.as_str()) {
            Some("initialize") => self.init_request = Some(line.to_string()),
            Some("notifications/initialized") => {
                self.initialized_notification = Some(line.to_string())
            }
            _ => {}
        }
    }

    /// POST one line to the current endpoint, capturing `Mcp-Session-Id` from
    /// the response while we do not yet hold one.
    async fn post_once(&mut self, line: &str) -> reqwest::Result<reqwest::Response> {
        let body = self.rewrite_default_repo(line);
        let response = self
            .client
            .post(&self.endpoint)
            .headers(self.request_headers())
            .body(body)
            .send()
            .await?;
        if self.session_id.is_none() {
            if let Some(value) = response.headers().get(&self.session_header_name).cloned() {
                if let Ok(text) = value.to_str() {
                    info!("Proxy session established (Mcp-Session-Id={})", text);
                }
                self.session_id = Some(value);
            }
        }
        Ok(response)
    }

    fn rewrite_default_repo(&self, line: &str) -> String {
        let Some(default_repo) = &self.default_repo else {
            return line.to_string();
        };

        let Ok(mut value) = serde_json::from_str::<Value>(line) else {
            return line.to_string();
        };
        if value.get("method").and_then(Value::as_str) != Some("tools/call") {
            return line.to_string();
        }

        let Some(arguments) = value
            .get_mut("params")
            .and_then(|params| params.get_mut("arguments"))
            .and_then(Value::as_object_mut)
        else {
            return line.to_string();
        };
        if arguments.get("repo").and_then(Value::as_str) != Some(".") {
            return line.to_string();
        }

        arguments.insert("repo".to_string(), Value::String(default_repo.clone()));
        serde_json::to_string(&value).unwrap_or_else(|_| line.to_string())
    }

    /// Forward one line, retrying transparently across a server restart. A
    /// reconnect is triggered by a transport error (failed send or dropped
    /// response body) or by a 404/503 from the upstream — the streamable
    /// handler returns 404 when it no longer knows our session id and 503
    /// while it is bound but not yet serving, both of which happen when the
    /// server rebinds the same port on restart. Any other non-2xx terminates.
    /// A timeout is answered with an error instead: the server is alive and
    /// still working, and replaying the line would run the request twice.
    async fn forward(&mut self, line: &str) -> Result<Forward> {
        let mut reconnects: u32 = 0;
        loop {
            let response = match self.post_once(line).await {
                Ok(response) => response,
                Err(e) if e.is_timeout() => return Ok(timeout_reply(line)),
                Err(e) => {
                    self.reconnect_or_bail(line, &mut reconnects, &format!("send failed: {e}"))
                        .await?;
                    continue;
                }
            };

            let status = response.status();
            let code = status.as_u16();
            if code == 202 {
                return Ok(Forward::Accepted);
            }
            if code == 404 || code == 503 {
                self.reconnect_or_bail(line, &mut reconnects, &format!("HTTP {code}"))
                    .await?;
                continue;
            }
            if !status.is_success() {
                return Err(anyhow!("upstream returned HTTP {}", code));
            }

            match response.bytes().await {
                Ok(body) => return Ok(Forward::Body(body.to_vec())),
                Err(e) if e.is_timeout() => return Ok(timeout_reply(line)),
                Err(e) => {
                    self.reconnect_or_bail(
                        line,
                        &mut reconnects,
                        &format!("body read failed: {e}"),
                    )
                    .await?;
                    continue;
                }
            }
        }
    }

    /// Run one reconnect cycle for the in-flight `line`, bailing once the
    /// per-line reconnect budget ([`MAX_RECONNECTS`]) is spent.
    async fn reconnect_or_bail(
        &mut self,
        line: &str,
        attempts: &mut u32,
        reason: &str,
    ) -> Result<()> {
        *attempts += 1;
        if *attempts > MAX_RECONNECTS {
            return Err(anyhow!(
                "giving up after {} reconnect attempts (last reason: {})",
                MAX_RECONNECTS,
                reason
            ));
        }
        warn!(
            "Proxy upstream {}; reconnecting (attempt {}/{})",
            reason, attempts, MAX_RECONNECTS
        );
        self.reconnect(line)
            .await
            .context("reconnecting to SSE server")
    }

    /// Re-establish a session against the restarted (possibly moved) server.
    /// Rediscovers via the registry with bounded backoff, then replays the
    /// cached handshake — unless `in_flight` is itself the `initialize`
    /// request, whose replay by the caller re-establishes the session anyway.
    /// Errors once [`RECONNECT_WINDOW`] is exhausted so the caller exits and
    /// the editor respawns us.
    async fn reconnect(&mut self, in_flight: &str) -> Result<()> {
        let start = Instant::now();
        let mut backoff = Duration::from_millis(100);
        loop {
            let repos = self.repos.clone();
            // find_server_for_repos uses a blocking HTTP probe; keep it off the
            // async worker so the shutdown-signal select stays responsive.
            let found = tokio::task::spawn_blocking(move || {
                crate::sse_discovery::find_server_for_repos(&repos)
            })
            .await
            .ok()
            .flatten();

            // A restarted server has forgotten every repo it was asked to index
            // rather than started with, so ask it again — otherwise this
            // session's own repo answers nothing.
            let reattached = found.map(|(url, missing)| {
                crate::sse_discovery::adopt_repos_in_background(&url, missing);
                url
            });

            if let Some(url) = reattached {
                self.endpoint = format!("{}/mcp", url.trim_end_matches('/'));
                self.session_id = None;
                if self.init_request.as_deref() == Some(in_flight) {
                    info!(
                        "Proxy reconnected to {} (in-flight initialize re-establishes session)",
                        url
                    );
                    return Ok(());
                }
                match self.replay_handshake().await {
                    Ok(()) => {
                        info!("Proxy reconnected to {}", url);
                        // The client saw no disconnect, so it will not re-read
                        // tools/list by itself; the new server may serve a
                        // different set.
                        self.tools_may_have_changed = true;
                        return Ok(());
                    }
                    Err(e) => warn!("Proxy reconnect: handshake replay failed: {}", e),
                }
            }

            if start.elapsed() >= RECONNECT_WINDOW {
                return Err(anyhow!(
                    "no SSE server reachable within {:?} of restart",
                    RECONNECT_WINDOW
                ));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RECONNECT_BACKOFF_CAP);
        }
    }

    /// Replay the cached `initialize` (and the `initialized` notification) to
    /// mint a fresh `Mcp-Session-Id`. The replayed responses are drained, not
    /// forwarded — the editor already saw them on the original handshake.
    async fn replay_handshake(&mut self) -> Result<()> {
        let init = self
            .init_request
            .clone()
            .ok_or_else(|| anyhow!("no cached initialize request to replay"))?;
        let response = self
            .post_once(&init)
            .await
            .context("replaying initialize after reconnect")?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "initialize replay returned HTTP {}",
                response.status().as_u16()
            ));
        }
        let _ = response.bytes().await;
        if self.session_id.is_none() {
            return Err(anyhow!("server returned no session id on reconnect"));
        }
        if let Some(note) = self.initialized_notification.clone() {
            let response = self
                .post_once(&note)
                .await
                .context("replaying initialized notification after reconnect")?;
            let _ = response.bytes().await;
        }
        Ok(())
    }
}

/// Run the proxy loop against `base_url` until stdin closes, the upstream
/// returns an unrecoverable error, or a shutdown signal arrives. `repos` is
/// the set this process serves, used to rediscover the server if it restarts.
pub async fn run_stdio_proxy_with_shutdown(base_url: &str, repos: &[PathBuf]) -> Result<()> {
    let mut session = ProxySession::new(base_url, repos)?;

    tokio::select! {
        result = proxy_loop(&mut session) => result,
        _ = tokio::signal::ctrl_c() => {
            info!("Proxy session terminating: shutdown signal (Ctrl-C)");
            exit_after_flush(0).await
        }
        _ = wait_for_terminate_signal() => {
            info!("Proxy session terminating: shutdown signal (SIGTERM)");
            exit_after_flush(0).await
        }
    }
}

/// Write the one-line `tools/list_changed` notification if a reconnect
/// happened, then clear the flag. One ~60-byte line per reconnect: no polling,
/// no diffing, and nothing at all on the steady-state path.
///
/// Suppressed when the request that hit the restart was itself `tools/list` —
/// its reply already carries the new server's list, so telling the client to
/// fetch it again would buy nothing and cost a round trip.
async fn notify_tools_changed(
    session: &mut ProxySession,
    stdout: &mut tokio::io::Stdout,
    answered: &str,
) -> Result<()> {
    if !std::mem::take(&mut session.tools_may_have_changed) {
        return Ok(());
    }
    if method_of(answered).as_deref() == Some("tools/list") {
        debug!("proxy: reconnect answered by a tools/list; no notification needed");
        return Ok(());
    }

    info!("Proxy → client: tools/list_changed (server restarted)");
    stdout.write_all(TOOLS_LIST_CHANGED.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    Ok(())
}

/// The `method` of a JSON-RPC line, if it parses.
fn method_of(line: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()?
        .get("method")?
        .as_str()
        .map(String::from)
}

/// JSON-RPC error answering `line` after [`UPSTREAM_TIMEOUT`]; a notification
/// gets no answer.
fn timeout_reply(line: &str) -> Forward {
    warn!(
        "proxy: upstream did not answer within {:?}",
        UPSTREAM_TIMEOUT
    );
    let id = serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|request| request.get("id").cloned());
    let Some(id) = id else {
        return Forward::Accepted;
    };
    let reply = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            // Not -32001: that is the daemon's "index busy, retry" code.
            "code": -32002,
            "message": format!(
                "narsil-xref server did not answer within {}s; the request may \
                 still be running there",
                UPSTREAM_TIMEOUT.as_secs()
            ),
        },
    });
    Forward::Body(reply.to_string().into_bytes())
}

#[cfg(test)]
mod list_changed_tests {
    use super::*;

    #[test]
    fn test_notification_is_valid_jsonrpc_without_an_id() {
        let value: Value = serde_json::from_str(TOOLS_LIST_CHANGED).expect("valid JSON");
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["method"], "notifications/tools/list_changed");
        assert!(
            value.get("id").is_none(),
            "a notification must carry no id, or clients answer it"
        );
    }

    #[test]
    fn test_method_of_reads_requests_and_notifications() {
        assert_eq!(
            method_of(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).as_deref(),
            Some("tools/list")
        );
        assert_eq!(
            method_of(TOOLS_LIST_CHANGED).as_deref(),
            Some("notifications/tools/list_changed")
        );
        assert_eq!(method_of(r#"{"jsonrpc":"2.0","id":1}"#), None);
        assert_eq!(method_of("not json"), None);
    }

    #[test]
    fn test_timeout_reply_answers_the_request_id() {
        let Forward::Body(body) =
            timeout_reply(r#"{"jsonrpc":"2.0","id":7,"method":"tools/call"}"#)
        else {
            panic!("a request must get an error reply");
        };
        let reply: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(reply["id"], 7);
        assert_eq!(reply["error"]["code"], -32002);
        assert!(matches!(
            timeout_reply(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Forward::Accepted
        ));
    }
}

async fn proxy_loop(session: &mut ProxySession) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .await
            .context("Reading stdin for proxy")?;
        if bytes_read == 0 {
            info!("Proxy session terminating: stdin closed");
            // A returning main would block in runtime shutdown until a
            // still-running adoption request ends, up to its timeout.
            exit_after_flush(0).await
        }

        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            continue;
        }
        debug!("proxy → {} bytes", trimmed.len());

        // Cache the handshake before sending so a reconnect can replay it even
        // if this very request is the one that hits a restarted server.
        session.observe_handshake(trimmed);

        match session.forward(trimmed).await? {
            Forward::Accepted => {
                debug!("proxy ← 202 Accepted (notification)");
                notify_tools_changed(session, &mut stdout, trimmed).await?;
                continue;
            }
            Forward::Body(body) => {
                debug!("proxy ← bytes={}", body.len());
                stdout.write_all(&body).await?;
                // The streamable HTTP transport returns a single JSON object
                // per POST; stdio framing requires a trailing newline that the
                // HTTP body does not always carry.
                if !body.ends_with(b"\n") {
                    stdout.write_all(b"\n").await?;
                }
                stdout.flush().await?;
                // After the reply to the request that hit the restart, so the
                // client is not handed a notification mid-request.
                notify_tools_changed(session, &mut stdout, trimmed).await?;
            }
        }
    }
}

#[cfg(unix)]
async fn wait_for_terminate_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            term.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}

#[cfg(not(unix))]
async fn wait_for_terminate_signal() {
    std::future::pending::<()>().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_repo_picks_enclosing_repo_among_many() {
        let repos = vec![PathBuf::from("/repos/alpha"), PathBuf::from("/repos/beta")];
        // Multi-repo proxy: cwd inside beta resolves to beta, not forwarded verbatim.
        let cwd = PathBuf::from("/repos/beta/src/sub");
        assert_eq!(
            ProxySession::dot_repo_for_cwd(&repos, Some(&cwd)),
            Some("/repos/beta".to_string())
        );
    }

    #[test]
    fn dot_repo_prefers_most_specific_root() {
        // Nested served repos: cwd in the inner one resolves to the inner one.
        let repos = vec![
            PathBuf::from("/repos/alpha"),
            PathBuf::from("/repos/alpha/vendor/lib"),
        ];
        let cwd = PathBuf::from("/repos/alpha/vendor/lib/src");
        assert_eq!(
            ProxySession::dot_repo_for_cwd(&repos, Some(&cwd)),
            Some("/repos/alpha/vendor/lib".to_string())
        );
    }

    #[test]
    fn dot_repo_falls_back_to_sole_repo_when_cwd_outside() {
        let repos = vec![PathBuf::from("/repos/alpha")];
        // A single served repo is unambiguous even when cwd is elsewhere or absent.
        assert_eq!(
            ProxySession::dot_repo_for_cwd(&repos, Some(&PathBuf::from("/somewhere/else"))),
            Some("/repos/alpha".to_string())
        );
        assert_eq!(
            ProxySession::dot_repo_for_cwd(&repos, None),
            Some("/repos/alpha".to_string())
        );
    }

    #[test]
    fn dot_repo_none_when_ambiguous_and_cwd_outside() {
        let repos = vec![PathBuf::from("/repos/alpha"), PathBuf::from("/repos/beta")];
        // Several repos and cwd inside none: ambiguous, leave "." untouched.
        assert_eq!(
            ProxySession::dot_repo_for_cwd(&repos, Some(&PathBuf::from("/elsewhere"))),
            None
        );
        assert_eq!(ProxySession::dot_repo_for_cwd(&repos, None), None);
    }
}
