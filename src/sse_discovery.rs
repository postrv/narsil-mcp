//! Auto-discovery of running SSE narsil-mcp servers.
//!
//! When an editor spawns narsil-mcp in stdio mode and another long-running
//! SSE narsil-mcp already covers the requested repositories, the stdio
//! process delegates to it instead of building a duplicate index. This
//! module owns the on-disk registry that lets stdio find SSE.
//!
//! The registry is a JSON array of [`SseServerRecord`] under either
//! `$XDG_RUNTIME_DIR/narsil-mcp/servers.json` (Linux, tmpfs, per-user) or
//! `<cache_dir>/narsil-mcp/servers.json` (macOS / unset XDG). The
//! directory is chmod'd to `0700` on Unix so other users on a shared host
//! cannot read URLs or repo paths.
//!
//! Liveness is checked solely by sending an MCP `ping` POST to each
//! candidate's URL. PID-based checks were considered and rejected — they
//! add OS-specific code while the HTTP probe is authoritative (a localhost
//! connection refused is microseconds, same order as `kill(pid, 0)`).
//!
//! Reads that prune stale entries hold an advisory exclusive lock on the
//! discovery file so two concurrent stdio starts cannot corrupt it.

use anyhow::{Context, Result};
use fs4::fs_std::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, info, warn};

/// On-disk record of a running SSE narsil-mcp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SseServerRecord {
    /// Base URL with no trailing slash, e.g. `http://127.0.0.1:7557`.
    pub url: String,
    /// Canonical absolute paths of repositories the server indexes.
    pub repos: Vec<PathBuf>,
}

/// RAII guard that removes this process's entry from the discovery file
/// when dropped. The entry is identified by URL — while a server is alive
/// it holds the listen socket for its URL, so no other process on the same
/// host can register the same URL concurrently.
pub struct DiscoveryEntry {
    path: PathBuf,
    url: String,
}

impl DiscoveryEntry {
    /// Path of the file this entry was written to. Exposed for tests.
    pub fn file_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DiscoveryEntry {
    fn drop(&mut self) {
        match remove_entry(&self.path, &self.url) {
            Ok(()) => info!("SSE discovery: removed entry url={}", self.url),
            Err(e) => warn!(
                "SSE discovery: failed to remove entry url={}: {}",
                self.url, e
            ),
        }
    }
}

/// Resolve the path of the discovery registry file.
///
/// Linux/BSD: `$XDG_RUNTIME_DIR/narsil-mcp/servers.json` when XDG is set
/// to an absolute path (tmpfs, per-user, cleaned on logout).
///
/// Fallback (macOS, Windows, or unset XDG): the user's cache directory
/// joined with `narsil-mcp/servers.json`. Both locations are already
/// user-scoped — no shared `/tmp` involved.
pub fn discovery_file_path() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(dir);
        if dir.is_absolute() {
            return Ok(dir.join("narsil-mcp").join("servers.json"));
        }
    }
    let base = directories::BaseDirs::new()
        .context("Cannot determine a per-user cache directory for the SSE discovery file")?;
    Ok(base.cache_dir().join("narsil-mcp").join("servers.json"))
}

/// Write (or refresh) a record for the SSE server running on `url`.
/// Returns a guard that removes the entry on drop. The parent directory
/// is created if missing and chmod'd to `0700` on Unix.
pub fn register_server(url: &str, repos: &[PathBuf]) -> Result<DiscoveryEntry> {
    let path = discovery_file_path()?;
    register_at(&path, url, repos)
}

/// Same as [`register_server`] but writes to an explicit path; used by
/// tests to avoid touching the real per-user registry.
pub fn register_at(path: &Path, url: &str, repos: &[PathBuf]) -> Result<DiscoveryEntry> {
    ensure_parent_dir(path)?;
    let normalized = url.trim_end_matches('/').to_string();
    let record = SseServerRecord {
        url: normalized.clone(),
        repos: repos.to_vec(),
    };

    {
        let mut file = open_locked(path)?;
        let mut records = read_records(&mut file).unwrap_or_default();
        // Replace any prior record with the same URL — that record's
        // owner can no longer be alive, since we just bound the socket.
        records.retain(|r| r.url != normalized);
        records.push(record);
        atomic_write(path, &records)?;
    }
    info!(
        "SSE discovery: registered url={} repos={} → {}",
        normalized,
        repos.len(),
        path.display()
    );

    Ok(DiscoveryEntry {
        path: path.to_path_buf(),
        url: normalized,
    })
}

/// Return the base URL of a record that answers an MCP `ping` POST, together
/// with the entries of `repos` that record does not list. Removes records that
/// fail the probe with a transport-level error as a side effect.
pub fn find_server_for_repos(repos: &[PathBuf]) -> Option<(String, Vec<PathBuf>)> {
    let path = discovery_file_path().ok()?;
    find_at(&path, repos)
}

/// [`find_server_for_repos`], retried until `retry_budget` elapses. A stdio
/// process started moments before its SSE counterpart registers otherwise
/// loses the race for its whole lifetime: local-index mode, once entered by
/// the caller, is never re-evaluated. `retry_budget` of zero probes exactly
/// once, matching the pre-retry behavior.
///
/// `find_server_for_repos` runs synchronous blocking I/O (file locking, an
/// HTTP probe), so each attempt runs on a blocking-pool thread; only the
/// wait between attempts is a plain async sleep.
pub async fn find_server_for_repos_with_retry(
    repos: &[PathBuf],
    retry_budget: Duration,
) -> Option<(String, Vec<PathBuf>)> {
    let path = discovery_file_path().ok()?;
    find_at_with_retry(&path, repos, retry_budget).await
}

/// Same as [`find_server_for_repos_with_retry`] but reads from an explicit
/// path; used by tests.
pub async fn find_at_with_retry(
    path: &Path,
    repos: &[PathBuf],
    retry_budget: Duration,
) -> Option<(String, Vec<PathBuf>)> {
    const POLL_INTERVAL: Duration = Duration::from_millis(250);
    let deadline = std::time::Instant::now() + retry_budget;
    loop {
        let probe_path = path.to_path_buf();
        let probe_repos = repos.to_vec();
        let found = tokio::task::spawn_blocking(move || find_at(&probe_path, &probe_repos))
            .await
            .ok()
            .flatten();
        if found.is_some() || std::time::Instant::now() >= deadline {
            return found;
        }
        debug!(
            "SSE discovery: no match yet, retrying for up to {:?} more",
            deadline.saturating_duration_since(std::time::Instant::now())
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// How long a stdio process waits for the server at `sse_url` to appear in
/// servers.json: a socket-activated server registers once its engine is built.
const SSE_URL_REGISTRATION_WAIT: Duration = Duration::from_secs(5);

/// For a caller that found no server in servers.json: the server at `url`
/// if it answers a ping, with the entries of `repos` it does not list.
///
/// The ping may be what starts a socket-activated server. Its servers.json
/// entry, written once it runs, names the repos it has; asking it to adopt
/// one of those would redo that repo's whole index pass.
pub async fn find_server_at_url(url: &str, repos: &[PathBuf]) -> Option<(String, Vec<PathBuf>)> {
    let probe_url = url.to_string();
    let probe = tokio::task::spawn_blocking(move || http_probe(&probe_url))
        .await
        .ok()?;
    if !matches!(probe, ProbeResult::Ok) {
        info!("SSE discovery: no server answers at sse_url {}", url);
        return None;
    }
    let registered = match discovery_file_path() {
        Ok(path) => find_at_with_retry(&path, repos, SSE_URL_REGISTRATION_WAIT).await,
        Err(_) => None,
    };
    match registered {
        Some(found) => Some(found),
        None => {
            info!(
                "SSE discovery: {} answers but is not in servers.json; every repo counts as missing",
                url
            );
            Some((url.trim_end_matches('/').to_string(), repos.to_vec()))
        }
    }
}

/// Same as [`find_server_for_repos`] but reads from an explicit path;
/// used by tests.
pub fn find_at(path: &Path, repos: &[PathBuf]) -> Option<(String, Vec<PathBuf>)> {
    info!("SSE discovery: checking {}", path.display());
    if !path.exists() {
        info!("SSE discovery: no registry file yet");
        return None;
    }

    let mut file = open_locked(path).ok()?;
    let records = read_records(&mut file).unwrap_or_default();

    let mut surviving: Vec<SseServerRecord> = Vec::with_capacity(records.len());
    // A server covering every requested repo needs nothing from the caller, so
    // it wins over one that would first have to be told about the rest.
    let mut exact: Option<String> = None;
    let mut partial: Option<(String, Vec<PathBuf>)> = None;

    for record in records {
        debug!(
            "SSE discovery: candidate url={} repos={:?}",
            record.url, record.repos
        );

        if exact.is_some() {
            // Already picked a winner — keep this record but do not probe.
            surviving.push(record);
            continue;
        }

        let missing = missing_repos(&record.repos, repos);

        match http_probe(&record.url) {
            ProbeResult::Ok => {
                debug!(
                    "SSE discovery: ping {}/mcp → 200, does not serve {:?}",
                    record.url, missing
                );
                if missing.is_empty() {
                    exact = Some(record.url.clone());
                } else if partial.is_none() {
                    partial = Some((record.url.clone(), missing));
                }
                surviving.push(record);
            }
            ProbeResult::HttpError(status) => {
                debug!("SSE discovery: ping {}/mcp → http {}", record.url, status);
                // Server is bound but unhappy with the probe; keep the
                // entry for a future call to retry, but do not delegate.
                surviving.push(record);
            }
            ProbeResult::Transport(err) => {
                debug!(
                    "SSE discovery: removed stale entry url={} reason=probe_failed ({})",
                    record.url, err
                );
            }
        }
    }

    if let Err(e) = atomic_write(path, &surviving) {
        warn!("SSE discovery: failed to rewrite registry: {}", e);
    }

    exact.map(|url| (url, Vec::new())).or(partial)
}

/// Ask the server at `url` to index every repo in `missing`, one at a time.
///
/// Each call blocks until that repo's index pass has finished or
/// [`ADOPT_TIMEOUT`] has passed, so it runs on
/// the blocking pool rather than on the async worker.
pub async fn adopt_repos(url: &str, missing: &[PathBuf]) -> Result<()> {
    for repo in missing {
        info!("SSE discovery: asking {} to index {}", url, repo.display());
        let target = url.to_string();
        let path = repo.clone();
        tokio::task::spawn_blocking(move || {
            adopt_repo(&target, &path)?;
            // Otherwise every later stdio start finds the repo missing and
            // asks again, and `reindex` redoes the full index pass each time.
            if let Err(e) =
                discovery_file_path().and_then(|file| record_adopted_repo(&file, &target, &path))
            {
                warn!(
                    "SSE discovery: could not list {} under {}: {}",
                    path.display(),
                    target,
                    e
                );
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("the adopt request task was cancelled")?
        .with_context(|| format!("{} could not index {}", url, repo.display()))?;
    }
    Ok(())
}

/// [`adopt_repos`] as a detached task. Nothing may wait on it: a repo's index
/// pass can outlast the MCP client's connect and tool timeouts, and until it
/// finishes the server answers queries for the repo with "being indexed".
pub fn adopt_repos_in_background(url: &str, missing: Vec<PathBuf>) {
    if missing.is_empty() {
        return;
    }
    let target = url.to_string();
    tokio::spawn(async move {
        if let Err(e) = adopt_repos(&target, &missing).await {
            warn!("SSE discovery: adoption failed: {}", e);
        }
    });
}

// ── internals ────────────────────────────────────────────────────────────

/// How long to wait for a server to finish indexing a repo it was asked to
/// adopt. `reindex` answers only once the index pass is done. The stdio
/// entry point runs this in the background and nothing waits on it: past the
/// timeout the server keeps indexing, and the repo is recorded as adopted
/// all the same.
const ADOPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Call the `reindex` tool on `url` for `repo`.
///
/// `reindex` registers a repository the server was never started with, which
/// is what lets a stdio process delegate to a server that does not yet know
/// its project. The POST carries no `Mcp-Session-Id`; the server opens a fresh
/// session for it, exactly as it does for [`http_probe`]'s `ping`.
fn adopt_repo(url: &str, repo: &Path) -> Result<()> {
    let endpoint = format!("{}/mcp", url.trim_end_matches('/'));
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "reindex",
            "arguments": { "repo": repo.to_string_lossy() },
        },
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(ADOPT_TIMEOUT)
        .build()?;
    let sent = client
        .post(&endpoint)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .body(serde_json::to_vec(&request)?)
        .send();
    let response = match sent {
        // The server has registered the repo and keeps indexing it; treating
        // this as a failure leaves the repo unrecorded, and the next stdio
        // start restarts the unfinished index pass.
        Err(e) if e.is_timeout() => {
            info!(
                "SSE discovery: {} still indexing {} after {:?}; continuing without waiting",
                url,
                repo.display(),
                ADOPT_TIMEOUT
            );
            return Ok(());
        }
        sent => sent.with_context(|| format!("POST reindex to {endpoint}"))?,
    };

    let status = response.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!("HTTP {}", status.as_u16()));
    }

    let body: serde_json::Value = response
        .json()
        .with_context(|| format!("parsing the reindex response from {endpoint}"))?;
    match body.pointer("/error/message").and_then(|m| m.as_str()) {
        Some(message) => Err(anyhow::anyhow!("{}", message)),
        None => Ok(()),
    }
}

fn ensure_parent_dir(file: &Path) -> Result<()> {
    let dir = file
        .parent()
        .context("Discovery file path has no parent directory")?;
    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create discovery directory: {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(dir)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(dir, perms).with_context(|| {
                format!("Failed to chmod discovery directory: {}", dir.display())
            })?;
        }
    }
    Ok(())
}

/// Open the discovery file (creating an empty one if missing) and take an
/// advisory exclusive lock. The lock is released when the file is closed.
fn open_locked(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("Failed to open {}", path.display()))?;
    file.lock_exclusive()
        .with_context(|| format!("Failed to lock {}", path.display()))?;
    Ok(file)
}

fn read_records(file: &mut File) -> Result<Vec<SseServerRecord>> {
    file.seek(SeekFrom::Start(0))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    if buf.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&buf).context("Failed to parse discovery file as JSON")
}

/// Write `records` atomically: serialise to `.servers.json.tmp-<pid>`,
/// fsync, rename into place. If the rename fails, the partial tmp file is
/// removed. PID in the tmp name is only for collision avoidance between
/// concurrent writers, not for liveness — see module docs.
fn atomic_write(path: &Path, records: &[SseServerRecord]) -> Result<()> {
    let dir = path
        .parent()
        .context("Discovery file path has no parent directory")?;
    let tmp = dir.join(format!(".servers.json.tmp-{}", std::process::id()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("Failed to create {}", tmp.display()))?;
        let bytes = serde_json::to_vec_pretty(records)?;
        file.write_all(&bytes)?;
        let _ = file.sync_all();
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow::Error::new(e).context(format!(
            "Failed to rename {} → {}",
            tmp.display(),
            path.display()
        )));
    }
    Ok(())
}

/// Add `repo` to the record of the server at `url`. The server rewrites its
/// record on restart, which drops the repo again with the index it had.
/// A missing record (server gone meanwhile) is left missing.
fn record_adopted_repo(path: &Path, url: &str, repo: &Path) -> Result<()> {
    let mut file = open_locked(path)?;
    let mut records = read_records(&mut file)?;
    let Some(record) = records.iter_mut().find(|r| r.url == url) else {
        return Ok(());
    };
    if record.repos.iter().any(|have| have == repo) {
        return Ok(());
    }
    record.repos.push(repo.to_path_buf());
    atomic_write(path, &records)
}

fn remove_entry(path: &Path, url: &str) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut file = open_locked(path)?;
    let mut records = read_records(&mut file).unwrap_or_default();
    let before = records.len();
    records.retain(|r| r.url != url);
    if records.len() == before {
        return Ok(());
    }
    atomic_write(path, &records)
}

/// The paths in `requested` that `available` does not list, in the order the
/// caller gave them. Empty means `available` is a superset.
fn missing_repos(available: &[PathBuf], requested: &[PathBuf]) -> Vec<PathBuf> {
    requested
        .iter()
        .filter(|path| !available.iter().any(|have| have == *path))
        .cloned()
        .collect()
}

enum ProbeResult {
    /// 2xx response, or connected but no answer in time — server is alive.
    Ok,
    /// Non-2xx response — server is bound but rejected the ping. Entry
    /// is kept for future probes but we will not delegate now.
    HttpError(u16),
    /// Connection refused / connect timeout / DNS — server is gone, drop entry.
    Transport(String),
}

fn http_probe(url: &str) -> ProbeResult {
    let body = r#"{"jsonrpc":"2.0","id":0,"method":"ping"}"#;
    let endpoint = format!("{}/mcp", url.trim_end_matches('/'));
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
    {
        Ok(c) => c,
        Err(e) => return ProbeResult::Transport(e.to_string()),
    };
    match client
        .post(&endpoint)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .body(body)
        .send()
    {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                ProbeResult::Ok
            } else {
                ProbeResult::HttpError(status.as_u16())
            }
        }
        // Connected but slow to answer: a busy server, e.g. mid-index. Taking
        // it for gone would drop its record, and new stdio starts would build
        // a duplicate local index instead of delegating.
        Err(e) if e.is_timeout() && !e.is_connect() => {
            debug!(
                "SSE discovery: ping {} timed out; treating as alive",
                endpoint
            );
            ProbeResult::Ok
        }
        Err(e) => ProbeResult::Transport(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// A URL that reliably refuses connections in the test environment.
    /// Port 1 is the well-known TCPMUX port; nothing listens on it on
    /// developer machines or CI runners, so localhost yields *connection
    /// refused* in microseconds.
    const UNREACHABLE_URL: &str = "http://127.0.0.1:1";

    fn record(url: &str, repos: &[&str]) -> SseServerRecord {
        SseServerRecord {
            url: url.to_string(),
            repos: repos.iter().map(PathBuf::from).collect(),
        }
    }

    fn write_records(path: &Path, records: &[SseServerRecord]) {
        let _ = std::fs::create_dir_all(path.parent().unwrap());
        let bytes = serde_json::to_vec_pretty(records).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn read_back(path: &Path) -> Vec<SseServerRecord> {
        let bytes = std::fs::read(path).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn atomic_write_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");

        atomic_write(&path, &[record("http://127.0.0.1:7557", &["/a"])]).unwrap();
        assert_eq!(
            read_back(&path),
            vec![record("http://127.0.0.1:7557", &["/a"])]
        );

        // Rewriting overwrites cleanly with no leftover tmp file.
        atomic_write(&path, &[record("http://127.0.0.1:7558", &["/b"])]).unwrap();
        assert_eq!(
            read_back(&path),
            vec![record("http://127.0.0.1:7558", &["/b"])]
        );

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".servers.json.tmp")
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "tmp files left behind: {:?}",
            leftovers
        );
    }

    #[test]
    fn superset_match_and_miss() {
        let available: Vec<PathBuf> = ["/repo/a", "/repo/b"].iter().map(PathBuf::from).collect();
        let requested_subset: Vec<PathBuf> = ["/repo/a"].iter().map(PathBuf::from).collect();
        let requested_extra: Vec<PathBuf> =
            ["/repo/a", "/repo/c"].iter().map(PathBuf::from).collect();

        assert!(missing_repos(&available, &requested_subset).is_empty());
        assert_eq!(
            missing_repos(&available, &requested_extra),
            vec![PathBuf::from("/repo/c")]
        );
    }

    /// A live server that serves only some of the requested repos is still a
    /// match, reported with the ones it lacks so the caller can act on them.
    #[test]
    fn partial_match_reports_the_repos_the_server_lacks() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");
        let url = spawn_200_server();
        write_records(&path, &[record(&url, &["/a"])]);

        let (found, missing) = find_at(&path, &[PathBuf::from("/a"), PathBuf::from("/b")])
            .expect("a live server matches even when it lacks a repo");
        assert_eq!(found, url);
        assert_eq!(missing, vec![PathBuf::from("/b")]);
    }

    /// With a partial and an exact match both alive, the exact one wins even
    /// though the partial one is probed first.
    #[test]
    fn exact_match_wins_over_a_partial_one() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");
        let partial_url = spawn_200_server();
        let exact_url = spawn_200_server();
        write_records(
            &path,
            &[
                record(&partial_url, &["/a"]),
                record(&exact_url, &["/a", "/b"]),
            ],
        );

        let (found, missing) = find_at(&path, &[PathBuf::from("/a"), PathBuf::from("/b")])
            .expect("the exact record is alive");
        assert_eq!(found, exact_url);
        assert!(missing.is_empty(), "exact match must lack nothing");
    }

    /// After one stdio start adopted `/b`, the next finds nothing missing
    /// and so sends no second `reindex`.
    #[test]
    fn adopted_repo_is_no_longer_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");
        let url = spawn_200_server();
        write_records(
            &path,
            &[record(&url, &["/a"]), record(UNREACHABLE_URL, &["/c"])],
        );

        record_adopted_repo(&path, &url, Path::new("/b")).unwrap();
        record_adopted_repo(&path, &url, Path::new("/b")).unwrap();
        assert_eq!(
            read_back(&path),
            vec![
                record(&url, &["/a", "/b"]),
                record(UNREACHABLE_URL, &["/c"])
            ],
            "listed once, other servers' records untouched"
        );

        let (found, missing) = find_at(&path, &[PathBuf::from("/a"), PathBuf::from("/b")])
            .expect("the server is alive");
        assert_eq!(found, url);
        assert!(missing.is_empty());
    }

    #[test]
    fn unreachable_entry_is_pruned_by_find_at() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");
        write_records(&path, &[record(UNREACHABLE_URL, &["/r"])]);

        let result = find_at(&path, &[PathBuf::from("/r")]);
        assert!(result.is_none(), "should not match an unreachable URL");

        let surviving = read_back(&path);
        assert!(
            surviving.is_empty(),
            "unreachable entry should be pruned, got {:?}",
            surviving
        );
    }

    #[test]
    fn drop_removes_only_own_entry() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");

        // Seed the file with a foreign entry first.
        let foreign = record("http://127.0.0.1:7600", &["/elsewhere"]);
        write_records(&path, std::slice::from_ref(&foreign));

        // Register our own; let the guard drop at the end of the block.
        let our_url = "http://127.0.0.1:7557";
        {
            let _entry = register_at(&path, our_url, &[PathBuf::from("/r")]).unwrap();
            let mid = read_back(&path);
            assert!(mid.iter().any(|r| r.url == our_url));
            assert!(mid.iter().any(|r| r == &foreign));
        }

        let after = read_back(&path);
        assert!(
            !after.iter().any(|r| r.url == our_url),
            "our entry should be gone after drop, got {:?}",
            after
        );
        assert!(
            after.iter().any(|r| r == &foreign),
            "foreign entry should be untouched, got {:?}",
            after
        );
    }

    #[test]
    fn concurrent_find_at_does_not_lose_or_duplicate_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");

        // Two unreachable entries every thread must prune, plus one live entry
        // every thread must keep -- exactly once, however the writes interleave.
        let irrelevant = SseServerRecord {
            url: spawn_200_server(),
            repos: vec![PathBuf::from("/elsewhere")],
        };
        write_records(
            &path,
            &[
                record(UNREACHABLE_URL, &["/r"]),
                record("http://127.0.0.1:3", &["/r"]),
                irrelevant.clone(),
            ],
        );

        let path_arc = Arc::new(path.clone());
        let mut handles = Vec::new();
        for _ in 0..4 {
            let cloned_path = Arc::clone(&path_arc);
            handles.push(std::thread::spawn(move || {
                find_at(&cloned_path, &[PathBuf::from("/r")]);
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        let surviving = read_back(&path);
        // Unreachable matching entries must be gone; the non-matching
        // entry must remain exactly once.
        let irrelevant_count = surviving.iter().filter(|r| **r == irrelevant).count();
        assert_eq!(
            irrelevant_count, 1,
            "non-matching entry should appear exactly once, got {:?}",
            surviving
        );
        assert!(
            !surviving
                .iter()
                .any(|r| r.url == UNREACHABLE_URL || r.url == "http://127.0.0.1:3"),
            "matching-but-unreachable entries should be pruned, got {:?}",
            surviving
        );
    }

    /// A minimal listener that answers every connection with `body` as a 200
    /// JSON response. Serves until the test binary exits; its thread is never
    /// joined.
    fn spawn_json_server(body: &'static str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    /// A server too busy to answer: accepts connections, never replies.
    fn spawn_silent_server() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let held: Vec<_> = listener.incoming().flatten().collect();
            drop(held);
        });
        format!("http://127.0.0.1:{port}")
    }

    /// The qemu failure: a daemon busy indexing missed the ping deadline, its
    /// record was pruned, and the next stdio start built a local index.
    #[test]
    fn slow_server_is_kept_and_delegated_to() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");
        let url = spawn_silent_server();
        write_records(&path, &[record(&url, &["/a"])]);

        let (found, missing) =
            find_at(&path, &[PathBuf::from("/a")]).expect("a busy server is still alive");
        assert_eq!(found, url);
        assert!(missing.is_empty());
        assert_eq!(read_back(&path), vec![record(&url, &["/a"])]);
    }

    /// A live server for the probe, which only checks the status code.
    fn spawn_200_server() -> String {
        spawn_json_server("{}")
    }

    /// A tool that fails answers with a JSON-RPC error, not an HTTP one, so
    /// adopt_repo has to read the body to know the repo was not indexed.
    #[test]
    fn adopt_repo_reports_the_servers_error() {
        let url = spawn_json_server(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"repo not found"}}"#,
        );

        let error = adopt_repo(&url, Path::new("/r")).expect_err("a JSON-RPC error must not pass");
        assert!(
            error.to_string().contains("repo not found"),
            "the server's own message must survive: {error}"
        );
    }

    #[test]
    fn adopt_repo_accepts_an_indexed_repo() {
        let url = spawn_json_server(
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text",
                "text":"Registered and indexed repository: /r"}]}}"#,
        );

        adopt_repo(&url, Path::new("/r")).expect("a successful reindex must be accepted");
    }

    /// The regression this whole feature exists for: a stdio process started
    /// before its SSE counterpart registers must still find it, as long as
    /// registration lands inside the retry budget.
    #[tokio::test]
    async fn find_at_with_retry_picks_up_a_server_registered_after_the_first_probe() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");
        // No record at t=0: the first probe inside the loop must miss.
        let url = spawn_200_server();

        let writer_path = path.clone();
        let writer_url = url.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            write_records(&writer_path, &[record(&writer_url, &["/r"])]);
        });

        let found = find_at_with_retry(&path, &[PathBuf::from("/r")], Duration::from_secs(3)).await;
        assert_eq!(
            found,
            Some((url, Vec::new())),
            "a retry budget spanning the late registration must still find it"
        );
    }

    /// retry_budget of zero must behave exactly like the pre-retry single
    /// probe: no waiting for a registration that arrives moments later.
    #[tokio::test]
    async fn find_at_with_retry_zero_budget_does_not_sleep() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json"); // no records at all

        let start = std::time::Instant::now();
        let found = find_at_with_retry(&path, &[PathBuf::from("/r")], Duration::ZERO).await;
        let elapsed = start.elapsed();

        assert!(found.is_none());
        assert!(
            elapsed < Duration::from_millis(200),
            "zero retry budget must not wait for a retry, took {:?}",
            elapsed
        );
    }
}
