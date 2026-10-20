//! Per-process status files for running narsil-xref servers.
//!
//! Every long-running narsil-xref process (SSE listener, stdio process with a
//! local index, or stdio process proxying to an SSE upstream) writes a status
//! file named `<pid>.status` so an out-of-band observer — chiefly
//! `narsil-xref stats` — can see which processes are alive, what role each
//! plays, the SSE URL it listens on or delegates to, and the per-repo symbol
//! counts. This is the data source that makes a stdio→SSE connection problem
//! diagnosable from a plain shell.
//!
//! Location: `/run/narsil-xref/<pid>.status` when that directory is creatable
//! and writable (system-wide, visible across users), otherwise
//! `$XDG_RUNTIME_DIR/narsil-xref/<pid>.status` (or the per-user cache dir when
//! XDG is unset) — the same per-user base the SSE discovery file uses. Because
//! a write can land in either location, readers scan both.
//!
//! A clean exit removes the file via the [`PidStatusEntry`] RAII guard. A
//! crash or `process::exit` (the stdio-proxy signal path) leaves the file
//! behind; such stale files are pruned on read by checking `/proc/<pid>`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// What a narsil-xref process is doing, as recorded in its status file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum ProcessRole {
    /// This process is an SSE listener bound to `url`.
    Sse { url: String },
    /// A stdio process serving its own local index.
    StdioLocal,
    /// A stdio process delegating MCP traffic to the SSE server at `upstream_url`.
    StdioProxy { upstream_url: String },
}

/// Per-repo symbol/file counts as seen by a running process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoStatus {
    pub path: PathBuf,
    pub symbol_count: usize,
    pub file_count: usize,
}

/// On-disk status record for one running narsil-xref process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PidStatus {
    pub pid: u32,
    /// "stdio" or "sse".
    pub transport: String,
    pub role: ProcessRole,
    /// Process start time, seconds since the Unix epoch.
    pub started_at_unix: u64,
    pub repos: Vec<RepoStatus>,
}

impl PidStatus {
    /// Build a status for the current process. Repo counts start at zero;
    /// call [`with_repo_counts`](Self::with_repo_counts) once indexing
    /// completes to fill them in.
    pub fn new(transport: &str, role: ProcessRole, repos: &[PathBuf]) -> Self {
        let repos = repos
            .iter()
            .map(|path| RepoStatus {
                path: path.clone(),
                symbol_count: 0,
                file_count: 0,
            })
            .collect();
        Self {
            pid: std::process::id(),
            transport: transport.to_string(),
            role,
            started_at_unix: now_unix(),
            repos,
        }
    }

    /// Replace the repo list with post-indexing counts. `snapshot` carries
    /// `(repo_key, symbol_count, file_count)` as produced by the engine.
    pub fn with_repo_counts(mut self, snapshot: Vec<(String, usize, usize)>) -> Self {
        self.repos = snapshot
            .into_iter()
            .map(|(path, symbol_count, file_count)| RepoStatus {
                path: PathBuf::from(path),
                symbol_count,
                file_count,
            })
            .collect();
        self
    }
}

/// RAII guard that removes this process's `<pid>.status` file on drop.
pub struct PidStatusEntry {
    path: PathBuf,
}

impl PidStatusEntry {
    /// Path of the file this entry was written to. Exposed for tests.
    pub fn file_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PidStatusEntry {
    fn drop(&mut self) {
        match fs::remove_file(&self.path) {
            Ok(()) => info!("pid status: removed {}", self.path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                "pid status: failed to remove {}: {}",
                self.path.display(),
                e
            ),
        }
    }
}

/// Write `status` to the first writable candidate directory and return a
/// guard that removes the file on drop. Use this for the process's initial
/// write, where the guard's lifetime bounds the file's lifetime; use
/// [`update_status`] to overwrite in place without affecting the guard.
pub fn write_status(status: &PidStatus) -> Result<PidStatusEntry> {
    let path = write_inner(status)?;
    info!("pid status: wrote {}", path.display());
    Ok(PidStatusEntry { path })
}

/// Overwrite the current process's status file in place (no guard). Lands on
/// the same path as the initial [`write_status`], so the existing guard still
/// owns removal.
pub fn update_status(status: &PidStatus) -> Result<()> {
    write_inner(status).map(|_| ())
}

/// Write `status` to the first writable candidate directory, returning the
/// path written.
fn write_inner(status: &PidStatus) -> Result<PathBuf> {
    let mut last_err: Option<anyhow::Error> = None;
    for dir in candidate_dirs() {
        match write_to_dir(&dir, status) {
            Ok(path) => return Ok(path),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no writable status directory")))
}

/// Read every live process's status from all candidate directories,
/// pruning files whose pid is no longer running. De-duplicated by pid.
pub fn read_all() -> Result<Vec<PidStatus>> {
    let mut out: Vec<PidStatus> = Vec::new();
    for dir in candidate_dirs() {
        for status in read_dir_statuses(&dir) {
            if !out.iter().any(|existing| existing.pid == status.pid) {
                out.push(status);
            }
        }
    }
    out.sort_by_key(|s| s.pid);
    Ok(out)
}

// ── internals ────────────────────────────────────────────────────────────

/// Directories that may hold status files, most-preferred first. The
/// system-wide `/run/narsil-xref` is tried before the per-user runtime dir;
/// both are returned so readers cover files written under either privilege.
fn candidate_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![Path::new("/run").join(crate::APP_NAME)];
    if let Some(user) = user_runtime_dir() {
        if !dirs.contains(&user) {
            dirs.push(user);
        }
    }
    dirs
}

/// Per-user runtime directory: `$XDG_RUNTIME_DIR/narsil-xref` when XDG is set
/// to an absolute path, else the per-user cache dir joined with `narsil-xref`.
/// Matches the base the SSE discovery file uses.
fn user_runtime_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(dir);
        if dir.is_absolute() {
            return Some(dir.join(crate::APP_NAME));
        }
    }
    directories::BaseDirs::new().map(|dirs| dirs.cache_dir().join(crate::APP_NAME))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Create `dir` (mode 0700 on Unix) and atomically write `<pid>.status` into
/// it. Returns the final path on success.
fn write_to_dir(dir: &Path, status: &PidStatus) -> Result<PathBuf> {
    ensure_dir(dir)?;
    let final_path = dir.join(format!("{}.status", status.pid));
    let tmp = dir.join(format!(".{}.status.tmp", status.pid));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("Failed to create {}", tmp.display()))?;
        let bytes = serde_json::to_vec_pretty(status)?;
        file.write_all(&bytes)?;
        let _ = file.sync_all();
    }
    if let Err(e) = fs::rename(&tmp, &final_path) {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow::Error::new(e).context(format!(
            "Failed to rename {} → {}",
            tmp.display(),
            final_path.display()
        )));
    }
    Ok(final_path)
}

fn ensure_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create status directory: {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort: a pre-existing root-owned /run/narsil-xref may reject the
        // chmod; the subsequent write decides whether this dir is usable.
        if let Ok(meta) = fs::metadata(dir) {
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            let _ = fs::set_permissions(dir, perms);
        }
    }
    Ok(())
}

/// Parse every `*.status` file in `dir`, removing those whose pid is dead.
fn read_dir_statuses(dir: &Path) -> Vec<PidStatus> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return out,
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("status") {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let status: PidStatus = match serde_json::from_slice(&bytes) {
            Ok(status) => status,
            Err(_) => continue,
        };
        if pid_is_dead(status.pid) {
            let _ = fs::remove_file(&path);
            continue;
        }
        out.push(status);
    }
    out
}

/// True when `pid` is provably not running. Only decisive where `/proc`
/// exists (Linux); elsewhere we conservatively treat the pid as alive so a
/// live process is never pruned.
fn pid_is_dead(pid: u32) -> bool {
    if !Path::new("/proc").is_dir() {
        return false;
    }
    !Path::new(&format!("/proc/{}", pid)).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample(pid: u32) -> PidStatus {
        PidStatus {
            pid,
            transport: "sse".to_string(),
            role: ProcessRole::Sse {
                url: "http://127.0.0.1:7557".to_string(),
            },
            started_at_unix: 1_700_000_000,
            repos: vec![RepoStatus {
                path: PathBuf::from("/repo/a"),
                symbol_count: 42,
                file_count: 7,
            }],
        }
    }

    #[test]
    fn write_and_read_round_trip() {
        let dir = TempDir::new().unwrap();
        // Use the current pid so the liveness prune keeps the record.
        let status = sample(std::process::id());
        let path = write_to_dir(dir.path(), &status).unwrap();
        assert!(path.exists());

        let read_back = read_dir_statuses(dir.path());
        assert_eq!(read_back, vec![status]);
    }

    #[test]
    fn dead_pid_status_is_pruned_on_read() {
        // Linux-only: pruning needs /proc to decide liveness.
        if !Path::new("/proc").is_dir() {
            return;
        }
        let dir = TempDir::new().unwrap();
        // pid 0 never names a live process; its /proc/0 does not exist.
        let path = write_to_dir(dir.path(), &sample(0)).unwrap();
        assert!(path.exists());

        let read_back = read_dir_statuses(dir.path());
        assert!(read_back.is_empty(), "dead-pid record should be pruned");
        assert!(!path.exists(), "dead-pid file should be removed");
    }

    #[test]
    fn entry_guard_removes_file_on_drop() {
        let dir = TempDir::new().unwrap();
        let path = write_to_dir(dir.path(), &sample(std::process::id())).unwrap();
        let entry = PidStatusEntry { path: path.clone() };
        assert!(entry.file_path().exists());
        drop(entry);
        assert!(
            !path.exists(),
            "guard should remove the status file on drop"
        );
    }

    #[test]
    fn with_repo_counts_replaces_repos() {
        let status = PidStatus::new(
            "stdio",
            ProcessRole::StdioLocal,
            &[PathBuf::from("/repo/a")],
        )
        .with_repo_counts(vec![("/repo/a".to_string(), 99, 12)]);
        assert_eq!(status.repos.len(), 1);
        assert_eq!(status.repos[0].symbol_count, 99);
        assert_eq!(status.repos[0].file_count, 12);
    }
}
