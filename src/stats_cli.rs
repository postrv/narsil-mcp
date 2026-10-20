//! `narsil-xref stats` CLI subcommand.
//!
//! Reads persistent metrics from `~/.cache/narsil-xref/stats/` without
//! starting an engine, and prints either aggregate or per-`index_path`
//! views. Designed so users can check "how much has narsil helped me?"
//! from a plain shell.

use crate::metrics::{
    global_stats_dir, index_path_hash, list_stats_files, render_aggregate_json,
    render_aggregate_markdown, render_list_markdown, stats_file_for, PersistedMetrics,
};
use crate::pid_status::{self, PidStatus, ProcessRole};
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Output format for `stats` subcommands.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum StatsFormat {
    Markdown,
    Json,
}

#[derive(Debug, clap::Args)]
pub struct StatsArgs {
    /// Show one row per index_path instead of aggregating.
    #[arg(long)]
    pub list: bool,

    /// Restrict the report to one specific index_path (canonical path, the
    /// same value you'd pass to `--index-path` when starting the server).
    #[arg(long)]
    pub index_path: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = StatsFormat::Markdown)]
    pub format: StatsFormat,

    /// Show where stats are stored and exit.
    #[arg(long)]
    pub show_path: bool,
}

pub fn handle_stats_command(args: StatsArgs) -> Result<()> {
    if args.show_path {
        println!("{}", global_stats_dir().display());
        return Ok(());
    }

    if let Some(index_path) = args.index_path.as_ref() {
        return handle_single(index_path, args.format);
    }

    if args.list {
        return handle_list(args.format);
    }

    handle_aggregate(args.format)
}

fn handle_single(index_path: &std::path::Path, format: StatsFormat) -> Result<()> {
    let file = stats_file_for(index_path);
    if !file.exists() {
        anyhow::bail!(
            "No stats found for index path {:?} (looked for {:?}). \
             Has narsil-xref ever been started with --index-path {:?}?",
            index_path,
            file,
            index_path,
        );
    }
    let snapshot = PersistedMetrics::load(&file)
        .with_context(|| format!("Failed to read stats file {:?}", file))?;
    emit(&[snapshot], format)
}

fn handle_aggregate(format: StatsFormat) -> Result<()> {
    emit_live_processes(format)?;
    let snapshots = collect_all()?;
    emit(&snapshots, format)
}

/// Print the live "Running narsil-xref processes" view: one block per process
/// found in the pid-status directories, showing its role, SSE URL, and the
/// per-repo symbol counts. Dead-pid files are pruned by `read_all`.
fn emit_live_processes(format: StatsFormat) -> Result<()> {
    let procs = pid_status::read_all().unwrap_or_default();
    match format {
        StatsFormat::Markdown => print!("{}", render_live_processes_markdown(&procs)),
        StatsFormat::Json => {
            // JSON callers consume the live view as a sibling document.
            println!("{}", serde_json::to_string_pretty(&procs)?);
        }
    }
    Ok(())
}

fn render_live_processes_markdown(procs: &[PidStatus]) -> String {
    let mut out = String::from("# Running narsil-xref processes\n\n");
    if procs.is_empty() {
        out.push_str("*No running narsil-xref processes found.*\n\n");
        return out;
    }
    for proc in procs {
        let role = match &proc.role {
            ProcessRole::Sse { url } => format!("sse, listening on {}", url),
            ProcessRole::StdioLocal => "stdio, local index".to_string(),
            ProcessRole::StdioProxy { upstream_url } => {
                format!("stdio, proxy → {}", upstream_url)
            }
        };
        out.push_str(&format!("## PID {} — {}\n", proc.pid, role));

        // For an SSE listener, "connected instances" are the live stdio
        // narsil-xref processes delegating to its URL. There is no persistent
        // SSE connection to count server-side; each proxy is a stateless POST
        // client, so its status record is the authoritative signal.
        if let ProcessRole::Sse { url } = &proc.role {
            let connected = connected_instance_pids(procs, url);
            out.push_str(&format!("- connected instances: {}", connected.len()));
            if !connected.is_empty() {
                let pids: Vec<String> = connected.iter().map(|pid| pid.to_string()).collect();
                out.push_str(&format!(" (pids: {})", pids.join(", ")));
            }
            out.push('\n');
        }

        if proc.repos.is_empty() {
            out.push_str("- *(no repositories)*\n");
        }
        let is_proxy = matches!(proc.role, ProcessRole::StdioProxy { .. });
        for repo in &proc.repos {
            if is_proxy {
                // A proxy holds no local symbols; counts live in the upstream.
                out.push_str(&format!("- `{}` (delegated)\n", repo.path.display()));
            } else {
                out.push_str(&format!(
                    "- `{}` — {} symbols, {} files\n",
                    repo.path.display(),
                    repo.symbol_count,
                    repo.file_count
                ));
            }
        }
        out.push('\n');
    }
    out
}

/// Pids of stdio proxies whose `upstream_url` matches `sse_url` — i.e. the
/// instances currently delegating to this SSE listener. URLs are compared
/// with a trailing slash trimmed so registry and proxy forms agree.
fn connected_instance_pids(procs: &[PidStatus], sse_url: &str) -> Vec<u32> {
    let target = sse_url.trim_end_matches('/');
    procs
        .iter()
        .filter_map(|proc| match &proc.role {
            ProcessRole::StdioProxy { upstream_url }
                if upstream_url.trim_end_matches('/') == target =>
            {
                Some(proc.pid)
            }
            _ => None,
        })
        .collect()
}

fn handle_list(format: StatsFormat) -> Result<()> {
    emit_live_processes(format)?;
    let files = list_stats_files()?;
    let mut pairs: Vec<(PathBuf, PersistedMetrics)> = Vec::with_capacity(files.len());
    for file in files {
        match PersistedMetrics::load(&file) {
            Ok(snap) => pairs.push((file, snap)),
            Err(e) => eprintln!("warning: skipping unreadable stats file {:?}: {}", file, e),
        }
    }
    // Most-recently-updated first.
    pairs.sort_by(|a, b| b.1.saved_at.cmp(&a.1.saved_at));

    match format {
        StatsFormat::Markdown => {
            print!("{}", render_list_markdown(&pairs));
        }
        StatsFormat::Json => {
            let json: Vec<serde_json::Value> = pairs
                .iter()
                .map(|(path, snap)| {
                    serde_json::json!({
                        "stats_file": path.to_string_lossy(),
                        "index_path": snap.index_path,
                        "index_path_hash": index_path_hash(std::path::Path::new(&snap.index_path)),
                        "first_started_at": snap.first_started_at,
                        "saved_at": snap.saved_at,
                        "total_uptime_seconds": snap.total_uptime_seconds,
                        "total_requests": snap.total_requests(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }
    Ok(())
}

fn collect_all() -> Result<Vec<PersistedMetrics>> {
    let files = list_stats_files()?;
    let mut out = Vec::with_capacity(files.len());
    for file in files {
        match PersistedMetrics::load(&file) {
            Ok(snap) => out.push(snap),
            Err(e) => eprintln!("warning: skipping unreadable stats file {:?}: {}", file, e),
        }
    }
    Ok(out)
}

fn emit(snapshots: &[PersistedMetrics], format: StatsFormat) -> Result<()> {
    match format {
        StatsFormat::Markdown => {
            print!("{}", render_aggregate_markdown(snapshots)?);
        }
        StatsFormat::Json => {
            let json = render_aggregate_json(snapshots)?;
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sse(pid: u32, url: &str) -> PidStatus {
        PidStatus {
            pid,
            transport: "sse".to_string(),
            role: ProcessRole::Sse {
                url: url.to_string(),
            },
            started_at_unix: 0,
            repos: vec![],
        }
    }

    fn proxy(pid: u32, upstream: &str) -> PidStatus {
        PidStatus {
            pid,
            transport: "stdio".to_string(),
            role: ProcessRole::StdioProxy {
                upstream_url: upstream.to_string(),
            },
            started_at_unix: 0,
            repos: vec![],
        }
    }

    #[test]
    fn connected_pids_match_proxies_by_upstream_url() {
        let procs = vec![
            sse(1, "http://127.0.0.1:7557"),
            proxy(2, "http://127.0.0.1:7557"),
            proxy(3, "http://127.0.0.1:7557/"), // trailing slash still matches
            proxy(4, "http://127.0.0.1:9999"),  // different server
            PidStatus {
                pid: 5,
                transport: "stdio".to_string(),
                role: ProcessRole::StdioLocal, // not a proxy
                started_at_unix: 0,
                repos: vec![PathBuf::from("/x")]
                    .into_iter()
                    .map(|path| crate::pid_status::RepoStatus {
                        path,
                        symbol_count: 0,
                        file_count: 0,
                    })
                    .collect(),
            },
        ];

        let connected = connected_instance_pids(&procs, "http://127.0.0.1:7557");
        assert_eq!(connected, vec![2, 3]);
    }

    #[test]
    fn connected_pids_empty_when_no_proxies() {
        let procs = vec![sse(1, "http://127.0.0.1:7557")];
        assert!(connected_instance_pids(&procs, "http://127.0.0.1:7557").is_empty());
    }
}
