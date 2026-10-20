//! SSE server memory watchdog: diagnostics above the soft limit, exit above the hard limit.

use crate::byte_size::parse_byte_size;
use narsil_xref::index::CodeIntelEngine;
use narsil_xref::metrics::{format_bytes, MemoryReport};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

/// EX_TEMPFAIL; the systemd unit's Restart=on-failure starts the server again.
pub const EXIT_CODE: i32 = 75;
pub const DEFAULT_SOFT_LIMIT: MemoryLimit = MemoryLimit::TimesBaseline(1.5);
pub const DEFAULT_HARD_LIMIT: MemoryLimit = MemoryLimit::TimesBaseline(2.0);
pub const DEFAULT_SOFT_LIMIT_INTERVAL_SECS: u64 = 300;

const POLL_INTERVAL: Duration = Duration::from_secs(10);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
/// memory_report() takes the search index lock, which an index update can hold.
const MEMORY_REPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// A `--memory-soft-limit` / `--memory-hard-limit` value: `off`, `1.5x`, `512M`, `64G`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MemoryLimit {
    Off,
    /// Times the RSS after the last full index pass.
    TimesBaseline(f64),
    Bytes(usize),
}

impl FromStr for MemoryLimit {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let invalid = || {
            format!(
                "invalid memory limit '{}': expected off, <N>x, <N>M or <N>G",
                text
            )
        };
        if text.eq_ignore_ascii_case("off") {
            return Ok(MemoryLimit::Off);
        }
        let Some(suffix) = text.chars().last() else {
            return Err(invalid());
        };
        match suffix.to_ascii_lowercase() {
            'x' => {
                let number = &text[..text.len() - suffix.len_utf8()];
                let factor: f64 = number.parse().map_err(|_| invalid())?;
                if !factor.is_finite() || factor <= 0.0 {
                    return Err(invalid());
                }
                Ok(MemoryLimit::TimesBaseline(factor))
            }
            // A bare number or K would be bytes: `8` meant as 8G exits at once.
            'm' | 'g' => parse_byte_size(text)
                .map(MemoryLimit::Bytes)
                .map_err(|_| invalid()),
            _ => Err(invalid()),
        }
    }
}

impl fmt::Display for MemoryLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryLimit::Off => write!(f, "off"),
            MemoryLimit::TimesBaseline(factor) => write!(f, "{}x", factor),
            MemoryLimit::Bytes(bytes) => write!(f, "{}", format_bytes(*bytes)),
        }
    }
}

/// Error a soft limit at or above the hard limit; limits of different kinds cannot be compared.
pub fn check_soft_below_hard(soft: MemoryLimit, hard: MemoryLimit) -> anyhow::Result<()> {
    let soft_not_below = match (soft, hard) {
        (MemoryLimit::TimesBaseline(soft), MemoryLimit::TimesBaseline(hard)) => soft >= hard,
        (MemoryLimit::Bytes(soft), MemoryLimit::Bytes(hard)) => soft >= hard,
        _ => false,
    };
    if soft_not_below {
        anyhow::bail!(
            "memory soft limit {} must be below the memory hard limit {}",
            soft,
            hard
        );
    }
    Ok(())
}

/// The limit in bytes for `baseline` (0 = no full index pass yet), None when not checked.
fn limit_bytes(
    limit: MemoryLimit,
    baseline: usize,
    without_baseline: Option<usize>,
) -> Option<usize> {
    match limit {
        MemoryLimit::Off => None,
        MemoryLimit::Bytes(bytes) => Some(bytes),
        MemoryLimit::TimesBaseline(_) if baseline == 0 => without_baseline,
        MemoryLimit::TimesBaseline(factor) => Some((baseline as f64 * factor) as usize),
    }
}

/// `limit` when `rss` is above it.
fn exceeded(rss: usize, limit: Option<usize>) -> Option<usize> {
    limit.filter(|&limit| rss > limit)
}

pub struct WatchdogSettings {
    pub soft_limit: MemoryLimit,
    pub hard_limit: MemoryLimit,
    pub soft_limit_interval: Duration,
    pub diagnostics_dir: PathBuf,
}

/// Directory of `--log-file`, else the user state directory.
pub fn diagnostics_dir(log_file: Option<&Path>) -> PathBuf {
    if let Some(parent) = log_file.and_then(Path::parent) {
        if !parent.as_os_str().is_empty() {
            return parent.to_path_buf();
        }
    }
    let base_dirs = directories::BaseDirs::new();
    match base_dirs.as_ref().and_then(|dirs| dirs.state_dir()) {
        Some(state_dir) => state_dir.join(narsil_xref::APP_NAME),
        None => std::env::temp_dir().join(narsil_xref::APP_NAME),
    }
}

/// Above the hard limit the thread notifies `hard_limit_exit`, then exits the
/// process itself if `main` has not after `SHUTDOWN_DEADLINE`.
pub fn spawn_memory_watchdog(
    engine: Arc<CodeIntelEngine>,
    settings: WatchdogSettings,
    hard_limit_exit: Arc<Notify>,
) {
    if settings.soft_limit == MemoryLimit::Off && settings.hard_limit == MemoryLimit::Off {
        info!("Memory watchdog off");
        return;
    }
    info!(
        "Memory watchdog: soft limit {}, hard limit {}",
        settings.soft_limit, settings.hard_limit
    );
    let spawned = std::thread::Builder::new()
        .name("memory-watchdog".to_string())
        .spawn(move || watch_memory(engine, settings, hard_limit_exit));
    if let Err(e) = spawned {
        warn!("Could not start the memory watchdog thread: {}", e);
    }
}

/// While RSS stays above the soft limit.
struct SoftLimitState {
    last_summary: Instant,
    last_report: Option<MemoryReport>,
}

fn watch_memory(
    engine: Arc<CodeIntelEngine>,
    settings: WatchdogSettings,
    hard_limit_exit: Arc<Notify>,
) {
    // A `<N>x` hard limit before the first full index pass.
    let half_mem_total = mem_total_bytes().map(|total| total / 2);
    let mut soft_limit_state: Option<SoftLimitState> = None;
    loop {
        if let Some(measured_rss) = CodeIntelEngine::process_rss_bytes() {
            let baseline = engine.memory_baseline();
            let soft = limit_bytes(settings.soft_limit, baseline, None);
            let hard = limit_bytes(settings.hard_limit, baseline, half_mem_total);
            let mut rss = measured_rss;
            if exceeded(rss, soft).is_some() || exceeded(rss, hard).is_some() {
                CodeIntelEngine::return_freed_heap_to_os();
                rss = CodeIntelEngine::process_rss_bytes().unwrap_or(measured_rss);
                debug!(
                    "Memory watchdog: malloc_trim took RSS from {} to {}",
                    format_bytes(measured_rss),
                    format_bytes(rss)
                );
            }

            if let Some(limit) = exceeded(rss, hard) {
                let trigger = limit_line("hard", settings.hard_limit, limit, rss, baseline);
                let report = memory_report_with_timeout(&engine);
                let diag_path = write_memory_diagnostics(
                    &settings.diagnostics_dir,
                    &trigger,
                    report.as_ref(),
                    &engine,
                );
                let restart = if std::env::var_os("INVOCATION_ID").is_some() {
                    "systemd restarts the server"
                } else {
                    "not started by systemd, so nothing restarts it"
                };
                error!(
                    "{}; diagnostics in {}; shutting down, {}",
                    trigger,
                    display_path(diag_path.as_deref()),
                    restart
                );
                hard_limit_exit.notify_one();
                std::thread::sleep(SHUTDOWN_DEADLINE);
                error!(
                    "Shutdown did not finish within {:?}, exiting with code {}",
                    SHUTDOWN_DEADLINE, EXIT_CODE
                );
                std::process::exit(EXIT_CODE);
            }

            if let Some(limit) = exceeded(rss, soft) {
                match &mut soft_limit_state {
                    None => {
                        let trigger = limit_line("soft", settings.soft_limit, limit, rss, baseline);
                        let report = memory_report_with_timeout(&engine);
                        let diag_path = write_memory_diagnostics(
                            &settings.diagnostics_dir,
                            &trigger,
                            report.as_ref(),
                            &engine,
                        );
                        warn!(
                            "{}; diagnostics in {}",
                            trigger,
                            display_path(diag_path.as_deref())
                        );
                        soft_limit_state = Some(SoftLimitState {
                            last_summary: Instant::now(),
                            last_report: report,
                        });
                    }
                    Some(state) if state.last_summary.elapsed() >= settings.soft_limit_interval => {
                        let trigger = limit_line("soft", settings.soft_limit, limit, rss, baseline);
                        let report = memory_report_with_timeout(&engine);
                        let summary = match (&report, &state.last_report) {
                            (Some(now), Some(before)) => now.growth_line(before),
                            (Some(now), None) => now.summary_line(),
                            (None, _) => "memory_report() did not finish".to_string(),
                        };
                        warn!("{}; {}", trigger, summary);
                        state.last_summary = Instant::now();
                        if report.is_some() {
                            state.last_report = report;
                        }
                    }
                    Some(_) => {}
                }
            } else if soft_limit_state.take().is_some() {
                info!(
                    "RSS {} is back under the memory soft limit",
                    format_bytes(rss)
                );
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn limit_line(
    kind: &str,
    setting: MemoryLimit,
    limit: usize,
    rss: usize,
    baseline: usize,
) -> String {
    let baseline_text = if baseline == 0 {
        "no full index pass yet".to_string()
    } else {
        format_bytes(baseline)
    };
    format!(
        "RSS {} is above the memory {} limit {} = {} (baseline {})",
        format_bytes(rss),
        kind,
        setting,
        format_bytes(limit),
        baseline_text
    )
}

fn display_path(path: Option<&Path>) -> String {
    match path {
        Some(path) => path.display().to_string(),
        None => "no file".to_string(),
    }
}

fn memory_report_with_timeout(engine: &Arc<CodeIntelEngine>) -> Option<MemoryReport> {
    let (sender, receiver) = std::sync::mpsc::channel();
    let engine = Arc::clone(engine);
    let spawned = std::thread::Builder::new()
        .name("memory-report".to_string())
        .spawn(move || {
            let _ = sender.send(engine.memory_report());
        });
    if let Err(e) = spawned {
        warn!("Could not start the memory_report() thread: {}", e);
        return None;
    }
    match receiver.recv_timeout(MEMORY_REPORT_TIMEOUT) {
        Ok(report) => Some(report),
        Err(_) => {
            warn!(
                "memory_report() did not finish within {:?}",
                MEMORY_REPORT_TIMEOUT
            );
            None
        }
    }
}

/// Path of the written `memory-<pid>-<unix time>.diag`, None when writing failed.
fn write_memory_diagnostics(
    dir: &Path,
    trigger: &str,
    report: Option<&MemoryReport>,
    engine: &CodeIntelEngine,
) -> Option<PathBuf> {
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let path = dir.join(format!("memory-{}-{}.diag", std::process::id(), unix_time));
    match write_diagnostics_file(dir, &path, trigger, report, engine) {
        Ok(()) => Some(path),
        Err(e) => {
            warn!("Could not write {}: {}", path.display(), e);
            None
        }
    }
}

fn write_diagnostics_file(
    dir: &Path,
    path: &Path,
    trigger: &str,
    report: Option<&MemoryReport>,
    engine: &CodeIntelEngine,
) -> io::Result<()> {
    const STATUS_FIELDS: [&str; 9] = [
        "VmPeak:",
        "VmSize:",
        "VmHWM:",
        "VmRSS:",
        "RssAnon:",
        "RssFile:",
        "RssShmem:",
        "VmSwap:",
        "Threads:",
    ];
    std::fs::create_dir_all(dir)?;
    let mut file = File::create(path)?;
    writeln!(
        file,
        "narsil-xref {} ({}) pid {}",
        env!("CARGO_PKG_VERSION"),
        env!("NARSIL_BUILD_ID"),
        std::process::id()
    )?;
    writeln!(file, "{}", trigger)?;

    writeln!(file, "\n== /proc/self/status")?;
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if STATUS_FIELDS.iter().any(|field| line.starts_with(field)) {
            writeln!(file, "{}", line)?;
        }
    }

    writeln!(file, "\n== /proc/self/smaps_rollup")?;
    match std::fs::read_to_string("/proc/self/smaps_rollup") {
        Ok(rollup) => file.write_all(rollup.as_bytes())?,
        Err(e) => writeln!(file, "unavailable: {}", e)?,
    }

    writeln!(file, "\n== threads by name")?;
    for (name, count) in thread_name_counts() {
        writeln!(file, "{:>4}  {}", count, name)?;
    }

    writeln!(file, "\n== memory_report")?;
    match report {
        Some(report) => file.write_all(report.render_table().as_bytes())?,
        None => writeln!(file, "memory_report() did not finish")?,
    }

    writeln!(file, "\n== repos (symbols, files)")?;
    for (repo, symbol_count, file_count) in engine.repo_status_snapshot() {
        writeln!(file, "{} {} {}", repo, symbol_count, file_count)?;
    }

    writeln!(file, "\n== malloc_info")?;
    file.flush()?;
    write_malloc_info(file)
}

fn thread_name_counts() -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    if let Ok(tasks) = std::fs::read_dir("/proc/self/task") {
        for task in tasks.flatten() {
            if let Ok(name) = std::fs::read_to_string(task.path().join("comm")) {
                *counts.entry(name.trim().to_string()).or_insert(0) += 1;
            }
        }
    }
    counts
}

fn mem_total_bytes() -> Option<usize> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: usize = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// glibc's per-arena XML: shows how much freed memory the arenas keep.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn write_malloc_info(file: File) -> io::Result<()> {
    use std::os::fd::{FromRawFd, IntoRawFd};
    use std::os::raw::{c_char, c_int};

    #[repr(C)]
    struct CFile {
        _private: [u8; 0],
    }
    extern "C" {
        fn fdopen(fd: c_int, mode: *const c_char) -> *mut CFile;
        fn malloc_info(options: c_int, stream: *mut CFile) -> c_int;
        fn fclose(stream: *mut CFile) -> c_int;
    }

    let fd = file.into_raw_fd();
    // SAFETY: fd is an open file this function owns; on success the FILE
    // stream takes it over and fclose closes it.
    unsafe {
        let stream = fdopen(fd, c"a".as_ptr());
        if stream.is_null() {
            let error = io::Error::last_os_error();
            drop(File::from_raw_fd(fd));
            return Err(error);
        }
        let rc = malloc_info(0, stream);
        fclose(stream);
        if rc != 0 {
            return Err(io::Error::other("malloc_info failed"));
        }
    }
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn write_malloc_info(mut file: File) -> io::Result<()> {
    writeln!(file, "not available on this platform")
}

/// `main`'s shutdown error when the hard limit ended the server.
#[derive(Debug)]
pub struct HardLimitExceeded;

impl fmt::Display for HardLimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "memory hard limit exceeded")
    }
}

impl std::error::Error for HardLimitExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_limit_parses_every_form() {
        assert_eq!("off".parse(), Ok(MemoryLimit::Off));
        assert_eq!("OFF".parse(), Ok(MemoryLimit::Off));
        assert_eq!("1.5x".parse(), Ok(MemoryLimit::TimesBaseline(1.5)));
        assert_eq!("2X".parse(), Ok(MemoryLimit::TimesBaseline(2.0)));
        assert_eq!("512M".parse(), Ok(MemoryLimit::Bytes(512 << 20)));
        assert_eq!("64g".parse(), Ok(MemoryLimit::Bytes(64 << 30)));
    }

    #[test]
    fn test_memory_limit_rejects_garbage() {
        for text in [
            "", "x", "1.5", "0x", "-1x", "nanx", "0G", "1.5G", "64T", "lotsG", "é", "8", "8K",
        ] {
            assert!(
                text.parse::<MemoryLimit>().is_err(),
                "'{}' must not parse",
                text
            );
        }
    }

    #[test]
    fn test_limit_bytes_per_kind() {
        let gib = 1 << 30;
        assert_eq!(limit_bytes(MemoryLimit::Off, gib, Some(gib)), None);
        assert_eq!(limit_bytes(MemoryLimit::Bytes(gib), 0, None), Some(gib));
        assert_eq!(
            limit_bytes(MemoryLimit::TimesBaseline(1.5), 2 * gib, None),
            Some(3 * gib)
        );
        // No full index pass yet: soft passes None, hard passes half of MemTotal.
        assert_eq!(limit_bytes(MemoryLimit::TimesBaseline(2.0), 0, None), None);
        assert_eq!(
            limit_bytes(MemoryLimit::TimesBaseline(2.0), 0, Some(8 * gib)),
            Some(8 * gib)
        );
    }

    #[test]
    fn test_soft_limit_must_be_below_hard_limit() {
        let times = MemoryLimit::TimesBaseline;
        let bytes = MemoryLimit::Bytes;
        assert!(check_soft_below_hard(times(1.5), times(2.0)).is_ok());
        assert!(check_soft_below_hard(times(2.0), times(2.0)).is_err());
        assert!(check_soft_below_hard(bytes(2 << 30), bytes(1 << 30)).is_err());
        assert!(check_soft_below_hard(bytes(1 << 30), times(2.0)).is_ok());
        assert!(check_soft_below_hard(MemoryLimit::Off, times(2.0)).is_ok());
    }
}
