//! Performance metrics tracking for tool operations.
//!
//! Counters are stored ccache-style in a global per-`index_path` file under
//! `~/.cache/narsil-mcp/stats/<hash>.bin`. The same file is shared by every
//! narsil-mcp instance that uses the same `--index-path`; concurrent writers
//! coordinate via an advisory file lock and a delta-based merge so that no
//! instance's contribution is clobbered.
//!
//! Each process keeps three views:
//!   - **session**: counters since process start (reset on every restart).
//!   - **baseline**: shared state loaded from disk; refreshed at every flush.
//!   - **delta**: counters accumulated since the last successful flush.
//!
//! The displayed *lifetime* view is `baseline + delta`. On flush we re-read
//! the shared file (it may have advanced because of other processes), merge
//! our delta in, write atomically, and reset `baseline = merged` / `delta = 0`.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use fs4::fs_std::FileExt;
use hdrhistogram::serialization::{Deserializer, Serializer, V2Serializer};
use hdrhistogram::Histogram;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Notify;
use tracing::{debug, warn};

/// HDR histogram significant figures — 3 gives ~0.1% precision, plenty for
/// tool latencies in the µs–s range.
const HISTOGRAM_SIGFIG: u8 = 3;

/// Default flush cadence when no override is provided.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(180);

/// Length of the hex-encoded SHA-256 prefix used as the on-disk filename.
const PATH_HASH_LEN: usize = 16;

// ---------- MetricStats ------------------------------------------------------

/// Statistics for a single metric stream (one tool, or file parsing).
///
/// Units of `total`/`min`/`max` are determined by the caller: tool times are
/// recorded in milliseconds, file-parse times in microseconds. Field names
/// keep the historical `_ms` suffix even though the data may be µs — callers
/// know which is which by context.
#[derive(Clone)]
pub struct MetricStats {
    pub count: u64,
    pub total_ms: u64,
    pub min_ms: u64,
    pub max_ms: u64,
    histogram: Histogram<u64>,
}

impl Default for MetricStats {
    fn default() -> Self {
        let mut histogram =
            Histogram::<u64>::new(HISTOGRAM_SIGFIG).expect("sigfig=3 is always valid");
        histogram.auto(true);
        Self {
            count: 0,
            total_ms: 0,
            min_ms: u64::MAX,
            max_ms: 0,
            histogram,
        }
    }
}

impl std::fmt::Debug for MetricStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricStats")
            .field("count", &self.count)
            .field("total_ms", &self.total_ms)
            .field("min_ms", &self.min_ms)
            .field("max_ms", &self.max_ms)
            .finish()
    }
}

impl MetricStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, duration_units: u64) {
        self.count += 1;
        self.total_ms += duration_units;
        self.min_ms = self.min_ms.min(duration_units);
        self.max_ms = self.max_ms.max(duration_units);
        // HDR histograms reject 0; bump to 1 so the percentile is still meaningful
        // for sub-resolution samples without skewing the distribution materially.
        let value = duration_units.max(1);
        if let Err(e) = self.histogram.record(value) {
            debug!("HDR histogram record failed for value {}: {}", value, e);
        }
    }

    pub fn avg_ms(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total_ms as f64 / self.count as f64
        }
    }

    pub fn percentile(&self, p: f64) -> u64 {
        if self.histogram.is_empty() {
            return 0;
        }
        self.histogram.value_at_quantile(p / 100.0)
    }

    pub fn p50(&self) -> u64 {
        self.percentile(50.0)
    }

    pub fn p95(&self) -> u64 {
        self.percentile(95.0)
    }

    pub fn p99(&self) -> u64 {
        self.percentile(99.0)
    }

    /// Merge another stats stream into this one.
    pub fn merge_from(&mut self, other: &MetricStats) {
        self.count += other.count;
        self.total_ms += other.total_ms;
        if other.count > 0 {
            self.min_ms = self.min_ms.min(other.min_ms);
            self.max_ms = self.max_ms.max(other.max_ms);
        }
        if let Err(e) = self.histogram.add(&other.histogram) {
            warn!("HDR histogram merge failed: {}", e);
        }
    }

    fn to_persisted(&self) -> Result<PersistedCounter> {
        let mut buf = Vec::new();
        let mut serializer = V2Serializer::new();
        serializer
            .serialize(&self.histogram, &mut buf)
            .context("Failed to serialise HDR histogram")?;
        Ok(PersistedCounter {
            count: self.count,
            total_ms: self.total_ms,
            min_ms: if self.count == 0 { 0 } else { self.min_ms },
            max_ms: self.max_ms,
            histogram_bytes: buf,
        })
    }

    fn from_persisted(p: &PersistedCounter) -> Result<Self> {
        let mut deserializer = Deserializer::new();
        let mut histogram = deserializer
            .deserialize::<u64, _>(&mut p.histogram_bytes.as_slice())
            .context("Failed to deserialise HDR histogram")?;
        // V2Deserializer doesn't preserve the auto-resize flag, but we always
        // want it on so future merges can grow the histogram if a process
        // contributes values above the previously-seen range.
        histogram.auto(true);
        Ok(Self {
            count: p.count,
            total_ms: p.total_ms,
            min_ms: if p.count == 0 { u64::MAX } else { p.min_ms },
            max_ms: p.max_ms,
            histogram,
        })
    }
}

/// Repository indexing metrics (session-only, not persisted).
#[derive(Debug, Clone)]
pub struct RepoIndexMetrics {
    pub repo_name: String,
    pub index_time_ms: u64,
    pub file_count: usize,
    pub symbol_count: usize,
    pub indexed_at: Instant,
}

// ---------- Persistence types -----------------------------------------------

/// On-disk metric counter, one per tool (plus one for file parsing).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedCounter {
    count: u64,
    total_ms: u64,
    min_ms: u64,
    max_ms: u64,
    histogram_bytes: Vec<u8>,
}

/// On-disk heap snapshot: the live [`MemoryReport`] plus when it was taken.
/// Overwritten (not merged) on each flush — memory is a per-run snapshot, not a
/// counter. Added in v3; lost its `neural` field in v4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedMemoryReport {
    /// Unix seconds when the engine measured this snapshot.
    pub measured_at: u64,
    pub report: MemoryReport,
}

/// On-disk metric snapshot. Loaded on startup, written periodically and on
/// shutdown so accumulated counters survive process restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedMetrics {
    pub version: u32,
    /// Canonical filesystem path of the index this stats file describes —
    /// kept readable for `narsil-mcp stats --list` output.
    pub index_path: String,
    /// Unix seconds when this metrics file was first created.
    pub first_started_at: u64,
    /// Unix seconds when the snapshot was last written.
    pub saved_at: u64,
    /// Cumulative server uptime across all runs that share this file, in seconds.
    pub total_uptime_seconds: u64,
    tools: HashMap<String, PersistedCounter>,
    file_parse: PersistedCounter,
    /// Per-backend C/C++ reference query call counts (added in v2).
    backends: HashMap<String, u64>,
    /// Heap snapshot from the most recent run (None for migrated v1/v2 files;
    /// added in v3).
    pub memory: Option<PersistedMemoryReport>,
}

/// v3 on-disk layout, whose [`MemoryReportV3`] still carried the always-zero
/// `neural` slot. Kept only so `load` can migrate those files. Field order
/// must match the v3 structs exactly — postcard is positional and not
/// self-describing.
///
/// `Serialize` is derived only so tests can write authentic v3 byte streams;
/// production code never serialises this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedMetricsV3 {
    version: u32,
    index_path: String,
    first_started_at: u64,
    saved_at: u64,
    total_uptime_seconds: u64,
    tools: HashMap<String, PersistedCounter>,
    file_parse: PersistedCounter,
    backends: HashMap<String, u64>,
    memory: Option<PersistedMemoryReportV3>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedMemoryReportV3 {
    measured_at: u64,
    report: MemoryReportV3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemoryReportV3 {
    symbols: usize,
    search_index: usize,
    embeddings: usize,
    file_cache: usize,
    call_graphs: usize,
    repos: usize,
    git_repos: usize,
    neural: usize,
    process_rss: Option<usize>,
}

impl PersistedMetricsV3 {
    fn upgrade(self) -> PersistedMetrics {
        PersistedMetrics {
            version: PersistedMetrics::CURRENT_VERSION,
            index_path: self.index_path,
            first_started_at: self.first_started_at,
            saved_at: self.saved_at,
            total_uptime_seconds: self.total_uptime_seconds,
            tools: self.tools,
            file_parse: self.file_parse,
            backends: self.backends,
            memory: self.memory.map(|m| PersistedMemoryReport {
                measured_at: m.measured_at,
                report: MemoryReport {
                    symbols: m.report.symbols,
                    search_index: m.report.search_index,
                    embeddings: m.report.embeddings,
                    file_cache: m.report.file_cache,
                    call_graphs: m.report.call_graphs,
                    repos: m.report.repos,
                    git_repos: m.report.git_repos,
                    process_rss: m.report.process_rss,
                },
            }),
        }
    }
}

/// v1 on-disk layout (pre-`backends`). Kept only so `load` can migrate files
/// written before per-backend counts existed, preserving their tool/uptime
/// history. Field order must match the original v1 struct exactly — postcard
/// is positional and not self-describing.
///
/// `Serialize` is derived only so tests can write authentic v1 byte streams;
/// production code never serialises this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedMetricsV1 {
    version: u32,
    index_path: String,
    first_started_at: u64,
    saved_at: u64,
    total_uptime_seconds: u64,
    tools: HashMap<String, PersistedCounter>,
    file_parse: PersistedCounter,
}

impl PersistedMetricsV1 {
    fn upgrade(self) -> PersistedMetrics {
        PersistedMetrics {
            version: PersistedMetrics::CURRENT_VERSION,
            index_path: self.index_path,
            first_started_at: self.first_started_at,
            saved_at: self.saved_at,
            total_uptime_seconds: self.total_uptime_seconds,
            tools: self.tools,
            file_parse: self.file_parse,
            backends: HashMap::new(),
            memory: None,
        }
    }
}

/// v2 on-disk layout (pre-`memory`). Kept only so `load` can migrate files
/// written before the heap snapshot existed, preserving their tool/backend/
/// uptime history. Field order must match the v2 struct exactly — postcard is
/// positional and not self-describing.
///
/// `Serialize` is derived only so tests can write authentic v2 byte streams;
/// production code never serialises this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedMetricsV2 {
    version: u32,
    index_path: String,
    first_started_at: u64,
    saved_at: u64,
    total_uptime_seconds: u64,
    tools: HashMap<String, PersistedCounter>,
    file_parse: PersistedCounter,
    backends: HashMap<String, u64>,
}

impl PersistedMetricsV2 {
    fn upgrade(self) -> PersistedMetrics {
        PersistedMetrics {
            version: PersistedMetrics::CURRENT_VERSION,
            index_path: self.index_path,
            first_started_at: self.first_started_at,
            saved_at: self.saved_at,
            total_uptime_seconds: self.total_uptime_seconds,
            tools: self.tools,
            file_parse: self.file_parse,
            backends: self.backends,
            memory: None,
        }
    }
}

impl PersistedMetrics {
    const CURRENT_VERSION: u32 = 4;

    fn empty(index_path: String) -> Self {
        let now = now_unix_seconds();
        Self {
            version: Self::CURRENT_VERSION,
            index_path,
            first_started_at: now,
            saved_at: now,
            total_uptime_seconds: 0,
            tools: HashMap::new(),
            file_parse: empty_persisted_counter(),
            backends: HashMap::new(),
            memory: None,
        }
    }

    /// Read and decode a stats file. Returns an error for any failure
    /// (missing file, bad version, deserialisation failure).
    ///
    /// Older files lack the trailing fields each version added (`backends` in
    /// v2, `memory` in v3) or carry a slot v4 dropped, so decoding them at the
    /// current layout hits EOF or a wrong version. postcard ignores trailing
    /// bytes, so we try the largest layout first and fall back through v3 and
    /// v2 to v1, upgrading in place.
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).context("Failed to read metrics file")?;
        if let Ok(snapshot) = postcard::from_bytes::<Self>(&data) {
            if snapshot.version == Self::CURRENT_VERSION {
                return Ok(snapshot);
            }
        }
        if let Ok(v3) = postcard::from_bytes::<PersistedMetricsV3>(&data) {
            if v3.version == 3 {
                return Ok(v3.upgrade());
            }
        }
        if let Ok(v2) = postcard::from_bytes::<PersistedMetricsV2>(&data) {
            if v2.version == 2 {
                return Ok(v2.upgrade());
            }
        }
        let v1: PersistedMetricsV1 = postcard::from_bytes(&data)
            .context("Failed to deserialise metrics file (tried v4, v3, v2 and v1)")?;
        if v1.version != 1 {
            return Err(anyhow::anyhow!(
                "Unsupported metrics file version: {}",
                v1.version
            ));
        }
        Ok(v1.upgrade())
    }

    fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create stats directory")?;
        }
        let data = postcard::to_stdvec(self).context("Failed to serialise metrics")?;
        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, &data).context("Failed to write temp metrics file")?;
        std::fs::rename(&temp_path, path).context("Failed to rename metrics file into place")?;
        Ok(())
    }

    /// Total recorded requests across all tools in this snapshot.
    pub fn total_requests(&self) -> u64 {
        self.tools.values().map(|t| t.count).sum()
    }
}

fn empty_persisted_counter() -> PersistedCounter {
    MetricStats::new()
        .to_persisted()
        .expect("empty histogram always serialises")
}

// ---------- Path resolution --------------------------------------------------

/// Hex-encoded SHA-256 prefix of a canonical filesystem path. Used as the
/// filename for the per-`index_path` stats file. Stable across runs and OS-
/// safe.
pub fn index_path_hash(canonical_path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_path.as_os_str().to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    hex[..PATH_HASH_LEN].to_string()
}

/// Directory holding all per-`index_path` stats files. Created on demand.
pub fn global_stats_dir() -> PathBuf {
    if let Some(dirs) = ProjectDirs::from("", "", "narsil-mcp") {
        dirs.cache_dir().join("stats")
    } else {
        // Fallback: $HOME/.cache/narsil-mcp/stats. ProjectDirs only fails when
        // the platform has no notion of a home directory, which is rare.
        PathBuf::from("/tmp/narsil-mcp/stats")
    }
}

/// Resolve the stats file path for a given index_path. The directory is
/// created if it doesn't yet exist.
pub fn stats_file_for(index_path: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(index_path).unwrap_or_else(|_| index_path.to_path_buf());
    let hash = index_path_hash(&canonical);
    global_stats_dir().join(format!("{}.bin", hash))
}

/// Lock file accompanying a stats file. Holding an exclusive lock on this
/// file guards the read-merge-write cycle against concurrent writers.
fn lock_file_for(stats_path: &Path) -> PathBuf {
    stats_path.with_extension("lock")
}

/// `pub(crate)`: also used by `gtags` to serialize database writes — the
/// open+flock sequence here is generic over any path, not stats-specific.
pub(crate) fn acquire_exclusive_lock(stats_path: &Path) -> Result<File> {
    let lock_path = lock_file_for(stats_path);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create stats directory for lock")?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("Failed to open lock file at {:?}", lock_path))?;
    file.lock_exclusive()
        .context("Failed to acquire exclusive lock on stats file")?;
    Ok(file)
}

// ---------- LifetimeCounters / Metrics --------------------------------------

#[derive(Default)]
struct CounterSet {
    tools: HashMap<String, MetricStats>,
    file_parse: MetricStats,
    /// Per-backend C/C++ reference query call counts, keyed by backend label
    /// ("clangd", "ccls", "gtags").
    backends: HashMap<String, u64>,
}

impl CounterSet {
    fn record_tool(&mut self, name: &str, duration_units: u64) {
        self.tools
            .entry(name.to_string())
            .or_default()
            .record(duration_units);
    }

    fn record_backend_call(&mut self, label: &str) {
        *self.backends.entry(label.to_string()).or_insert(0) += 1;
    }

    fn merge_from(&mut self, other: &CounterSet) {
        for (name, stats) in &other.tools {
            self.tools
                .entry(name.clone())
                .or_default()
                .merge_from(stats);
        }
        self.file_parse.merge_from(&other.file_parse);
        for (label, count) in &other.backends {
            *self.backends.entry(label.clone()).or_insert(0) += count;
        }
    }

    fn from_persisted(p: &PersistedMetrics) -> Result<Self> {
        let mut tools = HashMap::with_capacity(p.tools.len());
        for (name, pc) in &p.tools {
            tools.insert(name.clone(), MetricStats::from_persisted(pc)?);
        }
        Ok(Self {
            tools,
            file_parse: MetricStats::from_persisted(&p.file_parse)?,
            backends: p.backends.clone(),
        })
    }

    fn write_into_persisted(&self, target: &mut PersistedMetrics) -> Result<()> {
        let mut tools = HashMap::with_capacity(self.tools.len());
        for (name, stats) in &self.tools {
            tools.insert(name.clone(), stats.to_persisted()?);
        }
        target.tools = tools;
        target.file_parse = self.file_parse.to_persisted()?;
        target.backends = self.backends.clone();
        Ok(())
    }
}

struct LifetimeState {
    /// Baseline = last shared state read from disk (loaded at startup, refreshed
    /// after every successful flush). Other concurrent processes' contributions
    /// land here when we re-read at flush time.
    baseline: CounterSet,
    /// Counters accumulated since the baseline was set. Merged into the shared
    /// file at flush time, then cleared.
    deltas: CounterSet,
    /// Total uptime persisted in the shared file the last time we read it.
    persisted_uptime_seconds: u64,
    /// Unix seconds of the first ever invocation that wrote to this file.
    first_started_at: u64,
    /// Canonical index path this lifetime view describes.
    index_path: String,
    /// Session seconds we've already attributed to the lifetime uptime in a
    /// previous flush; used to compute the next increment without double-counting.
    uptime_credited: u64,
}

impl LifetimeState {
    fn fresh(index_path: String) -> Self {
        Self {
            baseline: CounterSet::default(),
            deltas: CounterSet::default(),
            persisted_uptime_seconds: 0,
            first_started_at: now_unix_seconds(),
            index_path,
            uptime_credited: 0,
        }
    }

    fn from_persisted(p: PersistedMetrics) -> Result<Self> {
        Ok(Self {
            baseline: CounterSet::from_persisted(&p)?,
            deltas: CounterSet::default(),
            persisted_uptime_seconds: p.total_uptime_seconds,
            first_started_at: p.first_started_at,
            index_path: p.index_path,
            uptime_credited: 0,
        })
    }

    /// View shown to callers: baseline + pending deltas.
    fn snapshot(&self) -> CounterSet {
        let mut combined = CounterSet::default();
        combined.merge_from(&self.baseline);
        combined.merge_from(&self.deltas);
        combined
    }
}

/// Global metrics collection.
pub struct Metrics {
    start_time: Instant,
    /// Session-only counters (reset on process start).
    tool_metrics: RwLock<HashMap<String, MetricStats>>,
    /// Per-tool response size in bytes. Session-only and not persisted: it
    /// exists to make an oversized response visible before it costs a session.
    tool_response_bytes: RwLock<HashMap<String, MetricStats>>,
    repo_index_metrics: RwLock<Vec<RepoIndexMetrics>>,
    file_parse_metrics: RwLock<MetricStats>,
    /// Lifetime counters split into baseline + deltas. See module docs.
    lifetime: RwLock<LifetimeState>,
    /// Persistence target. `None` means metrics are session-only.
    persist_path: Option<PathBuf>,
    /// Set whenever lifetime counters change; cleared by the flush task.
    dirty: AtomicBool,
    /// Notifies the flush task to wake up (used for shutdown).
    flush_notify: Arc<Notify>,
    /// Full list of registered tool names, used to show zero rows in reports.
    /// In-memory only; not persisted.
    known_tools: RwLock<Vec<String>>,
    /// Session-only per-backend C/C++ reference query counts (reset on start).
    /// The lifetime view lives in the shared `lifetime` state.
    backend_calls: RwLock<HashMap<String, u64>>,
    /// Latest live heap snapshot from this run, written to disk on the next
    /// flush. None until the engine reports one; overwritten, never merged.
    memory_snapshot: RwLock<Option<PersistedMemoryReport>>,
}

impl Metrics {
    /// In-memory only — no persistence. Used in tests and when persistence is
    /// explicitly disabled.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            tool_metrics: RwLock::new(HashMap::new()),
            tool_response_bytes: RwLock::new(HashMap::new()),
            repo_index_metrics: RwLock::new(Vec::new()),
            file_parse_metrics: RwLock::new(MetricStats::new()),
            lifetime: RwLock::new(LifetimeState::fresh(String::new())),
            persist_path: None,
            dirty: AtomicBool::new(false),
            flush_notify: Arc::new(Notify::new()),
            known_tools: RwLock::new(Vec::new()),
            backend_calls: RwLock::new(HashMap::new()),
            memory_snapshot: RwLock::new(None),
        }
    }

    /// Create a Metrics instance backed by the global per-`index_path` stats
    /// file. The actual file is `~/.cache/narsil-mcp/stats/<hash>.bin`.
    pub fn with_persistence(index_path: PathBuf) -> Self {
        let stats_path = stats_file_for(&index_path);
        let canonical_str = std::fs::canonicalize(&index_path)
            .unwrap_or(index_path)
            .to_string_lossy()
            .to_string();

        let lifetime = if stats_path.exists() {
            match PersistedMetrics::load(&stats_path) {
                Ok(snapshot) => LifetimeState::from_persisted(snapshot).unwrap_or_else(|e| {
                    warn!(
                        "Stats file at {:?} parsed but decode failed: {} — starting fresh",
                        stats_path, e
                    );
                    LifetimeState::fresh(canonical_str.clone())
                }),
                Err(e) => {
                    warn!(
                        "Failed to load stats file at {:?}: {} — starting fresh",
                        stats_path, e
                    );
                    LifetimeState::fresh(canonical_str.clone())
                }
            }
        } else {
            LifetimeState::fresh(canonical_str.clone())
        };

        Self {
            start_time: Instant::now(),
            tool_metrics: RwLock::new(HashMap::new()),
            tool_response_bytes: RwLock::new(HashMap::new()),
            repo_index_metrics: RwLock::new(Vec::new()),
            file_parse_metrics: RwLock::new(MetricStats::new()),
            lifetime: RwLock::new(lifetime),
            persist_path: Some(stats_path),
            dirty: AtomicBool::new(false),
            flush_notify: Arc::new(Notify::new()),
            known_tools: RwLock::new(Vec::new()),
            backend_calls: RwLock::new(HashMap::new()),
            memory_snapshot: RwLock::new(None),
        }
    }

    fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Record a tool execution time (milliseconds).
    pub fn record_tool(&self, tool_name: &str, duration: Duration) {
        let duration_ms = duration.as_millis() as u64;
        self.tool_metrics
            .write()
            .entry(tool_name.to_string())
            .or_default()
            .record(duration_ms);
        self.lifetime
            .write()
            .deltas
            .record_tool(tool_name, duration_ms);
        self.mark_dirty();
    }

    /// Record the size of a tool's rendered response, before any clamping.
    pub fn record_tool_response(&self, tool_name: &str, response_bytes: usize) {
        self.tool_response_bytes
            .write()
            .entry(tool_name.to_string())
            .or_default()
            .record(response_bytes as u64);
    }

    /// Per-tool response sizes recorded this session, in bytes.
    pub fn get_tool_response_bytes(&self) -> HashMap<String, MetricStats> {
        self.tool_response_bytes.read().clone()
    }

    /// Record one query to a reference backend (an LSP backend or language id
    /// such as "clangd", "ccls", "rust", or "gtags"). Call counts only —
    /// surfaced by `narsil-mcp stats` so a user can see which backends are
    /// actually being exercised.
    pub fn record_backend_call(&self, label: &str) {
        *self
            .backend_calls
            .write()
            .entry(label.to_string())
            .or_insert(0) += 1;
        self.lifetime.write().deltas.record_backend_call(label);
        self.mark_dirty();
    }

    /// Record the engine's live heap breakdown for persistence. Unlike the
    /// counters, this is a snapshot: it overwrites any previous value and is
    /// written verbatim (not merged) by the next flush.
    pub fn set_memory_report(&self, report: MemoryReport) {
        *self.memory_snapshot.write() = Some(PersistedMemoryReport {
            measured_at: now_unix_seconds(),
            report,
        });
        self.mark_dirty();
    }

    /// Record a repository indexing run (session-only — not persisted).
    pub fn record_repo_index(
        &self,
        repo_name: String,
        duration: Duration,
        file_count: usize,
        symbol_count: usize,
    ) {
        let metric = RepoIndexMetrics {
            repo_name,
            index_time_ms: duration.as_millis() as u64,
            file_count,
            symbol_count,
            indexed_at: Instant::now(),
        };
        self.repo_index_metrics.write().push(metric);
    }

    /// Record a single file parsing time (microseconds).
    pub fn record_file_parse(&self, duration: Duration) {
        let duration_us = duration.as_micros() as u64;
        self.file_parse_metrics.write().record(duration_us);
        self.lifetime.write().deltas.file_parse.record(duration_us);
        self.mark_dirty();
    }

    pub fn get_tool_stats(&self, tool_name: &str) -> Option<MetricStats> {
        self.tool_metrics.read().get(tool_name).cloned()
    }

    pub fn get_all_tool_stats(&self) -> HashMap<String, MetricStats> {
        self.tool_metrics.read().clone()
    }

    pub fn get_repo_index_metrics(&self) -> Vec<RepoIndexMetrics> {
        self.repo_index_metrics.read().clone()
    }

    pub fn get_file_parse_stats(&self) -> MetricStats {
        self.file_parse_metrics.read().clone()
    }

    pub fn total_requests(&self) -> u64 {
        self.tool_metrics.read().values().map(|s| s.count).sum()
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn uptime_string(&self) -> String {
        format_duration_seconds(self.uptime_seconds())
    }

    /// Lifetime view: baseline (last loaded shared state) merged with our
    /// deltas since the last flush.
    pub fn get_lifetime_tool_stats(&self) -> HashMap<String, MetricStats> {
        self.lifetime.read().snapshot().tools
    }

    pub fn get_lifetime_file_parse_stats(&self) -> MetricStats {
        self.lifetime.read().snapshot().file_parse
    }

    /// Session per-backend call counts (since process start).
    pub fn get_session_backend_calls(&self) -> HashMap<String, u64> {
        self.backend_calls.read().clone()
    }

    /// Lifetime per-backend call counts (baseline + pending deltas).
    pub fn get_lifetime_backend_calls(&self) -> HashMap<String, u64> {
        self.lifetime.read().snapshot().backends
    }

    /// Cumulative uptime across all runs that share this stats file.
    pub fn lifetime_uptime_seconds(&self) -> u64 {
        let state = self.lifetime.read();
        // Uncredited portion of this session's uptime — what would be added
        // on the next flush. Showing it live keeps the lifetime number from
        // appearing to "freeze" between flushes.
        let uncredited = self.uptime_seconds().saturating_sub(state.uptime_credited);
        state.persisted_uptime_seconds + uncredited
    }

    pub fn first_started_at(&self) -> u64 {
        self.lifetime.read().first_started_at
    }

    /// Register the full set of tool names so that reports can show zero rows
    /// for tools that have never been called. Call once at startup after the
    /// tool registry is built. In-memory only; not persisted.
    pub fn set_known_tools(&self, names: Vec<String>) {
        *self.known_tools.write() = names;
    }

    pub fn lifetime_total_requests(&self) -> u64 {
        let state = self.lifetime.read();
        let baseline: u64 = state.baseline.tools.values().map(|s| s.count).sum();
        let deltas: u64 = state.deltas.tools.values().map(|s| s.count).sum();
        baseline + deltas
    }

    fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::Relaxed)
    }

    /// Force-write lifetime counters to disk. Re-reads the shared file under
    /// an exclusive lock so concurrent writers' contributions are preserved.
    pub fn flush(&self) -> Result<()> {
        let Some(path) = self.persist_path.as_ref() else {
            return Ok(());
        };

        // Lock first — everything between here and unlock is the critical
        // section. The lock is held across the read-merge-write cycle so two
        // processes can't both read-then-overwrite the same shared state.
        let _lock = acquire_exclusive_lock(path)?;

        // Re-read what's on disk *now* (may have advanced past our baseline
        // because of other concurrent processes).
        let mut current = if path.exists() {
            match PersistedMetrics::load(path) {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    warn!(
                        "Stats file at {:?} unreadable during flush ({}); rewriting from scratch",
                        path, e
                    );
                    PersistedMetrics::empty(self.lifetime.read().index_path.clone())
                }
            }
        } else {
            PersistedMetrics::empty(self.lifetime.read().index_path.clone())
        };

        // Decode current shared state, merge our deltas into it.
        let mut merged = CounterSet::from_persisted(&current).unwrap_or_default();
        {
            let state = self.lifetime.read();
            merged.merge_from(&state.deltas);
        }

        // Compute uptime delta to add to the shared total.
        let session_uptime = self.uptime_seconds();
        let uptime_delta = {
            let state = self.lifetime.read();
            session_uptime.saturating_sub(state.uptime_credited)
        };

        // Write merged counters into the persisted struct.
        merged.write_into_persisted(&mut current)?;
        // Memory is a snapshot, not a counter: overwrite with this run's value
        // if we have one, otherwise preserve whatever the file already held.
        if let Some(snapshot) = self.memory_snapshot.read().clone() {
            current.memory = Some(snapshot);
        }
        current.saved_at = now_unix_seconds();
        current.total_uptime_seconds = current.total_uptime_seconds.saturating_add(uptime_delta);
        // Preserve the earliest first_started_at across concurrent writers.
        {
            let state = self.lifetime.read();
            if state.first_started_at != 0 && state.first_started_at < current.first_started_at {
                current.first_started_at = state.first_started_at;
            }
            current.index_path = state.index_path.clone();
        }

        current.save(path)?;

        // Update our local baseline to match what we just wrote; clear deltas
        // and bump the uptime-credited bookkeeping.
        {
            let mut state = self.lifetime.write();
            state.baseline = merged;
            state.deltas = CounterSet::default();
            state.persisted_uptime_seconds = current.total_uptime_seconds;
            state.uptime_credited = session_uptime;
            state.first_started_at = current.first_started_at;
        }

        debug!("Flushed metrics to {:?}", path);
        // `_lock` is dropped here, releasing the advisory lock.
        Ok(())
    }

    pub fn is_persistent(&self) -> bool {
        self.persist_path.is_some()
    }

    pub fn persist_path(&self) -> Option<&Path> {
        self.persist_path.as_deref()
    }

    pub fn shutdown_notifier(&self) -> Arc<Notify> {
        self.flush_notify.clone()
    }

    pub fn notify_shutdown(&self) {
        self.flush_notify.notify_waiters();
    }

    /// Generate a formatted Markdown metrics report.
    pub fn report(&self) -> String {
        let mut output = String::new();
        let lifetime_snapshot = self.lifetime.read().snapshot();
        let index_path = self.lifetime.read().index_path.clone();

        output.push_str("# Performance Metrics\n\n");
        if !index_path.is_empty() {
            output.push_str(&format!("**Index path**: {}\n", index_path));
        }
        output.push_str(&format!("**Session Uptime**: {}\n", self.uptime_string()));
        output.push_str(&format!(
            "**Lifetime Uptime**: {} (tracking since {})\n",
            format_duration_seconds(self.lifetime_uptime_seconds()),
            format_unix_timestamp(self.first_started_at())
        ));
        output.push_str(&format!(
            "**Session Requests**: {}\n",
            self.total_requests()
        ));
        output.push_str(&format!(
            "**Lifetime Requests**: {}\n\n",
            self.lifetime_total_requests()
        ));

        output.push_str("## Repository Indexing (this session)\n\n");
        let repo_metrics = self.get_repo_index_metrics();
        if !repo_metrics.is_empty() {
            output.push_str("| Repository | Index Time | Files | Symbols | Files/sec |\n");
            output.push_str("|------------|------------|-------|---------|----------|\n");
            for metric in &repo_metrics {
                let files_per_sec = if metric.index_time_ms > 0 {
                    (metric.file_count as f64 / (metric.index_time_ms as f64 / 1000.0)).round()
                        as u64
                } else {
                    0
                };
                output.push_str(&format!(
                    "| {} | {}ms | {} | {} | {} |\n",
                    metric.repo_name,
                    metric.index_time_ms,
                    metric.file_count,
                    metric.symbol_count,
                    files_per_sec
                ));
            }
            output.push('\n');
        } else {
            output.push_str("*No repositories indexed yet.*\n\n");
        }

        let session_parse = self.get_file_parse_stats();
        let lifetime_parse = &lifetime_snapshot.file_parse;
        if session_parse.count > 0 || lifetime_parse.count > 0 {
            output.push_str("## File Parsing\n\n");
            let mut parse_rows: Vec<(&str, &MetricStats)> = Vec::new();
            if session_parse.count > 0 {
                parse_rows.push(("Session", &session_parse));
            }
            if lifetime_parse.count > 0 {
                parse_rows.push(("Lifetime", lifetime_parse));
            }
            push_parse_table(&mut output, &parse_rows);
        }

        push_backend_table(
            &mut output,
            &lifetime_snapshot.backends,
            Some(&self.get_session_backend_calls()),
        );

        let known = self.known_tools.read();
        let lifetime_tools = fill_known_tools(&lifetime_snapshot.tools, &known);
        let session_tools = fill_known_tools(&self.get_all_tool_stats(), &known);

        output.push_str("## Tool Execution Times (Lifetime)\n\n");
        if !lifetime_tools.is_empty() {
            push_tool_table(&mut output, &lifetime_tools);
        } else {
            output.push_str("*No tool calls recorded yet.*\n");
        }
        output.push('\n');

        output.push_str("## Tool Execution Times (This Session)\n\n");
        if !session_tools.is_empty() {
            push_tool_table(&mut output, &session_tools);
        } else {
            output.push_str("*No tool calls recorded this session.*\n");
        }
        output.push('\n');

        let response_sizes = self.get_tool_response_bytes();
        output.push_str("## Tool Response Sizes (This Session)\n\n");
        if !response_sizes.is_empty() {
            push_response_size_table(&mut output, &response_sizes);
        } else {
            output.push_str("*No tool responses recorded this session.*\n");
        }

        output
    }

    /// Generate a JSON report of all metrics.
    pub fn report_json(&self) -> serde_json::Value {
        use serde_json::json;

        let lifetime_snapshot = self.lifetime.read().snapshot();
        let session_tools_json = tool_stats_to_json(&self.get_all_tool_stats());
        let lifetime_tools_json = tool_stats_to_json(&lifetime_snapshot.tools);

        let repo_metrics = self.get_repo_index_metrics();
        let repo_json: Vec<serde_json::Value> = repo_metrics
            .iter()
            .map(|metric| {
                json!({
                    "repo_name": metric.repo_name,
                    "index_time_ms": metric.index_time_ms,
                    "file_count": metric.file_count,
                    "symbol_count": metric.symbol_count
                })
            })
            .collect();

        json!({
            "session": {
                "uptime_seconds": self.uptime_seconds(),
                "uptime_string": self.uptime_string(),
                "total_requests": self.total_requests(),
                "file_parsing": parse_stats_to_json(&self.get_file_parse_stats()),
                "tools": session_tools_json,
                "tool_response_bytes": tool_stats_to_json(&self.get_tool_response_bytes()),
                "cxx_backends": backend_calls_to_json(&self.get_session_backend_calls()),
            },
            "lifetime": {
                "index_path": self.lifetime.read().index_path,
                "first_started_at": self.first_started_at(),
                "uptime_seconds": self.lifetime_uptime_seconds(),
                "uptime_string": format_duration_seconds(self.lifetime_uptime_seconds()),
                "total_requests": self.lifetime_total_requests(),
                "file_parsing": parse_stats_to_json(&lifetime_snapshot.file_parse),
                "tools": lifetime_tools_json,
                "cxx_backends": backend_calls_to_json(&lifetime_snapshot.backends),
                "persistent": self.is_persistent(),
            },
            "repository_indexing": repo_json,
        })
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Metrics {
    /// Best-effort sync flush so metrics aren't lost if the engine is dropped
    /// without an explicit shutdown call. Errors are logged, not propagated —
    /// Drop must not panic.
    fn drop(&mut self) {
        if !self.dirty.load(Ordering::Relaxed) {
            return;
        }
        if self.persist_path.is_none() {
            return;
        }
        if let Err(e) = self.flush() {
            warn!("Metrics flush on drop failed: {}", e);
        }
    }
}

// ---------- Helpers / rendering ---------------------------------------------

/// C/C++ reference backends always shown in stats output, so a backend that is
/// enabled but never resolves appears as a `0` row rather than vanishing.
const CXX_BACKENDS: [&str; 3] = ["clangd", "ccls", "gtags"];

/// Return a copy of `recorded` extended with zero-count entries for every name
/// in `known` that is not already present. This ensures the report table lists
/// every registered tool even if it has never been called.
fn fill_known_tools(
    recorded: &HashMap<String, MetricStats>,
    known: &[String],
) -> HashMap<String, MetricStats> {
    let mut out = recorded.clone();
    for name in known {
        out.entry(name.clone()).or_default();
    }
    out
}

/// Build the rows for a backend-calls table: the three known backends first
/// (zero-filled), then any other labels that were recorded, sorted.
fn backend_rows(recorded: &HashMap<String, u64>) -> Vec<(String, u64)> {
    let mut rows: Vec<(String, u64)> = CXX_BACKENDS
        .iter()
        .map(|label| {
            (
                label.to_string(),
                recorded.get(*label).copied().unwrap_or(0),
            )
        })
        .collect();
    let mut extra: Vec<(String, u64)> = recorded
        .iter()
        .filter(|(label, _)| !CXX_BACKENDS.contains(&label.as_str()))
        .map(|(label, count)| (label.clone(), *count))
        .collect();
    extra.sort_by(|a, b| a.0.cmp(&b.0));
    rows.extend(extra);
    rows
}

/// Render a `## Reference Backends` markdown section listing call counts.
/// `lifetime`/`session` are the two scopes; pass `session = None` for the
/// aggregate (`stats`) view which has no session.
fn push_backend_table(
    output: &mut String,
    lifetime: &HashMap<String, u64>,
    session: Option<&HashMap<String, u64>>,
) {
    output.push_str("## Reference Backends\n\n");
    let life_rows = backend_rows(lifetime);
    match session {
        Some(sess) => {
            output.push_str("| Backend | Lifetime Calls | Session Calls |\n");
            output.push_str("|---------|----------------|---------------|\n");
            for (label, life) in &life_rows {
                let sess_count = sess.get(label).copied().unwrap_or(0);
                output.push_str(&format!("| {} | {} | {} |\n", label, life, sess_count));
            }
        }
        None => {
            output.push_str("| Backend | Calls |\n");
            output.push_str("|---------|-------|\n");
            for (label, life) in &life_rows {
                output.push_str(&format!("| {} | {} |\n", label, life));
            }
        }
    }
    output.push('\n');
}

fn backend_calls_to_json(calls: &HashMap<String, u64>) -> serde_json::Value {
    serde_json::Value::Object(
        backend_rows(calls)
            .into_iter()
            .map(|(label, count)| (label, serde_json::Value::from(count)))
            .collect(),
    )
}

/// Render a `## Memory (most recent run)` section from the per-`index_path`
/// snapshots that carry one. Memory is never summed across paths: a single
/// snapshot gets the full per-subsystem breakdown, multiple get one row each.
fn push_memory_section(output: &mut String, snapshots: &[PersistedMetrics]) {
    let with_memory: Vec<&PersistedMetrics> = snapshots
        .iter()
        .filter(|snap| snap.memory.is_some())
        .collect();

    output.push_str("## Memory (most recent run)\n\n");
    if with_memory.is_empty() {
        output.push_str("*No memory snapshot recorded yet.*\n\n");
        return;
    }

    // Single index path: show the full per-subsystem breakdown.
    if let [snap] = with_memory.as_slice() {
        let mem = snap.memory.as_ref().expect("filtered to Some");
        if !snap.index_path.is_empty() {
            output.push_str(&format!("**Index path**: {}\n", snap.index_path));
        }
        output.push_str(&format!(
            "**Measured**: {}\n\n",
            format_unix_timestamp(mem.measured_at)
        ));
        output.push_str(&mem.report.render_table());
        output.push('\n');
        return;
    }

    // Multiple index paths: one compact row each (never summed).
    output.push_str("| Index Path | Measured | Tracked | RSS |\n");
    output.push_str("|------------|----------|---------|-----|\n");
    for snap in &with_memory {
        let mem = snap.memory.as_ref().expect("filtered to Some");
        let rss = mem
            .report
            .process_rss
            .map(format_bytes)
            .unwrap_or_else(|| "n/a".to_string());
        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            snap.index_path,
            format_unix_timestamp(mem.measured_at),
            format_bytes(mem.report.total_tracked()),
            rss
        ));
    }
    output.push('\n');
}

fn push_md_row<'a>(output: &mut String, cells: impl Iterator<Item = &'a str>, widths: &[usize]) {
    output.push('|');
    for (cell, w) in cells.zip(widths.iter()) {
        output.push_str(&format!(" {:<width$} |", cell, width = w));
    }
    output.push('\n');
}

fn push_md_sep(output: &mut String, widths: &[usize]) {
    output.push('|');
    for w in widths {
        output.push_str(&"-".repeat(w + 2));
        output.push('|');
    }
    output.push('\n');
}

fn push_parse_table(output: &mut String, rows: &[(&str, &MetricStats)]) {
    let headers = ["Scope", "Files Parsed", "Avg", "Min", "Max"];
    let data: Vec<[String; 5]> = rows
        .iter()
        .map(|(scope, stats)| {
            [
                scope.to_string(),
                stats.count.to_string(),
                format!("{:.2}µs", stats.avg_ms()),
                format!("{}µs", stats.min_ms),
                format!("{}µs", stats.max_ms),
            ]
        })
        .collect();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &data {
        for (col, cell) in row.iter().enumerate() {
            widths[col] = widths[col].max(cell.len());
        }
    }
    push_md_row(output, headers.iter().copied(), &widths);
    push_md_sep(output, &widths);
    for row in &data {
        push_md_row(output, row.iter().map(|s| s.as_str()), &widths);
    }
    output.push('\n');
}

fn push_tool_table(output: &mut String, tools: &HashMap<String, MetricStats>) {
    let headers = ["Tool", "Calls", "Avg (ms)", "Min (ms)", "Max (ms)"];
    let mut sorted: Vec<_> = tools.iter().collect();
    sorted.sort_by_key(|(name, _)| name.as_str().to_owned());
    let data: Vec<[String; 5]> = sorted
        .iter()
        .map(|(name, stats)| {
            let min = if stats.count == 0 { 0 } else { stats.min_ms };
            [
                name.to_string(),
                stats.count.to_string(),
                format!("{:.2}", stats.avg_ms()),
                min.to_string(),
                stats.max_ms.to_string(),
            ]
        })
        .collect();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &data {
        for (col, cell) in row.iter().enumerate() {
            widths[col] = widths[col].max(cell.len());
        }
    }
    push_md_row(output, headers.iter().copied(), &widths);
    push_md_sep(output, &widths);
    for row in &data {
        push_md_row(output, row.iter().map(|s| s.as_str()), &widths);
    }
}

/// Response sizes reuse MetricStats, whose fields are ms-named but unit-agnostic.
fn push_response_size_table(output: &mut String, tools: &HashMap<String, MetricStats>) {
    let headers = ["Tool", "Responses", "Avg (bytes)", "Max (bytes)"];
    let mut sorted: Vec<_> = tools.iter().collect();
    sorted.sort_by_key(|(_, stats)| std::cmp::Reverse(stats.max_ms));
    let data: Vec<[String; 4]> = sorted
        .iter()
        .map(|(name, stats)| {
            [
                name.to_string(),
                stats.count.to_string(),
                format!("{:.0}", stats.avg_ms()),
                stats.max_ms.to_string(),
            ]
        })
        .collect();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &data {
        for (col, cell) in row.iter().enumerate() {
            widths[col] = widths[col].max(cell.len());
        }
    }
    push_md_row(output, headers.iter().copied(), &widths);
    push_md_sep(output, &widths);
    for row in &data {
        push_md_row(output, row.iter().map(|s| s.as_str()), &widths);
    }
}

fn tool_stats_to_json(tools: &HashMap<String, MetricStats>) -> serde_json::Value {
    use serde_json::json;
    tools
        .iter()
        .map(|(name, stats)| {
            (
                name.clone(),
                json!({
                    "count": stats.count,
                    "avg_ms": stats.avg_ms(),
                    "min_ms": stats.min_ms,
                    "max_ms": stats.max_ms,
                    "total_ms": stats.total_ms,
                }),
            )
        })
        .collect()
}

fn parse_stats_to_json(stats: &MetricStats) -> serde_json::Value {
    use serde_json::json;
    json!({
        "count": stats.count,
        "avg_us": stats.avg_ms(),
        "min_us": stats.min_ms,
        "max_us": stats.max_ms,
    })
}

fn format_duration_seconds(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

fn format_unix_timestamp(seconds: u64) -> String {
    use chrono::DateTime;
    DateTime::from_timestamp(seconds as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("{}", seconds))
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------- CLI helpers ------------------------------------------------------

/// List every per-`index_path` stats file under the global stats directory.
/// Returns an empty vec if the dir doesn't exist yet.
pub fn list_stats_files() -> Result<Vec<PathBuf>> {
    let dir = global_stats_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .with_context(|| format!("Failed to read stats directory {:?}", dir))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("bin") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Aggregate counters across many persisted snapshots and render them as a
/// markdown report. Used by `narsil-mcp stats`.
pub fn render_aggregate_markdown(snapshots: &[PersistedMetrics]) -> Result<String> {
    let mut merged = CounterSet::default();
    let mut total_uptime: u64 = 0;
    let mut earliest = u64::MAX;
    let mut latest = 0u64;
    let mut total_requests: u64 = 0;
    for snap in snapshots {
        let set = CounterSet::from_persisted(snap)?;
        merged.merge_from(&set);
        total_uptime = total_uptime.saturating_add(snap.total_uptime_seconds);
        earliest = earliest.min(snap.first_started_at);
        latest = latest.max(snap.saved_at);
        total_requests = total_requests.saturating_add(snap.total_requests());
    }
    if snapshots.is_empty() {
        earliest = 0;
    }

    let mut output = String::new();
    output.push_str("# narsil-mcp Lifetime Stats\n\n");
    output.push_str(&format!("**Index paths covered**: {}\n", snapshots.len()));
    output.push_str(&format!("**Total Requests**: {}\n", total_requests));
    output.push_str(&format!(
        "**Total Uptime**: {}\n",
        format_duration_seconds(total_uptime)
    ));
    if !snapshots.is_empty() {
        output.push_str(&format!(
            "**Tracking Since**: {}\n",
            format_unix_timestamp(earliest)
        ));
        output.push_str(&format!(
            "**Last Update**: {}\n\n",
            format_unix_timestamp(latest)
        ));
    } else {
        output.push('\n');
    }

    if merged.file_parse.count > 0 {
        output.push_str("## File Parsing\n\n");
        output.push_str("| Files Parsed | Avg | Min | Max | P50 | P95 | P99 |\n");
        output.push_str("|--------------|-----|-----|-----|-----|-----|-----|\n");
        let stats = &merged.file_parse;
        output.push_str(&format!(
            "| {} | {:.2}µs | {}µs | {}µs | {}µs | {}µs | {}µs |\n\n",
            stats.count,
            stats.avg_ms(),
            stats.min_ms,
            stats.max_ms,
            stats.p50(),
            stats.p95(),
            stats.p99()
        ));
    }

    push_backend_table(&mut output, &merged.backends, None);

    push_memory_section(&mut output, snapshots);

    output.push_str("## Tool Execution Times\n\n");
    if merged.tools.is_empty() {
        output.push_str("*No tool calls recorded.*\n");
    } else {
        push_tool_table(&mut output, &merged.tools);
    }

    Ok(output)
}

/// One-row-per-stats-file summary for `narsil-mcp stats --list`.
pub fn render_list_markdown(snapshots: &[(PathBuf, PersistedMetrics)]) -> String {
    let mut output = String::new();
    output.push_str("# narsil-mcp Stats Files\n\n");
    if snapshots.is_empty() {
        output.push_str("*No stats files found.*\n");
        return output;
    }
    output.push_str(
        "| Index Path | Requests | Tracking Since | Last Update | Total Uptime | Tracked Heap | RSS |\n",
    );
    output.push_str(
        "|------------|----------|----------------|-------------|--------------|--------------|-----|\n",
    );
    for (_path, snap) in snapshots {
        let (heap, rss) = match snap.memory.as_ref() {
            Some(mem) => (
                format_bytes(mem.report.total_tracked()),
                mem.report
                    .process_rss
                    .map(format_bytes)
                    .unwrap_or_else(|| "n/a".to_string()),
            ),
            None => ("n/a".to_string(), "n/a".to_string()),
        };
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            snap.index_path,
            snap.total_requests(),
            format_unix_timestamp(snap.first_started_at),
            format_unix_timestamp(snap.saved_at),
            format_duration_seconds(snap.total_uptime_seconds),
            heap,
            rss
        ));
    }
    output
}

/// Render the aggregate as JSON for scripts.
pub fn render_aggregate_json(snapshots: &[PersistedMetrics]) -> Result<serde_json::Value> {
    use serde_json::json;
    let mut merged = CounterSet::default();
    let mut total_uptime: u64 = 0;
    let mut earliest = u64::MAX;
    let mut latest = 0u64;
    let mut total_requests: u64 = 0;
    for snap in snapshots {
        let set = CounterSet::from_persisted(snap)?;
        merged.merge_from(&set);
        total_uptime = total_uptime.saturating_add(snap.total_uptime_seconds);
        earliest = earliest.min(snap.first_started_at);
        latest = latest.max(snap.saved_at);
        total_requests = total_requests.saturating_add(snap.total_requests());
    }
    if snapshots.is_empty() {
        earliest = 0;
    }

    // Memory is per-run and never summed across index paths — emit one entry
    // per snapshot that carries a heap breakdown.
    let memory_by_index_path: Vec<serde_json::Value> = snapshots
        .iter()
        .filter_map(|snap| {
            let mem = snap.memory.as_ref()?;
            Some(json!({
                "index_path": snap.index_path,
                "measured_at": mem.measured_at,
                "tracked_bytes": mem.report.total_tracked(),
                "process_rss_bytes": mem.report.process_rss,
                "subsystems": {
                    "symbols": mem.report.symbols,
                    "search_index": mem.report.search_index,
                    "embeddings": mem.report.embeddings,
                    "file_cache": mem.report.file_cache,
                    "call_graphs": mem.report.call_graphs,
                    "repos": mem.report.repos,
                    "git_repos": mem.report.git_repos,
                },
            }))
        })
        .collect();

    Ok(json!({
        "index_paths_covered": snapshots.len(),
        "total_requests": total_requests,
        "total_uptime_seconds": total_uptime,
        "first_started_at": earliest,
        "last_update_at": latest,
        "file_parsing": parse_stats_to_json(&merged.file_parse),
        "tools": tool_stats_to_json(&merged.tools),
        "cxx_backends": backend_calls_to_json(&merged.backends),
        "memory_by_index_path": memory_by_index_path,
    }))
}

/// Spawn a background task that flushes lifetime counters to disk every
/// `interval`. The task exits when the metrics shutdown notifier fires (and
/// performs one last flush before returning).
pub fn spawn_flush_task(metrics: Arc<Metrics>, interval: Duration) -> tokio::task::JoinHandle<()> {
    let notify = metrics.shutdown_notifier();
    tokio::spawn(async move {
        if !metrics.is_persistent() {
            debug!("Metrics flush task: persistence disabled, exiting");
            return;
        }
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Discard the immediate first tick — we just loaded; nothing to write.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if metrics.take_dirty() {
                        if let Err(e) = metrics.flush() {
                            warn!("Periodic metrics flush failed: {}", e);
                        }
                    }
                }
                _ = notify.notified() => {
                    debug!("Metrics flush task received shutdown signal");
                    if let Err(e) = metrics.flush() {
                        warn!("Final metrics flush on shutdown failed: {}", e);
                    }
                    break;
                }
            }
        }
    })
}

// ---------- Memory reporting -------------------------------------------------

/// Approximate the heap held by a hashbrown table (`HashMap`/`HashSet`) with
/// `capacity` slots of `(K, V)`: one control byte plus the inline key and value
/// per slot. Heap *behind* the keys/values (String buffers, Vec payloads) is
/// summed separately by the caller. For a `HashSet<T>` pass `V = ()`. Good to
/// ~10%; the small fixed table header is ignored.
pub(crate) fn hashmap_table_bytes<K, V>(capacity: usize) -> usize {
    capacity * (std::mem::size_of::<K>() + std::mem::size_of::<V>() + 1)
}

/// Per-subsystem heap estimate. Bytes are summed from container capacities and
/// owned String/Vec/f32 allocations — heap *held by the index*, not process RSS
/// (allocator overhead and transient parse buffers are excluded; `process_rss`
/// shows the gap).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryReport {
    /// DashMap<String, Vec<Symbol>>: keys + Vec caps + per-Symbol strings.
    pub symbols: usize,
    /// BM25 documents + inverted_index postings + doc_freq + synonyms.
    pub search_index: usize,
    /// TF-IDF Vec<f32> per doc + vocabulary/doc_freq maps.
    pub embeddings: usize,
    /// Cached file contents (Arc<String> lengths + path keys).
    pub file_cache: usize,
    /// Call graph nodes + edges (0 unless --call-graph).
    pub call_graphs: usize,
    /// Per-repo metadata (names, paths, language maps).
    pub repos: usize,
    /// Git repository handle keys (libgit2-internal buffers not tracked).
    pub git_repos: usize,
    /// Process resident set size (Linux /proc/self/status), when available.
    pub process_rss: Option<usize>,
}

impl MemoryReport {
    /// Sum of all subsystem fields (excludes process_rss).
    pub fn total_tracked(&self) -> usize {
        self.symbols
            + self.search_index
            + self.embeddings
            + self.file_cache
            + self.call_graphs
            + self.repos
            + self.git_repos
    }

    /// Named subsystem rows, largest first, for table rendering.
    fn rows_desc(&self) -> Vec<(&'static str, usize)> {
        let mut rows = vec![
            ("Embeddings (TF-IDF)", self.embeddings),
            ("Search index (BM25)", self.search_index),
            ("File cache", self.file_cache),
            ("Symbols", self.symbols),
            ("Call graphs", self.call_graphs),
            ("Repos", self.repos),
            ("Git repos", self.git_repos),
        ];
        rows.sort_by(|a, b| b.1.cmp(&a.1));
        rows
    }

    /// Markdown `## Memory usage` section: rows sorted desc with human-readable
    /// bytes and % of tracked, plus a process_rss line and the unaccounted gap.
    pub fn render_markdown(&self) -> String {
        let mut out = String::from("## Memory usage\n\n");
        out.push_str(&self.render_table());
        out
    }

    /// The heap table plus the process_rss / unaccounted-gap lines, without a
    /// section header, so callers can place it under their own heading.
    pub fn render_table(&self) -> String {
        let tracked = self.total_tracked();
        let mut out = String::new();
        out.push_str("| Subsystem | Heap | % of tracked |\n");
        out.push_str("|-----------|------|--------------|\n");
        for (name, bytes) in self.rows_desc() {
            let pct = if tracked > 0 {
                bytes as f64 / tracked as f64 * 100.0
            } else {
                0.0
            };
            out.push_str(&format!(
                "| {} | {} | {:.1}% |\n",
                name,
                format_bytes(bytes),
                pct
            ));
        }
        out.push_str(&format!(
            "| **Total tracked** | **{}** | **100.0%** |\n\n",
            format_bytes(tracked)
        ));
        match self.process_rss {
            Some(rss) => {
                out.push_str(&format!("**Process RSS**: {}\n", format_bytes(rss)));
                out.push_str(&format!(
                    "**Unaccounted** (allocator overhead, transient buffers, untracked): {}\n",
                    format_bytes(rss.saturating_sub(tracked))
                ));
            }
            None => out.push_str("**Process RSS**: unavailable\n"),
        }
        out
    }

    /// One-line summary for the startup log.
    pub fn summary_line(&self) -> String {
        let rss = match self.process_rss {
            Some(bytes) => format_bytes(bytes),
            None => "n/a".to_string(),
        };
        format!(
            "memory: tracked={} (embeddings={}, search={}, file_cache={}, symbols={}, call_graphs={}), rss={}",
            format_bytes(self.total_tracked()),
            format_bytes(self.embeddings),
            format_bytes(self.search_index),
            format_bytes(self.file_cache),
            format_bytes(self.symbols),
            format_bytes(self.call_graphs),
            rss
        )
    }

    /// Per-subsystem change since `earlier`, largest growth first.
    pub fn growth_line(&self, earlier: &MemoryReport) -> String {
        let mut rows = vec![
            ("embeddings", earlier.embeddings, self.embeddings),
            ("search", earlier.search_index, self.search_index),
            ("file_cache", earlier.file_cache, self.file_cache),
            ("symbols", earlier.symbols, self.symbols),
            ("call_graphs", earlier.call_graphs, self.call_graphs),
            ("repos", earlier.repos, self.repos),
            ("git_repos", earlier.git_repos, self.git_repos),
        ];
        rows.sort_by_key(|&(_, before, now)| std::cmp::Reverse(now as i128 - before as i128));
        let mut parts = Vec::new();
        for (name, before, now) in rows {
            let change = if now >= before {
                format!("+{}", format_bytes(now - before))
            } else {
                format!("-{}", format_bytes(before - now))
            };
            parts.push(format!("{}={} ({})", name, format_bytes(now), change));
        }
        format!("memory growth: {}", parts.join(", "))
    }
}

/// Render a byte count with a binary unit suffix (KiB/MiB/GiB).
pub fn format_bytes(bytes: usize) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use tempfile::TempDir;

    // Override the global stats dir for tests so we don't touch the real
    // ~/.cache/narsil-mcp. We do this by giving each test a temp directory
    // and feeding it as the `index_path` — the stats file lands under the
    // global cache regardless, but with a unique hash it won't collide.
    // For tests that need exact path control we use Metrics with
    // `persist_path` set directly via the helper below.

    fn make_persisted_metrics(path: PathBuf) -> Metrics {
        // Build a Metrics that writes to a known path (bypassing the global
        // cache dir resolution) so tests can isolate their files.
        let mut m = Metrics::new();
        m.persist_path = Some(path);
        m.lifetime.write().index_path = "test/path".to_string();
        m
    }

    #[test]
    fn test_metric_stats_basic() {
        let mut stats = MetricStats::new();
        assert_eq!(stats.count, 0);
        stats.record(100);
        assert_eq!(stats.count, 1);
        assert_eq!(stats.avg_ms(), 100.0);
        assert_eq!(stats.min_ms, 100);
        assert_eq!(stats.max_ms, 100);
    }

    #[test]
    fn test_memory_report_render_and_total() {
        let report = MemoryReport {
            symbols: 100,
            search_index: 400,
            embeddings: 1000,
            file_cache: 50,
            call_graphs: 0,
            repos: 10,
            git_repos: 5,
            process_rss: Some(4096),
        };
        assert_eq!(report.total_tracked(), 100 + 400 + 1000 + 50 + 10 + 5);

        let md = report.render_markdown();
        assert!(md.contains("## Memory usage"));
        assert!(md.contains("Embeddings (TF-IDF)"));
        assert!(md.contains("Total tracked"));
        assert!(md.contains("Process RSS"));
        assert!(md.contains("Unaccounted"));

        // Rows are sorted descending, so the largest subsystem (embeddings)
        // must render before a smaller one (symbols).
        let embeddings_pos = md.find("Embeddings (TF-IDF)").unwrap();
        let symbols_pos = md.find("Symbols").unwrap();
        assert!(
            embeddings_pos < symbols_pos,
            "rows must be sorted descending by size"
        );
    }

    #[test]
    fn test_memory_snapshot_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("memory.bin");
        {
            let m = make_persisted_metrics(path.clone());
            m.set_memory_report(MemoryReport {
                search_index: 4096,
                embeddings: 8192,
                process_rss: Some(99999),
                ..Default::default()
            });
            m.flush().unwrap();
        }
        let snap = PersistedMetrics::load(&path).unwrap();
        let mem = snap.memory.expect("memory snapshot persisted");
        assert_eq!(mem.report.search_index, 4096);
        assert_eq!(mem.report.embeddings, 8192);
        assert_eq!(mem.report.process_rss, Some(99999));
        assert!(mem.measured_at > 0);
    }

    #[test]
    fn test_flush_preserves_existing_memory_snapshot() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shared.bin");

        // First process records a memory snapshot.
        let m1 = make_persisted_metrics(path.clone());
        m1.set_memory_report(MemoryReport {
            embeddings: 1234,
            ..Default::default()
        });
        m1.flush().unwrap();

        // Second process never measures memory; its flush must not wipe the
        // snapshot the first one wrote.
        let m2 = make_persisted_metrics(path.clone());
        m2.record_tool("alpha", Duration::from_millis(5));
        m2.flush().unwrap();

        let snap = PersistedMetrics::load(&path).unwrap();
        let mem = snap.memory.expect("prior memory snapshot preserved");
        assert_eq!(mem.report.embeddings, 1234);
        assert_eq!(snap.tools.get("alpha").unwrap().count, 1);
    }

    #[test]
    fn test_v2_file_migrates_without_memory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v2.bin");

        // Write an authentic v2 byte stream (no trailing `memory` field).
        let mut tool = MetricStats::new();
        tool.record(42);
        let mut tools = HashMap::new();
        tools.insert("alpha".to_string(), tool.to_persisted().unwrap());
        let mut backends = HashMap::new();
        backends.insert("clangd".to_string(), 7u64);
        let v2 = PersistedMetricsV2 {
            version: 2,
            index_path: "/path/v2".to_string(),
            first_started_at: 111,
            saved_at: 222,
            total_uptime_seconds: 50,
            tools,
            file_parse: empty_persisted_counter(),
            backends,
        };
        std::fs::write(&path, postcard::to_stdvec(&v2).unwrap()).unwrap();

        let snap = PersistedMetrics::load(&path).unwrap();
        assert_eq!(snap.version, PersistedMetrics::CURRENT_VERSION);
        assert_eq!(snap.tools.get("alpha").unwrap().count, 1);
        assert_eq!(snap.backends.get("clangd"), Some(&7));
        assert!(
            snap.memory.is_none(),
            "migrated v2 file has no memory snapshot"
        );
    }

    #[test]
    fn test_v3_file_migrates_keeping_memory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v3.bin");

        // Write an authentic v3 byte stream (memory report with the old
        // `neural` slot).
        let mut tool = MetricStats::new();
        tool.record(42);
        let mut tools = HashMap::new();
        tools.insert("alpha".to_string(), tool.to_persisted().unwrap());
        let v3 = PersistedMetricsV3 {
            version: 3,
            index_path: "/path/v3".to_string(),
            first_started_at: 111,
            saved_at: 222,
            total_uptime_seconds: 50,
            tools,
            file_parse: empty_persisted_counter(),
            backends: HashMap::new(),
            memory: Some(PersistedMemoryReportV3 {
                measured_at: 333,
                report: MemoryReportV3 {
                    symbols: 1,
                    search_index: 2,
                    embeddings: 3,
                    file_cache: 4,
                    call_graphs: 5,
                    repos: 6,
                    git_repos: 7,
                    neural: 0,
                    process_rss: Some(4096),
                },
            }),
        };
        std::fs::write(&path, postcard::to_stdvec(&v3).unwrap()).unwrap();

        let snap = PersistedMetrics::load(&path).unwrap();
        assert_eq!(snap.version, PersistedMetrics::CURRENT_VERSION);
        assert_eq!(snap.tools.get("alpha").unwrap().count, 1);
        let mem = snap.memory.expect("v3 memory snapshot survives migration");
        assert_eq!(mem.measured_at, 333);
        assert_eq!(mem.report.git_repos, 7);
        assert_eq!(mem.report.process_rss, Some(4096));
    }

    #[test]
    fn test_metric_stats_percentiles() {
        let mut stats = MetricStats::new();
        for i in 1..=100 {
            stats.record(i);
        }
        assert_eq!(stats.count, 100);
        assert_eq!(stats.avg_ms(), 50.5);
        let p50 = stats.p50();
        let p95 = stats.p95();
        let p99 = stats.p99();
        assert!((49..=51).contains(&p50), "p50 was {}", p50);
        assert!((94..=96).contains(&p95), "p95 was {}", p95);
        assert!((98..=100).contains(&p99), "p99 was {}", p99);
    }

    #[test]
    fn test_metrics_tool_recording() {
        let metrics = Metrics::new();
        metrics.record_tool("list_repos", Duration::from_millis(50));
        metrics.record_tool("list_repos", Duration::from_millis(100));
        metrics.record_tool("find_symbols", Duration::from_millis(200));

        let stats = metrics.get_tool_stats("list_repos").unwrap();
        assert_eq!(stats.count, 2);
        assert_eq!(stats.avg_ms(), 75.0);
        assert_eq!(stats.min_ms, 50);
        assert_eq!(stats.max_ms, 100);
        assert_eq!(metrics.total_requests(), 3);
    }

    /// The size regression this series fixes was invisible; the report must
    /// name the offending tool and its worst response.
    #[test]
    fn test_metrics_response_size_recording() {
        let metrics = Metrics::new();
        metrics.record_tool_response("get_contributors", 2_231_347);
        metrics.record_tool_response("get_contributors", 1_000);
        metrics.record_tool_response("get_callers", 4_500);

        let sizes = metrics.get_tool_response_bytes();
        let contributors = sizes.get("get_contributors").unwrap();
        assert_eq!(contributors.count, 2);
        assert_eq!(contributors.max_ms, 2_231_347);

        let report = metrics.report();
        assert!(report.contains("Tool Response Sizes (This Session)"));
        assert!(report.contains("2231347"));
    }

    #[test]
    fn test_index_path_hash_stable() {
        let path = Path::new("/home/foo/.cache/narsil-mcp");
        let a = index_path_hash(path);
        let b = index_path_hash(path);
        assert_eq!(a, b);
        assert_eq!(a.len(), PATH_HASH_LEN);
        let other = index_path_hash(Path::new("/home/foo/.cache/narsil-other"));
        assert_ne!(a, other);
    }

    #[test]
    fn test_persistence_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("metrics.bin");

        {
            let metrics = make_persisted_metrics(path.clone());
            for _ in 0..10 {
                metrics.record_tool("alpha", Duration::from_millis(50));
            }
            metrics.record_file_parse(Duration::from_micros(120));
            metrics.flush().unwrap();
        }

        let metrics = make_persisted_metrics(path.clone());
        let snap = PersistedMetrics::load(&path).unwrap();
        // Adopt the loaded snapshot into the freshly-built Metrics so the
        // assertions exercise the post-startup baseline path.
        *metrics.lifetime.write() = LifetimeState::from_persisted(snap).unwrap();

        let tools = metrics.get_lifetime_tool_stats();
        let alpha = tools.get("alpha").expect("alpha tool should be loaded");
        assert_eq!(alpha.count, 10);
        assert_eq!(alpha.min_ms, 50);
        assert_eq!(alpha.max_ms, 50);

        let parse = metrics.get_lifetime_file_parse_stats();
        assert_eq!(parse.count, 1);
        assert_eq!(parse.min_ms, 120);
    }

    #[test]
    fn test_concurrent_writers_accumulate_without_loss() {
        // Two Metrics instances sharing the same file — both flush in turn,
        // each preserving the other's contributions.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shared.bin");

        let m1 = make_persisted_metrics(path.clone());
        let m2 = make_persisted_metrics(path.clone());

        m1.record_tool("alpha", Duration::from_millis(10));
        m1.record_tool("alpha", Duration::from_millis(20));
        m1.flush().unwrap();

        m2.record_tool("alpha", Duration::from_millis(30));
        m2.record_tool("beta", Duration::from_millis(5));
        m2.flush().unwrap();

        // After m2 flushed, the shared file should contain m1's + m2's data.
        m1.flush().unwrap(); // re-read the shared file
        let tools = m1.get_lifetime_tool_stats();
        assert_eq!(tools.get("alpha").unwrap().count, 3, "alpha = 2 + 1");
        assert_eq!(
            tools.get("alpha").unwrap().total_ms,
            10 + 20 + 30,
            "alpha total"
        );
        assert_eq!(tools.get("beta").unwrap().count, 1);
        assert_eq!(tools.get("beta").unwrap().min_ms, 5);
    }

    #[test]
    fn test_flush_reread_picks_up_other_writers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shared.bin");

        let m1 = make_persisted_metrics(path.clone());
        let m2 = make_persisted_metrics(path.clone());

        // m2 writes first.
        m2.record_tool("alpha", Duration::from_millis(100));
        m2.flush().unwrap();

        // m1 records, flushes — should preserve m2's contribution.
        m1.record_tool("alpha", Duration::from_millis(50));
        m1.flush().unwrap();

        let snap = PersistedMetrics::load(&path).unwrap();
        assert_eq!(snap.tools.get("alpha").unwrap().count, 2);
        assert_eq!(snap.tools.get("alpha").unwrap().total_ms, 150);
    }

    #[test]
    fn test_persistence_corrupt_file_starts_fresh() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("corrupt.bin");
        std::fs::write(&path, b"not a valid postcard payload").unwrap();
        // Corrupt content is treated as "no baseline" by from_persisted; the
        // flush should overwrite it cleanly.
        let m = make_persisted_metrics(path.clone());
        m.record_tool("alpha", Duration::from_millis(1));
        m.flush().unwrap();
        let snap = PersistedMetrics::load(&path).unwrap();
        assert_eq!(snap.tools.get("alpha").unwrap().count, 1);
    }

    #[test]
    fn test_dirty_flag_lifecycle() {
        let m = Metrics::new();
        assert!(!m.take_dirty(), "fresh instance is clean");
        m.record_tool("alpha", Duration::from_millis(1));
        assert!(m.take_dirty(), "record_tool marks dirty");
        assert!(!m.take_dirty(), "take_dirty clears the flag");
    }

    #[test]
    fn test_in_memory_metrics_not_persistent() {
        let m = Metrics::new();
        assert!(!m.is_persistent());
        m.flush().unwrap();
    }

    #[test]
    fn test_render_aggregate_markdown_empty() {
        let out = render_aggregate_markdown(&[]).unwrap();
        assert!(out.contains("narsil-mcp Lifetime Stats"));
        assert!(out.contains("No tool calls recorded"));
    }

    #[test]
    fn test_render_aggregate_markdown_merges_multiple() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a.bin");
        let b = dir.path().join("b.bin");

        let m1 = make_persisted_metrics(a.clone());
        m1.lifetime.write().index_path = "/path/a".to_string();
        m1.record_tool("alpha", Duration::from_millis(10));
        m1.flush().unwrap();

        let m2 = make_persisted_metrics(b.clone());
        m2.lifetime.write().index_path = "/path/b".to_string();
        m2.record_tool("alpha", Duration::from_millis(20));
        m2.record_tool("beta", Duration::from_millis(7));
        m2.flush().unwrap();

        let snaps = vec![
            PersistedMetrics::load(&a).unwrap(),
            PersistedMetrics::load(&b).unwrap(),
        ];
        let out = render_aggregate_markdown(&snaps).unwrap();
        assert!(out.contains("Total Requests**: 3"));
        assert!(out.contains("alpha"));
        assert!(out.contains("beta"));
    }

    #[test]
    fn test_render_list_markdown() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a.bin");
        let m1 = make_persisted_metrics(a.clone());
        m1.lifetime.write().index_path = "/proj/foo".to_string();
        m1.record_tool("alpha", Duration::from_millis(10));
        m1.flush().unwrap();
        let snaps = vec![(a.clone(), PersistedMetrics::load(&a).unwrap())];
        let out = render_list_markdown(&snaps);
        assert!(out.contains("/proj/foo"));
        assert!(out.contains("| 1 |")); // request count
    }

    #[test]
    fn test_uptime_format() {
        assert_eq!(format_duration_seconds(0), "0s");
        assert_eq!(format_duration_seconds(75), "1m 15s");
        assert_eq!(format_duration_seconds(3661), "1h 1m 1s");
        assert_eq!(format_duration_seconds(90_061), "1d 1h 1m 1s");
    }

    #[test]
    fn test_uptime_seconds_grows() {
        let metrics = Metrics::new();
        thread::sleep(Duration::from_millis(100));
        assert!(metrics.uptime_seconds() < 10);
    }

    #[test]
    fn test_record_backend_call_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("backends.bin");
        {
            let m = make_persisted_metrics(path.clone());
            m.record_backend_call("clangd");
            m.record_backend_call("clangd");
            m.record_backend_call("ccls");
            m.record_backend_call("gtags");
            // Session view reflects calls immediately.
            assert_eq!(m.get_session_backend_calls().get("clangd"), Some(&2));
            m.flush().unwrap();
        }
        let snap = PersistedMetrics::load(&path).unwrap();
        assert_eq!(snap.backends.get("clangd"), Some(&2));
        assert_eq!(snap.backends.get("ccls"), Some(&1));
        assert_eq!(snap.backends.get("gtags"), Some(&1));
    }

    #[test]
    fn test_backend_calls_accumulate_across_writers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shared.bin");
        let m1 = make_persisted_metrics(path.clone());
        let m2 = make_persisted_metrics(path.clone());

        m1.record_backend_call("ccls");
        m1.flush().unwrap();
        m2.record_backend_call("ccls");
        m2.record_backend_call("gtags");
        m2.flush().unwrap();

        let snap = PersistedMetrics::load(&path).unwrap();
        assert_eq!(snap.backends.get("ccls"), Some(&2), "ccls = 1 + 1");
        assert_eq!(snap.backends.get("gtags"), Some(&1));
    }

    #[test]
    fn test_v1_file_migrates_preserving_tools() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v1.bin");

        // Write an authentic v1 byte stream (no trailing `backends` map).
        let mut tool = MetricStats::new();
        tool.record(10);
        tool.record(20);
        let mut tools = HashMap::new();
        tools.insert("alpha".to_string(), tool.to_persisted().unwrap());
        let v1 = PersistedMetricsV1 {
            version: 1,
            index_path: "/path/v1".to_string(),
            first_started_at: 111,
            saved_at: 222,
            total_uptime_seconds: 99,
            tools,
            file_parse: empty_persisted_counter(),
        };
        std::fs::write(&path, postcard::to_stdvec(&v1).unwrap()).unwrap();

        let snap = PersistedMetrics::load(&path).unwrap();
        assert_eq!(snap.version, PersistedMetrics::CURRENT_VERSION);
        assert_eq!(
            snap.tools.get("alpha").unwrap().count,
            2,
            "tool history kept"
        );
        assert_eq!(snap.total_uptime_seconds, 99);
        assert_eq!(snap.first_started_at, 111);
        assert!(
            snap.backends.is_empty(),
            "migrated v1 file starts with no backend counts"
        );
    }

    #[test]
    fn test_render_aggregate_markdown_shows_backends() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a.bin");
        let m = make_persisted_metrics(a.clone());
        m.record_backend_call("ccls");
        m.record_backend_call("gtags");
        m.flush().unwrap();

        let snaps = vec![PersistedMetrics::load(&a).unwrap()];
        let out = render_aggregate_markdown(&snaps).unwrap();
        assert!(out.contains("Reference Backends"));
        // All three known backends are listed, including the never-called one.
        assert!(out.contains("| clangd | 0 |"));
        assert!(out.contains("| ccls | 1 |"));
        assert!(out.contains("| gtags | 1 |"));
    }
}
