//! Code Intelligence Engine - main indexing and query implementation
//!
//! This is the core engine that powers all MCP tool operations.

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, info, warn};

use crate::cache::query_cache::{QueryCache, QueryCacheKey, QueryCacheStats, SearchOptions};
use crate::cache::{AnalysisCache, AnalysisCacheKey, CacheStats};
use crate::callgraph::{CallEdge, CallGraph, CallType};
use crate::cfg;
use crate::dfg;
use crate::embeddings::EmbeddingEngine;
use crate::git::GitRepo;
use crate::gtags::{gtags_file_path, GtagsManager};
use crate::lsp::{LspConfig, LspManager};
use crate::metrics::{spawn_flush_task, MemoryReport, Metrics, DEFAULT_FLUSH_INTERVAL};
use crate::parser::LanguageParser;
use crate::persist::{IndexStore, PersistedIndex};
use crate::response_budget;
use crate::search::{build_file_doc, ConcurrentSearchIndex, SearchDocument};
use crate::streaming::StreamingConfig;
use crate::symbols::{SourceLine, SourceSet, Symbol, SymbolKind};

/// Metadata about an indexed repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoMetadata {
    pub name: String,
    pub path: PathBuf,
    pub file_count: usize,
    pub total_lines: usize,
    pub languages: HashMap<String, LanguageStats>,
    pub last_indexed: SystemTime,
    /// git HEAD and compile_commands.json fingerprint this index was built
    /// against; a mismatch on startup means the cached symbols are stale.
    pub head_hash: Option<String>,
    pub cdb_hash: Option<String>,
    /// git HEAD the compile_commands.json filter was applied at. A checkout
    /// does not regenerate the manifest, so sources changed since this commit
    /// are unlisted through no fault of their own and survive the filter.
    pub cdb_head_hash: Option<String>,
    /// Indexer extraction-logic version (`crate::persist::INDEX_LOGIC_VERSION`)
    /// this index was built under; a mismatch forces a rebuild even when the
    /// fingerprint is unchanged.
    pub logic_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LanguageStats {
    pub file_count: usize,
    pub line_count: usize,
    pub byte_count: usize,
}

/// A code excerpt with context
#[derive(Debug, Clone, Serialize)]
pub struct CodeExcerpt {
    pub file_path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub content: String,
    pub language: String,
    pub relevance_score: f32,
}

/// Per-backend enable intent recorded at startup. `Auto` defers the decision to
/// each repository — LSP on a `compile_commands.json`, gtags on a GTAGS db — so
/// a multi-repo session can enable a backend for the repos that warrant it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendIntent {
    /// Forced on (`--lsp` / `--gtags`): augment every C/C++ repo.
    On,
    /// Forced off (`--no-lsp` / `--no-gtags`).
    Off,
    /// Decide per repo from what it ships.
    #[default]
    Auto,
}

/// Upper bound on file count for `--gtags-generate`: building a GTAGS database
/// on a very large tree (e.g. the kernel) is slow and writes into the repo, so
/// auto-generation is skipped above this size.
const GTAGS_GENERATE_MAX_FILES: usize = 50_000;

/// Files parsed per definition-map batch. Bounds the build's memory, and gives
/// an abort a point between batches at which it can take effect.
const DEFINITION_BUILD_CHUNK_FILES: usize = 512;

/// Files between definition-map progress lines. The build has no size cap, so
/// it has to stay visible in the log — otherwise a stall looks like silence.
const DEFINITION_BUILD_PROGRESS_FILES: usize = 10_000;

/// Floor for get_commit_diff's `max_bytes`. The header and the footer that
/// names the files left out already take about 2 KB, so a smaller cap would
/// return no diff at all.
const MIN_COMMIT_DIFF_BYTES: usize = 4 * 1024;

/// Options for configuring the CodeIntelEngine
#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// Enable git integration (blame, history, etc.)
    pub git_enabled: bool,
    /// Enable call graph analysis
    pub call_graph_enabled: bool,
    /// Enable index persistence to disk
    pub persist_enabled: bool,
    /// Enable file watching for incremental updates
    pub watch_enabled: bool,
    /// Streaming configuration
    pub streaming_config: StreamingConfig,
    /// LSP configuration
    pub lsp_config: LspConfig,
    /// Enable analysis caching for expensive operations
    pub cache_enabled: bool,
    /// Cache TTL in seconds (default: 1800 = 30 minutes)
    pub cache_ttl_seconds: u64,
    /// Days an adopted repository may go unqueried before the idle sweep drops
    /// it (default: 7). Repos the server was started with are never swept.
    pub adopted_repo_ttl_days: u64,
    /// TF-IDF embedding vocabulary size / vector dimension (default: 1000)
    pub embedding_dim: usize,
    /// When true, restrict C/C++ source indexing to files in compile_commands.json
    pub use_compile_commands: bool,
    /// Path to compile_commands.json, relative to the repo root (default: "compile_commands.json")
    pub compile_commands_path: Option<PathBuf>,
    /// Glob patterns (relative to repo root) for files to always index
    pub include: Vec<String>,
    /// Paths/globs (relative to repo root) that additionally get the clangd/ccls
    /// pass. Empty means the whole repo. tree-sitter and gtags are unaffected;
    /// this only bounds the secondary LSP augmentation.
    pub lsp_scope: Vec<String>,
    /// Paths/globs that restrict the base (tree-sitter) index: when set, a repo
    /// with any matching file indexes only matching files (plus --include).
    /// A repo with no match is indexed in full. Empty means the whole repo.
    pub index_filter: Vec<String>,
    /// Per-repo overrides (from a `--profile` config). A repo listed here uses
    /// its own index_filter/lsp_scope/background_index; `lsp_scope`/`index_filter`
    /// above remain the defaults for any repo without an entry.
    pub repo_settings: Vec<crate::config::schema::RepoEntrySettings>,
    /// Settings for a repo without an entry in `repo_settings`, such as one
    /// adopted after startup: the profile's group defaults, `path` unused.
    pub unlisted_repo_settings: crate::config::schema::RepoEntrySettings,
    /// Enable GNU Global (gtags) as an additional C/C++ reference backend
    pub gtags_enabled: bool,
    /// Per-repo intent for LSP index-time augmentation (On/Off/Auto).
    pub lsp_intent: BackendIntent,
    /// Per-repo intent for gtags index-time augmentation (On/Off/Auto).
    pub gtags_intent: BackendIntent,
    /// Build a GTAGS database (via the `gtags` binary) for C/C++ repos that lack
    /// one. Writes into the repo, so opt-in; size-gated by GTAGS_GENERATE_MAX_FILES.
    pub gtags_generate: bool,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            git_enabled: false,
            call_graph_enabled: false,
            persist_enabled: false,
            watch_enabled: false,
            streaming_config: StreamingConfig::default(),
            lsp_config: LspConfig::default(),
            cache_enabled: true,
            cache_ttl_seconds: 1800,
            adopted_repo_ttl_days: DEFAULT_ADOPTED_REPO_TTL_DAYS,
            embedding_dim: 1000,
            use_compile_commands: false,
            compile_commands_path: None,
            include: Vec::new(),
            lsp_scope: Vec::new(),
            index_filter: Vec::new(),
            repo_settings: Vec::new(),
            unlisted_repo_settings: Default::default(),
            gtags_enabled: false,
            lsp_intent: BackendIntent::default(),
            gtags_intent: BackendIntent::default(),
            gtags_generate: false,
        }
    }
}

/// One compiled scope entry (`--lsp-scope` / `--index-filter`). A plain path is a
/// recursive directory prefix; an entry with glob metacharacters is matched with
/// `glob`. Matched against both the repo-relative and the absolute path.
#[derive(Clone)]
enum ScopeRule {
    Prefix(String),
    Glob(glob::Pattern),
}

/// Per-repo compiled scope rules and gtags overrides. Built once per repo in
/// `with_options` from the profile entry (falling back to the global
/// `--index-filter`/`--lsp-scope`/`--gtags*` defaults when the entry omits them).
struct CompiledRepoSettings {
    /// Effective `--index-filter` rules for this repo (empty = whole repo).
    index_filter: Vec<ScopeRule>,
    /// Effective `--lsp-scope` rules for this repo (empty = whole repo).
    lsp_scope: Vec<ScopeRule>,
    /// Per-repo gtags enable override (`gtags: { enabled }`). None = global intent.
    gtags_enabled: Option<bool>,
    /// Per-repo gtags auto-generate override (`gtags: { generate }`). None = global flag.
    gtags_generate: Option<bool>,
    /// Per-repo compile_commands coverage threshold (percent). None = global default.
    compile_commands_min_coverage_pct: Option<usize>,
}

/// clangd/ccls tuning from a repo entry's backend blocks; an unset field keeps
/// the `RepoLspTuning` default (backend on, no dial). None when the entry has
/// neither block.
fn lsp_tuning_from(
    entry: &crate::config::schema::RepoEntrySettings,
) -> Option<crate::lsp::RepoLspTuning> {
    if entry.clangd.is_none() && entry.ccls.is_none() {
        return None;
    }
    let clangd = entry.clangd.as_ref();
    let ccls = entry.ccls.as_ref();
    Some(crate::lsp::RepoLspTuning {
        clangd_enabled: clangd.and_then(|c| c.enabled).unwrap_or(true),
        clangd_jobs: clangd.and_then(|c| c.jobs),
        clangd_background_index: clangd.and_then(|c| c.background_index).unwrap_or(true),
        ccls_enabled: ccls.and_then(|c| c.enabled).unwrap_or(true),
        ccls_threads: ccls.and_then(|c| c.threads),
        ccls_retain_in_memory: ccls.and_then(|c| c.retain_in_memory),
        ccls_background_index: ccls.and_then(|c| c.background_index).unwrap_or(true),
    })
}

/// Compile raw scope entries (paths or globs) into matchers. Invalid globs are
/// downgraded to a literal prefix with a warning.
fn compile_scope(entries: &[String]) -> Vec<ScopeRule> {
    entries
        .iter()
        .filter_map(|entry| {
            let trimmed = entry.trim().trim_end_matches('/');
            if trimmed.is_empty() {
                return None;
            }
            if trimmed.contains(['*', '?', '[']) {
                match glob::Pattern::new(trimmed) {
                    Ok(pattern) => Some(ScopeRule::Glob(pattern)),
                    Err(e) => {
                        warn!("scope: ignoring invalid glob {:?}: {}", trimmed, e);
                        Some(ScopeRule::Prefix(trimmed.to_string()))
                    }
                }
            } else {
                Some(ScopeRule::Prefix(trimmed.to_string()))
            }
        })
        .collect()
}

/// Whether a file (`rel` repo-relative, `abs` absolute) is under any of `rules`.
/// Empty `rules` never matches — callers treat empty as "no scoping".
fn scope_matches(rules: &[ScopeRule], rel: &str, abs: &str) -> bool {
    let under =
        |path: &str, prefix: &str| path == prefix || path.starts_with(&format!("{prefix}/"));
    rules.iter().any(|rule| match rule {
        ScopeRule::Prefix(prefix) => under(rel, prefix) || under(abs, prefix),
        ScopeRule::Glob(pattern) => pattern.matches(rel) || pattern.matches(abs),
    })
}

/// True for git merge-conflict leftovers (`foo_BACKUP_1234.c`, `foo.orig`,
/// `foo.rej`, ...) that a merge tool or `git apply --reject` writes next to
/// the real source file. They are untracked and never gitignored, so the
/// index walk below would otherwise index them alongside the tracked file
/// they were generated from.
fn is_merge_conflict_artifact(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name.ends_with(".orig") || name.ends_with(".rej") {
        return true;
    }
    ["_BACKUP_", "_BASE_", "_LOCAL_", "_REMOTE_"]
        .iter()
        .any(|marker| name.contains(marker))
}

/// How long a query waits for an in-flight index update before it is refused.
/// Long enough to absorb the incremental batches a save or a small commit
/// triggers — those finish in well under a second, and a caller told to retry
/// waits longer than that anyway — while still far short of a checkout.
const INDEX_LEASE_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// How a repository came to be registered. Only an adopted repo is ever swept:
/// the repos a server was started with are its declared set, however long they
/// sit idle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoOrigin {
    /// Named by `--repos`, `--discover`, or a config profile.
    Configured,
    /// Registered at run time by `reindex` on a path the server never saw.
    Adopted,
}

/// A repository the engine answers for, with what an idle sweep needs to
/// decide whether to drop it.
struct RegisteredRepo {
    path: PathBuf,
    origin: RepoOrigin,
    /// Unix seconds when a caller last named this repo. Atomic so the stamp
    /// costs a read lock and not a write lock on every query.
    last_used: AtomicU64,
}

impl RegisteredRepo {
    /// Registered now, so a freshly adopted repo gets a whole TTL before the
    /// first sweep can consider it.
    fn new(path: PathBuf, origin: RepoOrigin) -> Self {
        Self {
            path,
            origin,
            last_used: AtomicU64::new(unix_secs()),
        }
    }
}

/// Seconds since the unix epoch, 0 if the clock reads before it.
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Days an adopted repository may go unqueried before the idle sweep drops it.
/// Long enough to survive a holiday, short enough that a project touched once
/// does not sit in a server's memory for a month.
pub const DEFAULT_ADOPTED_REPO_TTL_DAYS: u64 = 7;

/// How often the idle sweep looks for adopted repos to drop. Well below any
/// sensible TTL, so a repo is forgotten within the hour of crossing it.
const IDLE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Run the idle sweep for as long as the returned `Sender` is held.
///
/// **The caller must hold the `Sender`**; dropping it makes the sweep exit on
/// its next poll, the same trap `spawn_watch_mode` documents.
#[must_use = "the returned Sender must be held until the sweep should stop; \
              dropping it immediately exits the sweep"]
pub fn spawn_idle_repo_sweep(engine: Arc<CodeIntelEngine>) -> tokio::sync::broadcast::Sender<()> {
    let ttl = std::time::Duration::from_secs(engine.options.adopted_repo_ttl_days * 24 * 60 * 60);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel(1);
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(IDLE_SWEEP_INTERVAL);
        // interval fires its first tick immediately; the engine has nothing to
        // sweep at startup.
        ticks.tick().await;
        loop {
            tokio::select! {
                _ = ticks.tick() => engine.sweep_idle_repos(ttl).await,
                _ = shutdown_rx.recv() => {
                    info!("Idle repo sweep shutting down");
                    break;
                }
            }
        }
    });
    shutdown_tx
}

/// Per-repo index lease. A query holds the read side for the duration of its
/// tool call, an index update the write side. tokio's RwLock is
/// write-preferring, so a waiting update also keeps new queries out — the
/// update is one busy window, not a race renewed per file batch.
type IndexLease = Arc<tokio::sync::RwLock<()>>;

/// Refusal handed to a query whose repo is mid-update. Retryable: the same
/// request succeeds once the update finishes.
#[derive(Debug)]
pub struct IndexBusy {
    /// Canonical repo path whose index is being updated.
    pub repo: String,
    /// Repos indexed so far, out of the total configured — the same counters
    /// get_index_status reports, so a caller can tell a slow first-time index
    /// from one that looks stuck without a separate call.
    pub indexed_repos: usize,
    pub total_repos: usize,
    /// The repo has no finished index pass yet (queued at startup, or adopted
    /// and mid-pass), rather than an update of an existing index.
    pub first_pass: bool,
}

impl std::fmt::Display for IndexBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.first_pass {
            return write!(
                f,
                "EAGAIN: {} is being indexed — retry later ({}/{} repos indexed)",
                self.repo, self.indexed_repos, self.total_repos,
            );
        }
        write!(
            f,
            "EAGAIN: index update in progress for {} — waited {}s, retry the request \
             ({}/{} repos indexed)",
            self.repo,
            INDEX_LEASE_GRACE.as_secs_f32(),
            self.indexed_repos,
            self.total_repos,
        )
    }
}

impl std::error::Error for IndexBusy {}

/// JSON-RPC error code for [`IndexBusy`], in the implementation-defined range.
/// Distinct from the generic -32000 so a client can tell retry from failure.
pub const JSONRPC_INDEX_BUSY: i32 = -32001;

/// Write leases held for one index update, plus the gate admitting a single
/// updater at a time. Dropping it reopens the affected repos to queries.
///
/// Owned (no borrowed guards) so a caller can grow it with `add()` across
/// `.await` points and hand the whole thing to another task — the watcher
/// takes this at the first file-change event for a debounce batch, not only
/// once the batch is dequeued, so a query can never land in the gap between
/// a file landing on disk and the batch that re-indexes it.
pub struct IndexUpdateLeases {
    /// Held for the whole update: writers never interleave, so the order in
    /// which they take per-repo leases cannot deadlock them against each other.
    _gate: tokio::sync::OwnedMutexGuard<()>,
    /// Held write leases, keyed by canonical repo path.
    leases: HashMap<String, tokio::sync::OwnedRwLockWriteGuard<()>>,
}

impl IndexUpdateLeases {
    /// Whether this update window already covers `repo_key`.
    pub fn covers(&self, repo_key: &str) -> bool {
        self.leases.contains_key(repo_key)
    }

    /// Add `repo_key` to this window if not already covered. The caller
    /// already holds `_gate`, so acquisition order across repos added one at
    /// a time this way still cannot deadlock against another updater.
    pub async fn add(&mut self, engine: &CodeIntelEngine, repo_key: &str) {
        if !self.leases.contains_key(repo_key) {
            self.leases
                .insert(repo_key.to_string(), engine.index_lease(repo_key).write_owned().await);
        }
    }
}

/// The main code intelligence engine
pub struct CodeIntelEngine {
    /// Base path for index storage (stored for potential future use)
    _index_path: PathBuf,
    /// Registered repository paths. Behind a lock because `reindex` takes
    /// `&self` yet may register a repo the server was never started with.
    repo_paths: parking_lot::RwLock<Vec<RegisteredRepo>>,
    async_file_watcher: parking_lot::Mutex<
        std::sync::Weak<parking_lot::Mutex<crate::persist::AsyncFileWatcher>>,
    >,
    /// Cached repo metadata
    repos: DashMap<String, RepoMetadata>,
    /// Symbol index: repo -> symbols
    symbols: DashMap<String, Vec<Symbol>>,
    /// File content cache (path -> content)
    file_cache: DashMap<PathBuf, Arc<String>>,
    /// Language parser
    parser: Arc<LanguageParser>,
    /// Git repository handles (when git is enabled)
    git_repos: DashMap<String, GitRepo>,
    /// Call graphs per repository (when call_graph is enabled)
    call_graphs: DashMap<String, CallGraph>,
    /// Semantic search index
    search_index: Arc<ConcurrentSearchIndex>,
    /// Embedding engine for semantic similarity (TF-IDF)
    embedding_engine: Arc<EmbeddingEngine>,
    /// Engine options (feature flags)
    options: EngineOptions,
    /// Index store for persistence (when persist is enabled)
    /// Performance metrics
    pub metrics: Arc<Metrics>,
    /// Shared, because the background definition-map build writes through the
    /// same handle: redb locks a database file exclusively, so a second
    /// `IndexStore` over the same repo could not open it.
    index_store: Option<Arc<IndexStore>>,
    /// LSP manager for enhanced code analysis (when lsp is enabled)
    lsp_manager: Option<Arc<LspManager>>,
    /// GNU Global manager for C/C++ reference queries (when gtags is enabled)
    gtags_manager: Option<Arc<GtagsManager>>,
    /// Analysis cache for expensive operations (call graphs, etc.)
    analysis_cache: Arc<AnalysisCache<AnalysisCacheKey, String>>,
    /// Query result cache for symbol lookups and search operations
    query_cache: Arc<QueryCache>,
    /// Tracks whether background initialization has completed
    initialization_complete: AtomicBool,
    /// Number of repositories that have been fully indexed
    indexed_repos_count: AtomicUsize,
    /// Total number of repositories to index
    total_repos_count: AtomicUsize,
    /// Background task that periodically flushes lifetime metrics to disk.
    /// Aborted on shutdown after a final synchronous flush.
    metrics_flush_task: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// In-flight definition-map builds, keyed by repo. Held so a reindex or a
    /// shutdown can abort a build that is still walking the tree. The handle
    /// yields whether the map changed, which decides if a catch-up pass is
    /// worth running.
    definition_builds: DashMap<String, tokio::task::JoinHandle<bool>>,
    /// Per-repo cached `.gitignore` matcher, so the watch path rejects the same
    /// paths the index-time WalkBuilder would (built lazily on first use).
    gitignore_matchers: DashMap<PathBuf, Arc<ignore::gitignore::Gitignore>>,
    /// C/C++ sources the compile_commands.json coverage filter dropped for the
    /// most recent index of each repo (absolute paths), so a symbol query that
    /// comes up empty for one of them can say why instead of "not found".
    compile_commands_filtered_files: DashMap<String, Vec<PathBuf>>,
    /// Last time a `global -u` ran per repo, to debounce gtags refreshes under
    /// a burst of file events.
    gtags_last_refresh: DashMap<PathBuf, std::time::Instant>,
    /// Global `--lsp-scope` rules, used as the default for any repo without a
    /// per-repo override; empty means the clangd/ccls pass runs repo-wide.
    default_lsp_scope: Vec<ScopeRule>,
    /// Global `--index-filter` rules, used as the default for any repo without a
    /// per-repo override; empty means the whole repo is indexed.
    default_index_filter: Vec<ScopeRule>,
    /// Per-repo compiled scope rules and flags, keyed by canonical repo path.
    /// A repo absent here uses `unlisted_repo_settings`.
    repo_settings: std::collections::HashMap<String, CompiledRepoSettings>,
    /// Compiled `EngineOptions::unlisted_repo_settings`.
    unlisted_repo_settings: CompiledRepoSettings,
    /// Per-repo memo: true when the repo had >=1 file under `--index-filter`, so
    /// the watch path can drop changes to out-of-scope files. Absent = not
    /// scoped (full index), which keeps unrelated repos untouched.
    index_filtered_repos: DashMap<String, bool>,
    /// Per-repo index leases keyed by canonical repo path, created on first use.
    index_leases: DashMap<String, IndexLease>,
    /// Admits one index update at a time. Updates take several per-repo leases
    /// at once (reindex_all, a watch batch spanning repos); serializing them
    /// makes their acquisition order irrelevant. `Arc`-wrapped so the owned
    /// guard can be held by `IndexUpdateLeases` across `.await` points and
    /// moved into the watcher's debounce task.
    update_gate: Arc<tokio::sync::Mutex<()>>,
}

impl CodeIntelEngine {
    /// Create a new engine with default options (no git, no call graphs, no persistence)
    ///
    /// # Arguments
    /// * `index_path` - Directory path for storing index data
    /// * `repo_paths` - List of repository paths to index
    pub async fn new(index_path: PathBuf, repo_paths: Vec<PathBuf>) -> Result<Self> {
        Self::with_options(index_path, repo_paths, EngineOptions::default()).await
    }

    /// Create a new engine with the specified options
    pub async fn with_options(
        index_path: PathBuf,
        repo_paths: Vec<PathBuf>,
        mut options: EngineOptions,
    ) -> Result<Self> {
        let expanded_index = expand_path(&index_path)?;
        std::fs::create_dir_all(&expanded_index)?;

        let expanded_repos: Vec<PathBuf> = repo_paths
            .iter()
            .map(|p| expand_path(p).unwrap_or_else(|_| p.clone()))
            .collect();

        // Initialize index store for persistence if enabled
        let index_store = if options.persist_enabled {
            match IndexStore::new(expanded_index.clone()) {
                Ok(store) => {
                    info!("Index persistence enabled, storing in {:?}", expanded_index);
                    Some(Arc::new(store))
                }
                Err(e) => {
                    warn!("Failed to initialize index store: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Initialize LSP manager if enabled
        let lsp_manager = if options.lsp_config.enabled {
            info!("LSP integration enabled");
            // Per-repo clangd/ccls tuning, keyed by canonical repo root so it
            // matches the repo encoded in server keys. A field left unset on the
            // config block keeps the RepoLspTuning default (backend on, no dial).
            let mut tuning_map = std::collections::HashMap::new();
            for entry in &options.repo_settings {
                let Some(tuning) = lsp_tuning_from(entry) else {
                    continue;
                };
                let key = match expand_path(&entry.path).and_then(|p| canonical_repo_key(&p)) {
                    Ok(key) => PathBuf::from(key),
                    Err(e) => {
                        warn!("per-repo LSP tuning ignored for {:?}: {}", entry.path, e);
                        continue;
                    }
                };
                tuning_map.insert(key, tuning);
            }
            if !tuning_map.is_empty() {
                info!(
                    "per-repo clangd/ccls tuning for {} repo(s)",
                    tuning_map.len()
                );
            }
            options.lsp_config.lsp_tuning = tuning_map;
            options.lsp_config.default_tuning = lsp_tuning_from(&options.unlisted_repo_settings);
            Some(Arc::new(LspManager::new(
                options.lsp_config.clone(),
                expanded_repos.clone(),
            )))
        } else {
            None
        };

        // Initialize GNU Global manager if enabled
        let gtags_manager = if options.gtags_enabled {
            info!("GNU Global (gtags) integration enabled");
            Some(Arc::new(GtagsManager::new(expanded_repos.clone())))
        } else {
            None
        };

        // Initialize analysis cache for expensive operations
        let analysis_cache = if options.cache_enabled {
            let ttl = std::time::Duration::from_secs(options.cache_ttl_seconds);
            info!(
                "Analysis cache enabled (TTL: {}s, capacity: 1000)",
                options.cache_ttl_seconds
            );
            Arc::new(AnalysisCache::new(1000, ttl))
        } else {
            // Create a minimal cache even when disabled (0 TTL means immediate expiry)
            Arc::new(AnalysisCache::new(1, std::time::Duration::from_secs(0)))
        };

        // Initialize query cache for symbol lookups and search operations
        let query_cache = if options.cache_enabled {
            let ttl = std::time::Duration::from_secs(options.cache_ttl_seconds);
            info!(
                "Query cache enabled (TTL: {}s, capacity: 2000)",
                options.cache_ttl_seconds
            );
            Arc::new(QueryCache::new(2000, ttl))
        } else {
            // Create a minimal cache even when disabled (0 TTL means immediate expiry)
            Arc::new(QueryCache::new(1, std::time::Duration::from_secs(0)))
        };

        let total_repos = expanded_repos.len();

        // Lifetime metrics are persisted globally under the user's cache
        // directory, keyed by the canonical index_path so multiple invocations
        // for the same index share a single stats file (ccache-style). This is
        // independent of `--persist`: the file is tiny and the user wants
        // accumulation regardless.
        let metrics = Arc::new(Metrics::with_persistence(expanded_index.clone()));
        let flush_task = spawn_flush_task(Arc::clone(&metrics), DEFAULT_FLUSH_INTERVAL);

        // Compile the global path-scope flags once; these are the defaults for
        // any repo without a per-repo override.
        let default_lsp_scope = compile_scope(&options.lsp_scope);
        let default_index_filter = compile_scope(&options.index_filter);

        // Compile per-repo overrides, keyed by canonical repo path so lookups
        // match canonical_repo_key(repo_path). A repo entry that omits a scope
        // list inherits the corresponding global default.
        let compile_entry =
            |entry: &crate::config::schema::RepoEntrySettings| CompiledRepoSettings {
                index_filter: if entry.index_filter.is_empty() {
                    default_index_filter.clone()
                } else {
                    compile_scope(&entry.index_filter)
                },
                lsp_scope: if entry.lsp_scope.is_empty() {
                    default_lsp_scope.clone()
                } else {
                    compile_scope(&entry.lsp_scope)
                },
                gtags_enabled: entry.gtags.as_ref().and_then(|g| g.enabled),
                gtags_generate: entry.gtags.as_ref().and_then(|g| g.generate),
                compile_commands_min_coverage_pct: entry.compile_commands_min_coverage_pct,
            };
        let mut repo_settings: std::collections::HashMap<String, CompiledRepoSettings> =
            std::collections::HashMap::new();
        for entry in &options.repo_settings {
            let key = match expand_path(&entry.path).and_then(|p| canonical_repo_key(&p)) {
                Ok(key) => key,
                Err(e) => {
                    warn!("per-repo config ignored for {:?}: {}", entry.path, e);
                    continue;
                }
            };
            repo_settings.insert(key, compile_entry(entry));
        }
        let unlisted_repo_settings = compile_entry(&options.unlisted_repo_settings);

        let engine = Self {
            _index_path: expanded_index,
            repo_paths: parking_lot::RwLock::new(
                expanded_repos
                    .iter()
                    .map(|path| RegisteredRepo::new(path.clone(), RepoOrigin::Configured))
                    .collect(),
            ),
            async_file_watcher: parking_lot::Mutex::new(std::sync::Weak::new()),
            repos: DashMap::new(),
            symbols: DashMap::new(),
            file_cache: DashMap::new(),
            parser: Arc::new(LanguageParser::new()?),
            git_repos: DashMap::new(),
            call_graphs: DashMap::new(),
            search_index: Arc::new(ConcurrentSearchIndex::new()),
            embedding_engine: Arc::new(EmbeddingEngine::new(options.embedding_dim)),
            options: options.clone(),
            index_store,
            metrics,
            lsp_manager,
            gtags_manager,
            analysis_cache,
            query_cache,
            initialization_complete: AtomicBool::new(false),
            indexed_repos_count: AtomicUsize::new(0),
            total_repos_count: AtomicUsize::new(total_repos),
            metrics_flush_task: parking_lot::Mutex::new(Some(flush_task)),
            definition_builds: DashMap::new(),
            gitignore_matchers: DashMap::new(),
            compile_commands_filtered_files: DashMap::new(),
            gtags_last_refresh: DashMap::new(),
            default_lsp_scope,
            default_index_filter,
            repo_settings,
            unlisted_repo_settings,
            index_filtered_repos: DashMap::new(),
            index_leases: DashMap::new(),
            update_gate: Arc::new(tokio::sync::Mutex::new(())),
        };

        // Try to load persisted indexes first if persistence is enabled
        let mut loaded_repos: Vec<String> = Vec::new();
        if options.persist_enabled {
            if let Some(ref store) = engine.index_store {
                for repo_path in &expanded_repos {
                    if let Ok(persisted) = store.load_repo(repo_path) {
                        if !persisted.files.is_empty() {
                            let repo_name = match canonical_repo_key(repo_path) {
                                Ok(k) => k,
                                Err(e) => {
                                    warn!("Skipping cached repo {:?}: {}", repo_path, e);
                                    continue;
                                }
                            };

                            // Load symbols from persisted index
                            let symbols: Vec<Symbol> = persisted
                                .files
                                .values()
                                .flat_map(|f| f.symbols.clone())
                                .collect();

                            info!(
                                "Loaded {} symbols from persisted index for {}",
                                symbols.len(),
                                repo_name
                            );

                            // Calculate metadata from persisted data
                            let mut languages: HashMap<String, LanguageStats> = HashMap::new();
                            let mut total_lines = 0;

                            for file_meta in persisted.files.values() {
                                let ext = file_meta
                                    .path
                                    .extension()
                                    .and_then(|e| e.to_str())
                                    .unwrap_or("unknown");
                                let lang = ext_to_language(ext);
                                let stats = languages.entry(lang).or_default();
                                stats.file_count += 1;
                                stats.byte_count += file_meta.size as usize;
                                // Estimate lines from symbols
                                let max_line = file_meta
                                    .symbols
                                    .iter()
                                    .map(|s| s.end_line)
                                    .max()
                                    .unwrap_or(0);
                                stats.line_count += max_line;
                                total_lines += max_line;
                            }

                            let metadata = RepoMetadata {
                                name: repo_name.clone(),
                                path: repo_path.clone(),
                                file_count: persisted.files.len(),
                                total_lines,
                                languages,
                                last_indexed: SystemTime::UNIX_EPOCH
                                    + std::time::Duration::from_secs(persisted.updated_at),
                                head_hash: persisted.head_hash.clone(),
                                cdb_hash: persisted.cdb_hash.clone(),
                                cdb_head_hash: persisted.cdb_head_hash.clone(),
                                logic_version: persisted.logic_version,
                            };

                            engine.repos.insert(repo_name.clone(), metadata);
                            engine.symbols.insert(repo_name.clone(), symbols);
                            loaded_repos.push(repo_name);
                        }
                    }
                }
            }
        }

        // Initialize call graphs BEFORE indexing (must exist for index_repo to populate them)
        if options.call_graph_enabled {
            for repo_path in &expanded_repos {
                if repo_path.exists() {
                    let repo_name = match canonical_repo_key(repo_path) {
                        Ok(k) => k,
                        Err(e) => {
                            warn!("Skipping call graph init for {:?}: {}", repo_path, e);
                            continue;
                        }
                    };
                    let call_graph = CallGraph::new();
                    info!("Call graph initialized for repository: {}", repo_name);
                    engine.call_graphs.insert(repo_name, call_graph);
                }
            }
        }

        // Initialize git repos BEFORE returning, same as call graphs above:
        // GitRepo::new is a single fast `git rev-parse` subprocess call, unlike
        // the deferred embedding/symbol indexing, so there's no reason to make
        // get_branch_info/get_modified_files callers race complete_initialization().
        if options.git_enabled {
            for repo_path in &expanded_repos {
                if repo_path.exists() {
                    let repo_name = match canonical_repo_key(repo_path) {
                        Ok(k) => k,
                        Err(e) => {
                            warn!("Skipping git init for {:?}: {}", repo_path, e);
                            continue;
                        }
                    };

                    match GitRepo::new(repo_path) {
                        Ok(git_repo) => {
                            info!("Git enabled for repository: {}", repo_name);
                            engine.git_repos.insert(repo_name, git_repo);
                        }
                        Err(e) => {
                            warn!("Failed to initialize git for {}: {}", repo_name, e);
                        }
                    }
                }
            }
        }

        // Initialize watch mode if enabled
        if options.watch_enabled {
            info!("Watch mode enabled - monitoring for file changes");
            // Note: Watch mode runs asynchronously. Use process_watch_events() to handle changes.
        }

        // NOTE: We now return the engine IMMEDIATELY without blocking on indexing.
        // This allows the MCP server to respond to initialize requests quickly.
        // Call complete_initialization() to finish indexing in the background.
        info!(
            "Engine created (initialization deferred for {} repos)",
            total_repos
        );

        Ok(engine)
    }

    /// Gracefully stop the metrics flush task and write a final snapshot.
    ///
    /// Should be called before the process exits so the last few minutes of
    /// metrics activity aren't lost. The background flush task is signalled,
    /// performs a final write, then exits; this function awaits it.
    pub async fn shutdown(&self) {
        // Wake the flush task so it writes immediately rather than waiting for
        // the next tick.
        self.metrics.notify_shutdown();
        let handle = self.metrics_flush_task.lock().take();
        if let Some(handle) = handle {
            if let Err(e) = handle.await {
                if !e.is_cancelled() {
                    warn!("Metrics flush task ended abnormally: {}", e);
                }
            }
        }
        // Belt-and-braces: also do an explicit flush in case the task already
        // exited or never started.
        if let Err(e) = self.metrics.flush() {
            warn!("Final metrics flush failed: {}", e);
        }
        // A definition-map build has nothing worth saving half-done — its map
        // only exists once it commits — so drop it rather than wait out a
        // whole-repo parse.
        self.definition_builds.retain(|_, handle| {
            handle.abort();
            false
        });
    }

    /// Complete the deferred initialization by indexing all repositories
    /// and initializing git. This should be called in the background after
    /// the engine is created to allow the MCP server to respond quickly.
    pub async fn complete_initialization(&self) -> Result<()> {
        if self.initialization_complete.load(Ordering::Acquire) {
            info!("Initialization already complete, skipping");
            return Ok(());
        }

        info!("Starting background initialization");

        // For repos loaded from persistence: index_repo still runs to rebuild the
        // BM25 search index and call graph (which are not persisted), but it
        // skips the expensive embedding indexing since symbols are already cached.
        // For repos not in the cache: do a full fresh index and save afterwards.
        let mut any_freshly_indexed = false;
        // A cache-loaded repo whose fingerprint went stale is rebuilt in memory
        // by index_repo but, unlike a fresh repo, would otherwise never be
        // written back — so the rebuilt symbols and the new fingerprint must be
        // persisted too, else the same rebuild repeats on every startup.
        let mut any_rebuilt = false;

        let repo_paths = self.registered_repo_paths();
        let total_repos = repo_paths.len();
        let mut done_repos = 0;
        for repo_path in &repo_paths {
            let repo_name = match canonical_repo_key(repo_path) {
                Ok(k) => k,
                Err(e) => {
                    warn!("Skipping indexing of {:?}: {}", repo_path, e);
                    continue;
                }
            };

            let from_cache = self.repos.contains_key(&repo_name);
            // Checked before index_repo, which updates the in-memory fingerprint.
            let fingerprint_stale = from_cache && !self.fingerprint_matches(&repo_name, repo_path);
            if from_cache {
                info!(
                    "Repository {} loaded from cache; rebuilding search index and call graph",
                    repo_name
                );
            } else {
                info!("Indexing repository: {:?}", repo_path);
            }

            if repo_path.exists() {
                // A query landing mid-build would be answered from a repo whose
                // symbols are still being filled in.
                let _leases = self
                    .index_update_leases(std::slice::from_ref(&repo_name))
                    .await;
                if let Err(e) = self.index_repo(repo_path).await {
                    warn!("Failed to index {:?}: {}", repo_path, e);
                } else {
                    self.indexed_repos_count.fetch_add(1, Ordering::Release);
                    if !from_cache {
                        any_freshly_indexed = true;
                    } else if fingerprint_stale {
                        any_rebuilt = true;
                    }
                }
            } else {
                warn!("Repository path does not exist: {:?}", repo_path);
            }
            done_repos += 1;
            info!(
                "Indexed {}/{} repositories: {}",
                done_repos, total_repos, repo_name
            );
        }

        // Persist the freshly-built index so subsequent startups skip embedding
        // re-indexing (the expensive serial part).
        if self.options.persist_enabled && (any_freshly_indexed || any_rebuilt) {
            if let Err(e) = self.save_index().await {
                warn!("Failed to save index to disk: {}", e);
            }
        }

        // Warm clangd now so the cross-validation path is ready before the
        // first C/C++ query, rather than racing a cold preamble/index build.
        if let Some(lsp) = &self.lsp_manager {
            // Servers are per repo, so warm each repo's C/C++ backends rooted at
            // that repo rather than starting a single shared server.
            for repo in self.repos.iter() {
                // gtags-only repos never start a language server.
                if self.lsp_augment_disabled(repo.key()) {
                    continue;
                }
                let mut has_c = false;
                let mut has_cpp = false;
                for lang in repo.value().languages.keys() {
                    match lang.as_str() {
                        "c" | "C" => has_c = true,
                        "cpp" | "C++" => has_cpp = true,
                        _ => {}
                    }
                }
                if !has_c && !has_cpp {
                    continue;
                }
                let repo_path = PathBuf::from(repo.key());
                if has_c {
                    lsp.warm_up(&repo_path, "c").await;
                }
                if has_cpp {
                    lsp.warm_up(&repo_path, "cpp").await;
                }
            }
        }

        self.initialization_complete.store(true, Ordering::Release);
        info!("Background initialization complete");
        // The initial build's transient buffers (parse trees, cleared content
        // strings) are the bulk of glibc's retained high-water mark — trim
        // before measuring so the startup RSS reflects the live working set.
        Self::return_freed_heap_to_os();
        let memory = self.memory_report();
        info!("{}", memory.summary_line());
        // Persist the snapshot so the offline `narsil-mcp stats` command can
        // report it; written by the next periodic/shutdown/Drop flush.
        self.metrics.set_memory_report(memory);

        Ok(())
    }

    /// Check if background initialization has completed
    pub fn is_fully_initialized(&self) -> bool {
        self.initialization_complete.load(Ordering::Acquire)
    }

    /// Get detailed initialization status
    /// (repos indexed so far, total repos configured) -- the same counters
    /// get_initialization_status reports, exposed directly for IndexBusy's
    /// EAGAIN message.
    pub fn indexing_progress(&self) -> (usize, usize) {
        (
            self.indexed_repos_count.load(Ordering::Acquire),
            self.total_repos_count.load(Ordering::Acquire),
        )
    }

    pub fn get_initialization_status(&self) -> HashMap<String, serde_json::Value> {
        let mut status = HashMap::new();
        status.insert(
            "is_initialized".to_string(),
            serde_json::Value::Bool(self.is_fully_initialized()),
        );
        status.insert(
            "indexed_repos".to_string(),
            serde_json::Value::Number(self.indexed_repos_count.load(Ordering::Acquire).into()),
        );
        status.insert(
            "total_repos".to_string(),
            serde_json::Value::Number(self.total_repos_count.load(Ordering::Acquire).into()),
        );
        status.insert(
            "progress_percentage".to_string(),
            serde_json::Value::Number(
                if self.total_repos_count.load(Ordering::Acquire) > 0 {
                    ((self.indexed_repos_count.load(Ordering::Acquire) as f64
                        / self.total_repos_count.load(Ordering::Acquire) as f64)
                        * 100.0) as i64
                } else {
                    100
                }
                .into(),
            ),
        );
        status
    }

    /// Index one symbol's signature into the embedding engine. Skips symbols
    /// without a signature (nothing to embed). `symbol.file_path` must already
    /// be the repo-relative path.
    fn index_symbol_embeddings(&self, repo: &str, symbol: &Symbol) {
        let sig = match symbol.signature {
            Some(ref sig) => sig,
            None => return,
        };
        // file_path is repo-relative, so two repos can share the same one --
        // prefix with repo to keep the embedding store's document id unique.
        let symbol_id = format!("{}::{}::{}", repo, symbol.file_path, symbol.name);
        self.embedding_engine.index_snippet(
            symbol_id,
            repo.to_string(),
            symbol.file_path.clone(),
            sig.clone(),
            symbol.start_line,
            symbol.end_line,
        );
    }

    /// Does `repo_path` ship a compile_commands.json clangd can read? Honors an
    /// explicit `--compile-commands-path`, else the conventional locations.
    fn compile_commands_present(&self, repo_path: &Path) -> bool {
        if let Some(rel) = &self.options.compile_commands_path {
            return repo_path.join(rel).exists();
        }
        repo_path.join("compile_commands.json").exists()
            || repo_path.join("build/compile_commands.json").exists()
    }

    /// Candidate compile_commands.json paths for `repo_path`, mirroring the
    /// resolution in `load_compile_commands_filter`.
    fn compile_commands_candidate_paths(&self, repo_path: &Path) -> Vec<PathBuf> {
        match &self.options.compile_commands_path {
            Some(explicit) if explicit.is_absolute() => vec![explicit.clone()],
            Some(explicit) => vec![repo_path.join(explicit)],
            None => vec![
                repo_path.join("compile_commands.json"),
                repo_path.join("build/compile_commands.json"),
            ],
        }
    }

    /// sha256 over the resolved compile_commands.json content, or None when CDB
    /// filtering is off or no CDB is present. Folds candidate files in a fixed
    /// order for determinism; part of the index freshness fingerprint.
    fn compile_commands_hash(&self, repo_path: &Path) -> Option<String> {
        if !self.options.use_compile_commands {
            return None;
        }
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut any = false;
        for cdb in self.compile_commands_candidate_paths(repo_path) {
            if let Ok(bytes) = std::fs::read(&cdb) {
                hasher.update(&bytes);
                any = true;
            }
        }
        any.then(|| format!("{:x}", hasher.finalize()))
    }

    /// The commit the current compile_commands.json describes. A manifest
    /// byte-identical to the one the last index used still describes the commit
    /// recorded then; a regenerated one describes the tree it was built from,
    /// i.e. this HEAD. None when there is no manifest to filter with.
    fn compile_commands_diff_base(&self, repo_name: &str, repo_path: &Path) -> Option<String> {
        let current_cdb = self.compile_commands_hash(repo_path)?;
        // An explicit reindex drops the in-memory metadata before rebuilding, so
        // fall back to the persisted header: the base outlives both.
        let prior = self
            .repos
            .get(repo_name)
            .map(|meta| (meta.cdb_hash.clone(), meta.cdb_head_hash.clone()))
            .or_else(|| {
                let header = self
                    .index_store
                    .as_ref()?
                    .load_repo_header(repo_path)
                    .ok()?;
                Some((header.cdb_hash, header.cdb_head_hash))
            });
        let carried = prior.and_then(|(prior_cdb, base)| {
            (prior_cdb.as_deref() == Some(current_cdb.as_str()))
                .then_some(base)
                .flatten()
        });
        carried.or_else(|| self.git_head_hash(repo_path))
    }

    /// Repo-relative C/C++ sources the manifest cannot describe because they
    /// changed after `base`. Empty when the repo is not a git checkout or when
    /// `base` is a commit it no longer has.
    fn sources_unlisted_since_cdb(
        &self,
        repo_path: &Path,
        base: &str,
    ) -> std::collections::HashSet<String> {
        let repo = match GitRepo::new(repo_path) {
            Ok(r) => r,
            Err(_) => return std::collections::HashSet::new(),
        };
        repo.changed_files_since(base)
            .unwrap_or_default()
            .into_iter()
            .filter(|rel| {
                let ext = Path::new(rel)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                is_c_source_ext(ext)
            })
            .collect()
    }

    /// git HEAD commit hash for `repo_path`, or None when it is not a git
    /// checkout; part of the index freshness fingerprint.
    fn git_head_hash(&self, repo_path: &Path) -> Option<String> {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(repo_path)
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let hash = String::from_utf8(output.stdout).ok()?.trim().to_string();
        (!hash.is_empty()).then_some(hash)
    }

    /// True when the in-memory repo metadata's recorded fingerprint still matches
    /// the repo's current git HEAD and compile_commands.json. A false result
    /// means the cached symbols are stale and must be rebuilt.
    fn fingerprint_matches(&self, repo_name: &str, repo_path: &Path) -> bool {
        let (prior_head, prior_cdb, prior_logic) = match self.repos.get(repo_name) {
            Some(meta) => (
                meta.head_hash.clone(),
                meta.cdb_hash.clone(),
                meta.logic_version,
            ),
            None => return false,
        };
        // An index built by an older indexer would produce different symbols/edges
        // for the same source, so a logic-version bump invalidates it regardless of
        // git HEAD / compile_commands.json.
        if prior_logic != crate::persist::INDEX_LOGIC_VERSION {
            return false;
        }
        let head = self.git_head_hash(repo_path);
        let cdb = self.compile_commands_hash(repo_path);
        // With neither a git HEAD nor a compile_commands.json there is no fingerprint
        // to prove freshness, so an in-place edit between restarts would go undetected
        // and stale symbols would be served. Treat the cache as invalid and rebuild.
        if head.is_none() && cdb.is_none() {
            return false;
        }
        prior_head == head && prior_cdb == cdb
    }

    /// Persisted per-file `(content_hash, symbols)` for a repo, keyed by the
    /// repo-relative path, so a fingerprint-triggered rebuild can reuse unchanged
    /// files' symbols instead of re-augmenting them. None when persistence is off,
    /// no prior index exists, or another [`crate::persist::INDEX_LOGIC_VERSION`]
    /// built it. Files are persisted only when they have at least
    /// one symbol, whose `file_path` is the repo-relative path.
    fn load_prior_file_symbols(
        &self,
        repo_path: &Path,
    ) -> Option<HashMap<String, (String, Vec<Symbol>)>> {
        let store = self.index_store.as_ref()?;
        let persisted = store.load_repo(repo_path).ok()?;
        // An older indexer would extract or merge the same content differently.
        if persisted.logic_version != crate::persist::INDEX_LOGIC_VERSION {
            return None;
        }
        let mut by_rel: HashMap<String, (String, Vec<Symbol>)> = HashMap::new();
        for file_meta in persisted.files.into_values() {
            if let Some(rel) = file_meta.symbols.first().map(|s| s.file_path.clone()) {
                by_rel.insert(rel, (file_meta.content_hash, file_meta.symbols));
            }
        }
        Some(by_rel)
    }

    /// Persisted call-graph augmentation edges for a repo as `(caller_key, edge)`,
    /// flattened across all files. Replayed onto the freshly-built baseline when
    /// the fingerprint matches, sparing the clangd/ccls/gtags round-trips. None
    /// when persistence is off or no prior index exists.
    fn load_prior_call_edges(&self, repo_path: &Path) -> Option<Vec<(String, CallEdge)>> {
        let store = self.index_store.as_ref()?;
        let persisted = store.load_repo(repo_path).ok()?;
        let edges = persisted
            .files
            .into_values()
            .flat_map(|file_meta| file_meta.call_edges)
            .map(|persisted_edge| (persisted_edge.caller_key, persisted_edge.edge))
            .collect();
        Some(edges)
    }

    /// Whether LSP augmentation applies to `repo_path` given the recorded intent
    /// and what the repo ships. Does not test for C/C++ presence — callers gate
    /// that per file/symbol.
    fn lsp_repo_enabled(&self, repo_path: &Path) -> bool {
        self.lsp_manager.as_ref().is_some_and(|l| l.is_enabled())
            && match self.options.lsp_intent {
                BackendIntent::On => true,
                BackendIntent::Off => false,
                BackendIntent::Auto => self.compile_commands_present(repo_path),
            }
    }

    /// Per-repo compiled settings for `repo_path`, looked up by canonical key
    /// (matching how `repo_settings` was built); `unlisted_repo_settings` for a
    /// repo with no profile entry.
    fn repo_settings_for_path(&self, repo_path: &Path) -> &CompiledRepoSettings {
        canonical_repo_key(repo_path)
            .ok()
            .and_then(|key| self.repo_settings.get(&key))
            .unwrap_or(&self.unlisted_repo_settings)
    }

    /// Effective compile_commands coverage threshold (percent) for `repo_path`:
    /// the per-repo `compile_commands_min_coverage_pct` override wins over the
    /// global default.
    fn compile_commands_min_coverage_pct(&self, repo_path: &Path) -> usize {
        self.repo_settings_for_path(repo_path)
            .compile_commands_min_coverage_pct
            .unwrap_or(COMPILE_COMMANDS_DEFAULT_MIN_COVERAGE_PCT)
    }

    /// Note appended to a zero-symbol find_symbols answer when `file_glob`
    /// matches a file the compile_commands.json coverage filter dropped from
    /// this repo's index, so the miss reads as "not indexed", not "no
    /// symbols" or "parser failure".
    fn compile_commands_filter_note(
        &self,
        repo: &str,
        file_glob: Option<&glob::Pattern>,
    ) -> String {
        let Some(glob) = file_glob else {
            return String::new();
        };
        let Some(filtered) = self.compile_commands_filtered_files.get(repo) else {
            return String::new();
        };
        let repo_path = Path::new(repo);
        let matches: Vec<String> = filtered
            .iter()
            .filter_map(|abs| {
                let rel = abs.strip_prefix(repo_path).unwrap_or(abs).to_string_lossy();
                glob.matches(&rel).then(|| rel.into_owned())
            })
            .collect();
        if matches.is_empty() {
            return String::new();
        }
        format!(
            "> Note: {} matched by `file_pattern` and not listed in this repo's \
             compile_commands.json, so the index excluded {} from the base build \
             (not a parser failure). Regenerate the manifest to include {}, then reindex.\n\n",
            matches
                .iter()
                .map(|f| format!("`{}`", f))
                .collect::<Vec<_>>()
                .join(", "),
            if matches.len() == 1 { "it" } else { "them" },
            if matches.len() == 1 { "it" } else { "them" },
        )
    }

    /// Whether gtags is intended for `repo_path`, ignoring whether a GTAGS db
    /// exists yet (used by the auto-generate gate, which runs before the db is
    /// built). The per-repo `gtags: { enabled }` override wins over the global
    /// `--gtags`/`--no-gtags` intent.
    fn gtags_repo_intended(&self, repo_path: &Path) -> bool {
        match self.repo_settings_for_path(repo_path).gtags_enabled {
            Some(enabled) => enabled,
            None => self.options.gtags_intent != BackendIntent::Off,
        }
    }

    /// Whether GTAGS should be auto-generated/refreshed for `repo_path`: the
    /// per-repo `gtags: { generate }` override wins over the global
    /// `--gtags-generate` flag.
    fn gtags_generate_for_repo(&self, repo_path: &Path) -> bool {
        self.repo_settings_for_path(repo_path)
            .gtags_generate
            .unwrap_or(self.options.gtags_generate)
    }

    /// Whether gtags augmentation applies to `repo_path`. A GTAGS database is
    /// required even when intent is `On` (global cannot query without one);
    /// `On` only forces the manager to exist at startup. The per-repo enable
    /// override is folded in via `gtags_repo_intended`.
    fn gtags_repo_enabled(&self, repo_path: &Path) -> bool {
        self.gtags_manager.is_some()
            && self.gtags_repo_intended(repo_path)
            && gtags_file_path(repo_path).exists()
    }

    /// Effective `--index-filter` rules for a repo: its per-repo override if it
    /// has one, else the global default.
    fn repo_index_filter_rules(&self, repo_name: &str) -> &[ScopeRule] {
        self.repo_settings
            .get(repo_name)
            .map(|s| s.index_filter.as_slice())
            .unwrap_or(&self.default_index_filter)
    }

    /// Effective `--lsp-scope` rules for a repo: its per-repo override if it has
    /// one, else the global default.
    fn repo_lsp_scope_rules(&self, repo_name: &str) -> &[ScopeRule] {
        self.repo_settings
            .get(repo_name)
            .map(|s| s.lsp_scope.as_slice())
            .unwrap_or(&self.default_lsp_scope)
    }

    /// Whether `--lsp-scope` applies to this repo (empty = LSP pass runs
    /// repo-wide).
    fn lsp_scope_active(&self, repo_name: &str) -> bool {
        !self.repo_lsp_scope_rules(repo_name).is_empty()
    }

    /// Whether a file is under any `--lsp-scope` entry for this repo. Each entry
    /// is matched against both the repo-relative path and the absolute path, so
    /// a relative entry (e.g. `fs/fuse`) matches that path in any repo, while an
    /// absolute entry (e.g. `/home/u/src/linux.git/fs`) scopes one repo
    /// precisely and never matches another.
    fn lsp_scope_matches(&self, repo_name: &str, rel: &str, abs: &str) -> bool {
        scope_matches(self.repo_lsp_scope_rules(repo_name), rel, abs)
    }

    /// Whether the clangd/ccls augment passes are off for this repo: true when
    /// it enables no C/C++ backend (clangd and ccls both disabled), so it is
    /// indexed with tree-sitter + gtags only.
    fn lsp_augment_disabled(&self, repo_name: &str) -> bool {
        self.lsp_manager
            .as_ref()
            .map(|lsp| lsp.active_cxx_backends_for(Path::new(repo_name)).is_empty())
            .unwrap_or(true)
    }

    /// Whether `--index-filter` restricted this repo's base index (memoized at
    /// index time). Absent = not restricted, so unrelated repos stay full.
    fn repo_index_filtered(&self, repo_name: &str) -> bool {
        self.index_filtered_repos
            .get(repo_name)
            .map(|v| *v)
            .unwrap_or(false)
    }

    /// Whether the additional clangd/ccls pass should run for `rel`. tree-sitter
    /// and gtags always run; this only bounds the LSP layer. `repo_scoped` is true
    /// when the repo has at least one file under `--lsp-scope` (so an unrelated
    /// repo is never silently dropped). In a scoped repo the pass is limited to
    /// matching files that are real C/C++ source TUs — honoring compile_commands
    /// (headers / non-built files are excluded; the `.c` files reaching
    /// augmentation are already compile_commands-filtered, so an extension check
    /// suffices).
    fn lsp_augment_allows(&self, repo_name: &str, repo_scoped: bool, rel: &str, abs: &str) -> bool {
        if self.lsp_augment_disabled(repo_name) {
            return false;
        }
        if !repo_scoped {
            return true;
        }
        let ext = Path::new(rel)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        self.lsp_scope_matches(repo_name, rel, abs) && is_c_source_ext(ext)
    }

    /// Per-repo `.gitignore` matcher (repo `.gitignore` + `.git/info/exclude`),
    /// built once and cached. Mirrors the `git_ignore`/`git_exclude` flags the
    /// index-time `ignore::WalkBuilder` uses so the watch path can reject the
    /// same paths the indexer would.
    fn gitignore_for(&self, repo_path: &Path) -> Arc<ignore::gitignore::Gitignore> {
        if let Some(matcher) = self.gitignore_matchers.get(repo_path) {
            return matcher.clone();
        }
        let mut builder = ignore::gitignore::GitignoreBuilder::new(repo_path);
        builder.add(repo_path.join(".gitignore"));
        builder.add(repo_path.join(".git/info/exclude"));
        let matcher = Arc::new(
            builder
                .build()
                .unwrap_or_else(|_| ignore::gitignore::Gitignore::empty()),
        );
        self.gitignore_matchers
            .insert(repo_path.to_path_buf(), matcher.clone());
        matcher
    }

    /// True when the indexer would never have indexed `abs_path` under
    /// `repo_path` — a dotfile/dir, a `.gitignore`d path, or a merge-conflict
    /// artifact — mirroring the index-time `WalkBuilder` (`hidden(true)` +
    /// git ignores + `is_merge_conflict_artifact`). The watch path consults
    /// this so build output written into a watched tree never triggers a
    /// re-index or a gtags refresh (an in-tree kernel build emits `*.o`,
    /// `*.o.d`, `include/generated/*.h`, `*.mod.c`, …).
    fn is_ignored_for_index(&self, repo_path: &Path, abs_path: &Path) -> bool {
        let rel = abs_path.strip_prefix(repo_path).unwrap_or(abs_path);
        // hidden(true): the indexer skips any entry whose name starts with '.'.
        // Covers .git, .ccls-cache, .cache/clangd and hidden Kbuild deps such as
        // arch/x86/boot/.early_serial_console.o.d.
        if rel
            .components()
            .any(|c| c.as_os_str().to_str().is_some_and(|s| s.starts_with('.')))
        {
            return true;
        }
        if is_merge_conflict_artifact(abs_path) {
            return true;
        }
        self.gitignore_for(repo_path)
            .matched_path_or_any_parents(rel, false)
            .is_ignore()
    }

    /// Refresh the GTAGS database for `repo_path` when gtags is the active C/C++
    /// backend, mirroring index_repo's refresh gating. The watch path calls this
    /// wherever it brings clangd back in sync (compile_commands change, source edit)
    /// so the gtags peer backend does not silently drift its line numbers.
    async fn refresh_gtags_if_active(&self, repo_path: &Path) {
        // gtags_repo_enabled == gtags is genuinely active here (manager present,
        // intent not Off, a GTAGS db exists) — i.e. "if gtags is used".
        if !self.gtags_repo_enabled(repo_path) {
            return;
        }
        // Debounce: a burst of edits (e.g. a branch switch touching many files)
        // must not spawn back-to-back full-tree `global -u` passes, each of which
        // re-stats the whole repo. Skip when one ran for this repo recently.
        const GTAGS_REFRESH_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(5);
        if let Some(last) = self.gtags_last_refresh.get(repo_path) {
            if last.elapsed() < GTAGS_REFRESH_DEBOUNCE {
                debug!(
                    "gtags: refresh for {:?} debounced ({:?} since last)",
                    repo_path,
                    last.elapsed()
                );
                return;
            }
        }
        if self.gtags_generate_for_repo(repo_path) && crate::gtags::gtags_binary_present() {
            if let Some(gtags) = &self.gtags_manager {
                self.gtags_last_refresh
                    .insert(repo_path.to_path_buf(), std::time::Instant::now());
                gtags.update_database(repo_path).await; // global -u, incremental
            }
        } else {
            warn!(
                "gtags: {:?} changed under watch but GTAGS was not refreshed (pass \
                 --gtags-generate to refresh automatically); cross-validation degraded.",
                repo_path
            );
        }
    }

    /// Backends enabled for cross-validation on `repo_path`. tree-sitter is
    /// always present; the C/C++ LSP backends and gtags count only for C/C++
    /// data (`is_cxx`) and only when this repo actually enabled them. Gates
    /// provenance annotations — a divergence is only meaningful when at least
    /// two backends were enabled.
    fn enabled_backends_for_repo(&self, repo_path: &Path, is_cxx: bool) -> SourceSet {
        let mut set = SourceSet::TREE_SITTER;
        if is_cxx {
            if self.lsp_repo_enabled(repo_path) {
                if let Some(lsp) = &self.lsp_manager {
                    for backend in lsp.active_cxx_backends_for(repo_path) {
                        set.insert(backend);
                    }
                }
            }
            if self.gtags_repo_enabled(repo_path) {
                set.insert(SourceSet::GTAGS);
            }
        }
        set
    }

    async fn index_repos(&self) -> Result<()> {
        for repo_path in &self.registered_repo_paths() {
            if repo_path.exists() {
                info!("Indexing repository: {:?}", repo_path);
                if let Err(e) = self.index_repo(repo_path).await {
                    warn!("Failed to index {:?}: {}", repo_path, e);
                }
            } else {
                warn!("Repository path does not exist: {:?}", repo_path);
            }
        }
        Ok(())
    }

    /// Make the git tools answer for `repo_name`, unless --git is off or its
    /// work tree is already registered. A path git does not own is skipped
    /// silently: the git tools then report it as they do for any non-checkout.
    fn register_git_repo(&self, repo_name: &str, path: &Path) {
        if !self.options.git_enabled || self.git_repos.contains_key(repo_name) {
            return;
        }
        match GitRepo::new(path) {
            Ok(git_repo) => {
                info!("Git enabled for repository: {}", repo_name);
                self.git_repos.insert(repo_name.to_string(), git_repo);
            }
            Err(e) => debug!("Failed to initialize git for {}: {}", repo_name, e),
        }
    }

    /// Build (or rebuild) the index for `path`. The caller holds the repo's
    /// update lease — `reindex` needs it across the clears preceding this call.
    async fn index_repo(&self, path: &Path) -> Result<()> {
        let start_time = std::time::Instant::now();
        let repo_name = canonical_repo_key(path)?;

        self.register_git_repo(&repo_name, path);
        // A repo adopted after startup (e.g. via `reindex`) is otherwise absent
        // from the LSP manager's workspace roots, so `repo_for_path` silently
        // misattributes its files to the first-configured root instead.
        if let Some(lsp) = &self.lsp_manager {
            lsp.register_workspace_root(path.to_path_buf());
        }

        // If symbols are already loaded from the persistence cache, skip the
        // expensive per-symbol embedding indexing — BM25 and call graph still
        // get rebuilt from the parsed files below.
        // A cached repo whose fingerprint still matches needs no symbol work. A
        // mismatch (git HEAD moved or compile_commands.json changed since the
        // index was built) forces a rebuild that reuses unchanged files' persisted
        // symbols. A never-indexed repo is a full build.
        let was_cached = self.symbols.contains_key(&repo_name);
        let symbols_cached = was_cached && self.fingerprint_matches(&repo_name, path);
        let prior_symbols = if was_cached && !symbols_cached {
            info!(
                "index fingerprint changed (HEAD or compile_commands.json) — rebuilding symbols for {}",
                repo_name
            );
            self.load_prior_file_symbols(path)
        } else {
            None
        };

        // C/C++ symbol augmentation (Phases 2/3): clangd/ccls documentSymbol and
        // gtags definitions are folded into the tree-sitter baseline. Whether a
        // backend actually runs is decided per repo *after* parsing (it needs the
        // repo's language set and its compile_commands.json / GTAGS db); here we
        // only decide whether to defer C/C++ symbols for that later pass. Cached
        // repos skip it with the rest of the re-index work.
        let lsp_candidate = self.lsp_manager.as_ref().is_some_and(|l| l.is_enabled())
            && self.options.lsp_intent != BackendIntent::Off;
        let gtags_candidate =
            self.gtags_manager.is_some() && self.options.gtags_intent != BackendIntent::Off;
        let cxx_augment = !symbols_cached && (lsp_candidate || gtags_candidate);
        let mut cxx_groups: Vec<CxxFileSymbols> = Vec::new();

        let mut languages: HashMap<String, LanguageStats> = HashMap::new();
        let mut symbols_vec: Vec<Symbol> = Vec::new();
        let mut file_count = 0;
        let mut total_lines = 0;

        // Use ignore crate to respect .gitignore
        let walker = ignore::WalkBuilder::new(path)
            .hidden(true)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .require_git(false)
            .build();

        let mut files: Vec<PathBuf> = walker
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .filter(|e| !is_merge_conflict_artifact(e.path()))
            .map(|e| e.path().to_path_buf())
            .collect();

        // --index-filter: restrict the base index to matching files, but only for
        // a repo that actually contains a match — a repo with none is indexed in
        // full, so unrelated repos are never touched. Files named by --include are
        // force-kept. The decision is memoized for the watch path.
        let index_filter_rules = self.repo_index_filter_rules(&repo_name);
        let repo_index_filtered = !index_filter_rules.is_empty()
            && files.iter().any(|f| {
                let rel = f
                    .strip_prefix(path)
                    .unwrap_or(f)
                    .to_string_lossy()
                    .into_owned();
                scope_matches(index_filter_rules, &rel, &f.to_string_lossy())
            });
        // The full walk result, kept only where the filter is active: a pull-in
        // may only resolve a reference to a file the walker itself listed, never
        // to an arbitrary path.
        let all_files: std::collections::HashSet<PathBuf> = if repo_index_filtered {
            files.iter().cloned().collect()
        } else {
            std::collections::HashSet::new()
        };
        if repo_index_filtered {
            let before = files.len();
            let include = compile_scope(&self.options.include);
            files.retain(|f| {
                let rel = f
                    .strip_prefix(path)
                    .unwrap_or(f)
                    .to_string_lossy()
                    .into_owned();
                let abs = f.to_string_lossy();
                scope_matches(index_filter_rules, &rel, &abs) || scope_matches(&include, &rel, &abs)
            });
            info!(
                "--index-filter: {} → {} files ({} filtered out) in {}",
                before,
                files.len(),
                before - files.len(),
                repo_name
            );
        }
        self.index_filtered_repos
            .insert(repo_name.clone(), repo_index_filtered);

        // A handful of C/C++ files usually means a plain-Makefile project that
        // ships no compile_commands.json; applying the filter there would drop
        // those sources from indexing and warn pointlessly. Engage it only for
        // repos with a real C/C++ build.
        let cxx_source_count = files
            .iter()
            .filter(|f| {
                let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
                is_c_source_ext(ext)
            })
            .count();
        let cdb_diff_base = self.compile_commands_diff_base(&repo_name, path);
        // Reset before deciding: a repo that no longer engages the filter (or
        // whose manifest is now stale) must not keep reporting last run's
        // exclusions as the reason a file has no symbols.
        self.compile_commands_filtered_files.remove(&repo_name);
        if self.options.use_compile_commands && cxx_source_count >= COMPILE_COMMANDS_MIN_CXX_SOURCES
        {
            let explicit: Option<&Path> = self.options.compile_commands_path.as_deref();
            let compiled = if let Some(p) = explicit {
                load_compile_commands_filter(path, &[p])
            } else {
                load_compile_commands_filter(
                    path,
                    &[
                        Path::new("compile_commands.json"),
                        Path::new("build/compile_commands.json"),
                    ],
                )
            };
            let patterns = compile_include_patterns(&self.options.include);

            // A manifest covering only a sliver of the repo's C sources is
            // stale/partial (e.g. an incremental `bear -- make` that recompiled
            // one TU); honouring it would silently drop nearly every source, so
            // fall back to indexing all sources. clangd still gets the manifest.
            let min_coverage_pct = self.compile_commands_min_coverage_pct(path);
            let covered = files
                .iter()
                .filter(|abs_path| {
                    let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    is_c_source_ext(ext) && compiled.contains(abs_path.as_path())
                })
                .count();

            if covered * 100 < cxx_source_count * min_coverage_pct {
                warn!(
                    "compile_commands.json covers only {}/{} C sources (<{}%) for {} — \
                     treating as stale; indexing all sources",
                    covered, cxx_source_count, min_coverage_pct, repo_name
                );
            } else {
                // The build wrote the manifest at one commit; a checkout since
                // then added sources it cannot list. Carry those, or they vanish
                // from the index with nothing saying why.
                let unlisted = cdb_diff_base
                    .as_deref()
                    .map(|base| self.sources_unlisted_since_cdb(path, base))
                    .unwrap_or_default();
                let before = files.len();
                let mut carried = 0usize;
                let mut filtered_out: Vec<PathBuf> = Vec::new();
                files.retain(|abs_path| {
                    let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if is_c_header_ext(ext) {
                        return true;
                    }
                    if !is_c_source_ext(ext) {
                        return true;
                    }
                    if compiled.contains(abs_path.as_path()) {
                        return true;
                    }
                    let rel = abs_path.strip_prefix(path).unwrap_or(abs_path);
                    if unlisted.contains(rel.to_string_lossy().as_ref()) {
                        carried += 1;
                        return true;
                    }
                    let keep = patterns.iter().any(|p| p.matches_path(rel));
                    if !keep {
                        filtered_out.push(abs_path.clone());
                    }
                    keep
                });
                self.compile_commands_filtered_files
                    .insert(repo_name.clone(), filtered_out);
                let behind = cdb_diff_base
                    .as_deref()
                    .and_then(|base| GitRepo::new(path).ok().and_then(|r| r.commits_since(base)))
                    .unwrap_or(0);
                info!(
                    "compile_commands filter: {} → {} files ({} filtered out, \
                     {} carried past a manifest {} commit(s) behind HEAD)",
                    before,
                    files.len(),
                    before - files.len(),
                    carried,
                    behind
                );
            }
        }

        // Whether the repo holds C/C++ at all, decided per repo before parsing:
        // the gtags database has to exist before the --index-filter pull-in
        // below can ask it where an out-of-scope callee is defined, and the
        // backends that run (Auto needs compile_commands.json / a GTAGS db)
        // follow from the same answer. gtags builds its database on demand
        // first, size-gated, since it writes into the repo tree.
        let cxx_present = files.iter().any(|file| {
            file.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| is_c_source_ext(ext) || is_c_header_ext(ext))
        });
        if cxx_present
            && self.gtags_generate_for_repo(path)
            && self.gtags_repo_intended(path)
            && !gtags_file_path(path).exists()
        {
            if files.len() > GTAGS_GENERATE_MAX_FILES {
                info!(
                    "gtags: skip auto-generate for {} ({} files > {} limit)",
                    repo_name,
                    files.len(),
                    GTAGS_GENERATE_MAX_FILES
                );
            } else if crate::gtags::gtags_binary_present() {
                if let Some(gtags) = &self.gtags_manager {
                    gtags.ensure_database(path).await;
                }
            }
        }
        // An existing GTAGS predating the current sources drifts its line numbers,
        // which the line-window symbol merge cannot pair — silently degrading gtags
        // cross-validation. Refresh it (writes into the repo, so opt-in via
        // --gtags-generate) before the augment runs, else warn.
        if cxx_present
            && self.gtags_repo_intended(path)
            && gtags_file_path(path).exists()
            && gtags_database_stale(path, &files)
        {
            if self.gtags_generate_for_repo(path) && crate::gtags::gtags_binary_present() {
                if let Some(gtags) = &self.gtags_manager {
                    gtags.update_database(path).await;
                }
            } else {
                warn!(
                    "gtags: GTAGS in {:?} is older than indexed sources; symbol \
                     cross-validation will be degraded. Run `global -u` (or pass \
                     --gtags-generate to refresh automatically).",
                    path
                );
            }
        }

        // Parse files in parallel
        let parse_phase_start = std::time::Instant::now();
        let metrics = Arc::clone(&self.metrics);
        let parse_files =
            |to_parse: &[PathBuf]| -> Vec<(PathBuf, String, crate::parser::ParsedFile)> {
                to_parse
                    .par_iter()
                    .filter_map(|file_path| {
                        let parse_start = std::time::Instant::now();
                        let content = std::fs::read_to_string(file_path).ok()?;
                        let parsed = self.parser.parse_file(file_path, &content).ok()?;
                        metrics.record_file_parse(parse_start.elapsed());
                        Some((file_path.clone(), content, parsed))
                    })
                    .collect()
            };
        let mut parsed_results = parse_files(&files);

        // --index-filter keeps only the files its rules name, so a definition or
        // header that in-scope code calls or includes directly is left out and
        // reads as "not indexed". Index those specific files too.
        if repo_index_filtered {
            let pulled_in = self
                .pull_in_referenced_files(path, &all_files, &parsed_results)
                .await;
            if !pulled_in.files.is_empty() {
                let extra = parse_files(&pulled_in.files);
                info!(
                    "--index-filter: pulled in {} file(s) referenced by in-scope code in {} \
                     ({} via #include, {} via gtags, {} via definition map)",
                    pulled_in.files.len(),
                    repo_name,
                    pulled_in.from_includes,
                    pulled_in.from_gtags,
                    pulled_in.from_store
                );
                files.extend(pulled_in.files);
                parsed_results.extend(extra);
            }
        }

        // Tokenize all files in parallel and build SearchDocuments.
        // tokenize_code is the dominant cost of the old serial index_file loop;
        // doing it here with par_iter avoids one write-lock acquisition per file.
        let search_docs: Vec<SearchDocument> = parsed_results
            .par_iter()
            .map(|(file_path, content, _)| {
                let relative_path = file_path
                    .strip_prefix(path)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .to_string();
                build_file_doc(&repo_name, &relative_path, content)
            })
            .collect();

        // Collect parsed trees for call graph construction
        let mut trees_for_callgraph: Vec<(String, String, tree_sitter::Tree)> = Vec::new();

        // A cached repo's symbols only cover the files that produced them, and
        // the pull-in can name more than it did last time — a definition map
        // that landed after the previous index widens it without moving git
        // HEAD or compile_commands.json, so the fingerprint still matches.
        // Those files would otherwise be parsed into the search index and the
        // call graph while staying invisible to find_symbols.
        let cached_symbol_files: std::collections::HashSet<String> = if symbols_cached {
            self.symbols
                .get(&repo_name)
                .map(|symbols| symbols.iter().map(|s| s.file_path.clone()).collect())
                .unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        };
        let mut late_symbols: Vec<Symbol> = Vec::new();

        for (file_path, content, parsed) in parsed_results {
            file_count += 1;
            let lines = content.lines().count();
            total_lines += lines;

            // Update language stats
            let lang_stats = languages.entry(parsed.language.clone()).or_default();
            lang_stats.file_count += 1;
            lang_stats.line_count += lines;
            lang_stats.byte_count += content.len();

            // Collect symbols with file path and index for embeddings
            let relative_path = file_path
                .strip_prefix(path)
                .unwrap_or(&file_path)
                .to_string_lossy()
                .to_string();

            if !symbols_cached {
                let is_cxx = is_cxx_language(parsed.language.as_str());
                // On a fingerprint rebuild, an unchanged C/C++ file reuses its
                // persisted (already-augmented) symbols, skipping the costly
                // clangd/gtags round-trip below.
                let reused = if cxx_augment && is_cxx {
                    prior_symbols
                        .as_ref()
                        .and_then(|prior| prior.get(&relative_path))
                        .filter(|(hash, _)| *hash == content_sha256(content.as_bytes()))
                        .map(|(_, symbols)| symbols.clone())
                } else {
                    None
                };

                if let Some(symbols) = reused {
                    for symbol in &symbols {
                        self.index_symbol_embeddings(&repo_name, symbol);
                    }
                    symbols_vec.extend(symbols);
                } else if cxx_augment && is_cxx {
                    // Queue the tree-sitter baseline for the async LSP/gtags pass
                    // below; embeddings happen there once the symbols are merged.
                    let mut symbols = parsed.symbols;
                    for symbol in &mut symbols {
                        symbol.file_path = relative_path.clone();
                    }
                    cxx_groups.push(CxxFileSymbols {
                        abs_path: file_path.clone(),
                        relative_path: relative_path.clone(),
                        symbols,
                    });
                } else {
                    for mut symbol in parsed.symbols {
                        symbol.file_path = relative_path.clone();
                        self.index_symbol_embeddings(&repo_name, &symbol);
                        symbols_vec.push(symbol);
                    }
                }
            } else if !cached_symbol_files.contains(&relative_path) {
                // Pulled in since the cached symbols were written. Tree-sitter
                // only, and no embeddings: a cached repo did not build its
                // vocabulary this run, so feeding a handful of files into it
                // would skew the IDF values the rest of the index was built on.
                for mut symbol in parsed.symbols {
                    symbol.file_path = relative_path.clone();
                    late_symbols.push(symbol);
                }
            }

            // Cache file content
            self.file_cache
                .insert(file_path.clone(), Arc::new(content.clone()));

            // Collect tree for call graph if enabled and tree exists
            if self.options.call_graph_enabled {
                if let Some(tree) = parsed.tree {
                    trees_for_callgraph.push((relative_path, content, tree));
                }
            }
        }

        info!(
            "timing: parsed {} files in {:?} for {}",
            file_count,
            parse_phase_start.elapsed(),
            repo_name
        );

        let lsp_for_repo = (cxx_present && self.lsp_repo_enabled(path))
            .then(|| self.lsp_manager.clone())
            .flatten();
        let gtags_for_repo = (cxx_present && self.gtags_repo_enabled(path))
            .then(|| self.gtags_manager.clone())
            .flatten();

        // Phases 2/3: augment the queued C/C++ files with clangd/ccls
        // documentSymbol and gtags definitions. The LSP/gtags calls are async and
        // cannot run inside the rayon parse closure, so they run here, after it.
        // A small semaphore bounds in-flight files to overlap the servers and
        // subprocesses without flooding a single LSP process. Runs before
        // embedding finalisation so the merged symbols are embedded.
        if !cxx_groups.is_empty() && lsp_for_repo.is_none() && gtags_for_repo.is_none() {
            // C/C++ files were deferred but this repo enabled no backend (no
            // compile_commands.json / GTAGS db, or intent Off): embed and store
            // the tree-sitter baseline unchanged.
            for group in cxx_groups {
                for symbol in &group.symbols {
                    self.index_symbol_embeddings(&repo_name, symbol);
                }
                symbols_vec.extend(group.symbols);
            }
        } else if !cxx_groups.is_empty() {
            let doc_sym_start = std::time::Instant::now();
            let doc_sym_files = cxx_groups.len();
            let semaphore = Arc::new(tokio::sync::Semaphore::new(CXX_AUGMENT_CONCURRENCY));
            // When --lsp-scope is given, gate the LSP pass to files under it (only
            // for repos that actually contain a matching file). gtags is unaffected.
            let repo_scoped = self.lsp_scope_active(&repo_name)
                && cxx_groups.iter().any(|g| {
                    self.lsp_scope_matches(
                        &repo_name,
                        &g.relative_path,
                        &g.abs_path.to_string_lossy(),
                    )
                });
            // The repo's enabled C/C++ backends, resolved once; each
            // documentSymbol task filters its calls to these.
            let active_backends = lsp_for_repo
                .as_ref()
                .map(|lsp| lsp.active_cxx_backends_for(Path::new(&repo_name)))
                .unwrap_or_default();
            let mut tasks = tokio::task::JoinSet::new();
            for group in cxx_groups {
                let permit = semaphore.clone().acquire_owned().await?;
                let lsp = if self.lsp_augment_allows(
                    &repo_name,
                    repo_scoped,
                    &group.relative_path,
                    &group.abs_path.to_string_lossy(),
                ) {
                    lsp_for_repo.clone()
                } else {
                    None
                };
                let gtags = gtags_for_repo.clone();
                let repo_path = path.to_path_buf();
                let active_backends = active_backends.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let CxxFileSymbols {
                        abs_path,
                        relative_path,
                        mut symbols,
                    } = group;
                    let lang = get_language_from_path(&abs_path.to_string_lossy());

                    if let Some(lsp) = &lsp {
                        for &backend in &active_backends {
                            match lsp.get_document_symbols(backend, &abs_path, &lang).await {
                                Ok(mut lsp_symbols) => {
                                    for symbol in &mut lsp_symbols {
                                        symbol.file_path = relative_path.clone();
                                    }
                                    merge_symbols(&mut symbols, lsp_symbols, backend);
                                }
                                Err(e) => {
                                    debug!("LSP documentSymbol failed for {:?}: {}", abs_path, e)
                                }
                            }
                        }
                    }

                    if let Some(gtags) = &gtags {
                        let gtags_symbols: Vec<Symbol> = gtags
                            .list_file_symbols(&abs_path, &repo_path)
                            .await
                            .into_iter()
                            .map(|(name, line)| Symbol {
                                name,
                                kind: SymbolKind::Unknown,
                                file_path: relative_path.clone(),
                                start_line: line,
                                end_line: line,
                                signature: None,
                                qualified_name: None,
                                doc_comment: None,
                                confirmed_by: SourceSet::GTAGS,
                                line_conflicts: Vec::new(),
                            })
                            .collect();
                        merge_symbols(&mut symbols, gtags_symbols, SourceSet::GTAGS);
                    }

                    symbols
                });
            }

            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok(file_symbols) => {
                        for symbol in &file_symbols {
                            self.index_symbol_embeddings(&repo_name, symbol);
                        }
                        symbols_vec.extend(file_symbols);
                    }
                    Err(e) => warn!("C/C++ symbol augmentation task failed: {}", e),
                }
            }
            info!(
                "timing: cxx documentSymbol+gtags: {} files in {:?} for {}",
                doc_sym_files,
                doc_sym_start.elapsed(),
                repo_name
            );
        }

        // Batch-insert all pre-tokenized search documents under a single write lock.
        self.search_index.batch_add_documents(search_docs);

        // TF-IDF vocabulary finalisation — skip when symbols came from the
        // persistence cache (embedding_engine was not populated this run).
        if !symbols_cached {
            // Build vocabulary and re-embed all snippets with final IDF values.
            // Must happen after the per-file loop so all document frequencies are
            // accumulated before the single O(V log V) sort.
            self.embedding_engine.finalize();
        }

        // Fold in the newly pulled-in files' symbols before the count is
        // reported, so the log describes what the index actually holds.
        if !late_symbols.is_empty() {
            let added = late_symbols.len();
            let mut late_files: Vec<&str> = late_symbols
                .iter()
                .map(|symbol| symbol.file_path.as_str())
                .collect();
            late_files.sort_unstable();
            late_files.dedup();
            let late_file_count = late_files.len();
            if let Some(mut symbols) = self.symbols.get_mut(&repo_name) {
                symbols.extend(late_symbols);
            }
            info!(
                "--index-filter: {} symbol(s) from {} newly pulled-in file(s) added to the \
                 cached index for {}",
                added, late_file_count, repo_name
            );
        }

        let symbol_count = if symbols_cached {
            self.symbols.get(&repo_name).map(|s| s.len()).unwrap_or(0)
        } else {
            symbols_vec.len()
        };

        let metadata = RepoMetadata {
            name: repo_name.clone(),
            path: path.to_path_buf(),
            file_count,
            total_lines,
            languages,
            last_indexed: SystemTime::now(),
            head_hash: self.git_head_hash(path),
            cdb_hash: self.compile_commands_hash(path),
            cdb_head_hash: cdb_diff_base,
            logic_version: crate::persist::INDEX_LOGIC_VERSION,
        };

        info!(
            "Indexed {} files, {} symbols in {}",
            file_count, symbol_count, repo_name
        );

        // Record indexing metrics
        let elapsed = start_time.elapsed();
        self.metrics
            .record_repo_index(repo_name.clone(), elapsed, file_count, symbol_count);

        if !symbols_cached {
            self.repos.insert(repo_name.clone(), metadata);
            self.symbols.insert(repo_name.clone(), symbols_vec);
        }

        // Build call graph if enabled
        if self.options.call_graph_enabled && !trees_for_callgraph.is_empty() {
            if let Some(call_graph) = self.call_graphs.get(&repo_name) {
                let call_graph_start = std::time::Instant::now();
                if let Err(e) = call_graph.build_from_files(&trees_for_callgraph) {
                    warn!("Failed to build call graph for {}: {}", repo_name, e);
                } else {
                    info!(
                        "Built call graph for {} with {} files in {:?}",
                        repo_name,
                        trees_for_callgraph.len(),
                        call_graph_start.elapsed()
                    );
                }
            }
        }

        // Phases 5/6: augment the C/C++ call graph from LSP callHierarchy and
        // gtags references. The baseline graph built above provides the nodes
        // merge_edges folds edges onto. A fingerprint-matching repo replays the
        // edges persisted last run instead of re-querying the backends — the
        // dominant cost of startup, and redundant when no source changed.
        if self.options.call_graph_enabled && self.call_graphs.contains_key(&repo_name) {
            if symbols_cached {
                let restored = self.load_prior_call_edges(path).unwrap_or_default();
                if !restored.is_empty() {
                    if let Some(call_graph) = self.call_graphs.get(&repo_name) {
                        let restore_start = std::time::Instant::now();
                        let edge_count = restored.len();
                        call_graph.restore_augmentation_edges(restored);
                        info!(
                            "restored {} call-graph augmentation edge(s) in {:?} for {}",
                            edge_count,
                            restore_start.elapsed(),
                            repo_name
                        );
                    }
                }
            } else if lsp_for_repo.is_some() || gtags_for_repo.is_some() {
                let call_hierarchy_start = std::time::Instant::now();
                self.augment_call_graph_cxx(&repo_name, path, &lsp_for_repo, &gtags_for_repo)
                    .await;
                info!(
                    "timing: cxx callHierarchy augmentation in {:?} for {}",
                    call_hierarchy_start.elapsed(),
                    repo_name
                );
            }
        }

        // What lets a filtered index name the file defining a symbol the filter
        // dropped. Started here, after the index is published, so the repo is
        // already answering queries while the map fills.
        if repo_index_filtered {
            let mut repo_files: Vec<PathBuf> = all_files.into_iter().collect();
            repo_files.sort();
            self.spawn_definition_build(path, &repo_name, repo_files)
                .await;
        }

        Ok(())
    }

    /// Start (or restart) the background build of a repo's definition map.
    ///
    /// Runs behind the index: the repo already answers queries, and the map
    /// stays invisible until the build commits it. A build already running for
    /// this repo is aborted and awaited first, so its writes cannot land on top
    /// of the new one.
    async fn spawn_definition_build(&self, repo_path: &Path, repo_name: &str, files: Vec<PathBuf>) {
        let Some(store) = self.index_store.clone() else {
            // The map lives in the persisted store, so without --persist the
            // callee pull-in has only gtags to go on. Say so rather than
            // silently doing nothing.
            info!(
                "--index-filter: {} has no persisted store, so callee definitions \
                 can only come from gtags (enable --persist for the definition map)",
                repo_name
            );
            return;
        };
        if let Some((_, previous)) = self.definition_builds.remove(repo_name) {
            previous.abort();
            let _ = previous.await;
        }

        let handle = tokio::spawn(build_definition_map(
            store,
            Arc::clone(&self.parser),
            repo_path.to_path_buf(),
            repo_name.to_string(),
            files,
        ));
        self.definition_builds.insert(repo_name.to_string(), handle);
    }

    /// Wait for the background definition-map builds, then index each repo
    /// whose map has just landed one more time.
    ///
    /// A map commits after the pull-in that wants it has already run, so
    /// without this pass a repo indexed for the first time pulls in nothing
    /// until something else triggers a reindex — precisely while someone is
    /// first exploring it. The second pass costs one more index of an
    /// already-warm repo, and the build it would start is skipped because the
    /// map it just wrote is current.
    pub async fn catch_up_on_definition_maps(&self) {
        let pending: Vec<String> = self
            .definition_builds
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        for repo_name in pending {
            let Some((_, handle)) = self.definition_builds.remove(&repo_name) else {
                continue;
            };
            // A build that was aborted, panicked, or found nothing to change
            // leaves the pull-in exactly as it already ran it.
            if !matches!(handle.await, Ok(true)) {
                continue;
            }

            let repo_path = self
                .registered_repo_paths()
                .into_iter()
                .find(|path| canonical_repo_key(path).is_ok_and(|key| key == repo_name));
            let Some(repo_path) = repo_path else {
                continue;
            };

            info!(
                "--index-filter: definition map ready for {}; re-running the pull-in",
                repo_name
            );
            // Every other index_repo call holds these: a query landing mid-pass
            // would be answered from a repo whose symbols are half rebuilt.
            let _leases = self
                .index_update_leases(std::slice::from_ref(&repo_name))
                .await;
            if let Err(e) = self.index_repo(&repo_path).await {
                warn!(
                    "definition map: catch-up index of {} failed: {}",
                    repo_name, e
                );
            }
        }
    }

    /// Keep a repo's definition map in step with one changed file.
    ///
    /// A no-op for a repo with no map, so an unfiltered repo pays nothing, and
    /// so does a repo whose build has not committed yet. That leaves a window
    /// where an edit to a file the build already passed is not reflected until
    /// the next index; both ways that can go wrong — a row naming a file that
    /// no longer defines the symbol, or a missing row — cost at most one
    /// wrongly-indexed or one un-indexed file, never a wrong answer.
    fn update_definition_map(
        &self,
        repo_path: &Path,
        file: &Path,
        change: &crate::persist::ChangeType,
    ) {
        let Some(store) = &self.index_store else {
            return;
        };
        let rel = file
            .strip_prefix(repo_path)
            .unwrap_or(file)
            .to_string_lossy()
            .to_string();

        let updated = match change {
            crate::persist::ChangeType::Deleted => store.remove_file_definitions(repo_path, &rel),
            _ => match std::fs::read_to_string(file)
                .ok()
                .and_then(|content| self.parser.definition_names(file, &content).ok())
            {
                Some(definitions) => store.update_file_definitions(repo_path, &rel, &definitions),
                None => Ok(()),
            },
        };
        if let Err(e) = updated {
            warn!("definition map: update failed for {:?}: {}", file, e);
        }
    }

    /// Files outside `--index-filter` that the in-scope files reference
    /// directly: the definition site of a callee no in-scope file defines, and
    /// the target of an `#include` no in-scope file provides.
    ///
    /// One hop only — a pulled-in file's own references are not chased, or a
    /// single call chain would drag in the fraction of the repo the filter
    /// exists to keep out. Candidates are accepted only if they are in
    /// `repo_files`, the walker's own pre-filter listing.
    async fn pull_in_referenced_files(
        &self,
        repo_path: &Path,
        repo_files: &std::collections::HashSet<PathBuf>,
        base: &[(PathBuf, String, crate::parser::ParsedFile)],
    ) -> PulledInFiles {
        use std::collections::{BTreeMap, BTreeSet, HashSet};

        let mut candidates: BTreeMap<PathBuf, PullInSource> = BTreeMap::new();

        // Headers. The same header is included by many files, so collect the
        // distinct (including directory, target) pairs and resolve each once.
        let mut includes: BTreeSet<(&Path, String)> = BTreeSet::new();
        for (file, content, _) in base {
            let is_cxx = file
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| is_c_source_ext(ext) || is_c_header_ext(ext));
            let dir = match (is_cxx, file.parent()) {
                (true, Some(dir)) => dir,
                _ => continue,
            };
            for import in parse_imports_from_content(content, &file.to_string_lossy()) {
                if matches!(
                    import.import_type,
                    crate::incremental::ImportType::CppInclude
                ) {
                    includes.insert((dir, import.import_path));
                }
            }
        }
        if !includes.is_empty() {
            let include_dirs = compile_commands_include_dirs(
                repo_path,
                &self.compile_commands_candidate_paths(repo_path),
            );
            let mut by_name: HashMap<&std::ffi::OsStr, Vec<&PathBuf>> = HashMap::new();
            for file in repo_files {
                if let Some(name) = file.file_name() {
                    by_name.entry(name).or_default().push(file);
                }
            }
            for (dir, target) in includes {
                if let Some(resolved) = resolve_include_target(
                    &target,
                    dir,
                    repo_path,
                    &include_dirs,
                    repo_files,
                    &by_name,
                ) {
                    candidates.insert(resolved, PullInSource::Include);
                }
            }
        }

        // Callees no in-scope file defines. gtags and the definition map answer
        // the same question about them, so resolve the names once.
        let unresolved = unresolved_callee_names(base);

        // gtags indexes the whole repo regardless of --index-filter, so it can
        // name the file holding a definition the filter dropped.
        if !unresolved.is_empty() {
            if let Some(gtags) = &self.gtags_manager {
                if self.gtags_repo_enabled(repo_path) {
                    for rel in gtags.find_definition_files(&unresolved, repo_path).await {
                        candidates
                            .entry(repo_path.join(rel))
                            .or_insert(PullInSource::Gtags);
                    }
                }
            }
        }

        // The definition map answers for every language narsil parses and needs
        // no external tool, so for a repo gtags does not index it is the only
        // source. Consulted last, so a file gtags already named keeps its
        // attribution and the reported counts still sum to the total.
        if !unresolved.is_empty() {
            if let Some(store) = &self.index_store {
                if store.definition_stats(repo_path).is_some() {
                    match store.definitions_of(repo_path, &unresolved) {
                        Ok(hits) => {
                            for hit in hits {
                                candidates
                                    .entry(repo_path.join(hit.file))
                                    .or_insert(PullInSource::Store);
                            }
                        }
                        Err(e) => warn!("definition map: lookup failed for {:?}: {}", repo_path, e),
                    }
                }
            }
        }

        let in_base: HashSet<&Path> = base.iter().map(|(file, _, _)| file.as_path()).collect();
        let mut pulled = PulledInFiles::default();
        for (candidate, source) in candidates {
            if in_base.contains(candidate.as_path()) || !repo_files.contains(&candidate) {
                continue;
            }
            match source {
                PullInSource::Include => pulled.from_includes += 1,
                PullInSource::Gtags => pulled.from_gtags += 1,
                PullInSource::Store => pulled.from_store += 1,
            }
            pulled.files.push(candidate);
        }
        pulled
    }

    /// Phases 5/6 (C/C++ call-graph augmentation): after the tree-sitter
    /// baseline graph is built, fold in clangd/ccls `callHierarchy` outgoing
    /// calls and gtags reverse references. The LSP/gtags queries are async and
    /// the dominant indexing cost, so they fan out with bounded concurrency;
    /// `merge_edges` is applied serially afterwards (the call graph is not
    /// shared across tasks). Only existing tree-sitter caller/callee nodes are
    /// touched — edges to functions the baseline never saw are dropped.
    async fn augment_call_graph_cxx(
        &self,
        repo_name: &str,
        repo_path: &Path,
        lsp: &Option<Arc<LspManager>>,
        gtags: &Option<Arc<GtagsManager>>,
    ) {
        // C/C++ function/method definitions from the merged symbols: (name,
        // relative file, 1-based definition line).
        let functions: Vec<(String, String, usize)> = match self.symbols.get(repo_name) {
            Some(symbols) => symbols
                .iter()
                .filter(|sym| {
                    matches!(sym.kind, SymbolKind::Function | SymbolKind::Method)
                        && matches!(get_language_from_path(&sym.file_path).as_str(), "c" | "cpp")
                })
                .map(|sym| (sym.name.clone(), sym.file_path.clone(), sym.start_line))
                .collect(),
            None => return,
        };
        if functions.is_empty() {
            return;
        }

        // Phase 5: one task per (function, backend) querying callHierarchy
        // outgoing calls. Each returns its backend bit and the resolved edges;
        // the graph mutation happens serially below.
        let lsp_phase_start = std::time::Instant::now();
        let mut lsp_edges: Vec<(SourceSet, Vec<(String, CallEdge)>)> = Vec::new();
        // gtags-only repos skip the callHierarchy pass entirely: with the
        // background index off it re-parses every TU cold to resolve callees,
        // which is ruinous on a huge tree. Phase 6 (gtags) below still runs.
        // The same cold-reparse bars clangd/ccls without a compile_commands.json:
        // every call then reparses its TU cold, so the pass costs ~one request
        // timeout per function (136s on a 22-file repo) yet every call times out
        // → zero edges. gtags + tree-sitter still build the graph.
        let lsp = lsp.as_ref().filter(|_| {
            !self.lsp_augment_disabled(repo_name) && self.compile_commands_present(repo_path)
        });
        if let Some(lsp) = lsp {
            let backends = lsp.active_cxx_backends_for(Path::new(repo_name));
            // Same --lsp-scope gate as the documentSymbol pass: skip callHierarchy
            // for functions outside the scoped paths in a scoped repo.
            let repo_scoped = self.lsp_scope_active(repo_name)
                && functions.iter().any(|(_, rel, _)| {
                    self.lsp_scope_matches(repo_name, rel, &repo_path.join(rel).to_string_lossy())
                });
            // Group functions by file so each translation unit is opened once and
            // all its functions are queried against that single open document,
            // rather than reopening (and rebuilding the preamble) per function.
            let mut by_file: std::collections::HashMap<String, Vec<(String, u32)>> =
                std::collections::HashMap::new();
            for (name, rel_path, line) in &functions {
                by_file
                    .entry(rel_path.clone())
                    .or_default()
                    .push((name.clone(), *line as u32));
            }
            if !backends.is_empty() {
                let semaphore = Arc::new(tokio::sync::Semaphore::new(CXX_AUGMENT_CONCURRENCY));
                let mut tasks = tokio::task::JoinSet::new();
                // Files skipped because the wall-clock budget elapsed before
                // they could be queried; reported so the truncation is visible.
                let mut budget_skipped: usize = 0;
                // One task per (file, backend); the semaphore runs files in
                // parallel up to CXX_AUGMENT_CONCURRENCY.
                for (rel_path, file_funcs) in by_file {
                    if !self.lsp_augment_allows(
                        repo_name,
                        repo_scoped,
                        &rel_path,
                        &repo_path.join(&rel_path).to_string_lossy(),
                    ) {
                        continue;
                    }
                    let abs_path = match validate_path(repo_path, &rel_path) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    // Stop launching new files once the phase budget is spent;
                    // in-flight tasks drain below. Granularity is one file, so a
                    // file with many functions may overhang the budget slightly.
                    if lsp_phase_start.elapsed() > CXX_CALLHIERARCHY_BUDGET {
                        budget_skipped += 1;
                        continue;
                    }
                    for backend in &backends {
                        let permit = match semaphore.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => break,
                        };
                        let lsp = lsp.clone();
                        let backend = *backend;
                        let rel_path = rel_path.clone();
                        let abs_path = abs_path.clone();
                        let file_funcs = file_funcs.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            let per_func = lsp
                                .call_hierarchy_outgoing_batch(backend, &abs_path, &file_funcs)
                                .await;
                            // per_func is aligned with file_funcs; map each
                            // function's outgoing calls onto its caller edges.
                            let mut edges: Vec<(String, CallEdge)> = Vec::new();
                            for ((name, _line), calls) in file_funcs.iter().zip(per_func) {
                                let caller_key = CallGraph::qualified_key(&rel_path, name);
                                for (callee_name, _callee_file, call_line) in calls {
                                    edges.push((
                                        caller_key.clone(),
                                        CallEdge {
                                            target: callee_name,
                                            file_path: rel_path.clone(),
                                            line: call_line as usize,
                                            column: 0,
                                            call_type: CallType::Unknown,
                                            scope_hint: None,
                                            confirmed_by: backend,
                                            line_conflicts: Vec::new(),
                                        },
                                    ));
                                }
                            }
                            (backend, edges)
                        });
                    }
                }
                while let Some(joined) = tasks.join_next().await {
                    match joined {
                        Ok((backend, edges)) if !edges.is_empty() => {
                            lsp_edges.push((backend, edges))
                        }
                        Ok(_) => {}
                        Err(e) => warn!("LSP callHierarchy task failed: {}", e),
                    }
                }
                if budget_skipped > 0 {
                    warn!(
                        "callHierarchy (LSP) budget {:?} exceeded for {}: {} file(s) \
                         skipped; tree-sitter/gtags edges retained",
                        CXX_CALLHIERARCHY_BUDGET, repo_name, budget_skipped
                    );
                }
            }
        }
        info!(
            "timing: callHierarchy (LSP) in {:?} for {}",
            lsp_phase_start.elapsed(),
            repo_name
        );

        // Phase 6: one task per function fetching gtags reverse references.
        // `global -rx` returns *uses* (which include address-of and
        // declarations, not only resolved calls), so these edges are weaker —
        // recorded via the GTAGS bit so the consumer can tell them apart.
        let gtags_phase_start = std::time::Instant::now();
        #[allow(clippy::type_complexity)]
        let mut gtags_refs: Vec<(String, Vec<(String, usize, String)>)> = Vec::new();
        if let Some(gtags) = gtags {
            let semaphore = Arc::new(tokio::sync::Semaphore::new(CXX_AUGMENT_CONCURRENCY));
            let mut tasks = tokio::task::JoinSet::new();
            // A prototype and its definition are two symbols with one name;
            // querying both merges every reference twice.
            let mut names: Vec<&String> = functions.iter().map(|(name, _, _)| name).collect();
            names.sort_unstable();
            names.dedup();
            for name in names {
                let permit = match semaphore.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let gtags = gtags.clone();
                let name = name.clone();
                let repo_path = repo_path.to_path_buf();
                tasks.spawn(async move {
                    let _permit = permit;
                    let refs = gtags.find_references(&name, &repo_path).await;
                    (name, refs)
                });
            }
            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok((name, refs)) if !refs.is_empty() => gtags_refs.push((name, refs)),
                    Ok(_) => {}
                    Err(e) => warn!("gtags reference task failed: {}", e),
                }
            }
        }
        info!(
            "timing: gtags references in {:?} for {}",
            gtags_phase_start.elapsed(),
            repo_name
        );

        if lsp_edges.is_empty() && gtags_refs.is_empty() {
            return;
        }

        // Serial merge — the call graph is not shared with the async tasks.
        let call_graph = match self.call_graphs.get(repo_name) {
            Some(cg) => cg,
            None => return,
        };

        for (backend, edges) in lsp_edges {
            call_graph.merge_edges(edges, backend);
        }

        // Map each gtags reference site back to its enclosing function (the
        // caller); the queried function is the callee.
        if !gtags_refs.is_empty() {
            if let Some(symbols) = self.symbols.get(repo_name) {
                // enclosing_function_at scans every symbol; calling it per gtags
                // reference is O(refs × symbols) and dominates indexing on large
                // trees. Group function/method symbols by file once so each
                // reference scans only its own file's functions.
                let mut funcs_by_file: std::collections::HashMap<&str, Vec<&Symbol>> =
                    std::collections::HashMap::new();
                for sym in symbols.value() {
                    if matches!(sym.kind, SymbolKind::Function | SymbolKind::Method) {
                        funcs_by_file
                            .entry(sym.file_path.as_str())
                            .or_default()
                            .push(sym);
                    }
                }
                for (callee_name, refs) in gtags_refs {
                    let edges: Vec<(String, CallEdge)> = refs
                        .into_iter()
                        .filter_map(|(rel_file, line, text)| {
                            // `global -rx` reports uses, not calls: a parameter
                            // of the same name, a declaration, a mention in a
                            // comment. Only a call belongs in the graph.
                            if !is_call_site(&text, &callee_name) {
                                return None;
                            }
                            let caller = funcs_by_file
                                .get(rel_file.as_str())?
                                .iter()
                                .find(|sym| sym.start_line <= line && line <= sym.end_line)?;
                            // A definition is not a call to itself; its
                            // signature line matches the call syntax above.
                            if caller.name == callee_name && caller.start_line == line {
                                return None;
                            }
                            Some((
                                CallGraph::qualified_key(&caller.file_path, &caller.name),
                                CallEdge {
                                    target: callee_name.clone(),
                                    file_path: rel_file,
                                    line,
                                    column: 0,
                                    call_type: CallType::Unknown,
                                    scope_hint: None,
                                    confirmed_by: SourceSet::GTAGS,
                                    line_conflicts: Vec::new(),
                                },
                            ))
                        })
                        .collect();
                    if !edges.is_empty() {
                        call_graph.merge_edges(edges, SourceSet::GTAGS);
                    }
                }
            }
        }
    }

    /// The lease for `repo_key`, created on first use.
    fn index_lease(&self, repo_key: &str) -> IndexLease {
        self.index_leases
            .entry(repo_key.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::RwLock::new(())))
            .clone()
    }

    /// Read lease for a query against `repo_key`, or None when an index update
    /// holds — or is waiting for — the write side. None is the EAGAIN case: the
    /// caller must refuse rather than answer from an index being rebuilt.
    pub async fn try_query_lease(
        &self,
        repo_key: &str,
    ) -> Option<tokio::sync::OwnedRwLockReadGuard<()>> {
        let lease = self.index_lease(repo_key);
        tokio::time::timeout(INDEX_LEASE_GRACE, lease.read_owned())
            .await
            .ok()
    }

    /// Begin an update window covering no repos yet. Waits for in-flight
    /// queries to drain on each repo `add()`ed to it; queries arriving
    /// meanwhile are refused. Grow it with `add()` as repos are discovered —
    /// the watcher takes this at the first change of a debounce batch, before
    /// the batch's final repo set is known.
    pub async fn begin_update_window(&self) -> IndexUpdateLeases {
        let gate = Arc::clone(&self.update_gate).lock_owned().await;
        IndexUpdateLeases {
            _gate: gate,
            leases: HashMap::new(),
        }
    }

    /// Write leases over `repo_keys` for one index update.
    pub async fn index_update_leases(&self, repo_keys: &[String]) -> IndexUpdateLeases {
        let mut leases = self.begin_update_window().await;
        for key in repo_keys {
            leases.add(self, key).await;
        }
        leases
    }

    /// Snapshot of the registered repository paths. A snapshot rather than a
    /// borrow: callers iterate across `.await` points, and holding the lock
    /// there would block a concurrent registration for the whole pass.
    fn registered_repo_paths(&self) -> Vec<PathBuf> {
        self.repo_paths
            .read()
            .iter()
            .map(|repo| repo.path.clone())
            .collect()
    }

    /// Register `path` as a repository the engine answers for. Returns false if
    /// it was already registered.
    fn register_repo_path(&self, path: PathBuf, origin: RepoOrigin) -> bool {
        let mut repos = self.repo_paths.write();
        if repos.iter().any(|repo| repo.path == path) {
            return false;
        }
        repos.push(RegisteredRepo::new(path, origin));
        drop(repos);
        if let Some(watcher) = self.async_file_watcher.lock().upgrade() {
            self.watch_registered_paths(&mut watcher.lock());
        }
        true
    }

    /// Record that a caller just named `repo_key`, so an idle sweep can tell a
    /// repo still in use from one nobody has asked about in days.
    fn mark_repo_used(&self, repo_key: &str) {
        let now = unix_secs();
        let named = Path::new(repo_key);
        for repo in self.repo_paths.read().iter() {
            if repo.path == named {
                repo.last_used.store(now, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Forget every adopted repository nobody has named for `ttl`.
    ///
    /// `resolve_repo` stamps a repo on every mention, so one still in use never
    /// reaches the deadline. Does nothing until the first index pass finishes:
    /// before that a configured repo carries no stamp either.
    pub async fn sweep_idle_repos(&self, ttl: std::time::Duration) {
        if !self.initialization_complete.load(Ordering::Acquire) {
            return;
        }
        let deadline = unix_secs().saturating_sub(ttl.as_secs());
        let idle: Vec<PathBuf> = self
            .repo_paths
            .read()
            .iter()
            .filter(|repo| {
                repo.origin == RepoOrigin::Adopted
                    && repo.last_used.load(Ordering::Relaxed) < deadline
            })
            .map(|repo| repo.path.clone())
            .collect();

        for path in idle {
            let repo = path.to_string_lossy().into_owned();
            info!("Idle sweep: dropping {} after {:?} unused", repo, ttl);
            if let Err(e) = self.forget_repo(&repo).await {
                warn!("Idle sweep: could not drop {}: {}", repo, e);
            }
        }
    }

    /// Canonical keys of every configured repo — what a query naming no repo
    /// reads, since those tools search all of them.
    pub fn all_repo_keys(&self) -> Vec<String> {
        self.registered_repo_paths()
            .iter()
            .filter_map(|path| canonical_repo_key(path).ok())
            .collect()
    }

    /// Canonical keys of the repos a watch batch touches, deduplicated.
    pub fn repos_for_changes(&self, changes: &[crate::persist::FileChange]) -> Vec<String> {
        let repo_paths = self.registered_repo_paths();
        let mut keys: Vec<String> = changes
            .iter()
            .filter_map(|change| {
                repo_paths
                    .iter()
                    .find(|repo| path_is_within_repo(&change.path, repo))
            })
            .filter_map(|repo| canonical_repo_key(repo).ok())
            .collect();
        keys.sort();
        keys.dedup();
        keys
    }

    pub async fn reindex_all(&self) -> Result<()> {
        let _leases = self.index_update_leases(&self.all_repo_keys()).await;
        self.repos.clear();
        self.symbols.clear();
        self.file_cache.clear();
        self.search_index.clear();
        self.embedding_engine.clear();
        // Clear all caches on full reindex
        self.analysis_cache.clear();
        self.query_cache.clear();
        let result = self.index_repos().await;
        self.refresh_memory_snapshot();
        result
    }

    pub async fn reindex(&self, repo: Option<&str>) -> Result<String> {
        match repo {
            Some(name) => {
                let (repo_key, newly_registered) = match self.resolve_repo(name) {
                    Ok(key) => (key, false),
                    // reindex is the documented first move for a repo a query
                    // found nothing in, so a valid repo the server was never
                    // started with has to register here rather than error.
                    Err(unknown) => match self.register_unknown_repo(name) {
                        Some(key) => (key, true),
                        None => return Err(unknown),
                    },
                };
                let path = PathBuf::from(&repo_key);
                // Held across the clears below: without it a query lands
                // between "symbols removed" and "symbols rebuilt" and is
                // answered from an empty index.
                let _leases = self
                    .index_update_leases(std::slice::from_ref(&repo_key))
                    .await;
                let was_indexed = self.repos.remove(&repo_key).is_some();
                self.symbols.remove(&repo_key);
                // Drop this repo's cached contents; index_repo only inserts, so a
                // file the new branch does not have would keep answering
                // find_references and every other file_cache reader. A nested
                // registered repo lives under the same root and keeps its own.
                let nested: Vec<PathBuf> = self
                    .registered_repo_paths()
                    .into_iter()
                    .filter(|p| p != &path && p.starts_with(&path))
                    .collect();
                self.file_cache.retain(|cached, _| {
                    !cached.starts_with(&path) || nested.iter().any(|n| cached.starts_with(n))
                });
                // Reset call graph so stale nodes from a branch switch don't linger.
                // build_from_files only inserts/overwrites — it never removes — so
                // functions deleted on the new branch would otherwise persist.
                if self.options.call_graph_enabled {
                    self.call_graphs.insert(repo_key.clone(), CallGraph::new());
                }
                // Invalidate all caches for this repo so stale analysis results
                // (callers, callees, paths) are not served after the rebuild.
                self.query_cache.invalidate_for_repo(&repo_key);
                self.analysis_cache.invalidate_where(|k| k.repo == repo_key);
                self.index_repo(&path).await?;
                // A configured repo is counted by the startup sweep instead,
                // which may not have reached it yet.
                let adopted = self
                    .repo_paths
                    .read()
                    .iter()
                    .any(|repo| repo.path == path && repo.origin == RepoOrigin::Adopted);
                if adopted && !was_indexed {
                    self.indexed_repos_count.fetch_add(1, Ordering::Release);
                }
                self.refresh_memory_snapshot();
                if newly_registered {
                    Ok(format!("Registered and indexed repository: {}", repo_key))
                } else {
                    Ok(format!("Re-indexed repository: {}", repo_key))
                }
            }
            None => {
                self.reindex_all().await?;
                Ok("Re-indexed all repositories".to_string())
            }
        }
    }

    /// Drop every trace of a repository: its symbols, search documents, call
    /// graph, cached file contents, language servers and persisted store. The
    /// repo stops resolving afterwards, so a query names it in vain until
    /// something registers it again — `reindex` on the same path does.
    ///
    /// Holds the same update leases a rebuild does, so a query sees the repo
    /// whole or reports it unknown, never half-emptied.
    pub async fn forget_repo(&self, repo: &str) -> Result<String> {
        fn decrement(counter: &AtomicUsize) {
            let _ = counter.fetch_update(Ordering::Release, Ordering::Acquire, |count| {
                Some(count.saturating_sub(1))
            });
        }

        let repo_key = self.resolve_repo(repo)?;
        let path = PathBuf::from(&repo_key);
        let leases = self
            .index_update_leases(std::slice::from_ref(&repo_key))
            .await;

        // Stop what could still write to this repo before dropping its data,
        // so nothing refills a map behind the teardown.
        if let Some((_, build)) = self.definition_builds.remove(&repo_key) {
            build.abort();
        }
        if let Some(lsp) = &self.lsp_manager {
            lsp.forget_repo(&path).await;
        }

        self.search_index.drop_repo(&repo_key);
        self.embedding_engine.drop_repo(&repo_key);
        let was_indexed = self.repos.remove(&repo_key).is_some();
        self.symbols.remove(&repo_key);
        self.git_repos.remove(&repo_key);
        self.call_graphs.remove(&repo_key);
        self.index_filtered_repos.remove(&repo_key);
        self.compile_commands_filtered_files.remove(&repo_key);
        self.gitignore_matchers.remove(&path);
        self.gtags_last_refresh.remove(&path);

        // A repo registered underneath this one keeps its own cached contents.
        let nested: Vec<PathBuf> = self
            .registered_repo_paths()
            .into_iter()
            .filter(|other| other != &path && other.starts_with(&path))
            .collect();
        self.file_cache.retain(|cached, _| {
            !cached.starts_with(&path) || nested.iter().any(|n| cached.starts_with(n))
        });

        self.query_cache.invalidate_for_repo(&repo_key);
        self.analysis_cache.invalidate_where(|k| k.repo == repo_key);

        if let Some(store) = &self.index_store {
            if let Err(e) = store.forget(&path) {
                warn!("forget_repo: {}", e);
            }
        }

        // Last: until here a concurrent resolve_repo still finds the repo and
        // blocks on the write lease above; afterwards it reports it unknown.
        // The watcher keeps its descriptor, but process_file_changes drops a
        // change no registered repo encloses.
        self.repo_paths.write().retain(|other| other.path != path);
        decrement(&self.total_repos_count);
        if was_indexed {
            decrement(&self.indexed_repos_count);
        }
        self.refresh_memory_snapshot();

        // After the guard, so a task already holding this lease keeps it alive;
        // one arriving later makes a fresh lease for a repo that no longer
        // resolves anyway.
        drop(leases);
        self.index_leases.remove(&repo_key);

        info!("Forgot repository {}", repo_key);
        Ok(format!("Forgot repository: {}", repo_key))
    }

    /// Register a repo `resolve_repo` did not know, when `name` names a
    /// readable directory that looks like a repository — the same check
    /// `validate_repo` reports on. Returns its canonical key, or None when the
    /// path is not one the engine should adopt, leaving the caller's original
    /// "not found" error intact.
    fn register_unknown_repo(&self, name: &str) -> Option<String> {
        let canonical = PathBuf::from(name).canonicalize().ok()?;
        crate::repo::validate_repo_path(&canonical).ok()?;
        if !crate::repo::is_repository(&canonical) {
            return None;
        }

        let repo_key = canonical_repo_key(&canonical).ok()?;
        if self.register_repo_path(canonical, RepoOrigin::Adopted) {
            info!("reindex: registered new repository {}", repo_key);
            // forget_repo takes it off again, for adopted and configured alike.
            self.total_repos_count.fetch_add(1, Ordering::Release);
        }
        Some(repo_key)
    }

    /// Returns true if any directory from `target` up to (but excluding)
    /// `root` has its own `.git` entry.
    ///
    /// A `.git` there means `target` sits inside a distinct git checkout —
    /// e.g. a linked worktree or a nested clone — rather than a plain
    /// subdirectory of `root`; resolving it to `root`'s index would silently
    /// answer from the wrong checkout's files.
    fn crosses_git_boundary(root: &Path, target: &Path) -> bool {
        let mut current = target;
        while current != root {
            if current.join(".git").exists() {
                return true;
            }
            match current.parent() {
                Some(parent) => current = parent,
                None => break,
            }
        }
        false
    }

    /// Whether `candidate` is `root` itself, or a subdirectory of it that
    /// doesn't cross a nested git checkout boundary (see
    /// [`crosses_git_boundary`](Self::crosses_git_boundary)). Both arguments
    /// must already be canonicalized.
    fn path_matches_repo_root(root: &Path, candidate: &Path) -> bool {
        candidate == root
            || (candidate.starts_with(root) && !Self::crosses_git_boundary(root, candidate))
    }

    /// Resolve a user-supplied repo argument to the canonical absolute path of
    /// an indexed repository.
    ///
    /// Accepts `"."`, a relative path, or an absolute path. The input is
    /// canonicalized (resolving `..`, symlinks, and the current directory) and
    /// then matched against indexed repositories: an exact match returns the
    /// repo root, and any subdirectory of an indexed repo also resolves to
    /// that repo's root (so `"."` from inside a repo subdirectory works).
    ///
    /// A bare short name (e.g. `"linux.git"`) matches an indexed repo's
    /// directory name, with or without the trailing `.git`; when several repos
    /// share that name the caller is asked for a path instead.
    ///
    /// The returned string is the canonical absolute path as stored in the
    /// engine's repository maps — use it directly as the lookup key.
    pub(crate) fn resolve_repo(&self, input: &str) -> Result<String> {
        let key = self.repo_key_for(input)?;
        // Stamped here rather than per tool: this is the one funnel a caller
        // passes through to name a repo, whatever it goes on to ask for.
        self.mark_repo_used(&key);
        Ok(key)
    }

    /// The canonical key `input` names, without recording the use.
    fn repo_key_for(&self, input: &str) -> Result<String> {
        if input.is_empty() {
            // With a single indexed repo there is nothing to disambiguate, so
            // naming it adds nothing the engine doesn't already know.
            if let [only] = self.indexed_repo_paths().as_slice() {
                return Ok(only.to_string_lossy().into_owned());
            }
            return Err(self.repo_not_found_error(input));
        }

        // A bare short name is not a path, so match it against the indexed
        // repos' directory names instead.
        let looks_like_path = input == "." || input.contains('/') || input.contains('\\');
        if !looks_like_path {
            return self.resolve_repo_by_name(input);
        }

        // Resolve the input to an absolute canonical path on disk.
        let as_path = if input == "." {
            std::env::current_dir().context("Failed to read current directory")?
        } else {
            PathBuf::from(input)
        };
        let canonical_input = as_path
            .canonicalize()
            .with_context(|| format!("Failed to canonicalize repo path '{}'", input))?;

        // Match against indexed repos: exact, or a subdirectory of one.
        for entry in self.repos.iter() {
            let stored = &entry.value().path;
            let stored_canonical = match stored.canonicalize() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if Self::path_matches_repo_root(&stored_canonical, &canonical_input) {
                return Ok(stored_canonical.to_string_lossy().into_owned());
            }
        }

        // Fall back to the configured repo paths (set synchronously at
        // construction) for a repo that hasn't reached the front of
        // complete_initialization()'s indexing loop yet — self.repos above is
        // only populated once that repo's (potentially slow) index_repo() call
        // finishes. Without this, a request landing during startup gets a
        // misleading "repo not found" for a repo that IS configured.
        for repo_path in &self.registered_repo_paths() {
            let stored_canonical = match repo_path.canonicalize() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if Self::path_matches_repo_root(&stored_canonical, &canonical_input) {
                return Ok(stored_canonical.to_string_lossy().into_owned());
            }
        }

        Err(self.repo_not_found_error(input))
    }

    /// Canonical paths of every repository the engine answers for: the indexed
    /// set plus the configured repos whose first index pass hasn't run yet.
    fn indexed_repo_paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = self
            .repos
            .iter()
            .map(|entry| entry.value().path.clone())
            .chain(self.registered_repo_paths())
            .filter_map(|path| path.canonicalize().ok())
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }

    /// Resolve a bare name (`libfuse`, `linux.git`) against the indexed repos'
    /// directory names, matching with or without a trailing `.git`. Only an
    /// unambiguous match resolves — a shared basename is precisely what passing
    /// a path settles.
    fn resolve_repo_by_name(&self, name: &str) -> Result<String> {
        let matches: Vec<String> = self
            .indexed_repo_paths()
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|base| base.to_str())
                    .is_some_and(|base| base == name || base.trim_end_matches(".git") == name)
            })
            .map(|path| path.to_string_lossy().into_owned())
            .collect();

        match matches.as_slice() {
            [only] => Ok(only.clone()),
            [] => Err(self.repo_not_found_error(name)),
            several => Err(anyhow!(
                "Repository name '{}' matches {} indexed repositories: {}. \
                 Pass the path of the one you mean.",
                name,
                several.len(),
                several.join(", ")
            )),
        }
    }

    /// Get a reference to the engine options
    pub fn options(&self) -> &EngineOptions {
        &self.options
    }

    /// Get cache statistics for metrics reporting
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        self.analysis_cache.stats()
    }

    /// Get query cache statistics for metrics reporting
    #[must_use]
    pub fn query_cache_stats(&self) -> QueryCacheStats {
        self.query_cache.stats()
    }

    /// Check if analysis caching is enabled
    #[must_use]
    pub fn is_cache_enabled(&self) -> bool {
        self.options.cache_enabled
    }

    /// Compute a hash of the repository's file modification times for cache invalidation.
    /// This hash changes when any file in the repo is modified, added, or deleted.
    ///
    /// `repo_key` must be the canonical absolute path string returned by
    /// `resolve_repo`.
    fn compute_repo_hash(&self, repo_key: &str) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        let repo_path = PathBuf::from(repo_key);

        // Collect all file mtimes from this repo
        let mut file_info: Vec<(PathBuf, SystemTime)> = self
            .file_cache
            .iter()
            .filter(|entry| entry.key().starts_with(&repo_path))
            .filter_map(|entry| {
                let path = entry.key().clone();
                std::fs::metadata(&path)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .map(|mtime| (path, mtime))
            })
            .collect();

        // Sort for deterministic ordering
        file_info.sort_by(|a, b| a.0.cmp(&b.0));

        for (path, mtime) in file_info {
            hasher.update(path.to_string_lossy().as_bytes());
            if let Ok(duration) = mtime.duration_since(std::time::UNIX_EPOCH) {
                hasher.update(duration.as_secs().to_le_bytes());
            }
        }

        format!("{:x}", hasher.finalize())
    }

    /// Clear cache entries for a specific repository (e.g., after reindexing)
    pub fn invalidate_cache_for_repo(&self, repo_name: &str) {
        let repo_prefix = repo_name.to_string();
        self.analysis_cache
            .invalidate_where(|key| key.repo == repo_prefix);
    }

    /// Registered repos whose first index pass has not finished: queued at
    /// startup, or adopted and still indexing. Canonical keys.
    fn repos_being_indexed(&self) -> Vec<String> {
        self.registered_repo_paths()
            .iter()
            .filter_map(|path| canonical_repo_key(path).ok())
            .filter(|key| !self.repos.contains_key(key))
            .collect()
    }

    /// "Come back later" for a repo that is registered but not indexed yet, so
    /// a client retries instead of calling it unknown and reindexing it.
    fn first_pass_busy(&self, repo_key: &str) -> Option<IndexBusy> {
        if !self.repos_being_indexed().iter().any(|key| key == repo_key) {
            return None;
        }
        let (indexed_repos, total_repos) = self.indexing_progress();
        Some(IndexBusy {
            repo: repo_key.to_string(),
            indexed_repos,
            total_repos,
            first_pass: true,
        })
    }

    /// Helper to create a helpful error message for missing/invalid repo parameter
    fn repo_not_found_error(&self, repo: &str) -> anyhow::Error {
        if let Some(busy) = self.first_pass_busy(repo) {
            return busy.into();
        }
        if repo.is_empty() {
            let repo_names: Vec<_> = self.repos.iter().map(|r| r.key().clone()).collect();
            if repo_names.is_empty() {
                anyhow!(
                    "Missing required 'repo' parameter. No repositories are indexed yet. \
                     Use --repos flag when starting the server."
                )
            } else {
                anyhow!(
                    "Missing required 'repo' parameter. Available repositories: {}. \
                     Use list_repos to see all indexed repositories.",
                    repo_names.join(", ")
                )
            }
        } else {
            let repo_names: Vec<_> = self.repos.iter().map(|r| r.key().clone()).collect();
            if repo_names.is_empty() {
                anyhow!(
                    "Repository '{}' not found. No repositories are indexed yet. \
                     Use --repos flag when starting the server.",
                    repo
                )
            } else {
                anyhow!(
                    "Repository '{}' not found. Available repositories: {}. \
                     Use list_repos to see all indexed repositories.",
                    repo,
                    repo_names.join(", ")
                )
            }
        }
    }

    pub async fn list_repos(&self) -> Result<String> {
        // Back-compat: the bare form keeps the full per-language detail for all repos.
        self.list_repos_scoped(None, true).await
    }

    /// List indexed repositories, optionally scoped to one and/or with the
    /// per-language breakdown.
    ///
    /// @param[in] repo    Show only this repo (resolved like any `repo` arg); all if None.
    /// @param[in] detail  Emit the per-language file/line table; compact summary if false.
    pub async fn list_repos_scoped(&self, repo: Option<&str>, detail: bool) -> Result<String> {
        let only: Option<String> = match repo {
            Some(r) => Some(self.resolve_repo(r)?),
            None => None,
        };
        if let Some(busy) = only.as_deref().and_then(|key| self.first_pass_busy(key)) {
            return Err(busy.into());
        }

        let mut output = String::new();
        output.push_str("# Indexed Repositories\n\n");
        output.push_str(
            "Pass the **Repo** value below as the `repo` argument to any tool.\n\
             It is the canonical absolute path of the repository on disk; \
             relative paths and `.` (current directory) are also accepted.\n\n",
        );

        let mut shown = 0usize;
        for entry in self.repos.iter() {
            if only.as_deref().is_some_and(|key| entry.key() != key) {
                continue;
            }
            let repo = entry.value();
            // The map key is the canonical absolute path string; the basename
            // is shown as a friendly label only.
            output.push_str(&format!("## {}\n", repo.name));
            output.push_str(&format!("- **Repo**: `{}`\n", entry.key()));

            if detail {
                output.push_str(&format!("- **Files**: {}\n", repo.file_count));
                output.push_str(&format!("- **Total Lines**: {}\n", repo.total_lines));
                output.push_str("- **Languages**:\n");

                let mut langs: Vec<_> = repo.languages.iter().collect();
                langs.sort_by_key(|(_, stats)| std::cmp::Reverse(stats.line_count));

                for (lang, stats) in langs {
                    output.push_str(&format!(
                        "  - {}: {} files, {} lines\n",
                        lang, stats.file_count, stats.line_count
                    ));
                }
            } else {
                // Compact default: one summary line, no per-language table.
                output.push_str(&format!(
                    "- **Files**: {}, **Lines**: {} (pass `detail=true` for languages)\n",
                    repo.file_count, repo.total_lines
                ));
            }
            output.push('\n');
            shown += 1;
        }

        if self.repos.is_empty() {
            output.push_str("*No repositories indexed yet.*\n");
        } else if shown == 0 {
            output.push_str("*No matching repository.*\n");
        }

        if only.is_none() {
            let being_indexed = self.repos_being_indexed();
            if !being_indexed.is_empty() {
                output.push_str("\n# Being Indexed — retry later\n\n");
                for key in being_indexed {
                    output.push_str(&format!("- `{}`\n", key));
                }
            }
        }

        Ok(output)
    }

    /// Per-repo `(repo_key, symbol_count, file_count)` for every indexed repo.
    /// Repos still indexing have no symbol entry yet and report zero.
    pub fn repo_status_snapshot(&self) -> Vec<(String, usize, usize)> {
        self.repos
            .iter()
            .map(|entry| {
                let key = entry.key().clone();
                let symbol_count = self.symbols.get(&key).map(|s| s.len()).unwrap_or(0);
                (key, symbol_count, entry.value().file_count)
            })
            .collect()
    }

    pub async fn get_project_structure(
        &self,
        repo: &str,
        max_depth: usize,
        max_entries_per_dir: usize,
        max_total_entries: usize,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let path = PathBuf::from(&repo_key);
        let mut output = String::new();
        output.push_str(&format!("# Project Structure: {}\n\n```\n", repo_key));

        let mut budget = TreeBudget {
            max_depth,
            max_entries_per_dir,
            max_total: max_total_entries,
            emitted: 0,
        };
        self.build_tree(&path, 0, &mut budget, &mut output)?;

        output.push_str("```\n");
        if budget.exhausted() {
            output.push_str(&format!(
                "\n*Tree truncated at {} entries. Raise `max_total_entries` / \
                 `max_entries_per_dir`, or lower `max_depth` for a wider overview.*\n",
                max_total_entries
            ));
        }
        Ok(output)
    }

    fn build_tree(
        &self,
        current: &Path,
        depth: usize,
        budget: &mut TreeBudget,
        output: &mut String,
    ) -> Result<()> {
        if depth > budget.max_depth || budget.exhausted() {
            return Ok(());
        }

        let indent = "  ".repeat(depth);
        let name = current.file_name().and_then(|n| n.to_str()).unwrap_or(".");

        if current.is_dir() {
            // Skip hidden and common non-essential directories (but not at root level,
            // since the repo itself might be in a hidden directory like ~/.dotfiles)
            if depth > 0
                && (name.starts_with('.')
                    || name == "node_modules"
                    || name == "target"
                    || name == "__pycache__"
                    || name == "venv")
            {
                return Ok(());
            }

            output.push_str(&format!("{}{} {}/\n", indent, "\u{1f4c1}", name));
            budget.emitted += 1;

            let mut entries: Vec<_> = std::fs::read_dir(current)?.filter_map(|e| e.ok()).collect();
            entries.sort_by_key(|e| (!e.path().is_dir(), e.file_name()));

            let shown = if budget.max_entries_per_dir == 0 {
                entries.len()
            } else {
                entries.len().min(budget.max_entries_per_dir)
            };

            for entry in entries.iter().take(shown) {
                self.build_tree(&entry.path(), depth + 1, budget, output)?;
                if budget.exhausted() {
                    break;
                }
            }

            if shown < entries.len() {
                output.push_str(&format!(
                    "{}  … (+{} more entries)\n",
                    indent,
                    entries.len() - shown
                ));
            }
        } else {
            let size = std::fs::metadata(current).map(|m| m.len()).unwrap_or(0);
            let size_str = format_size(size);
            let icon = get_file_icon(name);
            output.push_str(&format!("{}{} {} ({})\n", indent, icon, name, size_str));
            budget.emitted += 1;
        }

        Ok(())
    }

    pub async fn find_symbols(
        &self,
        repo: &str,
        symbol_type: Option<&str>,
        pattern: Option<&str>,
        file_pattern: Option<&str>,
        exclude_tests: Option<bool>,
        limit: usize,
    ) -> Result<String> {
        use crate::extract::is_test_file;

        let repo = self.resolve_repo(repo)?;

        // A missing name filter must not silently dump every symbol in the repo: a
        // misnamed argument (e.g. `query=` before it was aliased, or a typo) lands here
        // with no filter and would return the first `limit` symbols of the whole repo.
        // Refuse with guidance; an explicit `pattern="*"` is the way to list everything.
        if pattern.is_none() && file_pattern.is_none() && symbol_type.is_none() {
            return Ok(format!(
                "# Symbols in {}\n\nNo `pattern` (or `query`) given — refusing to list \
                 every symbol.\nPass a name pattern, e.g. `pattern=\"next_mount_opt\"` or \
                 `pattern=\"fuse_*\"`; use `pattern=\"*\"` to list all.\n",
                repo
            ));
        }

        // Build cache key from query parameters
        let cache_key = {
            let options = SearchOptions {
                file_pattern: file_pattern.map(String::from),
                max_results: Some(limit),
                exclude_tests,
                mode: None,
            };
            let query = format!(
                "{}|{}",
                pattern.unwrap_or("*"),
                symbol_type.unwrap_or("all")
            );
            QueryCacheKey::code_search_with_options(Some(repo.as_str()), query, &options)
        };

        // Check cache first
        if self.options.cache_enabled {
            if let Some(cached) = self.query_cache.get(&cache_key) {
                return Ok(cached);
            }
        }

        let symbols = self
            .symbols
            .get(&repo)
            .ok_or_else(|| self.repo_not_found_error(&repo))?;

        let exclude_tests = exclude_tests.unwrap_or(false);

        let type_filter: Option<SymbolKind> = symbol_type.and_then(|t| match t {
            "struct" => Some(SymbolKind::Struct),
            "class" => Some(SymbolKind::Class),
            "enum" => Some(SymbolKind::Enum),
            "interface" => Some(SymbolKind::Interface),
            "function" => Some(SymbolKind::Function),
            "method" => Some(SymbolKind::Method),
            "trait" => Some(SymbolKind::Trait),
            "type" => Some(SymbolKind::TypeAlias),
            _ => None,
        });

        // Compile name pattern: glob when wildcards present, substring otherwise.
        let name_glob: Option<glob::Pattern> = pattern
            .filter(|p| p.contains('*') || p.contains('?'))
            .and_then(|p| glob::Pattern::new(p).ok());
        let glob_opts = glob::MatchOptions {
            case_sensitive: false,
            require_literal_separator: false,
            require_literal_leading_dot: false,
        };

        let file_glob = file_pattern.and_then(|p| glob::Pattern::new(p).ok());

        let mut filtered: Vec<_> = symbols
            .iter()
            .filter(|s| {
                if exclude_tests && is_test_file(&s.file_path) {
                    return false;
                }
                if let Some(ref kind) = type_filter {
                    if &s.kind != kind {
                        return false;
                    }
                }
                // Glob match when wildcards present, substring match otherwise.
                if let Some(ref glob) = name_glob {
                    if !glob.matches_with(&s.name, glob_opts) {
                        return false;
                    }
                } else if let Some(pat) = pattern {
                    if !s.name.to_lowercase().contains(&pat.to_lowercase()) {
                        return false;
                    }
                }
                if let Some(ref glob) = file_glob {
                    if !glob.matches(&s.file_path) {
                        return false;
                    }
                }
                true
            })
            .collect();

        // Surface the most relevant matches within `limit`: exact name (case-insensitive)
        // first, then prefix, then substring/other. Stable sort keeps insertion order on
        // ties, so a specific pattern lands its intended symbol at the top of the window.
        if let Some(pat) = pattern {
            let pat_lc = pat.to_lowercase();
            filtered.sort_by_key(|s| {
                let name_lc = s.name.to_lowercase();
                if name_lc == pat_lc {
                    0u8
                } else if name_lc.starts_with(&pat_lc) {
                    1
                } else {
                    2
                }
            });
        }

        let total = filtered.len();

        // A file_pattern that matched nothing is indistinguishable from "this
        // file has no symbols" unless the compile_commands filter is the
        // actual reason -- name it instead of a bare zero.
        let filter_note = if total == 0 {
            self.compile_commands_filter_note(&repo, file_glob.as_ref())
        } else {
            String::new()
        };

        // Collect dependent files for smart invalidation (from displayed results only).
        let dependent_files: Vec<String> = filtered
            .iter()
            .take(limit)
            .map(|s| s.file_path.clone())
            .collect();

        let mut output = String::new();
        output.push_str(&format!("# Symbols in {}\n\n", repo));
        if total > limit {
            output.push_str(&format!(
                "Found {} symbols (showing first {}; increase `limit` to see more)\n\n",
                total, limit
            ));
        } else {
            output.push_str(&format!("Found {} symbols\n\n", total));
        }
        if !filter_note.is_empty() {
            output.push_str(&filter_note);
        }

        // Group displayed results by kind.
        let mut by_kind: HashMap<SymbolKind, Vec<&Symbol>> = HashMap::new();
        for symbol in filtered.iter().copied().take(limit) {
            by_kind.entry(symbol.kind.clone()).or_default().push(symbol);
        }

        let repo_path = PathBuf::from(&repo);
        for (kind, syms) in by_kind {
            output.push_str(&format!("## {:?}s\n\n", kind));
            for sym in syms {
                let is_cxx = matches!(get_language_from_path(&sym.file_path).as_str(), "c" | "cpp");
                let provenance = render_provenance(
                    ProvenanceSubject::Symbol,
                    self.enabled_backends_for_repo(&repo_path, is_cxx),
                    sym.confirmed_by,
                    sym.start_line,
                    &sym.line_conflicts,
                )
                .map(|annotation| format!(" _({})_", annotation))
                .unwrap_or_default();
                output.push_str(&format!(
                    "- **{}** (`{}:{}`) {}{}\n",
                    sym.name,
                    sym.file_path,
                    sym.start_line,
                    sym.signature.as_deref().unwrap_or(""),
                    provenance
                ));
            }
            output.push('\n');
        }

        // A git submodule is indexed as its own repo, not merged into this one
        // (a nested checkout crosses the git boundary), so a submodule-defined
        // symbol can surface only its header declaration here while the .c
        // definition is absent. Point the caller at the submodule to index.
        let submodules = submodule_paths(&repo_path);
        if !submodules.is_empty() {
            output.push_str(&format!(
                "\n> Note: this repo has git submodule(s): {}. Their sources are indexed \
                 separately — if a definition looks missing, index the submodule with \
                 `reindex(repo=\"{}/{}\")`.\n",
                submodules.join(", "),
                repo,
                submodules[0]
            ));
        }

        // Cache the result with file dependencies for smart invalidation.
        if self.options.cache_enabled {
            self.query_cache
                .insert_with_files(cache_key, output.clone(), dependent_files);
        }

        Ok(output)
    }

    /// Render a definition located via gtags when the AST symbol table missed it
    /// (e.g. a file-local static the C parser dropped). gtags yields only the start
    /// line, not an AST end line, so a bounded window after it is shown and the
    /// provenance is flagged as approximate.
    fn render_gtags_definition(
        &self,
        repo_path: &Path,
        symbol_name: &str,
        rel_file: &str,
        start_line: usize,
        context_lines: usize,
    ) -> Result<String> {
        // Number of body lines shown after the definition site, since gtags gives no
        // end line; enough to reveal a typical signature and the start of the body.
        const GTAGS_DEF_WINDOW: usize = 40;

        let file_path = validate_path(repo_path, rel_file)?;
        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;
        let lines: Vec<&str> = content.lines().collect();
        // end is bounded by the file; clamp start so a line number past EOF
        // yields an empty window instead of a slice-index panic.
        let end = (start_line + GTAGS_DEF_WINDOW).min(lines.len());
        let start = start_line.saturating_sub(context_lines + 1).min(end);

        let mut output = String::new();
        output.push_str(&format!("# {}\n\n", symbol_name));
        output.push_str(&format!("**File**: `{}`\n", rel_file));
        output.push_str(&format!("**Line**: {}\n", start_line));
        output.push_str(
            "**Provenance**: located via gtags (GNU Global); the AST symbol table \
             missed it, so the shown body window is approximate\n\n",
        );
        output.push_str("```");
        output.push_str(get_language_id(rel_file));
        output.push('\n');
        for (offset, line) in lines[start..end].iter().enumerate() {
            let line_num = start + offset + 1;
            let marker = if line_num == start_line { "→" } else { " " };
            output.push_str(&format!("{} {:4} │ {}\n", marker, line_num, line));
        }
        output.push_str("```\n");
        Ok(output)
    }

    /// Render a symbol located by a live workspace/symbol query. Mirrors
    /// `render_gtags_definition`: the LSP response gives only a point (the
    /// name token), not an AST end line, so a bounded window after it is
    /// shown and the provenance is flagged as approximate.
    fn render_lsp_definition(
        &self,
        repo_path: &Path,
        symbol: &Symbol,
        backend: SourceSet,
        context_lines: usize,
    ) -> Result<String> {
        const LSP_DEF_WINDOW: usize = 40;

        let file_path = validate_path(repo_path, &symbol.file_path)?;
        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;
        let lines: Vec<&str> = content.lines().collect();
        let end = (symbol.start_line + LSP_DEF_WINDOW).min(lines.len());
        let start = symbol.start_line.saturating_sub(context_lines + 1).min(end);

        let mut output = String::new();
        output.push_str(&format!("# {}\n\n", symbol.name));
        output.push_str(&format!("**File**: `{}`\n", symbol.file_path));
        output.push_str(&format!("**Line**: {}\n", symbol.start_line));
        output.push_str(&format!(
            "**Provenance**: located via a live {} workspace/symbol query; the AST \
             symbol table and gtags both missed it, so the shown body window is \
             approximate\n\n",
            backend.labels().join("/"),
        ));
        output.push_str("```");
        output.push_str(get_language_id(&symbol.file_path));
        output.push('\n');
        for (offset, line) in lines[start..end].iter().enumerate() {
            let line_num = start + offset + 1;
            let marker = if line_num == symbol.start_line { "→" } else { " " };
            output.push_str(&format!("{} {:4} │ {}\n", marker, line_num, line));
        }
        output.push_str("```\n");
        Ok(output)
    }

    pub async fn get_symbol_definition(
        &self,
        repo: &str,
        symbol_name: &str,
        context_lines: usize,
    ) -> Result<String> {
        let repo = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo);
        let symbols = self
            .symbols
            .get(&repo)
            .ok_or_else(|| self.repo_not_found_error(&repo))?;

        // Find matching symbol. Prefer a real definition over a forward-decl or
        // prototype (the C backend emits those as their own entries): a body
        // makes the definition span strictly more lines. An `impl` block is not
        // the definition of the type it names, so rank it below everything else
        // (it can span more lines than the struct it implements). reduce() keeps
        // the first match on ties and yields None when nothing matches,
        // preserving the gtags fallback below.
        let definition_rank = |s: &Symbol| {
            (
                !matches!(s.kind, SymbolKind::Implementation),
                s.line_count(),
            )
        };
        // qualified_name is rarely populated by the extractors, so a caller-supplied
        // "Type::method" or "Type.method" (the natural way to name an inherent-impl
        // or Python method) would otherwise never match anything but the bare
        // method name itself.
        let method_tail = match symbol_name.contains("::") {
            true => symbol_name.rsplit("::").next().unwrap_or(symbol_name),
            false => symbol_name.rsplit('.').next().unwrap_or(symbol_name),
        };
        let matches: Vec<&Symbol> = symbols
            .iter()
            .filter(|s| {
                s.name == symbol_name
                    || s.qualified_name.as_deref() == Some(symbol_name)
                    || (method_tail != symbol_name && s.name == method_tail)
            })
            .collect();
        let symbol = match matches.iter().copied().reduce(|best, s| {
            if definition_rank(s) > definition_rank(best) {
                s
            } else {
                best
            }
        }) {
            Some(s) => s,
            None => {
                // AST miss (e.g. a file-local static the C parser dropped): consult
                // gtags, which indexes definitions independently of the AST pass.
                if self.gtags_repo_enabled(&repo_path) {
                    if let Some(gtags) = &self.gtags_manager {
                        if let Some((file, line, _)) = gtags
                            .find_definitions(symbol_name, &repo_path)
                            .await
                            .into_iter()
                            .next()
                        {
                            return self.render_gtags_definition(
                                &repo_path,
                                symbol_name,
                                &file,
                                line,
                                context_lines,
                            );
                        }
                    }
                }
                // Still nothing: gtags is a text-based tag scan and misses some
                // declaration forms entirely (e.g. GNU Global's own parser never
                // tags a file-scope variable definition). clangd/ccls parse the
                // real AST, so a live workspace/symbol query against every active
                // backend can still resolve a name neither of the above did.
                if self.lsp_repo_enabled(&repo_path) && !self.lsp_augment_disabled(&repo) {
                    if let Some(lsp) = &self.lsp_manager {
                        for backend in lsp.active_cxx_backends_for(&repo_path) {
                            for language in ["c", "cpp"] {
                                match lsp
                                    .get_workspace_symbols(backend, &repo_path, language, symbol_name)
                                    .await
                                {
                                    Ok(hits) => {
                                        if let Some(hit) = hits.into_iter().next() {
                                            return self.render_lsp_definition(
                                                &repo_path,
                                                &hit,
                                                backend,
                                                context_lines,
                                            );
                                        }
                                    }
                                    Err(e) => debug!(
                                        "workspace/symbol failed for {:?} ({language}): {}",
                                        repo_path, e
                                    ),
                                }
                            }
                        }
                    }
                }
                // Still nothing: offer near-miss candidates rather than a bare error,
                // so the caller can re-query instead of falling back to grep.
                let mut hints: Vec<&str> = symbols
                    .iter()
                    .filter(|s| s.name.to_lowercase().contains(&symbol_name.to_lowercase()))
                    .map(|s| s.name.as_str())
                    .collect();
                hints.sort_unstable();
                hints.dedup();
                hints.truncate(10);
                return Err(anyhow!(
                    "Symbol '{}' not found in repository '{}'.{}",
                    symbol_name,
                    repo,
                    if hints.is_empty() {
                        String::new()
                    } else {
                        format!(" Did you mean: {}", hints.join(", "))
                    }
                ));
            }
        };

        let file_path = validate_path(&repo_path, &symbol.file_path)?;
        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let lines: Vec<&str> = content.lines().collect();
        // end is bounded by the file; clamp start so a stale line number past
        // EOF yields an empty window instead of a slice-index panic.
        let end = (symbol.end_line + context_lines).min(lines.len());
        let start = symbol.start_line.saturating_sub(context_lines + 1).min(end);

        let mut output = String::new();
        output.push_str(&format!("# {}\n\n", symbol.name));
        output.push_str(&symbol_definition_ambiguity_note(&matches, symbol));
        output.push_str(&format!("**File**: `{}`\n", symbol.file_path));
        output.push_str(&format!(
            "**Lines**: {}-{}\n",
            symbol.start_line, symbol.end_line
        ));
        output.push_str(&format!("**Kind**: {:?}\n\n", symbol.kind));
        let is_cxx = matches!(
            get_language_from_path(&symbol.file_path).as_str(),
            "c" | "cpp"
        );
        if let Some(provenance) = render_provenance(
            ProvenanceSubject::Symbol,
            self.enabled_backends_for_repo(&repo_path, is_cxx),
            symbol.confirmed_by,
            symbol.start_line,
            &symbol.line_conflicts,
        ) {
            output.push_str(&format!("**Provenance**: {}\n\n", provenance));
        }

        output.push_str("```");
        output.push_str(get_language_id(&symbol.file_path));
        output.push('\n');

        // Try to get LSP hover info for enhanced information
        if let Some(ref lsp) = self.lsp_manager {
            let language = get_language_from_path(&symbol.file_path);
            if let Ok(Some(hover)) = lsp
                .get_hover(&language, &file_path, symbol.start_line as u32, 0)
                .await
            {
                output.push_str("\n## Type Information (LSP enhanced)\n\n");
                output.push_str(&crate::lsp::hover_to_markdown(&hover));
                output.push('\n');
            }
        }
        for (i, line) in lines[start..end].iter().enumerate() {
            let line_num = start + i + 1;
            let marker = if line_num >= symbol.start_line && line_num <= symbol.end_line {
                "→"
            } else {
                " "
            };
            output.push_str(&format!("{} {:4} │ {}\n", marker, line_num, line));
        }

        output.push_str("```\n");

        Ok(output)
    }

    pub async fn search_code(
        &self,
        repo: Option<&str>,
        query: &str,
        file_pattern: Option<&str>,
        max_results: usize,
        exclude_tests: Option<bool>,
        mode: Option<&str>,
    ) -> Result<String> {
        use crate::extract::is_test_file;

        // A pattern the regex crate rejects has to say so: silently matching
        // nothing reads as "the code is not there".
        let pattern = match mode {
            Some("regex") => Some(regex::Regex::new(query).map_err(|e| {
                anyhow!(
                    "Invalid regex `{}` for search_code(mode=\"regex\"): {}",
                    query,
                    e
                )
            })?),
            Some("text") | None => None,
            Some(other) => {
                return Err(anyhow!(
                    "search_code does not know mode `{}`. Accepted modes: text (default), regex.",
                    other
                ))
            }
        };

        // Build cache key from query parameters
        let cache_key = {
            let options = SearchOptions {
                file_pattern: file_pattern.map(String::from),
                max_results: Some(max_results),
                exclude_tests,
                mode: mode.map(String::from),
            };
            QueryCacheKey::code_search_with_options(repo, query, &options)
        };

        // Check cache first
        if self.options.cache_enabled {
            if let Some(cached) = self.query_cache.get(&cache_key) {
                return Ok(cached);
            }
        }

        let query_lower = query.to_lowercase();
        // Whitespace-split tokens let a multi-word query match a line (or, as a
        // fallback, a file) that contains every term without the terms being
        // adjacent — otherwise `line.contains(query)` treats "struct foo" as an
        // exact phrase and misses the far more common non-adjacent case.
        let tokens: Vec<String> = query_lower.split_whitespace().map(String::from).collect();
        let multi_token = tokens.len() > 1;
        let exclude_tests = exclude_tests.unwrap_or(false); // Default false for search
                                                            // Each hit is paired with its owning repo root so cross-repo searches
                                                            // can name where the hit lives.
        let mut results: Vec<(String, CodeExcerpt)> = Vec::new();

        let repos_to_search: Vec<String> = match repo {
            Some(r) => vec![self.resolve_repo(r)?],
            None => self.repos.iter().map(|r| r.key().clone()).collect(),
        };
        // Only name the owning repo per hit when the search spanned more than
        // one repo; a single-repo search already knows where its hits live.
        let multi_repo = repos_to_search.len() > 1;

        let glob = file_pattern.and_then(|p| glob::Pattern::new(p).ok());

        // Shared per-file gate: repo membership, test exclusion, file pattern.
        // Returns the repo-relative path when the file is in scope.
        let file_in_scope = |file_path: &Path, repo_path: &Path| -> Option<String> {
            if !file_path.starts_with(repo_path) {
                return None;
            }
            let rel_path = file_path
                .strip_prefix(repo_path)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();
            if exclude_tests && is_test_file(&rel_path) {
                return None;
            }
            if let Some(ref g) = glob {
                if !g.matches(&rel_path) {
                    return None;
                }
            }
            Some(rel_path)
        };

        // Build a context excerpt centred on the 0-based line index `center`.
        let make_excerpt =
            |lines: &[&str], center: usize, rel_path: &str, score: f32| -> CodeExcerpt {
                let start = center.saturating_sub(3);
                let end = (center + 4).min(lines.len());
                let excerpt_content: String = lines[start..end]
                    .iter()
                    .enumerate()
                    .map(|(i, l)| format!("{:4} | {}", start + i + 1, l))
                    .collect::<Vec<_>>()
                    .join("\n");
                CodeExcerpt {
                    file_path: rel_path.to_string(),
                    start_line: start + 1,
                    end_line: end,
                    content: excerpt_content,
                    language: get_language_id(rel_path).to_string(),
                    relevance_score: score,
                }
            };

        // Pass 1: lines containing the whole phrase, or (for a multi-word
        // query) every token in any order.
        for repo_name in &repos_to_search {
            // After resolve_repo / iteration of self.repos, repo_name is the
            // canonical absolute path used as both the engine's map key and
            // the on-disk repository root.
            let repo_path = PathBuf::from(repo_name);

            for entry in self.file_cache.iter() {
                let file_path = entry.key();
                let Some(rel_path) = file_in_scope(file_path, &repo_path) else {
                    continue;
                };

                let content = entry.value();
                let lines: Vec<&str> = content.lines().collect();

                for (line_num, line) in lines.iter().enumerate() {
                    let score = match &pattern {
                        Some(re) => re
                            .find(line)
                            .map(|hit| calculate_relevance(line, &hit.as_str().to_lowercase())),
                        None => {
                            let line_lower = line.to_lowercase();
                            let matched = line_lower.contains(&query_lower)
                                || (multi_token
                                    && tokens.iter().all(|t| line_lower.contains(t.as_str())));
                            matched.then(|| calculate_relevance(line, &query_lower))
                        }
                    };
                    if let Some(score) = score {
                        results.push((
                            repo_name.clone(),
                            make_excerpt(&lines, line_num, &rel_path, score),
                        ));
                    }
                }
            }
        }

        // Pass 2 (fallback): if no single line matched a multi-word query, fall
        // back to files that contain every token somewhere, anchored at the
        // first token occurrence. Runs only when pass 1 found nothing, so it
        // never dilutes precise single-line hits.
        let used_fallback = results.is_empty() && multi_token && pattern.is_none();
        if used_fallback {
            for repo_name in &repos_to_search {
                let repo_path = PathBuf::from(repo_name);

                for entry in self.file_cache.iter() {
                    let file_path = entry.key();
                    let Some(rel_path) = file_in_scope(file_path, &repo_path) else {
                        continue;
                    };

                    let content = entry.value();
                    let content_lower = content.to_lowercase();
                    if !tokens.iter().all(|t| content_lower.contains(t.as_str())) {
                        continue;
                    }

                    let lines: Vec<&str> = content.lines().collect();
                    let (anchor, coverage) = best_anchor(&lines, &tokens);
                    let anchor_line = lines.get(anchor).copied().unwrap_or("");
                    // Coverage dominates: a file whose terms sit together in
                    // code must outrank one that mentions them scattered
                    // through a help-text block.
                    let score = coverage + calculate_relevance(anchor_line, &query_lower);
                    results.push((
                        repo_name.clone(),
                        make_excerpt(&lines, anchor, &rel_path, score),
                    ));
                }
            }
        }

        // A term on consecutive lines yields one excerpt per line, each with the
        // same context lines around it — the same region of the file, several
        // times over. Keep the best-scoring excerpt of each region.
        results.sort_by(|a, b| {
            a.1.file_path
                .cmp(&b.1.file_path)
                .then(a.1.start_line.cmp(&b.1.start_line))
        });
        let mut regions: Vec<(String, CodeExcerpt)> = Vec::new();
        for (repo_name, excerpt) in results {
            match regions.last_mut() {
                Some((prev_repo, prev))
                    if *prev_repo == repo_name
                        && prev.file_path == excerpt.file_path
                        && excerpt.start_line <= prev.end_line =>
                {
                    if excerpt.relevance_score > prev.relevance_score {
                        *prev = excerpt;
                    }
                }
                _ => regions.push((repo_name, excerpt)),
            }
        }
        let mut results = regions;

        // Sort by relevance and take top results
        results.sort_by(|a, b| {
            b.1.relevance_score
                .partial_cmp(&a.1.relevance_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(max_results);

        // Collect dependent files for smart invalidation
        let dependent_files: Vec<String> =
            results.iter().map(|(_, r)| r.file_path.clone()).collect();

        let mut output = String::new();
        output.push_str(&format!("# Search Results for: `{}`\n\n", query));
        output.push_str(&format!("Found {} results\n\n", results.len()));
        if used_fallback && !results.is_empty() {
            output.push_str(
                "*No single line contained all terms; showing files that contain every term \
                 across multiple lines.*\n\n",
            );
        }

        for (i, (repo_name, result)) in results.iter().enumerate() {
            output.push_str(&format!("## {}. `{}`\n", i + 1, result.file_path));
            if multi_repo {
                output.push_str(&format!("**Repo**: `{}`\n", repo_name));
            }
            output.push_str(&format!(
                "Lines {}-{} | Score: {:.2}\n\n",
                result.start_line, result.end_line, result.relevance_score
            ));
            output.push_str("```");
            output.push_str(&result.language);
            output.push('\n');
            output.push_str(&result.content);
            output.push_str("\n```\n\n");
        }

        // Cache the result with file dependencies for smart invalidation
        if self.options.cache_enabled {
            self.query_cache
                .insert_with_files(cache_key, output.clone(), dependent_files);
        }

        Ok(output)
    }

    pub async fn get_file(
        &self,
        repo: &str,
        path: &str,
        start_line: Option<usize>,
        end_line: Option<usize>,
    ) -> Result<String> {
        let repo_path = PathBuf::from(self.resolve_repo(repo)?);
        let file_path = validate_path(&repo_path, path)?;

        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let lines: Vec<&str> = content.lines().collect();
        let start = start_line.unwrap_or(1).saturating_sub(1);
        let end = end_line.unwrap_or(lines.len()).min(lines.len());

        // Both bounds index into `lines` below, so a range the file cannot
        // satisfy has to be refused here; slicing it panics.
        if let (Some(first), Some(last)) = (start_line, end_line) {
            if first > last {
                return Err(anyhow!(
                    "start_line {first} is after end_line {last} in {path}"
                ));
            }
        }
        if start > 0 && start >= lines.len() {
            return Err(anyhow!(
                "start_line {} is past the end of {} ({} lines)",
                start + 1,
                path,
                lines.len()
            ));
        }

        // Format under the response budget first: the header has to name the
        // range that survives, not the one that was asked for. Leave room for
        // the header, the fences and the continuation note.
        let budget = response_budget::MAX_RESPONSE_BYTES.saturating_sub(1024);
        let mut body = String::new();
        let mut last_line = start;
        for (i, line) in lines[start..end].iter().enumerate() {
            let numbered = format!("{:4} │ {}\n", start + i + 1, line);
            if body.len() + numbered.len() > budget {
                break;
            }
            body.push_str(&numbered);
            last_line = start + i + 1;
        }
        // One line longer than the whole budget still gets returned: an empty
        // body under a "Lines 1-0" header would be the same lie in reverse.
        if body.is_empty() && start < end {
            body.push_str(&format!("{:4} │ {}\n", start + 1, lines[start]));
            last_line = start + 1;
        }

        let mut output = String::new();
        output.push_str(&format!("# {}\n\n", path));
        output.push_str(&format!(
            "Lines {}-{} of {}\n\n",
            start + 1,
            last_line,
            lines.len()
        ));

        output.push_str("```");
        output.push_str(get_language_id(path));
        output.push('\n');
        output.push_str(&body);
        output.push_str("```\n");

        if last_line < end {
            output.push_str(&format!(
                "\n*Stopped at the {} KB response budget, {} lines short of the \
                 requested line {}. Continue with `start_line={}`.*\n",
                response_budget::MAX_RESPONSE_BYTES / 1024,
                end - last_line,
                end,
                last_line + 1
            ));
        }

        Ok(output)
    }

    pub async fn find_references(
        &self,
        repo: &str,
        symbol: &str,
        _include_definition: bool,
        exclude_tests: Option<bool>,
        window: response_budget::ListWindow,
    ) -> Result<String> {
        use crate::extract::is_test_file;

        let repo = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo);
        let exclude_tests = exclude_tests.unwrap_or(false); // Default false for symbol search

        // Phase B3: Run text search and LSP search in parallel
        // Text search is fast (synchronous), LSP can be slow
        // Use tokio::select! to avoid blocking on LSP timeout

        // Check if LSP is enabled before spawning async work
        let lsp_enabled = self
            .lsp_manager
            .as_ref()
            .map(|lsp| lsp.is_enabled())
            .unwrap_or(false);

        // Helper to filter test files from references
        let filter_tests = |refs: Vec<(String, usize, String)>| -> Vec<(String, usize, String)> {
            if exclude_tests {
                refs.into_iter()
                    .filter(|(path, _, _)| !is_test_file(path))
                    .collect()
            } else {
                refs
            }
        };

        if !lsp_enabled {
            // Fast path: no LSP, just do text search
            let text_refs = filter_tests(self.text_search_references(&repo_path, symbol));
            return Ok(self.format_references(&text_refs, false, symbol, window));
        }

        // LSP is enabled - race text search against LSP with a grace period
        // 1. Do text search immediately (it's fast)
        let text_refs = filter_tests(self.text_search_references(&repo_path, symbol));

        // 2. Try LSP with a short additional timeout (500ms grace period)
        // This way we don't block the full LSP timeout (1.5s) if text search is ready
        let lsp_result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            self.lsp_search_references(&repo, symbol, &repo_path),
        )
        .await;

        // 3. Merge LSP and text results instead of letting either win outright:
        //    LSP can miss cross-TU definitions/calls that a text scan catches,
        //    while text over-reports. The union (deduped by location) keeps both
        //    sources' hits — the same combined-view rule find_symbol_usages
        //    already follows. Returning LSP-only here silently dropped the
        //    definition and real call sites text search had found.
        let lsp_refs = match lsp_result {
            Ok(Some(refs)) => filter_tests(refs),
            _ => Vec::new(),
        };
        let lsp_used = !lsp_refs.is_empty();
        let merged = Self::merge_references(text_refs, lsp_refs);

        Ok(self.format_references(&merged, lsp_used, symbol, window))
    }

    /// Merge two reference lists, deduplicated by (path, line). `primary`'s
    /// content wins on a location collision; locations unique to either list
    /// survive. Ordered by (path, line) for deterministic output.
    fn merge_references(
        primary: Vec<(String, usize, String)>,
        secondary: Vec<(String, usize, String)>,
    ) -> Vec<(String, usize, String)> {
        use std::collections::BTreeMap;
        let mut merged: BTreeMap<(String, usize), String> = BTreeMap::new();
        for (path, line, content) in primary.into_iter().chain(secondary) {
            merged.entry((path, line)).or_insert(content);
        }
        merged
            .into_iter()
            .map(|((path, line), content)| (path, line, content))
            .collect()
    }

    /// Text-based reference search (fast, synchronous)
    fn text_search_references(
        &self,
        repo_path: &Path,
        symbol: &str,
    ) -> Vec<(String, usize, String)> {
        let mut references = Vec::new();

        for entry in self.file_cache.iter() {
            let file_path = entry.key();
            if !file_path.starts_with(repo_path) {
                continue;
            }

            let rel_path = file_path
                .strip_prefix(repo_path)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let content = entry.value();
            for (line_num, line) in content.lines().enumerate() {
                if line.contains(symbol) {
                    references.push((rel_path.clone(), line_num + 1, line.trim().to_string()));
                }
            }
        }

        references
    }

    /// 0-based (line, UTF-16 column) of `name` as a whole-word token, scanning
    /// from the definition's start line.
    ///
    /// clangd resolves a symbol from the identifier under the cursor, so a
    /// reference query must anchor on the name token — column 0 sits on the
    /// return type or a leading keyword. The name is usually on the start line
    /// but a return type on its own line pushes it down, so a few lines are
    /// scanned, never past the definition body.
    fn locate_name_anchor(
        content: &str,
        name: &str,
        start_line: usize,
        end_line: usize,
    ) -> Option<(u32, u32)> {
        if name.is_empty() {
            return None;
        }
        let lines: Vec<&str> = content.lines().collect();
        let first = start_line.saturating_sub(1);
        let window_end = (first + 8).min(end_line).min(lines.len());

        // line_idx is returned as the matched line number, so indexing is the
        // loop's purpose, not an incidental cursor.
        #[allow(clippy::needless_range_loop)]
        for line_idx in first..window_end {
            let line = lines[line_idx];
            let mut search_from = 0;
            while let Some(rel) = line[search_from..].find(name) {
                let byte_idx = search_from + rel;
                let before_ok = line[..byte_idx]
                    .chars()
                    .next_back()
                    .map(|c| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(true);
                let after_idx = byte_idx + name.len();
                let after_ok = line[after_idx..]
                    .chars()
                    .next()
                    .map(|c| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(true);
                if before_ok && after_ok {
                    let col = line[..byte_idx].encode_utf16().count() as u32;
                    return Some((line_idx as u32, col));
                }
                search_from = after_idx;
            }
        }
        None
    }

    /// LSP-based reference search (can be slow, async)
    async fn lsp_search_references(
        &self,
        repo: &str,
        symbol: &str,
        repo_path: &Path,
    ) -> Option<Vec<(String, usize, String)>> {
        let lsp = self.lsp_manager.as_ref()?;
        let symbol_entry = self.symbols.get(repo)?;

        for sym in symbol_entry.iter() {
            if sym.name == symbol || sym.qualified_name.as_deref() == Some(symbol) {
                let file_path = match validate_path(repo_path, &sym.file_path) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let language = get_language_from_path(&sym.file_path);

                // Anchor on the name token (0-based); fall back to the start of
                // the definition line when it cannot be located.
                let (anchor_line, anchor_col) = std::fs::read_to_string(&file_path)
                    .ok()
                    .and_then(|content| {
                        Self::locate_name_anchor(&content, &sym.name, sym.start_line, sym.end_line)
                    })
                    .unwrap_or_else(|| (sym.start_line.saturating_sub(1) as u32, 0));

                let lsp_map = lsp
                    .find_references_parallel(&language, &file_path, anchor_line, anchor_col, true)
                    .await;
                if !lsp_map.is_empty() {
                    let mut seen = std::collections::HashSet::new();
                    let mut references = Vec::new();
                    for locations in lsp_map.into_values() {
                        for loc in locations {
                            if let Ok(path) = loc.uri.to_file_path() {
                                let line_idx = loc.range.start.line as usize;
                                if seen.insert((path.clone(), line_idx)) {
                                    if let Ok(content) = std::fs::read_to_string(&path) {
                                        let lines: Vec<&str> = content.lines().collect();
                                        if line_idx < lines.len() {
                                            let rel = path
                                                .strip_prefix(repo_path)
                                                .unwrap_or(&path)
                                                .to_string_lossy()
                                                .to_string();
                                            references.push((
                                                rel,
                                                line_idx + 1,
                                                lines[line_idx].trim().to_string(),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !references.is_empty() {
                        return Some(references);
                    }
                }
                break;
            }
        }

        None
    }

    /// Query all enabled reference backends for `symbol` and return per-backend
    /// hit sets. Returns `None` when no backend applies (none enabled, or the
    /// symbol's language has no LSP server and gtags does not apply).
    ///
    /// LSP backends apply to any configured language; gtags (GNU Global) is
    /// C/C++ only. Backend labels: the LSP backend or language id (`"clangd"`,
    /// `"ccls"`, `"rust"`, ...) and `"gtags"`.
    async fn refs_for_symbol(
        &self,
        repo: &str,
        symbol: &str,
        repo_path: &Path,
        symbols: &[Symbol],
    ) -> Option<HashMap<String, Vec<(String, usize, String)>>> {
        // gtags indexes C/C++ only; used to gate the gtags backend below.
        let is_cxx = symbols.iter().any(|s| {
            s.name == symbol && matches!(get_language_from_path(&s.file_path).as_str(), "c" | "cpp")
        });

        let lsp_enabled = self.lsp_manager.as_ref().is_some_and(|l| l.is_enabled());
        let gtags_enabled = self.gtags_manager.is_some();

        if !lsp_enabled && !gtags_enabled {
            return None;
        }

        let mut all: HashMap<String, Vec<(String, usize, String)>> = HashMap::new();

        // LSP backends: find the anchor position then query all backends in parallel
        if lsp_enabled {
            if let Some(lsp) = &self.lsp_manager {
                let symbol_entry = self.symbols.get(repo);
                if let Some(entry) = symbol_entry {
                    for sym in entry.iter() {
                        if sym.name != symbol && sym.qualified_name.as_deref() != Some(symbol) {
                            continue;
                        }
                        let language = get_language_from_path(&sym.file_path);
                        let file_path = match crate::index::validate_path(repo_path, &sym.file_path)
                        {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        let (anchor_line, anchor_col) = std::fs::read_to_string(&file_path)
                            .ok()
                            .and_then(|content| {
                                Self::locate_name_anchor(
                                    &content,
                                    &sym.name,
                                    sym.start_line,
                                    sym.end_line,
                                )
                            })
                            .unwrap_or_else(|| (sym.start_line.saturating_sub(1) as u32, 0));

                        let lsp_map = lsp
                            .find_references_parallel(
                                &language,
                                &file_path,
                                anchor_line,
                                anchor_col,
                                true,
                            )
                            .await;

                        for (label, locations) in lsp_map {
                            self.metrics.record_backend_call(&label);
                            let mut refs: Vec<(String, usize, String)> = Vec::new();
                            for loc in locations {
                                if let Ok(path) = loc.uri.to_file_path() {
                                    if let Ok(content) = std::fs::read_to_string(&path) {
                                        let lines: Vec<&str> = content.lines().collect();
                                        let line_idx = loc.range.start.line as usize;
                                        if line_idx < lines.len() {
                                            let rel = path
                                                .strip_prefix(repo_path)
                                                .unwrap_or(&path)
                                                .to_string_lossy()
                                                .to_string();
                                            refs.push((
                                                rel,
                                                line_idx + 1,
                                                lines[line_idx].trim().to_string(),
                                            ));
                                        }
                                    }
                                }
                            }
                            if !refs.is_empty() {
                                all.insert(label, refs);
                            }
                        }
                        break;
                    }
                }
            }
        }

        // gtags backend (C/C++ only)
        if is_cxx {
            if let Some(gtags) = &self.gtags_manager {
                let gtags_refs = gtags.find_references(symbol, repo_path).await;
                self.metrics.record_backend_call("gtags");
                if !gtags_refs.is_empty() {
                    all.insert("gtags".to_string(), gtags_refs);
                }
            }
        }

        if all.is_empty() {
            None
        } else {
            Some(all)
        }
    }

    /// Format references into output string
    fn format_references(
        &self,
        references: &[(String, usize, String)],
        lsp_enhanced: bool,
        symbol: &str,
        window: response_budget::ListWindow,
    ) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "# References to `{}`{}\n\n",
            symbol,
            if lsp_enhanced { " (LSP enhanced)" } else { "" }
        ));
        output.push_str(&format!("Found {} references\n\n", references.len()));

        let (page, capped) = response_budget::cap(references, window, "find_references");
        for (path, line, content) in page {
            output.push_str(&format!(
                "- `{}:{}` - `{}`\n",
                path,
                line,
                response_budget::truncate_on_char_boundary(content, 80)
            ));
        }

        if capped.truncated() {
            let dropped = &references[(capped.offset + capped.shown).min(references.len())..];
            output.push_str("\n## Remaining references by file\n\n");
            output.push_str(&response_budget::by_file_summary(
                dropped,
                |(path, _, _)| path.as_str(),
                20,
            ));
            output.push('\n');
            output.push_str(&capped.footer());
        }

        output
    }

    pub async fn get_dependencies(
        &self,
        repo: &str,
        path: &str,
        direction: &str,
    ) -> Result<String> {
        let repo_path = PathBuf::from(self.resolve_repo(repo)?);
        let file_path = validate_path(&repo_path, path)?;

        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let mut output = String::new();
        output.push_str(&format!("# Dependencies for `{}`\n\n", path));

        // Extract imports based on language
        let imports = extract_imports(&content, path);

        if direction == "imports" || direction == "both" {
            output.push_str("## Imports\n\n");
            for import in &imports {
                output.push_str(&format!("- `{}`\n", import));
            }
            output.push('\n');
        }

        if direction == "imported_by" || direction == "both" {
            output.push_str("## Imported By\n\n");

            // Search for files that import this module
            let module_name = Path::new(path)
                .file_stem()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            for entry in self.file_cache.iter() {
                let fp = entry.key();
                if !fp.starts_with(&repo_path) || fp == &file_path {
                    continue;
                }

                let content = entry.value();
                if content.contains(module_name) {
                    let rel_path = fp.strip_prefix(&repo_path).unwrap_or(fp).to_string_lossy();
                    output.push_str(&format!("- `{}`\n", rel_path));
                }
            }
        }

        Ok(output)
    }

    pub async fn read_resource(&self, uri: &str) -> Result<String> {
        // Parse URI like "file:///path/to/file"
        let path_str = uri.strip_prefix("file://").unwrap_or(uri);
        let requested_path = Path::new(path_str);

        // Security: Validate the path is within one of the indexed repositories
        // Try to canonicalize the requested path first
        let canonical_requested = requested_path
            .canonicalize()
            .context("Path does not exist or cannot be accessed")?;

        // Check if the path is within any indexed repository
        for repo_entry in self.repos.iter() {
            let repo_meta = repo_entry.value();
            if let Ok(canonical_root) = repo_meta.path.canonicalize() {
                if canonical_requested.starts_with(&canonical_root) {
                    // Path is within this repository, safe to read
                    return std::fs::read_to_string(&canonical_requested)
                        .context("Failed to read resource");
                }
            }
        }

        // Path is not within any indexed repository - reject the request
        Err(anyhow!(
            "Access denied: path '{}' is outside all indexed repositories",
            path_str
        ))
    }

    // === Persistence Methods ===

    /// Save the current index to disk
    pub async fn save_index(&self) -> Result<String> {
        if !self.options.persist_enabled {
            return Ok(
                "Persistence is not enabled. Start with --persist flag to enable.".to_string(),
            );
        }

        let store = match &self.index_store {
            Some(s) => s,
            None => return Err(anyhow!("Index store not initialized")),
        };

        let mut saved_count = 0;
        for repo_path in &self.registered_repo_paths() {
            let repo_name = match canonical_repo_key(repo_path) {
                Ok(k) => k,
                Err(e) => {
                    warn!("Skipping save_index for {:?}: {}", repo_path, e);
                    continue;
                }
            };

            // Create a persisted index from current state. The repo_root field
            // is stored as the canonical absolute path so future loads route
            // through the canonical-keyed index file.
            let mut persisted = PersistedIndex::new(PathBuf::from(&repo_name));
            persisted.head_hash = self.git_head_hash(repo_path);
            persisted.cdb_hash = self.compile_commands_hash(repo_path);
            // Re-derived, not copied from memory: a build that regenerated the
            // manifest since the last full index moved the base to HEAD, and
            // writing the old base next to the new hash would strand it.
            persisted.cdb_head_hash = self.compile_commands_diff_base(&repo_name, repo_path);

            // Group augmentation edges by the caller's file so each rides its
            // file's record (and the incremental watch path's keying).
            let mut edges_by_file: HashMap<String, Vec<crate::persist::PersistedCallEdge>> =
                HashMap::new();
            if let Some(call_graph) = self.call_graphs.get(&repo_name) {
                for (caller_key, edge) in call_graph.export_augmentation_edges() {
                    edges_by_file
                        .entry(edge.file_path.clone())
                        .or_default()
                        .push(crate::persist::PersistedCallEdge { caller_key, edge });
                }
            }

            // Populate with current symbols
            if let Some(symbols) = self.symbols.get(&repo_name) {
                // Group symbols by file path
                let mut by_file: HashMap<String, Vec<Symbol>> = HashMap::new();
                for sym in symbols.iter() {
                    by_file
                        .entry(sym.file_path.clone())
                        .or_default()
                        .push(sym.clone());
                }

                // Create file metadata for each file
                for (file_path, file_symbols) in by_file {
                    let call_edges = edges_by_file.remove(&file_path).unwrap_or_default();
                    let full_path = repo_path.join(&file_path);
                    if let Ok(metadata) = std::fs::metadata(&full_path) {
                        let modified = metadata
                            .modified()
                            .ok()
                            .and_then(|m| m.duration_since(SystemTime::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);

                        let content_hash = if let Ok(content) = std::fs::read(&full_path) {
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            hasher.update(&content);
                            format!("{:x}", hasher.finalize())
                        } else {
                            String::new()
                        };

                        persisted.files.insert(
                            full_path.clone(),
                            crate::persist::FileMetadata {
                                path: full_path,
                                content_hash,
                                modified_time: modified,
                                size: metadata.len(),
                                symbols: file_symbols,
                                call_edges,
                            },
                        );
                    }
                }
            }

            // Save the index (full rewrite — one-time after a fresh index and
            // for the explicit save_index tool; the watch path is incremental).
            // A per-repo failure (e.g. redb lock held by another process) must
            // not abort saving the remaining repos.
            match store.save_full(&persisted) {
                Ok(()) => saved_count += 1,
                Err(e) => warn!("Failed to save index for {}: {}", repo_name, e),
            }
        }

        Ok(format!(
            "Saved {} repository index(es) to disk successfully.",
            saved_count
        ))
    }

    /// Resolved compile_commands.json paths that watch mode must cover, mirroring
    /// the resolution in `index_repo` so the watch set and the load set agree.
    /// Empty when compile_commands filtering is disabled.
    #[cfg(feature = "native")]
    fn compile_commands_watch_paths(&self) -> Vec<PathBuf> {
        if !self.options.use_compile_commands {
            return Vec::new();
        }
        let mut paths = Vec::new();
        match &self.options.compile_commands_path {
            Some(explicit) if explicit.is_absolute() => paths.push(explicit.clone()),
            Some(explicit) => {
                for repo in &self.registered_repo_paths() {
                    paths.push(repo.join(explicit));
                }
            }
            None => {
                for repo in &self.registered_repo_paths() {
                    paths.push(repo.join("compile_commands.json"));
                    paths.push(repo.join("build/compile_commands.json"));
                }
            }
        }
        paths
    }

    /// Parent directories of out-of-tree compile_commands paths that the watcher
    /// must cover. Watch the directory, not the file: an atomic write-and-rename
    /// replaces the inode and would break a file-level watch. Sibling files that
    /// leak through are dropped later by the repo lookup in `process_file_changes`.
    #[cfg(feature = "native")]
    fn compile_commands_watch_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        let repo_paths = self.registered_repo_paths();
        for cc_path in self.compile_commands_watch_paths() {
            if let Some(dir) = cc_path.parent() {
                let already_watched = repo_paths.iter().any(|r| dir.starts_with(r));
                if dir.exists() && !already_watched && !dirs.contains(&dir.to_path_buf()) {
                    dirs.push(dir.to_path_buf());
                }
            }
        }
        dirs
    }

    /// Create a file watcher for the indexed repositories.
    /// The caller is responsible for managing the watcher lifecycle.
    /// Returns None if watch mode is not enabled.
    #[cfg(feature = "native")]
    pub fn create_file_watcher(&self) -> Option<crate::persist::FileWatcher> {
        if !self.options.watch_enabled {
            return None;
        }

        match crate::persist::FileWatcher::new() {
            Ok(mut watcher) => {
                for repo_path in &self.registered_repo_paths() {
                    if repo_path.exists() {
                        if let Err(e) = watcher.watch(repo_path) {
                            warn!("Failed to watch {:?}: {}", repo_path, e);
                        }
                    }
                }
                for dir in self.compile_commands_watch_dirs() {
                    if let Err(e) = watcher.watch(&dir) {
                        warn!("Failed to watch compile_commands dir {:?}: {}", dir, e);
                    }
                }
                Some(watcher)
            }
            Err(e) => {
                warn!("Failed to create file watcher: {}", e);
                None
            }
        }
    }

    /// Create an async file watcher for the indexed repositories.
    /// Returns the watcher and a receiver for batched file change events.
    /// Returns None if watch mode is not enabled.
    ///
    /// Takes `Arc<Self>` (not `&self`) because the watcher's debounce task
    /// holds it past this call, to take an update-window lease at the first
    /// change of a batch rather than only once the batch is dequeued.
    #[cfg(feature = "native")]
    pub fn create_async_file_watcher(
        self: Arc<Self>,
    ) -> Option<(
        Arc<parking_lot::Mutex<crate::persist::AsyncFileWatcher>>,
        tokio::sync::mpsc::Receiver<crate::persist::WatchBatch>,
    )> {
        if !self.options.watch_enabled {
            return None;
        }

        // Serialize the initial path snapshot with repository registration.
        let mut active = self.async_file_watcher.lock();
        match crate::persist::AsyncFileWatcher::new(Arc::clone(&self)) {
            Ok((mut watcher, rx)) => {
                self.watch_registered_paths(&mut watcher);
                let watcher = Arc::new(parking_lot::Mutex::new(watcher));
                *active = Arc::downgrade(&watcher);
                Some((watcher, rx))
            }
            Err(e) => {
                warn!("Failed to create async file watcher: {}", e);
                None
            }
        }
    }

    fn watch_registered_paths(&self, watcher: &mut crate::persist::AsyncFileWatcher) {
        let paths = self
            .registered_repo_paths()
            .into_iter()
            .chain(self.compile_commands_watch_dirs());
        for path in paths {
            if path.exists() && !watcher.watched_paths().contains(&path) {
                if let Err(error) = watcher.watch(&path) {
                    warn!("Failed to watch {:?}: {}", path, error);
                }
            }
        }
    }

    /// The indexed repo a changed compile_commands.json belongs to, matching the
    /// repo's resolved CDB candidate paths (covers out-of-tree build dirs) and
    /// falling back to tree containment.
    fn repo_for_compile_commands(&self, cdb_path: &Path) -> Option<PathBuf> {
        let canon = cdb_path.canonicalize().ok();
        for repo in &self.registered_repo_paths() {
            for candidate in self.compile_commands_candidate_paths(repo) {
                if candidate == cdb_path
                    || (canon.is_some() && candidate.canonicalize().ok() == canon)
                {
                    return Some(repo.clone());
                }
            }
            if path_is_within_repo(cdb_path, repo) {
                return Some(repo.clone());
            }
        }
        None
    }

    /// Augment a C/C++ file's tree-sitter `symbols` with clangd/ccls
    /// documentSymbol and gtags definitions, honoring this repo's enabled
    /// backends. The per-file analogue of the index-time augment pass, for the
    /// incremental watch path.
    async fn augment_cxx_symbols(
        &self,
        repo_name: &str,
        abs_path: &Path,
        relative_path: &str,
        repo_path: &Path,
        repo_scoped: bool,
        mut symbols: Vec<Symbol>,
    ) -> Vec<Symbol> {
        if self.lsp_augment_allows(
            repo_name,
            repo_scoped,
            relative_path,
            &abs_path.to_string_lossy(),
        ) && self.lsp_repo_enabled(repo_path)
        {
            if let Some(lsp) = &self.lsp_manager {
                let lang = get_language_from_path(&abs_path.to_string_lossy());
                for backend in lsp.active_cxx_backends_for(Path::new(repo_name)) {
                    match lsp.get_document_symbols(backend, abs_path, &lang).await {
                        Ok(mut lsp_symbols) => {
                            for symbol in &mut lsp_symbols {
                                symbol.file_path = relative_path.to_string();
                            }
                            merge_symbols(&mut symbols, lsp_symbols, backend);
                        }
                        Err(e) => debug!("LSP documentSymbol failed for {:?}: {}", abs_path, e),
                    }
                }
            }
        }
        if self.gtags_repo_enabled(repo_path) {
            if let Some(gtags) = &self.gtags_manager {
                let gtags_symbols: Vec<Symbol> = gtags
                    .list_file_symbols(abs_path, repo_path)
                    .await
                    .into_iter()
                    .map(|(name, line)| Symbol {
                        name,
                        kind: SymbolKind::Unknown,
                        file_path: relative_path.to_string(),
                        start_line: line,
                        end_line: line,
                        signature: None,
                        qualified_name: None,
                        doc_comment: None,
                        confirmed_by: SourceSet::GTAGS,
                        line_conflicts: Vec::new(),
                    })
                    .collect();
                merge_symbols(&mut symbols, gtags_symbols, SourceSet::GTAGS);
            }
        }
        symbols
    }

    /// Re-index the C/C++ sources a compile_commands.json change adds to or
    /// removes from `repo_path`'s included set: newly-included files are parsed
    /// and augmented (clangd/gtags), dropped files are removed. Headers and
    /// non-C/C++ files are unaffected (never filtered). Returns files changed.
    async fn reindex_compile_commands_delta(&self, repo_path: &Path) -> usize {
        use crate::persist::FileMetadata;
        let repo_name = match canonical_repo_key(repo_path) {
            Ok(k) => k,
            Err(e) => {
                warn!(
                    "compile_commands re-index skipped for {:?}: {}",
                    repo_path, e
                );
                return 0;
            }
        };
        let canon_repo = repo_path
            .canonicalize()
            .unwrap_or_else(|_| repo_path.to_path_buf());

        // Source files clangd now knows about (canonical absolute paths).
        let compiled = if let Some(p) = self.options.compile_commands_path.as_deref() {
            load_compile_commands_filter(repo_path, &[p])
        } else {
            load_compile_commands_filter(
                repo_path,
                &[
                    Path::new("compile_commands.json"),
                    Path::new("build/compile_commands.json"),
                ],
            )
        };

        // C/C++ source files already carrying symbols, by repo-relative path.
        let indexed: std::collections::HashSet<String> = self
            .symbols
            .get(&repo_name)
            .map(|syms| {
                syms.iter()
                    .map(|s| s.file_path.clone())
                    .filter(|p| {
                        Path::new(p)
                            .extension()
                            .and_then(|e| e.to_str())
                            .is_some_and(is_c_source_ext)
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut upserts: Vec<FileMetadata> = Vec::new();
        let mut deletes: Vec<PathBuf> = Vec::new();

        // --lsp-scope gate for this repo: scoped only when some compiled TU lies
        // under a scope entry (else this repo is unaffected).
        let repo_scoped = self.lsp_scope_active(&repo_name)
            && compiled.iter().any(|abs| {
                abs.strip_prefix(&canon_repo)
                    .ok()
                    .map(|rel| {
                        self.lsp_scope_matches(
                            &repo_name,
                            &rel.to_string_lossy(),
                            &abs.to_string_lossy(),
                        )
                    })
                    .unwrap_or(false)
            });

        // Newly-included sources: parse, augment, insert.
        for abs_path in &compiled {
            let relative_path = match abs_path.strip_prefix(&canon_repo) {
                Ok(rel) => rel.to_string_lossy().to_string(),
                Err(_) => continue,
            };
            if indexed.contains(&relative_path) {
                continue;
            }
            // Honor --index-filter on the compile_commands delta too.
            if self.repo_index_filtered(&repo_name)
                && !scope_matches(
                    self.repo_index_filter_rules(&repo_name),
                    &relative_path,
                    &abs_path.to_string_lossy(),
                )
            {
                continue;
            }
            let content = match std::fs::read_to_string(abs_path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let parsed = match self.parser.parse_file(abs_path, &content) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let mut symbols = parsed.symbols;
            for symbol in &mut symbols {
                symbol.file_path = relative_path.clone();
            }
            let symbols = self
                .augment_cxx_symbols(
                    &repo_name,
                    abs_path,
                    &relative_path,
                    repo_path,
                    repo_scoped,
                    symbols,
                )
                .await;

            if let Some(mut entry) = self.symbols.get_mut(&repo_name) {
                entry.retain(|s| s.file_path != relative_path);
                entry.extend(symbols.iter().cloned());
            }
            self.file_cache
                .insert(abs_path.clone(), Arc::new(content.clone()));
            self.search_index
                .index_file(&repo_name, &relative_path, &content);
            self.query_cache.invalidate_for_file(&relative_path);

            let content_hash = content_sha256(content.as_bytes());
            let (modified_time, size) = std::fs::metadata(abs_path)
                .ok()
                .map(|meta| {
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    (mtime, meta.len())
                })
                .unwrap_or((0, 0));
            upserts.push(FileMetadata {
                path: abs_path.clone(),
                content_hash,
                modified_time,
                size,
                symbols,
                // Watch upserts drop augmentation edges; a later reindex or a
                // fingerprint mismatch rebuilds them.
                call_edges: Vec::new(),
            });
        }

        // Sources dropped from the CDB: remove their symbols.
        for relative_path in &indexed {
            let abs = canon_repo.join(relative_path);
            let still_included = abs
                .canonicalize()
                .ok()
                .map(|c| compiled.contains(&c))
                .unwrap_or(false);
            if still_included {
                continue;
            }
            if let Some(mut entry) = self.symbols.get_mut(&repo_name) {
                entry.retain(|s| s.file_path != *relative_path);
            }
            self.file_cache.remove(&abs);
            self.query_cache.invalidate_for_file(relative_path);
            deletes.push(abs);
        }

        let changed = upserts.len() + deletes.len();
        if changed > 0 && self.options.persist_enabled {
            if let Some(store) = &self.index_store {
                if let Err(e) =
                    store.apply_file_changes(&PathBuf::from(&repo_name), &upserts, &deletes)
                {
                    warn!(
                        "Failed to persist compile_commands delta for {}: {}",
                        repo_name, e
                    );
                }
            }
        }
        if changed > 0 {
            info!(
                "compile_commands change: re-indexed {} source file(s) in {}",
                changed, repo_name
            );
        }
        changed
    }

    /// Process file changes detected by the watcher.
    /// Returns the number of files re-indexed.
    ///
    /// The caller holds the update leases for the batch's repos (see
    /// `run_watch_mode`) — the window spans several batches on a branch
    /// switch, so it cannot be taken here.
    pub async fn process_file_changes(
        &self,
        changes: &[crate::persist::FileChange],
    ) -> Result<usize> {
        use crate::persist::{ChangeType, FileMetadata};

        // Per-repo batches so each repo's redb store is updated in one write
        // transaction, touching only changed records — never the whole repo.
        #[derive(Default)]
        struct RepoPending {
            upserts: Vec<FileMetadata>,
            deletes: Vec<PathBuf>,
        }
        let mut pending: HashMap<String, RepoPending> = HashMap::new();

        let mut count = 0;
        // Repos whose C/C++ sources changed this batch, mapped to the changed
        // source paths: their GTAGS db drifts on every edit, so refresh it once
        // per repo after the loop (not per file), and only when actually stale.
        let mut gtags_dirty: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
        let registered_repos = self.registered_repo_paths();

        for change in changes {
            // compile_commands.json regenerated → clangd holds stale flags. Restart
            // the C/C++ servers and skip normal re-indexing (it is not a source
            // file). Checked before the repo lookup so an out-of-tree build dir is
            // also handled. Deliberately does not bump `count` or add to
            // `pending`, so it does not trigger a persist on its own.
            if change
                .path
                .file_name()
                .is_some_and(|n| n == "compile_commands.json")
            {
                let cc_repo = self.repo_for_compile_commands(&change.path);
                if let Some(lsp) = &self.lsp_manager {
                    match &cc_repo {
                        Some(repo_path) => {
                            for lang in ["c", "cpp"] {
                                lsp.restart_server(repo_path, lang).await;
                            }
                        }
                        // Out-of-tree build dir we could not map to a repo:
                        // restart every repo's C/C++ servers so none keeps stale
                        // flags. A repo with no running server is a no-op.
                        None => {
                            for repo in &self.registered_repo_paths() {
                                for lang in ["c", "cpp"] {
                                    lsp.restart_server(repo, lang).await;
                                }
                            }
                        }
                    }
                }
                // The included C/C++ source set changed: bring symbols in line by
                // indexing newly-added sources (augmented) and dropping removed
                // ones. LSP is restarted first so the augment sees fresh flags.
                if let Some(repo_path) = cc_repo {
                    count += self.reindex_compile_commands_delta(&repo_path).await;
                    // gtags is the peer C/C++ backend: keep its database in sync with
                    // the changed source set, just as clangd was restarted above.
                    self.refresh_gtags_if_active(&repo_path).await;
                }
                continue;
            }

            // Find which repo this file belongs to. Notify may emit canonical
            // paths even when the user supplied a symlinked path (for example
            // `/private/var/...` vs `/var/...` on macOS), so compare both raw
            // and canonical forms.
            let repo_path = registered_repos
                .iter()
                .find(|p| path_is_within_repo(&change.path, p));

            let repo_path = match repo_path {
                Some(p) => p,
                None => continue,
            };

            // Build artifacts written into a watched tree (e.g. an in-tree kernel
            // build) must never trigger a re-index or a gtags refresh. Mirror the
            // index-time WalkBuilder(hidden + git_ignore) filter so the watch path
            // tracks exactly the files the indexer would.
            if self.is_ignored_for_index(repo_path, &change.path) {
                continue;
            }

            let repo_name = match canonical_repo_key(repo_path) {
                Ok(k) => k,
                Err(e) => {
                    warn!("Skipping re-index of {:?}: {}", change.path, e);
                    continue;
                }
            };

            // The definition map covers the whole repo, so it is updated before
            // the --index-filter check below, which drops out-of-scope files.
            self.update_definition_map(repo_path, &change.path, &change.change_type);

            // --index-filter: in a repo whose base index is restricted, never
            // (re)index a file outside the scope. Repos not restricted are
            // untouched, so this changes nothing for them.
            if self.repo_index_filtered(&repo_name) {
                let rel = change
                    .path
                    .strip_prefix(repo_path)
                    .unwrap_or(&change.path)
                    .to_string_lossy()
                    .into_owned();
                // A file pulled in for being referenced by in-scope code sits
                // outside the rules yet is already indexed; its presence in the
                // file cache is what says so.
                if !scope_matches(
                    self.repo_index_filter_rules(&repo_name),
                    &rel,
                    &change.path.to_string_lossy(),
                ) && !self.file_cache.contains_key(&change.path)
                {
                    continue;
                }
            }

            // A C/C++ source changed (created/modified/deleted): flag the repo so its
            // GTAGS database is refreshed below, keeping the gtags backend in sync.
            if matches!(
                get_language_from_path(&change.path.to_string_lossy()).as_str(),
                "c" | "cpp"
            ) {
                gtags_dirty
                    .entry(repo_path.to_path_buf())
                    .or_default()
                    .push(change.path.clone());
            }

            match change.change_type {
                ChangeType::Created | ChangeType::Modified => {
                    // Re-index the changed file
                    if let Ok(content) = std::fs::read_to_string(&change.path) {
                        if let Ok(parsed) = self.parser.parse_file(&change.path, &content) {
                            let rel_path = change
                                .path
                                .strip_prefix(repo_path)
                                .unwrap_or(&change.path)
                                .to_string_lossy()
                                .to_string();

                            if self.options.call_graph_enabled {
                                if let (Some(call_graph), Some(tree)) =
                                    (self.call_graphs.get(&repo_name), parsed.tree.clone())
                                {
                                    call_graph.replace_file((
                                        rel_path.clone(),
                                        content.clone(),
                                        tree,
                                    ))?;
                                }
                            }

                            // Build this file's symbols once and reuse them for
                            // both the in-memory index and the persisted record.
                            let mut file_symbols: Vec<_> = parsed
                                .symbols
                                .into_iter()
                                .map(|mut symbol| {
                                    symbol.file_path = rel_path.clone();
                                    symbol
                                })
                                .collect();

                            // Augment with LSP for C/C++ files, mirroring index_repo
                            // phase 2. LSP servers are always current; gtags
                            // augmentation happens after GTAGS is refreshed below.
                            let lang = get_language_from_path(&change.path.to_string_lossy());
                            if matches!(lang.as_str(), "c" | "cpp") {
                                if let Some(lsp) = &self.lsp_manager {
                                    let abs_str = change.path.to_string_lossy();
                                    let repo_scoped = self.lsp_scope_active(&repo_name);
                                    if self.lsp_augment_allows(
                                        &repo_name,
                                        repo_scoped,
                                        &rel_path,
                                        &abs_str,
                                    ) {
                                        let active_backends =
                                            lsp.active_cxx_backends_for(repo_path);
                                        for &backend in &active_backends {
                                            match lsp
                                                .get_document_symbols(backend, &change.path, &lang)
                                                .await
                                            {
                                                Ok(mut lsp_syms) => {
                                                    for s in &mut lsp_syms {
                                                        s.file_path = rel_path.clone();
                                                    }
                                                    merge_symbols(
                                                        &mut file_symbols,
                                                        lsp_syms,
                                                        backend,
                                                    );
                                                }
                                                Err(e) => debug!(
                                                    "LSP documentSymbol failed for {:?}: {}",
                                                    change.path, e
                                                ),
                                            }
                                        }
                                    }
                                }
                            }

                            // Update symbols for this file
                            if let Some(mut symbols) = self.symbols.get_mut(&repo_name) {
                                symbols.retain(|s| s.file_path != rel_path);
                                symbols.extend(file_symbols.iter().cloned());
                            }

                            // Update file cache
                            self.file_cache
                                .insert(change.path.clone(), Arc::new(content.clone()));

                            // Update search index
                            self.search_index
                                .index_file(&repo_name, &rel_path, &content);

                            // Smart cache invalidation - only invalidate entries that depend on this file
                            self.query_cache.invalidate_for_file(&rel_path);

                            // Persisted per-file record: hash the content already
                            // read (no second disk read), stat for mtime/size.
                            let content_hash = {
                                use sha2::{Digest, Sha256};
                                let mut hasher = Sha256::new();
                                hasher.update(content.as_bytes());
                                format!("{:x}", hasher.finalize())
                            };
                            let (modified_time, size) = std::fs::metadata(&change.path)
                                .ok()
                                .map(|meta| {
                                    let mtime = meta
                                        .modified()
                                        .ok()
                                        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                                        .map(|d| d.as_secs())
                                        .unwrap_or(0);
                                    (mtime, meta.len())
                                })
                                .unwrap_or((0, 0));
                            pending.entry(repo_name.clone()).or_default().upserts.push(
                                FileMetadata {
                                    path: change.path.clone(),
                                    content_hash,
                                    modified_time,
                                    size,
                                    symbols: file_symbols,
                                    // Watch upserts drop augmentation edges; a
                                    // later reindex or fingerprint mismatch
                                    // rebuilds them.
                                    call_edges: Vec::new(),
                                },
                            );

                            debug!("Re-indexed file: {}", rel_path);
                            count += 1;
                        }
                    }
                }
                ChangeType::Deleted => {
                    let rel_path = change
                        .path
                        .strip_prefix(repo_path)
                        .unwrap_or(&change.path)
                        .to_string_lossy()
                        .to_string();

                    if self.options.call_graph_enabled {
                        if let Some(call_graph) = self.call_graphs.get(&repo_name) {
                            call_graph.remove_file(&rel_path);
                        }
                    }

                    // Remove symbols for this file
                    if let Some(mut symbols) = self.symbols.get_mut(&repo_name) {
                        symbols.retain(|s| s.file_path != rel_path);
                    }

                    // Remove from file cache
                    self.file_cache.remove(&change.path);

                    // Smart cache invalidation - only invalidate entries that depend on this file
                    self.query_cache.invalidate_for_file(&rel_path);

                    info!("Removed file from index: {}", rel_path);
                    pending
                        .entry(repo_name.clone())
                        .or_default()
                        .deletes
                        .push(change.path.clone());
                    count += 1;
                }
            }
        }

        // Persist only the repos that changed, each in a single redb write
        // transaction. Untouched repos (e.g. the kernel tree) are never opened.
        if self.options.persist_enabled {
            if let Some(store) = &self.index_store {
                for (repo_name, repo_pending) in &pending {
                    if let Err(e) = store.apply_file_changes(
                        &PathBuf::from(repo_name),
                        &repo_pending.upserts,
                        &repo_pending.deletes,
                    ) {
                        warn!("Failed to persist index changes for {}: {}", repo_name, e);
                    }
                }
            }
        }

        // Bring the gtags peer backend in sync for every repo whose C/C++ sources
        // changed — once per repo, since the watcher already debounces/batches.
        // Only pay for a full-tree `global -u` when the DB is actually behind the
        // changed sources (or one was deleted); the refresh itself is debounced.
        for (repo_path, changed) in &gtags_dirty {
            let any_deleted = changed.iter().any(|p| !p.exists());
            if any_deleted || gtags_database_stale(repo_path, changed) {
                self.refresh_gtags_if_active(repo_path).await;
            } else {
                debug!(
                    "gtags: {:?} already current vs {} changed source(s); skip global -u",
                    repo_path,
                    changed.len()
                );
            }
        }

        // Augment changed C/C++ file symbols from gtags, now that global -u has
        // run and the GTAGS database reflects the current sources. Mirrors
        // index_repo phase 3 for the incremental path.
        if let Some(gtags) = &self.gtags_manager {
            for (repo_path, changed) in &gtags_dirty {
                if !self.gtags_repo_enabled(repo_path) {
                    continue;
                }
                let repo_name = match canonical_repo_key(repo_path) {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                for abs_path in changed {
                    if !abs_path.exists() {
                        continue; // deleted — symbols already removed above
                    }
                    let rel_path = abs_path
                        .strip_prefix(repo_path)
                        .unwrap_or(abs_path)
                        .to_string_lossy()
                        .to_string();
                    let gtags_syms: Vec<Symbol> = gtags
                        .list_file_symbols(abs_path, repo_path)
                        .await
                        .into_iter()
                        .map(|(name, line)| Symbol {
                            name,
                            kind: SymbolKind::Unknown,
                            file_path: rel_path.clone(),
                            start_line: line,
                            end_line: line,
                            signature: None,
                            qualified_name: None,
                            doc_comment: None,
                            confirmed_by: SourceSet::GTAGS,
                            line_conflicts: Vec::new(),
                        })
                        .collect();
                    if gtags_syms.is_empty() {
                        continue;
                    }
                    if let Some(mut symbols) = self.symbols.get_mut(&repo_name) {
                        // Extract the file's current symbols (tree-sitter + LSP),
                        // merge gtags in, then put the merged set back.
                        let mut file_syms: Vec<Symbol> = symbols
                            .iter()
                            .filter(|s| s.file_path == rel_path)
                            .cloned()
                            .collect();
                        merge_symbols(&mut file_syms, gtags_syms, SourceSet::GTAGS);
                        symbols.retain(|s| s.file_path != rel_path);
                        symbols.extend(file_syms);
                    }
                }
            }
        }

        // Re-measure only when something was actually re-indexed (a lone
        // compile_commands.json restart that touches no sources leaves count 0).
        if count > 0 {
            self.refresh_memory_snapshot();
        }

        Ok(count)
    }

    // === Git Integration Methods ===

    /// Get git blame for a file
    pub async fn get_blame(
        &self,
        repo: &str,
        path: &str,
        start_line: Option<usize>,
        end_line: Option<usize>,
        revision: Option<&str>,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        // Validate path to prevent traversal attacks. At a revision the file
        // may no longer exist in the working tree.
        match revision {
            Some(_) => validate_pathspec(path)?,
            None => {
                validate_path(&repo_path, path)?;
            }
        }

        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let blame = match (start_line, end_line) {
            (Some(start), Some(end)) => git_repo.blame_range(path, start, end, revision)?,
            _ => git_repo.blame(path, revision)?,
        };

        Ok(git_repo.blame_markdown(&blame))
    }

    /// Get git history for a file
    pub async fn get_file_history(
        &self,
        repo: &str,
        path: &str,
        max_commits: usize,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        // Validate path to prevent traversal attacks
        validate_path(&repo_path, path)?;

        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let history = git_repo.file_history(path, max_commits)?;
        Ok(git_repo.history_markdown(&history))
    }

    /// Get commits that modified a specific symbol/function
    pub async fn get_symbol_history(
        &self,
        repo: &str,
        path: &str,
        symbol: &str,
        max_commits: usize,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        // `git log -S` needs a pathspec, and an empty one is an error rather
        // than "search everywhere". The index knows where the symbol lives, so
        // ask it instead of scanning the whole history of a large tree.
        let paths = if path.is_empty() {
            let files = self.symbol_files(&repo_key, symbol);
            if files.is_empty() {
                return Err(anyhow!(
                    "No indexed file defines '{}' in {}. Pass 'path' to search a \
                     specific file, or find the symbol first with find_symbols.",
                    symbol,
                    repo_key
                ));
            }
            files
        } else {
            // Validate path to prevent traversal attacks
            validate_path(&repo_path, path)?;
            vec![path.to_string()]
        };

        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let history = git_repo.symbol_history(&paths, symbol, max_commits)?;
        let mut output = git_repo.history_markdown(&history);
        if path.is_empty() {
            // The caller named no file, so say which ones the answer covers —
            // an empty history is otherwise indistinguishable from a miss.
            output.push_str(&format!("\n**Files searched**: {}\n", paths.join(", ")));
        }
        Ok(output)
    }

    /// Repo-relative files where `symbol` is indexed.
    fn symbol_files(&self, repo_key: &str, symbol: &str) -> Vec<String> {
        let Some(symbols) = self.symbols.get(repo_key) else {
            return Vec::new();
        };
        let mut files: Vec<String> = symbols
            .value()
            .iter()
            .filter(|indexed| indexed.name == symbol)
            .map(|indexed| indexed.file_path.clone())
            .collect();
        files.sort();
        files.dedup();
        files
    }

    /// Get the diff for a specific commit
    pub async fn get_commit_diff(
        &self,
        repo: &str,
        commit: &str,
        path: Option<&str>,
        max_bytes: Option<usize>,
        context_lines: Option<usize>,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        // A commit's path is a pathspec, not a file that has to exist now: the
        // commit may be the one that deletes it.
        if let Some(p) = path {
            validate_pathspec(p)?;
        }

        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let diff = git_repo.commit_diff(commit, path, context_lines)?;
        let files = split_diff_by_file(&diff);

        let mut output = String::new();
        output.push_str(&format!("# Commit Diff: `{}`\n\n", commit));
        if let Some(p) = path {
            output.push_str(&format!("**File**: `{}`\n\n", p));
        }
        output.push_str(&format!("**Files changed**: {}\n\n", files.len()));
        for file in &files {
            output.push_str(&format!("- `{}` ({} bytes)\n", file.path, file.text.len()));
        }
        output.push('\n');

        // A caller putting two commits in one answer needs to ask for less than
        // the whole budget; under MIN_COMMIT_DIFF_BYTES a diff carries nothing.
        let cap = max_bytes
            .unwrap_or(response_budget::MAX_RESPONSE_BYTES)
            .clamp(MIN_COMMIT_DIFF_BYTES, response_budget::MAX_RESPONSE_BYTES);

        // Whole file sections only: a cut inside a hunk loses the files behind
        // it without trace. Leave room for the header above and the footer below.
        let budget = cap.saturating_sub(output.len() + 2048);
        let mut used = 0;
        let mut shown = 0;
        let mut cut_inside = None;
        output.push_str("```diff\n");
        for file in &files {
            let room = budget.saturating_sub(used);
            if file.text.len() > room {
                // One file bigger than the whole budget: show its head rather
                // than nothing, cut on a line boundary.
                if shown == 0 {
                    let head = response_budget::truncate_on_char_boundary(file.text, room);
                    output.push_str(&head[..head.rfind('\n').map_or(head.len(), |nl| nl + 1)]);
                    cut_inside = Some(file.path);
                    shown = 1;
                }
                break;
            }
            output.push_str(file.text);
            used += file.text.len();
            shown += 1;
        }
        if !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str("```\n");

        if let Some(cut) = cut_inside {
            output.push_str(&format!(
                "\n*`{}` alone exceeds the {} KB budget and is cut above.*\n",
                cut,
                cap / 1024
            ));
        }

        if shown < files.len() {
            output.push_str("\n## Files not shown\n\n");
            for file in &files[shown..] {
                output.push_str(&format!("- `{}` ({} bytes)\n", file.path, file.text.len()));
            }
            output.push_str(&format!(
                "\n*Showing {} of {} files. One file at a time: \
                 get_commit_diff(commit=\"{}\", path=\"{}\").*\n",
                shown,
                files.len(),
                commit,
                files[shown].path
            ));
        }

        Ok(output)
    }

    /// Get current branch and repository status
    pub async fn get_branch_info(
        &self,
        repo: &str,
        window: response_budget::ListWindow,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let branch = git_repo.current_branch()?;
        let modified = git_repo.modified_files()?;
        // Best-effort: no upstream (detached HEAD / no tracking branch) is a
        // normal state, not an error, so a failure here must not sink the call.
        let upstream = git_repo.upstream_info().ok().flatten();

        let mut output = String::new();
        output.push_str(&format!("# Git Status: {}\n\n", repo_key));
        output.push_str(&format!("**Current Branch**: `{}`\n", branch));
        match &upstream {
            Some(up) => {
                output.push_str(&format!("**Upstream**: `{}`\n", up.upstream));
                output.push_str(&format!(
                    "**Ahead**: {} | **Behind**: {}\n",
                    up.ahead, up.behind
                ));
            }
            None => output.push_str("**Upstream**: *none (no tracking branch)*\n"),
        }
        output.push_str(&format!("**Modified Files**: {}\n\n", modified.len()));

        if !modified.is_empty() {
            output.push_str("## Working Tree Changes\n\n");
            let (page, capped) = response_budget::cap(&modified, window, "get_branch_info");
            for file in page {
                output.push_str(&format!("- `{}`\n", file));
            }
            if capped.truncated() {
                output.push('\n');
                output.push_str(&capped.footer());
            }
        } else {
            output.push_str("*No changes in working tree*\n");
        }

        if let Some(up) = &upstream {
            if !up.unpushed.is_empty() {
                output.push_str("\n## Unpushed Commits\n\n");
                let (page, capped) = response_budget::cap(&up.unpushed, window, "get_branch_info");
                for commit in page {
                    output.push_str(&format!("- {}\n", commit));
                }
                if capped.truncated() {
                    output.push('\n');
                    output.push_str(&capped.footer());
                }
            }
        }

        Ok(output)
    }

    /// Get list of modified files in working tree
    pub async fn get_modified_files(&self, repo: &str) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let modified = git_repo.modified_files()?;

        let mut output = String::new();
        output.push_str(&format!("# Modified Files in {}\n\n", repo_key));
        output.push_str(&format!("Found {} modified files\n\n", modified.len()));

        if !modified.is_empty() {
            for file in &modified {
                output.push_str(&format!("- `{}`\n", file));
            }
        } else {
            output.push_str("*No changes in working tree*\n");
        }

        Ok(output)
    }

    /// Get recent changes across the repository
    pub async fn get_recent_changes(&self, repo: &str, days: u32) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let changes = git_repo.recent_changes(days)?;

        let mut output = String::new();
        output.push_str(&format!("# Recent Changes (last {} days)\n\n", days));
        output.push_str(&format!("Found {} commits\n\n", changes.len()));

        for commit in changes.iter().take(20) {
            output.push_str(&format!(
                "- `{}` {} - {} (+{} -{})\n",
                commit.short_hash,
                commit.subject,
                commit.author,
                commit.insertions,
                commit.deletions
            ));
        }

        Ok(output)
    }

    pub async fn get_commit_range(
        &self,
        repo: &str,
        base: &str,
        branch: &str,
        include_body: bool,
        window: response_budget::ListWindow,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!("Git not available for {}. Enable with --git flag.", repo_key)
        })?;
        let range = git_repo.commit_range(base, branch, include_body, window)?;
        let mut output = format!(
            "# Commits in `{base}..{branch}`\n\nMerge base: `{}`\n\nFound {} commits (oldest first)\n\n",
            range.merge_base, range.total
        );
        for commit in &range.commits {
            output.push_str(&format!("- `{}` {}\n", commit.hash, commit.subject));
            if include_body && !commit.body.is_empty() {
                for line in commit.body.lines() {
                    output.push_str(&format!("  {line}\n"));
                }
                output.push('\n');
            }
        }
        let page = response_budget::ListCap {
            tool: "get_commit_range",
            total: range.total,
            shown: range.commits.len(),
            offset: window.offset.min(range.total),
        };
        output.push_str(&page.footer());
        Ok(output)
    }

    /// Get code hotspots (complex + frequently changed)
    pub async fn get_hotspots(
        &self,
        repo: &str,
        days: u32,
        _min_complexity: Option<usize>,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let freq = git_repo.change_frequency(days)?;

        let mut output = String::new();
        output.push_str(&format!("# Code Hotspots (last {} days)\n\n", days));
        output.push_str("Files with high change frequency (potential maintenance burden):\n\n");

        output.push_str("| File | Commits | Authors | Churn Score |\n");
        output.push_str("|------|---------|---------|-------------|\n");

        for item in freq.iter().take(20) {
            output.push_str(&format!(
                "| `{}` | {} | {} | {:.2} |\n",
                item.file_path, item.total_commits, item.unique_authors, item.churn_score
            ));
        }

        Ok(output)
    }

    /// Get contributors to a file or repository
    pub async fn get_contributors(
        &self,
        repo: &str,
        path: Option<&str>,
        window: response_budget::ListWindow,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        // Validate path to prevent traversal attacks
        if let Some(p) = path {
            validate_path(&repo_path, p)?;
        }

        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let mut output = String::new();

        match path {
            Some(p) => {
                output.push_str(&format!("# Contributors to `{}`\n\n", p));
                let contributors = git_repo.file_contributors(p)?;

                if contributors.is_empty() {
                    output.push_str("*No contributors found for this file.*\n");
                } else {
                    render_contributors(&contributors, window, &mut output);
                }
            }
            None => {
                output.push_str(&format!("# Repository Contributors: {}\n\n", repo));
                let contributors = git_repo.repo_contributors()?;

                if contributors.is_empty() {
                    output.push_str("*No contributors found.*\n");
                } else {
                    output.push_str(&format!(
                        "**Total contributors**: {}\n\n",
                        contributors.len()
                    ));
                    render_contributors(&contributors, window, &mut output);
                }
            }
        }

        Ok(output)
    }

    // === Repository Discovery ===

    /// Discover repositories in a directory
    pub async fn discover_repos(&self, base_path: &str, max_depth: usize) -> Result<String> {
        let path = std::path::Path::new(base_path);
        let repos = crate::repo::discover_repos(path, max_depth)?;

        let mut output = String::new();
        output.push_str(&format!("# Discovered Repositories in `{}`\n\n", base_path));
        output.push_str(&format!(
            "Found {} repositories (max depth: {})\n\n",
            repos.len(),
            max_depth
        ));

        for repo_path in &repos {
            let name = crate::repo::repo_name_from_path(repo_path);
            output.push_str(&format!("- **{}** - `{}`\n", name, repo_path.display()));
        }

        if repos.is_empty() {
            output.push_str("*No repositories found.*\n");
        }

        Ok(output)
    }

    /// Validate a repository path
    pub async fn validate_repo(&self, path: &str) -> Result<String> {
        let repo_path = std::path::Path::new(path);

        match crate::repo::validate_repo_path(repo_path) {
            Ok(_) => {
                let is_repo = crate::repo::is_repository(repo_path);
                let name = crate::repo::repo_name_from_path(repo_path);

                let mut output = String::new();
                output.push_str(&format!("# Repository Validation: `{}`\n\n", path));
                output.push_str(&format!("**Name**: {}\n", name));
                output.push_str(&format!("**Path**: {}\n", repo_path.display()));
                output.push_str(&format!(
                    "**Is Repository**: {}\n",
                    if is_repo {
                        "Yes"
                    } else {
                        "No (no VCS or project markers detected)"
                    }
                ));
                output.push_str("**Readable**: Yes\n");

                if is_repo {
                    output.push_str("\nThis path can be indexed with `--repos` flag.\n");
                } else {
                    output.push_str("\nWarning: No VCS (.git) or project markers detected. It may still be indexable but might not be a proper repository.\n");
                }

                Ok(output)
            }
            Err(e) => {
                let mut output = String::new();
                output.push_str(&format!("# Repository Validation: `{}`\n\n", path));
                output.push_str("**Status**: Invalid\n\n");
                output.push_str(&format!("**Error**: {}\n", e));
                Ok(output)
            }
        }
    }

    /// Walk every in-memory subsystem and return a heap breakdown. Sizes the
    /// engine-owned collections (symbols, file_cache, repos, git_repos) here and
    /// delegates to each subsystem's `heap_bytes()` for the rest. Sizes are
    /// estimates from container capacities and owned allocations — see
    /// [`MemoryReport`].
    pub fn memory_report(&self) -> MemoryReport {
        use crate::metrics::hashmap_table_bytes;

        // symbols: DashMap<String, Vec<Symbol>>
        let symbols = hashmap_table_bytes::<String, Vec<Symbol>>(self.symbols.len())
            + self
                .symbols
                .iter()
                .map(|entry| {
                    entry.key().capacity()
                        + entry.value().capacity() * std::mem::size_of::<Symbol>()
                        + entry.value().iter().map(Symbol::heap_bytes).sum::<usize>()
                })
                .sum::<usize>();

        // file_cache: DashMap<PathBuf, Arc<String>> — content is shared via Arc
        // but each entry holds a distinct file, so count each once.
        let file_cache = hashmap_table_bytes::<PathBuf, Arc<String>>(self.file_cache.len())
            + self
                .file_cache
                .iter()
                .map(|entry| entry.key().capacity() + entry.value().capacity())
                .sum::<usize>();

        // repos: DashMap<String, RepoMetadata>
        let repos = hashmap_table_bytes::<String, RepoMetadata>(self.repos.len())
            + self
                .repos
                .iter()
                .map(|entry| {
                    let meta = entry.value();
                    entry.key().capacity()
                        + meta.name.capacity()
                        + meta.path.capacity()
                        + hashmap_table_bytes::<String, LanguageStats>(meta.languages.capacity())
                        + meta.languages.keys().map(String::capacity).sum::<usize>()
                        + meta.head_hash.as_ref().map_or(0, String::capacity)
                        + meta.cdb_hash.as_ref().map_or(0, String::capacity)
                        + meta.cdb_head_hash.as_ref().map_or(0, String::capacity)
                })
                .sum::<usize>();

        // git_repos: DashMap<String, GitRepo> — only the keys are tracked;
        // libgit2 keeps its own buffers that are invisible here.
        let git_repos = hashmap_table_bytes::<String, GitRepo>(self.git_repos.len())
            + self
                .git_repos
                .iter()
                .map(|entry| entry.key().capacity())
                .sum::<usize>();

        // call_graphs: DashMap<String, CallGraph>
        let call_graphs = hashmap_table_bytes::<String, CallGraph>(self.call_graphs.len())
            + self
                .call_graphs
                .iter()
                .map(|entry| entry.key().capacity() + entry.value().heap_bytes())
                .sum::<usize>();

        MemoryReport {
            symbols,
            search_index: self.search_index.inner.read().heap_bytes(),
            embeddings: self.embedding_engine.heap_bytes(),
            file_cache,
            call_graphs,
            repos,
            git_repos,
            process_rss: Self::process_rss_bytes(),
        }
    }

    /// Resident set size in bytes from the `VmRSS:` line of /proc/self/status
    /// (already in kB, so no page-size lookup is needed). None when the file is
    /// unavailable (non-Linux).
    fn process_rss_bytes() -> Option<usize> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb: usize = rest.split_whitespace().next()?.parse().ok()?;
                return Some(kb * 1024);
            }
        }
        None
    }

    /// Release freed heap back to the kernel. glibc keeps the indexing
    /// high-water mark in its arenas; malloc_trim(0) returns the unused top so
    /// RSS tracks the live working set. glibc/Linux only — a no-op on
    /// musl/macOS/wasm, which lack malloc_trim.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn return_freed_heap_to_os() {
        extern "C" {
            fn malloc_trim(pad: usize) -> std::os::raw::c_int;
        }
        // SAFETY: malloc_trim is safe to call at any point; it only walks the
        // allocator's free lists and may madvise unused pages away.
        unsafe {
            malloc_trim(0);
        }
    }

    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    fn return_freed_heap_to_os() {}

    /// Re-measure the live heap and hand it to metrics so the next flush
    /// persists an up-to-date snapshot. Called after a runtime re-index changes
    /// the in-memory subsystems. `memory_report()` walks every DashMap, so this
    /// is only invoked on actual re-index events, never on a timer. Trims first
    /// so the persisted RSS reflects the reclaimed working set.
    fn refresh_memory_snapshot(&self) {
        Self::return_freed_heap_to_os();
        self.metrics.set_memory_report(self.memory_report());
    }

    /// Get status of the search index
    pub async fn get_index_status(&self, repo: Option<&str>) -> Result<String> {
        // An unknown repo is an error: answering with every other repo's
        // status read as if the requested one were indexed or absent.
        let repo_filter: Option<String> = match repo {
            Some(r) if !r.is_empty() => Some(self.resolve_repo(r)?),
            _ => None,
        };

        let mut output = String::new();
        output.push_str("# Index Status\n\n");

        // Initialization status (critical for editors like Zed)
        let init_status = self.get_initialization_status();
        let is_initialized = init_status
            .get("is_initialized")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let indexed_repos = init_status
            .get("indexed_repos")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let total_repos = init_status
            .get("total_repos")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let progress = init_status
            .get("progress_percentage")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        output.push_str("## Initialization Status\n\n");
        output.push_str(&format!(
            "- **Status**: {}\n",
            if is_initialized {
                "✓ Complete"
            } else {
                "⏳ In Progress"
            }
        ));
        output.push_str(&format!(
            "- **Progress**: {}/{} repositories ({}%)\n\n",
            indexed_repos, total_repos, progress
        ));

        // Server-wide sections would bury the one repo section asked for.
        if repo_filter.is_none() {
            let stats = self.search_index.stats();
            output.push_str(&format!("**Total Documents**: {}\n", stats.total_documents));
            output.push_str(&format!("**Total Terms**: {}\n", stats.total_terms));
            output.push_str(&format!(
                "**Avg Document Length**: {:.1} tokens\n\n",
                stats.avg_doc_length
            ));

            // Feature flags section
            output.push_str("## Enabled Features\n\n");
            output.push_str(&format!(
                "- **Git integration**: {}\n",
                if self.options.git_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ));
            output.push_str(&format!(
                "- **Call graph analysis**: {}\n",
                if self.options.call_graph_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ));
            output.push_str(&format!(
                "- **Index persistence**: {}\n",
                if self.options.persist_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ));
            output.push_str(&format!(
                "- **Watch mode**: {}\n\n",
                if self.options.watch_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ));

            output.push_str("## Document Types\n\n");
            for (doc_type, count) in &stats.doc_types {
                output.push_str(&format!("- {:?}: {}\n", doc_type, count));
            }
        }

        output.push_str("\n## Repositories\n\n");
        for entry in self.repos.iter() {
            let meta = entry.value();
            let key = entry.key();
            if repo_filter.as_deref().is_none_or(|f| f == key) {
                output.push_str(&format!("### {}\n", meta.name));
                output.push_str(&format!("- Repo: `{}`\n", key));
                output.push_str(&format!("- Files: {}\n", meta.file_count));
                output.push_str(&format!(
                    "- Symbols: {}\n",
                    self.symbols.get(key).map(|s| s.len()).unwrap_or(0)
                ));
                output.push_str(&format!(
                    "- Git: {}\n",
                    if self.git_repos.contains_key(key) {
                        "enabled"
                    } else {
                        "disabled"
                    }
                ));
                // A manifest older than HEAD still drives the index filter; say
                // so, since the widening cannot restore the missing compile flags.
                if let Some(base) = meta.cdb_head_hash.as_deref() {
                    if meta.head_hash.as_deref() != Some(base) {
                        let behind = GitRepo::new(&meta.path)
                            .ok()
                            .and_then(|r| r.commits_since(base))
                            .unwrap_or(0);
                        output.push_str(&format!(
                            "- compile_commands.json: generated at {}, HEAD is {} \
                             ({} commit(s) behind) — regenerate it for accurate C/C++ flags\n",
                            short_hash(base),
                            meta.head_hash.as_deref().map(short_hash).unwrap_or("?"),
                            behind
                        ));
                    }
                }
                if let Some((regions, files)) = self
                    .call_graphs
                    .get(key)
                    .and_then(|cg| cg.degraded_summary())
                {
                    output.push_str(&format!(
                        "- Call graph: {} unparsed region(s) across {} file(s) — \
                         see get_callers/get_callees for detail\n",
                        regions, files
                    ));
                }
                output.push('\n');
            }
        }

        match &repo_filter {
            // Registered, but its first index pass has not finished.
            Some(key) if !self.repos.contains_key(key) => {
                output.push_str(&format!("### {}\n- Not indexed yet\n\n", key));
            }
            Some(_) => {}
            None => output.push_str(&self.memory_report().render_markdown()),
        }

        Ok(output)
    }

    // === Semantic Search ===

    /// Perform semantic code search using BM25 ranking
    pub async fn semantic_search(
        &self,
        repo: Option<&str>,
        query: &str,
        max_results: usize,
        _doc_type: Option<&str>,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::extract::is_test_file;

        // Build cache key from query parameters
        let cache_key = {
            let options = SearchOptions {
                file_pattern: None,
                max_results: Some(max_results),
                exclude_tests,
                mode: None,
            };
            QueryCacheKey::code_search_with_options(repo, format!("semantic:{}", query), &options)
        };

        // Check cache first
        if self.options.cache_enabled {
            if let Some(cached) = self.query_cache.get(&cache_key) {
                return Ok(cached);
            }
        }

        let exclude_tests = exclude_tests.unwrap_or(false); // Default false for search

        // Validate repo if specified
        let repo_key = if let Some(r) = repo {
            if !r.is_empty() {
                Some(self.resolve_repo(r)?)
            } else {
                None
            }
        } else {
            None
        };
        let repo_name = repo_key.as_deref();

        // A file that has been re-indexed is in the search index once per
        // generation, so the same location comes back several times. Drop the
        // repeats before the cap — results are score-ordered, so the first copy
        // of a location is its best-scoring one.
        let mut seen_locations = std::collections::HashSet::new();
        let results: Vec<_> = self
            .search_index
            .search(query, max_results * 8) // Enough to survive filtering and dedup
            .into_iter()
            .filter(|r| repo_name.is_none_or(|rn| r.document.repo == rn))
            .filter(|r| !exclude_tests || !is_test_file(&r.document.file_path))
            .filter(|r| {
                seen_locations.insert((
                    r.document.repo.clone(),
                    r.document.file_path.clone(),
                    r.document.start_line,
                    r.document.end_line,
                ))
            })
            .take(max_results)
            .collect();

        // Collect dependent files for smart invalidation
        let dependent_files: Vec<String> = results
            .iter()
            .map(|r| r.document.file_path.clone())
            .collect();

        let mut output = String::new();
        let repo_paths = self.registered_repo_paths();
        output.push_str(&format!("# Semantic Search: `{}`\n\n", query));
        if let Some(r) = repo_name {
            output.push_str(&format!("Repository: {}\n", r));
        }
        output.push_str(&format!("Found {} results\n\n", results.len()));

        for (i, result) in results.iter().enumerate() {
            output.push_str(&format!(
                "## {}. {} (score: {:.2})\n",
                i + 1,
                result.document.file_path,
                result.score
            ));
            // A whole-file document covers the file; the caller needs the lines
            // that matched, which is the window the snippet is taken from.
            // snippet is empty for the persistent index (content is None there);
            // regenerate from file_cache — O(num_repos) lookup per top-N result
            let regenerated = repo_paths.iter().find_map(|rp| {
                self.file_cache
                    .get(&rp.join(&result.document.file_path))
                    .map(|entry| {
                        crate::search::snippet_with_range(entry.value(), &result.matched_terms)
                    })
            });

            let whole_file = result.document.doc_type == crate::search::DocType::File;
            let (start_line, end_line) = match (&regenerated, whole_file) {
                (Some((start, end, _)), true) => (*start, *end),
                _ => (result.document.start_line, result.document.end_line),
            };
            output.push_str(&format!("Lines {}-{}\n\n", start_line, end_line));

            let snippet = if result.snippet.is_empty() {
                regenerated.map(|(_, _, text)| text).unwrap_or_default()
            } else {
                result.snippet.clone()
            };
            output.push_str("```\n");
            output.push_str(&snippet);
            output.push_str("\n```\n\n");
        }

        if results.is_empty() {
            output.push_str("*No results found.*\n");
        }

        // Cache the result with file dependencies for smart invalidation
        if self.options.cache_enabled {
            self.query_cache
                .insert_with_files(cache_key, output.clone(), dependent_files);
        }

        Ok(output)
    }

    // === Call Graph Methods ===

    /// Get the call graph for a function
    ///
    /// Results are cached for performance. Cache is invalidated when files change.
    pub async fn get_call_graph(
        &self,
        repo: &str,
        function: &str,
        _depth: usize,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        let exclude_tests = exclude_tests.unwrap_or(false);

        let repo = self.resolve_repo(repo)?;

        if !self.is_fully_initialized() {
            return Err(anyhow!(
                "Call graph not yet available — initialization in progress. \
                 Please retry in a moment."
            ));
        }

        // Build cache key with function as discriminator
        let cache_key = AnalysisCacheKey::with_discriminator(
            &repo,
            "call_graph",
            format!("{}|{}", function, exclude_tests),
        );

        // Compute repo hash for invalidation
        let repo_hash = self.compute_repo_hash(&repo);

        // Check cache first
        if self.options.cache_enabled {
            if let Some(cached) = self
                .analysis_cache
                .get_if_hash_matches(&cache_key, &repo_hash)
            {
                return Ok(cached);
            }
        }

        let call_graph = self.call_graphs.get(&repo).ok_or_else(|| {
            anyhow!(
                "Call graph not found for '{}'. Is --call-graph enabled?",
                repo
            )
        })?;

        // Empty string means show summary (None), otherwise look up specific function
        let func_option = if function.is_empty() {
            None
        } else {
            Some(function)
        };
        let mut result = call_graph.to_markdown(func_option, exclude_tests);
        result.push_str(&degraded_note(&call_graph));

        // Cache the result
        if self.options.cache_enabled {
            self.analysis_cache
                .insert_with_hash(cache_key, result.clone(), Some(repo_hash));
        }

        Ok(result)
    }

    /// Find the symbol (function/method) in `repo` whose body contains `file:line`.
    /// Used to map an LSP reference location back to a caller name.
    fn enclosing_function_at<'a>(
        symbols: &'a [Symbol],
        file: &str,
        line: usize,
    ) -> Option<&'a Symbol> {
        // Tightest range wins. A prototype recorded with an overlong range
        // otherwise claims lines that belong to the function below it.
        symbols
            .iter()
            .filter(|sym| {
                matches!(sym.kind, SymbolKind::Function | SymbolKind::Method)
                    && sym.file_path == file
                    && sym.start_line <= line
                    && line <= sym.end_line
            })
            .min_by_key(|sym| sym.end_line.saturating_sub(sym.start_line))
    }

    /// Whether an LSP reference at `file:line` is a call rather than the
    /// definition or a declaration of `function`.
    ///
    /// `textDocument/references` reports both, and ccls additionally reports a
    /// reference under a header that includes the translation unit, keeping the
    /// line number of the file the reference really came from — so the named
    /// line does not contain the function at all.
    fn reference_is_a_call(
        symbols: &[Symbol],
        function: &str,
        file: &str,
        line: usize,
        source_line: &str,
    ) -> bool {
        if !source_line.contains(function) {
            return false;
        }

        !symbols
            .iter()
            .any(|sym| sym.name == function && sym.file_path == file && sym.start_line == line)
    }

    /// Get callers of a function.
    ///
    /// When LSP is enabled and the queried function lives in a C/C++ file, LSP
    /// `textDocument/references` results are merged with the AST-based call graph
    /// to produce the most complete caller list. Each edge is tagged with its
    /// source (`[LSP]`, `[ast]`, or confirmed by both).
    pub async fn get_callers(
        &self,
        repo: &str,
        function: &str,
        transitive: bool,
        max_depth: usize,
        exclude_tests: Option<bool>,
        window: response_budget::ListWindow,
    ) -> Result<String> {
        use crate::callgraph::file_of_key;
        use crate::extract::is_test_file;

        let repo = self.resolve_repo(repo)?;
        let exclude_tests = exclude_tests.unwrap_or(false);

        if function.trim().is_empty() {
            return Err(anyhow!(
                "get_callers requires a non-empty 'function' argument (the function/symbol name)"
            ));
        }

        if !self.is_fully_initialized() {
            return Err(anyhow!(
                "Call graph not yet available — initialization in progress. \
                 Please retry in a moment."
            ));
        }

        // The window is part of the key: the rendered page is what gets cached,
        // so a limit=0 caller must not be served a 50-item answer.
        let cache_key = AnalysisCacheKey::with_discriminator(
            &repo,
            "callers_hybrid",
            format!(
                "{}|{}|{}|{}",
                function, window.offset, window.limit, exclude_tests
            ),
        );
        let repo_hash = self.compute_repo_hash(&repo);
        if self.options.cache_enabled {
            if let Some(cached) = self
                .analysis_cache
                .get_if_hash_matches(&cache_key, &repo_hash)
            {
                return Ok(cached);
            }
        }

        let call_graph = self.call_graphs.get(&repo).ok_or_else(|| {
            anyhow!(
                "Call graph not found for '{}'. Is --call-graph enabled?",
                repo
            )
        })?;

        let mut output = String::new();
        output.push_str(&format!("# Callers of `{}`\n\n", function));
        output.push_str(&ambiguity_note(&call_graph, function));
        output.push_str(&degraded_note(&call_graph));

        if transitive {
            let mut callers = call_graph.get_transitive_callers(function, max_depth);
            if exclude_tests {
                callers.retain(|(key, _)| !is_test_file(file_of_key(key)));
            }
            output.push_str(&format!(
                "Found {} transitive callers (max depth: {})\n\n",
                callers.len(),
                max_depth
            ));
            let (page, capped) = response_budget::cap(&callers, window, "get_callers");
            for (name, depth) in page {
                output.push_str(&format!("- `{}` (depth: {})\n", name, depth));
            }
            if capped.truncated() {
                output.push('\n');
                output.push_str(&capped.footer());
            }
        } else {
            // Collect AST-derived callers.
            let mut callers: Vec<CallEdge> = call_graph.get_callers(function);

            // LSP augmentation for C/C++ when a language server is available.
            // `repo` here is already the canonical absolute path.
            let repo_path = PathBuf::from(&repo);
            if let (Some(lsp), false) = (&self.lsp_manager, transitive) {
                if lsp.is_enabled() {
                    if let Some(sym_list) = self.symbols.get(&repo) {
                        // Find the definition of the queried function to know its file/language.
                        let def_sym = sym_list.iter().find(|s| {
                            s.name == function || s.qualified_name.as_deref() == Some(function)
                        });
                        if let Some(def) = def_sym {
                            let lang = get_language_from_path(&def.file_path);
                            if lang == "c" || lang == "cpp" {
                                if let Some(lsp_refs) = self
                                    .lsp_search_references(&repo, function, &repo_path)
                                    .await
                                {
                                    let sym_slice: Vec<Symbol> = sym_list.iter().cloned().collect();
                                    let ast_keys: std::collections::HashSet<(String, usize)> =
                                        callers
                                            .iter()
                                            .map(|e| (e.file_path.clone(), e.line))
                                            .collect();

                                    // lsp_search_references merges all configured
                                    // C/C++ backends; tag agreement with the primary
                                    // backend's bit as a coarse "LSP-confirmed" marker.
                                    let lsp_bit = lsp
                                        .active_cxx_backends_for(&repo_path)
                                        .first()
                                        .copied()
                                        .unwrap_or(SourceSet::CLANGD);

                                    for (rel_path, ref_line, content) in &lsp_refs {
                                        let key = (rel_path.clone(), *ref_line);
                                        if !ast_keys.contains(&key)
                                            && !Self::reference_is_a_call(
                                                &sym_slice, function, rel_path, *ref_line, content,
                                            )
                                        {
                                            continue;
                                        }
                                        if ast_keys.contains(&key) {
                                            // Both sources agree — record the LSP confirmer.
                                            for edge in callers.iter_mut() {
                                                if edge.file_path == *rel_path
                                                    && edge.line == *ref_line
                                                {
                                                    edge.confirmed_by.insert(lsp_bit);
                                                }
                                            }
                                        } else {
                                            // LSP-only edge: resolve enclosing function.
                                            let caller_name = Self::enclosing_function_at(
                                                &sym_slice, rel_path, *ref_line,
                                            )
                                            .map(|s| s.name.clone())
                                            .unwrap_or_else(|| format!("<unknown>@{}", ref_line));

                                            callers.push(CallEdge {
                                                target: caller_name,
                                                file_path: rel_path.clone(),
                                                line: *ref_line,
                                                column: 0,
                                                call_type: CallType::Unknown,
                                                scope_hint: None,
                                                confirmed_by: lsp_bit,
                                                line_conflicts: Vec::new(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let mut callers = CallGraph::fold_duplicate_sites(callers);
            if exclude_tests {
                callers.retain(|edge| !is_test_file(&edge.file_path));
            }

            output.push_str(&format!("Found {} direct callers\n\n", callers.len()));
            let (page, capped) = response_budget::cap(&callers, window, "get_callers");
            for caller in page {
                let is_cxx = matches!(
                    get_language_from_path(&caller.file_path).as_str(),
                    "c" | "cpp"
                );
                let provenance = render_provenance(
                    ProvenanceSubject::CallEdge,
                    self.enabled_backends_for_repo(&repo_path, is_cxx),
                    caller.confirmed_by,
                    caller.line,
                    &caller.line_conflicts,
                )
                .map(|annotation| format!(" — {}", annotation))
                .unwrap_or_default();
                output.push_str(&format!(
                    "- `{}` at `{}:{}`{} ({:?})\n",
                    caller.target, caller.file_path, caller.line, provenance, caller.call_type
                ));
            }

            if capped.truncated() {
                let dropped = &callers[(capped.offset + capped.shown).min(callers.len())..];
                output.push_str("\n## Remaining callers by file\n\n");
                output.push_str(&response_budget::by_file_summary(
                    dropped,
                    |edge| edge.file_path.as_str(),
                    20,
                ));
                output.push('\n');
                output.push_str(&capped.footer());
            }
        }

        if output.ends_with("\n\n") {
            output.push_str("*No callers found.*\n");
        }

        if self.options.cache_enabled {
            self.analysis_cache
                .insert_with_hash(cache_key, output.clone(), Some(repo_hash));
        }

        Ok(output)
    }

    /// Get callees of a function.
    pub async fn get_callees(
        &self,
        repo: &str,
        function: &str,
        transitive: bool,
        max_depth: usize,
        exclude_tests: Option<bool>,
        window: response_budget::ListWindow,
    ) -> Result<String> {
        use crate::callgraph::file_of_key;
        use crate::extract::is_test_file;

        let repo = self.resolve_repo(repo)?;
        let exclude_tests = exclude_tests.unwrap_or(false);

        if function.trim().is_empty() {
            return Err(anyhow!(
                "get_callees requires a non-empty 'function' argument (the function/symbol name)"
            ));
        }

        if !self.is_fully_initialized() {
            return Err(anyhow!(
                "Call graph not yet available — initialization in progress. \
                 Please retry in a moment."
            ));
        }

        let cache_key = AnalysisCacheKey::with_discriminator(
            &repo,
            "callees_hybrid",
            format!(
                "{}|{}|{}|{}",
                function, window.offset, window.limit, exclude_tests
            ),
        );
        let repo_hash = self.compute_repo_hash(&repo);
        if self.options.cache_enabled {
            if let Some(cached) = self
                .analysis_cache
                .get_if_hash_matches(&cache_key, &repo_hash)
            {
                return Ok(cached);
            }
        }

        let call_graph = self.call_graphs.get(&repo).ok_or_else(|| {
            anyhow!(
                "Call graph not found for '{}'. Is --call-graph enabled?",
                repo
            )
        })?;

        let mut output = String::new();
        output.push_str(&format!("# Callees of `{}`\n\n", function));
        output.push_str(&ambiguity_note(&call_graph, function));
        output.push_str(&degraded_note(&call_graph));

        if transitive {
            let mut callees = call_graph.get_transitive_callees(function, max_depth);
            if exclude_tests {
                callees.retain(|(key, _)| !is_test_file(file_of_key(key)));
            }
            output.push_str(&format!(
                "Found {} transitive callees (max depth: {})\n\n",
                callees.len(),
                max_depth
            ));
            let (page, capped) = response_budget::cap(&callees, window, "get_callees");
            for (name, depth) in page {
                output.push_str(&format!("- `{}` (depth: {})\n", name, depth));
            }
            if capped.truncated() {
                output.push('\n');
                output.push_str(&capped.footer());
            }
        } else {
            let mut callees = CallGraph::fold_duplicate_sites(call_graph.get_callees(function));
            if exclude_tests {
                callees.retain(|edge| !is_test_file(file_of_key(&edge.target)));
            }
            output.push_str(&format!("Found {} direct callees\n\n", callees.len()));
            let (page, capped) = response_budget::cap(&callees, window, "get_callees");
            for callee in page {
                output.push_str(&format!(
                    "- `{}` at `{}:{}` ({:?})\n",
                    callee.target, callee.file_path, callee.line, callee.call_type
                ));
            }
            if capped.truncated() {
                let dropped = &callees[(capped.offset + capped.shown).min(callees.len())..];
                output.push_str("\n## Remaining callees by file\n\n");
                output.push_str(&response_budget::by_file_summary(
                    dropped,
                    |edge| edge.file_path.as_str(),
                    20,
                ));
                output.push('\n');
                output.push_str(&capped.footer());
            }
        }

        if output.ends_with("\n\n") {
            output.push_str("*No callees found.*\n");
        }

        if self.options.cache_enabled {
            self.analysis_cache
                .insert_with_hash(cache_key, output.clone(), Some(repo_hash));
        }

        Ok(output)
    }

    /// Find the call path between two functions
    pub async fn find_call_path(&self, repo: &str, from: &str, to: &str) -> Result<String> {
        let repo = self.resolve_repo(repo)?;

        if !self.is_fully_initialized() {
            return Err(anyhow!(
                "Call graph not yet available — initialization in progress. \
                 Please retry in a moment."
            ));
        }

        let call_graph = self.call_graphs.get(&repo).ok_or_else(|| {
            anyhow!(
                "Call graph not found for '{}'. Is --call-graph enabled?",
                repo
            )
        })?;

        let mut output = String::new();
        output.push_str(&format!("# Call Path: `{}` → `{}`\n\n", from, to));

        match call_graph.find_call_path(from, to) {
            Some(path) => {
                output.push_str(&format!("Found path with {} steps:\n\n", path.len() - 1));
                for (i, func) in path.iter().enumerate() {
                    if i > 0 {
                        output.push_str("  ↓\n");
                    }
                    output.push_str(&format!("{}. `{}`\n", i + 1, func));
                }
            }
            None => {
                output.push_str("*No path found between these functions.*\n");
            }
        }

        Ok(output)
    }

    /// Get complexity metrics for a function
    pub async fn get_complexity(&self, repo: &str, function: &str) -> Result<String> {
        let repo = self.resolve_repo(repo)?;

        if !self.is_fully_initialized() {
            return Err(anyhow!(
                "Call graph not yet available — initialization in progress. \
                 Please retry in a moment."
            ));
        }

        let call_graph = self.call_graphs.get(&repo).ok_or_else(|| {
            anyhow!(
                "Call graph not found for '{}'. Is --call-graph enabled?",
                repo
            )
        })?;

        let mut output = String::new();
        output.push_str(&format!("# Complexity Metrics: `{}`\n\n", function));

        match call_graph.get_metrics(function) {
            Some(metrics) => {
                output.push_str("| Metric | Value |\n");
                output.push_str("|--------|-------|\n");
                output.push_str(&format!("| Lines of Code | {} |\n", metrics.loc));
                output.push_str(&format!(
                    "| Cyclomatic Complexity | {} |\n",
                    metrics.cyclomatic
                ));
                output.push_str(&format!("| Max Nesting Depth | {} |\n", metrics.max_depth));
                output.push_str(&format!("| Parameters | {} |\n", metrics.params));
                output.push_str(&format!("| Return Points | {} |\n", metrics.returns));
                output.push_str(&format!(
                    "| Cognitive Complexity | {} |\n",
                    metrics.cognitive
                ));

                // Add health assessment
                output.push_str("\n## Health Assessment\n\n");
                if metrics.cyclomatic > 10 {
                    output.push_str("⚠️ **High cyclomatic complexity** - Consider refactoring into smaller functions.\n");
                } else if metrics.cyclomatic > 5 {
                    output.push_str("⚡ **Moderate complexity** - Function is manageable but could be simplified.\n");
                } else {
                    output.push_str("✅ **Low complexity** - Function is well-structured.\n");
                }

                if metrics.max_depth > 4 {
                    output.push_str("⚠️ **Deep nesting** - Consider early returns or extracting nested logic.\n");
                }
            }
            None => {
                output.push_str("*Function not found in call graph.*\n");
            }
        }

        Ok(output)
    }

    /// Get function hotspots (highly connected functions)
    pub async fn get_function_hotspots(
        &self,
        repo: &str,
        min_connections: usize,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::callgraph::file_of_key;
        use crate::extract::is_test_file;

        let exclude_tests = exclude_tests.unwrap_or(false);
        let repo = self.resolve_repo(repo)?;

        if !self.is_fully_initialized() {
            return Err(anyhow!(
                "Call graph not yet available — initialization in progress. \
                 Please retry in a moment."
            ));
        }

        let call_graph = self.call_graphs.get(&repo).ok_or_else(|| {
            anyhow!(
                "Call graph not found for '{}'. Is --call-graph enabled?",
                repo
            )
        })?;

        let default_limit = 50;
        let mut all_hotspots = call_graph.get_hotspots(min_connections);
        if exclude_tests {
            all_hotspots.retain(|(key, _, _)| !is_test_file(file_of_key(key)));
        }
        let total_count = all_hotspots.len();
        let mut hotspots = all_hotspots;
        hotspots.truncate(default_limit);

        let mut output = String::new();
        output.push_str(&format!(
            "# Function Hotspots in {} (min {} connections)\n\n",
            repo, min_connections
        ));

        if hotspots.is_empty() {
            output.push_str("*No hotspots found matching the criteria.*\n");
        } else {
            if total_count > hotspots.len() {
                output.push_str(&format!(
                    "Showing top {} of {} highly connected functions (generic trait methods filtered):\n\n",
                    hotspots.len(),
                    total_count
                ));
            } else {
                output.push_str(&format!(
                    "Found {} highly connected functions (generic trait methods filtered):\n\n",
                    hotspots.len()
                ));
            }
            output.push_str("| Function | Incoming | Outgoing | Total |\n");
            output.push_str("|----------|----------|----------|-------|\n");

            for (name, incoming, outgoing) in &hotspots {
                output.push_str(&format!(
                    "| `{}` | {} | {} | {} |\n",
                    name,
                    incoming,
                    outgoing,
                    incoming + outgoing
                ));
            }

            output.push_str("\n## Analysis\n\n");
            output.push_str(
                "Functions with many connections are potential refactoring candidates:\n",
            );
            output.push_str("- **High incoming**: Widely used, changes have broad impact\n");
            output.push_str("- **High outgoing**: Complex, depends on many other functions\n");
            output
                .push_str("- **High both**: Central to the codebase, requires careful attention\n");
        }

        Ok(output)
    }

    // === Excerpt Extraction ===

    /// Get an intelligent code excerpt with context
    pub async fn get_excerpt(
        &self,
        repo: &str,
        path: &str,
        match_lines: &[usize],
        config: crate::extract::ExcerptConfig,
    ) -> Result<String> {
        let repo_path = PathBuf::from(self.resolve_repo(repo)?);
        let file_path = validate_path(&repo_path, path)?;
        if file_path.is_dir() {
            return Err(anyhow!("'{}' is a directory, not a file", path));
        }

        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let excerpts = crate::extract::extract_excerpts(&content, match_lines, &config);
        let best = crate::extract::select_best_excerpt(&excerpts, 3);

        let mut output = String::new();
        output.push_str(&format!("# Code Excerpt: `{}`\n\n", path));
        output.push_str(&format!(
            "Extracted {} excerpt(s) from {} match line(s)\n\n",
            best.len(),
            match_lines.len()
        ));

        for (i, excerpt) in best.iter().enumerate() {
            output.push_str(&format!("## Excerpt {}\n", i + 1));
            output.push_str(&format!(
                "Lines {}-{} | Relevance: {:.2}\n\n",
                excerpt.start_line, excerpt.end_line, excerpt.relevance
            ));
            output.push_str("```");
            output.push_str(get_language_id(path));
            output.push('\n');
            output.push_str(&excerpt.content);
            output.push_str("\n```\n\n");
        }

        if best.is_empty() {
            output.push_str("*No excerpts could be extracted.*\n");
        }

        Ok(output)
    }

    // === Performance Metrics Methods ===

    /// Get performance metrics report including cache statistics
    pub async fn get_metrics(&self, format: &str) -> Result<String> {
        let cache_stats = self.cache_stats();

        if format == "json" {
            let mut json = self.metrics.report_json();
            // Add cache statistics to JSON
            json["cache"] = serde_json::json!({
                "enabled": self.options.cache_enabled,
                "ttl_seconds": self.options.cache_ttl_seconds,
                "hits": cache_stats.hits,
                "misses": cache_stats.misses,
                "hit_rate_percent": cache_stats.hit_rate(),
                "evictions": cache_stats.evictions,
                "expirations": cache_stats.expirations,
                "size": cache_stats.size,
                "capacity": cache_stats.capacity,
            });
            Ok(json.to_string())
        } else {
            let mut output = self.metrics.report();

            // Add cache statistics section
            output.push_str("\n## Analysis Cache\n\n");
            output.push_str(&format!(
                "**Status**: {}\n",
                if self.options.cache_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ));
            output.push_str(&format!(
                "**TTL**: {} seconds\n\n",
                self.options.cache_ttl_seconds
            ));

            output.push_str("| Metric | Value |\n");
            output.push_str("|--------|-------|\n");
            output.push_str(&format!("| Hits | {} |\n", cache_stats.hits));
            output.push_str(&format!("| Misses | {} |\n", cache_stats.misses));
            output.push_str(&format!("| Hit Rate | {:.2}% |\n", cache_stats.hit_rate()));
            output.push_str(&format!("| Evictions | {} |\n", cache_stats.evictions));
            output.push_str(&format!("| Expirations | {} |\n", cache_stats.expirations));
            output.push_str(&format!(
                "| Size | {} / {} |\n",
                cache_stats.size, cache_stats.capacity
            ));

            Ok(output)
        }
    }

    // === LSP Integration Methods ===

    /// Get hover information from LSP (type info, documentation, etc.)
    pub async fn get_hover_info(
        &self,
        repo: &str,
        path: &str,
        line: usize,
        character: usize,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        let file_path = validate_path(&repo_path, path)?;

        // Detect language from file extension
        let language = get_language_from_path(path);

        let mut output = String::new();
        output.push_str(&format!("# Hover Info: `{}`\n\n", path));
        output.push_str(&format!("**Position**: {}:{}\n\n", line, character));

        // Try LSP first if available
        if let Some(ref lsp) = self.lsp_manager {
            match lsp
                .get_hover(&language, &file_path, line as u32, character as u32)
                .await
            {
                Ok(Some(hover)) => {
                    output.push_str("## LSP Hover Information (LSP enhanced)\n\n");
                    output.push_str(&crate::lsp::hover_to_markdown(&hover));
                    output.push_str("\n\n");
                    return Ok(output);
                }
                Ok(None) => {
                    output.push_str("*No hover information available from LSP*\n\n");
                }
                Err(e) => {
                    output.push_str(&format!("*LSP error: {}*\n\n", e));
                }
            }
        }

        // Fallback to tree-sitter symbols
        output.push_str("## Symbol Information (tree-sitter)\n\n");
        let symbols = self
            .symbols
            .get(&repo_key)
            .ok_or_else(|| self.repo_not_found_error(&repo_key))?;

        // Find symbol at this location
        for symbol in symbols.iter() {
            if symbol.file_path == path && line >= symbol.start_line && line <= symbol.end_line {
                output.push_str(&format!("**Symbol**: {}\n", symbol.name));
                output.push_str(&format!("**Kind**: {:?}\n", symbol.kind));
                if let Some(sig) = &symbol.signature {
                    output.push_str(&format!("**Signature**: `{}`\n", sig));
                }
                if let Some(doc) = &symbol.doc_comment {
                    output.push_str(&format!("\n{}\n", doc));
                }
                break;
            }
        }

        Ok(output)
    }

    /// Get type information for a symbol (requires LSP)
    pub async fn get_type_info(
        &self,
        repo: &str,
        path: &str,
        line: usize,
        character: usize,
    ) -> Result<String> {
        let repo_path = PathBuf::from(self.resolve_repo(repo)?);
        let file_path = validate_path(&repo_path, path)?;
        let language = get_language_from_path(path);

        let mut output = String::new();
        output.push_str(&format!("# Type Information: `{}`\n\n", path));
        output.push_str(&format!("**Position**: {}:{}\n\n", line, character));

        if let Some(ref lsp) = self.lsp_manager {
            match lsp
                .get_hover(&language, &file_path, line as u32, character as u32)
                .await
            {
                Ok(Some(hover)) => {
                    output.push_str("## Type Information (LSP enhanced)\n\n");
                    output.push_str(&crate::lsp::hover_to_markdown(&hover));
                    return Ok(output);
                }
                Ok(None) => {
                    output.push_str("*No type information available from LSP*\n");
                }
                Err(e) => {
                    output.push_str(&format!("*LSP error: {}*\n", e));
                }
            }
        } else {
            output.push_str("*LSP not enabled. Use --lsp flag to enable type information.*\n");
        }

        Ok(output)
    }

    // === Go to Definition (LSP) ===

    /// Get definition location using LSP
    pub async fn go_to_definition(
        &self,
        repo: &str,
        path: &str,
        line: usize,
        character: usize,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        let file_path = validate_path(&repo_path, path)?;
        let language = get_language_from_path(path);

        let mut output = String::new();
        output.push_str(&format!("# Go to Definition: `{}`\n\n", path));
        output.push_str(&format!("**Position**: {}:{}\n\n", line, character));

        if let Some(ref lsp) = self.lsp_manager {
            match lsp
                .get_definition(&language, &file_path, line as u32, character as u32)
                .await
            {
                Ok(Some(locations)) => {
                    if locations.is_empty() {
                        output.push_str("*No definition found*\n");
                    } else {
                        output.push_str(&format!("Found {} definition(s):\n\n", locations.len()));
                        for loc in locations {
                            if let Ok(def_path) = loc.uri.to_file_path() {
                                let rel_path = def_path
                                    .strip_prefix(&repo_path)
                                    .unwrap_or(&def_path)
                                    .to_string_lossy();
                                output.push_str(&format!(
                                    "- `{}:{}:{}`\n",
                                    rel_path,
                                    loc.range.start.line + 1,
                                    loc.range.start.character
                                ));
                            } else {
                                output.push_str(&format!(
                                    "- `{}:{}:{}`\n",
                                    loc.uri,
                                    loc.range.start.line + 1,
                                    loc.range.start.character
                                ));
                            }
                        }
                    }
                    return Ok(output);
                }
                Ok(None) => {
                    output.push_str("*No definition found from LSP*\n");
                }
                Err(e) => {
                    output.push_str(&format!("*LSP error: {}*\n", e));
                }
            }
        } else {
            output.push_str("*LSP not enabled. Use --lsp flag to enable go-to-definition.*\n");
        }

        // Fallback: try to find in our symbol index
        output.push_str("\n## Symbol Index Fallback\n\n");

        // Read the file to find what symbol is at this position
        let content = std::fs::read_to_string(&file_path)?;
        let lines: Vec<&str> = content.lines().collect();

        if line > 0 && line <= lines.len() {
            let source_line = lines[line - 1];
            // Try to find a symbol at or near the character position
            if let Some(symbols) = self.symbols.get(&repo_key) {
                for symbol in symbols.iter() {
                    if source_line.contains(&symbol.name) {
                        output.push_str(&format!(
                            "Possible match: **{}** at `{}:{}` ({:?})\n",
                            symbol.name, symbol.file_path, symbol.start_line, symbol.kind
                        ));
                    }
                }
            }
        }

        Ok(output)
    }

    /// Get control flow graph for a specific function
    pub async fn get_control_flow(&self, repo: &str, path: &str, function: &str) -> Result<String> {
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;

        // Parse the file
        let parsed = self.parser.parse_file(&full_path, &content)?;

        // Get the tree (required for CFG analysis)
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;

        // Build CFGs for all functions
        let cfgs = cfg::analyze_function(tree, &content, path)?;

        // Find the requested function
        let cfg = cfgs
            .iter()
            .find(|c| c.function_name == function)
            .ok_or_else(|| anyhow!("Function '{}' not found in {}", function, path))?;

        Ok(cfg.to_markdown())
    }

    // ==================== Data Flow Graph (DFG) Tools ====================

    /// Get data flow analysis for a specific function
    pub async fn get_data_flow(&self, repo: &str, path: &str, function: &str) -> Result<String> {
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;

        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;
        let analyses = dfg::analyze_file(tree, &content, path)?;

        // Find the requested function
        let analysis = analyses
            .iter()
            .find(|a| a.function_name == function)
            .ok_or_else(|| anyhow!("Function '{}' not found in {}", function, path))?;

        Ok(analysis.to_markdown())
    }

    /// Get reaching definitions analysis for a function
    pub async fn get_reaching_definitions(
        &self,
        repo: &str,
        path: &str,
        function: &str,
    ) -> Result<String> {
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;

        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;
        let cfgs = cfg::analyze_function(tree, &content, path)?;

        let cfg = cfgs
            .iter()
            .find(|c| c.function_name == function)
            .ok_or_else(|| anyhow!("Function '{}' not found in {}", function, path))?;

        let mut analyzer = dfg::DfgAnalyzer::new(cfg);
        let analysis = analyzer.analyze();

        let mut output = String::new();
        output.push_str(&format!("# Reaching Definitions: `{}`\n\n", function));
        output.push_str(&format!("**File**: `{}`\n\n", path));

        output.push_str("## Def-Use Chains\n\n");
        for chain in &analysis.def_use_chains {
            output.push_str(&format!(
                "### `{}` (line {})\n\n",
                chain.definition.variable, chain.definition.line
            ));

            if chain.uses.is_empty() {
                output.push_str("*No uses found (dead store)*\n\n");
            } else {
                output.push_str("**Reaches**:\n");
                for use_ in &chain.uses {
                    output.push_str(&format!("- Line {}: {:?}\n", use_.line, use_.kind));
                }
                output.push('\n');
            }
        }

        Ok(output)
    }

    // Phase 2: Enhanced Search & Embeddings

    /// Perform hybrid search combining BM25 and TF-IDF
    pub async fn hybrid_search(
        &self,
        query: &str,
        repo: Option<&str>,
        max_results: usize,
        mode: &str,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::extract::is_test_file;
        use crate::hybrid_search::create_hybrid_engine;

        let exclude_tests = exclude_tests.unwrap_or(false); // Default false for search

        // The engine's own indexes are built at index time and updated by the
        // watch path. Building a private pair here re-chunked and re-tokenized
        // the whole repository on every call, and left the TF-IDF vocabulary
        // holding only that call's most frequent terms.
        let repo_key = match repo {
            Some(r) if !r.is_empty() => Some(self.resolve_repo(r)?),
            _ => None,
        };
        let hybrid_engine =
            create_hybrid_engine(self.search_index.clone(), self.embedding_engine.clone())
                .scoped_to(repo_key.clone());

        // Perform search based on mode
        let mut results = match mode {
            "bm25" => hybrid_engine.search_bm25(query, max_results * 2),
            "tfidf" => hybrid_engine.search_tfidf(query, max_results * 2),
            _ => hybrid_engine.search(query, max_results * 2),
        };
        if exclude_tests {
            results.retain(|r| !is_test_file(&r.file_path));
        }

        // Format results
        let repo_paths = self.registered_repo_paths();

        // An identifier is indexed as its parts as well as whole, so a file
        // using the common parts matches a query for a name it never mentions.
        // A result has to carry a term as the caller typed it.
        let typed: Vec<String> = query
            .split_whitespace()
            .map(|term| term.to_lowercase())
            .filter(|term| term.len() >= 2)
            .collect();
        let carries_typed_term = |result: &crate::hybrid_search::HybridResult| -> bool {
            if result
                .matched_terms
                .iter()
                .any(|term| typed.iter().any(|t| term.eq_ignore_ascii_case(t)))
            {
                return true;
            }
            repo_paths
                .iter()
                .find_map(|rp| self.file_cache.get(&rp.join(&result.file_path)))
                .is_some_and(|entry| {
                    let content = entry.value().to_lowercase();
                    typed.iter().any(|term| content.contains(term.as_str()))
                })
        };

        let exact: Vec<_> = results
            .iter()
            .filter(|r| carries_typed_term(r))
            .cloned()
            .collect();
        // Nothing carried the terms as typed: the partial matches are all there
        // is, so return them rather than an empty answer, and say which it is.
        let partial_only = exact.is_empty() && !results.is_empty();
        if !exact.is_empty() {
            results = exact;
        }
        results.truncate(max_results);

        let mut output = String::new();
        output.push_str(&format!("# Hybrid Search Results for: `{}`\n\n", query));
        output.push_str(&format!("**Mode**: {}\n", mode));
        if let Some(ref r) = repo_key {
            output.push_str(&format!("**Repository**: {}\n", r));
        }
        output.push_str(&format!("**Results**: {}\n\n", results.len()));
        if partial_only {
            output.push_str(
                "*No result contains the query terms as written; these match parts of \
                 them only.*\n\n",
            );
        }

        for (i, result) in results.iter().enumerate() {
            // A file document covers the whole file and carries no content of
            // its own; both the lines to report and the snippet to show come
            // from the matching window in the cached source.
            let regenerated = repo_paths.iter().find_map(|rp| {
                self.file_cache
                    .get(&rp.join(&result.file_path))
                    .map(|entry| {
                        crate::search::snippet_with_range(entry.value(), &result.matched_terms)
                    })
            });
            let whole_file = result.result_type == "File";
            let (start_line, end_line, snippet) = match regenerated {
                Some((start, end, text)) if whole_file || result.content.is_empty() => {
                    (start, end, text)
                }
                _ => (result.start_line, result.end_line, result.content.clone()),
            };

            output.push_str(&format!("## {}. {}\n", i + 1, result.file_path));
            output.push_str(&format!("- **Score**: {:.4}\n", result.score));
            output.push_str(&format!("- **Lines**: {}-{}\n", start_line, end_line));

            if let Some(bm25) = result.bm25_rank {
                output.push_str(&format!("- **BM25 rank**: {}\n", bm25 + 1));
            }
            if let Some(tfidf) = result.tfidf_rank {
                output.push_str(&format!("- **TF-IDF rank**: {}\n", tfidf + 1));
            }

            if !result.matched_terms.is_empty() {
                output.push_str(&format!(
                    "- **Matched terms**: {}\n",
                    result.matched_terms.join(", ")
                ));
            }

            // Show snippet
            output.push_str("\n```\n");
            let snippet_lines: Vec<&str> = snippet.lines().take(10).collect();
            output.push_str(&snippet_lines.join("\n"));
            if snippet.lines().count() > 10 {
                output.push_str("\n... (truncated)");
            }
            output.push_str("\n```\n\n");
        }

        if results.is_empty() {
            output.push_str("No results found.\n");
        }

        Ok(output)
    }

    // =========================================================================
    // Phase 6: Advanced Features
    // =========================================================================

    /// Get incremental indexing status
    pub async fn get_incremental_status(&self, repo_name: &str) -> Result<String> {
        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);

        let mut output = String::new();
        output.push_str(&format!("# Incremental Index Status: {}\n\n", repo_name));

        // Count files and symbols
        let symbol_count = self.symbols.get(&repo_name).map(|s| s.len()).unwrap_or(0);

        let file_count = self.file_cache.len();

        output.push_str("## Index Statistics\n\n");
        output.push_str(&format!("- **Repository**: {}\n", repo_path.display()));
        output.push_str(&format!("- **Indexed Symbols**: {}\n", symbol_count));
        output.push_str(&format!("- **Cached Files**: {}\n", file_count));

        // Check for persisted index
        if let Some(ref store) = self.index_store {
            let index_file = store.store_path(&repo_path);
            if index_file.exists() {
                if let Ok(metadata) = std::fs::metadata(&index_file) {
                    output.push_str(&format!(
                        "- **Index File Size**: {}\n",
                        format_size(metadata.len())
                    ));
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(duration) = modified.elapsed() {
                            let mins = duration.as_secs() / 60;
                            output.push_str(&format!("- **Last Updated**: {} minutes ago\n", mins));
                        }
                    }
                }
            } else {
                output.push_str("- **Index File**: Not persisted\n");
            }
        }

        // Symbol breakdown by kind
        if let Some(symbols) = self.symbols.get(&repo_name) {
            output.push_str("\n## Symbol Breakdown\n\n");
            let mut by_kind: std::collections::HashMap<crate::symbols::SymbolKind, usize> =
                std::collections::HashMap::new();
            for s in symbols.iter() {
                *by_kind.entry(s.kind.clone()).or_insert(0) += 1;
            }

            let mut counts: Vec<_> = by_kind.into_iter().collect();
            counts.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

            for (kind, count) in counts {
                output.push_str(&format!("- {:?}: {}\n", kind, count));
            }
        }

        Ok(output)
    }

    /// Find all usages of a symbol
    pub async fn find_symbol_usages(
        &self,
        repo_name: &str,
        symbol_name: &str,
        include_imports: bool,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::extract::is_test_file;

        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let exclude_tests = exclude_tests.unwrap_or(false); // Default false for symbol search
        let symbols = self
            .symbols
            .get(&repo_name)
            .map(|s| s.clone())
            .unwrap_or_default();

        let mut usages: Vec<(String, usize, String)> = Vec::new();
        let mut definitions: Vec<(String, usize, String)> = Vec::new();

        // Find definitions
        for symbol in &symbols {
            if symbol.name == symbol_name {
                if exclude_tests && is_test_file(&symbol.file_path) {
                    continue;
                }
                definitions.push((
                    symbol.file_path.clone(),
                    symbol.start_line,
                    format!("{:?} definition", symbol.kind),
                ));
            }
        }

        // Search for usages in files
        for entry in self.file_cache.iter() {
            let path = entry.key();
            let content = entry.value();

            if !path.starts_with(&repo_path) {
                continue;
            }

            let rel_path = path
                .strip_prefix(&repo_path)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| path.to_string_lossy().to_string());

            // Skip test files if exclude_tests is enabled
            if exclude_tests && is_test_file(&rel_path) {
                continue;
            }

            for (line_num, line) in content.lines().enumerate() {
                let is_import = line.contains("import ")
                    || line.contains("use ")
                    || line.contains("from ")
                    || line.contains("require(");

                if !include_imports && is_import {
                    continue;
                }

                if line.contains(symbol_name) && crate::dfg::contains_word(line, symbol_name) {
                    let context = if is_import { "import" } else { "usage" };
                    usages.push((rel_path.clone(), line_num + 1, context.to_string()));
                }
            }
        }

        // Query all enabled semantic backends to cross-validate textual hits.
        // Neither source alone is trusted (grep over-reports, a cold backend
        // under-reports), so results are labelled, not replaced.
        let backend_refs = self
            .refs_for_symbol(&repo_name, symbol_name, &repo_path, &symbols)
            .await;

        let mut output = String::new();
        output.push_str(&format!("# Symbol Usages: '{}'\n\n", symbol_name));

        // A file name is not a symbol; the substring match below still finds
        // #include / mention sites, so return them but say what happened rather
        // than let the caller read a filename query as a real symbol lookup.
        if is_filename_like(symbol_name) {
            output.push_str(
                "> Note: this looks like a file name, not a symbol. The results below are \
                 lines that mention it (e.g. `#include` sites). For a broader text search, \
                 use search_code.\n\n",
            );
        }

        if !definitions.is_empty() {
            output.push_str("## Definitions\n\n");
            for (file, line, kind) in &definitions {
                output.push_str(&format!("- `{}:{}` ({})\n", file, line, kind));
            }
            output.push('\n');
        }

        if let Some(backends) = &backend_refs {
            // Build a per-backend key set for fast membership tests
            let mut backend_keys: HashMap<String, std::collections::HashSet<(String, usize)>> =
                HashMap::new();
            for (label, refs) in backends {
                let keys = refs.iter().map(|(f, l, _)| (f.clone(), *l)).collect();
                backend_keys.insert(label.clone(), keys);
            }

            let grep_keys: std::collections::HashSet<(String, usize)> = usages
                .iter()
                .map(|(file, line, _)| (file.clone(), *line))
                .collect();

            // Union of all backend key sets — any semantic backend confirming a
            // textual hit marks it "confirmed"
            let all_semantic_keys: std::collections::HashSet<(String, usize)> = backend_keys
                .values()
                .flat_map(|s| s.iter().cloned())
                .collect();

            let mut rows: Vec<(String, usize, String)> = Vec::new();
            for (file, line, _) in &usages {
                let label = if all_semantic_keys.contains(&(file.clone(), *line)) {
                    "confirmed".to_string()
                } else {
                    "syntactic-only".to_string()
                };
                rows.push((file.clone(), *line, label));
            }

            // Hits found by a backend but not by text search
            for (blabel, refs) in backends {
                for (file, line, _) in refs {
                    if !grep_keys.contains(&(file.clone(), *line)) {
                        rows.push((file.clone(), *line, format!("{}-only", blabel)));
                    }
                }
            }

            rows.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            rows.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

            if rows.is_empty() {
                output.push_str("## Usages\n\nNo usages found.\n");
            } else {
                let confirmed = rows.iter().filter(|r| r.2 == "confirmed").count();
                let syntactic = rows.iter().filter(|r| r.2 == "syntactic-only").count();
                let backend_only = rows.len() - confirmed - syntactic;

                // Build a sorted, deduplicated list of active backend labels
                let mut active: Vec<&str> = backends.keys().map(String::as_str).collect();
                active.sort_unstable();
                let active_str = active.join(", ");

                output.push_str(&format!(
                    "## Usages ({} total — cross-validated by: {})\n\n",
                    rows.len(),
                    active_str
                ));
                output.push_str(&format!(
                    "*{} confirmed, {} syntactic-only (no backend confirmed — possible \
                     false match or unindexed TU), {} backend-only (backend found, \
                     text search missed)*\n\n",
                    confirmed, syntactic, backend_only
                ));
                output.push_str("| File | Line | Source |\n");
                output.push_str("|------|------|--------|\n");
                for (file, line, label) in rows.iter().take(50) {
                    output.push_str(&format!("| {} | {} | {} |\n", file, line, label));
                }
                if rows.len() > 50 {
                    output.push_str(&format!("\n*... and {} more*\n", rows.len() - 50));
                }
            }
        } else if usages.is_empty() {
            output.push_str("## Usages\n\nNo usages found.\n");
        } else {
            output.push_str(&format!("## Usages ({} found)\n\n", usages.len()));
            output.push_str("| File | Line | Context |\n");
            output.push_str("|------|------|--------|\n");

            for (file, line, context) in usages.iter().take(50) {
                output.push_str(&format!("| {} | {} | {} |\n", file, line, context));
            }

            if usages.len() > 50 {
                output.push_str(&format!("\n*... and {} more*\n", usages.len() - 50));
            }
        }

        Ok(output)
    }

    /// Get export map for a file
    pub async fn get_export_map(&self, repo_name: &str, path: &str) -> Result<String> {
        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let file_path = validate_path(&repo_path, path)?;

        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let symbols = self
            .symbols
            .get(&repo_name)
            .map(|s| s.clone())
            .unwrap_or_default();

        // Find symbols defined in this file
        let file_symbols: Vec<_> = symbols.iter().filter(|s| s.file_path == path).collect();

        let mut output = String::new();
        output.push_str(&format!("# Export Map: {}\n\n", path));

        if file_symbols.is_empty() {
            output.push_str("No exported symbols found.\n");
        } else {
            // Get all symbols - we can't determine visibility without AST info
            let mut public_symbols: Vec<_> = file_symbols.iter().collect();
            public_symbols.sort_by_key(|symbol| symbol.start_line);

            output.push_str("## Exported Symbols\n\n");
            output.push_str("| Name | Kind | Line | Signature |\n");
            output.push_str("|------|------|------|----------|\n");

            for symbol in public_symbols {
                let sig = symbol.signature.as_deref().unwrap_or("-");
                output.push_str(&format!(
                    "| `{}` | {:?} | {} | {} |\n",
                    symbol.name,
                    symbol.kind,
                    symbol.start_line,
                    response_budget::truncate_on_char_boundary(sig, 50)
                ));
            }

            // Detect export statements in the file
            let export_lines: Vec<_> = content
                .lines()
                .enumerate()
                .filter(|(_, line)| {
                    let trimmed = line.trim();
                    trimmed.starts_with("export ")
                        || trimmed.starts_with("pub ")
                        || trimmed.starts_with("module.exports")
                        || trimmed.starts_with("__all__")
                })
                .collect();

            if !export_lines.is_empty() {
                output.push_str("\n## Export Statements\n\n");
                for (line_num, line) in export_lines {
                    output.push_str(&format!(
                        "- Line {}: `{}`\n",
                        line_num + 1,
                        line.trim().chars().take(80).collect::<String>()
                    ));
                }
            }
        }

        Ok(output)
    }

    // ========================================================================
    // Graph Visualization Helper Methods
    // ========================================================================

    /// Get call graph data for visualization
    /// Returns a reference to the call graph for the given repository
    pub fn get_call_graph_for_viz(
        &self,
        repo: &str,
    ) -> Result<dashmap::mapref::one::Ref<'_, String, CallGraph>> {
        if !self.options.call_graph_enabled {
            return Err(anyhow!(
                "Call graph not enabled. Start with --call-graph flag."
            ));
        }

        // Find the repo
        let repo_name = if repo.is_empty() {
            // Use first available repo
            self.call_graphs
                .iter()
                .next()
                .map(|e| e.key().clone())
                .ok_or_else(|| anyhow!("No repositories indexed with call graphs"))?
        } else {
            repo.to_string()
        };

        self.call_graphs
            .get(&repo_name)
            .ok_or_else(|| anyhow!("Call graph not found for repository: {}", repo_name))
    }

    /// Get a code excerpt for visualization (simplified version for graph tooltips)
    pub async fn get_excerpt_for_viz(
        &self,
        repo: &str,
        path: &str,
        center_line: usize,
        context: usize,
    ) -> Result<String> {
        let repo_path = PathBuf::from(self.resolve_repo(repo)?);
        let file_path = validate_path(&repo_path, path)?;

        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let lines: Vec<&str> = content.lines().collect();
        let start = center_line.saturating_sub(context + 1);
        let end = (center_line + context).min(lines.len());

        let excerpt: String = lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, line)| format!("{:4} | {}", start + i + 1, line))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(excerpt)
    }

    /// Get import graph data for visualization
    ///
    /// Uses the cached symbol and file data instead of re-walking the filesystem.
    ///
    /// # Arguments
    /// * `repo` - Repository name
    /// * `max_nodes` - Maximum number of file nodes to include (early exit)
    ///
    /// # Errors
    /// Returns an error if the repository is not indexed
    pub async fn get_import_graph_for_viz(
        &self,
        repo: &str,
        max_nodes: usize,
    ) -> Result<crate::tool_handlers::graph::ImportGraphData> {
        use std::collections::HashMap;

        let repo = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo);

        // Use cached symbols to get unique file paths (same approach as get_import_graph)
        let symbols = self
            .symbols
            .get(&repo)
            .map(|s| s.clone())
            .unwrap_or_default();

        let unique_files: std::collections::HashSet<_> =
            symbols.iter().map(|s| s.file_path.clone()).collect();

        let mut files: HashMap<String, Vec<String>> = HashMap::new();
        let mut node_count = 0;

        for rel_path in unique_files {
            if node_count >= max_nodes {
                break;
            }

            // Try the file_cache first, fall back to disk read
            let abs_path = repo_path.join(&rel_path);
            let content = if let Some(cached) = self.file_cache.get(&abs_path) {
                cached.clone()
            } else if let Ok(content) = std::fs::read_to_string(&abs_path) {
                std::sync::Arc::new(content)
            } else {
                continue;
            };

            let imports = parse_imports_from_content(&content, &rel_path);
            let import_paths: Vec<String> = imports.iter().map(|i| i.import_path.clone()).collect();

            if !import_paths.is_empty() {
                node_count += 1 + import_paths.len(); // source file + targets
                files.insert(rel_path, import_paths);
            }
        }

        let cycles: Vec<Vec<String>> = Vec::new();

        Ok(crate::tool_handlers::graph::ImportGraphData { files, cycles })
    }

    /// Get symbol graph data for visualization
    ///
    /// Iterates the file cache directly to find references instead of round-tripping
    /// through the markdown-formatted `find_references` output.
    ///
    /// # Arguments
    /// * `repo` - Repository name
    /// * `symbol_name` - Symbol to find references for
    /// * `max_nodes` - Maximum number of reference nodes to include
    ///
    /// # Errors
    /// Returns an error if the repository is not indexed or the symbol is not found
    pub async fn get_symbol_graph_for_viz(
        &self,
        repo: &str,
        symbol_name: &str,
        max_nodes: usize,
    ) -> Result<crate::tool_handlers::graph::SymbolGraphData> {
        let repo = self.resolve_repo(repo)?;
        // Find the symbol definition
        let symbols = self
            .symbols
            .get(&repo)
            .ok_or_else(|| anyhow!("Repository not indexed: {}", repo))?;

        let target_symbol = symbols
            .iter()
            .find(|s| s.name == symbol_name || s.name.ends_with(&format!("::{}", symbol_name)))
            .ok_or_else(|| anyhow!("Symbol not found: {}", symbol_name))?;

        let definition = crate::tool_handlers::graph::SymbolDefinition {
            id: target_symbol.name.clone(),
            kind: format!("{:?}", target_symbol.kind).to_lowercase(),
            file_path: target_symbol.file_path.clone(),
            line: target_symbol.start_line,
        };

        // Iterate file_cache directly to find references (same logic as text_search_references)
        let repo_path = PathBuf::from(&repo);
        let mut references = Vec::new();

        // Reserve one node for the definition itself
        let max_refs = max_nodes.saturating_sub(1);

        for entry in self.file_cache.iter() {
            if references.len() >= max_refs {
                break;
            }

            let file_path = entry.key();
            if !file_path.starts_with(&repo_path) {
                continue;
            }

            let rel_path = file_path
                .strip_prefix(&repo_path)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let content = entry.value();
            for (line_num, line) in content.lines().enumerate() {
                if references.len() >= max_refs {
                    break;
                }
                if line.contains(symbol_name) {
                    references.push(crate::tool_handlers::graph::SymbolReference {
                        file_path: rel_path.clone(),
                        line: line_num + 1,
                    });
                }
            }
        }

        Ok(crate::tool_handlers::graph::SymbolGraphData {
            definition,
            references,
        })
    }

    /// Get control flow graph data for visualization
    ///
    /// Uses the real `cfg::analyze_function` builder to produce actual basic blocks
    /// and control flow edges instead of a single-block stub.
    ///
    /// # Arguments
    /// * `repo` - Repository name
    /// * `function` - Function name to analyze
    ///
    /// # Errors
    /// Returns an error if the repository, function, or file is not found, or if parsing fails
    pub async fn get_cfg_for_viz(
        &self,
        repo: &str,
        function: &str,
    ) -> Result<crate::tool_handlers::graph::CfgData> {
        let repo = self.resolve_repo(repo)?;
        let repo_meta = self
            .repos
            .get(&repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        // Find the function in symbols
        let symbols = self
            .symbols
            .get(&repo)
            .ok_or_else(|| anyhow!("No symbols for repository: {}", repo))?;

        let func_symbol = symbols
            .iter()
            .find(|s| s.name == function || s.name.ends_with(&format!("::{}", function)))
            .ok_or_else(|| anyhow!("Function not found: {}", function))?;

        let full_path = validate_path(&repo_meta.path, &func_symbol.file_path)?;
        let content = std::fs::read_to_string(&full_path)?;

        // Parse the file with tree-sitter (same approach as get_control_flow)
        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;

        // Build CFGs for all functions in the file
        let cfgs = cfg::analyze_function(tree, &content, &func_symbol.file_path)?;

        // Find the requested function's CFG
        let cfg_result = cfgs
            .iter()
            .find(|c| c.function_name == function || c.function_name == func_symbol.name);

        let cfg_result = match cfg_result {
            Some(c) => c,
            None => {
                // Fallback: try partial match
                cfgs.iter()
                    .find(|c| {
                        c.function_name.ends_with(&format!("::{}", function))
                            || function.ends_with(&format!("::{}", c.function_name))
                            || c.function_name.contains(function)
                    })
                    .ok_or_else(|| {
                        let available: Vec<_> =
                            cfgs.iter().map(|c| c.function_name.as_str()).collect();
                        anyhow!(
                            "Function '{}' not found in CFG analysis. Available: {:?}",
                            function,
                            available
                        )
                    })?
            }
        };

        // Convert cfg::BasicBlock → graph::CfgBlock
        let source_lines: Vec<&str> = content.lines().collect();
        let mut blocks = Vec::new();
        for (id, block) in &cfg_result.blocks {
            let block_type = if block.is_entry {
                "entry"
            } else if block.is_exit {
                "exit"
            } else {
                match &block.terminator {
                    cfg::Terminator::Branch { .. } => "branch",
                    cfg::Terminator::Loop => "loop",
                    cfg::Terminator::Return => "return",
                    cfg::Terminator::Unreachable => "unreachable",
                    _ => "basic",
                }
            };

            // Extract code from source lines
            let start_idx = block.start_line.saturating_sub(1);
            let end_idx = block.end_line.min(source_lines.len());
            let code = if start_idx < end_idx {
                source_lines[start_idx..end_idx].join("\n")
            } else {
                block.label.clone()
            };

            blocks.push(crate::tool_handlers::graph::CfgBlock {
                id: format!("block_{}", id),
                label: block.label.clone(),
                block_type: block_type.to_string(),
                start_line: block.start_line,
                code,
            });
        }

        // Convert cfg::CfgEdge → graph::CfgEdge
        let mut edges = Vec::new();
        for edge in &cfg_result.edges {
            let (edge_type, condition, is_back_edge) = match &edge.kind {
                cfg::EdgeKind::TrueBranch => ("branch", Some("true".to_string()), None),
                cfg::EdgeKind::FalseBranch => ("branch", Some("false".to_string()), None),
                cfg::EdgeKind::LoopBack => ("loop_back", None, Some(true)),
                cfg::EdgeKind::LoopExit => ("loop_exit", None, None),
                cfg::EdgeKind::FallThrough => ("fallthrough", None, None),
                cfg::EdgeKind::Jump => ("jump", None, None),
                cfg::EdgeKind::Exception => ("exception", None, None),
            };

            edges.push(crate::tool_handlers::graph::CfgEdge {
                from: format!("block_{}", edge.from),
                to: format!("block_{}", edge.to),
                edge_type: edge_type.to_string(),
                condition,
                is_back_edge,
            });
        }

        Ok(crate::tool_handlers::graph::CfgData {
            file_path: func_symbol.file_path.clone(),
            blocks,
            edges,
        })
    }
}

/// Minimum C/C++ source files for a repo to be treated as a compile-commands
/// build. Below this, a missing compile_commands.json is assumed intentional
/// (e.g. a plain-Makefile project) rather than an error worth filtering or
/// warning for.
const COMPILE_COMMANDS_MIN_CXX_SOURCES: usize = 5;

/// Default minimum percent of a repo's C sources that compile_commands.json must
/// cover to be trusted as the index filter (per-repo overridable via
/// `compile_commands_min_coverage_pct`). Below this the manifest is treated as
/// stale/partial and ignored so a one-off `bear` capture of a single TU cannot
/// silently gut the index.
const COMPILE_COMMANDS_DEFAULT_MIN_COVERAGE_PCT: usize = 25;

fn is_c_source_ext(ext: &str) -> bool {
    matches!(ext, "c" | "cpp" | "cc" | "cxx" | "c++" | "C" | "S" | "s")
}

/// True when `repo_path`'s GTAGS database is older than the newest indexed
/// C/C++ source. A stale database reports drifted line numbers that the
/// line-window symbol merge cannot pair, silently dropping gtags confirmation.
fn gtags_database_stale(repo_path: &Path, files: &[PathBuf]) -> bool {
    let gtags_mtime = match std::fs::metadata(gtags_file_path(repo_path)).and_then(|m| m.modified())
    {
        Ok(mtime) => mtime,
        Err(_) => return false,
    };
    files.iter().any(|file| {
        let is_cxx = file
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| is_c_source_ext(e) || is_c_header_ext(e));
        is_cxx
            && std::fs::metadata(file)
                .and_then(|m| m.modified())
                .map(|mtime| mtime > gtags_mtime)
                .unwrap_or(false)
    })
}

/// sha256 hex of file content, matching the `content_hash` persisted in
/// `FileMetadata`, so a rebuild can tell whether a file changed since last index.
fn content_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn is_c_header_ext(ext: &str) -> bool {
    matches!(ext, "h" | "hpp" | "hh" | "hxx" | "h++")
}

/// Abbreviate a commit hash for display. Hex is ASCII, so the byte cut is safe.
fn short_hash(hash: &str) -> &str {
    &hash[..hash.len().min(8)]
}

fn load_compile_commands_filter(
    repo_root: &Path,
    json_paths: &[&Path],
) -> std::collections::HashSet<PathBuf> {
    let mut result = std::collections::HashSet::new();
    let mut any_loaded = false;

    for json_path in json_paths {
        let full_path = if json_path.is_absolute() {
            json_path.to_path_buf()
        } else {
            repo_root.join(json_path)
        };

        let (arr, json_parent) = match read_compile_commands(&full_path) {
            Some(loaded) => loaded,
            None => continue,
        };

        let count_before = result.len();
        let mut unresolved = 0usize;
        for entry in arr.iter() {
            let file_str = match entry.get("file").and_then(|f| f.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let directory: Option<&Path> = entry
                .get("directory")
                .and_then(|d| d.as_str())
                .map(Path::new);
            match resolve_compile_command_file(file_str, directory, json_parent.as_deref()) {
                Some(canonical) => {
                    result.insert(canonical);
                }
                None => {
                    unresolved += 1;
                }
            }
        }
        if unresolved > 0 {
            warn!(
                "compile_commands.json at {:?}: {} entries with unresolvable paths",
                full_path, unresolved
            );
        }
        info!(
            "Loaded {} compiled files from {:?}",
            result.len() - count_before,
            full_path
        );
        any_loaded = true;
    }

    if !any_loaded {
        warn!(
            "No compile_commands.json found in {:?} (tried: {:?})",
            repo_root, json_paths
        );
    }

    result
}

/// Read a compile_commands.json into its entries plus the JSON's containing
/// directory — the fallback base for the relative paths inside it. None when
/// the file is absent, unparsable, or not a JSON array.
fn read_compile_commands(full_path: &Path) -> Option<(Vec<serde_json::Value>, Option<PathBuf>)> {
    let content = std::fs::read_to_string(full_path).ok()?;

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "Failed to parse compile_commands.json at {:?}: {}",
                full_path, e
            );
            return None;
        }
    };

    let arr = match parsed {
        serde_json::Value::Array(entries) => entries,
        _ => {
            warn!(
                "compile_commands.json at {:?} is not a JSON array",
                full_path
            );
            return None;
        }
    };

    // A present-but-empty compile_commands.json (e.g. `[]`) parses fine yet,
    // under --use-compile-commands, silently filters out every C/C++ source
    // file, leaving only headers indexed. Surface it loudly.
    if arr.is_empty() {
        warn!(
            "compile_commands.json at {:?} exists but has 0 entries ({} bytes); \
             with --use-compile-commands all C/C++ source files will be skipped \
             (headers still indexed). Regenerate it or drop --use-compile-commands.",
            full_path,
            content.len()
        );
    }

    Some((arr, full_path.parent().map(Path::to_path_buf)))
}

/// Include search directories named by a repo's compile_commands.json, in the
/// order the manifest lists them. Only directories inside the repo are kept —
/// nothing outside it can hold a file `--index-filter` dropped.
fn compile_commands_include_dirs(repo_root: &Path, json_paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();

    for json_path in json_paths {
        let (entries, json_parent) = match read_compile_commands(json_path) {
            Some(loaded) => loaded,
            None => continue,
        };
        for entry in &entries {
            let base = entry
                .get("directory")
                .and_then(|d| d.as_str())
                .map(PathBuf::from)
                .or_else(|| json_parent.clone())
                .unwrap_or_else(|| repo_root.to_path_buf());
            for dir in entry_include_dirs(entry) {
                let abs = normalize_lexically(&base.join(dir));
                if abs.starts_with(repo_root) && !dirs.contains(&abs) {
                    dirs.push(abs);
                }
            }
        }
    }

    dirs
}

/// The include-directory arguments of one compile_commands entry, in both the
/// separate (`-I dir`) and joined (`-Idir`) spellings.
fn entry_include_dirs(entry: &serde_json::Value) -> Vec<String> {
    const INCLUDE_FLAGS: [&str; 3] = ["-I", "-isystem", "-iquote"];

    let args: Vec<String> = match entry.get("arguments").and_then(|a| a.as_array()) {
        Some(list) => list
            .iter()
            .filter_map(|arg| arg.as_str())
            .map(str::to_owned)
            .collect(),
        None => entry
            .get("command")
            .and_then(|command| command.as_str())
            .map(|command| command.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default(),
    };

    let mut dirs = Vec::new();
    let mut flag_awaiting_dir = false;
    for arg in args {
        if flag_awaiting_dir {
            dirs.push(arg);
            flag_awaiting_dir = false;
            continue;
        }
        match INCLUDE_FLAGS.iter().find(|flag| arg.starts_with(**flag)) {
            Some(flag) if arg.len() == flag.len() => flag_awaiting_dir = true,
            Some(flag) => dirs.push(arg[flag.len()..].to_string()),
            None => {}
        }
    }

    dirs
}

/// Threads a background definition-map build may use: half the machine, so the
/// build finishes in reasonable time while the other half stays free for the
/// queries the repo is meanwhile serving.
fn definition_build_threads() -> usize {
    std::thread::available_parallelism()
        .map(|cores| (cores.get() / 2).max(1))
        .unwrap_or(1)
}

/// Parse every file of a repo and record what each one defines.
///
/// Runs as its own task so the repo stays serviceable throughout. Cancellation
/// takes effect between batches; because the map is published only by the final
/// commit, an aborted build leaves the repo with no map rather than half of one.
async fn build_definition_map(
    store: Arc<crate::persist::IndexStore>,
    parser: Arc<LanguageParser>,
    repo_path: PathBuf,
    repo_name: String,
    mut files: Vec<PathBuf>,
) -> bool {
    let started = std::time::Instant::now();

    // An existing map under the current rules is refreshed file by file; only
    // absent or rule-mismatched maps are rebuilt whole.
    let refreshing = store.definition_stats(&repo_path).is_some();
    let stamps = if refreshing {
        match store.definition_file_stamps(&repo_path) {
            Ok(stamps) => stamps,
            Err(e) => {
                warn!(
                    "definition map: cannot read stamps for {}: {}",
                    repo_name, e
                );
                return false;
            }
        }
    } else {
        HashMap::new()
    };

    // Stat every file the walker listed: unchanged ones need no read, no parse
    // and no write. Whatever the map still holds but the walk did not list has
    // gone from the tree and must come out.
    let mut removed: Vec<String> = Vec::new();
    if refreshing {
        let mut seen: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(files.len());
        files.retain(|file| {
            let relative = file
                .strip_prefix(&repo_path)
                .unwrap_or(file)
                .to_string_lossy()
                .to_string();
            let current = crate::persist::file_stamp(file);
            let unchanged = matches!((current, stamps.get(&relative)), (Some(now), Some(before)) if now == *before);
            seen.insert(relative);
            !unchanged
        });
        removed.extend(
            stamps
                .keys()
                .filter(|relative| !seen.contains(*relative))
                .cloned(),
        );

        if files.is_empty() && removed.is_empty() {
            debug!("definition map for {} is up to date", repo_name);
            return false;
        }
        info!(
            "definition map: refreshing {} changed and {} removed file(s) for {}",
            files.len(),
            removed.len(),
            repo_name
        );
    }

    let mut writer = match if refreshing {
        store.open_definitions(&repo_path)
    } else {
        store.begin_definitions(&repo_path)
    } {
        Ok(writer) => writer,
        Err(e) => {
            warn!(
                "definition map: cannot start build for {}: {}",
                repo_name, e
            );
            return false;
        }
    };

    for relative in &removed {
        if let Err(e) = writer.remove_file(relative) {
            warn!("definition map: retract failed for {}: {}", repo_name, e);
            return false;
        }
    }
    let pool = match rayon::ThreadPoolBuilder::new()
        .num_threads(definition_build_threads())
        .build()
    {
        Ok(pool) => Arc::new(pool),
        Err(e) => {
            warn!("definition map: no thread pool for {}: {}", repo_name, e);
            return false;
        }
    };

    // Sorted so progress reporting walks the tree in a predictable order.
    files.sort();
    let total = files.len();
    if !refreshing {
        info!(
            "definition map: building for {} from {} file(s)",
            repo_name, total
        );
    }

    let mut done = 0usize;
    let mut next_report = DEFINITION_BUILD_PROGRESS_FILES;
    for chunk in files.chunks(DEFINITION_BUILD_CHUNK_FILES) {
        let batch: Vec<PathBuf> = chunk.to_vec();
        let batch_len = batch.len();
        let parser = Arc::clone(&parser);
        let pool = Arc::clone(&pool);
        let root = repo_path.clone();

        // Parsing is CPU work: it belongs on the bounded pool via a blocking
        // thread, not on the runtime's workers. This await is also the point at
        // which an abort stops the build.
        let parsed = tokio::task::spawn_blocking(move || {
            pool.install(|| {
                batch
                    .par_iter()
                    .filter_map(|file| {
                        let stamp = crate::persist::file_stamp(file)?;
                        let content = std::fs::read_to_string(file).ok()?;
                        let definitions = parser.definition_names(file, &content).ok()?;
                        let relative = file
                            .strip_prefix(&root)
                            .unwrap_or(file)
                            .to_string_lossy()
                            .to_string();
                        Some((relative, definitions, stamp))
                    })
                    .collect::<Vec<_>>()
            })
        })
        .await;

        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(e) => {
                warn!("definition map: build for {} stopped: {}", repo_name, e);
                return false;
            }
        };
        for (relative, definitions, stamp) in parsed {
            let written = if refreshing {
                writer.replace_file(&relative, &definitions, stamp)
            } else {
                writer.add_file(&relative, &definitions, stamp)
            };
            if let Err(e) = written {
                warn!("definition map: write failed for {}: {}", repo_name, e);
                return false;
            }
        }

        done += batch_len;
        if !refreshing && done >= next_report {
            info!(
                "definition map: {}/{} file(s) for {}",
                done, total, repo_name
            );
            next_report += DEFINITION_BUILD_PROGRESS_FILES;
        }
    }

    match writer.commit() {
        Ok(stats) => {
            info!(
                "definition map: {} definition(s) from {} file(s) in {:?} for {} \
                 ({} file(s) {})",
                stats.definitions,
                stats.files,
                started.elapsed(),
                repo_name,
                total,
                if refreshing { "refreshed" } else { "parsed" }
            );
            true
        }
        Err(e) => {
            warn!("definition map: commit failed for {}: {}", repo_name, e);
            false
        }
    }
}

/// Which rule first named a pulled-in file. A file both rules name is
/// attributed to the include resolver, which runs first, so the per-source
/// counts sum to the total rather than double-counting the overlap.
#[derive(Clone, Copy)]
enum PullInSource {
    Include,
    Gtags,
    Store,
}

/// Files `pull_in_referenced_files` accepted, with the per-source counts the
/// log needs. Counted after the `repo_files`/`in_base` filter, so a candidate
/// that is dropped there is not reported as pulled in.
#[derive(Default)]
struct PulledInFiles {
    files: Vec<PathBuf>,
    from_includes: usize,
    from_gtags: usize,
    from_store: usize,
}

/// Names the in-scope files reference but none of them defines — what both
/// gtags and the definition map are asked to locate.
fn unresolved_callee_names(base: &[(PathBuf, String, crate::parser::ParsedFile)]) -> Vec<String> {
    let defined: std::collections::HashSet<&str> = base
        .iter()
        .flat_map(|(_, _, parsed)| parsed.symbols.iter().map(|s| s.name.as_str()))
        .collect();
    let mut names: Vec<String> = base
        .par_iter()
        .filter_map(|(_, content, parsed)| {
            parsed
                .tree
                .as_ref()
                .map(|tree| CallGraph::referenced_callee_names(content, tree))
        })
        .flatten()
        .filter(|name| !defined.contains(name.as_str()))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Resolve an `#include` target to a file the repo walker listed: relative to
/// the including file first (the quoted form's own rule), then to the repo
/// root, then through each compile_commands include directory.
///
/// A repo whose build ships no compile_commands.json has none of those spell
/// out `<linux/io_uring/cmd.h>`, so the last resort is the single repo file
/// whose path ends with the target. Several matches resolve to nothing rather
/// than to a guess.
fn resolve_include_target(
    target: &str,
    source_dir: &Path,
    repo_root: &Path,
    include_dirs: &[PathBuf],
    repo_files: &std::collections::HashSet<PathBuf>,
    by_name: &HashMap<&std::ffi::OsStr, Vec<&PathBuf>>,
) -> Option<PathBuf> {
    let target_path = Path::new(target);
    if target.is_empty() || target_path.is_absolute() {
        return None;
    }

    let bases = [source_dir, repo_root]
        .into_iter()
        .chain(include_dirs.iter().map(PathBuf::as_path));
    for base in bases {
        let candidate = normalize_lexically(&base.join(target_path));
        if repo_files.contains(&candidate) {
            return Some(candidate);
        }
    }

    let suffix = format!("{}{}", std::path::MAIN_SEPARATOR, target);
    let mut matches = by_name
        .get(target_path.file_name()?)?
        .iter()
        .filter(|file| file.to_string_lossy().ends_with(&suffix));
    match (matches.next(), matches.next()) {
        (Some(only), None) => Some((*only).clone()),
        _ => None,
    }
}

/// Resolve `.` and `..` textually, without touching the filesystem: the result
/// is compared against the walker's listing, which is not canonicalized either.
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

/// Resolve a compile_commands.json `file` field to a canonical absolute path.
///
/// Per the clang spec, when `file` is relative it must be resolved against
/// the entry's `directory` field. We also fall back to resolving against
/// the JSON's containing directory, which lets us tolerate JSONs generated
/// on another machine where `directory` points at a path that doesn't exist
/// on this filesystem.
fn resolve_compile_command_file(
    file: &str,
    directory: Option<&Path>,
    json_parent: Option<&Path>,
) -> Option<PathBuf> {
    let file_path = Path::new(file);
    if file_path.is_absolute() {
        return file_path.canonicalize().ok();
    }
    if let Some(dir) = directory {
        if let Ok(canonical) = dir.join(file_path).canonicalize() {
            return Some(canonical);
        }
    }
    if let Some(parent) = json_parent {
        if let Ok(canonical) = parent.join(file_path).canonicalize() {
            return Some(canonical);
        }
    }
    None
}

fn compile_include_patterns(patterns: &[String]) -> Vec<glob::Pattern> {
    patterns
        .iter()
        .filter_map(|p| match glob::Pattern::new(p) {
            Ok(pattern) => Some(pattern),
            Err(e) => {
                warn!("Invalid include pattern '{}': {}", p, e);
                None
            }
        })
        .collect()
}

/// Parse imports from file content
fn parse_imports_from_content(content: &str, file_path: &str) -> Vec<crate::incremental::Import> {
    let mut imports = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // JavaScript/TypeScript ES imports
        if trimmed.starts_with("import ") {
            if let Some(from_idx) = trimmed.find(" from ") {
                let path_part = &trimmed[from_idx + 7..];
                let import_path = path_part
                    .trim_matches(|c| c == '\'' || c == '"' || c == ';')
                    .to_string();

                imports.push(crate::incremental::Import {
                    source_file: std::path::PathBuf::from(file_path),
                    import_path,
                    imported_symbols: parse_imported_symbols(&trimmed[7..from_idx]),
                    import_type: crate::incremental::ImportType::EsModule,
                    line: line_num + 1,
                });
            }
        }
        // CommonJS require
        else if trimmed.contains("require(") {
            if let Some(start) = trimmed.find("require(") {
                let after = &trimmed[start + 8..];
                if let Some(end) = after.find(')') {
                    let import_path = after[..end]
                        .trim_matches(|c| c == '\'' || c == '"')
                        .to_string();

                    imports.push(crate::incremental::Import {
                        source_file: std::path::PathBuf::from(file_path),
                        import_path,
                        imported_symbols: parse_commonjs_imported_symbols(&trimmed[..start]),
                        import_type: crate::incremental::ImportType::CommonJs,
                        line: line_num + 1,
                    });
                }
            }
        }
        // Python imports
        else if let Some(stripped) = trimmed.strip_prefix("from ") {
            let (import_path, imported_symbols) = stripped
                .split_once(" import ")
                .map(|(path, symbols)| (path.to_string(), parse_imported_symbols(symbols)))
                .unwrap_or_else(|| (stripped.to_string(), Vec::new()));
            if !import_path.is_empty() {
                imports.push(crate::incremental::Import {
                    source_file: std::path::PathBuf::from(file_path),
                    import_path,
                    imported_symbols,
                    import_type: crate::incremental::ImportType::Python,
                    line: line_num + 1,
                });
            }
        } else if let Some(stripped) = trimmed.strip_prefix("import ") {
            // Handle Go imports separately from Python
            if file_path.ends_with(".go") {
                let import_path = stripped
                    .trim_matches(|c| c == '"' || c == '(' || c == ')')
                    .to_string();

                if !import_path.is_empty() {
                    imports.push(crate::incremental::Import {
                        source_file: std::path::PathBuf::from(file_path),
                        import_path,
                        imported_symbols: vec![],
                        import_type: crate::incremental::ImportType::Go,
                        line: line_num + 1,
                    });
                }
            } else {
                // Python import
                let import_path = stripped.split_whitespace().next().unwrap_or("").to_string();
                if !import_path.is_empty() {
                    imports.push(crate::incremental::Import {
                        source_file: std::path::PathBuf::from(file_path),
                        imported_symbols: parse_imported_symbols(&import_path),
                        import_path,
                        import_type: crate::incremental::ImportType::Python,
                        line: line_num + 1,
                    });
                }
            }
        }
        // Rust use statements
        else if let Some(stripped) = trimmed.strip_prefix("use ") {
            // Extract the full module path, removing the item/group at the end
            // e.g., "use crate::api::client::Client;" → "crate::api::client"
            // e.g., "use crate::api::{foo, bar};" → "crate::api"
            let cleaned = stripped.trim_end_matches(';').trim();

            let import_path = if let Some(brace_idx) = cleaned.find('{') {
                // Group import: take everything before the brace
                cleaned[..brace_idx].trim_end_matches("::").to_string()
            } else {
                // Single import: take all segments (resolver will try
                // progressively shorter paths)
                cleaned.to_string()
            };

            if !import_path.is_empty() {
                let imported_symbols = if let Some(brace_idx) = cleaned.find('{') {
                    parse_imported_symbols(&cleaned[brace_idx..])
                } else {
                    parse_imported_symbols(cleaned.rsplit("::").next().unwrap_or(""))
                };
                imports.push(crate::incremental::Import {
                    source_file: std::path::PathBuf::from(file_path),
                    import_path,
                    imported_symbols,
                    import_type: crate::incremental::ImportType::Rust,
                    line: line_num + 1,
                });
            }
        }
        // C/C++ includes
        else if let Some(stripped) = trimmed.strip_prefix("#include") {
            let import_path = stripped
                .trim()
                .trim_matches(|c| c == '"' || c == '<' || c == '>')
                .to_string();

            imports.push(crate::incremental::Import {
                source_file: std::path::PathBuf::from(file_path),
                import_path,
                imported_symbols: vec![],
                import_type: crate::incremental::ImportType::CppInclude,
                line: line_num + 1,
            });
        }
    }

    imports
}

fn parse_imported_symbols(bindings: &str) -> Vec<crate::incremental::ImportedSymbol> {
    let bindings = bindings.trim().trim_matches(|ch| ch == '{' || ch == '}');
    bindings
        .split(',')
        .filter_map(|binding| {
            let binding = binding.trim();
            if binding.is_empty() || binding == "*" {
                return None;
            }
            let (name, alias) = binding
                .split_once(" as ")
                .map(|(name, alias)| (name.trim(), Some(alias.trim().to_string())))
                .unwrap_or((binding, None));
            Some(crate::incremental::ImportedSymbol {
                name: name.to_string(),
                alias,
                is_default: false,
            })
        })
        .collect()
}

fn parse_commonjs_imported_symbols(prefix: &str) -> Vec<crate::incremental::ImportedSymbol> {
    if let Some(start) = prefix.find('{') {
        if let Some(end) = prefix[start + 1..].find('}') {
            return parse_imported_symbols(&prefix[start + 1..start + 1 + end]);
        }
    }
    prefix
        .rsplit(|ch: char| ch.is_whitespace() || ch == '=')
        .find(|binding| !binding.is_empty())
        .map(parse_imported_symbols)
        .unwrap_or_default()
}

/// Format a vulnerability finding for output
/// Caps for one `get_project_structure` walk. Depth alone does not bound the
/// output: one wide directory is thousands of entries.
struct TreeBudget {
    /// Deepest directory level rendered.
    max_depth: usize,
    /// Entries listed per directory before the elision marker. 0 = unlimited.
    max_entries_per_dir: usize,
    /// Entries the whole walk may emit. 0 = unlimited.
    max_total: usize,
    /// Entries emitted so far.
    emitted: usize,
}

impl TreeBudget {
    fn exhausted(&self) -> bool {
        self.max_total != 0 && self.emitted >= self.max_total
    }
}

/// Render one page of a contributor ranking, with the paging footer when the
/// list was cut.
fn render_contributors(
    contributors: &[(String, usize)],
    window: response_budget::ListWindow,
    output: &mut String,
) {
    let (page, capped) = response_budget::cap(contributors, window, "get_contributors");
    for (name, count) in page {
        output.push_str(&format!("- {} ({} commits)\n", name, count));
    }
    if capped.truncated() {
        output.push('\n');
        output.push_str(&capped.footer());
    }
}

// Helper functions

/// Derive the canonical absolute path string used as the engine's repository
/// key. All repository-keyed maps (`repos`, `symbols`, `git_repos`,
/// `call_graphs`) share this single key derivation so that two repositories
/// with the same basename (e.g. two `linux.git` clones) do not collide.
fn canonical_repo_key(path: &Path) -> Result<String> {
    Ok(path
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize repo path {:?}", path))?
        .to_string_lossy()
        .into_owned())
}

fn expand_path(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("~") {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Cannot find home directory"))?;
        Ok(home.join(path_str.strip_prefix("~/").unwrap_or(stripped)))
    } else {
        Ok(path.to_path_buf())
    }
}

fn path_is_within_repo(path: &Path, repo: &Path) -> bool {
    if path.starts_with(repo) {
        return true;
    }

    let Ok(repo_canonical) = repo.canonicalize() else {
        return false;
    };

    if let Ok(path_canonical) = path.canonicalize() {
        return path_canonical.starts_with(&repo_canonical);
    }

    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(parent_canonical) = parent.canonicalize() else {
        return false;
    };

    parent_canonical.starts_with(repo_canonical)
}

/// Header naming every definition of `function` when the graph holds more than
/// one, so edges gathered from several files cannot read as one definition's own.
/// Empty when the name is unambiguous.
fn ambiguity_note(call_graph: &CallGraph, function: &str) -> String {
    let matches = call_graph.find_all_functions(function);
    if matches.len() < 2 {
        return String::new();
    }
    let named: Vec<String> = matches.iter().map(|key| format!("`{}`", key)).collect();

    format!(
        "> `{}` has {} definitions; the edges of all of them are listed.\n\
         > Defined in: {}.\n\
         > Pass the file-qualified name (e.g. `{}`) for one alone.\n\n",
        function,
        matches.len(),
        named.join(", "),
        matches[0],
    )
}

/// Footnote naming a call graph's unparsed regions, or empty when there are
/// none. Attached to every call-graph-derived answer so a short list reads as
/// possibly incomplete rather than exhaustive.
fn degraded_note(call_graph: &CallGraph) -> String {
    match call_graph.degraded_summary() {
        Some((regions, files)) => format!(
            "> {} region(s) across {} file(s) could not be parsed by tree-sitter \
             (commonly an `if` split across `#if`/`#else`/`#endif`) and are missing \
             from this call graph; the list above may be incomplete.\n\n",
            regions, files
        ),
        None => String::new(),
    }
}

/// Note naming every other real (body-having) definition of a symbol name,
/// so a caller who only sees get_symbol_definition's rank-picked winner
/// still learns a stub or an alternate implementation exists elsewhere
/// (e.g. lib/fuse_service.c vs lib/fuse_service_stub.c). Empty when at most
/// one distinct file defines the name — a header prototype alongside its
/// single .c definition is the common case, not an ambiguity.
fn symbol_definition_ambiguity_note(matches: &[&Symbol], chosen: &Symbol) -> String {
    let looks_like_definition = |s: &Symbol| {
        s.kind == chosen.kind && !matches!(s.kind, SymbolKind::Implementation) && s.line_count() > 1
    };

    let mut by_file: Vec<&str> = matches
        .iter()
        .filter(|s| looks_like_definition(s))
        .map(|s| s.file_path.as_str())
        .collect();
    by_file.sort_unstable();
    by_file.dedup();

    if by_file.len() < 2 {
        return String::new();
    }

    let others: Vec<&str> = by_file
        .iter()
        .filter(|f| **f != chosen.file_path)
        .copied()
        .collect();

    format!(
        "> `{}` has {} definitions. Showing `{}` ({}:{}).\n\
         > Also defined in: {}.\n\n",
        chosen.name,
        by_file.len(),
        chosen.name,
        chosen.file_path,
        chosen.start_line,
        others
            .iter()
            .map(|f| format!("`{}`", f))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

/// One file's section of a commit diff: its header through to the next one.
struct DiffFile<'a> {
    /// Path the header names; the post-commit name for a rename.
    path: &'a str,
    /// Section text, header included.
    text: &'a str,
}

/// Split a `git show` patch into per-file sections, in git's order. Text before
/// the first header rides along with the first section rather than being lost.
fn split_diff_by_file(diff: &str) -> Vec<DiffFile<'_>> {
    let mut headers: Vec<usize> = Vec::new();
    let mut offset = 0;
    for line in diff.split_inclusive('\n') {
        if line.starts_with("diff --git ") || line.starts_with("diff --cc ") {
            headers.push(offset);
        }
        offset += line.len();
    }

    headers
        .iter()
        .enumerate()
        .map(|(idx, header_start)| {
            let end = headers.get(idx + 1).copied().unwrap_or(diff.len());
            let header_line = diff[*header_start..end].lines().next().unwrap_or("");
            DiffFile {
                path: diff_header_path(header_line),
                text: &diff[if idx == 0 { 0 } else { *header_start }..end],
            }
        })
        .collect()
}

/// The path named by a `diff --git a/x b/x` or `diff --cc x` header line.
fn diff_header_path(header: &str) -> &str {
    if let Some(rest) = header.strip_prefix("diff --cc ") {
        return rest;
    }
    let rest = header.strip_prefix("diff --git ").unwrap_or(header);
    // The b-side is what the file is called after the commit.
    match rest.rfind(" b/") {
        Some(pos) => &rest[pos + 3..],
        None => rest,
    }
}

/// Validate a repo-relative pathspec handed to a git command: containment
/// only, no existence check. A commit's diff legitimately names files the
/// working tree no longer has. Shell metacharacters and a leading `-` are
/// rejected further down by GitRepo::validate_input.
fn validate_pathspec(requested: &str) -> Result<()> {
    if requested.starts_with('/') {
        return Err(anyhow!("Absolute paths not allowed"));
    }
    if Path::new(requested)
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(anyhow!(
            "Path traversal attempt blocked: '..' is not allowed in a pathspec"
        ));
    }
    Ok(())
}

/// Validate that a requested path is within the repository root to prevent path traversal attacks
fn validate_path(repo_root: &Path, requested: &str) -> Result<PathBuf> {
    // Don't allow paths starting with /
    if requested.starts_with('/') {
        return Err(anyhow!("Absolute paths not allowed"));
    }

    // Build and canonicalize the full path
    let full_path = repo_root.join(requested);

    // Canonicalize both paths for comparison (handles ../ etc)
    let canonical_root = repo_root
        .canonicalize()
        .context("Failed to canonicalize repo root")?;
    let canonical_path = full_path
        .canonicalize()
        .context("Path does not exist or cannot be accessed")?;

    // Verify the requested path is within the repo root
    if !canonical_path.starts_with(&canonical_root) {
        return Err(anyhow!(
            "Path traversal attempt blocked: path is outside repository"
        ));
    }

    Ok(canonical_path)
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;

    if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

fn get_file_icon(name: &str) -> &'static str {
    match name.rsplit('.').next() {
        // Rust Crab (\u{1f980})
        Some("rs") => "\u{1f980}",
        // Python Snake (\u{1f40d})
        Some("py") => "\u{1f40d}",
        // Lua Moon (\u{1f319})
        Some("lua") => "\u{1f319}",
        // Scroll (\u{1f4dc})
        Some("js" | "jsx") => "\u{1f4dc}",
        // Blue Book (\u{1f4d8})
        Some("ts" | "tsx") => "\u{1f4d8}",
        // Hamster Face (\u{1f439})
        Some("go") => "\u{1f439}",
        // Hot Beverage (\u{2615})
        Some("java") => "\u{2615}",
        // Gear (\u{2699}\u{fe0f})
        Some("c" | "h" | "cpp" | "hpp" | "cc") => "\u{2699}\u{fe0f}",
        // Memo (\u{1f4dd})
        Some("md") => "\u{1f4dd}",
        // Clipboard (\u{1f4cb})
        Some("json") => "\u{1f4cb}",
        // Gear (\u{2699}\u{fe0f})
        Some("toml" | "yaml" | "yml") => "\u{2699}\u{fe0f}",
        // Globe with Meridians (\u{1f310})
        Some("html") => "\u{1f310}",
        // Artist Palette (\u{1f3a8})
        Some("css" | "scss") => "\u{1f3a8}",
        // Page Facing Up (\u{1f4c4})
        _ => "\u{1f4c4}",
    }
}

/// True when a string looks like a source/header file name rather than a
/// symbol: it ends in a known source extension and contains none of the
/// characters that only appear in symbol expressions (`::`, spaces, `(`).
fn is_filename_like(name: &str) -> bool {
    const EXTS: &[&str] = &[
        ".h", ".hpp", ".hh", ".hxx", ".c", ".cc", ".cpp", ".cxx", ".rs", ".py", ".js", ".ts",
        ".go", ".java",
    ];
    let lower = name.to_lowercase();
    EXTS.iter().any(|ext| lower.ends_with(ext))
        && !name.contains("::")
        && !name.contains(' ')
        && !name.contains('(')
}

/// Submodule paths declared in `<repo_root>/.gitmodules`, parsed from the
/// `path = <p>` entries. Returns empty when there is no .gitmodules file.
fn submodule_paths(repo_root: &Path) -> Vec<String> {
    let Ok(content) = std::fs::read_to_string(repo_root.join(".gitmodules")) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("path")
                .and_then(|rest| rest.trim_start().strip_prefix('='))
                .map(|value| value.trim().to_string())
        })
        .filter(|path| !path.is_empty())
        .collect()
}

fn get_language_id(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("rs") => "rust",
        Some("py") => "python",
        Some("js") => "javascript",
        Some("jsx") => "jsx",
        Some("ts") => "typescript",
        Some("tsx") => "tsx",
        Some("go") => "go",
        Some("java") => "java",
        Some("c" | "h") => "c",
        Some("cpp" | "hpp" | "cc") => "cpp",
        Some("md") => "markdown",
        Some("json") => "json",
        Some("toml") => "toml",
        Some("yaml" | "yml") => "yaml",
        Some("html") => "html",
        Some("css") => "css",
        Some("scss") => "scss",
        Some("sh" | "bash") => "bash",
        _ => "",
    }
}

/// Whether `text`, the source line of a gtags reference, calls `name`: the
/// name as a whole word followed by `(`. A parameter of the same name, a
/// prototype's caller-less mention, an address-of use and a comment all name
/// the function without calling it, and gtags reports every one of them.
fn is_call_site(text: &str, name: &str) -> bool {
    if crate::extract::is_comment_only_line(text) {
        return false;
    }
    let mut from = 0;
    while let Some(found) = text[from..].find(name) {
        let start = from + found;
        let end = start + name.len();
        let part_of_a_longer_name = text[..start]
            .chars()
            .next_back()
            .is_some_and(|ch| ch.is_alphanumeric() || ch == '_');
        if !part_of_a_longer_name && text[end..].trim_start().starts_with('(') {
            return true;
        }
        from = end;
    }
    false
}

/// Lines a fallback hit spans: enough to hold a call and its arguments, short
/// enough that a term at the top of a file and one at the bottom are never
/// counted as the same hit.
const FALLBACK_WINDOW: usize = 5;

/// What a token found only in a comment contributes to a window's coverage.
/// Not zero — a comment naming every term still beats no anchor at all — but
/// far below code, so a help-text block cannot outrank the code implementing
/// the same terms.
const COMMENT_TOKEN_WEIGHT: f32 = 0.25;

/// The line to anchor a multi-line fallback hit at, and how well that hit
/// covers the query: the window of [`FALLBACK_WINDOW`] lines holding the most
/// distinct tokens, counting code ahead of comments. Ties go to the earliest.
///
/// Tokens past the 64th do not count towards coverage; a query that long is
/// already answered by the tokens before it.
fn best_anchor(lines: &[&str], tokens: &[String]) -> (usize, f32) {
    // Per line: the tokens it holds, and whether it is code. Computed once, so
    // the window scan below stays off the O(lines × tokens) path.
    let per_line: Vec<(u64, bool)> = lines
        .iter()
        .map(|line| {
            let lower = line.to_lowercase();
            let mut held = 0u64;
            for (index, token) in tokens.iter().enumerate().take(64) {
                if lower.contains(token.as_str()) {
                    held |= 1 << index;
                }
            }
            (held, !crate::extract::is_comment_only_line(line))
        })
        .collect();

    let mut best = (0, 0.0);
    for start in 0..per_line.len() {
        let mut in_code = 0u64;
        let mut in_comment = 0u64;
        for (held, is_code) in per_line.iter().skip(start).take(FALLBACK_WINDOW) {
            if *is_code {
                in_code |= held;
            } else {
                in_comment |= held;
            }
        }
        let coverage = in_code.count_ones() as f32
            + COMMENT_TOKEN_WEIGHT * (in_comment & !in_code).count_ones() as f32;
        if coverage > best.1 {
            // Anchor at the first line of the window that holds anything, so
            // the excerpt is centred on the match rather than on the run-up.
            let offset = per_line
                .iter()
                .skip(start)
                .take(FALLBACK_WINDOW)
                .position(|(held, _)| *held != 0)
                .unwrap_or(0);
            best = (start + offset, coverage);
        }
    }
    best
}

fn calculate_relevance(line: &str, query: &str) -> f32 {
    let mut score = 1.0;

    // Exact match bonus
    if line.contains(query) {
        score += 2.0;
    }

    // Word boundary bonus
    let words: Vec<&str> = line.split_whitespace().collect();
    for word in &words {
        if word.to_lowercase() == query {
            score += 3.0;
        }
    }

    // Definition-like patterns get bonus
    if line.contains("fn ")
        || line.contains("def ")
        || line.contains("func ")
        || line.contains("class ")
        || line.contains("struct ")
    {
        score += 1.5;
    }

    // Shorter lines with match are more relevant
    score += (100.0 / line.len() as f32).min(1.0);

    score
}

/// True for the tree-sitter language names of C and C++ sources. Accepts both
/// the parser's lowercase config names ("c"/"cpp") and the capitalized display
/// names from `ext_to_language` ("C"/"C++"), since the fresh-index and
/// persisted-load paths key the languages map with different conventions.
fn is_cxx_language(name: &str) -> bool {
    matches!(name, "c" | "cpp" | "C" | "C++")
}

fn ext_to_language(ext: &str) -> String {
    match ext {
        "rs" => "Rust",
        "py" => "Python",
        "js" | "jsx" => "JavaScript",
        "ts" | "tsx" => "TypeScript",
        "go" => "Go",
        "java" => "Java",
        "c" | "h" => "C",
        "cpp" | "hpp" | "cc" | "cxx" => "C++",
        "cs" => "C#",
        _ => ext,
    }
    .to_string()
}

fn extract_imports(content: &str, _path: &str) -> Vec<String> {
    let mut imports = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Detect imports across languages:
        // - Rust: use
        // - Python: import, from
        // - JavaScript/TypeScript: import, require()
        // - Go: import
        // - C/C++: #include
        let is_import = trimmed.starts_with("use ")
            || trimmed.starts_with("import ")
            || trimmed.starts_with("from ")
            || trimmed.contains("require(")
            || trimmed.starts_with("#include");

        if is_import {
            imports.push(trimmed.to_string());
        }
    }

    imports
}

mod dirs {
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
    }
}

/// Maximum line distance at which same-name symbols from different backends are
/// treated as the same definition. Backends report different rows for one
/// definition (tree-sitter = definition node, LSP = name token, gtags = tag
/// line); a small window pairs them while leaving genuine overloads — which sit
/// further apart — as separate symbols. Too wide merges adjacent overloads, too
/// narrow duplicates one symbol.
const SYMBOL_MATCH_WINDOW: usize = 3;

/// Concurrent in-flight C/C++ files during the LSP/gtags augmentation pass.
/// Kept small to overlap subprocesses and server round-trips without flooding a
/// single clangd/ccls process.
const CXX_AUGMENT_CONCURRENCY: usize = 6;

/// Wall-clock cap on the per-repo callHierarchy (LSP) augment phase. clangd/ccls
/// answer cold first-opens slowly; on a large tree the per-function round-trips
/// can otherwise run for minutes. Once exceeded, remaining files are skipped and
/// the graph keeps its tree-sitter/gtags edges plus whatever callHierarchy
/// already completed.
const CXX_CALLHIERARCHY_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// One C/C++ file's tree-sitter baseline symbols, queued for the async LSP/gtags
/// augmentation pass that cannot run inside the rayon parse closure.
struct CxxFileSymbols {
    abs_path: PathBuf,
    relative_path: String,
    symbols: Vec<Symbol>,
}

/// What a provenance annotation describes. Only the gtags-only wording differs:
/// gtags reports references, not resolved calls.
#[derive(Clone, Copy)]
enum ProvenanceSubject {
    Symbol,
    CallEdge,
}

/// All known backends, highest priority first — iterated to list which *enabled*
/// backends failed to confirm a datum.
const PROVENANCE_BACKENDS: [SourceSet; 4] = [
    SourceSet::CLANGD,
    SourceSet::CCLS,
    SourceSet::TREE_SITTER,
    SourceSet::GTAGS,
];

/// Render a backend-provenance annotation, or `None` when nothing is worth
/// surfacing. Annotates only on divergence: returns `None` when fewer than two
/// backends were enabled for the repo (no cross-validation possible) or when
/// every enabled backend confirmed the datum with no line conflict. Otherwise
/// it names the disagreement so the consumer reasons about it instead of
/// trusting one backend blindly.
fn render_provenance(
    subject: ProvenanceSubject,
    enabled: SourceSet,
    confirmed: SourceSet,
    canonical_line: usize,
    conflicts: &[SourceLine],
) -> Option<String> {
    if enabled.count() < 2 {
        return None;
    }

    // Enabled backends that did not confirm this datum.
    let mut missing = SourceSet::empty();
    for backend in PROVENANCE_BACKENDS {
        if enabled.contains(backend) && !confirmed.contains(backend) {
            missing.insert(backend);
        }
    }
    if missing.is_empty() && conflicts.is_empty() {
        return None; // full agreement, no dissent — silent
    }

    let mut parts: Vec<String> = Vec::new();

    if matches!(subject, ProvenanceSubject::CallEdge) && confirmed == SourceSet::GTAGS {
        // global -rx reports references, not resolved calls.
        parts.push("reference-derived (gtags) — unverified call".to_string());
    } else if missing.is_empty() {
        parts.push(format!("confirmed by {}", confirmed.labels().join(", ")));
    } else {
        parts.push(format!(
            "confirmed by {}; not by {}",
            confirmed.labels().join(", "),
            missing.labels().join(", ")
        ));
    }

    if !conflicts.is_empty() {
        let label = |source: SourceSet| source.labels().first().copied().unwrap_or("?");
        let mut entries = vec![format!("{} {}", label(confirmed.highest()), canonical_line)];
        for conflict in conflicts {
            entries.push(format!("{} {}", label(conflict.source), conflict.line));
        }
        parts.push(format!("WARNING line disagreement: {}", entries.join(", ")));
    }

    Some(parts.join("; "))
}

/// Merge one backend's `incoming` symbols into `existing`, keyed by (name, file)
/// with nearest-line matching inside [`SYMBOL_MATCH_WINDOW`]. Mirrors
/// `callgraph::CallGraph::fold_edge`: `confirmed_by` accumulates, priority
/// ([`SourceSet::rank`]) wins the canonical location and metadata, and divergent
/// lines are retained in `line_conflicts`. A symbol no prior backend saw is
/// inserted standalone (genuine overloads stay separate).
fn merge_symbols(existing: &mut Vec<Symbol>, incoming: Vec<Symbol>, source: SourceSet) {
    for inc in incoming {
        let best = existing
            .iter_mut()
            .filter(|sym| sym.name == inc.name && sym.file_path == inc.file_path)
            .filter(|sym| sym.start_line.abs_diff(inc.start_line) <= SYMBOL_MATCH_WINDOW)
            .min_by_key(|sym| sym.start_line.abs_diff(inc.start_line));

        match best {
            Some(sym) => fold_symbol(sym, inc, source),
            None => {
                let mut sym = inc;
                sym.confirmed_by = source;
                sym.line_conflicts = Vec::new();
                existing.push(sym);
            }
        }
    }
}

/// Fold a `source` confirmation into an existing symbol. Priority decides the
/// canonical location and which source's metadata is kept; the loser's line is
/// retained in `line_conflicts`. A lower-priority source never erases richer
/// metadata (e.g. gtags supplies only name+line), so its fields are taken only
/// when it outranks the current confirmer and actually carries them.
fn fold_symbol(existing: &mut Symbol, incoming: Symbol, source: SourceSet) {
    let old_canonical = existing.confirmed_by.highest();
    // tree-sitter parsed the file as it is now; an LSP server may answer from
    // its index of an older version, with an end line in unrelated code.
    let keep_parsed_end = existing.confirmed_by.contains(SourceSet::TREE_SITTER);
    existing.confirmed_by.insert(source);

    if source.rank() > old_canonical.rank() {
        if existing.start_line != incoming.start_line {
            existing.line_conflicts.push(SourceLine {
                source: old_canonical,
                line: existing.start_line,
            });
        }
        existing.start_line = incoming.start_line;
        if !keep_parsed_end {
            existing.end_line = incoming.end_line;
        }

        // Metadata follows the highest-priority source that supplies it.
        if incoming.kind != SymbolKind::Unknown {
            existing.kind = incoming.kind;
        }
        // Except a C signature: clang answers `int` for a parameter whose type
        // it could not resolve (implicit int, a C-only recovery), so a failing
        // translation unit would replace the text the file actually holds.
        let keep_source_signature =
            existing.signature.is_some() && get_language_from_path(&existing.file_path) == "c";
        if incoming.signature.is_some() && !keep_source_signature {
            existing.signature = incoming.signature;
        }
        if incoming.qualified_name.is_some() {
            existing.qualified_name = incoming.qualified_name;
        }
        if incoming.doc_comment.is_some() {
            existing.doc_comment = incoming.doc_comment;
        }
    } else if incoming.start_line != existing.start_line {
        existing.line_conflicts.push(SourceLine {
            source,
            line: incoming.start_line,
        });
    }
}

fn get_language_from_path(path: &str) -> String {
    match path.rsplit('.').next() {
        Some("rs") => "rust",
        Some("py") => "python",
        Some("js") | Some("jsx") => "javascript",
        Some("ts") | Some("tsx") => "typescript",
        Some("go") => "go",
        Some("java") => "java",
        Some("c") | Some("h") => "c",
        Some("cpp") | Some("hpp") | Some("cc") | Some("cxx") | Some("hxx") | Some("hh")
        | Some("c++") | Some("h++") | Some("C") | Some("H") => "cpp",
        Some("cs") => "csharp",
        _ => "unknown",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    /// Run a git command in `dir`, asserting success. gpg signing is disabled
    /// and identity is set via env so the test does not depend on global config.
    fn run_git(dir: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .arg("-c")
            .arg("commit.gpgsign=false")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e")
            .output()
            .expect("run git");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn is_merge_conflict_artifact_matches_known_shapes() {
        assert!(is_merge_conflict_artifact(Path::new(
            "src/sqe_op_BACKUP_324467.c"
        )));
        assert!(is_merge_conflict_artifact(Path::new(
            "src/sqe_op_BASE_324467.c"
        )));
        assert!(is_merge_conflict_artifact(Path::new(
            "src/sqe_op_LOCAL_324467.c"
        )));
        assert!(is_merge_conflict_artifact(Path::new(
            "src/sqe_op_REMOTE_324467.c"
        )));
        assert!(is_merge_conflict_artifact(Path::new("src/mount.c.orig")));
        assert!(is_merge_conflict_artifact(Path::new("src/mount.c.rej")));

        assert!(!is_merge_conflict_artifact(Path::new("src/sqe_op.c")));
        assert!(!is_merge_conflict_artifact(Path::new(
            "src/backup_service.c"
        )));
    }

    /// A branch far ahead of its upstream, with a large working tree, used
    /// to dump every commit subject and every changed path unbounded.
    #[tokio::test]
    async fn get_branch_info_caps_unpushed_commits_and_modified_files() {
        let dir = TempDir::new().unwrap();
        let repo_path = dir.path();
        run_git(repo_path, &["init", "-q"]);
        write_file(&repo_path.join("a.txt"), "base");
        run_git(repo_path, &["add", "a.txt"]);
        run_git(repo_path, &["commit", "-q", "-m", "base"]);
        run_git(repo_path, &["branch", "up"]);
        run_git(repo_path, &["branch", "--set-upstream-to=up"]);

        // 25 unpushed commits, well past the default limit of 20.
        for step in 0..25 {
            write_file(&repo_path.join("a.txt"), &step.to_string());
            run_git(repo_path, &["commit", "-qa", "-m", &format!("step {step}")]);
        }
        // 25 untracked (modified) files, same shape.
        for file_idx in 0..25 {
            write_file(&repo_path.join(format!("untracked_{file_idx}.txt")), "x");
        }

        let temp = TempDir::new().unwrap();
        let engine = CodeIntelEngine::with_options(
            temp.path().join("index"),
            vec![repo_path.to_path_buf()],
            EngineOptions {
                git_enabled: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let repo_key = canonical_repo_key(repo_path).unwrap();

        let output = engine
            .get_branch_info(&repo_key, response_budget::ListWindow::new(0, 20))
            .await
            .unwrap();
        assert_eq!(
            output.matches(" step ").count(),
            20,
            "limit=20 should cap unpushed commits at 20, got:\n{output}"
        );
        assert_eq!(
            output.matches("- `untracked_").count(),
            20,
            "limit=20 should cap modified files at 20, got:\n{output}"
        );
        assert!(
            output.contains("Showing 20 of 25"),
            "footer should name the total and next page:\n{output}"
        );

        // limit=0 is the documented escape hatch for "give me everything".
        let output = engine
            .get_branch_info(&repo_key, response_budget::ListWindow::new(0, 0))
            .await
            .unwrap();
        assert_eq!(output.matches(" step ").count(), 25);
        assert_eq!(output.matches("- `untracked_").count(), 25);
    }

    /// gtags answers with every use of a name. These are the ones that made
    /// `dash_prefixed` its own caller and turned its `what`/`value` parameters
    /// into calls to unrelated functions of those names.
    #[test]
    fn only_a_call_becomes_an_edge() {
        assert!(is_call_site(
            "\tret = dash_prefixed(progname, what);",
            "dash_prefixed"
        ));
        assert!(is_call_site("\tif (mount_opt (arg))", "mount_opt"));

        // The definition's own signature line, a parameter, an address-of use
        // and a comment: all uses, none of them calls.
        assert!(!is_call_site(
            "static int dash_prefixed(const char *progname, const char *what, const char *value)",
            "what"
        ));
        assert!(!is_call_site(
            "\thandler = &dash_prefixed;",
            "dash_prefixed"
        ));
        assert!(!is_call_site(
            "// dash_prefixed() builds the -o string",
            "dash_prefixed"
        ));
        // A longer name that merely ends with the one asked about.
        assert!(!is_call_site(
            "\tret = my_dash_prefixed(x);",
            "dash_prefixed"
        ));
    }

    /// Two examples in one repo each define a static `update_fs_loop`. The
    /// answer carries the edges of both, so it has to say so, name them, and
    /// say how to ask for one alone.
    #[test]
    fn a_repeated_function_name_names_its_other_definitions() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .unwrap();

        let source = "static void update_fs_loop(int fd) { (void)fd; }\n";
        let files: Vec<(String, String, tree_sitter::Tree)> =
            ["example/invalidate_path.c", "example/notify_prune.c"]
                .iter()
                .map(|path| {
                    (
                        path.to_string(),
                        source.to_string(),
                        parser.parse(source, None).unwrap(),
                    )
                })
                .collect();

        let call_graph = CallGraph::new();
        call_graph.build_from_files(&files).unwrap();

        let note = ambiguity_note(&call_graph, "update_fs_loop");
        assert!(note.contains("has 2 definitions"));
        assert!(note.contains("`example/invalidate_path.c::update_fs_loop`"));
        assert!(note.contains("`example/notify_prune.c::update_fs_loop`"));

        // A name defined once says nothing at all.
        assert!(ambiguity_note(&call_graph, "no_such_function").is_empty());
    }

    /// A commit's file list is what a review compares against; it has to
    /// survive the response budget even when the hunks do not.
    #[test]
    fn a_diff_splits_into_one_section_per_file() {
        let diff = "\
diff --git a/test/conftest.py b/test/conftest.py
deleted file mode 100644
--- a/test/conftest.py
+++ /dev/null
@@ -1,2 +0,0 @@
-import pytest
diff --git a/old_name.c b/new_name.c
similarity index 90%
--- a/old_name.c
+++ b/new_name.c
@@ -1 +1 @@
-int old;
+int new;
";
        let files = split_diff_by_file(diff);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "test/conftest.py");
        assert!(files[0].text.contains("-import pytest"));
        // A rename is named by what the commit leaves behind.
        assert_eq!(files[1].path, "new_name.c");
        assert!(files[1].text.contains("+int new;"));

        assert!(split_diff_by_file("").is_empty());
    }

    /// End to end on the tool: a commit too big for the response budget still
    /// says what it touched, and the file it deletes can be asked for by name.
    #[tokio::test]
    async fn a_commit_diff_lists_its_files_and_serves_a_deleted_one() {
        fn run_git(dir: &Path, args: &[&str]) {
            let out = std::process::Command::new("git")
                .arg("-c")
                .arg("commit.gpgsign=false")
                .args(args)
                .current_dir(dir)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@e")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@e")
                .output()
                .expect("run git");
            assert!(out.status.success(), "git {:?} failed", args);
        }
        // Two files whose rewrite alone outgrows the budget, so the third
        // (deleted) file can only survive in the inventory.
        fn bulk(tag: &str) -> String {
            (0..2000)
                .map(|line| format!("{} line {}\n", tag, line))
                .collect()
        }

        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        run_git(&repo, &["init", "-q"]);
        write_file(&repo.join("bulk_a.txt"), &bulk("before"));
        write_file(&repo.join("bulk_b.txt"), &bulk("before"));
        write_file(&repo.join("test_ctests.py"), "import pytest\n");
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-q", "-m", "base"]);

        write_file(&repo.join("bulk_a.txt"), &bulk("after"));
        write_file(&repo.join("bulk_b.txt"), &bulk("after"));
        run_git(&repo, &["rm", "-q", "test_ctests.py"]);
        run_git(&repo, &["commit", "-q", "-am", "drop the pytest suite"]);

        let engine = CodeIntelEngine::with_options(
            temp.path().join("index"),
            vec![repo.clone()],
            EngineOptions {
                git_enabled: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let repo_arg = repo.to_str().unwrap();

        let diff = engine
            .get_commit_diff(repo_arg, "HEAD", None, None, None)
            .await
            .unwrap();
        assert!(diff.contains("**Files changed**: 3"), "diff was: {}", diff);
        // Every file is named even though the hunks do not all fit.
        for file in ["bulk_a.txt", "bulk_b.txt", "test_ctests.py"] {
            assert!(diff.contains(file), "{} missing from the inventory", file);
        }
        assert!(diff.contains("## Files not shown"));
        assert!(diff.contains("get_commit_diff(commit=\"HEAD\""));

        // The deleted file is gone from the working tree; its diff is not.
        let deleted = engine
            .get_commit_diff(repo_arg, "HEAD", Some("test_ctests.py"), None, None)
            .await
            .unwrap();
        assert!(deleted.contains("-import pytest"), "diff was: {}", deleted);

        // A caller comparing two commits in one answer asks for less.
        let capped = engine
            .get_commit_diff(repo_arg, "HEAD", None, Some(6 * 1024), None)
            .await
            .unwrap();
        assert!(capped.len() < diff.len(), "max_bytes did not shrink");
        assert!(capped.contains("## Files not shown"));
    }

    /// The file a commit deletes is absent from the working tree, and it is
    /// exactly the file a review asks that commit's diff about.
    #[test]
    fn a_pathspec_need_not_exist_but_must_stay_in_the_repo() {
        assert!(validate_pathspec("test/test_ctests.py").is_ok());
        assert!(validate_pathspec("no/such/file/anywhere.c").is_ok());

        assert!(validate_pathspec("/etc/passwd").is_err());
        assert!(validate_pathspec("../outside.c").is_err());
        assert!(validate_pathspec("test/../../outside.c").is_err());
    }

    /// A repo's directory name is how it is talked about — in `--repos`, in a
    /// shell prompt, in the session's working directory — so it must resolve
    /// while it names exactly one indexed repo.
    #[tokio::test]
    async fn resolve_repo_accepts_an_unambiguous_bare_name() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("libfuse.git");
        std::fs::create_dir(&repo).unwrap();
        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();
        let repo_key = canonical_repo_key(&repo).unwrap();

        assert_eq!(engine.resolve_repo("libfuse.git").unwrap(), repo_key);
        // `.git` is part of the directory name, not of the repo's name.
        assert_eq!(engine.resolve_repo("libfuse").unwrap(), repo_key);
        assert!(engine.resolve_repo("no-such-repo").is_err());
    }

    /// Two repos sharing a basename is exactly what passing a path settles, so
    /// the error has to name them rather than list every indexed repo.
    #[tokio::test]
    async fn resolve_repo_names_the_candidates_for_an_ambiguous_name() {
        let temp = TempDir::new().unwrap();
        let first = temp.path().join("a/linux.git");
        let second = temp.path().join("b/linux.git");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let engine = CodeIntelEngine::new(
            temp.path().join("index"),
            vec![first.clone(), second.clone()],
        )
        .await
        .unwrap();

        let err = engine.resolve_repo("linux").unwrap_err().to_string();
        assert!(err.contains("a/linux.git"), "{err}");
        assert!(err.contains("b/linux.git"), "{err}");
    }

    /// The qemu regression: mid-pass, list_repos said "No matching repository"
    /// and queries said "not found", so the client reindexed from scratch.
    #[tokio::test]
    async fn repo_without_a_finished_pass_answers_come_back_later() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("adopted");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![])
            .await
            .unwrap();
        let key = engine
            .register_unknown_repo(&repo.to_string_lossy())
            .expect("a directory with .git is adoptable");

        let busy = |error: anyhow::Error| {
            error
                .downcast_ref::<IndexBusy>()
                .is_some_and(|busy| busy.first_pass && busy.repo == key)
        };
        let listed = engine.list_repos_scoped(Some(&key), false).await;
        assert!(busy(listed.unwrap_err()));
        let queried = engine.get_symbol_definition(&key, "main", 0).await;
        assert!(busy(queried.unwrap_err()));
        let listing = engine.list_repos_scoped(None, false).await.unwrap();
        assert!(
            listing.contains("Being Indexed") && listing.contains(&key),
            "{listing}"
        );
    }

    /// "(19/19 repos indexed)" was reported while qemu, adopted on top of 19
    /// configured repos, was still indexing; forgetting it then undercounted.
    #[tokio::test]
    async fn adopted_repo_counts_in_indexing_progress() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("adopted");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        write_file(&repo.join("main.c"), "int main(void) { return 0; }\n");
        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![])
            .await
            .unwrap();
        let repo_arg = repo.to_string_lossy().into_owned();

        let key = engine.register_unknown_repo(&repo_arg).unwrap();
        // Registered but not indexed yet.
        assert_eq!(engine.indexing_progress(), (0, 1));
        engine.reindex(Some(&key)).await.unwrap();
        assert_eq!(engine.indexing_progress(), (1, 1));
        // A second pass adds nothing.
        engine.reindex(Some(&key)).await.unwrap();
        assert_eq!(engine.indexing_progress(), (1, 1));
        engine.forget_repo(&key).await.unwrap();
        assert_eq!(engine.indexing_progress(), (0, 0));
    }

    /// With one indexed repo, naming it adds nothing the engine doesn't know.
    #[tokio::test]
    async fn resolve_repo_defaults_to_the_only_indexed_repo() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();

        assert_eq!(
            engine.resolve_repo("").unwrap(),
            canonical_repo_key(&repo).unwrap()
        );
    }

    /// Regression: a search naming two identifiers answered with one file that
    /// had them and four that had neither — the tokenizer indexes an
    /// identifier's parts, so a file using the common parts matched.
    #[tokio::test]
    async fn hybrid_search_keeps_only_results_carrying_a_typed_term() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        write_file(
            &repo.join("target.c"),
            "void widget_stop_engine(struct widget *w)\n{\n\tw->running = 0;\n}\n",
        );
        // Uses every part of the name, and never the name.
        let noise = "\tstop(engine);\n\twidget(engine);\n\tstop(widget);\n".repeat(40);
        write_file(&repo.join("noise.c"), &noise);

        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();
        engine.reindex_all().await.unwrap();

        let out = engine
            .hybrid_search(
                "widget_stop_engine",
                Some(repo.to_str().unwrap()),
                5,
                "hybrid",
                None,
            )
            .await
            .unwrap();

        assert!(out.contains("target.c"), "the file with the name: {out}");
        assert!(
            !out.contains("noise.c"),
            "a file with only the name's parts must not place: {out}"
        );
    }

    /// When nothing carries the name, the partial matches are the whole answer:
    /// returning them beats an empty result, as long as the answer says so.
    #[tokio::test]
    async fn hybrid_search_falls_back_to_partial_matches() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let noise = "\tstop(engine);\n\twidget(engine);\n\tstop(widget);\n".repeat(40);
        write_file(&repo.join("noise.c"), &noise);

        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();
        engine.reindex_all().await.unwrap();

        let out = engine
            .hybrid_search(
                "widget_stop_engine",
                Some(repo.to_str().unwrap()),
                5,
                "hybrid",
                None,
            )
            .await
            .unwrap();

        assert!(out.contains("noise.c"), "partial matches are kept: {out}");
        assert!(
            out.contains("match parts of them only"),
            "the answer has to say they are partial: {out}"
        );
    }

    /// Regression: a term on two consecutive lines came back as two results,
    /// one per line, each carrying the same context lines around it.
    #[tokio::test]
    async fn search_code_returns_a_region_once() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        write_file(
            &repo.join("optparse.c"),
            "static void usage(void)\n\
             {\n\
             \tprintf(\" --verbose\\t print more\\n\"\n\
             \t       \" --verbose=all  print everything\\n\");\n\
             \texit(1);\n\
             }\n",
        );

        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();
        engine.reindex_all().await.unwrap();

        let out = engine
            .search_code(
                Some(repo.to_str().unwrap()),
                "--verbose",
                None,
                10,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            out.matches("`optparse.c`").count(),
            1,
            "consecutive matches are one region: {out}"
        );
    }

    /// Regression: six results were the same location, one per index
    /// generation the file had been through.
    #[tokio::test]
    async fn semantic_search_returns_a_location_once() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        write_file(&repo.join("sample.c"), "int validate_tag(void);\n");

        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();
        let repo_key = canonical_repo_key(&repo).unwrap();

        // Re-index a file without removing what the last generation left.
        for _ in 0..6 {
            engine
                .search_index
                .index_file(&repo_key, "sample.c", "int validate_tag(void);\n");
        }

        let out = engine
            .semantic_search(Some(&repo_key), "validate tag", 6, None, None)
            .await
            .unwrap();

        assert_eq!(
            out.matches("sample.c (score").count(),
            1,
            "one location, one result: {out}"
        );
    }

    /// Regression: a request for lines 1-5000 of a large file was answered
    /// with a `Lines 1-5000` header over a body that stopped at line 1346 —
    /// the budget was applied after the header had been written.
    #[tokio::test]
    async fn get_file_header_names_the_range_it_returns() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let long_file = (1..=5000)
            .map(|n| format!("\tsome_call_number_{}(argument, argument, argument);", n))
            .collect::<Vec<_>>()
            .join("\n");
        write_file(&repo.join("big.c"), &long_file);

        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();
        let out = engine
            .get_file(repo.to_str().unwrap(), "big.c", Some(1), Some(5000))
            .await
            .unwrap();

        let header = out.lines().find(|l| l.starts_with("Lines ")).unwrap();
        let last_line: usize = header
            .trim_start_matches("Lines 1-")
            .split(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();

        assert!(last_line < 5000, "budget must bite for this file: {header}");
        assert!(
            out.contains(&format!("some_call_number_{}(", last_line)),
            "header names line {last_line}, which the body does not contain"
        );
        assert!(
            !out.contains(&format!("some_call_number_{}(", last_line + 1)),
            "body runs past the line the header names"
        );
        assert!(out.contains(&format!("start_line={}", last_line + 1)));
    }

    /// Regression: both bounds index into the line vector, so a range the file
    /// cannot satisfy used to abort the whole tool call with a slice panic.
    #[tokio::test]
    async fn get_file_refuses_a_range_the_file_cannot_satisfy() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        write_file(&repo.join("short.c"), "one\ntwo\nthree\n");

        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();
        let repo = repo.to_str().unwrap();

        let past_eof = engine
            .get_file(repo, "short.c", Some(99000), Some(99010))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            past_eof.contains("past the end") && past_eof.contains("3 lines"),
            "error must name the file length: {past_eof}"
        );

        let reversed = engine
            .get_file(repo, "short.c", Some(3), Some(1))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            reversed.contains("start_line 3 is after end_line 1"),
            "error must name both bounds: {reversed}"
        );

        // The bounds a short file does satisfy still answer.
        let clamped = engine
            .get_file(repo, "short.c", Some(2), Some(99))
            .await
            .unwrap();
        assert!(clamped.contains("Lines 2-3 of 3"), "{clamped}");
    }

    /// The lease is what a query consults to decide between answering and
    /// EAGAIN: while an update holds the write side no read lease is handed
    /// out, and the grace bounds how long the query waits to find that out.
    #[tokio::test]
    async fn query_lease_is_refused_while_an_update_holds_the_repo() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();
        let repo_key = canonical_repo_key(&repo).unwrap();

        assert!(engine.try_query_lease(&repo_key).await.is_some());

        let update = engine
            .index_update_leases(std::slice::from_ref(&repo_key))
            .await;
        let waited = std::time::Instant::now();
        assert!(engine.try_query_lease(&repo_key).await.is_none());
        assert!(waited.elapsed() >= INDEX_LEASE_GRACE);

        drop(update);
        assert!(engine.try_query_lease(&repo_key).await.is_some());
    }

    /// The watcher grows one `IndexUpdateLeases` as file-change events for
    /// different repos land, rather than acquiring the full set only once a
    /// debounce batch is known — this is what lets a repo's write lease start
    /// at its first change event instead of at the batch flush. A repo not
    /// yet `add()`ed must stay answerable; one just added must not.
    #[tokio::test]
    async fn update_window_grows_incrementally_across_repos() {
        let temp = TempDir::new().unwrap();
        let repo_a = temp.path().join("repo_a");
        let repo_b = temp.path().join("repo_b");
        std::fs::create_dir(&repo_a).unwrap();
        std::fs::create_dir(&repo_b).unwrap();
        let engine =
            CodeIntelEngine::new(temp.path().join("index"), vec![repo_a.clone(), repo_b.clone()])
                .await
                .unwrap();
        let key_a = canonical_repo_key(&repo_a).unwrap();
        let key_b = canonical_repo_key(&repo_b).unwrap();

        let mut window = engine.begin_update_window().await;
        assert!(!window.covers(&key_a));
        assert!(!window.covers(&key_b));
        assert!(engine.try_query_lease(&key_a).await.is_some());
        assert!(engine.try_query_lease(&key_b).await.is_some());

        window.add(&engine, &key_a).await;
        assert!(window.covers(&key_a));
        assert!(engine.try_query_lease(&key_a).await.is_none());
        assert!(engine.try_query_lease(&key_b).await.is_some());

        window.add(&engine, &key_b).await;
        assert!(window.covers(&key_b));
        assert!(engine.try_query_lease(&key_b).await.is_none());

        drop(window);
        assert!(engine.try_query_lease(&key_a).await.is_some());
        assert!(engine.try_query_lease(&key_b).await.is_some());
    }

    /// Regression: a repo the server did not know got the status of every
    /// other repo, which read as if it were indexed or simply missing.
    #[tokio::test]
    async fn index_status_answers_for_the_requested_repo_only() {
        let temp = TempDir::new().unwrap();
        let repo_a = temp.path().join("repo_a");
        let repo_b = temp.path().join("repo_b");
        let unknown = temp.path().join("unknown");
        for repo in [&repo_a, &repo_b, &unknown] {
            std::fs::create_dir_all(repo.join(".git")).unwrap();
            std::fs::write(repo.join("lib.rs"), "pub fn f() -> u32 { 1 }\n").unwrap();
        }
        let engine = CodeIntelEngine::new(
            temp.path().join("index"),
            vec![repo_a.clone(), repo_b.clone()],
        )
        .await
        .unwrap();
        engine.complete_initialization().await.unwrap();
        let key_a = canonical_repo_key(&repo_a).unwrap();
        let key_b = canonical_repo_key(&repo_b).unwrap();

        assert!(engine
            .get_index_status(Some(unknown.to_str().unwrap()))
            .await
            .is_err());

        let scoped = engine.get_index_status(Some(&key_a)).await.unwrap();
        assert!(scoped.contains(&format!("`{}`", key_a)), "{scoped}");
        assert!(!scoped.contains(&format!("`{}`", key_b)), "{scoped}");
        assert!(!scoped.contains("## Enabled Features"), "{scoped}");

        let all = engine.get_index_status(None).await.unwrap();
        assert!(all.contains(&format!("`{}`", key_b)), "{all}");
        assert!(all.contains("## Enabled Features"), "{all}");
    }

    /// Regression: after an INDEX_LOGIC_VERSION bump, unchanged C/C++ files
    /// reused the symbols the older indexer had persisted.
    #[tokio::test]
    async fn prior_symbols_from_another_logic_version_are_not_reused() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(repo.join("lib.rs"), "pub fn f() -> u32 { 1 }\n").unwrap();
        let engine = CodeIntelEngine::with_options(
            temp.path().join("index"),
            vec![repo.clone()],
            EngineOptions {
                persist_enabled: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        engine.complete_initialization().await.unwrap();

        let prior = engine.load_prior_file_symbols(&repo).unwrap();
        assert!(prior.contains_key("lib.rs"), "{:?}", prior.keys());

        let store = engine.index_store.as_ref().unwrap();
        let mut persisted = store.load_repo(&repo).unwrap();
        persisted.logic_version = crate::persist::INDEX_LOGIC_VERSION - 1;
        store.save_full(&persisted).unwrap();
        assert!(engine.load_prior_file_symbols(&repo).is_none());
    }

    /// The sweep exists to bound what stdio delegation adds to a long-running
    /// server, so it must leave the repos that server was started with alone
    /// however long they sit -- those are its declared set.
    #[tokio::test]
    async fn idle_sweep_drops_the_adopted_repo_and_keeps_the_configured_one() {
        let temp = TempDir::new().unwrap();
        let configured = temp.path().join("configured");
        let adopted = temp.path().join("adopted");
        for repo in [&configured, &adopted] {
            std::fs::create_dir_all(repo.join(".git")).unwrap();
            std::fs::write(repo.join("lib.rs"), "pub fn f() -> u32 { 1 }\n").unwrap();
        }

        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![configured.clone()])
            .await
            .unwrap();
        engine.complete_initialization().await.unwrap();
        engine
            .reindex(Some(adopted.to_str().unwrap()))
            .await
            .expect("adopting a repo the engine was not started with");

        // Age every stamp past the deadline: origin, not idleness, is what must
        // decide here.
        for repo in engine.repo_paths.read().iter() {
            repo.last_used.store(0, Ordering::Relaxed);
        }
        engine
            .sweep_idle_repos(std::time::Duration::from_secs(60))
            .await;

        let surviving = engine.registered_repo_paths();
        assert!(
            surviving.iter().any(|path| path == &configured),
            "a configured repo must survive any idle time: {surviving:?}"
        );
        assert!(
            !surviving.iter().any(|path| path == &adopted),
            "an idle adopted repo must be dropped: {surviving:?}"
        );
    }

    /// `UblkClient.start` is how the source and a review note name the method;
    /// the symbol table holds it under `start`.
    #[tokio::test]
    async fn a_dotted_method_name_resolves_to_its_definition() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(
            repo.join("run-system-tests.py"),
            "class UblkClient:\n    def start(self):\n        return 1\n",
        )
        .unwrap();

        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();
        engine.complete_initialization().await.unwrap();

        let definition = engine
            .get_symbol_definition(repo.to_str().unwrap(), "UblkClient.start", 2)
            .await
            .expect("a dotted method name must reach the method");
        assert!(
            definition.contains("def start"),
            "definition of the dotted name: {definition}"
        );
    }

    /// A repo the server was not started with — every adopted one, since
    /// adoption is a reindex over HTTP — must get the git tools too.
    #[tokio::test]
    async fn a_repo_registered_after_startup_answers_the_git_tools() {
        fn git(repo: &Path, args: &[&str]) {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .status()
                .expect("git");
            assert!(status.success(), "git {args:?}");
        }

        let temp = TempDir::new().unwrap();
        let configured = temp.path().join("configured");
        let adopted = temp.path().join("adopted");
        for repo in [&configured, &adopted] {
            std::fs::create_dir_all(repo).unwrap();
            std::fs::write(repo.join("lib.rs"), "pub fn f() -> u32 { 1 }\n").unwrap();
        }
        git(&adopted, &["init", "-q"]);
        git(&adopted, &["add", "lib.rs"]);
        git(
            &adopted,
            &[
                "-c",
                "user.name=narsil",
                "-c",
                "user.email=narsil@example.com",
                "commit",
                "-q",
                "-m",
                "add lib.rs",
            ],
        );

        let options = EngineOptions {
            git_enabled: true,
            ..EngineOptions::default()
        };
        let engine = CodeIntelEngine::with_options(
            temp.path().join("index"),
            vec![configured.clone()],
            options,
        )
        .await
        .unwrap();
        engine.complete_initialization().await.unwrap();

        engine
            .reindex(Some(adopted.to_str().unwrap()))
            .await
            .expect("adopting a repo the engine was not started with");

        let history = engine
            .get_file_history(adopted.to_str().unwrap(), "lib.rs", 5)
            .await
            .expect("an adopted repo must answer the git tools");
        assert!(
            history.contains("add lib.rs"),
            "history of the adopted repo: {history}"
        );
    }

    #[tokio::test]
    async fn a_repo_adopted_after_watch_startup_reports_new_callers() {
        let temp = TempDir::new().unwrap();
        let configured = temp.path().join("configured");
        let adopted = temp.path().join("adopted");
        for repo in [&configured, &adopted] {
            std::fs::create_dir_all(repo.join(".git")).unwrap();
            write_file(
                &repo.join("lib.rs"),
                "pub fn target() {}\npub fn caller() {}\n",
            );
        }
        let engine = Arc::new(
            CodeIntelEngine::with_options(
                temp.path().join("index"),
                vec![configured],
                EngineOptions {
                    watch_enabled: true,
                    call_graph_enabled: true,
                    ..EngineOptions::default()
                },
            )
            .await
            .unwrap(),
        );
        engine.complete_initialization().await.unwrap();
        let (_watcher, mut changes) = Arc::clone(&engine).create_async_file_watcher().unwrap();
        let repo = adopted.to_str().unwrap();
        engine.reindex(Some(repo)).await.unwrap();
        assert!(engine
            .call_graphs
            .get(repo)
            .unwrap()
            .get_callers("target")
            .is_empty());

        let source = adopted.join("lib.rs");
        write_file(
            &source,
            "pub fn target() {}\npub fn caller() { target(); }\n",
        );
        let batch = tokio::time::timeout(std::time::Duration::from_secs(5), changes.recv())
            .await
            .expect("no file-change event for the adopted repository")
            .expect("watcher stopped");
        assert!(batch.changes.iter().any(|change| change.path == source));
        engine.process_file_changes(&batch.changes).await.unwrap();
        drop(batch);
        let graph = engine.call_graphs.get(repo).unwrap();
        let callers = graph.get_callers("target");
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].target, "lib.rs::caller");
    }

    /// A repo named by a query is stamped, which is what keeps one in active
    /// use out of the sweep however long the server runs.
    #[tokio::test]
    async fn resolving_a_repo_stamps_it_as_used() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();

        for registered in engine.repo_paths.read().iter() {
            registered.last_used.store(0, Ordering::Relaxed);
        }
        engine
            .resolve_repo(repo.to_str().unwrap())
            .expect("resolve");

        let stamp = engine.repo_paths.read()[0]
            .last_used
            .load(Ordering::Relaxed);
        assert!(stamp > 0, "resolve_repo must record the use");
    }

    /// A watch batch names files; the update window needs the repos they belong
    /// to, once each, so one checkout burst takes one lease per repo.
    #[tokio::test]
    async fn repos_for_changes_maps_files_to_their_repo_once() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();

        let changes = vec![
            crate::persist::FileChange {
                path: repo.join("a.rs"),
                change_type: crate::persist::ChangeType::Modified,
            },
            crate::persist::FileChange {
                path: repo.join("sub/b.rs"),
                change_type: crate::persist::ChangeType::Created,
            },
            crate::persist::FileChange {
                path: temp.path().join("outside/c.rs"),
                change_type: crate::persist::ChangeType::Modified,
            },
        ];

        assert_eq!(
            engine.repos_for_changes(&changes),
            vec![canonical_repo_key(&repo).unwrap()]
        );
    }

    /// linux.git has 41k contributor identities; the default page must show the
    /// top of the ranking and say what it left out.
    #[test]
    fn render_contributors_caps_and_keeps_the_ranking() {
        let contributors: Vec<(String, usize)> = (0..100)
            .map(|rank| (format!("dev{} <d{}@e>", rank, rank), 100 - rank))
            .collect();

        let mut output = String::new();
        render_contributors(
            &contributors,
            response_budget::ListWindow::new(0, 30),
            &mut output,
        );

        assert_eq!(output.matches("commits)").count(), 30);
        assert!(output.starts_with("- dev0 <d0@e> (100 commits)\n"));
        assert!(output.contains("Showing 30 of 100"));
        assert!(output.contains("get_contributors(offset=30)"));
    }

    #[test]
    fn render_contributors_limit_zero_lists_everyone() {
        let contributors: Vec<(String, usize)> = (0..100)
            .map(|rank| (format!("dev{} <d{}@e>", rank, rank), 100 - rank))
            .collect();

        let mut output = String::new();
        render_contributors(
            &contributors,
            response_budget::ListWindow::new(0, 0),
            &mut output,
        );

        assert_eq!(output.matches("commits)").count(), 100);
        assert!(!output.contains("Showing"));
    }

    #[test]
    fn merge_references_unions_both_sources() {
        // Regression for the find_references LSP-wins bug: text search found the
        // definition and a call site; LSP found only the declaration. The union
        // must keep all three locations, not just the LSP one.
        let text = vec![
            ("chunk_remove.c".to_string(), 397, "def".to_string()),
            ("nisd_write.c".to_string(), 581, "call".to_string()),
            ("chunk_remove.h".to_string(), 53, "decl".to_string()),
        ];
        let lsp = vec![("chunk_remove.h".to_string(), 53, "lsp-decl".to_string())];

        let merged = CodeIntelEngine::merge_references(text, lsp);

        assert_eq!(
            merged.len(),
            3,
            "duplicate (path,line) must collapse: {merged:?}"
        );
        assert!(merged.contains(&("chunk_remove.c".to_string(), 397, "def".to_string())));
        assert!(merged.contains(&("nisd_write.c".to_string(), 581, "call".to_string())));
        // primary (text) content wins on the shared declaration location.
        assert!(merged.contains(&("chunk_remove.h".to_string(), 53, "decl".to_string())));
    }

    #[test]
    fn merge_references_keeps_lsp_only_locations() {
        // A location only LSP knows about must survive the merge.
        let text = vec![("a.c".to_string(), 1, "a".to_string())];
        let lsp = vec![("b.c".to_string(), 2, "b".to_string())];
        let merged = CodeIntelEngine::merge_references(text, lsp);
        assert_eq!(merged.len(), 2);
        assert!(merged.contains(&("b.c".to_string(), 2, "b".to_string())));
    }

    #[test]
    fn submodule_paths_parses_gitmodules() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir.path().join(".gitmodules"),
            "[submodule \"niova-core\"]\n\tpath = niova-core\n\turl = ../niova-core.git\n\
             [submodule \"other\"]\n\tpath = vendor/other\n",
        );
        let mut paths = submodule_paths(dir.path());
        paths.sort();
        assert_eq!(
            paths,
            vec!["niova-core".to_string(), "vendor/other".to_string()]
        );
    }

    #[test]
    fn submodule_paths_empty_without_gitmodules() {
        let dir = TempDir::new().unwrap();
        assert!(submodule_paths(dir.path()).is_empty());
    }

    #[test]
    fn is_filename_like_distinguishes_files_from_symbols() {
        assert!(is_filename_like("mount_i_linux.h"));
        assert!(is_filename_like("chunk_remove.c"));
        assert!(is_filename_like("index.rs"));
        // Symbols, not files.
        assert!(!is_filename_like("CodeIntelEngine"));
        assert!(!is_filename_like("Type::method"));
        assert!(!is_filename_like("fn foo("));
        assert!(!is_filename_like("validate_path"));
    }

    #[test]
    fn cxx_parser_language_names_drive_augmentation_gate() {
        // Regression: index_repo gates the clangd/ccls/gtags augmentation pass on
        // is_cxx_language(parsed.language). The parser names C "c" and C++ "cpp"
        // (lowercase); a stale uppercase "C"/"C++" comparison made the gate always
        // false, so no C/C++ symbol was ever cross-validated. Couple the two so
        // they cannot drift apart again.
        let parser = crate::parser::LanguageParser::new().unwrap();
        for (path, src) in [
            ("a.c", "int f(void) { return 0; }\n"),
            ("a.cpp", "int g() { return 0; }\n"),
        ] {
            let parsed = parser.parse_file(Path::new(path), src).unwrap();
            assert!(
                is_cxx_language(&parsed.language),
                "parser language {:?} for {} is not recognized by is_cxx_language",
                parsed.language,
                path
            );
        }
    }

    fn sym(name: &str, line: usize, source: SourceSet) -> Symbol {
        Symbol {
            name: name.to_string(),
            kind: if source == SourceSet::GTAGS {
                SymbolKind::Unknown
            } else {
                SymbolKind::Function
            },
            file_path: "a.c".to_string(),
            start_line: line,
            end_line: line,
            signature: (source != SourceSet::GTAGS).then(|| format!("sig@{}", line)),
            qualified_name: None,
            doc_comment: None,
            confirmed_by: source,
            line_conflicts: Vec::new(),
        }
    }

    /// A C function symbol: a definition in a `.c` file, or the prototype for
    /// it in a header.
    fn cxx_symbol(name: &str, file: &str, start_line: usize, end_line: usize) -> Symbol {
        Symbol {
            name: name.to_string(),
            kind: SymbolKind::Function,
            file_path: file.to_string(),
            start_line,
            end_line,
            signature: None,
            qualified_name: None,
            doc_comment: None,
            confirmed_by: SourceSet::CCLS,
            line_conflicts: Vec::new(),
        }
    }

    /// Regression: a caller list held the queried function itself, at its own
    /// definition line, and two entries naming a header at the line numbers of
    /// the `.c` file that includes it.
    #[test]
    fn only_a_call_site_counts_as_a_caller() {
        let symbols = vec![
            cxx_symbol("spawn_helper", "src/helper.c", 101, 140),
            cxx_symbol("obtain_fd", "src/helper.c", 660, 710),
            cxx_symbol("spawn_helper", "src/helper_i.h", 246, 246),
        ];

        // A real call site.
        assert!(CodeIntelEngine::reference_is_a_call(
            &symbols,
            "spawn_helper",
            "src/helper.c",
            695,
            "res = spawn_helper(&fd, argv);"
        ));

        // The definition line of the function itself.
        assert!(!CodeIntelEngine::reference_is_a_call(
            &symbols,
            "spawn_helper",
            "src/helper.c",
            101,
            "static int spawn_helper(int *fd, char **argv)"
        ));

        // A prototype in a header.
        assert!(!CodeIntelEngine::reference_is_a_call(
            &symbols,
            "spawn_helper",
            "src/helper_i.h",
            246,
            "int spawn_helper(int *fd, char **argv);"
        ));

        // ccls reporting the header path with the .c file's line number: the
        // named line does not mention the function at all.
        assert!(!CodeIntelEngine::reference_is_a_call(
            &symbols,
            "spawn_helper",
            "src/helper_linux.h",
            695,
            "#define HELPER_LINUX_H"
        ));
    }

    #[test]
    fn enclosing_function_prefers_the_tightest_range() {
        let symbols = vec![
            cxx_symbol("session_stop", "include/api.h", 2420, 6000),
            cxx_symbol("session_start", "include/api.h", 5300, 5320),
        ];

        let found = CodeIntelEngine::enclosing_function_at(&symbols, "include/api.h", 5310)
            .expect("a symbol covers the line");
        assert_eq!(found.name, "session_start");
    }

    #[test]
    fn merge_higher_priority_wins_line_and_records_conflict() {
        // tree-sitter at 10, clangd at 11 within the window: clangd wins the
        // canonical line, tree-sitter's line is retained as a conflict.
        let mut existing = vec![sym("foo", 10, SourceSet::TREE_SITTER)];
        merge_symbols(
            &mut existing,
            vec![sym("foo", 11, SourceSet::CLANGD)],
            SourceSet::CLANGD,
        );

        assert_eq!(existing.len(), 1);
        let foo = &existing[0];
        assert_eq!(foo.start_line, 11);
        assert!(foo.confirmed_by.contains(SourceSet::TREE_SITTER));
        assert!(foo.confirmed_by.contains(SourceSet::CLANGD));
        assert_eq!(foo.line_conflicts.len(), 1);
        assert_eq!(foo.line_conflicts[0].source, SourceSet::TREE_SITTER);
        assert_eq!(foo.line_conflicts[0].line, 10);
    }

    /// Regression: a function ending at line 20 was reported to end at line
    /// 90, the end line ccls gave from its index of an older file version.
    #[test]
    fn merge_keeps_the_end_line_tree_sitter_parsed() {
        let mut existing = vec![Symbol {
            end_line: 20,
            ..sym("foo", 10, SourceSet::TREE_SITTER)
        }];
        merge_symbols(
            &mut existing,
            vec![Symbol {
                end_line: 90,
                ..sym("foo", 11, SourceSet::CCLS)
            }],
            SourceSet::CCLS,
        );

        assert_eq!(existing.len(), 1);
        assert_eq!(existing[0].start_line, 11);
        assert_eq!(existing[0].end_line, 20);

        // Without a tree-sitter parse, the backend's end line is all there is.
        let mut gtags_only = vec![sym("foo", 10, SourceSet::GTAGS)];
        merge_symbols(
            &mut gtags_only,
            vec![Symbol {
                end_line: 30,
                ..sym("foo", 11, SourceSet::CCLS)
            }],
            SourceSet::CCLS,
        );
        assert_eq!(gtags_only[0].end_line, 30);
    }

    #[test]
    fn merge_lower_priority_keeps_line_but_adds_confirmer() {
        // gtags ranks below tree-sitter: it confirms existence and records its
        // divergent line, but never wins the canonical line or erases metadata.
        let mut existing = vec![sym("foo", 10, SourceSet::TREE_SITTER)];
        merge_symbols(
            &mut existing,
            vec![sym("foo", 9, SourceSet::GTAGS)],
            SourceSet::GTAGS,
        );

        let foo = &existing[0];
        assert_eq!(foo.start_line, 10);
        assert_eq!(foo.kind, SymbolKind::Function);
        assert_eq!(foo.signature.as_deref(), Some("sig@10"));
        assert!(foo.confirmed_by.contains(SourceSet::GTAGS));
        assert_eq!(
            foo.line_conflicts,
            vec![SourceLine {
                source: SourceSet::GTAGS,
                line: 9
            }]
        );
    }

    #[test]
    fn merge_beyond_window_keeps_overloads_separate() {
        // Two same-name definitions far apart are distinct overloads, not a
        // single symbol two backends disagree about.
        let mut existing = vec![sym("foo", 10, SourceSet::TREE_SITTER)];
        merge_symbols(
            &mut existing,
            vec![sym("foo", 40, SourceSet::CLANGD)],
            SourceSet::CLANGD,
        );

        assert_eq!(existing.len(), 2);
    }

    #[test]
    fn merge_inserts_symbol_no_prior_backend_saw() {
        // A macro-defined symbol only gtags found is added standalone.
        let mut existing = vec![sym("foo", 10, SourceSet::TREE_SITTER)];
        merge_symbols(
            &mut existing,
            vec![sym("BAR", 5, SourceSet::GTAGS)],
            SourceSet::GTAGS,
        );

        assert_eq!(existing.len(), 2);
        let bar = existing.iter().find(|s| s.name == "BAR").unwrap();
        assert_eq!(bar.confirmed_by, SourceSet::GTAGS);
    }

    /// clang assumes int for a parameter whose type it cannot resolve, so a
    /// translation unit missing the typedef reports fuse_req_t as int. The
    /// signature must stay the text the file holds.
    #[test]
    fn a_c_signature_survives_a_backend_that_could_not_resolve_a_type() {
        let source_text = "int fuse_req_get_payload(fuse_req_t req, unsigned *len)";
        let mut existing = vec![Symbol {
            signature: Some(source_text.to_string()),
            ..sym("fuse_req_get_payload", 10, SourceSet::TREE_SITTER)
        }];
        merge_symbols(
            &mut existing,
            vec![Symbol {
                signature: Some("int (int, unsigned int *)".to_string()),
                ..sym("fuse_req_get_payload", 10, SourceSet::CCLS)
            }],
            SourceSet::CCLS,
        );

        assert_eq!(existing.len(), 1);
        assert_eq!(existing[0].signature.as_deref(), Some(source_text));
        // The backend still wins everything it ranks for.
        assert!(existing[0].confirmed_by.contains(SourceSet::CCLS));

        // C++ keeps taking the backend's resolved, qualified rendering.
        let mut cxx = vec![Symbol {
            file_path: "a.cc".to_string(),
            signature: Some("auto run(T t)".to_string()),
            ..sym("run", 10, SourceSet::TREE_SITTER)
        }];
        merge_symbols(
            &mut cxx,
            vec![Symbol {
                file_path: "a.cc".to_string(),
                signature: Some("void Runner::run(Task &&)".to_string()),
                ..sym("run", 10, SourceSet::CCLS)
            }],
            SourceSet::CCLS,
        );
        assert_eq!(
            cxx[0].signature.as_deref(),
            Some("void Runner::run(Task &&)")
        );
    }

    fn source_set(bits: &[SourceSet]) -> SourceSet {
        let mut set = SourceSet::empty();
        for bit in bits {
            set.insert(*bit);
        }
        set
    }

    #[test]
    fn provenance_silent_without_cross_validation() {
        // Only one backend enabled — nothing to cross-validate against.
        let out = render_provenance(
            ProvenanceSubject::Symbol,
            SourceSet::TREE_SITTER,
            SourceSet::TREE_SITTER,
            10,
            &[],
        );
        assert!(out.is_none());
    }

    #[test]
    fn provenance_silent_on_full_agreement() {
        let enabled = source_set(&[SourceSet::TREE_SITTER, SourceSet::CLANGD]);
        assert!(render_provenance(ProvenanceSubject::Symbol, enabled, enabled, 10, &[]).is_none());
    }

    #[test]
    fn provenance_reports_existence_disagreement() {
        let enabled = source_set(&[SourceSet::TREE_SITTER, SourceSet::CLANGD, SourceSet::CCLS]);
        let msg = render_provenance(
            ProvenanceSubject::Symbol,
            enabled,
            SourceSet::CLANGD,
            10,
            &[],
        )
        .unwrap();
        assert!(msg.contains("confirmed by clangd"));
        assert!(msg.contains("not by"));
        assert!(msg.contains("ccls") && msg.contains("tree-sitter"));
    }

    #[test]
    fn provenance_flags_gtags_only_edge_as_unverified() {
        let enabled = source_set(&[SourceSet::TREE_SITTER, SourceSet::CLANGD, SourceSet::GTAGS]);
        let msg = render_provenance(
            ProvenanceSubject::CallEdge,
            enabled,
            SourceSet::GTAGS,
            10,
            &[],
        )
        .unwrap();
        assert!(msg.contains("reference-derived (gtags)"));
    }

    #[test]
    fn provenance_reports_line_disagreement() {
        let enabled = source_set(&[SourceSet::TREE_SITTER, SourceSet::CLANGD]);
        let conflicts = vec![SourceLine {
            source: SourceSet::TREE_SITTER,
            line: 9,
        }];
        let msg =
            render_provenance(ProvenanceSubject::Symbol, enabled, enabled, 10, &conflicts).unwrap();
        assert!(msg.contains("WARNING line disagreement"));
        assert!(msg.contains("clangd 10"));
        assert!(msg.contains("tree-sitter 9"));
    }

    #[test]
    fn anchor_lands_on_name_not_return_type() {
        // `foo` starts at column 4, past the `int ` return type.
        let src = "int foo(void) { return 0; }\n";
        let pos = CodeIntelEngine::locate_name_anchor(src, "foo", 1, 1);
        assert_eq!(pos, Some((0, 4)));
    }

    #[test]
    fn anchor_follows_name_onto_a_later_line() {
        // Return type on its own line pushes the name down one line.
        let src = "static int\nfoo(void)\n{\n}\n";
        let pos = CodeIntelEngine::locate_name_anchor(src, "foo", 1, 4);
        assert_eq!(pos, Some((1, 0)));
    }

    #[test]
    fn anchor_requires_whole_word_match() {
        // `foo` must not match inside `foobar`; the real definition is line 2.
        let src = "int foobar(void);\nint foo(void) { return 0; }\n";
        let pos = CodeIntelEngine::locate_name_anchor(src, "foo", 1, 2);
        assert_eq!(pos, Some((1, 4)));
    }

    #[test]
    fn anchor_returns_none_when_name_absent() {
        let src = "int bar(void) { return 0; }\n";
        assert_eq!(CodeIntelEngine::locate_name_anchor(src, "foo", 1, 1), None);
    }

    #[test]
    fn resolve_relative_file_via_directory_field() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        let src = repo.join("src/foo.c");
        write_file(&src, "int foo(void) { return 0; }\n");
        let build = repo.join("build");
        std::fs::create_dir_all(&build).unwrap();

        let resolved = resolve_compile_command_file("../src/foo.c", Some(&build), None)
            .expect("relative file with valid directory must resolve");

        assert_eq!(resolved, src.canonicalize().unwrap());
    }

    #[test]
    fn resolve_absolute_file_is_used_as_is() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        let src = repo.join("src/foo.c");
        write_file(&src, "");

        let abs = src.canonicalize().unwrap();
        let abs_str = abs.to_string_lossy();

        let resolved =
            resolve_compile_command_file(&abs_str, Some(Path::new("/nonexistent/build")), None)
                .expect("absolute file path must resolve regardless of directory");

        assert_eq!(resolved, abs);
    }

    #[test]
    fn resolve_falls_back_to_json_parent_when_directory_is_stale() {
        // Simulates a compile_commands.json generated on another machine:
        // `directory` points at a path that does not exist on this
        // filesystem, but the JSON itself sits in the real build dir, so
        // resolving against the JSON's parent yields the correct file.
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        let src = repo.join("src/foo.c");
        write_file(&src, "");
        let build = repo.join("build");
        std::fs::create_dir_all(&build).unwrap();

        let stale = Path::new("/this/path/does/not/exist/build");
        let resolved = resolve_compile_command_file("../src/foo.c", Some(stale), Some(&build))
            .expect("json-parent fallback must resolve when directory is stale");

        assert_eq!(resolved, src.canonicalize().unwrap());
    }

    #[test]
    fn resolve_returns_none_when_no_strategy_succeeds() {
        let tmp = TempDir::new().unwrap();
        let build = tmp.path().join("build");
        std::fs::create_dir_all(&build).unwrap();

        let resolved = resolve_compile_command_file(
            "no_such_file.c",
            Some(Path::new("/nonexistent/build")),
            Some(&build),
        );

        assert!(
            resolved.is_none(),
            "must return None when neither directory nor json-parent resolves"
        );
    }

    #[test]
    fn load_filter_resolves_meson_style_relative_paths() {
        // End-to-end: a meson-shaped compile_commands.json with `directory`
        // pointing at <repo>/build and `file` as `../lib/foo.c`. Confirms
        // that load_compile_commands_filter populates the set with the
        // canonical path that the walker would also emit — closing the
        // empty-set failure mode that drops every C source at the retain
        // filter.
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        let foo = repo.join("lib/foo.c");
        write_file(&foo, "");
        let build = repo.join("build");
        std::fs::create_dir_all(&build).unwrap();
        let json_path = build.join("compile_commands.json");
        let json = format!(
            r#"[{{"directory": "{}", "command": "cc -c ../lib/foo.c", "file": "../lib/foo.c"}}]"#,
            build.canonicalize().unwrap().display()
        );
        std::fs::write(&json_path, json).unwrap();

        let set = load_compile_commands_filter(repo, &[Path::new("build/compile_commands.json")]);

        assert_eq!(set.len(), 1, "must load exactly one entry");
        assert!(
            set.contains(&foo.canonicalize().unwrap()),
            "set must contain canonical path to lib/foo.c, got: {:?}",
            set
        );
    }

    /// find_symbols on a file the compile_commands filter dropped must say
    /// so, not read as "this file genuinely has no symbols".
    #[tokio::test]
    async fn find_symbols_names_compile_commands_filter_as_the_reason_for_zero() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        // 5 sources clears COMPILE_COMMANDS_MIN_CXX_SOURCES; listing 4 of them
        // (80%) clears the coverage threshold, so the filter engages and
        // drops exactly the one file left off the manifest: e.c.
        let listed_names = ["a.c", "b.c", "c.c", "d.c"];
        for name in listed_names {
            write_file(
                &repo.join(name),
                &format!("void {}(void) {{}}\n", name.replace('.', "_")),
            );
        }
        write_file(&repo.join("e.c"), "void e_func(void) {}\n");

        let entries: Vec<String> = listed_names
            .iter()
            .map(|name| {
                format!(
                    r#"{{"directory": "{}", "command": "cc -c {}", "file": "{}"}}"#,
                    repo.display(),
                    name,
                    repo.join(name).canonicalize().unwrap().display()
                )
            })
            .collect();
        write_file(
            &repo.join("compile_commands.json"),
            &format!("[{}]", entries.join(",")),
        );

        let engine = CodeIntelEngine::with_options(
            tmp.path().join("index"),
            vec![repo.to_path_buf()],
            EngineOptions {
                use_compile_commands: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        engine.complete_initialization().await.unwrap();
        let repo_key = canonical_repo_key(repo).unwrap();

        let output = engine
            .find_symbols(&repo_key, None, Some("*"), Some("e.c"), None, 100)
            .await
            .unwrap();

        assert!(
            output.contains("Found 0 symbols"),
            "e.c should be excluded from the index, got:\n{output}"
        );
        assert!(
            output.contains("compile_commands.json") && output.contains("e.c"),
            "zero-symbol answer must name the compile_commands filter as the reason, got:\n{output}"
        );

        // A listed file is unaffected and carries no such note.
        let output = engine
            .find_symbols(&repo_key, None, Some("*"), Some("a.c"), None, 100)
            .await
            .unwrap();
        assert!(
            output.contains("a_c"),
            "a.c's own symbol should be found:\n{output}"
        );
        assert!(
            !output.contains("compile_commands.json"),
            "a listed file must not carry the exclusion note:\n{output}"
        );
    }
}
