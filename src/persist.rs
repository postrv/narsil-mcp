//! Persistent index storage and watch mode for incremental updates
//!
//! Saves index to disk and watches for file changes to update incrementally.

use anyhow::{Context, Result};
#[cfg(feature = "native")]
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::symbols::Symbol;

/// File metadata for change detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub path: PathBuf,
    pub content_hash: String,
    pub modified_time: u64,
    pub size: u64,
    pub symbols: Vec<Symbol>,
}

/// Persisted index structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedIndex {
    pub version: u32,
    pub created_at: u64,
    pub updated_at: u64,
    pub repo_root: PathBuf,
    pub files: HashMap<PathBuf, FileMetadata>,
}

impl PersistedIndex {
    const CURRENT_VERSION: u32 = 1;

    pub fn new(repo_root: PathBuf) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            version: Self::CURRENT_VERSION,
            created_at: now,
            updated_at: now,
            repo_root,
            files: HashMap::new(),
        }
    }

    /// Load index from disk
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).context("Failed to read index file")?;
        let index: Self = bincode::deserialize(&data).context("Failed to deserialize index")?;

        if index.version != Self::CURRENT_VERSION {
            return Err(anyhow::anyhow!(
                "Index version mismatch: {} != {}",
                index.version,
                Self::CURRENT_VERSION
            ));
        }

        Ok(index)
    }

    /// Save index to disk
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = bincode::serialize(self).context("Failed to serialize index")?;

        // Write to temp file then rename for atomicity
        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, &data).context("Failed to write temp index")?;
        std::fs::rename(&temp_path, path).context("Failed to rename index file")?;

        Ok(())
    }

    /// Check if a file needs re-indexing
    pub fn needs_reindex(&self, path: &Path) -> Result<bool> {
        let metadata = std::fs::metadata(path)?;
        let modified = metadata
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        let size = metadata.len();

        if let Some(cached) = self.files.get(path) {
            // Quick check: size and mtime
            if cached.size == size && cached.modified_time == modified {
                return Ok(false);
            }

            // Slower check: content hash
            let hash = hash_file(path)?;
            Ok(hash != cached.content_hash)
        } else {
            Ok(true)
        }
    }

    /// Update file in index
    pub fn update_file(&mut self, path: PathBuf, symbols: Vec<Symbol>) -> Result<()> {
        let metadata = std::fs::metadata(&path)?;
        let hash = hash_file(&path)?;

        self.files.insert(
            path.clone(),
            FileMetadata {
                path,
                content_hash: hash,
                modified_time: metadata
                    .modified()?
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs(),
                size: metadata.len(),
                symbols,
            },
        );

        self.updated_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(())
    }

    /// Remove file from index
    pub fn remove_file(&mut self, path: &Path) {
        self.files.remove(path);
        self.updated_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Get all symbols across all files
    pub fn all_symbols(&self) -> Vec<&Symbol> {
        self.files.values().flat_map(|f| f.symbols.iter()).collect()
    }

    /// Get symbols for a specific file
    pub fn file_symbols(&self, path: &Path) -> Option<&[Symbol]> {
        self.files.get(path).map(|f| f.symbols.as_slice())
    }
}

/// Compute SHA256 hash of file content
fn hash_file(path: &Path) -> Result<String> {
    let content = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Index storage manager
pub struct IndexStore {
    index_dir: PathBuf,
}

impl IndexStore {
    pub fn new(index_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&index_dir)?;
        Ok(Self { index_dir })
    }

    /// Get the index file path for a repository
    pub fn index_path(&self, repo_root: &Path) -> PathBuf {
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(repo_root.to_string_lossy().as_bytes());
            format!("{:x}", hasher.finalize())
        };
        self.index_dir.join(format!("{}.idx", &hash[..16]))
    }

    /// Load or create index for a repository
    pub fn load_or_create(&self, repo_root: &Path) -> Result<PersistedIndex> {
        let index_path = self.index_path(repo_root);

        if index_path.exists() {
            match PersistedIndex::load(&index_path) {
                Ok(index) => {
                    info!("Loaded existing index from {:?}", index_path);
                    return Ok(index);
                }
                Err(e) => {
                    warn!("Failed to load index, creating new: {}", e);
                }
            }
        }

        info!("Creating new index for {:?}", repo_root);
        Ok(PersistedIndex::new(repo_root.to_path_buf()))
    }

    /// Save index for a repository
    pub fn save(&self, index: &PersistedIndex) -> Result<()> {
        let index_path = self.index_path(&index.repo_root);
        index.save(&index_path)?;
        info!("Saved index to {:?}", index_path);
        Ok(())
    }

    /// List all cached repositories
    pub fn list_cached(&self) -> Result<Vec<PathBuf>> {
        let mut repos = Vec::new();

        for entry in std::fs::read_dir(&self.index_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map(|e| e == "idx").unwrap_or(false) {
                if let Ok(index) = PersistedIndex::load(&path) {
                    repos.push(index.repo_root);
                }
            }
        }

        Ok(repos)
    }
}

/// File watcher for incremental updates (legacy, sync-based polling)
#[cfg(feature = "native")]
pub struct FileWatcher {
    watcher: RecommendedWatcher,
    rx: std::sync::mpsc::Receiver<Result<Event, notify::Error>>,
    watched_paths: Vec<PathBuf>,
}

#[cfg(feature = "native")]
impl FileWatcher {
    pub fn new() -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel();

        let watcher = notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        })?;

        Ok(Self {
            watcher,
            rx,
            watched_paths: Vec::new(),
        })
    }

    /// Start watching a directory
    pub fn watch(&mut self, path: &Path) -> Result<()> {
        self.watcher.watch(path, RecursiveMode::Recursive)?;
        self.watched_paths.push(path.to_path_buf());
        info!("Watching for changes: {:?}", path);
        Ok(())
    }

    /// Stop watching a directory
    pub fn unwatch(&mut self, path: &Path) -> Result<()> {
        self.watcher.unwatch(path)?;
        self.watched_paths.retain(|p| p != path);
        Ok(())
    }

    /// Poll for file changes (non-blocking)
    pub fn poll_changes(&self) -> Vec<FileChange> {
        let mut changes = Vec::new();

        while let Ok(result) = self.rx.try_recv() {
            if let Ok(event) = result {
                for path in event.paths {
                    let change_type = match event.kind {
                        EventKind::Create(_) => ChangeType::Created,
                        EventKind::Modify(_) => ChangeType::Modified,
                        EventKind::Remove(_) => ChangeType::Deleted,
                        _ => continue,
                    };

                    // Filter to source files
                    if is_source_file(&path) {
                        changes.push(FileChange {
                            path: path.to_path_buf(),
                            change_type,
                        });
                    }
                }
            }
        }

        // Deduplicate
        changes.sort_by(|a, b| a.path.cmp(&b.path));
        changes.dedup_by(|a, b| a.path == b.path);

        changes
    }

    /// Block until changes occur
    pub fn wait_for_changes(&self, timeout: Duration) -> Vec<FileChange> {
        let mut changes = Vec::new();

        if let Ok(Ok(event)) = self.rx.recv_timeout(timeout) {
            for path in event.paths {
                let change_type = match event.kind {
                    EventKind::Create(_) => ChangeType::Created,
                    EventKind::Modify(_) => ChangeType::Modified,
                    EventKind::Remove(_) => ChangeType::Deleted,
                    _ => continue,
                };

                if is_source_file(&path) {
                    changes.push(FileChange {
                        path: path.to_path_buf(),
                        change_type,
                    });
                }
            }
        }

        // Drain any additional events
        changes.extend(self.poll_changes());

        changes
    }
}

/// Async file watcher for event-driven incremental updates
#[cfg(feature = "native")]
pub struct AsyncFileWatcher {
    _watcher: RecommendedWatcher,
    watched_paths: Vec<PathBuf>,
}

#[cfg(feature = "native")]
impl AsyncFileWatcher {
    /// Create a new async file watcher and return a channel receiver for events
    pub fn new() -> Result<(Self, mpsc::Receiver<Vec<FileChange>>)> {
        let (tx, rx) = mpsc::channel(100);

        // Create a channel for the notify watcher
        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();

        let watcher = notify::recommended_watcher(move |res| {
            let _ = notify_tx.send(res);
        })?;

        // Spawn a task to process notify events and send batched changes
        tokio::spawn(async move {
            let mut debounce_buffer: HashMap<PathBuf, FileChange> = HashMap::new();
            let debounce_duration = Duration::from_millis(300);
            let mut debounce_timer = tokio::time::interval(debounce_duration);
            debounce_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    // Receive events from notify
                    Some(result) = notify_rx.recv() => {
                        if let Ok(event) = result {
                            for path in event.paths {
                                let change_type = match event.kind {
                                    EventKind::Create(_) => ChangeType::Created,
                                    EventKind::Modify(_) => ChangeType::Modified,
                                    EventKind::Remove(_) => ChangeType::Deleted,
                                    _ => continue,
                                };

                                // Filter to source files
                                if is_source_file(&path) {
                                    // Add to debounce buffer (overwrites previous events for same file)
                                    let path_buf = path.to_path_buf();
                                    debounce_buffer.insert(path_buf.clone(), FileChange { path: path_buf, change_type });
                                }
                            }
                        }
                    }
                    // Debounce timer tick - flush buffered changes
                    _ = debounce_timer.tick() => {
                        if !debounce_buffer.is_empty() {
                            let changes: Vec<FileChange> = debounce_buffer.drain().map(|(_, v)| v).collect();
                            if tx.send(changes).await.is_err() {
                                // Receiver dropped, exit task
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok((
            Self {
                _watcher: watcher,
                watched_paths: Vec::new(),
            },
            rx,
        ))
    }

    /// Watch a directory for changes
    pub fn watch(&mut self, path: &Path) -> Result<()> {
        self._watcher.watch(path, RecursiveMode::Recursive)?;
        self.watched_paths.push(path.to_path_buf());
        info!("Async watching for changes: {:?}", path);
        Ok(())
    }

    /// Stop watching a directory
    pub fn unwatch(&mut self, path: &Path) -> Result<()> {
        self._watcher.unwatch(path)?;
        self.watched_paths.retain(|p| p != path);
        Ok(())
    }

    /// Get the list of watched paths
    pub fn watched_paths(&self) -> &[PathBuf] {
        &self.watched_paths
    }
}

/// A detected file change
#[derive(Debug, Clone)]
pub struct FileChange {
    pub path: PathBuf,
    pub change_type: ChangeType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
}

/// Check if a path is a source file we care about
fn is_source_file(path: &Path) -> bool {
    let extensions = [
        "rs", "py", "js", "jsx", "ts", "tsx", "go", "java", "c", "h", "cpp", "hpp", "cc", "cxx",
        "hxx", "swift", "v", "vh", "sv", "svh",
    ];

    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| extensions.contains(&e))
        .unwrap_or(false)
}

/// Incremental indexer that combines persistence and watching
#[cfg(feature = "native")]
pub struct IncrementalIndexer {
    store: IndexStore,
    index: Arc<RwLock<PersistedIndex>>,
    watcher: Option<FileWatcher>,
}

#[cfg(feature = "native")]
impl IncrementalIndexer {
    pub fn new(index_dir: PathBuf, repo_root: &Path) -> Result<Self> {
        let store = IndexStore::new(index_dir)?;
        let index = store.load_or_create(repo_root)?;

        Ok(Self {
            store,
            index: Arc::new(RwLock::new(index)),
            watcher: None,
        })
    }

    /// Enable watch mode
    pub fn enable_watch(&mut self, repo_root: &Path) -> Result<()> {
        let mut watcher = FileWatcher::new()?;
        watcher.watch(repo_root)?;
        self.watcher = Some(watcher);
        Ok(())
    }

    /// Check for and process file changes
    pub fn process_changes<F>(&self, mut reindex_fn: F) -> Result<usize>
    where
        F: FnMut(&Path) -> Result<Vec<Symbol>>,
    {
        let changes = match &self.watcher {
            Some(w) => w.poll_changes(),
            None => return Ok(0),
        };

        if changes.is_empty() {
            return Ok(0);
        }

        let mut index = self.index.write();
        let mut count = 0;

        for change in changes {
            match change.change_type {
                ChangeType::Created | ChangeType::Modified => {
                    debug!("Re-indexing: {:?}", change.path);
                    match reindex_fn(&change.path) {
                        Ok(symbols) => {
                            index.update_file(change.path, symbols)?;
                            count += 1;
                        }
                        Err(e) => {
                            warn!("Failed to index {:?}: {}", change.path, e);
                        }
                    }
                }
                ChangeType::Deleted => {
                    debug!("Removing from index: {:?}", change.path);
                    index.remove_file(&change.path);
                    count += 1;
                }
            }
        }

        if count > 0 {
            self.store.save(&index)?;
        }

        Ok(count)
    }

    /// Get a read reference to the index
    pub fn index(&self) -> Arc<RwLock<PersistedIndex>> {
        Arc::clone(&self.index)
    }

    /// Force save the current index
    pub fn save(&self) -> Result<()> {
        let index = self.index.read();
        self.store.save(&index)
    }

    /// Get files that need re-indexing
    pub fn files_needing_reindex(&self) -> Result<Vec<PathBuf>> {
        let index = self.index.read();
        let mut needs_reindex = Vec::new();

        for path in index.files.keys() {
            if !path.exists() || index.needs_reindex(path)? {
                needs_reindex.push(path.clone());
            }
        }

        Ok(needs_reindex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_hash_consistency() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "hello world").unwrap();

        let hash1 = hash_file(&file).unwrap();
        let hash2 = hash_file(&file).unwrap();
        assert_eq!(hash1, hash2);

        std::fs::write(&file, "hello world!").unwrap();
        let hash3 = hash_file(&file).unwrap();
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_is_source_file() {
        assert!(is_source_file(Path::new("foo.rs")));
        assert!(is_source_file(Path::new("bar.py")));
        assert!(is_source_file(Path::new("src/index.ts")));
        assert!(!is_source_file(Path::new("README.md")));
        assert!(!is_source_file(Path::new("data.json")));
    }

    #[test]
    fn test_index_store() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();

        let repo = tempdir().unwrap();
        let index = PersistedIndex::new(repo.path().to_path_buf());

        store.save(&index).unwrap();

        let loaded = store.load_or_create(repo.path()).unwrap();
        assert_eq!(loaded.version, PersistedIndex::CURRENT_VERSION);
    }
}
