//! Code Intelligence Engine - main indexing and query implementation
//!
//! This is the core engine that powers all MCP tool operations.

// Allow dead code for Phase 2/3 features not yet wired up
#![allow(dead_code)]

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{info, warn};

use crate::callgraph::CallGraph;
use crate::cfg;
use crate::dfg;
use crate::embeddings::EmbeddingEngine;
use crate::git::GitRepo;
use crate::lsp::{LspConfig, LspManager};
use crate::metrics::Metrics;
use crate::neural::{NeuralConfig, NeuralEngine};
use crate::parser::LanguageParser;
use crate::persist::{IndexStore, PersistedIndex};
use crate::remote::RemoteRepoManager;
use crate::search::ConcurrentSearchIndex;
use crate::streaming::StreamingConfig;
use crate::symbols::{Symbol, SymbolKind};
use crate::type_inference::{TypeError, TypeInferencer};

/// Metadata about an indexed repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoMetadata {
    pub name: String,
    pub path: PathBuf,
    pub file_count: usize,
    pub total_lines: usize,
    pub languages: HashMap<String, LanguageStats>,
    pub last_indexed: SystemTime,
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

/// Options for configuring the CodeIntelEngine
#[derive(Debug, Clone, Default)]
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
    /// Neural embedding configuration
    pub neural_config: NeuralConfig,
}

/// The main code intelligence engine
pub struct CodeIntelEngine {
    /// Base path for index storage
    #[allow(dead_code)]
    index_path: PathBuf,
    /// Registered repository paths
    repo_paths: Vec<PathBuf>,
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
    /// Neural embedding engine for semantic search (when neural is enabled)
    neural_engine: Option<Arc<NeuralEngine>>,
    /// Engine options (feature flags)
    options: EngineOptions,
    /// Index store for persistence (when persist is enabled)
    /// Performance metrics
    pub metrics: Arc<Metrics>,
    index_store: Option<IndexStore>,
    /// LSP manager for enhanced code analysis (when lsp is enabled)
    lsp_manager: Option<Arc<LspManager>>,
    /// Remote repository manager for GitHub integration
    remote_manager: Option<Arc<tokio::sync::Mutex<RemoteRepoManager>>>,
    /// Cached security rules engine (avoids reloading rules on each scan)
    security_engine: Arc<crate::security_rules::SecurityRulesEngine>,
    /// Tracks whether background initialization has completed
    initialization_complete: AtomicBool,
    /// Number of repositories that have been fully indexed
    indexed_repos_count: AtomicUsize,
    /// Total number of repositories to index
    total_repos_count: AtomicUsize,
}

impl CodeIntelEngine {
    /// Create a new engine with default options (no git, no call graphs, no persistence)
    #[allow(dead_code)]
    pub async fn new(index_path: PathBuf, repo_paths: Vec<PathBuf>) -> Result<Self> {
        Self::with_options(index_path, repo_paths, EngineOptions::default()).await
    }

    /// Create a new engine with the specified options
    pub async fn with_options(
        index_path: PathBuf,
        repo_paths: Vec<PathBuf>,
        options: EngineOptions,
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
                    Some(store)
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
            Some(Arc::new(LspManager::new(
                options.lsp_config.clone(),
                expanded_repos.clone(),
            )))
        } else {
            None
        };
        // Initialize neural engine if enabled
        let neural_engine = if options.neural_config.enabled {
            match NeuralEngine::new(options.neural_config.clone()) {
                Ok(engine) => {
                    info!(
                        "Neural embedding engine initialized (backend={}, model={:?})",
                        options.neural_config.backend, options.neural_config.model_name
                    );
                    Some(Arc::new(engine))
                }
                Err(e) => {
                    warn!(
                        "Failed to initialize neural engine: {}. Run 'narsil-mcp config init --neural' to set up your API key.",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        // Pre-initialize security rules engine (caches compiled patterns)
        let security_engine = Arc::new(crate::security_rules::SecurityRulesEngine::new());

        let total_repos = expanded_repos.len();

        let engine = Self {
            index_path: expanded_index,
            repo_paths: expanded_repos.clone(),
            repos: DashMap::new(),
            symbols: DashMap::new(),
            file_cache: DashMap::new(),
            parser: Arc::new(LanguageParser::new()?),
            git_repos: DashMap::new(),
            call_graphs: DashMap::new(),
            search_index: Arc::new(ConcurrentSearchIndex::new()),
            embedding_engine: Arc::new(EmbeddingEngine::new(1000)), // 1000-dim TF-IDF vectors
            neural_engine,
            options: options.clone(),
            index_store,
            metrics: Arc::new(Metrics::new()),
            lsp_manager,
            remote_manager: None,
            security_engine,
            initialization_complete: AtomicBool::new(false),
            indexed_repos_count: AtomicUsize::new(0),
            total_repos_count: AtomicUsize::new(total_repos),
        };

        // Try to load persisted indexes first if persistence is enabled
        let mut loaded_repos: Vec<String> = Vec::new();
        if options.persist_enabled {
            if let Some(ref store) = engine.index_store {
                for repo_path in &expanded_repos {
                    if let Ok(persisted) = store.load_or_create(repo_path) {
                        if !persisted.files.is_empty() {
                            let repo_name = repo_path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown")
                                .to_string();

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
                    let repo_name = repo_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let call_graph = CallGraph::new();
                    info!("Call graph initialized for repository: {}", repo_name);
                    engine.call_graphs.insert(repo_name, call_graph);
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

    /// Complete the deferred initialization by indexing all repositories
    /// and initializing git. This should be called in the background after
    /// the engine is created to allow the MCP server to respond quickly.
    pub async fn complete_initialization(&self) -> Result<()> {
        if self.initialization_complete.load(Ordering::Acquire) {
            info!("Initialization already complete, skipping");
            return Ok(());
        }

        info!("Starting background initialization");

        // Index repos that weren't loaded from persistence
        for repo_path in &self.repo_paths {
            let repo_name = repo_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            // Check if already loaded from persistence
            if self.repos.contains_key(&repo_name) {
                info!("Repository {} already loaded from cache", repo_name);
                self.indexed_repos_count.fetch_add(1, Ordering::Release);
                continue;
            }

            if repo_path.exists() {
                info!("Indexing repository: {:?}", repo_path);
                if let Err(e) = self.index_repo(repo_path).await {
                    warn!("Failed to index {:?}: {}", repo_path, e);
                } else {
                    self.indexed_repos_count.fetch_add(1, Ordering::Release);
                }
            } else {
                warn!("Repository path does not exist: {:?}", repo_path);
            }
        }

        // Initialize git repos if enabled
        if self.options.git_enabled {
            for repo_path in &self.repo_paths {
                if repo_path.exists() {
                    let repo_name = repo_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();

                    match GitRepo::new(repo_path) {
                        Ok(git_repo) => {
                            info!("Git enabled for repository: {}", repo_name);
                            self.git_repos.insert(repo_name, git_repo);
                        }
                        Err(e) => {
                            warn!("Failed to initialize git for {}: {}", repo_name, e);
                        }
                    }
                }
            }
        }

        self.initialization_complete.store(true, Ordering::Release);
        info!("Background initialization complete");

        Ok(())
    }

    /// Check if background initialization has completed
    pub fn is_fully_initialized(&self) -> bool {
        self.initialization_complete.load(Ordering::Acquire)
    }

    /// Get detailed initialization status
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

    async fn index_repos(&self) -> Result<()> {
        for repo_path in &self.repo_paths {
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

    async fn index_repo(&self, path: &Path) -> Result<()> {
        let start_time = std::time::Instant::now();
        let repo_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let mut languages: HashMap<String, LanguageStats> = HashMap::new();
        let mut symbols_vec: Vec<Symbol> = Vec::new();
        let mut neural_docs: Vec<crate::neural::NeuralDocument> = Vec::new();
        let mut file_count = 0;
        let mut total_lines = 0;

        // Use ignore crate to respect .gitignore
        let walker = ignore::WalkBuilder::new(path)
            .hidden(true)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .build();

        let files: Vec<PathBuf> = walker
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .map(|e| e.path().to_path_buf())
            .collect();

        // Parse files in parallel
        let metrics = Arc::clone(&self.metrics);
        let parsed_results: Vec<_> = files
            .par_iter()
            .filter_map(|file_path| {
                let parse_start = std::time::Instant::now();
                let content = std::fs::read_to_string(file_path).ok()?;
                let parsed = self.parser.parse_file(file_path, &content).ok()?;
                metrics.record_file_parse(parse_start.elapsed());
                Some((file_path.clone(), content, parsed))
            })
            .collect();

        // Collect parsed trees for call graph construction
        let mut trees_for_callgraph: Vec<(String, String, tree_sitter::Tree)> = Vec::new();

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

            for mut symbol in parsed.symbols {
                symbol.file_path = relative_path.clone();

                // Index symbol into embedding engine for similarity search
                if let Some(ref sig) = symbol.signature {
                    let symbol_id = format!("{}::{}", relative_path, symbol.name);
                    self.embedding_engine.index_snippet(
                        symbol_id.clone(),
                        relative_path.clone(),
                        sig.clone(),
                        symbol.start_line,
                        symbol.end_line,
                    );

                    // Collect for neural batch indexing if enabled
                    if self.neural_engine.is_some() {
                        neural_docs.push(crate::neural::NeuralDocument {
                            id: symbol_id,
                            file_path: relative_path.clone(),
                            content: sig.clone(),
                            start_line: symbol.start_line,
                            end_line: symbol.end_line,
                            symbol_name: Some(symbol.name.clone()),
                        });
                    }
                }

                symbols_vec.push(symbol);
            }

            // Cache file content
            self.file_cache
                .insert(file_path.clone(), Arc::new(content.clone()));

            // Index file for semantic search
            self.search_index.index_file(&relative_path, &content);

            // Collect tree for call graph if enabled and tree exists
            if self.options.call_graph_enabled {
                if let Some(tree) = parsed.tree {
                    trees_for_callgraph.push((relative_path, content, tree));
                }
            }
        }

        let metadata = RepoMetadata {
            name: repo_name.clone(),
            path: path.to_path_buf(),
            file_count,
            total_lines,
            languages,
            last_indexed: SystemTime::now(),
        };

        info!(
            "Indexed {} files, {} symbols in {}",
            file_count,
            symbols_vec.len(),
            repo_name
        );

        // Batch index neural embeddings if enabled
        if let Some(ref neural) = self.neural_engine {
            if !neural_docs.is_empty() {
                info!(
                    "Generating neural embeddings for {} symbols...",
                    neural_docs.len()
                );
                let items: Vec<(crate::neural::NeuralDocument,)> =
                    neural_docs.into_iter().map(|d| (d,)).collect();
                if let Err(e) = neural.index_batch(&items) {
                    warn!("Failed to batch index neural embeddings: {}", e);
                } else {
                    info!("Neural embeddings indexed successfully");
                }
            }
        }

        // Record indexing metrics
        let elapsed = start_time.elapsed();
        self.metrics
            .record_repo_index(repo_name.clone(), elapsed, file_count, symbols_vec.len());

        self.repos.insert(repo_name.clone(), metadata);
        self.symbols.insert(repo_name.clone(), symbols_vec);

        // Build call graph if enabled
        if self.options.call_graph_enabled && !trees_for_callgraph.is_empty() {
            if let Some(call_graph) = self.call_graphs.get(&repo_name) {
                if let Err(e) = call_graph.build_from_files(&trees_for_callgraph) {
                    warn!("Failed to build call graph for {}: {}", repo_name, e);
                } else {
                    info!(
                        "Built call graph for {} with {} files",
                        repo_name,
                        trees_for_callgraph.len()
                    );
                }
            }
        }

        Ok(())
    }

    pub async fn reindex_all(&self) -> Result<()> {
        self.repos.clear();
        self.symbols.clear();
        self.file_cache.clear();
        self.search_index.clear();
        self.embedding_engine.clear();
        self.index_repos().await
    }

    pub async fn reindex(&self, repo: Option<&str>) -> Result<String> {
        match repo {
            Some(name) => {
                let path = self.get_repo_path(name)?;
                self.repos.remove(name);
                self.symbols.remove(name);
                self.index_repo(&path).await?;
                Ok(format!("Re-indexed repository: {}", name))
            }
            None => {
                self.reindex_all().await?;
                Ok("Re-indexed all repositories".to_string())
            }
        }
    }

    fn get_repo_path(&self, name: &str) -> Result<PathBuf> {
        // Check for empty/missing repo parameter
        if name.is_empty() {
            let repo_names: Vec<_> = self.repos.iter().map(|r| r.key().clone()).collect();
            if repo_names.is_empty() {
                return Err(anyhow!(
                    "Missing required 'repo' parameter. No repositories are indexed yet. \
                     Use --repos flag when starting the server."
                ));
            }
            return Err(anyhow!(
                "Missing required 'repo' parameter. Available repositories: {}. \
                 Use list_repos to see all indexed repositories.",
                repo_names.join(", ")
            ));
        }

        // Check if it's already a path
        let as_path = PathBuf::from(name);
        if as_path.exists() {
            return Ok(as_path);
        }

        // Look up by name
        self.repos.get(name).map(|r| r.path.clone()).ok_or_else(|| {
            let repo_names: Vec<_> = self.repos.iter().map(|r| r.key().clone()).collect();
            anyhow!(
                "Repository '{}' not found. Available repositories: {}. \
                 Use list_repos to see all indexed repositories.",
                name,
                repo_names.join(", ")
            )
        })
    }

    /// Phase C3: Check if streaming should be enabled for the given result count.
    ///
    /// Returns true if:
    /// - Streaming is enabled in options
    /// - Result count exceeds the auto_stream_threshold
    #[allow(dead_code)]
    pub fn should_stream(&self, result_count: usize) -> bool {
        self.options.streaming_config.enabled
            && result_count > self.options.streaming_config.auto_stream_threshold
    }

    /// Phase C3: Get a reference to the streaming configuration
    #[allow(dead_code)]
    pub fn streaming_config(&self) -> &StreamingConfig {
        &self.options.streaming_config
    }

    /// Get a reference to the engine options
    pub fn options(&self) -> &EngineOptions {
        &self.options
    }

    /// Helper to create a helpful error message for missing/invalid repo parameter
    fn repo_not_found_error(&self, repo: &str) -> anyhow::Error {
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
            anyhow!(
                "Repository '{}' not found. Available repositories: {}. \
                 Use list_repos to see all indexed repositories.",
                repo,
                repo_names.join(", ")
            )
        }
    }

    pub async fn list_repos(&self) -> Result<String> {
        let mut output = String::new();
        output.push_str("# Indexed Repositories\n\n");

        for entry in self.repos.iter() {
            let repo = entry.value();
            output.push_str(&format!("## {}\n", repo.name));
            output.push_str(&format!("- **Path**: {}\n", repo.path.display()));
            output.push_str(&format!("- **Files**: {}\n", repo.file_count));
            output.push_str(&format!("- **Total Lines**: {}\n", repo.total_lines));
            output.push_str("- **Languages**:\n");

            let mut langs: Vec<_> = repo.languages.iter().collect();
            langs.sort_by(|a, b| b.1.line_count.cmp(&a.1.line_count));

            for (lang, stats) in langs {
                output.push_str(&format!(
                    "  - {}: {} files, {} lines\n",
                    lang, stats.file_count, stats.line_count
                ));
            }
            output.push('\n');
        }

        if self.repos.is_empty() {
            output.push_str("*No repositories indexed yet.*\n");
        }

        Ok(output)
    }

    pub async fn get_project_structure(&self, repo: &str, max_depth: usize) -> Result<String> {
        let path = self.get_repo_path(repo)?;
        let mut output = String::new();
        output.push_str(&format!("# Project Structure: {}\n\n```\n", repo));

        self.build_tree(&path, &path, 0, max_depth, &mut output)?;

        output.push_str("```\n");
        Ok(output)
    }

    #[allow(clippy::only_used_in_recursion)]
    fn build_tree(
        &self,
        root: &Path,
        current: &Path,
        depth: usize,
        max_depth: usize,
        output: &mut String,
    ) -> Result<()> {
        if depth > max_depth {
            return Ok(());
        }

        let indent = "  ".repeat(depth);
        let name = current.file_name().and_then(|n| n.to_str()).unwrap_or(".");

        if current.is_dir() {
            // Skip hidden and common non-essential directories
            if name.starts_with('.')
                || name == "node_modules"
                || name == "target"
                || name == "__pycache__"
                || name == "venv"
                || name == ".git"
            {
                return Ok(());
            }

            output.push_str(&format!("{}{} {}/\n", indent, "\u{1f4c1}", name));

            let mut entries: Vec<_> = std::fs::read_dir(current)?.filter_map(|e| e.ok()).collect();
            entries.sort_by_key(|e| (!e.path().is_dir(), e.file_name()));

            for entry in entries {
                self.build_tree(root, &entry.path(), depth + 1, max_depth, output)?;
            }
        } else {
            let size = std::fs::metadata(current).map(|m| m.len()).unwrap_or(0);
            let size_str = format_size(size);
            let icon = get_file_icon(name);
            output.push_str(&format!("{}{} {} ({})\n", indent, icon, name, size_str));
        }

        Ok(())
    }

    pub async fn find_symbols(
        &self,
        repo: &str,
        symbol_type: Option<&str>,
        pattern: Option<&str>,
        file_pattern: Option<&str>,
    ) -> Result<String> {
        let symbols = self
            .symbols
            .get(repo)
            .ok_or_else(|| self.repo_not_found_error(repo))?;

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

        let glob_pattern = file_pattern.and_then(|p| glob::Pattern::new(p).ok());

        let filtered: Vec<_> = symbols
            .iter()
            .filter(|s| {
                // Type filter
                if let Some(ref kind) = type_filter {
                    if &s.kind != kind {
                        return false;
                    }
                }
                // Name pattern filter
                if let Some(pat) = pattern {
                    if !s.name.to_lowercase().contains(&pat.to_lowercase()) {
                        return false;
                    }
                }
                // File pattern filter
                if let Some(ref glob) = glob_pattern {
                    if !glob.matches(&s.file_path) {
                        return false;
                    }
                }
                true
            })
            .collect();

        let mut output = String::new();
        output.push_str(&format!("# Symbols in {}\n\n", repo));
        output.push_str(&format!("Found {} symbols\n\n", filtered.len()));

        // Group by kind
        let mut by_kind: HashMap<SymbolKind, Vec<&Symbol>> = HashMap::new();
        for symbol in &filtered {
            by_kind.entry(symbol.kind.clone()).or_default().push(symbol);
        }

        for (kind, syms) in by_kind {
            output.push_str(&format!("## {:?}s\n\n", kind));
            for sym in syms {
                output.push_str(&format!(
                    "- **{}** (`{}:{}`) {}\n",
                    sym.name,
                    sym.file_path,
                    sym.start_line,
                    sym.signature.as_deref().unwrap_or("")
                ));
            }
            output.push('\n');
        }

        Ok(output)
    }

    pub async fn get_symbol_definition(
        &self,
        repo: &str,
        symbol_name: &str,
        context_lines: usize,
    ) -> Result<String> {
        let repo_path = self.get_repo_path(repo)?;
        let symbols = self
            .symbols
            .get(repo)
            .ok_or_else(|| self.repo_not_found_error(repo))?;

        // Find matching symbol
        let symbol = symbols
            .iter()
            .find(|s| s.name == symbol_name || s.qualified_name.as_deref() == Some(symbol_name))
            .ok_or_else(|| {
                anyhow!(
                    "Symbol '{}' not found in repository '{}'",
                    symbol_name,
                    repo
                )
            })?;

        let file_path = validate_path(&repo_path, &symbol.file_path)?;
        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let lines: Vec<&str> = content.lines().collect();
        let start = symbol.start_line.saturating_sub(context_lines + 1);
        let end = (symbol.end_line + context_lines).min(lines.len());

        let mut output = String::new();
        output.push_str(&format!("# {}\n\n", symbol.name));
        output.push_str(&format!("**File**: `{}`\n", symbol.file_path));
        output.push_str(&format!(
            "**Lines**: {}-{}\n",
            symbol.start_line, symbol.end_line
        ));
        output.push_str(&format!("**Kind**: {:?}\n\n", symbol.kind));

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
                "â†’"
            } else {
                " "
            };
            output.push_str(&format!("{} {:4} â”‚ {}\n", marker, line_num, line));
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
    ) -> Result<String> {
        let query_lower = query.to_lowercase();
        let mut results: Vec<CodeExcerpt> = Vec::new();

        let repos_to_search: Vec<String> = match repo {
            Some(r) => vec![r.to_string()],
            None => self.repos.iter().map(|r| r.key().clone()).collect(),
        };

        let glob = file_pattern.and_then(|p| glob::Pattern::new(p).ok());

        for repo_name in repos_to_search {
            let repo_path = match self.get_repo_path(&repo_name) {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Search through cached files
            for entry in self.file_cache.iter() {
                let file_path = entry.key();

                // Check if file is in this repo
                if !file_path.starts_with(&repo_path) {
                    continue;
                }

                let rel_path = file_path
                    .strip_prefix(&repo_path)
                    .unwrap_or(file_path)
                    .to_string_lossy();

                // Apply file pattern filter
                if let Some(ref g) = glob {
                    if !g.matches(&rel_path) {
                        continue;
                    }
                }

                let content = entry.value();
                let lines: Vec<&str> = content.lines().collect();

                // Simple text search with scoring
                for (line_num, line) in lines.iter().enumerate() {
                    if line.to_lowercase().contains(&query_lower) {
                        let start = line_num.saturating_sub(3);
                        let end = (line_num + 4).min(lines.len());

                        let excerpt_content: String = lines[start..end]
                            .iter()
                            .enumerate()
                            .map(|(i, l)| format!("{:4} â”‚ {}", start + i + 1, l))
                            .collect::<Vec<_>>()
                            .join("\n");

                        // Calculate relevance score
                        let score = calculate_relevance(line, &query_lower);

                        results.push(CodeExcerpt {
                            file_path: rel_path.to_string(),
                            start_line: start + 1,
                            end_line: end,
                            content: excerpt_content,
                            language: get_language_id(&rel_path).to_string(),
                            relevance_score: score,
                        });
                    }
                }
            }
        }

        // Sort by relevance and take top results
        results.sort_by(|a, b| b.relevance_score.partial_cmp(&a.relevance_score).unwrap());
        results.truncate(max_results);

        let mut output = String::new();
        output.push_str(&format!("# Search Results for: `{}`\n\n", query));
        output.push_str(&format!("Found {} results\n\n", results.len()));

        for (i, result) in results.iter().enumerate() {
            output.push_str(&format!("## {}. `{}`\n", i + 1, result.file_path));
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

        Ok(output)
    }

    pub async fn get_file(
        &self,
        repo: &str,
        path: &str,
        start_line: Option<usize>,
        end_line: Option<usize>,
    ) -> Result<String> {
        let repo_path = self.get_repo_path(repo)?;
        let file_path = validate_path(&repo_path, path)?;

        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let lines: Vec<&str> = content.lines().collect();
        let start = start_line.unwrap_or(1).saturating_sub(1);
        let end = end_line.unwrap_or(lines.len()).min(lines.len());

        let mut output = String::new();
        output.push_str(&format!("# {}\n\n", path));
        output.push_str(&format!(
            "Lines {}-{} of {}\n\n",
            start + 1,
            end,
            lines.len()
        ));

        output.push_str("```");
        output.push_str(get_language_id(path));
        output.push('\n');

        for (i, line) in lines[start..end].iter().enumerate() {
            output.push_str(&format!("{:4} â”‚ {}\n", start + i + 1, line));
        }

        output.push_str("```\n");

        Ok(output)
    }

    pub async fn find_references(
        &self,
        repo: &str,
        symbol: &str,
        _include_definition: bool,
    ) -> Result<String> {
        let repo_path = self.get_repo_path(repo)?;

        // Phase B3: Run text search and LSP search in parallel
        // Text search is fast (synchronous), LSP can be slow
        // Use tokio::select! to avoid blocking on LSP timeout

        // Check if LSP is enabled before spawning async work
        let lsp_enabled = self
            .lsp_manager
            .as_ref()
            .map(|lsp| lsp.is_enabled())
            .unwrap_or(false);

        if !lsp_enabled {
            // Fast path: no LSP, just do text search
            let text_refs = self.text_search_references(&repo_path, symbol);
            return Ok(self.format_references(&text_refs, false, symbol));
        }

        // LSP is enabled - race text search against LSP with a grace period
        // 1. Do text search immediately (it's fast)
        let text_refs = self.text_search_references(&repo_path, symbol);

        // 2. Try LSP with a short additional timeout (500ms grace period)
        // This way we don't block the full LSP timeout (1.5s) if text search is ready
        let lsp_result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            self.lsp_search_references(repo, symbol, &repo_path),
        )
        .await;

        // 3. Use LSP results if available and non-empty, otherwise text search
        if let Ok(Some(lsp_refs)) = lsp_result {
            if !lsp_refs.is_empty() {
                return Ok(self.format_references(&lsp_refs, true, symbol));
            }
        }

        Ok(self.format_references(&text_refs, false, symbol))
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

                if let Ok(Some(locations)) = lsp
                    .find_references(&language, &file_path, sym.start_line as u32, 0, true)
                    .await
                {
                    let mut references = Vec::new();
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
                                    references.push((
                                        rel,
                                        line_idx + 1,
                                        lines[line_idx].trim().to_string(),
                                    ));
                                }
                            }
                        }
                    }
                    return Some(references);
                }
                break;
            }
        }

        None
    }

    /// Format references into output string
    fn format_references(
        &self,
        references: &[(String, usize, String)],
        lsp_enhanced: bool,
        symbol: &str,
    ) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "# References to `{}`{}\n\n",
            symbol,
            if lsp_enhanced { " (LSP enhanced)" } else { "" }
        ));
        output.push_str(&format!("Found {} references\n\n", references.len()));

        for (path, line, content) in references {
            output.push_str(&format!(
                "- `{}:{}` - `{}`\n",
                path,
                line,
                if content.len() > 80 {
                    &content[..80]
                } else {
                    content
                }
            ));
        }

        output
    }

    pub async fn get_dependencies(
        &self,
        repo: &str,
        path: &str,
        direction: &str,
    ) -> Result<String> {
        let repo_path = self.get_repo_path(repo)?;
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
        for repo_path in &self.repo_paths {
            let repo_name = repo_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            // Create a persisted index from current state
            let mut persisted = PersistedIndex::new(repo_path.clone());

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
                            },
                        );
                    }
                }
            }

            // Save the index
            store.save(&persisted)?;
            saved_count += 1;
            info!(
                "Saved index for {} ({} files)",
                repo_name,
                persisted.files.len()
            );
        }

        Ok(format!(
            "Saved {} repository index(es) to disk successfully.",
            saved_count
        ))
    }

    /// Load index from disk
    #[allow(dead_code)]
    pub async fn load_index(&self) -> Result<String> {
        if !self.options.persist_enabled {
            return Ok(
                "Persistence is not enabled. Start with --persist flag to enable.".to_string(),
            );
        }

        let store = match &self.index_store {
            Some(s) => s,
            None => return Err(anyhow!("Index store not initialized")),
        };

        let mut loaded_count = 0;
        for repo_path in &self.repo_paths {
            if let Ok(persisted) = store.load_or_create(repo_path) {
                if !persisted.files.is_empty() {
                    let repo_name = repo_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();

                    // Load symbols from persisted index
                    let symbols: Vec<Symbol> = persisted
                        .files
                        .values()
                        .flat_map(|f| f.symbols.clone())
                        .collect();

                    self.symbols.insert(repo_name.clone(), symbols.clone());
                    loaded_count += 1;
                    info!(
                        "Loaded {} symbols from persisted index for {}",
                        symbols.len(),
                        repo_name
                    );
                }
            }
        }

        Ok(format!(
            "Loaded {} repository index(es) from disk.",
            loaded_count
        ))
    }

    /// Get the current watch mode status
    #[allow(dead_code)]
    pub fn get_watch_status(&self) -> bool {
        self.options.watch_enabled
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
                for repo_path in &self.repo_paths {
                    if repo_path.exists() {
                        if let Err(e) = watcher.watch(repo_path) {
                            warn!("Failed to watch {:?}: {}", repo_path, e);
                        }
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
    #[cfg(feature = "native")]
    pub fn create_async_file_watcher(
        &self,
    ) -> Option<(
        crate::persist::AsyncFileWatcher,
        tokio::sync::mpsc::Receiver<Vec<crate::persist::FileChange>>,
    )> {
        if !self.options.watch_enabled {
            return None;
        }

        match crate::persist::AsyncFileWatcher::new() {
            Ok((mut watcher, rx)) => {
                for repo_path in &self.repo_paths {
                    if repo_path.exists() {
                        if let Err(e) = watcher.watch(repo_path) {
                            warn!("Failed to watch {:?}: {}", repo_path, e);
                        }
                    }
                }
                Some((watcher, rx))
            }
            Err(e) => {
                warn!("Failed to create async file watcher: {}", e);
                None
            }
        }
    }

    /// Process file changes detected by the watcher.
    /// Returns the number of files re-indexed.
    pub async fn process_file_changes(
        &self,
        changes: &[crate::persist::FileChange],
    ) -> Result<usize> {
        use crate::persist::ChangeType;

        let mut count = 0;

        for change in changes {
            // Find which repo this file belongs to
            let repo_path = self.repo_paths.iter().find(|p| change.path.starts_with(p));

            let repo_path = match repo_path {
                Some(p) => p,
                None => continue,
            };

            let repo_name = repo_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

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

                            // Update symbols for this file
                            if let Some(mut symbols) = self.symbols.get_mut(&repo_name) {
                                // Remove old symbols from this file
                                symbols.retain(|s| s.file_path != rel_path);

                                // Add new symbols
                                for mut symbol in parsed.symbols {
                                    symbol.file_path = rel_path.clone();
                                    symbols.push(symbol);
                                }
                            }

                            // Update file cache
                            self.file_cache
                                .insert(change.path.clone(), Arc::new(content.clone()));

                            // Update search index
                            self.search_index.index_file(&rel_path, &content);

                            info!("Re-indexed file: {}", rel_path);
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

                    // Remove symbols for this file
                    if let Some(mut symbols) = self.symbols.get_mut(&repo_name) {
                        symbols.retain(|s| s.file_path != rel_path);
                    }

                    // Remove from file cache
                    self.file_cache.remove(&change.path);

                    info!("Removed file from index: {}", rel_path);
                    count += 1;
                }
            }
        }

        // Save index if persistence is enabled
        if self.options.persist_enabled && count > 0 {
            let _ = self.save_index().await;
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
    ) -> Result<String> {
        let repo_path = self.get_repo_path(repo)?;
        // Validate path to prevent traversal attacks
        validate_path(&repo_path, path)?;

        let git_repo = self
            .git_repos
            .get(repo)
            .ok_or_else(|| anyhow!("Git not available for {}. Enable with --git flag.", repo))?;

        let blame = match (start_line, end_line) {
            (Some(start), Some(end)) => git_repo.blame_range(path, start, end)?,
            _ => git_repo.blame(path)?,
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
        let repo_path = self.get_repo_path(repo)?;
        // Validate path to prevent traversal attacks
        validate_path(&repo_path, path)?;

        let git_repo = self
            .git_repos
            .get(repo)
            .ok_or_else(|| anyhow!("Git not available for {}. Enable with --git flag.", repo))?;

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
        let repo_path = self.get_repo_path(repo)?;
        // Validate path to prevent traversal attacks
        validate_path(&repo_path, path)?;

        let git_repo = self
            .git_repos
            .get(repo)
            .ok_or_else(|| anyhow!("Git not available for {}. Enable with --git flag.", repo))?;

        let history = git_repo.symbol_history(path, symbol, max_commits)?;
        Ok(git_repo.history_markdown(&history))
    }

    /// Get the diff for a specific commit
    pub async fn get_commit_diff(
        &self,
        repo: &str,
        commit: &str,
        path: Option<&str>,
    ) -> Result<String> {
        let repo_path = self.get_repo_path(repo)?;
        // Validate path to prevent traversal attacks
        if let Some(p) = path {
            validate_path(&repo_path, p)?;
        }

        let git_repo = self
            .git_repos
            .get(repo)
            .ok_or_else(|| anyhow!("Git not available for {}. Enable with --git flag.", repo))?;

        let diff = git_repo.commit_diff(commit, path)?;

        let mut output = String::new();
        output.push_str(&format!("# Commit Diff: `{}`\n\n", commit));
        if let Some(p) = path {
            output.push_str(&format!("**File**: `{}`\n\n", p));
        }
        output.push_str("```diff\n");
        output.push_str(&diff);
        output.push_str("\n```\n");

        Ok(output)
    }

    /// Get current branch and repository status
    pub async fn get_branch_info(&self, repo: &str) -> Result<String> {
        let git_repo = self
            .git_repos
            .get(repo)
            .ok_or_else(|| anyhow!("Git not available for {}. Enable with --git flag.", repo))?;

        let branch = git_repo.current_branch()?;
        let modified = git_repo.modified_files()?;

        let mut output = String::new();
        output.push_str(&format!("# Git Status: {}\n\n", repo));
        output.push_str(&format!("**Current Branch**: `{}`\n", branch));
        output.push_str(&format!("**Modified Files**: {}\n\n", modified.len()));

        if !modified.is_empty() {
            output.push_str("## Working Tree Changes\n\n");
            for file in &modified {
                output.push_str(&format!("- `{}`\n", file));
            }
        } else {
            output.push_str("*No changes in working tree*\n");
        }

        Ok(output)
    }

    /// Get list of modified files in working tree
    pub async fn get_modified_files(&self, repo: &str) -> Result<String> {
        let git_repo = self
            .git_repos
            .get(repo)
            .ok_or_else(|| anyhow!("Git not available for {}. Enable with --git flag.", repo))?;

        let modified = git_repo.modified_files()?;

        let mut output = String::new();
        output.push_str(&format!("# Modified Files in {}\n\n", repo));
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
        let git_repo = self
            .git_repos
            .get(repo)
            .ok_or_else(|| anyhow!("Git not available for {}. Enable with --git flag.", repo))?;

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

    /// Get code hotspots (complex + frequently changed)
    pub async fn get_hotspots(
        &self,
        repo: &str,
        days: u32,
        _min_complexity: Option<usize>,
    ) -> Result<String> {
        let git_repo = self
            .git_repos
            .get(repo)
            .ok_or_else(|| anyhow!("Git not available for {}. Enable with --git flag.", repo))?;

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
    pub async fn get_contributors(&self, repo: &str, path: Option<&str>) -> Result<String> {
        let repo_path = self.get_repo_path(repo)?;
        // Validate path to prevent traversal attacks
        if let Some(p) = path {
            validate_path(&repo_path, p)?;
        }

        let git_repo = self
            .git_repos
            .get(repo)
            .ok_or_else(|| anyhow!("Git not available for {}. Enable with --git flag.", repo))?;

        let mut output = String::new();

        match path {
            Some(p) => {
                output.push_str(&format!("# Contributors to `{}`\n\n", p));
                let contributors = git_repo.file_contributors(p)?;

                if contributors.is_empty() {
                    output.push_str("*No contributors found for this file.*\n");
                } else {
                    for (name, count) in contributors {
                        output.push_str(&format!("- {} ({} commits)\n", name, count));
                    }
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
                    for (name, count) in contributors {
                        output.push_str(&format!("- {} ({} commits)\n", name, count));
                    }
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

    /// Get status of the search index
    pub async fn get_index_status(&self, repo: Option<&str>) -> Result<String> {
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
            "- **Watch mode**: {}\n",
            if self.options.watch_enabled {
                "enabled"
            } else {
                "disabled"
            }
        ));
        output.push_str(&format!(
            "- **Neural embeddings**: {}\n\n",
            if self.neural_engine.is_some() {
                format!(
                    "enabled (backend={}, model={:?})",
                    self.options.neural_config.backend, self.options.neural_config.model_name
                )
            } else {
                "disabled".to_string()
            }
        ));

        output.push_str("## Document Types\n\n");
        for (doc_type, count) in &stats.doc_types {
            output.push_str(&format!("- {:?}: {}\n", doc_type, count));
        }

        output.push_str("\n## Repositories\n\n");
        for entry in self.repos.iter() {
            let meta = entry.value();
            if repo.is_none() || repo == Some(entry.key()) {
                output.push_str(&format!("### {}\n", meta.name));
                output.push_str(&format!("- Files: {}\n", meta.file_count));
                output.push_str(&format!(
                    "- Symbols: {}\n",
                    self.symbols.get(&meta.name).map(|s| s.len()).unwrap_or(0)
                ));
                output.push_str(&format!(
                    "- Git: {}\n\n",
                    if self.git_repos.contains_key(&meta.name) {
                        "enabled"
                    } else {
                        "disabled"
                    }
                ));
            }
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
    ) -> Result<String> {
        // Validate repo if specified
        let repo_name = if let Some(r) = repo {
            if !r.is_empty() {
                // Verify the repo exists
                let _ = self.get_repo_path(r)?;
                Some(r)
            } else {
                None
            }
        } else {
            None
        };

        let results: Vec<_> = self
            .search_index
            .search(query, max_results)
            .into_iter()
            .collect();

        let mut output = String::new();
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
            output.push_str(&format!(
                "Lines {}-{}\n\n",
                result.document.start_line, result.document.end_line
            ));
            output.push_str("```\n");
            output.push_str(&result.snippet);
            output.push_str("\n```\n\n");
        }

        if results.is_empty() {
            output.push_str("*No results found.*\n");
        }

        Ok(output)
    }

    // === Similarity Search Methods ===

    /// Find code similar to a given code snippet using embeddings
    pub async fn find_similar_code(
        &self,
        repo: Option<&str>,
        query: &str,
        max_results: usize,
    ) -> Result<String> {
        // Validate repo if specified
        let repo_name = if let Some(r) = repo {
            if !r.is_empty() {
                // Verify the repo exists
                let _ = self.get_repo_path(r)?;
                Some(r)
            } else {
                None
            }
        } else {
            None
        };

        let results: Vec<_> = self
            .embedding_engine
            .find_similar_code(query, max_results)
            .into_iter()
            .collect();

        let mut output = String::new();
        output.push_str(&format!("# Similar Code Search: `{}`\n\n", query));
        if let Some(r) = repo_name {
            output.push_str(&format!("Repository: {}\n", r));
        }
        output.push_str(&format!(
            "Found {} similar code snippets\n\n",
            results.len()
        ));

        for (i, result) in results.iter().enumerate() {
            output.push_str(&format!(
                "## {}. {} (similarity: {:.3})\n",
                i + 1,
                result.document.file_path,
                result.similarity
            ));
            output.push_str(&format!(
                "Lines {}-{}\n\n",
                result.document.start_line, result.document.end_line
            ));
            output.push_str("```\n");
            output.push_str(&result.document.content);
            output.push_str("\n```\n\n");
        }

        if results.is_empty() {
            output.push_str("*No similar code found.*\n");
        }

        Ok(output)
    }

    /// Find code similar to a specific symbol
    pub async fn find_similar_to_symbol(
        &self,
        repo: &str,
        symbol_name: &str,
        max_results: usize,
    ) -> Result<String> {
        // First find the symbol to get its ID
        let symbols = self
            .symbols
            .get(repo)
            .ok_or_else(|| self.repo_not_found_error(repo))?;

        let symbol = symbols
            .iter()
            .find(|s| s.name == symbol_name || s.qualified_name.as_deref() == Some(symbol_name))
            .ok_or_else(|| {
                anyhow!(
                    "Symbol '{}' not found in repository '{}'",
                    symbol_name,
                    repo
                )
            })?;

        // Create symbol ID
        let symbol_id = format!("{}::{}", symbol.file_path, symbol.name);

        // Find similar code to this symbol
        let results = self
            .embedding_engine
            .find_similar_to_doc(&symbol_id, max_results);

        let mut output = String::new();
        output.push_str(&format!("# Code Similar to Symbol: `{}`\n\n", symbol_name));
        output.push_str(&format!(
            "Reference: `{}:{}` ({:?})\n\n",
            symbol.file_path, symbol.start_line, symbol.kind
        ));
        output.push_str(&format!("Found {} similar snippets\n\n", results.len()));

        for (i, result) in results.iter().enumerate() {
            // Skip the symbol itself
            if result.document.id == symbol_id {
                continue;
            }

            output.push_str(&format!(
                "## {}. {} (similarity: {:.3})\n",
                i + 1,
                result.document.file_path,
                result.similarity
            ));
            output.push_str(&format!(
                "Lines {}-{}\n\n",
                result.document.start_line, result.document.end_line
            ));
            output.push_str("```\n");
            output.push_str(&result.document.content);
            output.push_str("\n```\n\n");
        }

        if results.len() <= 1 {
            output.push_str("*No similar code found.*\n");
        }

        Ok(output)
    }

    // === Call Graph Methods ===

    /// Get the call graph for a function
    pub async fn get_call_graph(
        &self,
        repo: &str,
        function: &str,
        _depth: usize,
    ) -> Result<String> {
        let call_graph = self.call_graphs.get(repo).ok_or_else(|| {
            anyhow!(
                "Call graph not available for {}. Enable with --call-graph flag.",
                repo
            )
        })?;

        // Empty string means show summary (None), otherwise look up specific function
        let func_option = if function.is_empty() {
            None
        } else {
            Some(function)
        };
        Ok(call_graph.to_markdown(func_option))
    }

    /// Get callers of a function
    pub async fn get_callers(
        &self,
        repo: &str,
        function: &str,
        transitive: bool,
        max_depth: usize,
    ) -> Result<String> {
        let call_graph = self.call_graphs.get(repo).ok_or_else(|| {
            anyhow!(
                "Call graph not available for {}. Enable with --call-graph flag.",
                repo
            )
        })?;

        let mut output = String::new();
        output.push_str(&format!("# Callers of `{}`\n\n", function));

        if transitive {
            let callers = call_graph.get_transitive_callers(function, max_depth);
            output.push_str(&format!(
                "Found {} transitive callers (max depth: {})\n\n",
                callers.len(),
                max_depth
            ));

            for (name, depth) in &callers {
                output.push_str(&format!("- `{}` (depth: {})\n", name, depth));
            }
        } else {
            let callers = call_graph.get_callers(function);
            output.push_str(&format!("Found {} direct callers\n\n", callers.len()));

            for caller in &callers {
                output.push_str(&format!(
                    "- `{}` at `{}:{}` ({:?})\n",
                    caller.target, caller.file_path, caller.line, caller.call_type
                ));
            }
        }

        if output.ends_with("\n\n") {
            output.push_str("*No callers found.*\n");
        }

        Ok(output)
    }

    /// Get callees of a function
    pub async fn get_callees(
        &self,
        repo: &str,
        function: &str,
        transitive: bool,
        max_depth: usize,
    ) -> Result<String> {
        let call_graph = self.call_graphs.get(repo).ok_or_else(|| {
            anyhow!(
                "Call graph not available for {}. Enable with --call-graph flag.",
                repo
            )
        })?;

        let mut output = String::new();
        output.push_str(&format!("# Callees of `{}`\n\n", function));

        if transitive {
            let callees = call_graph.get_transitive_callees(function, max_depth);
            output.push_str(&format!(
                "Found {} transitive callees (max depth: {})\n\n",
                callees.len(),
                max_depth
            ));

            for (name, depth) in &callees {
                output.push_str(&format!("- `{}` (depth: {})\n", name, depth));
            }
        } else {
            let callees = call_graph.get_callees(function);
            output.push_str(&format!("Found {} direct callees\n\n", callees.len()));

            for callee in &callees {
                output.push_str(&format!(
                    "- `{}` at `{}:{}` ({:?})\n",
                    callee.target, callee.file_path, callee.line, callee.call_type
                ));
            }
        }

        if output.ends_with("\n\n") {
            output.push_str("*No callees found.*\n");
        }

        Ok(output)
    }

    /// Find the call path between two functions
    pub async fn find_call_path(&self, repo: &str, from: &str, to: &str) -> Result<String> {
        let call_graph = self.call_graphs.get(repo).ok_or_else(|| {
            anyhow!(
                "Call graph not available for {}. Enable with --call-graph flag.",
                repo
            )
        })?;

        let mut output = String::new();
        output.push_str(&format!("# Call Path: `{}` â†’ `{}`\n\n", from, to));

        match call_graph.find_call_path(from, to) {
            Some(path) => {
                output.push_str(&format!("Found path with {} steps:\n\n", path.len() - 1));
                for (i, func) in path.iter().enumerate() {
                    if i > 0 {
                        output.push_str("  â†“\n");
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
        let call_graph = self.call_graphs.get(repo).ok_or_else(|| {
            anyhow!(
                "Call graph not available for {}. Enable with --call-graph flag.",
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
                    output.push_str("âš ï¸ **High cyclomatic complexity** - Consider refactoring into smaller functions.\n");
                } else if metrics.cyclomatic > 5 {
                    output.push_str("âš¡ **Moderate complexity** - Function is manageable but could be simplified.\n");
                } else {
                    output.push_str("âœ… **Low complexity** - Function is well-structured.\n");
                }

                if metrics.max_depth > 4 {
                    output.push_str("âš ï¸ **Deep nesting** - Consider early returns or extracting nested logic.\n");
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
    ) -> Result<String> {
        let call_graph = self.call_graphs.get(repo).ok_or_else(|| {
            anyhow!(
                "Call graph not available for {}. Enable with --call-graph flag.",
                repo
            )
        })?;

        let hotspots = call_graph.get_hotspots(min_connections);

        let mut output = String::new();
        output.push_str(&format!(
            "# Function Hotspots in {} (min {} connections)\n\n",
            repo, min_connections
        ));

        if hotspots.is_empty() {
            output.push_str("*No hotspots found matching the criteria.*\n");
        } else {
            output.push_str(&format!(
                "Found {} highly connected functions:\n\n",
                hotspots.len()
            ));
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
        let repo_path = self.get_repo_path(repo)?;
        let file_path = validate_path(&repo_path, path)?;

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

    /// Get performance metrics report
    pub async fn get_metrics(&self, format: &str) -> Result<String> {
        if format == "json" {
            Ok(self.metrics.report_json().to_string())
        } else {
            Ok(self.metrics.report())
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
        let repo_path = self.get_repo_path(repo)?;
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
            .get(repo)
            .ok_or_else(|| self.repo_not_found_error(repo))?;

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
        let repo_path = self.get_repo_path(repo)?;
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
        let repo_path = self.get_repo_path(repo)?;
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
            if let Some(symbols) = self.symbols.get(repo) {
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

    // === Remote Repository Methods ===

    /// Initialize the remote repository manager
    pub fn init_remote_manager(&mut self) -> Result<()> {
        if self.remote_manager.is_none() {
            let manager = RemoteRepoManager::new()?;
            self.remote_manager = Some(Arc::new(tokio::sync::Mutex::new(manager)));
            info!("Remote repository manager initialized");
        }
        Ok(())
    }

    /// Add a remote GitHub repository for indexing
    pub async fn add_remote_repo(
        &self,
        url: &str,
        sparse_paths: Option<&[String]>,
    ) -> Result<String> {
        // Initialize manager if needed
        let manager = match &self.remote_manager {
            Some(m) => m.clone(),
            None => {
                return Err(anyhow!(
                    "Remote repository support not initialized. Use init_remote_manager() first."
                ));
            }
        };

        let remote = crate::remote::RemoteRepo::from_url(url)?;

        let mut output = String::new();
        output.push_str(&format!(
            "# Adding Remote Repository: {}\n\n",
            remote.identifier()
        ));
        output.push_str(&format!("**URL**: {}\n", remote.url));
        if let Some(branch) = &remote.branch {
            output.push_str(&format!("**Branch**: {}\n", branch));
        }
        output.push('\n');

        let local_path = {
            let mut mgr = manager.lock().await;
            if let Some(paths) = sparse_paths {
                let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
                output.push_str(&format!(
                    "Performing sparse checkout of {} paths...\n\n",
                    paths.len()
                ));
                mgr.sparse_checkout(&remote, &path_refs).await?
            } else {
                output.push_str("Cloning repository...\n\n");
                mgr.clone_repo(&remote).await?
            }
        };

        output.push_str(&format!("**Local Path**: `{}`\n\n", local_path.display()));
        output.push_str("Repository cloned successfully. You can now index it with `reindex`.\n");

        // Note: Full indexing would require adding this path to repo_paths and calling index_repo
        // For now we just clone and return the path

        Ok(output)
    }

    /// List files in a remote GitHub repository via API
    pub async fn list_remote_files(&self, url: &str, path: Option<&str>) -> Result<String> {
        let manager = match &self.remote_manager {
            Some(m) => m.clone(),
            None => {
                // Try to create a temporary manager for API-only operation
                let mgr = RemoteRepoManager::new()?;
                let remote = crate::remote::RemoteRepo::from_url(url)?;
                let files = mgr.list_files(&remote, path).await?;

                let mut output = String::new();
                output.push_str(&format!("# Files in {}\n\n", remote.identifier()));
                if let Some(p) = path {
                    output.push_str(&format!("**Path**: `{}`\n\n", p));
                }
                output.push_str(&format!("Found {} files:\n\n", files.len()));
                for file in files {
                    output.push_str(&format!("- `{}`\n", file));
                }
                return Ok(output);
            }
        };

        let remote = crate::remote::RemoteRepo::from_url(url)?;

        let files = {
            let mgr = manager.lock().await;
            mgr.list_files(&remote, path).await?
        };

        let mut output = String::new();
        output.push_str(&format!("# Files in {}\n\n", remote.identifier()));
        if let Some(p) = path {
            output.push_str(&format!("**Path**: `{}`\n\n", p));
        }
        output.push_str(&format!("Found {} files:\n\n", files.len()));
        for file in &files {
            output.push_str(&format!("- `{}`\n", file));
        }

        if files.is_empty() {
            output.push_str("*No files found (directory may be empty or not exist)*\n");
        }

        Ok(output)
    }

    /// Fetch a specific file from a remote GitHub repository
    pub async fn get_remote_file(&self, url: &str, path: &str) -> Result<String> {
        let manager = match &self.remote_manager {
            Some(m) => m.clone(),
            None => {
                // Try to create a temporary manager for API-only operation
                let mgr = RemoteRepoManager::new()?;
                let remote = crate::remote::RemoteRepo::from_url(url)?;
                let content = mgr.get_file(&remote, path).await?;

                let mut output = String::new();
                output.push_str(&format!("# {} from {}\n\n", path, remote.identifier()));
                output.push_str("```");
                output.push_str(get_language_id(path));
                output.push('\n');
                output.push_str(&content);
                output.push_str("\n```\n");
                return Ok(output);
            }
        };

        let remote = crate::remote::RemoteRepo::from_url(url)?;

        let content = {
            let mgr = manager.lock().await;
            mgr.get_file(&remote, path).await?
        };

        let mut output = String::new();
        output.push_str(&format!("# {} from {}\n\n", path, remote.identifier()));

        let lines: Vec<&str> = content.lines().collect();
        output.push_str(&format!("**Lines**: {}\n\n", lines.len()));

        output.push_str("```");
        output.push_str(get_language_id(path));
        output.push('\n');
        output.push_str(&content);
        output.push_str("\n```\n");

        Ok(output)
    }

    // ==================== Control Flow Graph (CFG) Tools ====================

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

    /// Find dead (unreachable) code blocks in a file or function
    pub async fn find_dead_code(
        &self,
        repo: &str,
        path: &str,
        function: Option<&str>,
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

        let mut output = String::new();
        output.push_str(&format!("# Dead Code Analysis: `{}`\n\n", path));

        let mut total_unreachable = 0;

        for cfg in &cfgs {
            // Filter by function if specified
            if let Some(func_name) = function {
                if cfg.function_name != func_name {
                    continue;
                }
            }

            if !cfg.unreachable_blocks.is_empty() {
                output.push_str(&format!("## Function: `{}`\n\n", cfg.function_name));
                output.push_str("### Unreachable Code Blocks\n\n");

                for &block_id in &cfg.unreachable_blocks {
                    if let Some(block) = cfg.blocks.get(&block_id) {
                        output.push_str(&format!(
                            "- **Block {}** (`{}`): lines {}-{}\n",
                            block_id, block.label, block.start_line, block.end_line
                        ));
                        total_unreachable += 1;
                    }
                }
                output.push('\n');
            }
        }

        if total_unreachable == 0 {
            output.push_str("✅ No unreachable code detected.\n");
        } else {
            output.push_str(&format!(
                "\n**Total**: {} unreachable block(s) found.\n",
                total_unreachable
            ));
        }

        Ok(output)
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

        let mut analyzer = dfg::DfgAnalyzer::new(cfg, &content);
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

    /// Find variables that may be used before initialization
    pub async fn find_uninitialized(
        &self,
        repo: &str,
        path: &str,
        function: Option<&str>,
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
        let analyses = dfg::analyze_file(tree, &content, path)?;

        let mut output = String::new();
        output.push_str(&format!(
            "# Uninitialized Variable Analysis: `{}`\n\n",
            path
        ));

        let mut total_issues = 0;

        for analysis in &analyses {
            if let Some(func_name) = function {
                if analysis.function_name != func_name {
                    continue;
                }
            }

            if !analysis.uninitialized_uses.is_empty() {
                output.push_str(&format!("## Function: `{}`\n\n", analysis.function_name));
                output.push_str("⚠️ **Potentially uninitialized variables:**\n\n");

                for use_ in &analysis.uninitialized_uses {
                    output.push_str(&format!(
                        "- `{}` at line {} ({:?})\n",
                        use_.variable, use_.line, use_.kind
                    ));
                    total_issues += 1;
                }
                output.push('\n');
            }
        }

        if total_issues == 0 {
            output.push_str("✅ No potentially uninitialized variables detected.\n");
        } else {
            output.push_str(&format!(
                "\n**Total**: {} potential issue(s) found.\n",
                total_issues
            ));
        }

        Ok(output)
    }

    /// Find dead stores (assignments that are never read)
    pub async fn find_dead_stores(
        &self,
        repo: &str,
        path: &str,
        function: Option<&str>,
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
        let analyses = dfg::analyze_file(tree, &content, path)?;

        let mut output = String::new();
        output.push_str(&format!("# Dead Store Analysis: `{}`\n\n", path));

        let mut total_dead = 0;

        for analysis in &analyses {
            if let Some(func_name) = function {
                if analysis.function_name != func_name {
                    continue;
                }
            }

            if !analysis.dead_stores.is_empty() {
                output.push_str(&format!("## Function: `{}`\n\n", analysis.function_name));
                output.push_str("⚠️ **Dead stores (assignments never read):**\n\n");

                for def in &analysis.dead_stores {
                    output.push_str(&format!(
                        "- `{}` at line {} (block {})\n",
                        def.variable, def.line, def.block
                    ));
                    total_dead += 1;
                }
                output.push('\n');
            }
        }

        if total_dead == 0 {
            output.push_str("✅ No dead stores detected.\n");
        } else {
            output.push_str(&format!(
                "\n**Total**: {} dead store(s) found.\n",
                total_dead
            ));
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
    ) -> Result<String> {
        use crate::chunking::AstChunker;
        use crate::embeddings::EmbeddingEngine;
        use crate::hybrid_search::create_hybrid_engine;
        use crate::search::ConcurrentSearchIndex;
        use std::sync::Arc;

        // Create search engines
        let bm25_index = Arc::new(ConcurrentSearchIndex::new());
        let tfidf_engine = Arc::new(EmbeddingEngine::new(1000));
        let hybrid_engine = create_hybrid_engine(bm25_index.clone(), tfidf_engine.clone());
        let chunker = AstChunker::new();

        // Index all files from relevant repos
        for repo_entry in self.repos.iter() {
            let repo_name = repo_entry.key();
            let repo_meta = repo_entry.value();

            // Filter by repo if specified
            if let Some(target_repo) = repo {
                if repo_name != target_repo && !repo_meta.path.ends_with(target_repo) {
                    continue;
                }
            }

            let repo_path = &repo_meta.path;

            for file_entry in self.file_cache.iter() {
                let file_path = file_entry.key();
                if !file_path.starts_with(repo_path) {
                    continue;
                }

                let content = file_entry.value();
                let file_path_str = file_path.to_string_lossy().to_string();

                // Chunk the file
                let chunks = chunker.chunk_file(content, &file_path_str);

                // Index each chunk
                for chunk in chunks {
                    hybrid_engine.index_chunk(&chunk);
                }
            }
        }

        // Perform search based on mode
        let results = match mode {
            "bm25" => hybrid_engine.search_bm25(query, max_results),
            "tfidf" => hybrid_engine.search_tfidf(query, max_results),
            _ => hybrid_engine.search(query, max_results),
        };

        // Format results
        let mut output = String::new();
        output.push_str(&format!("# Hybrid Search Results for: `{}`\n\n", query));
        output.push_str(&format!("**Mode**: {}\n", mode));
        output.push_str(&format!("**Results**: {}\n\n", results.len()));

        for (i, result) in results.iter().enumerate() {
            output.push_str(&format!("## {}. {}\n", i + 1, result.file_path));
            output.push_str(&format!("- **Score**: {:.4}\n", result.score));
            output.push_str(&format!(
                "- **Lines**: {}-{}\n",
                result.start_line, result.end_line
            ));

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
            let snippet_lines: Vec<&str> = result.content.lines().take(10).collect();
            output.push_str(&snippet_lines.join("\n"));
            if result.content.lines().count() > 10 {
                output.push_str("\n... (truncated)");
            }
            output.push_str("\n```\n\n");
        }

        if results.is_empty() {
            output.push_str("No results found.\n");
        }

        Ok(output)
    }

    /// Search over AST-aware code chunks
    pub async fn search_chunks(
        &self,
        query: &str,
        repo: Option<&str>,
        chunk_type: Option<&str>,
        max_results: usize,
    ) -> Result<String> {
        use crate::chunking::{AstChunker, ChunkType};
        use crate::search::tokenize_code;

        let chunker = AstChunker::new();
        let query_tokens: std::collections::HashSet<_> = tokenize_code(query).into_iter().collect();
        let mut all_chunks = Vec::new();

        let target_type = chunk_type.and_then(|t| match t {
            "function" => Some(ChunkType::Function),
            "method" => Some(ChunkType::Method),
            "class" => Some(ChunkType::Class),
            "trait" => Some(ChunkType::Trait),
            "module" => Some(ChunkType::Module),
            _ => None,
        });

        // Collect chunks from relevant repos
        for repo_entry in self.repos.iter() {
            let repo_name = repo_entry.key();
            let repo_meta = repo_entry.value();

            // Filter by repo if specified
            if let Some(target_repo) = repo {
                if repo_name != target_repo && !repo_meta.path.ends_with(target_repo) {
                    continue;
                }
            }

            let repo_path = &repo_meta.path;

            for file_entry in self.file_cache.iter() {
                let file_path = file_entry.key();
                if !file_path.starts_with(repo_path) {
                    continue;
                }

                let content = file_entry.value();
                let file_path_str = file_path.to_string_lossy().to_string();

                let chunks = chunker.chunk_file(content, &file_path_str);

                for chunk in chunks {
                    // Filter by type if specified
                    if let Some(ref target) = target_type {
                        if chunk.chunk_type != *target {
                            continue;
                        }
                    }

                    // Score the chunk
                    let chunk_tokens: std::collections::HashSet<_> =
                        tokenize_code(&chunk.content).into_iter().collect();
                    let common = query_tokens.intersection(&chunk_tokens).count();
                    let score = if query_tokens.is_empty() {
                        0.0
                    } else {
                        common as f64 / query_tokens.len() as f64
                    };

                    if score > 0.0 {
                        all_chunks.push((chunk, score));
                    }
                }
            }
        }

        // Sort by score
        all_chunks.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        all_chunks.truncate(max_results);

        // Format results
        let mut output = String::new();
        output.push_str(&format!("# Chunk Search Results for: `{}`\n\n", query));
        if let Some(ct) = chunk_type {
            output.push_str(&format!("**Filter**: {} chunks only\n", ct));
        }
        output.push_str(&format!("**Results**: {}\n\n", all_chunks.len()));

        for (i, (chunk, score)) in all_chunks.iter().enumerate() {
            output.push_str(&format!("## {}. {}\n", i + 1, chunk.id));
            output.push_str(&format!("- **File**: {}\n", chunk.file_path));
            output.push_str(&format!(
                "- **Lines**: {}-{}\n",
                chunk.start_line, chunk.end_line
            ));
            output.push_str(&format!("- **Type**: {}\n", chunk.chunk_type));
            output.push_str(&format!("- **Score**: {:.2}\n", score));

            if let Some(ref ctx) = chunk.symbol_context {
                output.push_str(&format!("- **Symbol**: `{}` ({:?})\n", ctx.name, ctx.kind));
                if let Some(ref sig) = ctx.signature {
                    output.push_str(&format!(
                        "- **Signature**: `{}`\n",
                        sig.chars().take(100).collect::<String>()
                    ));
                }
            }

            if let Some(ref doc) = chunk.doc_comment {
                let doc_preview: String = doc.lines().take(2).collect::<Vec<_>>().join(" ");
                output.push_str(&format!(
                    "- **Doc**: {}\n",
                    doc_preview.chars().take(80).collect::<String>()
                ));
            }

            output.push_str("\n```\n");
            let snippet_lines: Vec<&str> = chunk.content.lines().take(15).collect();
            output.push_str(&snippet_lines.join("\n"));
            if chunk.content.lines().count() > 15 {
                output.push_str("\n... (truncated)");
            }
            output.push_str("\n```\n\n");
        }

        if all_chunks.is_empty() {
            output.push_str("No matching chunks found.\n");
        }

        Ok(output)
    }

    /// Get AST-aware chunks for a file
    pub async fn get_chunks(
        &self,
        repo: &str,
        path: &str,
        include_imports: bool,
    ) -> Result<String> {
        use crate::chunking::{AstChunker, ChunkerConfig, ChunkingStats};

        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;

        let config = ChunkerConfig {
            include_context: include_imports,
            ..Default::default()
        };
        let chunker = AstChunker::with_config(config);
        let chunks = chunker.chunk_file(&content, path);
        let stats = ChunkingStats::from_chunks(&chunks);

        let mut output = String::new();
        output.push_str(&format!("# Code Chunks: `{}`\n\n", path));
        output.push_str(&format!("**Total chunks**: {}\n", stats.total_chunks));
        output.push_str(&format!(
            "**Avg lines/chunk**: {:.1}\n",
            stats.avg_chunk_lines
        ));
        output.push_str(&format!("**Max chunk lines**: {}\n", stats.max_chunk_lines));
        output.push_str(&format!(
            "**Min chunk lines**: {}\n\n",
            stats.min_chunk_lines
        ));

        output.push_str("## Chunk Types:\n");
        for (chunk_type, count) in &stats.by_type {
            output.push_str(&format!("- {}: {}\n", chunk_type, count));
        }
        output.push('\n');

        for (i, chunk) in chunks.iter().enumerate() {
            output.push_str(&format!(
                "---\n\n## Chunk {} ({})\n",
                i + 1,
                chunk.chunk_type
            ));
            output.push_str(&format!(
                "**Lines**: {}-{}\n",
                chunk.start_line, chunk.end_line
            ));

            if let Some(ref ctx) = chunk.symbol_context {
                output.push_str(&format!("**Symbol**: `{}` ({:?})\n", ctx.name, ctx.kind));
            }

            if !chunk.imports.is_empty() && include_imports {
                output.push_str(&format!(
                    "**Imports**: {} statements\n",
                    chunk.imports.len()
                ));
            }

            output.push_str("\n```\n");
            output.push_str(&chunk.content);
            output.push_str("\n```\n\n");
        }

        Ok(output)
    }

    /// Get statistics about code chunks in a repository
    pub async fn get_chunk_stats(&self, repo: &str) -> Result<String> {
        use crate::chunking::{AstChunker, ChunkingStats};

        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let repo_path = repo_meta.path.clone();
        drop(repo_meta); // Release the lock

        let chunker = AstChunker::new();
        let mut all_chunks = Vec::new();
        let mut file_count = 0;

        for file_entry in self.file_cache.iter() {
            let file_path = file_entry.key();
            if !file_path.starts_with(&repo_path) {
                continue;
            }

            file_count += 1;
            let content = file_entry.value();
            let file_path_str = file_path.to_string_lossy().to_string();

            let chunks = chunker.chunk_file(content, &file_path_str);
            all_chunks.extend(chunks);
        }

        let stats = ChunkingStats::from_chunks(&all_chunks);

        let mut output = String::new();
        output.push_str(&format!("# Chunk Statistics: `{}`\n\n", repo));
        output.push_str(&format!("**Files processed**: {}\n", file_count));
        output.push_str(&format!("**Total chunks**: {}\n", stats.total_chunks));
        output.push_str(&format!(
            "**Avg lines/chunk**: {:.1}\n",
            stats.avg_chunk_lines
        ));
        output.push_str(&format!("**Max chunk lines**: {}\n", stats.max_chunk_lines));
        output.push_str(&format!(
            "**Min chunk lines**: {}\n\n",
            stats.min_chunk_lines
        ));

        output.push_str("## Chunks by Type:\n\n");
        output.push_str("| Type | Count | Percentage |\n");
        output.push_str("|------|-------|------------|\n");

        let mut types: Vec<_> = stats.by_type.into_iter().collect();
        types.sort_by(|a, b| b.1.cmp(&a.1));

        for (chunk_type, count) in types {
            let pct = if stats.total_chunks > 0 {
                count as f64 / stats.total_chunks as f64 * 100.0
            } else {
                0.0
            };
            output.push_str(&format!("| {} | {} | {:.1}% |\n", chunk_type, count, pct));
        }

        Ok(output)
    }

    /// Get statistics about the embedding index
    pub async fn get_embedding_stats(&self) -> Result<String> {
        let (tfidf_stats, doc_count) = self.embedding_engine.stats();
        let search_stats = self.search_index.stats();

        let mut output = String::new();
        output.push_str("# Embedding & Search Index Statistics\n\n");

        output.push_str("## TF-IDF Embeddings\n\n");
        output.push_str(&format!("- **Documents indexed**: {}\n", doc_count));
        output.push_str(&format!(
            "- **Total docs in IDF**: {}\n",
            tfidf_stats.total_docs
        ));
        output.push_str(&format!(
            "- **Vocabulary size**: {}\n",
            tfidf_stats.vocab_size
        ));
        output.push_str(&format!(
            "- **Embedding dimension**: {}\n",
            tfidf_stats.dimension
        ));

        output.push_str("\n## BM25 Search Index\n\n");
        output.push_str(&format!(
            "- **Documents indexed**: {}\n",
            search_stats.total_documents
        ));
        output.push_str(&format!(
            "- **Total terms**: {}\n",
            search_stats.total_terms
        ));
        output.push_str(&format!(
            "- **Avg doc length**: {:.1} tokens\n",
            search_stats.avg_doc_length
        ));

        output.push_str("\n## Document Types:\n\n");
        output.push_str("| Type | Count |\n");
        output.push_str("|------|-------|\n");
        for (doc_type, count) in &search_stats.doc_types {
            output.push_str(&format!("| {:?} | {} |\n", doc_type, count));
        }

        Ok(output)
    }

    // Phase 3: Taint Analysis & Security Tools

    /// Find injection vulnerabilities using taint analysis
    pub async fn find_injection_vulnerabilities(
        &self,
        repo_name: &str,
        path: Option<&str>,
        vuln_types: &[String],
    ) -> Result<String> {
        let repo_path = self.get_repo_path(repo_name)?;

        let mut all_results: Vec<crate::taint::TaintAnalysisResult> = Vec::new();
        let include_all = vuln_types.contains(&"all".to_string()) || vuln_types.is_empty();

        // Get files to analyze - supports both file and directory paths
        let files_to_analyze: Vec<std::path::PathBuf> = self
            .file_cache
            .iter()
            .filter(|entry| entry.key().starts_with(&repo_path))
            .filter(|entry| {
                if let Some(specific_path) = path {
                    // Support both file and directory paths by checking if path matches
                    let entry_path = entry.key().to_string_lossy();
                    entry_path.contains(specific_path)
                } else {
                    true
                }
            })
            .filter(|entry| {
                let path_str = entry.key().to_string_lossy();
                path_str.ends_with(".py")
                    || path_str.ends_with(".js")
                    || path_str.ends_with(".ts")
                    || path_str.ends_with(".tsx")
                    || path_str.ends_with(".go")
                    || path_str.ends_with(".rs")
                    || path_str.ends_with(".php")
                    || path_str.ends_with(".java")
                    || path_str.ends_with(".rb")
                    || path_str.ends_with(".c")
                    || path_str.ends_with(".cpp")
                    || path_str.ends_with(".cs")
                    || path_str.ends_with(".kt")
            })
            .map(|entry| entry.key().clone())
            .collect();

        for file_path in &files_to_analyze {
            if let Some(content_entry) = self.file_cache.get(file_path) {
                let content = content_entry.value();
                let file_str = file_path.to_string_lossy();
                let result = crate::taint::analyze_code(content, &file_str);
                all_results.push(result);
            }
        }

        // Filter and aggregate results
        let mut output = String::new();
        output.push_str(&format!(
            "# Injection Vulnerability Analysis: {}\n\n",
            repo_name
        ));

        // Collect all vulnerabilities first
        let mut all_vulns: Vec<crate::taint::TaintFlow> = Vec::new();

        for result in &all_results {
            for vuln in &result.vulnerabilities {
                if let Some(ref vuln_kind) = vuln.vulnerability {
                    let type_key = match vuln_kind {
                        crate::taint::VulnerabilityKind::SqlInjection => "sql",
                        crate::taint::VulnerabilityKind::Xss => "xss",
                        crate::taint::VulnerabilityKind::CommandInjection => "command",
                        crate::taint::VulnerabilityKind::PathTraversal => "path",
                        _ => "other",
                    };

                    if include_all || vuln_types.iter().any(|t| t == type_key) {
                        all_vulns.push(vuln.clone());
                    }
                }
            }
        }

        // Sort by severity (highest first) then by confidence
        all_vulns.sort_by(|a, b| {
            let sev_a = a.severity.unwrap_or(crate::taint::Severity::Low);
            let sev_b = b.severity.unwrap_or(crate::taint::Severity::Low);
            sev_b
                .cmp(&sev_a)
                .then_with(|| b.confidence.cmp(&a.confidence))
        });

        let total_vulns = all_vulns.len();

        // Apply pagination to prevent overwhelming responses
        const MAX_FINDINGS_PER_REQUEST: usize = 50;
        let findings_to_show = if total_vulns > MAX_FINDINGS_PER_REQUEST {
            info!(
                "Limiting output to top {} of {} findings (sorted by severity)",
                MAX_FINDINGS_PER_REQUEST, total_vulns
            );
            &all_vulns[..MAX_FINDINGS_PER_REQUEST]
        } else {
            &all_vulns[..]
        };

        // Aggregate by type
        let mut by_type: std::collections::HashMap<String, Vec<crate::taint::TaintFlow>> =
            std::collections::HashMap::new();

        for vuln in findings_to_show {
            if let Some(ref vuln_kind) = vuln.vulnerability {
                let type_name = vuln_kind.display_name().to_string();
                by_type.entry(type_name).or_default().push(vuln.clone());
            }
        }

        // Summary
        output.push_str("## Summary\n\n");
        output.push_str(&format!(
            "- **Files Analyzed**: {}\n",
            files_to_analyze.len()
        ));
        output.push_str(&format!("- **Vulnerabilities Found**: {}\n", total_vulns));

        if total_vulns > MAX_FINDINGS_PER_REQUEST {
            output.push_str(&format!(
                "- **⚠️ Results Truncated**: Showing top {} most severe findings (sorted by severity and confidence)\n",
                MAX_FINDINGS_PER_REQUEST
            ));
            output.push_str("- **Note**: Many findings may be false positives. Focus on high-severity issues first.\n");
        }
        output.push('\n');

        if total_vulns == 0 {
            output.push_str("No injection vulnerabilities detected.\n");
            return Ok(output);
        }

        // By type breakdown
        output.push_str("## Vulnerabilities by Type\n\n");
        for (type_name, vulns) in &by_type {
            output.push_str(&format!("### {} ({})\n\n", type_name, vulns.len()));

            for vuln in vulns {
                let severity_icon = match vuln.severity {
                    Some(crate::taint::Severity::Critical) => "🔴",
                    Some(crate::taint::Severity::High) => "🟠",
                    Some(crate::taint::Severity::Medium) => "🟡",
                    Some(crate::taint::Severity::Low) => "🔵",
                    _ => "⚪",
                };

                output.push_str(&format!(
                    "{} **{}:{} → {}:{}**\n",
                    severity_icon,
                    vuln.source.file_path,
                    vuln.source.line,
                    vuln.sink.file_path,
                    vuln.sink.line
                ));
                output.push_str(&format!("  - Source: `{}`\n", vuln.source.code));
                output.push_str(&format!("  - Sink: `{}`\n", vuln.sink.code));

                if let Some(ref vk) = vuln.vulnerability {
                    if let Some(cwe) = vk.cwe_id() {
                        output.push_str(&format!("  - CWE: {}\n", cwe));
                    }
                }
                output.push('\n');
            }
        }

        Ok(output)
    }

    /// Trace taint flow from a specific source location
    pub async fn trace_taint(&self, repo_name: &str, path: &str, line: usize) -> Result<String> {
        let repo_path = self.get_repo_path(repo_name)?;
        let full_path = validate_path(&repo_path, path)?;

        let content = self
            .file_cache
            .get(&full_path)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| anyhow!("File not found: {}", path))?;

        let result = crate::taint::analyze_code(&content, path);

        let mut output = String::new();
        output.push_str(&format!("# Taint Trace: {}:{}\n\n", path, line));

        // Find flows that start near this line
        let relevant_flows: Vec<_> = result
            .flows
            .iter()
            .filter(|f| f.source.line == line || (f.source.line as i64 - line as i64).abs() <= 3)
            .collect();

        if relevant_flows.is_empty() {
            output.push_str(&format!(
                "No taint sources found at or near line {}.\n\n",
                line
            ));

            // Show nearby sources
            if !result.sources.is_empty() {
                output.push_str("## Nearby Taint Sources\n\n");
                for source in result.sources.iter().take(5) {
                    output.push_str(&format!(
                        "- Line {}: `{}` ({})\n",
                        source.line,
                        source.variable,
                        source.kind.display_name()
                    ));
                }
            }
            return Ok(output);
        }

        output.push_str(&format!(
            "Found {} taint flows from this location:\n\n",
            relevant_flows.len()
        ));

        for (i, flow) in relevant_flows.iter().enumerate() {
            output.push_str(&format!("## Flow {}\n\n", i + 1));
            output.push_str(&flow.to_markdown());
            output.push_str("\n---\n\n");
        }

        Ok(output)
    }

    /// Get all taint sources in a repository or file
    pub async fn get_taint_sources(
        &self,
        repo_name: &str,
        path: Option<&str>,
        source_types: &[String],
    ) -> Result<String> {
        let repo_path = self.get_repo_path(repo_name)?;
        let include_all = source_types.contains(&"all".to_string()) || source_types.is_empty();

        let mut all_sources: Vec<crate::taint::TaintSource> = Vec::new();

        // Get files to analyze - supports both file and directory paths
        let files_to_analyze: Vec<std::path::PathBuf> = self
            .file_cache
            .iter()
            .filter(|entry| entry.key().starts_with(&repo_path))
            .filter(|entry| {
                if let Some(specific_path) = path {
                    // Support both file and directory paths by checking if path matches
                    let entry_path = entry.key().to_string_lossy();
                    entry_path.contains(specific_path)
                } else {
                    true
                }
            })
            .filter(|entry| {
                let path_str = entry.key().to_string_lossy();
                path_str.ends_with(".py")
                    || path_str.ends_with(".js")
                    || path_str.ends_with(".ts")
                    || path_str.ends_with(".tsx")
                    || path_str.ends_with(".go")
                    || path_str.ends_with(".rs")
                    || path_str.ends_with(".php")
                    || path_str.ends_with(".java")
                    || path_str.ends_with(".rb")
                    || path_str.ends_with(".c")
                    || path_str.ends_with(".cpp")
                    || path_str.ends_with(".cs")
                    || path_str.ends_with(".kt")
            })
            .map(|entry| entry.key().clone())
            .collect();

        for file_path in &files_to_analyze {
            if let Some(content_entry) = self.file_cache.get(file_path) {
                let content = content_entry.value();
                let file_str = file_path.to_string_lossy();
                let result = crate::taint::analyze_code(content, &file_str);

                for source in result.sources {
                    // Filter by type
                    let type_match = match &source.kind {
                        crate::taint::SourceKind::UserInput { .. } => {
                            source_types.contains(&"user_input".to_string())
                        }
                        crate::taint::SourceKind::FileRead => {
                            source_types.contains(&"file_read".to_string())
                        }
                        crate::taint::SourceKind::DatabaseQuery => {
                            source_types.contains(&"database".to_string())
                        }
                        crate::taint::SourceKind::Environment => {
                            source_types.contains(&"environment".to_string())
                        }
                        crate::taint::SourceKind::Network => {
                            source_types.contains(&"network".to_string())
                        }
                        _ => true,
                    };

                    if include_all || type_match {
                        all_sources.push(source);
                    }
                }
            }
        }

        let mut output = String::new();
        output.push_str(&format!("# Taint Sources: {}\n\n", repo_name));
        output.push_str(&format!(
            "**Total sources found**: {}\n\n",
            all_sources.len()
        ));

        if all_sources.is_empty() {
            output.push_str("No taint sources found matching the criteria.\n");
            return Ok(output);
        }

        // Group by type
        let mut by_type: std::collections::HashMap<String, Vec<&crate::taint::TaintSource>> =
            std::collections::HashMap::new();
        for source in &all_sources {
            let type_name = source.kind.display_name();
            by_type.entry(type_name).or_default().push(source);
        }

        for (type_name, sources) in &by_type {
            output.push_str(&format!("## {} ({})\n\n", type_name, sources.len()));
            output.push_str("| File | Line | Variable | Code |\n");
            output.push_str("|------|------|----------|------|\n");

            for source in sources {
                let code_preview: String = source.code.chars().take(50).collect();
                output.push_str(&format!(
                    "| `{}` | {} | `{}` | `{}` |\n",
                    source.file_path, source.line, source.variable, code_preview
                ));
            }
            output.push('\n');
        }

        Ok(output)
    }

    /// Get a comprehensive security summary for a repository
    pub async fn get_security_summary(&self, repo_name: &str) -> Result<String> {
        let repo_path = self.get_repo_path(repo_name)?;

        let mut total_files = 0;
        let mut total_sources = 0;
        let mut total_sinks = 0;
        let mut total_vulns = 0;
        let mut total_sanitized = 0;

        let mut vuln_by_severity: std::collections::HashMap<crate::taint::Severity, usize> =
            std::collections::HashMap::new();
        let mut vuln_by_type: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        // Analyze all supported files
        let files: Vec<(std::path::PathBuf, Arc<String>)> = self
            .file_cache
            .iter()
            .filter(|entry| entry.key().starts_with(&repo_path))
            .filter(|entry| {
                let path_str = entry.key().to_string_lossy();
                path_str.ends_with(".py")
                    || path_str.ends_with(".js")
                    || path_str.ends_with(".ts")
                    || path_str.ends_with(".tsx")
                    || path_str.ends_with(".go")
                    || path_str.ends_with(".rs")
            })
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        for (file_path, content) in &files {
            total_files += 1;
            let file_str = file_path.to_string_lossy();
            let result = crate::taint::analyze_code(content, &file_str);

            total_sources += result.sources.len();
            total_sinks += result.sinks.len();

            for flow in &result.flows {
                if flow.is_sanitized {
                    total_sanitized += 1;
                } else if flow.vulnerability.is_some() {
                    total_vulns += 1;

                    if let Some(sev) = flow.severity {
                        *vuln_by_severity.entry(sev).or_insert(0) += 1;
                    }

                    if let Some(ref vuln_kind) = flow.vulnerability {
                        *vuln_by_type
                            .entry(vuln_kind.display_name().to_string())
                            .or_insert(0) += 1;
                    }
                }
            }
        }

        let mut output = String::new();
        output.push_str(&format!("# Security Summary: {}\n\n", repo_name));

        // Risk assessment
        let risk_level = if vuln_by_severity
            .get(&crate::taint::Severity::Critical)
            .unwrap_or(&0)
            > &0
        {
            "🔴 CRITICAL"
        } else if vuln_by_severity
            .get(&crate::taint::Severity::High)
            .unwrap_or(&0)
            > &0
        {
            "🟠 HIGH"
        } else if total_vulns > 0 {
            "🟡 MEDIUM"
        } else {
            "🟢 LOW"
        };

        output.push_str(&format!("## Risk Level: {}\n\n", risk_level));

        // Statistics
        output.push_str("## Analysis Statistics\n\n");
        output.push_str(&format!("- **Files Analyzed**: {}\n", total_files));
        output.push_str(&format!("- **Taint Sources**: {}\n", total_sources));
        output.push_str(&format!("- **Taint Sinks**: {}\n", total_sinks));
        output.push_str(&format!("- **Vulnerabilities Found**: {}\n", total_vulns));
        output.push_str(&format!("- **Sanitized Flows**: {}\n\n", total_sanitized));

        // Vulnerability breakdown by severity
        if total_vulns > 0 {
            output.push_str("## Vulnerabilities by Severity\n\n");
            for sev in [
                crate::taint::Severity::Critical,
                crate::taint::Severity::High,
                crate::taint::Severity::Medium,
                crate::taint::Severity::Low,
            ] {
                let count = vuln_by_severity.get(&sev).unwrap_or(&0);
                if *count > 0 {
                    let icon = match sev {
                        crate::taint::Severity::Critical => "🔴",
                        crate::taint::Severity::High => "🟠",
                        crate::taint::Severity::Medium => "🟡",
                        crate::taint::Severity::Low => "🔵",
                        crate::taint::Severity::Info => "⚪",
                    };
                    output.push_str(&format!("- {} {:?}: {}\n", icon, sev, count));
                }
            }
            output.push('\n');

            // Vulnerability breakdown by type
            output.push_str("## Vulnerabilities by Type\n\n");
            output.push_str("| Type | Count |\n");
            output.push_str("|------|-------|\n");
            for (vuln_type, count) in &vuln_by_type {
                output.push_str(&format!("| {} | {} |\n", vuln_type, count));
            }
            output.push('\n');

            // Recommendations
            output.push_str("## Recommendations\n\n");
            if vuln_by_type.contains_key("SQL Injection") {
                output.push_str(
                    "- **SQL Injection**: Use parameterized queries or prepared statements\n",
                );
            }
            if vuln_by_type.contains_key("Cross-Site Scripting (XSS)") {
                output.push_str(
                    "- **XSS**: Sanitize user input and use proper encoding for HTML output\n",
                );
            }
            if vuln_by_type.contains_key("Command Injection") {
                output.push_str("- **Command Injection**: Avoid shell execution or use strict input validation\n");
            }
            if vuln_by_type.contains_key("Path Traversal") {
                output.push_str("- **Path Traversal**: Validate file paths and use basename/realpath functions\n");
            }
        } else {
            output.push_str("## No vulnerabilities detected\n\n");
            output.push_str("The codebase appears secure based on the taint analysis.\n");
        }

        Ok(output)
    }

    // ========================================================================
    // Phase 4: Security Rules Engine
    // ========================================================================

    /// Scan repository for security issues using the security rules engine
    ///
    /// Phase C2: Added `max_findings` and `offset` parameters for pagination.
    /// This helps bound output size for large codebases.
    #[allow(clippy::too_many_arguments)]
    pub async fn scan_security(
        &self,
        repo_name: &str,
        path: Option<&str>,
        severity_threshold: Option<&str>,
        ruleset: Option<&str>,
        exclude_tests: Option<bool>,
        max_findings: Option<usize>,
        offset: Option<usize>,
    ) -> Result<String> {
        use crate::security_rules::{is_test_file, SecurityRulesEngine};

        let repo_path = self.get_repo_path(repo_name)?;
        let engine = SecurityRulesEngine::new();
        let exclude_tests = exclude_tests.unwrap_or(true);
        let min_severity = parse_severity_threshold(severity_threshold);

        // Collect files to scan with combined filters
        let files: Vec<_> = self
            .file_cache
            .iter()
            .filter(|e| e.key().starts_with(&repo_path))
            .filter(|e| path.is_none_or(|p| e.key().to_string_lossy().contains(p)))
            .filter(|e| !exclude_tests || !is_test_file(&e.key().to_string_lossy()))
            .filter(|e| is_security_scannable(&e.key().to_string_lossy()))
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();

        // Parse ruleset tags
        let ruleset_tags: Option<Vec<&str>> =
            ruleset.map(|r| r.split(',').map(str::trim).collect());

        // Scan all files and filter by severity
        let mut findings: Vec<_> = files
            .iter()
            .flat_map(|(file_path, content)| {
                let file_str = file_path.to_string_lossy();
                let lang = detect_language_from_path(&file_str);
                match &ruleset_tags {
                    Some(tags) => engine.scan_with_tags(content, &file_str, &lang, tags),
                    None => engine.scan(content, &file_str, &lang),
                }
            })
            .filter(|f| f.severity >= min_severity)
            .collect();

        findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        // Phase C2: Apply pagination (offset and limit)
        let total_findings = findings.len();
        let offset = offset.unwrap_or(0);
        let findings = if offset > 0 || max_findings.is_some() {
            let start = offset.min(findings.len());
            let end = match max_findings {
                Some(limit) => (start + limit).min(findings.len()),
                None => findings.len(),
            };
            findings[start..end].to_vec()
        } else {
            findings
        };
        let truncated = findings.len() < total_findings;

        // Build output
        let mut output = format!("# Security Scan: {}\n\n", repo_name);
        output.push_str(&format!("**Files Scanned**: {}\n", files.len()));
        output.push_str(&format!(
            "**Test Files**: {}\n",
            if exclude_tests {
                "excluded"
            } else {
                "included"
            }
        ));
        if let Some(ref tags) = ruleset_tags {
            output.push_str(&format!("**Ruleset Filter**: {}\n", tags.join(", ")));
        }

        // Phase C2: Show pagination info
        if truncated {
            output.push_str(&format!(
                "**Findings**: {} (showing {} of {}, offset: {})\n\n",
                findings.len(),
                findings.len(),
                total_findings,
                offset
            ));
        } else {
            output.push_str(&format!("**Findings**: {}\n\n", findings.len()));
        }

        if findings.is_empty() {
            if truncated && offset >= total_findings {
                output.push_str(&format!(
                    "Offset {} exceeds total findings {}. Try a smaller offset.\n",
                    offset, total_findings
                ));
            } else {
                output.push_str("No security issues found above the severity threshold.\n");
            }
        } else {
            output.push_str(&format_findings_by_severity(&findings));

            // Phase C2: Add pagination hint
            if truncated {
                output.push_str(&format!(
                    "\n---\n*Results truncated. Use `offset: {}` to see more findings.*\n",
                    offset + findings.len()
                ));
            }
        }

        Ok(output)
    }

    /// Scan for OWASP Top 10 vulnerabilities
    pub async fn check_owasp_top10(&self, repo_name: &str, path: Option<&str>) -> Result<String> {
        use crate::security_rules::SecurityRulesEngine;

        let repo_path = self.get_repo_path(repo_name)?;
        let engine = SecurityRulesEngine::new();

        let files: Vec<_> = self
            .file_cache
            .iter()
            .filter(|e| e.key().starts_with(&repo_path))
            .filter(|e| path.is_none_or(|p| e.key().to_string_lossy().contains(p)))
            .filter(|e| is_security_scannable(&e.key().to_string_lossy()))
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();

        let mut findings: Vec<_> = files
            .iter()
            .flat_map(|(file_path, content)| {
                let file_str = file_path.to_string_lossy();
                engine.scan_owasp_top10(content, &file_str, &detect_language_from_path(&file_str))
            })
            .collect();

        findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        let mut output = format!("# OWASP Top 10 2021 Scan: {}\n\n", repo_name);
        output.push_str(&format!("**Files Scanned**: {}\n", files.len()));
        output.push_str(&format!("**Findings**: {}\n\n", findings.len()));

        if findings.is_empty() {
            output.push_str("No OWASP Top 10 issues detected.\n");
        } else {
            output.push_str(&format_findings_by_category(
                &findings,
                OWASP_TOP10_CATEGORIES,
                |f| &f.owasp,
            ));
        }

        Ok(output)
    }

    /// Scan for CWE Top 25 vulnerabilities
    pub async fn check_cwe_top25(&self, repo_name: &str, path: Option<&str>) -> Result<String> {
        use crate::security_rules::SecurityRulesEngine;

        let repo_path = self.get_repo_path(repo_name)?;
        let engine = SecurityRulesEngine::new();

        let files: Vec<_> = self
            .file_cache
            .iter()
            .filter(|e| e.key().starts_with(&repo_path))
            .filter(|e| path.is_none_or(|p| e.key().to_string_lossy().contains(p)))
            .filter(|e| is_security_scannable(&e.key().to_string_lossy()))
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();

        let mut findings: Vec<_> = files
            .iter()
            .flat_map(|(file_path, content)| {
                let file_str = file_path.to_string_lossy();
                engine.scan_cwe_top25(content, &file_str, &detect_language_from_path(&file_str))
            })
            .collect();

        findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        let mut output = format!("# CWE Top 25 Scan: {}\n\n", repo_name);
        output.push_str(&format!("**Files Scanned**: {}\n", files.len()));
        output.push_str(&format!("**Findings**: {}\n\n", findings.len()));

        if findings.is_empty() {
            output.push_str("No CWE Top 25 issues detected.\n");
        } else {
            output.push_str(&format_findings_by_category(
                &findings,
                CWE_TOP25_TYPES,
                |f| &f.cwe,
            ));
        }

        Ok(output)
    }

    /// Get explanation of a vulnerability type
    pub async fn explain_vulnerability(
        &self,
        rule_id: Option<&str>,
        cwe: Option<&str>,
    ) -> Result<String> {
        use crate::security_rules::SecurityRulesEngine;

        let engine = SecurityRulesEngine::new();
        let mut output = String::new();

        // Look up by rule ID first
        if let Some(id) = rule_id {
            if let Some(explanation) = engine.explain_vulnerability(id) {
                output.push_str(&format!("# {}\n\n", explanation.name));
                output.push_str(&format!("**Rule ID**: {}\n", explanation.rule_id));
                output.push_str(&format!("**Severity**: {:?}\n\n", explanation.severity));

                if !explanation.cwe.is_empty() {
                    output.push_str("**CWE IDs**: ");
                    output.push_str(&explanation.cwe.join(", "));
                    output.push_str("\n\n");
                }

                if !explanation.owasp.is_empty() {
                    output.push_str("**OWASP Categories**: ");
                    output.push_str(&explanation.owasp.join(", "));
                    output.push_str("\n\n");
                }

                output.push_str("## Description\n\n");
                output.push_str(&explanation.description);
                output.push_str("\n\n");

                output.push_str("## Remediation\n\n");
                output.push_str(&explanation.remediation);
                output.push_str("\n\n");

                if !explanation.examples.is_empty() {
                    output.push_str("## Examples\n\n");
                    for example in &explanation.examples {
                        output.push_str(&format!("### {} Example\n\n", example.language));
                        output.push_str("**Vulnerable Code:**\n```\n");
                        output.push_str(&example.vulnerable);
                        output.push_str("\n```\n\n**Fixed Code:**\n```\n");
                        output.push_str(&example.fixed);
                        output.push_str("\n```\n\n");
                        output.push_str(&example.explanation);
                        output.push_str("\n\n");
                    }
                }

                if !explanation.references.is_empty() {
                    output.push_str("## References\n\n");
                    for ref_url in &explanation.references {
                        output.push_str(&format!("- {}\n", ref_url));
                    }
                }

                return Ok(output);
            }
        }

        // Look up by CWE
        if let Some(cwe_id) = cwe {
            // Find rules that match this CWE
            let matching_rules: Vec<_> = engine
                .get_rules()
                .into_iter()
                .filter(|r| r.cwe.iter().any(|c| c.contains(cwe_id)))
                .collect();

            if !matching_rules.is_empty() {
                output.push_str(&format!("# {} Vulnerabilities\n\n", cwe_id));

                // Add CWE reference
                let cwe_num = cwe_id.trim_start_matches("CWE-");
                output.push_str(&format!(
                    "**Reference**: https://cwe.mitre.org/data/definitions/{}.html\n\n",
                    cwe_num
                ));

                output.push_str("## Related Rules\n\n");
                for rule in &matching_rules {
                    output.push_str(&format!("### {} - {}\n\n", rule.id, rule.name));
                    output.push_str(&format!("**Severity**: {:?}\n\n", rule.severity));
                    output.push_str(&format!("{}\n\n", rule.message));
                    output.push_str(&format!("**Remediation**: {}\n\n", rule.remediation));
                }

                return Ok(output);
            }
        }

        output.push_str("# Vulnerability Not Found\n\n");
        output.push_str("The specified vulnerability type was not found in the rules engine.\n\n");
        output.push_str("Try one of these common rule IDs:\n");
        output.push_str("- OWASP-A03-001 (SQL Injection)\n");
        output.push_str("- OWASP-A03-003 (XSS)\n");
        output.push_str("- OWASP-A07-001 (Hardcoded Credentials)\n");
        output.push_str("- CWE-787-001 (Buffer Overflow)\n\n");
        output.push_str("Or search by CWE ID (e.g., CWE-89, CWE-79).\n");

        Ok(output)
    }

    /// Suggest fixes for a security finding
    pub async fn suggest_fix(
        &self,
        repo_name: &str,
        path: &str,
        line: usize,
        rule_id: Option<&str>,
    ) -> Result<String> {
        use crate::security_rules::SecurityRulesEngine;

        let repo_path = self.get_repo_path(repo_name)?;
        let full_path = validate_path(&repo_path, path)?;
        let engine = SecurityRulesEngine::new();

        // Get file content
        let content = self
            .file_cache
            .get(&full_path)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| anyhow!("File not found: {}", path))?;

        let file_str = full_path.to_string_lossy();
        let lang = detect_language_from_path(&file_str);

        // Scan the file
        let findings = engine.scan(&content, &file_str, &lang);

        // Find the finding at or near the specified line
        let finding = findings.iter().find(|f| {
            if let Some(rid) = rule_id {
                f.rule_id == rid && (f.line == line || (f.line <= line && f.end_line >= line))
            } else {
                f.line == line || (f.line <= line && f.end_line >= line)
            }
        });

        let mut output = String::new();

        if let Some(f) = finding {
            output.push_str(&format!("# Fix Suggestions for {}\n\n", f.rule_name));
            output.push_str(&format!("**Location**: {}:{}\n", path, f.line));
            output.push_str(&format!("**Rule**: {} - {}\n", f.rule_id, f.rule_name));
            output.push_str(&format!("**Severity**: {:?}\n\n", f.severity));

            output.push_str("## Issue\n\n");
            output.push_str(&f.message);
            output.push_str("\n\n");

            output.push_str("## Affected Code\n\n```\n");
            output.push_str(&f.snippet);
            output.push_str("\n```\n\n");

            // Get suggested fixes
            let fixes = engine.suggest_fix(f, &content);

            output.push_str("## Suggested Fixes\n\n");

            if fixes.is_empty() {
                output.push_str(&format!("**General Guidance**: {}\n", f.remediation));
            } else {
                for (i, fix) in fixes.iter().enumerate() {
                    output.push_str(&format!(
                        "### Option {} (Confidence: {:?})\n\n",
                        i + 1,
                        fix.confidence
                    ));
                    output.push_str(&fix.description);
                    output.push_str("\n\n");

                    if !fix.diff.is_empty() {
                        output.push_str("```diff\n");
                        output.push_str(&fix.diff);
                        output.push_str("\n```\n\n");
                    }
                }
            }

            // Add references
            if !f.cwe.is_empty() || !f.owasp.is_empty() {
                output.push_str("## References\n\n");
                for cwe in &f.cwe {
                    let cwe_num = cwe.trim_start_matches("CWE-");
                    output.push_str(&format!(
                        "- {}: https://cwe.mitre.org/data/definitions/{}.html\n",
                        cwe, cwe_num
                    ));
                }
                for owasp in &f.owasp {
                    output.push_str(&format!(
                        "- {}: https://owasp.org/Top10/{}\n",
                        owasp,
                        owasp.replace(":", "_")
                    ));
                }
            }
        } else {
            output.push_str("# No Finding at Specified Location\n\n");
            output.push_str(&format!(
                "No security finding found at {}:{}.\n\n",
                path, line
            ));

            if !findings.is_empty() {
                output.push_str("## Other findings in this file\n\n");
                for f in findings.iter().take(5) {
                    output.push_str(&format!(
                        "- Line {}: {} ({})\n",
                        f.line, f.rule_name, f.rule_id
                    ));
                }
            }
        }

        Ok(output)
    }

    // ========================================================================
    // Phase 5: Supply Chain Security
    // ========================================================================

    /// Generate Software Bill of Materials (SBOM) in CycloneDX or SPDX format
    ///
    /// Phase C1: Added `compact` parameter to output minified JSON (~25% smaller).
    pub async fn generate_sbom(
        &self,
        repo_name: &str,
        format: &str,
        compact: bool,
    ) -> Result<String> {
        use crate::supply_chain::{SBOMFormat, SupplyChainAnalyzer};

        let repo_path = self.get_repo_path(repo_name)?;
        let analyzer = SupplyChainAnalyzer::new();

        // Get project name and version from manifest if available
        let (project_name, project_version) = self.get_project_info(&repo_path);

        let sbom_format = match format.to_lowercase().as_str() {
            "spdx" => SBOMFormat::SPDX,
            "json" => SBOMFormat::JSON,
            _ => SBOMFormat::CycloneDX,
        };

        match analyzer.generate_sbom(
            &repo_path,
            &project_name,
            &project_version,
            sbom_format,
            compact,
        ) {
            Ok(sbom) => {
                let mut output = String::new();
                output.push_str(&format!("# Software Bill of Materials: {}\n\n", repo_name));
                output.push_str(&format!("**Format**: {:?}\n", sbom_format));
                output.push_str(&format!(
                    "**Project**: {} v{}\n\n",
                    project_name, project_version
                ));
                if compact {
                    output.push_str("**Output**: Compact (minified)\n\n");
                }
                output.push_str("```json\n");
                output.push_str(&sbom);
                output.push_str("\n```\n");
                Ok(output)
            }
            Err(e) => Err(anyhow!("Failed to generate SBOM: {}", e)),
        }
    }

    /// Check dependencies for known vulnerabilities
    pub async fn check_dependencies(
        &self,
        repo_name: &str,
        severity_threshold: Option<&str>,
        include_dev: bool,
    ) -> Result<String> {
        use crate::supply_chain::{SupplyChainAnalyzer, VulnSeverity};

        let repo_path = self.get_repo_path(repo_name)?;
        let analyzer = SupplyChainAnalyzer::new();

        let min_severity = match severity_threshold {
            Some("critical") => VulnSeverity::Critical,
            Some("high") => VulnSeverity::High,
            Some("medium") => VulnSeverity::Medium,
            _ => VulnSeverity::Low,
        };

        let deps = match analyzer.parse_dependencies(&repo_path) {
            Ok(d) => d,
            Err(e) => return Err(anyhow!("Failed to parse dependencies: {}", e)),
        };

        // Filter dev dependencies if needed
        let deps: Vec<_> = if include_dev {
            deps
        } else {
            deps.into_iter().filter(|d| !d.dev_dependency).collect()
        };

        let vulns = analyzer.check_vulnerabilities(&deps);

        // Filter by severity
        let vulns: Vec<_> = vulns
            .into_iter()
            .filter(|v| v.risk_level >= min_severity)
            .collect();

        let mut output = String::new();
        output.push_str(&format!(
            "# Dependency Vulnerability Scan: {}\n\n",
            repo_name
        ));
        output.push_str(&format!("**Dependencies Scanned**: {}\n", deps.len()));
        output.push_str(&format!("**Vulnerable Dependencies**: {}\n", vulns.len()));
        output.push_str(&format!("**Severity Threshold**: {:?}\n\n", min_severity));

        if vulns.is_empty() {
            output.push_str("No vulnerable dependencies found above the severity threshold.\n");
        } else {
            // Group by severity
            let critical: Vec<_> = vulns
                .iter()
                .filter(|v| v.risk_level == VulnSeverity::Critical)
                .collect();
            let high: Vec<_> = vulns
                .iter()
                .filter(|v| v.risk_level == VulnSeverity::High)
                .collect();
            let medium: Vec<_> = vulns
                .iter()
                .filter(|v| v.risk_level == VulnSeverity::Medium)
                .collect();
            let low: Vec<_> = vulns
                .iter()
                .filter(|v| v.risk_level == VulnSeverity::Low)
                .collect();

            if !critical.is_empty() {
                output.push_str(&format!("## 🔴 Critical ({})\n\n", critical.len()));
                for v in &critical {
                    output.push_str(&format_vuln_finding(v));
                }
            }

            if !high.is_empty() {
                output.push_str(&format!("## 🟠 High ({})\n\n", high.len()));
                for v in &high {
                    output.push_str(&format_vuln_finding(v));
                }
            }

            if !medium.is_empty() {
                output.push_str(&format!("## 🟡 Medium ({})\n\n", medium.len()));
                for v in &medium {
                    output.push_str(&format_vuln_finding(v));
                }
            }

            if !low.is_empty() {
                output.push_str(&format!("## 🔵 Low ({})\n\n", low.len()));
                for v in &low {
                    output.push_str(&format_vuln_finding(v));
                }
            }
        }

        Ok(output)
    }

    /// Check license compliance for dependencies
    pub async fn check_licenses(
        &self,
        repo_name: &str,
        project_license: Option<&str>,
        fail_on_copyleft: bool,
    ) -> Result<String> {
        use crate::supply_chain::SupplyChainAnalyzer;

        let repo_path = self.get_repo_path(repo_name)?;
        let analyzer = SupplyChainAnalyzer::new();

        let deps = match analyzer.parse_dependencies(&repo_path) {
            Ok(d) => d,
            Err(e) => return Err(anyhow!("Failed to parse dependencies: {}", e)),
        };

        let report = analyzer.check_licenses(&deps, project_license);

        let mut output = String::new();
        output.push_str(&format!("# License Compliance Report: {}\n\n", repo_name));

        if let Some(lic) = project_license {
            output.push_str(&format!("**Project License**: {}\n", lic));
        }
        output.push_str(&format!("**Dependencies Analyzed**: {}\n\n", deps.len()));
        output.push_str(&format!("{}\n\n", report.summary));

        // License distribution
        output.push_str("## License Distribution\n\n");
        output.push_str("| License | Count | Dependencies |\n");
        output.push_str("|---------|-------|-------------|\n");

        let mut sorted_licenses: Vec<_> = report.dependencies_by_license.iter().collect();
        sorted_licenses.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

        for (license, dep_list) in sorted_licenses.iter().take(15) {
            let deps_preview: String = dep_list
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let suffix = if dep_list.len() > 3 {
                format!(" +{} more", dep_list.len() - 3)
            } else {
                String::new()
            };
            output.push_str(&format!(
                "| {} | {} | {}{} |\n",
                license,
                dep_list.len(),
                deps_preview,
                suffix
            ));
        }
        output.push('\n');

        // Categorization
        output.push_str("## License Categories\n\n");
        output.push_str(&format!(
            "- **Permissive**: {} packages\n",
            report.permissive_deps.len()
        ));
        output.push_str(&format!(
            "- **Copyleft**: {} packages\n",
            report.copyleft_deps.len()
        ));
        output.push_str(&format!(
            "- **Unknown**: {} packages\n\n",
            report.unknown_license_deps.len()
        ));

        // Issues
        if !report.issues.is_empty() {
            output.push_str("## License Issues\n\n");

            let copyleft_issues: Vec<_> = report
                .issues
                .iter()
                .filter(|i| i.issue_type == crate::supply_chain::LicenseIssueType::Copyleft)
                .collect();
            let unknown_issues: Vec<_> = report
                .issues
                .iter()
                .filter(|i| {
                    i.issue_type == crate::supply_chain::LicenseIssueType::Unknown
                        || i.issue_type == crate::supply_chain::LicenseIssueType::NoLicense
                })
                .collect();

            if !copyleft_issues.is_empty() && fail_on_copyleft {
                output.push_str("### ⚠️ Copyleft License Warnings\n\n");
                for issue in &copyleft_issues {
                    output.push_str(&format!(
                        "- **{}**: {} ({})\n",
                        issue.dependency, issue.license, issue.message
                    ));
                    output.push_str(&format!("  - *Recommendation*: {}\n", issue.recommendation));
                }
                output.push('\n');
            }

            if !unknown_issues.is_empty() {
                output.push_str("### ⚠️ Unknown/Missing Licenses\n\n");
                for issue in &unknown_issues {
                    output.push_str(&format!("- **{}**: {}\n", issue.dependency, issue.message));
                }
                output.push('\n');
            }
        } else {
            output.push_str("No license compliance issues detected.\n");
        }

        // Copyleft dependencies list
        if !report.copyleft_deps.is_empty() {
            output.push_str("## Copyleft Dependencies\n\n");
            output.push_str("These dependencies may have viral licensing requirements:\n\n");
            for dep in &report.copyleft_deps {
                output.push_str(&format!("- {}\n", dep));
            }
            output.push('\n');
        }

        Ok(output)
    }

    /// Find safe upgrade paths for vulnerable dependencies
    pub async fn find_upgrade_path(
        &self,
        repo_name: &str,
        dependency: Option<&str>,
    ) -> Result<String> {
        use crate::supply_chain::SupplyChainAnalyzer;

        let repo_path = self.get_repo_path(repo_name)?;
        let analyzer = SupplyChainAnalyzer::new();

        let deps = match analyzer.parse_dependencies(&repo_path) {
            Ok(d) => d,
            Err(e) => return Err(anyhow!("Failed to parse dependencies: {}", e)),
        };

        // Filter to specific dependency if requested
        let deps: Vec<_> = if let Some(dep_name) = dependency {
            deps.into_iter().filter(|d| d.name == dep_name).collect()
        } else {
            deps
        };

        let vulns = analyzer.check_vulnerabilities(&deps);
        let upgrades = analyzer.find_upgrade_path(&vulns);

        let mut output = String::new();
        output.push_str(&format!("# Upgrade Recommendations: {}\n\n", repo_name));

        if let Some(dep) = dependency {
            output.push_str(&format!("**Dependency**: {}\n\n", dep));
        }

        if upgrades.is_empty() {
            if dependency.is_some() {
                output.push_str("No vulnerable versions found for this dependency.\n");
            } else {
                output.push_str("No vulnerable dependencies require upgrading.\n");
            }
        } else {
            output.push_str(&format!("**Upgrades Recommended**: {}\n\n", upgrades.len()));

            output.push_str(
                "| Dependency | Current | Recommended | Breaking | Vulnerabilities Fixed |\n",
            );
            output.push_str(
                "|------------|---------|-------------|----------|----------------------|\n",
            );

            for upgrade in &upgrades {
                let breaking = if upgrade.breaking_changes {
                    "⚠️ Yes"
                } else {
                    "No"
                };
                let fixed = upgrade.vulnerabilities_fixed.join(", ");
                output.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    upgrade.dependency,
                    upgrade.current_version,
                    upgrade.recommended_version,
                    breaking,
                    fixed
                ));
            }
            output.push('\n');

            // Detailed recommendations
            output.push_str("## Detailed Recommendations\n\n");
            for upgrade in &upgrades {
                output.push_str(&format!("### {}\n\n", upgrade.dependency));
                output.push_str(&format!("- **Current**: {}\n", upgrade.current_version));
                output.push_str(&format!(
                    "- **Recommended**: {}\n",
                    upgrade.recommended_version
                ));
                output.push_str(&format!("- **Reason**: {:?}\n", upgrade.reason));

                if upgrade.breaking_changes {
                    output.push_str(
                        "- **⚠️ Breaking Changes Expected**: Review changelog before upgrading\n",
                    );
                }

                if !upgrade.vulnerabilities_fixed.is_empty() {
                    output.push_str("- **Fixes**:\n");
                    for vuln_id in &upgrade.vulnerabilities_fixed {
                        output.push_str(&format!("  - {}\n", vuln_id));
                    }
                }
                output.push('\n');
            }
        }

        Ok(output)
    }

    /// Helper: Get project name and version from manifest files
    fn get_project_info(&self, repo_path: &std::path::Path) -> (String, String) {
        // Try Cargo.toml
        let cargo_toml = repo_path.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                if let Ok(parsed) = toml::from_str::<toml::Value>(&content) {
                    let name = parsed
                        .get("package")
                        .and_then(|p| p.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let version = parsed
                        .get("package")
                        .and_then(|p| p.get("version"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.0.0")
                        .to_string();
                    return (name, version);
                }
            }
        }

        // Try package.json
        let package_json = repo_path.join("package.json");
        if package_json.exists() {
            if let Ok(content) = std::fs::read_to_string(&package_json) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                    let name = parsed
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let version = parsed
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.0.0")
                        .to_string();
                    return (name, version);
                }
            }
        }

        // Fallback to directory name
        let name = repo_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        (name, "0.0.0".to_string())
    }

    // =========================================================================
    // Phase 6: Advanced Features
    // =========================================================================

    /// Get import graph for a file or repository
    pub async fn get_import_graph(
        &self,
        repo_name: &str,
        file: Option<&str>,
        direction: &str,
    ) -> Result<String> {
        let repo_path = self.get_repo_path(repo_name)?;
        let symbols = self
            .symbols
            .get(repo_name)
            .map(|s| s.clone())
            .unwrap_or_default();

        let mut resolver = crate::incremental::SymbolResolver::new();

        // Deduplicate file paths to avoid parsing the same file multiple times
        let unique_files: std::collections::HashSet<_> =
            symbols.iter().map(|s| s.file_path.clone()).collect();

        // Parse imports from unique files only
        for rel_path in unique_files {
            let file_path = repo_path.join(&rel_path);
            if file_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    let imports = parse_imports_from_content(&content, &rel_path);
                    resolver.register_imports(&file_path, imports);
                }
            }
        }

        let graph = resolver.build_import_graph(&repo_path);

        let mut output = String::new();
        output.push_str("# Import Graph\n\n");

        if let Some(target_file) = file {
            let target_path = repo_path.join(target_file);

            match direction {
                "imports" | "both" => {
                    output.push_str(&format!("## Files imported by `{}`\n\n", target_file));
                    let deps = graph.dependencies(&target_path);
                    if deps.is_empty() {
                        output.push_str("No imports found.\n\n");
                    } else {
                        for dep in deps {
                            let rel_path = dep
                                .strip_prefix(&repo_path)
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_else(|_| dep.to_string_lossy().to_string());
                            output.push_str(&format!("- `{}`\n", rel_path));
                        }
                        output.push('\n');
                    }
                }
                _ => {}
            }

            match direction {
                "importers" | "both" => {
                    output.push_str(&format!("## Files that import `{}`\n\n", target_file));
                    let dependents = graph.dependents(&target_path);
                    if dependents.is_empty() {
                        output.push_str("No importers found.\n\n");
                    } else {
                        for dep in dependents {
                            let rel_path = dep
                                .strip_prefix(&repo_path)
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_else(|_| dep.to_string_lossy().to_string());
                            output.push_str(&format!("- `{}`\n", rel_path));
                        }
                        output.push('\n');
                    }
                }
                _ => {}
            }

            let depth = graph.depth(&target_path);
            output.push_str(&format!("**Import depth**: {}\n", depth));
        } else {
            // Show summary for whole repo
            output.push_str("## Repository Import Summary\n\n");
            output.push_str("| File | Dependencies | Dependents |\n");
            output.push_str("|------|--------------|------------|\n");

            let mut file_stats: Vec<_> = symbols
                .iter()
                .map(|s| {
                    let path = repo_path.join(&s.file_path);
                    let deps = graph.dependencies(&path).len();
                    let dependents = graph.dependents(&path).len();
                    (s.file_path.clone(), deps, dependents)
                })
                .collect();

            file_stats.sort_by(|a, b| (b.1 + b.2).cmp(&(a.1 + a.2)));
            file_stats.truncate(20);

            for (file, deps, dependents) in file_stats {
                output.push_str(&format!("| {} | {} | {} |\n", file, deps, dependents));
            }
        }

        Ok(output)
    }

    /// Find circular import dependencies
    pub async fn find_circular_imports(&self, repo_name: &str) -> Result<String> {
        let repo_path = self.get_repo_path(repo_name)?;
        let symbols = self
            .symbols
            .get(repo_name)
            .map(|s| s.clone())
            .unwrap_or_default();

        let mut resolver = crate::incremental::SymbolResolver::new();

        // Parse imports from all files
        for symbol in &symbols {
            let file_path = repo_path.join(&symbol.file_path);
            if file_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    let imports = parse_imports_from_content(&content, &symbol.file_path);
                    resolver.register_imports(&file_path, imports);
                }
            }
        }

        let graph = resolver.build_import_graph(&repo_path);
        let cycles = graph.find_cycles();

        let mut output = String::new();
        output.push_str("# Circular Import Analysis\n\n");

        if cycles.is_empty() {
            output.push_str("No circular imports detected.\n");
        } else {
            output.push_str(&format!(
                "**Found {} circular import chain(s)**\n\n",
                cycles.len()
            ));

            for (i, cycle) in cycles.iter().enumerate() {
                output.push_str(&format!("## Cycle {}\n\n", i + 1));
                output.push_str("```\n");
                for (j, path) in cycle.iter().enumerate() {
                    let rel_path = path
                        .strip_prefix(&repo_path)
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| path.to_string_lossy().to_string());
                    output.push_str(&rel_path.to_string());
                    if j < cycle.len() - 1 {
                        output.push_str(" -> ");
                    }
                }
                output.push_str(&format!(
                    " -> {} (cycle)\n",
                    cycle
                        .first()
                        .map(|p| p
                            .strip_prefix(&repo_path)
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| p.to_string_lossy().to_string()))
                        .unwrap_or_default()
                ));
                output.push_str("```\n\n");
            }

            output.push_str("## Recommendations\n\n");
            output.push_str("- Extract shared code to a separate module\n");
            output.push_str("- Use dependency injection to break cycles\n");
            output.push_str("- Consider lazy imports or dynamic imports\n");
        }

        Ok(output)
    }

    /// Fuzzy workspace symbol search
    pub async fn workspace_symbol_search(
        &self,
        query: &str,
        kind: Option<&str>,
        limit: usize,
    ) -> Result<String> {
        let mut index = crate::incremental::WorkspaceSymbolIndex::new();

        // Index all symbols from all repos
        for entry in self.symbols.iter() {
            let repo_name = entry.key();
            for symbol in entry.value().iter() {
                let file_path =
                    std::path::PathBuf::from(format!("{}/{}", repo_name, symbol.file_path));
                index.add_symbol(symbol.clone(), file_path);
            }
        }

        // Filter by kind if specified
        let results = if let Some(kind_filter) = kind {
            if kind_filter == "all" {
                index.search(query, limit)
            } else {
                let target_kind = match kind_filter {
                    "function" => Some(crate::symbols::SymbolKind::Function),
                    "class" => Some(crate::symbols::SymbolKind::Class),
                    "struct" => Some(crate::symbols::SymbolKind::Struct),
                    "interface" => Some(crate::symbols::SymbolKind::Interface),
                    "enum" => Some(crate::symbols::SymbolKind::Enum),
                    "variable" => Some(crate::symbols::SymbolKind::Variable),
                    _ => None,
                };

                if let Some(kind) = target_kind {
                    index
                        .search(query, limit * 2)
                        .into_iter()
                        .filter(|r| r.symbol.kind == kind)
                        .take(limit)
                        .collect()
                } else {
                    index.search(query, limit)
                }
            }
        } else {
            index.search(query, limit)
        };

        let mut output = String::new();
        output.push_str(&format!("# Symbol Search: '{}'\n\n", query));

        if results.is_empty() {
            output.push_str("No symbols found.\n");
        } else {
            output.push_str(&format!("Found {} results:\n\n", results.len()));
            output.push_str("| Symbol | Kind | File | Line | Score |\n");
            output.push_str("|--------|------|------|------|-------|\n");

            for result in results {
                output.push_str(&format!(
                    "| `{}` | {:?} | {} | {} | {:.2} |\n",
                    result.symbol.name,
                    result.symbol.kind,
                    result.file_path.display(),
                    result.symbol.start_line,
                    result.score
                ));
            }
        }

        Ok(output)
    }

    /// Get incremental indexing status
    pub async fn get_incremental_status(&self, repo_name: &str) -> Result<String> {
        let repo_path = self.get_repo_path(repo_name)?;

        let mut output = String::new();
        output.push_str(&format!("# Incremental Index Status: {}\n\n", repo_name));

        // Count files and symbols
        let symbol_count = self.symbols.get(repo_name).map(|s| s.len()).unwrap_or(0);

        let file_count = self.file_cache.len();

        output.push_str("## Index Statistics\n\n");
        output.push_str(&format!("- **Repository**: {}\n", repo_path.display()));
        output.push_str(&format!("- **Indexed Symbols**: {}\n", symbol_count));
        output.push_str(&format!("- **Cached Files**: {}\n", file_count));

        // Check for persisted index
        if let Some(ref store) = self.index_store {
            let index_file = store.index_path(&repo_path);
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
        if let Some(symbols) = self.symbols.get(repo_name) {
            output.push_str("\n## Symbol Breakdown\n\n");
            let mut by_kind: std::collections::HashMap<crate::symbols::SymbolKind, usize> =
                std::collections::HashMap::new();
            for s in symbols.iter() {
                *by_kind.entry(s.kind.clone()).or_insert(0) += 1;
            }

            let mut counts: Vec<_> = by_kind.into_iter().collect();
            counts.sort_by(|a, b| b.1.cmp(&a.1));

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
    ) -> Result<String> {
        let repo_path = self.get_repo_path(repo_name)?;
        let symbols = self
            .symbols
            .get(repo_name)
            .map(|s| s.clone())
            .unwrap_or_default();

        let mut usages: Vec<(String, usize, String)> = Vec::new();
        let mut definitions: Vec<(String, usize, String)> = Vec::new();

        // Find definitions
        for symbol in &symbols {
            if symbol.name == symbol_name {
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

            for (line_num, line) in content.lines().enumerate() {
                let is_import = line.contains("import ")
                    || line.contains("use ")
                    || line.contains("from ")
                    || line.contains("require(");

                if !include_imports && is_import {
                    continue;
                }

                if line.contains(symbol_name) {
                    let context = if is_import { "import" } else { "usage" };
                    usages.push((rel_path.clone(), line_num + 1, context.to_string()));
                }
            }
        }

        let mut output = String::new();
        output.push_str(&format!("# Symbol Usages: '{}'\n\n", symbol_name));

        if !definitions.is_empty() {
            output.push_str("## Definitions\n\n");
            for (file, line, kind) in &definitions {
                output.push_str(&format!("- `{}:{}` ({})\n", file, line, kind));
            }
            output.push('\n');
        }

        if usages.is_empty() {
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
        let repo_path = self.get_repo_path(repo_name)?;
        let file_path = validate_path(&repo_path, path)?;

        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let symbols = self
            .symbols
            .get(repo_name)
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
            public_symbols.sort_by(|a, b| a.start_line.cmp(&b.start_line));

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
                    if sig.len() > 50 { &sig[..50] } else { sig }
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

    // === Neural Search Methods ===

    /// Perform neural semantic search
    pub async fn neural_search(
        &self,
        repo: Option<&str>,
        query: &str,
        max_results: usize,
    ) -> Result<String> {
        let neural = self.neural_engine.as_ref().ok_or_else(|| {
            anyhow!(
                "Neural search not available. Enable with --neural flag and set EMBEDDING_API_KEY."
            )
        })?;

        let results = neural.search(query, max_results)?;

        let mut output = String::new();
        output.push_str(&format!("# Neural Search Results for: `{}`\n\n", query));

        // Filter by repo if specified
        let filtered_results: Vec<_> = if let Some(repo_name) = repo {
            results
                .into_iter()
                .filter(|r| r.document.file_path.contains(repo_name))
                .collect()
        } else {
            results
        };

        if filtered_results.is_empty() {
            output.push_str("No results found.\n");
        } else {
            output.push_str(&format!(
                "Found {} semantically similar results:\n\n",
                filtered_results.len()
            ));

            for (i, result) in filtered_results.iter().enumerate() {
                output.push_str(&format!(
                    "## {}. {} (similarity: {:.3})\n",
                    i + 1,
                    result.document.file_path,
                    result.similarity
                ));
                output.push_str(&format!(
                    "Lines {}-{}\n\n",
                    result.document.start_line, result.document.end_line
                ));

                if let Some(ref symbol) = result.document.symbol_name {
                    output.push_str(&format!("**Symbol**: `{}`\n\n", symbol));
                }

                // Show snippet (truncated if long)
                let content = &result.document.content;
                let snippet = if content.len() > 500 {
                    format!("{}...", &content[..500])
                } else {
                    content.clone()
                };
                output.push_str("```\n");
                output.push_str(&snippet);
                output.push_str("\n```\n\n");
            }
        }

        Ok(output)
    }

    /// Find code semantically similar to a symbol
    pub async fn find_semantic_clones(
        &self,
        repo: &str,
        path: &str,
        function: &str,
        threshold: f32,
    ) -> Result<String> {
        let neural = self
            .neural_engine
            .as_ref()
            .ok_or_else(|| anyhow!("Neural search not available. Enable with --neural flag."))?;

        // Get the symbol's code
        let repo_path = self.get_repo_path(repo)?;
        let file_path = validate_path(&repo_path, path)?;
        let content = std::fs::read_to_string(&file_path)?;

        // Find the symbol in our index
        let symbols = self
            .symbols
            .get(repo)
            .ok_or_else(|| anyhow!("Repository not indexed"))?;
        let symbol = symbols
            .iter()
            .find(|s| s.name == function && s.file_path == path)
            .ok_or_else(|| anyhow!("Symbol not found: {}", function))?;

        // Extract the symbol's code
        let lines: Vec<&str> = content.lines().collect();
        let start = symbol.start_line.saturating_sub(1);
        let end = symbol.end_line.min(lines.len());
        let symbol_code = lines[start..end].join("\n");

        // Search for similar code
        let results = neural.search(&symbol_code, 20)?;

        let mut output = String::new();
        output.push_str(&format!("# Semantic Clones of `{}`\n\n", function));
        output.push_str(&format!("Threshold: {:.2}\n\n", threshold));

        let filtered: Vec<_> = results
            .into_iter()
            .filter(|r| {
                r.similarity >= threshold && r.document.symbol_name.as_deref() != Some(function)
            })
            .collect();

        if filtered.is_empty() {
            output.push_str("No semantic clones found above threshold.\n");
        } else {
            output.push_str(&format!("Found {} potential clones:\n\n", filtered.len()));

            for (i, result) in filtered.iter().enumerate() {
                output.push_str(&format!(
                    "## {}. {} (similarity: {:.3})\n",
                    i + 1,
                    result
                        .document
                        .symbol_name
                        .as_deref()
                        .unwrap_or(&result.document.file_path),
                    result.similarity
                ));
                output.push_str(&format!(
                    "File: {}:{}-{}\n\n",
                    result.document.file_path, result.document.start_line, result.document.end_line
                ));

                let content = &result.document.content;
                let snippet = if content.len() > 300 {
                    format!("{}...", &content[..300])
                } else {
                    content.clone()
                };
                output.push_str("```\n");
                output.push_str(&snippet);
                output.push_str("\n```\n\n");
            }
        }

        Ok(output)
    }

    /// Get neural engine statistics
    pub async fn get_neural_stats(&self) -> Result<String> {
        let neural = self
            .neural_engine
            .as_ref()
            .ok_or_else(|| anyhow!("Neural search not available. Enable with --neural flag."))?;

        let stats = neural.stats();

        let mut output = String::new();
        output.push_str("# Neural Embedding Statistics\n\n");
        output.push_str(&format!("**Backend**: {}\n", stats.backend));
        if let Some(model) = &stats.model {
            output.push_str(&format!("**Model**: {}\n", model));
        }
        output.push_str(&format!("**Dimension**: {}\n", stats.dimension));
        output.push_str(&format!("**Indexed Documents**: {}\n", stats.indexed_count));

        Ok(output)
    }

    /// Check if neural search is available
    pub fn is_neural_enabled(&self) -> bool {
        self.neural_engine.is_some()
    }

    // ========== Phase 8: Type Inference ==========

    /// Infer types for a Python/JavaScript function
    pub async fn infer_types(&self, repo: &str, path: &str, function: &str) -> Result<String> {
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;
        let language = detect_language_from_path(path);

        // Check if it's a dynamic language
        if !matches!(language.as_str(), "python" | "javascript" | "typescript") {
            return Err(anyhow!(
                "Type inference is only available for Python and JavaScript/TypeScript. Found: {}",
                language
            ));
        }

        // Parse the file
        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;

        // Find the function
        let mut found_cfg = None;
        let cfgs = cfg::analyze_function(tree, &content, path)?;

        for cfg_item in cfgs {
            if cfg_item.function_name == function {
                found_cfg = Some(cfg_item);
                break;
            }
        }

        let cfg_ref = found_cfg.as_ref();

        // Create inferencer and run
        let mut inferencer = TypeInferencer::new(&content, cfg_ref, &language);
        let result = inferencer.infer_from_cfg(&[]);

        Ok(result.to_markdown())
    }

    /// Check for type errors in a file without running external type checkers
    pub async fn check_type_errors(&self, repo: &str, path: &str) -> Result<String> {
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;
        let language = detect_language_from_path(path);

        // Check if it's a dynamic language
        if !matches!(language.as_str(), "python" | "javascript" | "typescript") {
            return Err(anyhow!(
                "Type checking is only available for Python and JavaScript/TypeScript. Found: {}",
                language
            ));
        }

        // Parse and analyze
        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;
        let cfgs = cfg::analyze_function(tree, &content, path)?;

        let mut all_errors: Vec<(String, TypeError)> = Vec::new();

        for cfg_item in &cfgs {
            let mut inferencer = TypeInferencer::new(&content, Some(cfg_item), &language);
            let result = inferencer.infer_from_cfg(&[]);

            for error in result.errors {
                all_errors.push((cfg_item.function_name.clone(), error));
            }

            // Also run type checking
            let check_errors = inferencer.check_type_errors();
            for error in check_errors {
                all_errors.push((cfg_item.function_name.clone(), error));
            }
        }

        // Format output
        let mut output = String::new();
        output.push_str(&format!("# Type Check Results: `{}`\n\n", path));
        output.push_str(&format!("**Functions analyzed**: {}\n\n", cfgs.len()));

        if all_errors.is_empty() {
            output.push_str("✅ No type errors found!\n");
        } else {
            output.push_str(&format!(
                "⚠️ **{} potential issues found**\n\n",
                all_errors.len()
            ));

            for (func_name, error) in &all_errors {
                output.push_str(&format!(
                    "- **{}** (line {}:{}): {:?} - {}\n",
                    func_name, error.line, error.column, error.kind, error.message
                ));
            }
        }

        Ok(output)
    }

    /// Enhanced taint analysis with type information
    pub async fn get_typed_taint_flow(
        &self,
        repo: &str,
        path: &str,
        source_line: usize,
    ) -> Result<String> {
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;
        let language = detect_language_from_path(path);

        // Parse the file
        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;
        let cfgs = cfg::analyze_function(tree, &content, path)?;

        let mut output = String::new();
        output.push_str(&format!(
            "# Typed Taint Flow: `{}` (line {})\n\n",
            path, source_line
        ));

        // Find which function contains this line
        let mut containing_cfg = None;
        for cfg_item in &cfgs {
            for block in cfg_item.blocks.values() {
                if block.start_line <= source_line && source_line <= block.end_line {
                    containing_cfg = Some(cfg_item);
                    break;
                }
            }
            if containing_cfg.is_some() {
                break;
            }
        }

        if let Some(cfg_item) = containing_cfg {
            output.push_str(&format!("**Function**: `{}`\n\n", cfg_item.function_name));

            // Get type information
            let mut inferencer = TypeInferencer::new(&content, Some(cfg_item), &language);
            let types = inferencer.infer_from_cfg(&[]);

            // Get taint information using the existing analyzer
            let taint_result = crate::taint::analyze_code(&content, path);

            // Combine type and taint info
            output.push_str("## Type Information at Source\n\n");
            if let Some(line_types) = types.variable_types.get(&source_line) {
                for (var, ty) in line_types {
                    let ty_ref: &crate::type_inference::Type = ty;
                    output.push_str(&format!("- `{}`: `{}`\n", var, ty_ref.display_name()));
                }
            } else {
                output.push_str("*No type information available at this line*\n");
            }
            output.push('\n');

            output.push_str("## Taint Sources Near Line\n\n");
            let nearby_sources: Vec<_> = taint_result
                .sources
                .iter()
                .filter(|s| s.line >= source_line.saturating_sub(5) && s.line <= source_line + 5)
                .collect();

            if nearby_sources.is_empty() {
                output.push_str("*No taint sources near this line*\n");
            } else {
                for source in nearby_sources {
                    let type_info = types
                        .variable_types
                        .get(&source.line)
                        .and_then(|vars: &HashMap<String, crate::type_inference::Type>| {
                            vars.get(&source.variable)
                        })
                        .map(|t: &crate::type_inference::Type| t.display_name())
                        .unwrap_or_else(|| "unknown".to_string());

                    output.push_str(&format!(
                        "- Line {}: `{}` ({}) - type: `{}`\n",
                        source.line,
                        source.variable,
                        source.kind.display_name(),
                        type_info
                    ));
                }
            }
            output.push('\n');

            output.push_str("## Taint Flows\n\n");
            if taint_result.flows.is_empty() {
                output.push_str("*No complete taint flows detected*\n");
            } else {
                for flow in &taint_result.flows {
                    if !flow.is_sanitized {
                        output.push_str(&format!(
                            "⚠️ {} flow: {} -> {} ({:?})\n",
                            flow.vulnerability
                                .as_ref()
                                .map(|v| v.display_name())
                                .unwrap_or("Unknown"),
                            flow.source.variable,
                            flow.sink.function,
                            flow.severity.unwrap_or(crate::taint::Severity::Medium)
                        ));

                        // Add type info for flow steps
                        for step in &flow.path {
                            let type_info = types
                                .variable_types
                                .get(&step.line)
                                .and_then(|vars: &HashMap<String, crate::type_inference::Type>| {
                                    vars.get(&step.variable)
                                })
                                .map(|t: &crate::type_inference::Type| t.display_name())
                                .unwrap_or_else(|| "unknown".to_string());

                            output.push_str(&format!(
                                "  - Line {}: `{}` - type: `{}`\n",
                                step.line, step.variable, type_info
                            ));
                        }
                    }
                }
            }

            // Add security notes based on types
            output.push_str("\n## Security Notes\n\n");
            let mut has_notes = false;

            for line_types in types.variable_types.values() {
                for (var, ty) in line_types {
                    let ty_ref: &crate::type_inference::Type = ty;
                    let type_name = ty_ref.display_name();
                    if type_name.contains("str") || type_name.contains("String") {
                        // Check if this variable appears in any unsanitized flow
                        for flow in &taint_result.flows {
                            if !flow.is_sanitized && flow.source.variable == *var {
                                output.push_str(&format!(
                                    "⚠️ String variable `{}` may flow to dangerous sink\n",
                                    var
                                ));
                                has_notes = true;
                            }
                        }
                    }
                }
            }

            if !has_notes {
                output.push_str("*No immediate security concerns detected*\n");
            }
        } else {
            output.push_str(&format!(
                "*Line {} is not within a function body*\n",
                source_line
            ));
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
        let repo_path = self.get_repo_path(repo)?;
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
    pub async fn get_import_graph_for_viz(
        &self,
        repo: &str,
    ) -> Result<crate::tool_handlers::graph::ImportGraphData> {
        use std::collections::HashMap;

        let repo_path = self.get_repo_path(repo)?;

        // Build import graph by parsing files directly
        let mut files: HashMap<String, Vec<String>> = HashMap::new();

        // Walk all files in the repo
        for entry in walkdir::WalkDir::new(&repo_path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let path_str = path.to_string_lossy().to_string();
            let relative_path = path
                .strip_prefix(&repo_path)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or(path_str.clone());

            if let Ok(content) = std::fs::read_to_string(path) {
                let imports = parse_imports_from_content(&content, &relative_path);
                let import_paths: Vec<String> =
                    imports.iter().map(|i| i.import_path.clone()).collect();

                if !import_paths.is_empty() {
                    files.insert(relative_path, import_paths);
                }
            }
        }

        // For now, skip complex cycle detection
        let cycles: Vec<Vec<String>> = Vec::new();

        Ok(crate::tool_handlers::graph::ImportGraphData { files, cycles })
    }

    /// Get symbol graph data for visualization
    pub async fn get_symbol_graph_for_viz(
        &self,
        repo: &str,
        symbol_name: &str,
    ) -> Result<crate::tool_handlers::graph::SymbolGraphData> {
        // Find the symbol definition
        let symbols = self
            .symbols
            .get(repo)
            .ok_or_else(|| anyhow!("Repository not indexed: {}", repo))?;

        let target_symbol = symbols
            .iter()
            .find(|s| s.name == symbol_name || s.name.ends_with(&format!("::{}", symbol_name)))
            .ok_or_else(|| anyhow!("Symbol not found: {}", symbol_name))?;

        // Get references
        let refs_output = self.find_references(repo, symbol_name, false).await?;

        // Parse references from markdown output (simplified)
        let mut references = Vec::new();
        for line in refs_output.lines() {
            if line.contains("- `") && line.contains(":`") {
                // Parse format: - `path/file.rs:123`: context
                if let Some(path_part) = line.split('`').nth(1) {
                    if let Some((file, line_str)) = path_part.rsplit_once(':') {
                        if let Ok(line_num) = line_str.parse::<usize>() {
                            references.push(crate::tool_handlers::graph::SymbolReference {
                                file_path: file.to_string(),
                                line: line_num,
                            });
                        }
                    }
                }
            }
        }

        Ok(crate::tool_handlers::graph::SymbolGraphData {
            definition: crate::tool_handlers::graph::SymbolDefinition {
                id: target_symbol.name.clone(),
                kind: format!("{:?}", target_symbol.kind).to_lowercase(),
                file_path: target_symbol.file_path.clone(),
                line: target_symbol.start_line,
            },
            references,
        })
    }

    /// Get control flow graph data for visualization
    pub async fn get_cfg_for_viz(
        &self,
        repo: &str,
        function: &str,
    ) -> Result<crate::tool_handlers::graph::CfgData> {
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        // Find the function in symbols
        let symbols = self
            .symbols
            .get(repo)
            .ok_or_else(|| anyhow!("No symbols for repository: {}", repo))?;

        let func_symbol = symbols
            .iter()
            .find(|s| s.name == function || s.name.ends_with(&format!("::{}", function)))
            .ok_or_else(|| anyhow!("Function not found: {}", function))?;

        let full_path = validate_path(&repo_meta.path, &func_symbol.file_path)?;
        let content = std::fs::read_to_string(&full_path)?;

        // Extract function body for the CFG visualization
        let lines: Vec<&str> = content.lines().collect();
        let start = func_symbol.start_line.saturating_sub(1);
        let end = func_symbol.end_line.min(lines.len());
        let function_code = lines[start..end].join("\n");

        // Create a simplified CFG representation
        // For V1, we'll just show the function as a single block
        let blocks = vec![crate::tool_handlers::graph::CfgBlock {
            id: "block_0".to_string(),
            label: format!("{} (entry)", function),
            block_type: "entry".to_string(),
            start_line: func_symbol.start_line,
            code: function_code,
        }];

        // No edges for single-block simplified CFG
        let edges = Vec::new();

        Ok(crate::tool_handlers::graph::CfgData {
            file_path: func_symbol.file_path.clone(),
            blocks,
            edges,
        })
    }

    /// Get security data for visualization overlay
    /// Only scans the specified file paths (from graph nodes) for efficiency
    pub async fn get_security_for_viz(
        &self,
        repo: &str,
        file_paths: &[String],
    ) -> Result<crate::tool_handlers::graph::SecurityVizData> {
        let repo_path = self.get_repo_path(repo)?;

        // Use cached security rules engine (already has compiled patterns)
        let engine = &self.security_engine;

        // Collect valid file paths first
        let valid_files: Vec<(std::path::PathBuf, String)> = file_paths
            .iter()
            .filter_map(|file_path| {
                let full_path = if std::path::Path::new(file_path).is_absolute() {
                    std::path::PathBuf::from(file_path)
                } else {
                    repo_path.join(file_path)
                };

                if !full_path.is_file() {
                    return None;
                }

                let path_str = full_path.to_string_lossy().to_string();
                if !is_security_scannable(&path_str) {
                    return None;
                }

                Some((full_path, path_str))
            })
            .collect();

        // Scan files in parallel using rayon
        let all_findings: Vec<_> = valid_files
            .par_iter()
            .filter_map(|(full_path, path_str)| {
                std::fs::read_to_string(full_path).ok().map(|content| {
                    let language = detect_language_from_path(path_str);
                    engine.scan(&content, path_str, &language)
                })
            })
            .flatten()
            .collect();

        // Get taint sources and sinks
        let mut taint_sources = Vec::new();
        let mut taint_sinks = Vec::new();

        // Simplified: extract from findings
        for finding in &all_findings {
            if finding.message.to_lowercase().contains("source")
                || finding.message.to_lowercase().contains("input")
            {
                taint_sources.push(format!("{}:{}", finding.file_path, finding.line));
            }
            if finding.message.to_lowercase().contains("sink")
                || finding.message.to_lowercase().contains("dangerous")
            {
                taint_sinks.push(format!("{}:{}", finding.file_path, finding.line));
            }
        }

        // Convert findings to visualization format
        let vulnerabilities: Vec<crate::tool_handlers::graph::VulnInfo> = all_findings
            .iter()
            .map(|f| crate::tool_handlers::graph::VulnInfo {
                file_path: f.file_path.clone(),
                line: f.line,
                severity: format!("{:?}", f.severity).to_lowercase(),
                function: None, // Would need to resolve from symbols
            })
            .collect();

        Ok(crate::tool_handlers::graph::SecurityVizData {
            vulnerabilities,
            taint_sources,
            taint_sinks,
        })
    }
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
                    imported_symbols: vec![],
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
                        imported_symbols: vec![],
                        import_type: crate::incremental::ImportType::CommonJs,
                        line: line_num + 1,
                    });
                }
            }
        }
        // Python imports
        else if let Some(stripped) = trimmed.strip_prefix("from ") {
            let import_path = stripped.split_whitespace().next().unwrap_or("").to_string();
            if !import_path.is_empty() {
                imports.push(crate::incremental::Import {
                    source_file: std::path::PathBuf::from(file_path),
                    import_path,
                    imported_symbols: vec![],
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
                        import_path,
                        imported_symbols: vec![],
                        import_type: crate::incremental::ImportType::Python,
                        line: line_num + 1,
                    });
                }
            }
        }
        // Rust use statements
        else if let Some(stripped) = trimmed.strip_prefix("use ") {
            let import_path = stripped
                .trim_end_matches(';')
                .split("::")
                .take(2)
                .collect::<Vec<_>>()
                .join("::");

            imports.push(crate::incremental::Import {
                source_file: std::path::PathBuf::from(file_path),
                import_path,
                imported_symbols: vec![],
                import_type: crate::incremental::ImportType::Rust,
                line: line_num + 1,
            });
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

/// Format a vulnerability finding for output
fn format_vuln_finding(v: &crate::supply_chain::DependencyVuln) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "### {} @ {}\n\n",
        v.dependency.name, v.dependency.version
    ));
    s.push_str(&format!("**Ecosystem**: {:?}\n", v.dependency.ecosystem));

    if let Some(ref upgrade) = v.upgrade_to {
        s.push_str(&format!("**Upgrade to**: {}\n\n", upgrade));
    }

    s.push_str("**Vulnerabilities**:\n\n");
    for vuln in &v.vulnerabilities {
        s.push_str(&format!("- **{}**: {}\n", vuln.id, vuln.summary));
        if !vuln.aliases.is_empty() {
            s.push_str(&format!("  - Aliases: {}\n", vuln.aliases.join(", ")));
        }
        if let Some(score) = vuln.cvss_score {
            s.push_str(&format!("  - CVSS: {:.1}\n", score));
        }
        if !vuln.fixed_versions.is_empty() {
            s.push_str(&format!(
                "  - Fixed in: {}\n",
                vuln.fixed_versions.join(", ")
            ));
        }
    }
    s.push('\n');
    s
}

/// Format a security finding for output
fn format_finding(f: &crate::security_rules::SecurityFinding) -> String {
    let mut s = String::new();
    s.push_str(&format!("### {} - {}\n\n", f.rule_id, f.rule_name));
    s.push_str(&format!("**File**: {}:{}\n", f.file_path, f.line));
    s.push_str(&format!("**Message**: {}\n", f.message));
    if !f.cwe.is_empty() {
        s.push_str(&format!("**CWE**: {}\n", f.cwe.join(", ")));
    }
    s.push_str(&format!("**Remediation**: {}\n\n", f.remediation));
    if !f.snippet.is_empty() {
        s.push_str("```\n");
        s.push_str(&f.snippet);
        s.push_str("\n```\n\n");
    }
    s
}

/// File extensions supported for security scanning
const SECURITY_SCAN_EXTENSIONS: &[&str] = &[
    ".py", ".js", ".ts", ".tsx", ".go", ".rs", ".c", ".cpp", ".h", ".java", ".rb", ".php",
];

/// Parse severity threshold from string
fn parse_severity_threshold(threshold: Option<&str>) -> crate::taint::Severity {
    use crate::taint::Severity;
    match threshold {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        Some("info") => Severity::Info,
        _ => Severity::Low,
    }
}

/// Check if file extension is supported for security scanning
fn is_security_scannable(path: &str) -> bool {
    SECURITY_SCAN_EXTENSIONS
        .iter()
        .any(|ext| path.ends_with(ext))
}

/// OWASP Top 10 2021 categories
const OWASP_TOP10_CATEGORIES: &[(&str, &str)] = &[
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable Components"),
    ("A07:2021", "Authentication Failures"),
    ("A08:2021", "Software Integrity Failures"),
    ("A09:2021", "Logging Failures"),
    ("A10:2021", "SSRF"),
];

/// CWE Top 25 vulnerability types
const CWE_TOP25_TYPES: &[(&str, &str)] = &[
    ("CWE-787", "Out-of-bounds Write"),
    ("CWE-79", "Cross-site Scripting (XSS)"),
    ("CWE-89", "SQL Injection"),
    ("CWE-416", "Use After Free"),
    ("CWE-78", "OS Command Injection"),
    ("CWE-20", "Improper Input Validation"),
    ("CWE-125", "Out-of-bounds Read"),
    ("CWE-22", "Path Traversal"),
    ("CWE-352", "Cross-Site Request Forgery"),
    ("CWE-434", "Unrestricted File Upload"),
    ("CWE-862", "Missing Authorization"),
    ("CWE-476", "NULL Pointer Dereference"),
    ("CWE-287", "Improper Authentication"),
    ("CWE-190", "Integer Overflow"),
    ("CWE-502", "Insecure Deserialization"),
    ("CWE-798", "Hardcoded Credentials"),
    ("CWE-918", "Server-Side Request Forgery"),
];

/// Format findings grouped by category (OWASP or CWE)
fn format_findings_by_category<'a, F>(
    findings: &'a [crate::security_rules::SecurityFinding],
    categories: &[(&str, &str)],
    get_cats: F,
) -> String
where
    F: Fn(&'a crate::security_rules::SecurityFinding) -> &'a Vec<String>,
{
    use std::collections::HashMap;

    let mut by_category: HashMap<String, Vec<_>> = HashMap::new();
    for f in findings {
        for cat in get_cats(f) {
            by_category.entry(cat.clone()).or_default().push(f);
        }
    }

    let mut output = String::new();
    for (cat_id, cat_name) in categories {
        if let Some(cat_findings) = by_category.get(*cat_id) {
            output.push_str(&format!(
                "## {} - {} ({})\n\n",
                cat_id,
                cat_name,
                cat_findings.len()
            ));
            for f in cat_findings {
                output.push_str(&format_finding(f));
            }
        }
    }
    output
}

/// Format findings grouped by severity level
fn format_findings_by_severity(findings: &[crate::security_rules::SecurityFinding]) -> String {
    use crate::taint::Severity;

    let mut output = String::new();

    let severity_groups = [
        (Severity::Critical, "🔴 Critical"),
        (Severity::High, "🟠 High"),
        (Severity::Medium, "🟡 Medium"),
        (Severity::Low, "🔵 Low"),
    ];

    for (severity, label) in severity_groups {
        let group: Vec<_> = findings.iter().filter(|f| f.severity == severity).collect();
        if !group.is_empty() {
            output.push_str(&format!("## {} ({})\n\n", label, group.len()));
            for f in group {
                output.push_str(&format_finding(f));
            }
        }
    }

    output
}

/// Detect language from file path
fn detect_language_from_path(path: &str) -> String {
    if path.ends_with(".py") {
        "python".to_string()
    } else if path.ends_with(".js") {
        "javascript".to_string()
    } else if path.ends_with(".ts") || path.ends_with(".tsx") {
        "typescript".to_string()
    } else if path.ends_with(".rs") {
        "rust".to_string()
    } else if path.ends_with(".go") {
        "go".to_string()
    } else if path.ends_with(".c") || path.ends_with(".h") {
        "c".to_string()
    } else if path.ends_with(".cpp")
        || path.ends_with(".cc")
        || path.ends_with(".cxx")
        || path.ends_with(".hpp")
    {
        "cpp".to_string()
    } else if path.ends_with(".java") {
        "java".to_string()
    } else if path.ends_with(".rb") {
        "ruby".to_string()
    } else if path.ends_with(".php") {
        "php".to_string()
    } else if path.ends_with(".cs") {
        "csharp".to_string()
    } else if path.ends_with(".swift") {
        "swift".to_string()
    } else if path.ends_with(".v")
        || path.ends_with(".vh")
        || path.ends_with(".sv")
        || path.ends_with(".svh")
    {
        "verilog".to_string()
    } else {
        "unknown".to_string()
    }
}

// Helper functions

fn expand_path(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("~") {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Cannot find home directory"))?;
        Ok(home.join(path_str.strip_prefix("~/").unwrap_or(stripped)))
    } else {
        Ok(path.to_path_buf())
    }
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

fn get_language_from_path(path: &str) -> String {
    match path.rsplit('.').next() {
        Some("rs") => "rust",
        Some("py") => "python",
        Some("js") | Some("jsx") => "javascript",
        Some("ts") | Some("tsx") => "typescript",
        Some("go") => "go",
        Some("java") => "java",
        Some("c") | Some("h") => "c",
        Some("cpp") | Some("hpp") | Some("cc") | Some("cxx") => "cpp",
        Some("cs") => "csharp",
        _ => "unknown",
    }
    .to_string()
}
