#![recursion_limit = "256"]
// Allow dead code - this binary is an MCP server that exposes only a subset of the library's features.
// Many library features (custom rulesets, direct analysis APIs, etc.) are intentionally available
// for integration use but not wired through MCP tools.
#![allow(dead_code)]

mod cache;
mod callgraph;
#[cfg(feature = "graph")]
mod ccg;
mod cfg;
mod chunking;
mod config;
mod dead_code;
mod dfg;
mod embeddings;
mod extract;
mod git;
mod http_server;
mod hybrid_search;
mod incremental;
mod index;
mod lsp;
mod mcp;
mod metrics;
mod neural;
mod parser;
mod persist;
#[cfg(feature = "graph")]
mod persistence;
mod remote;
mod repo;
mod search;
mod security_config;
mod security_rules;
mod streaming;
mod supply_chain;
mod symbols;
mod taint;
mod tool_handlers;
mod tool_metadata;
mod type_inference;

use anyhow::Result;
use clap::{Parser as ClapParser, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(ClapParser, Debug)]
#[command(name = "narsil-mcp")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Blazingly fast MCP server for code intelligence")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Configuration management commands
    #[command(subcommand)]
    Config(config::ConfigCommand),

    /// Tool listing and information commands
    #[command(subcommand)]
    Tools(config::ToolsCommand),
}

#[derive(ClapParser, Debug)]
struct ServerArgs {
    /// Paths to repositories or directories to index
    #[arg(short, long)]
    repos: Vec<PathBuf>,

    /// Path to persistent index storage
    #[arg(short, long, default_value = "~/.cache/narsil-mcp")]
    index_path: PathBuf,

    /// Enable verbose logging (to stderr)
    #[arg(short, long)]
    verbose: bool,

    /// Re-index all repositories on startup
    #[arg(long)]
    reindex: bool,

    /// Enable watch mode for incremental updates
    #[arg(short, long)]
    watch: bool,

    /// Enable call graph analysis (slower initial index)
    #[arg(long)]
    call_graph: bool,

    /// Enable git integration
    #[arg(long)]
    git: bool,

    /// Auto-discover repositories in a directory
    #[arg(long)]
    discover: Option<PathBuf>,

    /// Enable index persistence (save/load index to/from disk)
    #[arg(short, long)]
    persist: bool,

    /// Enable LSP integration for enhanced code intelligence (requires language servers installed)
    #[arg(long)]
    lsp: bool,

    /// Enable streaming responses for large result sets
    #[arg(long)]
    streaming: bool,

    /// Enable remote GitHub repository support (uses GITHUB_TOKEN env var for auth)
    #[arg(long)]
    remote: bool,

    /// Enable neural embeddings for semantic search (requires EMBEDDING_API_KEY, VOYAGE_API_KEY, or OPENAI_API_KEY)
    #[arg(long)]
    neural: bool,

    /// Neural embedding backend: "api" (default) or "onnx"
    #[arg(long, default_value = "api")]
    neural_backend: String,

    /// Neural embedding model name (e.g., "voyage-code-2", "text-embedding-3-small")
    #[arg(long)]
    neural_model: Option<String>,

    /// Neural embedding dimension (auto-detected from model if not specified)
    #[arg(long)]
    neural_dimension: Option<usize>,

    /// Enable HTTP server for visualization frontend
    #[arg(long)]
    http: bool,

    /// HTTP server port (default: 3000)
    #[arg(long, default_value = "3000")]
    http_port: u16,

    /// Tool preset (minimal, balanced, full, security-focused)
    /// Overrides the preset from config file
    #[arg(long)]
    preset: Option<String>,

    /// Disable analysis caching (caching is enabled by default)
    #[arg(long)]
    no_cache: bool,

    /// Cache TTL in seconds (default: 1800 = 30 minutes)
    #[arg(long, default_value = "1800")]
    cache_ttl: u64,

    /// Enable RDF knowledge graph storage for SPARQL queries and CCG export.
    /// NOTE: Binary must be built with --features graph for this to work.
    /// If unsure, check the startup log for warnings.
    #[arg(long)]
    graph: bool,

    /// Path for knowledge graph storage (default: <index_path>/graph).
    /// Only used when --graph is enabled and the graph feature is compiled in.
    #[arg(long)]
    graph_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle subcommands (config, tools)
    if let Some(command) = args.command {
        // For subcommands, we don't need logging to stderr
        return match command {
            Commands::Config(config_cmd) => config::handle_config_command(config_cmd).await,
            Commands::Tools(tools_cmd) => config::handle_tools_command(tools_cmd),
        };
    }

    // Default: run MCP server
    let server_args = args.server;

    // Initialize logging to stderr (stdout is for MCP protocol)
    let level = if server_args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting narsil-mcp v{}", env!("CARGO_PKG_VERSION"));

    // Handle repository discovery if requested
    let mut repos = server_args.repos;
    if let Some(discover_path) = server_args.discover {
        info!("Discovering repositories in: {:?}", discover_path);
        let discovered = repo::discover_repos(&discover_path, 3)?;
        info!("Found {} repositories", discovered.len());
        repos.extend(discovered);
    }

    // Expand "." to current directory
    if let Ok(cwd) = std::env::current_dir() {
        let dot_path = Path::new(".");

        if let Some(path) = repos.iter_mut().find(|p| *p == dot_path) {
            *path = cwd;
        }
    }

    info!("Repos to index: {:?}", repos);

    // Check if --graph flag is used but feature isn't compiled
    #[cfg(not(feature = "graph"))]
    if server_args.graph {
        warn!(
            "--graph flag was passed but the binary was built without the 'graph' feature. \
             SPARQL and CCG tools will not be available. \
             Rebuild with: cargo build --release --features graph"
        );
    }

    // Determine actual graph availability
    #[cfg(feature = "graph")]
    let graph_available = server_args.graph;
    #[cfg(not(feature = "graph"))]
    let graph_available = false;

    info!(
        "Features: call_graph={}, git={}, watch={}, persist={}, lsp={}, streaming={}, remote={}, neural={}, cache={}, graph={}",
        server_args.call_graph, server_args.git, server_args.watch, server_args.persist, server_args.lsp, server_args.streaming, server_args.remote, server_args.neural, !server_args.no_cache, graph_available
    );

    // Build LSP config
    let mut lsp_config = lsp::LspConfig::default();
    if server_args.lsp {
        lsp_config.enabled = true;
        // Enable LSP for common languages
        for lang in [
            "rust",
            "python",
            "typescript",
            "javascript",
            "go",
            "c",
            "cpp",
            "java",
        ] {
            lsp_config.enabled_languages.insert(lang.to_string(), true);
        }
        info!(
            "LSP integration enabled for: {:?}",
            lsp_config.enabled_languages.keys().collect::<Vec<_>>()
        );
    }

    // Build streaming config
    let streaming_config = streaming::StreamingConfig {
        enabled: server_args.streaming,
        ..Default::default()
    };
    if server_args.streaming {
        info!(
            "Streaming responses enabled (threshold: {} items)",
            streaming_config.auto_stream_threshold
        );
    }

    // Build neural config
    let neural_dimension = server_args.neural_dimension.unwrap_or_else(|| {
        neural::default_dimension_for_model(server_args.neural_model.as_deref())
    });
    let neural_config = neural::NeuralConfig {
        enabled: server_args.neural,
        backend: server_args.neural_backend.clone(),
        model_name: server_args.neural_model.clone(),
        dimension: neural_dimension,
        ..Default::default()
    };
    if server_args.neural {
        info!(
            "Neural embeddings requested (backend={}, model={:?}, dimension={})",
            server_args.neural_backend, server_args.neural_model, neural_dimension
        );
    }

    // Initialize the code intelligence engine with options
    let options = index::EngineOptions {
        git_enabled: server_args.git,
        call_graph_enabled: server_args.call_graph,
        persist_enabled: server_args.persist,
        watch_enabled: server_args.watch,
        streaming_config,
        lsp_config,
        neural_config,
        cache_enabled: !server_args.no_cache,
        cache_ttl_seconds: server_args.cache_ttl,
        #[cfg(feature = "graph")]
        graph_enabled: server_args.graph,
        #[cfg(feature = "graph")]
        graph_path: server_args.graph_path,
    };

    // NOTE: Engine creation is now fast and returns immediately.
    // Indexing happens in background to allow quick MCP server startup.
    let mut engine =
        index::CodeIntelEngine::with_options(server_args.index_path, repos, options).await?;

    // Initialize remote repository support if enabled
    if server_args.remote {
        match engine.init_remote_manager() {
            Ok(()) => info!("Remote repository support enabled"),
            Err(e) => warn!("Failed to initialize remote repository support: {}", e),
        }
    }

    let engine = Arc::new(engine);

    // Start background initialization task (indexing repos, git init)
    let init_engine = Arc::clone(&engine);
    let reindex_flag = server_args.reindex;
    tokio::spawn(async move {
        if reindex_flag {
            info!("Re-indexing all repositories...");
            if let Err(e) = init_engine.reindex_all().await {
                warn!("Error during re-indexing: {}", e);
            }
        } else {
            // Complete deferred initialization
            if let Err(e) = init_engine.complete_initialization().await {
                warn!("Error during background initialization: {}", e);
            }
        }
    });

    // Start watch mode in background if enabled
    if server_args.watch {
        let watch_engine = Arc::clone(&engine);

        // Create a shutdown signal channel for graceful shutdown
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        tokio::spawn(async move {
            run_watch_mode(watch_engine, shutdown_rx).await;
        });

        // Store shutdown sender for potential cleanup (not used currently but available for future)
        drop(shutdown_tx);
    }

    // Start HTTP server in background if enabled (for visualization frontend)
    // The MCP server still runs on stdio for editor communication
    if server_args.http {
        info!("Starting HTTP server on port {}", server_args.http_port);
        let http_engine = Arc::clone(&engine);
        let http_port = server_args.http_port;
        tokio::spawn(async move {
            let http_server = http_server::HttpServer::new(http_engine, http_port);
            if let Err(e) = http_server.run().await {
                warn!("HTTP server error: {}", e);
            }
        });
    }

    // Always start the MCP server on stdio (for editor communication)
    let server = mcp::McpServer::from_arc(engine, server_args.preset);
    server.run().await?;

    Ok(())
}

/// Run the file watcher in background using async event-driven approach
async fn run_watch_mode(
    engine: Arc<index::CodeIntelEngine>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    info!("Starting async watch mode background task");

    let (_watcher, mut rx) = match engine.create_async_file_watcher() {
        Some((w, r)) => (w, r),
        None => {
            warn!("Failed to create async file watcher, watch mode disabled");
            return;
        }
    };

    loop {
        tokio::select! {
            // Receive batched file change events
            Some(changes) = rx.recv() => {
                if !changes.is_empty() {
                    info!("Detected {} file change(s)", changes.len());
                    match engine.process_file_changes(&changes).await {
                        Ok(count) => {
                            if count > 0 {
                                info!("Re-indexed {} file(s)", count);
                            }
                        }
                        Err(e) => {
                            warn!("Error processing file changes: {}", e);
                        }
                    }
                }
            }
            // Handle shutdown signal
            _ = shutdown.recv() => {
                info!("Watch mode shutting down");
                break;
            }
        }
    }
}
