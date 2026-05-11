#![recursion_limit = "256"]

use anyhow::{bail, Context, Result};
use clap::{Parser as ClapParser, Subcommand};
use narsil_mcp::{config, http_server, index, lsp, mcp, neural, persist, repo, streaming};
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
    /// Paths to repositories or directories to index.
    /// Comma-separated when set via `NARSIL_REPOS`
    /// (e.g. `NARSIL_REPOS=/path/a,/path/b`).
    #[arg(short, long, env = "NARSIL_REPOS", value_delimiter = ',')]
    repos: Vec<PathBuf>,

    /// Named repository profile from config.yaml / .narsil.yaml
    #[arg(long, env = "NARSIL_PROFILE")]
    profile: Option<String>,

    /// Path to persistent index storage
    #[arg(
        short,
        long,
        env = "NARSIL_INDEX_PATH",
        default_value = "~/.cache/narsil-mcp"
    )]
    index_path: PathBuf,

    /// Enable verbose logging (to stderr)
    #[arg(short, long, env = "NARSIL_VERBOSE")]
    verbose: bool,

    /// Re-index all repositories on startup
    #[arg(long, env = "NARSIL_REINDEX")]
    reindex: bool,

    /// Enable watch mode for incremental updates
    #[arg(short, long, env = "NARSIL_WATCH")]
    watch: bool,

    /// Enable call graph analysis (slower initial index)
    #[arg(long, env = "NARSIL_CALL_GRAPH")]
    call_graph: bool,

    /// Enable git integration
    #[arg(long, env = "NARSIL_GIT")]
    git: bool,

    /// Auto-discover repositories in a directory
    #[arg(long, env = "NARSIL_DISCOVER")]
    discover: Option<PathBuf>,

    /// Enable index persistence (save/load index to/from disk)
    #[arg(short, long, env = "NARSIL_PERSIST")]
    persist: bool,

    /// Enable LSP integration for enhanced code intelligence (requires language servers installed)
    #[arg(long, env = "NARSIL_LSP")]
    lsp: bool,

    /// Enable streaming responses for large result sets
    #[arg(long, env = "NARSIL_STREAMING")]
    streaming: bool,

    /// Enable remote GitHub repository support (uses GITHUB_TOKEN env var for auth)
    #[arg(long, env = "NARSIL_REMOTE")]
    remote: bool,

    /// Enable neural embeddings for semantic search (requires EMBEDDING_API_KEY, VOYAGE_API_KEY, or OPENAI_API_KEY)
    #[arg(long, env = "NARSIL_NEURAL")]
    neural: bool,

    /// Neural embedding backend: "api" (default) or "onnx"
    #[arg(long, env = "NARSIL_NEURAL_BACKEND", default_value = "api")]
    neural_backend: String,

    /// Neural embedding model name (e.g., "voyage-code-2", "text-embedding-3-small")
    #[arg(long, env = "NARSIL_NEURAL_MODEL")]
    neural_model: Option<String>,

    /// Neural embedding dimension (auto-detected from model if not specified)
    #[arg(long, env = "NARSIL_NEURAL_DIMENSION")]
    neural_dimension: Option<usize>,

    /// Enable HTTP server for visualization frontend
    #[arg(long, env = "NARSIL_HTTP")]
    http: bool,

    /// HTTP server port (default: 3000)
    #[arg(long, env = "NARSIL_HTTP_PORT", default_value = "3000")]
    http_port: u16,

    /// Tool preset (minimal, balanced, full, security-focused)
    /// Overrides the preset from config file
    #[arg(long, env = "NARSIL_PRESET")]
    preset: Option<String>,

    /// Disable analysis caching (caching is enabled by default)
    #[arg(long, env = "NARSIL_NO_CACHE")]
    no_cache: bool,

    /// Cache TTL in seconds (default: 1800 = 30 minutes)
    #[arg(long, env = "NARSIL_CACHE_TTL", default_value = "1800")]
    cache_ttl: u64,

    /// Enable RDF knowledge graph storage for SPARQL queries and CCG export.
    /// NOTE: Binary must be built with --features graph for this to work.
    /// If unsure, check the startup log for warnings.
    #[arg(long, env = "NARSIL_GRAPH")]
    graph: bool,

    /// Path for knowledge graph storage (default: <index_path>/graph).
    /// Only used when --graph is enabled and the graph feature is compiled in.
    #[arg(long, env = "NARSIL_GRAPH_PATH")]
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
    let mut server_args = args.server;

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

    apply_named_profile(&mut server_args)?;

    // Resolve the final list of repository paths from CLI args, env, and
    // discovery. Auto-falls back to cwd when nothing is specified.
    let repos = resolve_repo_paths(server_args.repos.clone(), server_args.discover.clone())?;

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
        remote_enabled: server_args.remote,
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

    // Start watch mode in background if enabled.
    //
    // The returned `Sender` MUST live until `main` returns — dropping it
    // immediately makes the watcher loop see `Closed` on its first poll and
    // exit milliseconds after spawn (issue #26). Binding the value to
    // `_watch_shutdown_tx` here keeps it alive for the rest of `main`; the
    // tokio runtime tears the detached task down when `main` returns.
    let _watch_shutdown_tx = if server_args.watch {
        Some(persist::spawn_watch_mode(Arc::clone(&engine)))
    } else {
        None
    };

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

/// Apply a named repository profile from the loaded configuration.
///
/// Explicit CLI/env values remain authoritative. Profiles provide defaults for
/// repos, discovery, preset, and feature booleans.
fn apply_named_profile(server_args: &mut ServerArgs) -> Result<()> {
    let Some(profile_name) = server_args.profile.as_deref() else {
        return Ok(());
    };

    let config = config::ConfigLoader::new()
        .load()
        .context("Failed to load configuration for --profile")?;
    let profile = config.profiles.get(profile_name).ok_or_else(|| {
        let mut names: Vec<_> = config.profiles.keys().cloned().collect();
        names.sort();
        anyhow::anyhow!(
            "Unknown profile '{}'. Available profiles: {}",
            profile_name,
            if names.is_empty() {
                "<none>".to_string()
            } else {
                names.join(", ")
            }
        )
    })?;

    if server_args.repos.is_empty() {
        server_args.repos = profile.repos.clone();
    }
    if server_args.discover.is_none() {
        server_args.discover = profile.discover.clone();
    }
    if server_args.preset.is_none() {
        server_args.preset = profile.preset.clone();
    }

    apply_bool_default(&mut server_args.git, profile.git);
    apply_bool_default(&mut server_args.call_graph, profile.call_graph);
    apply_bool_default(&mut server_args.persist, profile.persist);
    apply_bool_default(&mut server_args.watch, profile.watch);
    apply_bool_default(&mut server_args.lsp, profile.lsp);
    apply_bool_default(&mut server_args.remote, profile.remote);
    apply_bool_default(&mut server_args.neural, profile.neural);
    apply_bool_default(&mut server_args.graph, profile.graph);

    info!("Applied repository profile '{}'", profile_name);
    Ok(())
}

fn apply_bool_default(target: &mut bool, profile_value: Option<bool>) {
    if !*target {
        if let Some(value) = profile_value {
            *target = value;
        }
    }
}

/// Resolve the final set of repository paths to index from CLI input.
///
/// Order of operations:
/// 1. Start with `cli_repos` (populated from `--repos` or `NARSIL_REPOS`).
/// 2. If `discover` is set, walk that directory and append discovered repos.
/// 3. Expand `~`, relative paths, and symlinks into canonical absolute paths.
/// 4. If the list is still empty, default to `[cwd]` so a bare invocation
///    indexes the project the user is sitting in (issue #22).
/// 5. Drop paths that do not exist on disk, logging each at WARN. If all
///    explicit paths were invalid, return a clear error.
fn resolve_repo_paths(cli_repos: Vec<PathBuf>, discover: Option<PathBuf>) -> Result<Vec<PathBuf>> {
    let mut repos = cli_repos;
    let had_explicit_input = !repos.is_empty() || discover.is_some();

    if let Some(discover_path) = discover {
        let discover_path = normalize_existing_path(&discover_path)
            .with_context(|| format!("Invalid --discover path: {}", discover_path.display()))?;
        info!("Discovering repositories in: {:?}", discover_path);
        let discovered = repo::discover_repos(&discover_path, 3)?;
        info!("Found {} repositories via discovery", discovered.len());
        repos.extend(discovered);
    }

    // Fall back to the current working directory when no repos are specified
    // anywhere — bare `narsil-mcp` should "just work" inside a project.
    if repos.is_empty() {
        let cwd = std::env::current_dir().context(
            "--repos was not specified and the current working directory is unavailable",
        )?;
        info!(
            "No --repos / NARSIL_REPOS / --discover specified; defaulting to cwd: {:?}",
            cwd
        );
        repos.push(cwd);
    }

    let mut validated = Vec::new();
    for path in repos {
        match normalize_existing_path(&path) {
            Ok(path) => {
                if !validated.contains(&path) {
                    validated.push(path);
                }
            }
            Err(_) => warn!("Repository path does not exist, skipping: {:?}", path),
        }
    }

    if validated.is_empty() {
        if had_explicit_input {
            bail!("No valid repository paths remain after validation");
        }
        bail!("Current working directory could not be resolved as a repository path");
    }

    Ok(validated)
}

fn normalize_existing_path(path: &Path) -> Result<PathBuf> {
    let expanded = expand_tilde(path)?;
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir()?.join(expanded)
    };

    absolute
        .canonicalize()
        .with_context(|| format!("Path does not exist: {}", path.display()))
}

fn expand_tilde(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    let Some(stripped) = path_str.strip_prefix('~') else {
        return Ok(path.to_path_buf());
    };

    let home = directories::BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .context("Cannot expand '~': home directory not found")?;
    if stripped.is_empty() {
        Ok(home)
    } else if let Some(rest) = stripped.strip_prefix('/') {
        Ok(home.join(rest))
    } else {
        Ok(path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests that mutate `NARSIL_*` env vars share process-wide state and
    /// must run sequentially. Without this lock, parallel test execution
    /// races between `set_var` and `Args::try_parse_from`.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn parse_with_env<F: FnOnce()>(setup: F) -> Args {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Ensure no NARSIL_* leak in from outside the test:
        for var in [
            "NARSIL_REPOS",
            "NARSIL_PROFILE",
            "NARSIL_CONFIG_PATH",
            "NARSIL_INDEX_PATH",
            "NARSIL_VERBOSE",
            "NARSIL_REINDEX",
            "NARSIL_WATCH",
            "NARSIL_CALL_GRAPH",
            "NARSIL_GIT",
            "NARSIL_DISCOVER",
            "NARSIL_PERSIST",
            "NARSIL_LSP",
            "NARSIL_STREAMING",
            "NARSIL_REMOTE",
            "NARSIL_NEURAL",
            "NARSIL_NEURAL_BACKEND",
            "NARSIL_NEURAL_MODEL",
            "NARSIL_NEURAL_DIMENSION",
            "NARSIL_HTTP",
            "NARSIL_HTTP_PORT",
            "NARSIL_PRESET",
            "NARSIL_NO_CACHE",
            "NARSIL_CACHE_TTL",
            "NARSIL_GRAPH",
            "NARSIL_GRAPH_PATH",
        ] {
            std::env::remove_var(var);
        }
        setup();
        Args::try_parse_from(["narsil-mcp"]).expect("CLI parse should succeed")
    }

    #[test]
    fn neural_model_is_settable_via_env() {
        let args = parse_with_env(|| {
            std::env::set_var("NARSIL_NEURAL_MODEL", "voyage-code-2");
        });
        std::env::remove_var("NARSIL_NEURAL_MODEL");
        assert_eq!(args.server.neural_model.as_deref(), Some("voyage-code-2"));
    }

    #[test]
    fn neural_dimension_is_settable_via_env() {
        let args = parse_with_env(|| {
            std::env::set_var("NARSIL_NEURAL_DIMENSION", "1024");
        });
        std::env::remove_var("NARSIL_NEURAL_DIMENSION");
        assert_eq!(args.server.neural_dimension, Some(1024));
    }

    #[test]
    fn boolean_flags_are_settable_via_env() {
        let args = parse_with_env(|| {
            std::env::set_var("NARSIL_GIT", "true");
            std::env::set_var("NARSIL_CALL_GRAPH", "true");
            std::env::set_var("NARSIL_REMOTE", "true");
            std::env::set_var("NARSIL_NEURAL", "true");
        });
        for var in [
            "NARSIL_GIT",
            "NARSIL_CALL_GRAPH",
            "NARSIL_REMOTE",
            "NARSIL_NEURAL",
        ] {
            std::env::remove_var(var);
        }
        assert!(args.server.git);
        assert!(args.server.call_graph);
        assert!(args.server.remote);
        assert!(args.server.neural);
    }

    #[test]
    fn repos_are_settable_via_env_comma_separated() {
        let args = parse_with_env(|| {
            std::env::set_var("NARSIL_REPOS", "/tmp/a,/tmp/b,/tmp/c");
        });
        std::env::remove_var("NARSIL_REPOS");
        assert_eq!(
            args.server.repos,
            vec![
                PathBuf::from("/tmp/a"),
                PathBuf::from("/tmp/b"),
                PathBuf::from("/tmp/c"),
            ]
        );
    }

    #[test]
    fn http_port_is_settable_via_env() {
        let args = parse_with_env(|| {
            std::env::set_var("NARSIL_HTTP_PORT", "4444");
        });
        std::env::remove_var("NARSIL_HTTP_PORT");
        assert_eq!(args.server.http_port, 4444);
    }

    #[test]
    fn profile_and_reindex_are_settable_via_env() {
        let args = parse_with_env(|| {
            std::env::set_var("NARSIL_PROFILE", "work");
            std::env::set_var("NARSIL_REINDEX", "true");
        });
        std::env::remove_var("NARSIL_PROFILE");
        std::env::remove_var("NARSIL_REINDEX");
        assert_eq!(args.server.profile.as_deref(), Some("work"));
        assert!(args.server.reindex);
    }

    #[test]
    fn cli_args_override_env_vars() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NARSIL_NEURAL_MODEL", "from-env");
        let args = Args::try_parse_from(["narsil-mcp", "--neural-model", "from-cli"]).unwrap();
        std::env::remove_var("NARSIL_NEURAL_MODEL");
        assert_eq!(args.server.neural_model.as_deref(), Some("from-cli"));
    }

    #[test]
    fn resolve_repo_paths_falls_back_to_cwd_when_empty() {
        let resolved = resolve_repo_paths(vec![], None).unwrap();
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(resolved, vec![cwd]);
    }

    #[test]
    fn resolve_repo_paths_filters_missing_paths() {
        let cwd = std::env::current_dir().unwrap();
        let nonexistent = PathBuf::from("/this/path/definitely/does/not/exist/narsil-test-zzz");
        assert!(!nonexistent.exists());

        let resolved = resolve_repo_paths(vec![cwd.clone(), nonexistent], None).unwrap();
        // The missing path is dropped; the existing one survives.
        assert_eq!(resolved, vec![cwd]);
    }

    #[test]
    fn resolve_repo_paths_errors_when_all_explicit_paths_are_missing() {
        let nonexistent = PathBuf::from("/this/path/definitely/does/not/exist/narsil-test-zzz");
        let err = resolve_repo_paths(vec![nonexistent], None).unwrap_err();
        assert!(err.to_string().contains("No valid repository paths"));
    }

    #[test]
    fn resolve_repo_paths_expands_dot_to_cwd() {
        let resolved = resolve_repo_paths(vec![PathBuf::from(".")], None).unwrap();
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(resolved, vec![cwd]);
    }

    #[test]
    fn resolve_repo_paths_keeps_explicit_paths() {
        let cwd = std::env::current_dir().unwrap();
        let resolved = resolve_repo_paths(vec![cwd.clone()], None).unwrap();
        assert_eq!(resolved, vec![cwd]);
    }

    #[test]
    fn named_profile_supplies_repos_and_flags() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            format!(
                r#"version: "1.0"
profiles:
  work:
    repos:
      - {}
    git: true
    call_graph: true
    preset: balanced
"#,
                repo.display()
            ),
        )
        .unwrap();

        std::env::set_var("NARSIL_CONFIG_PATH", &config_path);
        let mut args = Args::try_parse_from(["narsil-mcp", "--profile", "work"]).unwrap();
        apply_named_profile(&mut args.server).unwrap();
        std::env::remove_var("NARSIL_CONFIG_PATH");

        assert_eq!(args.server.repos, vec![repo]);
        assert!(args.server.git);
        assert!(args.server.call_graph);
        assert_eq!(args.server.preset.as_deref(), Some("balanced"));
    }
}
