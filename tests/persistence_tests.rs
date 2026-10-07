use anyhow::Result;
use narsil_mcp::lsp::LspConfig;
use narsil_mcp::neural::NeuralConfig;
use narsil_mcp::streaming::StreamingConfig;
use std::path::Path;
use tempfile::TempDir;

/// Test helper to create a temporary test repository
struct TestRepo {
    dir: TempDir,
}

impl TestRepo {
    fn new() -> Result<Self> {
        let dir = TempDir::new()?;
        Ok(Self { dir })
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn add_rust_file(&self, name: &str, content: &str) -> Result<()> {
        let path = self.dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[tokio::test]
async fn test_persistence_index_creation() -> Result<()> {
    use narsil_mcp::index::{CodeIntelEngine, EngineOptions};

    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub struct TestStruct {
            pub field: String,
        }

        pub fn test_function() {
            println!("test");
        }
    "#,
    )?;

    let index_dir = TempDir::new()?;

    // Create engine with persistence enabled
    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: false,
        persist_enabled: true,
        watch_enabled: false,
        streaming_config: StreamingConfig::default(),
        lsp_config: LspConfig::default(),
        neural_config: NeuralConfig::default(),
        ..Default::default()
    };

    let engine = CodeIntelEngine::with_options(
        index_dir.path().to_path_buf(),
        vec![repo.path().to_path_buf()],
        options,
    )
    .await?;

    // Verify the repository was indexed
    let repos_list = engine.list_repos().await?;
    assert!(repos_list.contains("Indexed Repositories"));

    Ok(())
}

#[tokio::test]
async fn test_persistence_index_loading() -> Result<()> {
    use narsil_mcp::index::{CodeIntelEngine, EngineOptions};
    use std::time::Duration;

    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub struct User {
            pub name: String,
            pub age: u32,
        }

        pub fn create_user(name: String, age: u32) -> User {
            User { name, age }
        }
    "#,
    )?;

    let index_dir = TempDir::new()?;

    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: false,
        persist_enabled: true,
        watch_enabled: false,
        streaming_config: StreamingConfig::default(),
        lsp_config: LspConfig::default(),
        neural_config: NeuralConfig::default(),
        ..Default::default()
    };

    // First indexing - creates the persisted index
    {
        let engine = CodeIntelEngine::with_options(
            index_dir.path().to_path_buf(),
            vec![repo.path().to_path_buf()],
            options.clone(),
        )
        .await?;

        // Complete initialization to index the repository
        engine.complete_initialization().await?;

        let symbols = engine
            .find_symbols(
                repo.path().file_name().unwrap().to_str().unwrap(),
                None,
                None,
                None,
                None,
            )
            .await?;
        assert!(symbols.contains("User"));
        assert!(symbols.contains("create_user"));
    }

    // Small delay to ensure file is written
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second indexing - should load from persisted index
    {
        let engine2 = CodeIntelEngine::with_options(
            index_dir.path().to_path_buf(),
            vec![repo.path().to_path_buf()],
            options,
        )
        .await?;

        // Complete initialization (should load from cache)
        engine2.complete_initialization().await?;

        // Verify symbols are available (loaded from cache)
        let symbols = engine2
            .find_symbols(
                repo.path().file_name().unwrap().to_str().unwrap(),
                None,
                None,
                None,
                None,
            )
            .await?;
        assert!(symbols.contains("User"));
        assert!(symbols.contains("create_user"));
    }

    Ok(())
}

#[tokio::test]
async fn test_persistence_stale_file_detection() -> Result<()> {
    use narsil_mcp::index::{CodeIntelEngine, EngineOptions};
    use std::time::Duration;

    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub struct OriginalStruct {
            pub field: String,
        }
    "#,
    )?;

    let index_dir = TempDir::new()?;

    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: false,
        persist_enabled: true,
        watch_enabled: false,
        streaming_config: StreamingConfig::default(),
        lsp_config: LspConfig::default(),
        neural_config: NeuralConfig::default(),
        ..Default::default()
    };

    // First indexing
    {
        let engine = CodeIntelEngine::with_options(
            index_dir.path().to_path_buf(),
            vec![repo.path().to_path_buf()],
            options.clone(),
        )
        .await?;

        // Complete initialization to index and persist
        engine.complete_initialization().await?;
    }

    // Wait a bit
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Modify the file
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub struct ModifiedStruct {
            pub new_field: i32,
        }
    "#,
    )?;

    // Wait to ensure modification time is different
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second indexing - should detect the file is stale and re-index
    {
        let engine2 = CodeIntelEngine::with_options(
            index_dir.path().to_path_buf(),
            vec![repo.path().to_path_buf()],
            options,
        )
        .await?;

        // Complete initialization (should detect stale file and re-index)
        engine2.complete_initialization().await?;

        // Verify the new struct is present
        let symbols = engine2
            .find_symbols(
                repo.path().file_name().unwrap().to_str().unwrap(),
                None,
                Some("Modified"),
                None,
                None,
            )
            .await?;
        assert!(symbols.contains("ModifiedStruct"));
    }

    Ok(())
}

#[tokio::test]
async fn test_persistence_disabled() -> Result<()> {
    use narsil_mcp::index::{CodeIntelEngine, EngineOptions};

    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub fn test() {}
    "#,
    )?;

    let index_dir = TempDir::new()?;

    // Create engine with persistence DISABLED
    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: false,
        persist_enabled: false, // Disabled
        watch_enabled: false,
        streaming_config: StreamingConfig::default(),
        lsp_config: LspConfig::default(),
        neural_config: NeuralConfig::default(),
        ..Default::default()
    };

    let engine = CodeIntelEngine::with_options(
        index_dir.path().to_path_buf(),
        vec![repo.path().to_path_buf()],
        options,
    )
    .await?;

    // Complete initialization to index the repository
    engine.complete_initialization().await?;

    // Verify it still works, just doesn't persist
    let symbols = engine
        .find_symbols(
            repo.path().file_name().unwrap().to_str().unwrap(),
            None,
            None,
            None,
            None,
        )
        .await?;
    assert!(symbols.contains("test"));

    Ok(())
}

#[tokio::test]
async fn test_empty_persisted_index() -> Result<()> {
    use narsil_mcp::index::{CodeIntelEngine, EngineOptions};

    let repo = TestRepo::new()?;
    // Don't add any files initially

    let index_dir = TempDir::new()?;

    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: false,
        persist_enabled: true,
        watch_enabled: false,
        streaming_config: StreamingConfig::default(),
        lsp_config: LspConfig::default(),
        neural_config: NeuralConfig::default(),
        ..Default::default()
    };

    // First time - empty repo
    {
        let engine = CodeIntelEngine::with_options(
            index_dir.path().to_path_buf(),
            vec![repo.path().to_path_buf()],
            options.clone(),
        )
        .await?;

        // Complete initialization (should create empty index)
        engine.complete_initialization().await?;
    }

    // Add a file
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub fn new_function() {}
    "#,
    )?;

    // Second time - should re-index because persisted index is empty
    {
        let engine2 = CodeIntelEngine::with_options(
            index_dir.path().to_path_buf(),
            vec![repo.path().to_path_buf()],
            options,
        )
        .await?;

        // Complete initialization (should re-index with new file)
        engine2.complete_initialization().await?;

        let symbols = engine2
            .find_symbols(
                repo.path().file_name().unwrap().to_str().unwrap(),
                None,
                None,
                None,
                None,
            )
            .await?;
        assert!(symbols.contains("new_function"));
    }

    Ok(())
}

#[tokio::test]
async fn test_async_watcher_creation() -> Result<()> {
    use narsil_mcp::index::{CodeIntelEngine, EngineOptions};

    let repo = TestRepo::new()?;
    repo.add_rust_file("src/lib.rs", "pub fn test() {}")?;

    let index_dir = TempDir::new()?;

    // Create engine with watch enabled
    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: false,
        persist_enabled: false,
        watch_enabled: true,
        streaming_config: StreamingConfig::default(),
        lsp_config: LspConfig::default(),
        neural_config: NeuralConfig::default(),
        ..Default::default()
    };

    let engine = CodeIntelEngine::with_options(
        index_dir.path().to_path_buf(),
        vec![repo.path().to_path_buf()],
        options,
    )
    .await?;

    // Should be able to create async watcher
    let result = engine.create_async_file_watcher();
    assert!(result.is_some());

    Ok(())
}

#[tokio::test]
async fn test_async_watcher_disabled_when_watch_disabled() -> Result<()> {
    use narsil_mcp::index::{CodeIntelEngine, EngineOptions};

    let repo = TestRepo::new()?;
    repo.add_rust_file("src/lib.rs", "pub fn test() {}")?;

    let index_dir = TempDir::new()?;

    // Create engine with watch DISABLED
    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: false,
        persist_enabled: false,
        watch_enabled: false,
        streaming_config: StreamingConfig::default(),
        lsp_config: LspConfig::default(),
        neural_config: NeuralConfig::default(),
        ..Default::default()
    };

    let engine = CodeIntelEngine::with_options(
        index_dir.path().to_path_buf(),
        vec![repo.path().to_path_buf()],
        options,
    )
    .await?;

    // Should NOT be able to create async watcher
    let result = engine.create_async_file_watcher();
    assert!(result.is_none());

    Ok(())
}

#[tokio::test]
async fn test_async_watcher_file_change_detection() -> Result<()> {
    use narsil_mcp::index::{CodeIntelEngine, EngineOptions};
    use std::time::Duration;

    let repo = TestRepo::new()?;
    repo.add_rust_file("src/lib.rs", "pub fn original() {}")?;
    let source = repo.path().join("src/lib.rs");
    let original_modified = std::fs::metadata(&source)?.modified()?;

    let index_dir = TempDir::new()?;

    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: false,
        persist_enabled: false,
        watch_enabled: true,
        streaming_config: StreamingConfig::default(),
        lsp_config: LspConfig::default(),
        neural_config: NeuralConfig::default(),
        ..Default::default()
    };

    let engine = CodeIntelEngine::with_options(
        index_dir.path().to_path_buf(),
        vec![repo.path().to_path_buf()],
        options,
    )
    .await?;

    // Create async watcher
    let (_watcher, mut rx) = engine.create_async_file_watcher().unwrap();

    // Wait for watcher to initialize (generous for slow CI)
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Modify the file
    repo.add_rust_file("src/lib.rs", "pub fn modified() {}")?;
    // PollWatcher compares whole seconds, so an edit within the same second
    // would not produce the metadata event this test exercises.
    std::fs::File::options()
        .write(true)
        .open(&source)?
        .set_times(
            std::fs::FileTimes::new().set_modified(original_modified + Duration::from_secs(2)),
        )?;

    // Wait for debounce timer and file system events (generous for slow CI)
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Check if we received change events
    let changes = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("Should receive file change event")
        .expect("Watcher event channel should remain open");
    assert!(!changes.is_empty(), "Changes should not be empty");

    Ok(())
}

#[tokio::test]
async fn test_async_watcher_debouncing() -> Result<()> {
    use narsil_mcp::index::{CodeIntelEngine, EngineOptions};
    use std::time::Duration;

    let repo = TestRepo::new()?;
    repo.add_rust_file("src/lib.rs", "pub fn test() {}")?;

    let index_dir = TempDir::new()?;

    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: false,
        persist_enabled: false,
        watch_enabled: true,
        streaming_config: StreamingConfig::default(),
        lsp_config: LspConfig::default(),
        neural_config: NeuralConfig::default(),
        ..Default::default()
    };

    let engine = CodeIntelEngine::with_options(
        index_dir.path().to_path_buf(),
        vec![repo.path().to_path_buf()],
        options,
    )
    .await?;

    let (_watcher, mut rx) = engine.create_async_file_watcher().unwrap();

    // Wait for watcher to initialize (generous for slow CI)
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Make multiple rapid changes to the same file
    for i in 0..5 {
        repo.add_rust_file("src/lib.rs", &format!("pub fn test_v{i}() {{}}"))?;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Wait for debounce window (generous for slow CI)
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Should receive batched changes (possibly just one batch due to debouncing)
    let mut batch_count = 0;
    while let Ok(Some(_changes)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await
    {
        batch_count += 1;
        // Don't wait forever - debouncing should limit the number of batches
        if batch_count > 10 {
            break;
        }
    }

    // Due to debouncing, should receive fewer batches than the number of changes.
    // The exact count depends on OS filesystem event timing, so we just verify
    // that debouncing reduced the count below the total number of writes (5).
    assert!(batch_count > 0, "Should receive at least one batch");
    assert!(
        batch_count < 5,
        "Debouncing should reduce the number of batches, got {batch_count}"
    );

    Ok(())
}

#[tokio::test]
async fn test_async_watcher_filters_non_source_files() -> Result<()> {
    use narsil_mcp::index::{CodeIntelEngine, EngineOptions};
    use std::time::Duration;

    let repo = TestRepo::new()?;
    repo.add_rust_file("src/lib.rs", "pub fn test() {}")?;

    let index_dir = TempDir::new()?;

    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: false,
        persist_enabled: false,
        watch_enabled: true,
        streaming_config: StreamingConfig::default(),
        lsp_config: LspConfig::default(),
        neural_config: NeuralConfig::default(),
        ..Default::default()
    };

    let engine = CodeIntelEngine::with_options(
        index_dir.path().to_path_buf(),
        vec![repo.path().to_path_buf()],
        options,
    )
    .await?;

    let (_watcher, mut rx) = engine.create_async_file_watcher().unwrap();

    // Wait for watcher to initialize (generous for slow CI)
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Add a non-source file (should be filtered out)
    let readme_path = repo.path().join("README.md");
    std::fs::write(&readme_path, "# Test")?;

    // Add a source file (should be detected)
    repo.add_rust_file("src/main.rs", "fn main() {}")?;

    // Wait for debounce (generous for slow CI)
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Should receive changes only for source file
    let timeout = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
    if let Ok(Some(changes)) = timeout {
        // Verify all changes are for source files (not README.md)
        for change in &changes {
            let path_str = change.path.to_string_lossy();
            assert!(
                !path_str.ends_with("README.md"),
                "Should filter out non-source files"
            );
        }
    }

    Ok(())
}

/// Issue #26 regression: when the caller holds the shutdown `Sender`, the
/// watcher must keep running and re-index files that change on disk. The
/// original `main.rs` wiring dropped the `Sender` immediately, which made the
/// internal `select!` loop see `Closed` on the first poll and exit before any
/// file event could arrive — silently disabling `--watch`.
#[tokio::test(flavor = "multi_thread")]
async fn test_spawn_watch_mode_keeps_running_when_sender_alive() -> Result<()> {
    use narsil_mcp::index::{CodeIntelEngine, EngineOptions};
    use narsil_mcp::persist;
    use std::sync::Arc;
    use std::time::Duration;

    let repo = TestRepo::new()?;
    repo.add_rust_file("src/lib.rs", "pub fn original() {}")?;
    let index_dir = TempDir::new()?;

    // Canonicalize so that `/var/folders/...` (TempDir on macOS) and
    // `/private/var/folders/...` (notify's emitted paths) line up — otherwise
    // `process_file_changes` cannot match the change to a registered repo.
    let repo_path = repo.path().canonicalize()?;

    let engine = Arc::new(
        CodeIntelEngine::with_options(
            index_dir.path().to_path_buf(),
            vec![repo_path.clone()],
            EngineOptions {
                watch_enabled: true,
                ..Default::default()
            },
        )
        .await?,
    );

    // Finish initial indexing so the repo is registered and findable.
    engine.complete_initialization().await?;

    // Mirror the production wiring from main.rs: hold the Sender so the
    // watcher keeps running.
    let _shutdown_tx = persist::spawn_watch_mode(Arc::clone(&engine));

    // Allow the watcher to initialise.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Modify a watched file and wait long enough for debounce (300 ms) +
    // event propagation + re-index.
    repo.add_rust_file("src/lib.rs", "pub fn watcher_reindexed_me() {}")?;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // The repo's directory name is what the engine uses as the repo key.
    let repo_name = repo_path.file_name().unwrap().to_string_lossy().to_string();

    // The new symbol must be visible — proves the watcher is alive and
    // processed the file change.
    let result = engine
        .find_symbols(&repo_name, None, Some("watcher_reindexed_me"), None, None)
        .await?;
    assert!(
        result.contains("watcher_reindexed_me"),
        "expected new symbol after watched file change; got:\n{result}"
    );

    Ok(())
}

/// Documents the design contract of `run_watch_mode`: dropping every `Sender`
/// is treated as a shutdown signal (the receiver returns `Err(Closed)`), so
/// the loop exits promptly. Issue #26 was a *caller* bug — the wiring code
/// dropped the Sender accidentally — not a bug in this function.
#[tokio::test(flavor = "multi_thread")]
async fn test_run_watch_mode_exits_when_sender_dropped() -> Result<()> {
    use narsil_mcp::index::{CodeIntelEngine, EngineOptions};
    use narsil_mcp::persist;
    use std::sync::Arc;
    use std::time::Duration;

    let repo = TestRepo::new()?;
    repo.add_rust_file("src/lib.rs", "pub fn test() {}")?;
    let index_dir = TempDir::new()?;

    let engine = Arc::new(
        CodeIntelEngine::with_options(
            index_dir.path().to_path_buf(),
            vec![repo.path().to_path_buf()],
            EngineOptions {
                watch_enabled: true,
                ..Default::default()
            },
        )
        .await?,
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let watch_engine = Arc::clone(&engine);
    let handle = tokio::spawn(async move {
        persist::run_watch_mode(watch_engine, shutdown_rx).await;
    });

    // Drop the only Sender — the function should observe Closed and exit.
    drop(shutdown_tx);

    let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(
        result.is_ok() && result.unwrap().is_ok(),
        "watcher must exit promptly after the only Sender is dropped"
    );

    Ok(())
}
