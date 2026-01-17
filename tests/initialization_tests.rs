/// Integration tests for non-blocking MCP server initialization
///
/// These tests verify that the MCP server can respond to initialization
/// requests even while repository indexing is still in progress.
/// This is critical for editors like Zed that have short timeout windows.
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;

// Re-use the library's test utilities
use narsil_mcp::index::{CodeIntelEngine, EngineOptions};

#[tokio::test]
async fn test_engine_creation_is_fast() {
    // GIVEN: A temporary directory with some code files
    let temp_dir = tempfile::tempdir().unwrap();
    let repo_path = temp_dir.path().to_path_buf();

    // Create a few test files to simulate a small repository
    std::fs::write(repo_path.join("test1.rs"), "fn main() {}").unwrap();
    std::fs::write(repo_path.join("test2.rs"), "fn helper() {}").unwrap();
    std::fs::write(repo_path.join("test3.rs"), "fn another() {}").unwrap();

    let index_path = temp_dir.path().join("index");
    let repos = vec![repo_path];

    // WHEN: We create the engine with default options
    let start = Instant::now();
    let result = timeout(
        Duration::from_millis(1500), // Generous timeout for CI environments
        CodeIntelEngine::with_options(index_path, repos, EngineOptions::default()),
    )
    .await;

    // THEN: The engine is created quickly (non-blocking)
    assert!(result.is_ok(), "Engine creation should not timeout");
    assert!(result.unwrap().is_ok(), "Engine creation should succeed");

    let elapsed = start.elapsed();
    println!("Engine creation took: {:?}", elapsed);
    // Use 3000ms threshold to account for CI environment variability
    // (CI runners like GitHub Actions can be 2-3x slower than local machines)
    // This is still fast enough for editors (Zed timeout is 2-3s, most use 5-10s)
    // The goal is non-blocking initialization, not exact millisecond precision
    assert!(
        elapsed < Duration::from_millis(3000),
        "Engine creation should be fast, took: {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_engine_creation_with_deferred_indexing() {
    // GIVEN: A temporary directory with code files
    let temp_dir = tempfile::tempdir().unwrap();
    let repo_path = temp_dir.path().to_path_buf();

    // Create test files
    std::fs::write(repo_path.join("test.rs"), "fn main() {}").unwrap();

    let index_path = temp_dir.path().join("index");
    let repos = vec![repo_path.clone()];

    // WHEN: We create the engine
    let engine = CodeIntelEngine::with_options(index_path, repos, EngineOptions::default())
        .await
        .unwrap();

    // THEN: The engine should indicate initialization is not yet complete
    assert!(
        !engine.is_fully_initialized(),
        "Engine should not be fully initialized immediately after creation"
    );

    // WHEN: We trigger background indexing
    let engine = Arc::new(engine);
    let engine_clone = Arc::clone(&engine);

    let handle = tokio::spawn(async move { engine_clone.complete_initialization().await });

    // THEN: The engine should eventually become fully initialized
    handle.await.unwrap().unwrap();

    assert!(
        engine.is_fully_initialized(),
        "Engine should be fully initialized after background indexing completes"
    );
}

#[tokio::test]
async fn test_list_repos_works_during_initialization() {
    // GIVEN: An engine that is still initializing
    let temp_dir = tempfile::tempdir().unwrap();
    let repo_path = temp_dir.path().to_path_buf();
    std::fs::write(repo_path.join("test.rs"), "fn main() {}").unwrap();

    let index_path = temp_dir.path().join("index");
    let repos = vec![repo_path.clone()];

    let engine = Arc::new(
        CodeIntelEngine::with_options(index_path, repos, EngineOptions::default())
            .await
            .unwrap(),
    );

    // WHEN: We call list_repos while initialization is in progress
    let repos_result = engine.list_repos().await;

    // THEN: It should return the repository list (even if not fully indexed)
    assert!(
        repos_result.is_ok(),
        "Should successfully return repository list"
    );
    let repos_str = repos_result.unwrap();
    assert!(
        !repos_str.is_empty(),
        "Should return repository list even during initialization"
    );
}

#[tokio::test]
async fn test_initialization_status_tracking() {
    // GIVEN: A new engine
    let temp_dir = tempfile::tempdir().unwrap();
    let index_path = temp_dir.path().join("index");
    let repos = vec![temp_dir.path().to_path_buf()];

    let engine = CodeIntelEngine::with_options(index_path, repos, EngineOptions::default())
        .await
        .unwrap();

    // THEN: We can query initialization status
    let status = engine.get_initialization_status();

    assert!(
        status.contains_key("is_initialized"),
        "Status should include is_initialized flag"
    );
    assert!(
        status.contains_key("indexed_repos"),
        "Status should include indexed repos count"
    );
    assert!(
        status.contains_key("total_repos"),
        "Status should include total repos count"
    );
}

#[tokio::test]
async fn test_mcp_initialize_responds_quickly() {
    // This test verifies that the MCP initialize request can be handled
    // even while background indexing is still in progress

    // GIVEN: A code intelligence engine that's still initializing
    let temp_dir = tempfile::tempdir().unwrap();
    let repo_path = temp_dir.path().to_path_buf();
    std::fs::write(
        repo_path.join("large_file.rs"),
        "fn main() {}\n".repeat(1000),
    )
    .unwrap();

    let index_path = temp_dir.path().join("index");
    let repos = vec![repo_path];

    let engine = Arc::new(
        CodeIntelEngine::with_options(index_path, repos, EngineOptions::default())
            .await
            .unwrap(),
    );

    // Start background indexing
    let engine_clone = Arc::clone(&engine);
    tokio::spawn(async move {
        let _ = engine_clone.complete_initialization().await;
    });

    // WHEN: The MCP server receives an initialize request
    // (We simulate this by checking the engine can be accessed)
    let start = Instant::now();
    let repos_result = engine.list_repos().await;
    let elapsed = start.elapsed();

    // THEN: The request should be handled quickly (< 100ms)
    assert!(
        elapsed < Duration::from_millis(100),
        "MCP operations should be fast during initialization, took: {:?}",
        elapsed
    );
    assert!(repos_result.is_ok(), "Should successfully return data");
    let repos_str = repos_result.unwrap();
    assert!(
        !repos_str.is_empty(),
        "Should return data even during initialization"
    );
}
