use narsil_mcp::index::CodeIntelEngine;
use std::fs;
use tempfile::TempDir;

/// Test that read_resource rejects paths outside indexed repositories
#[tokio::test]
async fn test_read_resource_path_traversal_protection() {
    // Create a temporary directory with a test repo
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("test-repo");
    fs::create_dir(&repo_path).unwrap();

    // Create a safe file inside the repo
    let safe_file = repo_path.join("safe.txt");
    fs::write(&safe_file, "safe content").unwrap();

    // Create a sensitive file outside the repo (in parent directory)
    let sensitive_file = temp_dir.path().join("sensitive.txt");
    fs::write(&sensitive_file, "sensitive data").unwrap();

    // Initialize the code intelligence engine
    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();

    // Complete initialization to index the repository
    engine.complete_initialization().await.unwrap();

    // Test 1: Reading a file inside the repository should succeed
    let safe_uri = format!("file://{}", safe_file.to_str().unwrap());
    let result = engine.read_resource(&safe_uri).await;
    assert!(
        result.is_ok(),
        "Should allow reading files within indexed repository"
    );
    assert_eq!(result.unwrap(), "safe content");

    // Test 2: Reading a file outside the repository should fail
    let malicious_uri = format!("file://{}", sensitive_file.to_str().unwrap());
    let result = engine.read_resource(&malicious_uri).await;
    assert!(
        result.is_err(),
        "Should block reading files outside indexed repositories"
    );

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Access denied") || error_msg.contains("outside"),
        "Error message should indicate access denial, got: {}",
        error_msg
    );

    // Test 3: Path traversal attempt using ../ should fail
    let traversal_uri = format!(
        "file://{}",
        repo_path.join("../sensitive.txt").to_str().unwrap()
    );
    let result = engine.read_resource(&traversal_uri).await;
    assert!(
        result.is_err(),
        "Should block path traversal attempts with ../"
    );

    // Test 4: Absolute path outside repo should fail
    let abs_path_uri = "file:///etc/passwd";
    let result = engine.read_resource(abs_path_uri).await;
    assert!(
        result.is_err(),
        "Should block absolute paths to system files"
    );
}

/// Test that read_resource handles non-existent paths correctly
#[tokio::test]
async fn test_read_resource_nonexistent_path() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("test-repo");
    fs::create_dir(&repo_path).unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();

    // Complete initialization to index the repository
    engine.complete_initialization().await.unwrap();

    // Attempt to read a non-existent file
    let nonexistent = repo_path.join("nonexistent.txt");
    let uri = format!("file://{}", nonexistent.to_str().unwrap());
    let result = engine.read_resource(&uri).await;

    assert!(result.is_err(), "Should fail for non-existent paths");
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("does not exist") || error_msg.contains("cannot be accessed"),
        "Error should indicate path doesn't exist, got: {}",
        error_msg
    );
}

/// Test that read_resource works with relative URIs
#[tokio::test]
async fn test_read_resource_relative_uri() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("test-repo");
    fs::create_dir(&repo_path).unwrap();

    let test_file = repo_path.join("test.txt");
    fs::write(&test_file, "test content").unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();

    // Complete initialization to index the repository
    engine.complete_initialization().await.unwrap();

    // Test with URI without file:// prefix
    let result = engine.read_resource(test_file.to_str().unwrap()).await;
    assert!(result.is_ok(), "Should handle URIs without file:// prefix");
    assert_eq!(result.unwrap(), "test content");
}

/// Test that get_repo_path rejects arbitrary filesystem paths not in indexed repos.
/// Uses get_project_structure which calls get_repo_path internally.
#[tokio::test]
async fn test_get_repo_path_rejects_arbitrary_paths() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("test-repo");
    fs::create_dir(&repo_path).unwrap();
    fs::write(repo_path.join("main.rs"), "fn main() {}").unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();
    engine.complete_initialization().await.unwrap();

    // Arbitrary filesystem paths should NOT resolve as repos via get_project_structure
    let result = engine.get_project_structure("/etc", 3).await;
    assert!(result.is_err(), "Should not allow /etc as a repo path");

    let result = engine.get_project_structure("/tmp", 3).await;
    assert!(result.is_err(), "Should not allow /tmp as a repo path");

    // But the indexed repo name should work
    let repo_name = repo_path.file_name().unwrap().to_str().unwrap();
    let result = engine.get_project_structure(repo_name, 3).await;
    assert!(
        result.is_ok(),
        "Indexed repo name should work: {:?}",
        result.err()
    );
}

/// Test that get_repo_path allows the actual indexed repo path
#[tokio::test]
async fn test_get_repo_path_allows_indexed_repo_path() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("my-project");
    fs::create_dir(&repo_path).unwrap();
    fs::write(repo_path.join("lib.rs"), "pub fn hello() {}").unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();
    engine.complete_initialization().await.unwrap();

    // The actual indexed path should still work when passed directly
    let result = engine
        .get_project_structure(repo_path.to_str().unwrap(), 3)
        .await;
    assert!(
        result.is_ok(),
        "Indexed repo path should work: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_check_type_errors_accepts_directory_path() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("typed-project");
    let src_path = repo_path.join("src");
    fs::create_dir_all(&src_path).unwrap();
    fs::write(
        src_path.join("app.py"),
        "def add_one(value):\n    return value + 1\n",
    )
    .unwrap();
    fs::write(src_path.join("lib.rs"), "pub fn rust_file() {}\n").unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path])
        .await
        .unwrap();
    engine.complete_initialization().await.unwrap();

    let result = engine
        .check_type_errors("typed-project", "src", Some(true))
        .await
        .unwrap();

    assert!(result.contains("**Files analyzed**: 1"));
    assert!(result.contains("**Functions analyzed**: 1"));
}
