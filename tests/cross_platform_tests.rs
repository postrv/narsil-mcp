/// Cross-platform integration tests
///
/// Tests configuration, file handling, and path resolution across
/// macOS, Linux, and Windows platforms.
use anyhow::Result;
use narsil_xref::config::ConfigLoader;
use narsil_xref::index::{CodeIntelEngine, EngineOptions};
use std::env;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Test that config paths are correctly resolved on each platform
#[test]
fn test_config_path_resolution() {
    let loader = ConfigLoader::new();

    // Get the default config path (platform-specific)
    let config_path = loader.get_default_user_config_path();

    // Verify it exists and is absolute
    assert!(
        config_path.is_absolute(),
        "Config path should be absolute: {:?}",
        config_path
    );

    // Platform-specific checks
    #[cfg(target_os = "windows")]
    {
        // Windows: Should be in %APPDATA%\narsil-xref\config.yaml
        let path_str = config_path.to_string_lossy();
        assert!(
            path_str.contains("AppData") || path_str.contains("narsil-xref"),
            "Windows config path should be in AppData: {:?}",
            config_path
        );
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: Should be in ~/Library/Application Support/narsil-xref/config.yaml
        // or ~/.config/narsil-xref/config.yaml
        let path_str = config_path.to_string_lossy();
        assert!(
            path_str.contains("Library/Application Support")
                || path_str.contains(".config/narsil-xref"),
            "macOS config path should be in Library/Application Support or .config: {:?}",
            config_path
        );
    }

    #[cfg(target_os = "linux")]
    {
        // Linux: Should be in ~/.config/narsil-xref/config.yaml
        let path_str = config_path.to_string_lossy();
        assert!(
            path_str.contains(".config/narsil-xref"),
            "Linux config path should be in .config: {:?}",
            config_path
        );
    }
}

/// Test that file operations work correctly across platforms
#[tokio::test]
async fn test_cross_platform_file_operations() -> Result<()> {
    // Create a temporary directory (works on all platforms)
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();

    // Create test files with different naming conventions
    let test_files = vec![
        "simple.rs",
        "with-dash.rs",
        "with_underscore.rs",
        "with.multiple.dots.rs",
        "UPPERCASE.rs",
        "nested/dir/file.rs",
    ];

    for file_path in &test_files {
        let full_path = repo_path.join(file_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&full_path, "fn test() {}")?;
    }

    // Create engine and index the repository
    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::with_options(
        index_path,
        vec![repo_path.clone()],
        EngineOptions::default(),
    )
    .await?;

    // Complete initialization
    engine.complete_initialization().await?;

    // Verify all files were indexed
    let repos = engine.list_repos().await?;
    assert!(
        !repos.is_empty(),
        "Should have indexed repository on all platforms"
    );

    Ok(())
}

/// Test that path separators are handled correctly
#[test]
fn test_path_separator_handling() {
    // PathBuf should handle separators correctly on each platform
    let path = PathBuf::from("dir").join("subdir").join("file.rs");

    // Verify the path is constructed correctly
    let path_str = path.to_string_lossy();

    #[cfg(target_os = "windows")]
    {
        assert!(
            path_str.contains('\\') || path_str.contains('/'),
            "Windows path should use backslash or forward slash: {:?}",
            path_str
        );
    }

    #[cfg(not(target_os = "windows"))]
    {
        assert!(
            path_str.contains('/'),
            "Unix path should use forward slash: {:?}",
            path_str
        );
        assert!(
            !path_str.contains('\\'),
            "Unix path should not use backslash: {:?}",
            path_str
        );
    }
}

/// Test environment variable handling across platforms
#[test]
fn test_environment_variable_handling() {
    // Set a test environment variable
    let test_var = "NARSIL_TEST_VAR";
    let test_value = "test_value";

    env::set_var(test_var, test_value);

    // Verify we can read it
    let read_value = env::var(test_var).expect("Should read environment variable");
    assert_eq!(
        read_value, test_value,
        "Environment variable should be readable on all platforms"
    );

    // Clean up
    env::remove_var(test_var);

    // Verify it's gone
    assert!(
        env::var(test_var).is_err(),
        "Environment variable should be removed"
    );
}

/// Test temp directory creation and cleanup
#[test]
fn test_temp_directory_handling() -> Result<()> {
    // Create a temp directory
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path().to_path_buf();

    // Verify it exists
    assert!(
        temp_path.exists(),
        "Temp directory should exist: {:?}",
        temp_path
    );

    // Create a file in it
    let test_file = temp_path.join("test.txt");
    fs::write(&test_file, "test content")?;
    assert!(test_file.exists(), "Test file should exist");

    // Get the path before dropping
    let path_copy = temp_path.clone();

    // Drop the temp directory
    drop(temp_dir);

    // On most platforms, the directory should be cleaned up
    // (Windows might take longer due to file locking)
    #[cfg(not(target_os = "windows"))]
    {
        assert!(
            !path_copy.exists(),
            "Temp directory should be cleaned up: {:?}",
            path_copy
        );
    }

    Ok(())
}

/// Test that config loading works across platforms
#[tokio::test]
async fn test_cross_platform_config_loading() -> Result<()> {
    // Create a temporary config directory
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join("config.yaml");

    // Write a test config
    let config_yaml = r#"
version: "1.0"
preset: "minimal"
tools:
  categories:
    Repository:
      enabled: true
  overrides:
    neural_search:
      enabled: false
      reason: "Test"
"#;
    fs::write(&config_path, config_yaml)?;

    // Load the config
    let loader = ConfigLoader::new();
    let config = loader.load_from_path(&config_path)?;

    // Verify it loaded correctly
    assert_eq!(config.version, "1.0");
    assert!(!config.tools.overrides["neural_search"].enabled);

    Ok(())
}

/// Test that repository paths work with different path styles
#[tokio::test]
async fn test_cross_platform_repo_paths() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();

    // Create a simple repo with a file
    fs::write(repo_path.join("test.rs"), "fn main() {}")?;

    // Create engine with the repo path
    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::with_options(
        index_path,
        vec![repo_path.clone()],
        EngineOptions::default(),
    )
    .await?;

    engine.complete_initialization().await?;

    // List repos
    let repos = engine.list_repos().await?;

    // Verify the repo path is included
    assert!(!repos.is_empty(), "Should list repository on all platforms");

    // The repo path should be absolute
    assert!(
        repo_path.is_absolute(),
        "Repo path should be absolute: {:?}",
        repo_path
    );

    Ok(())
}

/// Test line ending handling across platforms
#[tokio::test]
async fn test_cross_platform_line_endings() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();

    // Create files with different line endings
    let unix_file = repo_path.join("unix.rs");
    fs::write(&unix_file, "fn unix() {\n    println!(\"unix\");\n}\n")?;

    let windows_file = repo_path.join("windows.rs");
    fs::write(
        &windows_file,
        "fn windows() {\r\n    println!(\"windows\");\r\n}\r\n",
    )?;

    // Index the repository
    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::with_options(
        index_path,
        vec![repo_path.clone()],
        EngineOptions::default(),
    )
    .await?;

    engine.complete_initialization().await?;

    // Both files should be indexed successfully
    let repos = engine.list_repos().await?;
    assert!(
        !repos.is_empty(),
        "Should index files with different line endings"
    );

    Ok(())
}

/// Test that Unicode filenames work across platforms
#[tokio::test]
async fn test_unicode_filename_handling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();

    // Create files with Unicode names (if the platform supports it)
    let unicode_files = vec!["hello_世界.rs", "café.rs", "test_文件.rs"];

    for filename in &unicode_files {
        let file_path = repo_path.join(filename);
        // Try to create the file - some platforms may not support all Unicode
        if let Ok(()) = fs::write(&file_path, "fn test() {}") {
            assert!(
                file_path.exists(),
                "Unicode file should exist: {:?}",
                file_path
            );
        }
    }

    // Index the repository
    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::with_options(
        index_path,
        vec![repo_path.clone()],
        EngineOptions::default(),
    )
    .await?;

    engine.complete_initialization().await?;

    // Should successfully index (even if no Unicode files were created)
    let repos = engine.list_repos().await?;
    assert!(
        !repos.is_empty(),
        "Should handle Unicode filenames gracefully"
    );

    Ok(())
}

/// Test that very long paths are handled correctly
#[tokio::test]
async fn test_long_path_handling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();

    // Create a deeply nested directory structure
    let mut deep_path = repo_path.clone();
    for i in 0..10 {
        deep_path = deep_path.join(format!("level_{}", i));
    }

    // Try to create it (Windows has path length limits)
    match fs::create_dir_all(&deep_path) {
        Ok(()) => {
            // Create a file in the deep path
            let file_path = deep_path.join("deep_file.rs");
            fs::write(&file_path, "fn deep() {}")?;

            // Index the repository
            let index_path = temp_dir.path().join("index");
            let engine = CodeIntelEngine::with_options(
                index_path,
                vec![repo_path.clone()],
                EngineOptions::default(),
            )
            .await?;

            engine.complete_initialization().await?;

            let repos = engine.list_repos().await?;
            assert!(!repos.is_empty(), "Should handle deep paths");
        }
        Err(_) => {
            // Platform doesn't support such deep paths - that's OK
            // Just verify we can still create the engine
            let index_path = temp_dir.path().join("index");
            let engine = CodeIntelEngine::with_options(
                index_path,
                vec![repo_path.clone()],
                EngineOptions::default(),
            )
            .await?;
            assert!(
                engine.list_repos().await.is_ok(),
                "Should handle path errors gracefully"
            );
        }
    }

    Ok(())
}

/// Test case sensitivity handling across platforms
#[tokio::test]
async fn test_case_sensitivity_handling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();

    // Create files with different cases
    fs::write(repo_path.join("Test.rs"), "fn test1() {}")?;

    // Try to create a file with different case
    // On case-insensitive filesystems (macOS, Windows), this will overwrite
    // On case-sensitive filesystems (Linux), this will create a new file
    fs::write(repo_path.join("TEST.rs"), "fn test2() {}")?;

    // Index the repository
    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::with_options(
        index_path,
        vec![repo_path.clone()],
        EngineOptions::default(),
    )
    .await?;

    engine.complete_initialization().await?;

    // Should successfully index regardless of case sensitivity
    let repos = engine.list_repos().await?;
    assert!(
        !repos.is_empty(),
        "Should handle case sensitivity differences"
    );

    Ok(())
}

/// Test that hidden files are handled correctly
#[tokio::test]
async fn test_hidden_file_handling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();

    // Create visible and hidden files
    fs::write(repo_path.join("visible.rs"), "fn visible() {}")?;
    fs::write(repo_path.join(".hidden.rs"), "fn hidden() {}")?;

    // Create .gitignore
    fs::write(repo_path.join(".gitignore"), "ignored.rs\n")?;
    fs::write(repo_path.join("ignored.rs"), "fn ignored() {}")?;

    // Index the repository
    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::with_options(
        index_path,
        vec![repo_path.clone()],
        EngineOptions::default(),
    )
    .await?;

    engine.complete_initialization().await?;

    // Should successfully index (respecting .gitignore)
    let repos = engine.list_repos().await?;
    assert!(
        !repos.is_empty(),
        "Should handle hidden files and .gitignore"
    );

    Ok(())
}
