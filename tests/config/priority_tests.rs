/// Tests for configuration priority and merging
///
/// Priority order (highest to lowest):
/// 1. CLI flags (handled in main.rs)
/// 2. Environment variables (NARSIL_*)
/// 3. Project config (.narsil.yaml in repo root)
/// 4. User config (~/.config/narsil-xref/config.yaml)
/// 5. Default config (built-in)
use narsil_xref::config::ConfigLoader;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tempfile::TempDir;

/// Mutex to serialize tests that modify NARSIL_* environment variables
/// This prevents race conditions when tests run in parallel
static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// Helper to create a temporary config file
fn create_temp_config(dir: &TempDir, filename: &str, content: &str) -> PathBuf {
    let path = dir.path().join(filename);
    fs::write(&path, content).unwrap();
    path
}

/// Helper to create a user config
fn create_user_config(content: &str) -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    create_temp_config(&temp_dir, "config.yaml", content);
    temp_dir
}

/// Helper to create a project config
fn create_project_config(content: &str) -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    create_temp_config(&temp_dir, ".narsil.yaml", content);
    temp_dir
}

#[test]
fn test_default_config_loads() {
    // Acquire mutex to prevent env var race conditions with parallel tests
    let _guard = ENV_MUTEX.lock().unwrap();

    // Clean up environment variables that might be set by other tests
    std::env::remove_var("NARSIL_DISABLED_TOOLS");
    std::env::remove_var("NARSIL_CONFIG_PATH");

    // Set paths to non-existent files to ensure we only load the default config
    let nonexistent_user_path = PathBuf::from("/tmp/nonexistent_user_config_12345.yaml");
    let nonexistent_project_path = PathBuf::from("/tmp/nonexistent_project_config_12345.yaml");

    let loader = ConfigLoader::new()
        .with_user_config_path(Some(nonexistent_user_path))
        .with_project_config_path(Some(nonexistent_project_path));
    let config = loader.load().unwrap();

    assert_eq!(config.version, "1.0");
    assert!(config.tools.overrides.is_empty()); // Default has no tool overrides (no env vars)
}

#[test]
fn test_user_config_overrides_default() {
    // ConfigLoader::load() reads NARSIL_* env vars; serialize against tests
    // that set them so we are not affected by mid-test mutations.
    let _guard = ENV_MUTEX.lock().unwrap();
    std::env::remove_var("NARSIL_DISABLED_TOOLS");

    let user_config_content = r#"
version: "1.0"
tools:
  overrides:
    list_repos:
      enabled: false
      reason: "User disabled"
"#;

    let temp_dir = create_user_config(user_config_content);
    let user_config_path = temp_dir.path().join("config.yaml");

    let mut loader = ConfigLoader::new();
    loader = loader.with_user_config_path(Some(user_config_path));

    let config = loader.load().unwrap();

    // User config should override default
    assert!(config.tools.overrides.contains_key("list_repos"));
    let override_config = &config.tools.overrides["list_repos"];
    assert!(!override_config.enabled);
    assert_eq!(override_config.reason.as_deref(), Some("User disabled"));
}

/// merge_configs copies field by field, so a new top-level field is silently
/// dropped until it is added there — `expose` was, once.
#[test]
fn test_user_config_expose_survives_the_merge() {
    let _guard = ENV_MUTEX.lock().unwrap();
    std::env::remove_var("NARSIL_DISABLED_TOOLS");

    let user_config_content = r#"
version: "1.0"
expose: [code, git]
"#;

    let temp_dir = create_user_config(user_config_content);
    let mut loader = ConfigLoader::new();
    loader = loader.with_user_config_path(Some(temp_dir.path().join("config.yaml")));

    let config = loader.load().unwrap();

    assert_eq!(
        config.expose,
        vec!["code".to_string(), "git".to_string()],
        "top-level expose must survive merge_configs"
    );
}

#[test]
fn test_project_config_overrides_user_config() {
    let _guard = ENV_MUTEX.lock().unwrap();
    std::env::remove_var("NARSIL_DISABLED_TOOLS");
    let user_config_content = r#"
version: "1.0"
tools:
  overrides:
    search_code:
      enabled: false
      reason: "User disabled search"
"#;

    let project_config_content = r#"
version: "1.0"
tools:
  overrides:
    search_code:
      enabled: true
      reason: "Project re-enabled search"
"#;

    let user_dir = create_user_config(user_config_content);
    let project_dir = create_project_config(project_config_content);

    let user_config_path = user_dir.path().join("config.yaml");
    let project_config_path = project_dir.path().join(".narsil.yaml");

    let mut loader = ConfigLoader::new();
    loader = loader
        .with_user_config_path(Some(user_config_path))
        .with_project_config_path(Some(project_config_path));

    let config = loader.load().unwrap();

    // Project config should override user config
    assert!(config.tools.overrides.contains_key("search_code"));
    let override_config = &config.tools.overrides["search_code"];
    assert!(override_config.enabled); // Project re-enabled it
    assert_eq!(
        override_config.reason.as_deref(),
        Some("Project re-enabled search")
    );
}

#[test]
fn test_env_var_disabled_tools() {
    let _guard = ENV_MUTEX.lock().unwrap();

    env::set_var("NARSIL_DISABLED_TOOLS", "neural_search,generate_sbom");

    let loader = ConfigLoader::new();
    let config = loader.load().unwrap();

    // Should have tools disabled by env var
    assert!(config.tools.overrides.contains_key("neural_search"));
    assert!(config.tools.overrides.contains_key("generate_sbom"));

    assert!(!config.tools.overrides["neural_search"].enabled);
    assert!(!config.tools.overrides["generate_sbom"].enabled);

    env::remove_var("NARSIL_DISABLED_TOOLS");
}

#[test]
fn test_env_var_overrides_user_config() {
    let _guard = ENV_MUTEX.lock().unwrap();

    // User config enables neural_search
    let user_config_content = r#"
version: "1.0"
tools:
  overrides:
    neural_search:
      enabled: true
      reason: "User enabled"
"#;

    let temp_dir = create_user_config(user_config_content);
    let user_config_path = temp_dir.path().join("config.yaml");

    // Env var disables it
    env::set_var("NARSIL_DISABLED_TOOLS", "neural_search");

    let mut loader = ConfigLoader::new();
    loader = loader.with_user_config_path(Some(user_config_path));

    let config = loader.load().unwrap();

    // Env var should win
    assert!(config.tools.overrides.contains_key("neural_search"));
    assert!(!config.tools.overrides["neural_search"].enabled);

    env::remove_var("NARSIL_DISABLED_TOOLS");
}

#[test]
fn test_env_var_config_path() {
    let _guard = ENV_MUTEX.lock().unwrap();

    let custom_config_content = r#"
version: "1.0"
tools:
  overrides:
    find_symbols:
      enabled: false
      reason: "Custom config disabled"
"#;

    let temp_dir = TempDir::new().unwrap();
    let custom_config_path = create_temp_config(&temp_dir, "custom.yaml", custom_config_content);

    env::set_var("NARSIL_CONFIG_PATH", custom_config_path.to_str().unwrap());

    let loader = ConfigLoader::new();
    let config = loader.load().unwrap();

    // Should load from custom path
    assert!(config.tools.overrides.contains_key("find_symbols"));
    assert!(!config.tools.overrides["find_symbols"].enabled);

    env::remove_var("NARSIL_CONFIG_PATH");
}

#[test]
fn test_config_merging_preserves_both_tools() {
    let _guard = ENV_MUTEX.lock().unwrap();
    std::env::remove_var("NARSIL_DISABLED_TOOLS");
    let user_config_content = r#"
version: "1.0"
tools:
  overrides:
    tool_a:
      enabled: false
      reason: "User disabled A"
"#;

    let project_config_content = r#"
version: "1.0"
tools:
  overrides:
    tool_b:
      enabled: false
      reason: "Project disabled B"
"#;

    let user_dir = create_user_config(user_config_content);
    let project_dir = create_project_config(project_config_content);

    let user_config_path = user_dir.path().join("config.yaml");
    let project_config_path = project_dir.path().join(".narsil.yaml");

    let mut loader = ConfigLoader::new();
    loader = loader
        .with_user_config_path(Some(user_config_path))
        .with_project_config_path(Some(project_config_path));

    let config = loader.load().unwrap();

    // Both tools should be present
    assert!(config.tools.overrides.contains_key("tool_a"));
    assert!(config.tools.overrides.contains_key("tool_b"));
    assert!(!config.tools.overrides["tool_a"].enabled);
    assert!(!config.tools.overrides["tool_b"].enabled);
}

#[test]
fn test_invalid_config_returns_error() {
    let _guard = ENV_MUTEX.lock().unwrap();
    std::env::remove_var("NARSIL_DISABLED_TOOLS");
    // Use a config with a type mismatch - 'enabled' should be a bool, not a string
    let invalid_config_content = r#"
version: "1.0"
tools:
  overrides:
    list_repos:
      enabled: "not_a_boolean"
"#;

    let temp_dir = create_user_config(invalid_config_content);
    let user_config_path = temp_dir.path().join("config.yaml");

    let mut loader = ConfigLoader::new();
    loader = loader.with_user_config_path(Some(user_config_path));

    // Should return error for invalid type
    let result = loader.load();
    assert!(result.is_err());
}

#[test]
fn test_missing_user_config_falls_back_to_default() {
    let _guard = ENV_MUTEX.lock().unwrap();

    // Clean up env vars that could affect this test
    std::env::remove_var("NARSIL_DISABLED_TOOLS");

    let mut loader = ConfigLoader::new();
    loader = loader.with_user_config_path(Some(PathBuf::from("/nonexistent/path/config.yaml")));

    let config = loader.load().unwrap();

    // Should fall back to default config
    assert_eq!(config.version, "1.0");
    // Default config has no tool overrides
    assert!(config.tools.overrides.is_empty());
}
