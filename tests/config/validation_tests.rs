/// Tests for configuration validation
///
/// These tests verify that invalid configurations are caught
/// and that helpful error messages are provided.
use narsil_mcp::config::schema::{RepoProfile, ToolConfig, ToolOverride, ToolsConfig};
use narsil_mcp::config::validate_config;
use std::collections::HashMap;

fn override_named(name: &str, enabled: bool) -> HashMap<String, ToolOverride> {
    let mut overrides = HashMap::new();
    overrides.insert(
        name.to_string(),
        ToolOverride {
            enabled,
            reason: None,
            required_flags: vec![],
            config: HashMap::new(),
            performance_impact: None,
            requires_api_key: false,
        },
    );
    overrides
}

#[test]
fn test_validate_valid_config() {
    let config = ToolConfig {
        version: "1.0".to_string(),
        expose: Vec::new(),
        adopted_repo_ttl_days: None,
        memory_soft_limit: None,
        memory_hard_limit: None,
        memory_soft_limit_interval_secs: None,
        profiles: HashMap::new(),
        tools: ToolsConfig {
            overrides: override_named("list_repos", true),
        },
    };

    let result = validate_config(&config);
    assert!(result.is_ok(), "Valid config should pass validation");
}

#[test]
fn test_validate_invalid_version() {
    let config = ToolConfig {
        version: "2.0".to_string(), // Unsupported version
        ..Default::default()
    };

    let result = validate_config(&config);
    assert!(result.is_err(), "Invalid version should fail validation");

    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("version") || error.contains("Version"),
        "Error should mention version: {}",
        error
    );
}

#[test]
fn test_validate_unknown_tool_in_override() {
    let config = ToolConfig {
        version: "1.0".to_string(),
        expose: Vec::new(),
        adopted_repo_ttl_days: None,
        memory_soft_limit: None,
        memory_hard_limit: None,
        memory_soft_limit_interval_secs: None,
        profiles: HashMap::new(),
        tools: ToolsConfig {
            overrides: override_named("nonexistent_tool_xyz", false),
        },
    };

    let result = validate_config(&config);
    // Unknown tools should be allowed (warning, not error)
    // This allows forward compatibility with newer tool versions
    assert!(
        result.is_ok(),
        "Unknown tool in override should be allowed (with warning)"
    );
}

#[test]
fn test_validate_profile_requires_paths() {
    let mut config = ToolConfig::default();
    config
        .profiles
        .insert("empty".to_string(), RepoProfile::default());

    let result = validate_config(&config);
    assert!(
        result.is_err(),
        "profile without repos or discover should fail validation"
    );
}
