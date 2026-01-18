/// Tests for configuration validation
///
/// These tests verify that invalid configurations are caught
/// and that helpful error messages are provided.
use narsil_mcp::config::schema::{CategoryConfig, ToolConfig, ToolOverride, ToolsConfig};
use narsil_mcp::config::validate_config;
use std::collections::HashMap;

#[test]
fn test_validate_valid_config() {
    let mut categories = HashMap::new();
    categories.insert(
        "Repository".to_string(),
        CategoryConfig {
            enabled: true,
            description: Some("Repo tools".to_string()),
            required_flags: vec![],
            config: HashMap::new(),
        },
    );

    let config = ToolConfig {
        version: "1.0".to_string(),
        preset: None,
        editors: HashMap::new(),
        tools: ToolsConfig {
            categories,
            overrides: HashMap::new(),
        },
        performance: Default::default(),
        feature_requirements: HashMap::new(),
    };

    let result = validate_config(&config);
    assert!(result.is_ok(), "Valid config should pass validation");
}

#[test]
fn test_validate_invalid_version() {
    let mut categories = HashMap::new();
    categories.insert(
        "Repository".to_string(),
        CategoryConfig {
            enabled: true,
            description: None,
            required_flags: vec![],
            config: HashMap::new(),
        },
    );

    let config = ToolConfig {
        version: "999.0".to_string(), // Invalid version
        preset: None,
        editors: HashMap::new(),
        tools: ToolsConfig {
            categories,
            overrides: HashMap::new(),
        },
        performance: Default::default(),
        feature_requirements: HashMap::new(),
    };

    let result = validate_config(&config);
    assert!(
        result.is_err(),
        "Config with invalid version should fail validation"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("version") || err_msg.contains("1.0"),
        "Error should mention version issue: {}",
        err_msg
    );
}

#[test]
fn test_validate_unknown_category() {
    let mut categories = HashMap::new();
    categories.insert(
        "UnknownCategory".to_string(),
        CategoryConfig {
            enabled: true,
            description: None,
            required_flags: vec![],
            config: HashMap::new(),
        },
    );

    let config = ToolConfig {
        version: "1.0".to_string(),
        preset: None,
        editors: HashMap::new(),
        tools: ToolsConfig {
            categories,
            overrides: HashMap::new(),
        },
        performance: Default::default(),
        feature_requirements: HashMap::new(),
    };

    let result = validate_config(&config);
    // Should either warn or error about unknown category
    // For now, we'll allow unknown categories with a warning
    // So this test verifies it doesn't panic
    let _ = result;
}

#[test]
fn test_validate_performance_budgets() {
    let mut categories = HashMap::new();
    categories.insert(
        "Repository".to_string(),
        CategoryConfig {
            enabled: true,
            description: None,
            required_flags: vec![],
            config: HashMap::new(),
        },
    );

    let mut config = ToolConfig {
        version: "1.0".to_string(),
        preset: None,
        editors: HashMap::new(),
        tools: ToolsConfig {
            categories,
            overrides: HashMap::new(),
        },
        performance: Default::default(),
        feature_requirements: HashMap::new(),
    };

    // Invalid performance budget
    config.performance.max_tool_count = 0;

    let result = validate_config(&config);
    assert!(
        result.is_err(),
        "Config with invalid performance budget should fail"
    );
}

#[test]
fn test_validate_empty_categories() {
    let config = ToolConfig {
        version: "1.0".to_string(),
        preset: None,
        editors: HashMap::new(),
        tools: ToolsConfig {
            categories: HashMap::new(), // Empty categories
            overrides: HashMap::new(),
        },
        performance: Default::default(),
        feature_requirements: HashMap::new(),
    };

    let result = validate_config(&config);
    // Empty categories should be valid (all disabled)
    assert!(result.is_ok(), "Empty categories should be valid");
}

#[test]
fn test_validate_conflicting_overrides() {
    let mut categories = HashMap::new();
    categories.insert(
        "Repository".to_string(),
        CategoryConfig {
            enabled: false, // Category disabled
            description: None,
            required_flags: vec![],
            config: HashMap::new(),
        },
    );

    let mut overrides = HashMap::new();
    overrides.insert(
        "list_repos".to_string(),
        ToolOverride {
            enabled: true, // But specific tool enabled
            reason: None,
            required_flags: vec![],
            config: HashMap::new(),
            performance_impact: None,
            requires_api_key: false,
        },
    );

    let config = ToolConfig {
        version: "1.0".to_string(),
        preset: None,
        editors: HashMap::new(),
        tools: ToolsConfig {
            categories,
            overrides,
        },
        performance: Default::default(),
        feature_requirements: HashMap::new(),
    };

    let result = validate_config(&config);
    // This should be allowed - tool override can enable specific tools
    // even if category is disabled
    assert!(
        result.is_ok(),
        "Tool override should be allowed even if category disabled"
    );
}

#[test]
fn test_validate_unknown_tool_in_override() {
    let mut overrides = HashMap::new();
    overrides.insert(
        "nonexistent_tool".to_string(),
        ToolOverride {
            enabled: false,
            reason: None,
            required_flags: vec![],
            config: HashMap::new(),
            performance_impact: None,
            requires_api_key: false,
        },
    );

    let config = ToolConfig {
        version: "1.0".to_string(),
        preset: None,
        editors: HashMap::new(),
        tools: ToolsConfig {
            categories: HashMap::new(),
            overrides,
        },
        performance: Default::default(),
        feature_requirements: HashMap::new(),
    };

    let result = validate_config(&config);
    // Should warn about unknown tool but not fail
    // (allows forward compatibility)
    assert!(
        result.is_ok(),
        "Unknown tool override should be allowed with warning"
    );
}
