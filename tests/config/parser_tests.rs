/// Tests for configuration file parsing
///
/// These tests verify that YAML configuration files are parsed correctly
/// and that the config loader works as expected.
use narsil_mcp::config::schema::{CategoryConfig, ToolConfig, ToolOverride, ToolsConfig};
use narsil_mcp::config::ConfigLoader;
use std::collections::HashMap;

#[test]
fn test_parse_minimal_config() {
    let yaml = r#"
version: "1.0"
tools:
  categories:
    Repository:
      enabled: true
      description: "Repository and file operations"
  overrides: {}
"#;

    let config: ToolConfig = serde_yaml::from_str(yaml).expect("Should parse minimal config");
    assert_eq!(config.version, "1.0");
    assert!(config.tools.categories.contains_key("Repository"));
    assert!(config.tools.categories.get("Repository").unwrap().enabled);
}

#[test]
fn test_parse_full_config() {
    let yaml = r#"
version: "1.0"
tools:
  categories:
    Repository:
      enabled: true
      description: "Repository and file operations"
    Git:
      enabled: false
      description: "Git integration tools"
      required_flags: ["git"]
  overrides:
    neural_search:
      enabled: false
      reason: "Too slow for IDE usage"
      performance_impact: "high"
      requires_api_key: true
"#;

    let config: ToolConfig = serde_yaml::from_str(yaml).expect("Should parse full config");
    assert_eq!(config.version, "1.0");

    // Check categories
    assert!(config.tools.categories.contains_key("Repository"));
    assert!(config.tools.categories.contains_key("Git"));

    let git_cat = config.tools.categories.get("Git").unwrap();
    assert!(!git_cat.enabled);
    assert_eq!(git_cat.required_flags, vec!["git"]);

    // Check overrides
    assert!(config.tools.overrides.contains_key("neural_search"));
    let neural_override = config.tools.overrides.get("neural_search").unwrap();
    assert!(!neural_override.enabled);
    assert_eq!(
        neural_override.reason,
        Some("Too slow for IDE usage".to_string())
    );
}

#[test]
fn test_parse_category_config() {
    let yaml = r#"
enabled: true
description: "Test category"
required_flags: ["git", "call_graph"]
config:
  max_depth: 5
"#;

    let cat_config: CategoryConfig =
        serde_yaml::from_str(yaml).expect("Should parse category config");
    assert!(cat_config.enabled);
    assert_eq!(cat_config.description, Some("Test category".to_string()));
    assert_eq!(cat_config.required_flags, vec!["git", "call_graph"]);
    assert!(cat_config.config.contains_key("max_depth"));
}

#[test]
fn test_parse_tool_override() {
    let yaml = r#"
enabled: false
reason: "Performance concerns"
required_flags: ["neural"]
performance_impact: "high"
requires_api_key: true
config:
  timeout: 5000
"#;

    let override_config: ToolOverride =
        serde_yaml::from_str(yaml).expect("Should parse tool override");
    assert!(!override_config.enabled);
    assert_eq!(
        override_config.reason,
        Some("Performance concerns".to_string())
    );
    assert_eq!(override_config.required_flags, vec!["neural"]);
    assert!(override_config.requires_api_key);
}

#[test]
fn test_load_default_config() {
    let loader = ConfigLoader::new();
    let config = loader.load().expect("Should load default config");

    assert_eq!(config.version, "1.0");
    assert!(
        !config.tools.categories.is_empty(),
        "Should have categories"
    );

    // Default config should enable all basic categories
    assert!(config.tools.categories.contains_key("Repository"));
    assert!(config.tools.categories.contains_key("Symbols"));
    assert!(config.tools.categories.contains_key("Search"));
}

#[test]
fn test_config_with_empty_overrides() {
    let yaml = r#"
version: "1.0"
tools:
  categories:
    Repository:
      enabled: true
  overrides: {}
"#;

    let config: ToolConfig =
        serde_yaml::from_str(yaml).expect("Should parse config with empty overrides");
    assert!(config.tools.overrides.is_empty());
}

#[test]
fn test_config_roundtrip() {
    // Create a config programmatically
    let mut categories = HashMap::new();
    categories.insert(
        "Repository".to_string(),
        CategoryConfig {
            enabled: true,
            description: Some("Test".to_string()),
            required_flags: vec![],
            config: HashMap::new(),
        },
    );

    let original = ToolConfig {
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

    // Serialize to YAML
    let yaml = serde_yaml::to_string(&original).expect("Should serialize");

    // Deserialize back
    let parsed: ToolConfig = serde_yaml::from_str(&yaml).expect("Should deserialize");

    assert_eq!(parsed.version, original.version);
    assert_eq!(
        parsed.tools.categories.len(),
        original.tools.categories.len()
    );
}

#[test]
fn test_parse_invalid_version() {
    let yaml = r#"
version: "999.0"
tools:
  categories: {}
  overrides: {}
"#;

    // Should parse but validation should catch invalid version
    let config: ToolConfig = serde_yaml::from_str(yaml).expect("Should parse");
    assert_eq!(config.version, "999.0");
}

#[test]
fn test_parse_with_tools_field_omitted() {
    // Issue #5: tools field should now be optional with a default
    let yaml = r#"
version: "1.0"
"#;

    // Should succeed - tools field now has a default
    let config: ToolConfig = serde_yaml::from_str(yaml).expect("Should parse without tools field");
    assert_eq!(config.version, "1.0");
    // Tools should be empty by default
    assert!(config.tools.categories.is_empty());
    assert!(config.tools.overrides.is_empty());
}

#[test]
fn test_default_values() {
    let yaml = r#"
version: "1.0"
tools:
  categories:
    Repository:
      enabled: true
  overrides: {}
"#;

    let config: ToolConfig = serde_yaml::from_str(yaml).expect("Should parse");

    // Performance config should have defaults
    assert_eq!(config.performance.max_tool_count, 76);
    assert_eq!(config.performance.startup_latency_ms, 10);
    assert_eq!(config.performance.filtering_latency_ms, 1);
}

#[test]
fn test_parse_nested_config() {
    let yaml = r#"
version: "1.0"
tools:
  categories:
    Security:
      enabled: true
      config:
        severity_threshold: "medium"
        exclude_tests: true
  overrides: {}
"#;

    let config: ToolConfig = serde_yaml::from_str(yaml).expect("Should parse");
    let security_cat = config.tools.categories.get("Security").unwrap();

    assert_eq!(
        security_cat
            .config
            .get("severity_threshold")
            .unwrap()
            .as_str()
            .unwrap(),
        "medium"
    );
    assert!(security_cat
        .config
        .get("exclude_tests")
        .unwrap()
        .as_bool()
        .unwrap());
}
