/// Tests for configuration file parsing
///
/// These tests verify that YAML configuration files are parsed correctly
/// and that the config loader works as expected.
use narsil_xref::config::schema::{ToolConfig, ToolOverride, ToolsConfig};
use narsil_xref::config::ConfigLoader;
use std::collections::HashMap;

#[test]
fn test_parse_minimal_config() {
    let yaml = r#"
version: "1.0"
tools:
  overrides: {}
"#;

    let config: ToolConfig = serde_saphyr::from_str(yaml).expect("Should parse minimal config");
    assert_eq!(config.version, "1.0");
    assert!(config.tools.overrides.is_empty());
}

/// A YAML 1.1 parser would read a bare `off` as false and reject the whole file.
#[test]
fn test_parse_memory_limits() {
    let yaml = r#"
version: "1.0"
memory_soft_limit: off
memory_hard_limit: 64G
memory_soft_limit_interval_secs: 60
"#;

    let config: ToolConfig = serde_saphyr::from_str(yaml).expect("Should parse memory limits");
    assert_eq!(config.memory_soft_limit.as_deref(), Some("off"));
    assert_eq!(config.memory_hard_limit.as_deref(), Some("64G"));
    assert_eq!(config.memory_soft_limit_interval_secs, Some(60));
}

#[test]
fn test_parse_sse_url() {
    let yaml = r#"
version: "1.0"
sse_url: http://127.0.0.1:7557
"#;

    let config: ToolConfig = serde_saphyr::from_str(yaml).expect("Should parse sse_url");
    assert_eq!(config.sse_url.as_deref(), Some("http://127.0.0.1:7557"));
}

#[test]
fn test_parse_full_config() {
    let yaml = r#"
version: "1.0"
expose: [code, git]
tools:
  overrides:
    semantic_search:
      enabled: false
      reason: "Too slow for IDE usage"
      performance_impact: "high"
"#;

    let config: ToolConfig = serde_saphyr::from_str(yaml).expect("Should parse full config");
    assert_eq!(config.version, "1.0");
    assert_eq!(config.expose, vec!["code".to_string(), "git".to_string()]);

    // Check overrides
    assert!(config.tools.overrides.contains_key("semantic_search"));
    let search_override = config.tools.overrides.get("semantic_search").unwrap();
    assert!(!search_override.enabled);
    assert_eq!(
        search_override.reason,
        Some("Too slow for IDE usage".to_string())
    );
}

#[test]
fn test_parse_tool_override() {
    let yaml = r#"
enabled: false
reason: "Performance concerns"
required_flags: ["git"]
performance_impact: "high"
requires_api_key: true
config:
  timeout: 5000
"#;

    let override_config: ToolOverride =
        serde_saphyr::from_str(yaml).expect("Should parse tool override");
    assert!(!override_config.enabled);
    assert_eq!(
        override_config.reason,
        Some("Performance concerns".to_string())
    );
    assert_eq!(override_config.required_flags, vec!["git"]);
    assert!(override_config.requires_api_key);
}

#[test]
fn test_load_default_config() {
    let loader = ConfigLoader::new();
    let config = loader.load().expect("Should load default config");

    assert_eq!(config.version, "1.0");
}

#[test]
fn test_config_with_empty_overrides() {
    let yaml = r#"
version: "1.0"
tools:
  overrides: {}
"#;

    let config: ToolConfig =
        serde_saphyr::from_str(yaml).expect("Should parse config with empty overrides");
    assert!(config.tools.overrides.is_empty());
}

#[test]
fn test_config_roundtrip() {
    // Create a config programmatically
    let mut overrides = HashMap::new();
    overrides.insert(
        "get_blame".to_string(),
        ToolOverride {
            enabled: false,
            reason: Some("Test".to_string()),
            required_flags: vec![],
            config: HashMap::new(),
            performance_impact: None,
            requires_api_key: false,
        },
    );

    let original = ToolConfig {
        version: "1.0".to_string(),
        expose: vec!["code".to_string()],
        adopted_repo_ttl_days: None,
        memory_soft_limit: None,
        memory_hard_limit: None,
        memory_soft_limit_interval_secs: None,
        sse_url: None,
        profiles: HashMap::new(),
        tools: ToolsConfig { overrides },
    };

    // Serialize to YAML
    let yaml = serde_saphyr::to_string(&original).expect("Should serialize");

    // Deserialize back
    let parsed: ToolConfig = serde_saphyr::from_str(&yaml).expect("Should deserialize");

    assert_eq!(parsed.version, original.version);
    assert_eq!(parsed.expose, original.expose);
    assert_eq!(parsed.tools.overrides.len(), original.tools.overrides.len());
}

#[test]
fn test_parse_invalid_version() {
    let yaml = r#"
version: "999.0"
tools:
  overrides: {}
"#;

    // Should parse but validation should catch invalid version
    let config: ToolConfig = serde_saphyr::from_str(yaml).expect("Should parse");
    assert_eq!(config.version, "999.0");
}

#[test]
fn test_parse_with_tools_field_omitted() {
    // Issue #5: tools field should now be optional with a default
    let yaml = r#"
version: "1.0"
"#;

    // Should succeed - tools field now has a default
    let config: ToolConfig =
        serde_saphyr::from_str(yaml).expect("Should parse without tools field");
    assert_eq!(config.version, "1.0");
    // Tools should be empty by default
    assert!(config.tools.overrides.is_empty());
}
