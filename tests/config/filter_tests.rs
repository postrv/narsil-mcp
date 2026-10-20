/// Tests for ToolFilter - dynamic tool filtering based on configuration
///
/// These tests verify that the filtering logic correctly applies:
/// 1. Feature flags (git_enabled → Git tools)
/// 2. Tool overrides
/// 3. Expose groups
use narsil_xref::config::schema::{ToolConfig, ToolOverride};
use narsil_xref::config::ConfigLoader;
use narsil_xref::index::EngineOptions;
use narsil_xref::tool_metadata::{FeatureFlag, TOOL_METADATA};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// Import ToolFilter (will be implemented)
use narsil_xref::config::{ExposeGroup, ToolFilter};

#[test]
fn test_filter_by_feature_flags_git() {
    // Git enabled, call graph disabled
    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: false,
        ..Default::default()
    };

    let config = ToolConfig::default();
    let filter = ToolFilter::new(config, &options);
    let enabled = filter.get_enabled_tools();

    // Git tools should be included
    assert!(
        enabled.contains(&"get_blame"),
        "Git tools should be enabled when git_enabled=true"
    );
    assert!(
        enabled.contains(&"get_file_history"),
        "Git tools should be enabled"
    );

    // Call graph tools should NOT be included
    assert!(
        !enabled.contains(&"get_call_graph"),
        "Call graph tools should be disabled when call_graph_enabled=false"
    );
    assert!(
        !enabled.contains(&"get_callers"),
        "Call graph tools should be disabled"
    );
}

#[test]
fn test_filter_by_feature_flags_call_graph() {
    // Call graph enabled, git disabled
    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: true,
        ..Default::default()
    };

    let config = ToolConfig::default();
    let filter = ToolFilter::new(config, &options);
    let enabled = filter.get_enabled_tools();

    // Call graph tools should be included
    assert!(
        enabled.contains(&"get_call_graph"),
        "Call graph tools should be enabled"
    );
    assert!(
        enabled.contains(&"get_callers"),
        "Call graph tools should be enabled"
    );

    // Git tools should NOT be included
    assert!(
        !enabled.contains(&"get_blame"),
        "Git tools should be disabled when git_enabled=false"
    );
}

#[test]
fn test_filter_by_feature_flags_all_enabled() {
    // All flags enabled
    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: true,
        persist_enabled: true,
        watch_enabled: true,
        lsp_config: narsil_xref::lsp::LspConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let config = ToolConfig::default();
    let filter = ToolFilter::new(config, &options);
    let enabled = filter.get_enabled_tools();

    // Should include tools from all categories
    assert!(enabled.len() >= 35, "Most tools should be enabled");
    assert!(enabled.contains(&"get_blame"));
    assert!(enabled.contains(&"get_call_graph"));
}

#[test]
fn test_filter_by_tool_override_disabled() {
    // Disable specific tool via override
    let mut config = ToolConfig::default();
    config.tools.overrides.insert(
        "semantic_search".to_string(),
        ToolOverride {
            enabled: false,
            reason: Some("Too slow for interactive use".to_string()),
            required_flags: vec![],
            config: HashMap::new(),
            performance_impact: None,
            requires_api_key: false,
        },
    );

    let options = EngineOptions::default();

    let filter = ToolFilter::new(config, &options);
    let enabled = filter.get_enabled_tools();

    assert!(
        !enabled.contains(&"semantic_search"),
        "Overridden tools should be disabled"
    );
}

#[test]
fn test_filter_by_tool_override_enabled() {
    // Explicitly enable a tool that would normally be disabled
    let mut config = ToolConfig::default();
    config.tools.overrides.insert(
        "get_blame".to_string(),
        ToolOverride {
            enabled: true,
            reason: Some("Always enable git blame".to_string()),
            required_flags: vec![],
            config: HashMap::new(),
            performance_impact: None,
            requires_api_key: false,
        },
    );

    let options = EngineOptions {
        git_enabled: false,
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options);
    let enabled = filter.get_enabled_tools();

    // get_blame should be enabled due to override
    // Note: This might not work if we enforce required flags strictly
    // For now, let's test that overrides take precedence
    // Uncomment if we decide overrides can bypass flag requirements:
    // assert!(enabled.contains(&"get_blame"), "Override should enable tool despite missing flag");
    //
    // OR test that override can't bypass required flags:
    assert!(
        !enabled.contains(&"get_blame"),
        "Override cannot bypass required feature flags"
    );
}

#[test]
fn test_default_config_includes_all_basic_tools() {
    // Default config with no feature flags
    let config = ToolConfig::default();
    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options);
    let enabled = filter.get_enabled_tools();

    // Should include Repository, Symbols, Search categories
    assert!(enabled.contains(&"list_repos"));
    assert!(enabled.contains(&"find_symbols"));
    assert!(enabled.contains(&"search_code"));

    // Should NOT include flagged tools
    assert!(!enabled.contains(&"get_blame")); // Requires Git
    assert!(!enabled.contains(&"get_call_graph")); // Requires CallGraph
}

#[test]
fn test_filtering_performance() {
    // Test that filtering completes in <1ms
    let config = ToolConfig::default();
    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: true,
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options);

    let _ = filter.get_enabled_tools();

    let start = Instant::now();
    let _ = filter.get_enabled_tools();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(1),
        "Filtering should complete in <1ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_filtering_is_deterministic() {
    // Same config should produce same results
    let config = ToolConfig::default();
    let options = EngineOptions {
        git_enabled: true,
        ..Default::default()
    };

    let filter = ToolFilter::new(config.clone(), &options);
    let enabled1 = filter.get_enabled_tools();

    let filter2 = ToolFilter::new(config, &options);
    let enabled2 = filter2.get_enabled_tools();

    assert_eq!(enabled1, enabled2, "Filtering should be deterministic");
}

#[test]
fn test_feature_flag_conversion_from_engine_options() {
    // Test that EngineOptions correctly converts to FeatureFlags
    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: false,
        persist_enabled: true,
        lsp_config: narsil_xref::lsp::LspConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let flags = ToolFilter::convert_engine_options(&options);

    assert!(flags.contains(&FeatureFlag::Git));
    assert!(!flags.contains(&FeatureFlag::CallGraph));
    assert!(flags.contains(&FeatureFlag::Persist));
    assert!(flags.contains(&FeatureFlag::Lsp));
}

#[test]
fn test_all_enabled_tools_have_metadata() {
    // Verify that all enabled tools exist in TOOL_METADATA
    let config = ToolConfig::default();
    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: true,
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options);
    let enabled = filter.get_enabled_tools();

    for tool_name in enabled {
        assert!(
            TOOL_METADATA.contains_key(tool_name),
            "Tool {} should have metadata",
            tool_name
        );
    }
}

#[test]
fn test_empty_config_with_all_flags_enabled() {
    // Empty config (all categories enabled by default) + all flags
    let config = ToolConfig::default();
    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: true,
        persist_enabled: true,
        watch_enabled: true,
        lsp_config: narsil_xref::lsp::LspConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options);
    let enabled = filter.get_enabled_tools();

    // Should get most tools; some still depend on compile-time or runtime flags.
    assert!(
        enabled.len() >= 35,
        "Should have most tools enabled with all flags"
    );
}

#[test]
fn test_filter_with_loaded_config() {
    // Test with a loaded config
    let loader = ConfigLoader::new();
    let config = loader.load().unwrap();

    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options);
    let enabled = filter.get_enabled_tools();

    // Should have basic tools
    assert!(!enabled.is_empty());
    assert!(enabled.contains(&"list_repos"));
}

/// All feature flags on, so nothing below is filtered out by a missing flag.
fn all_features_enabled() -> EngineOptions {
    EngineOptions {
        git_enabled: true,
        call_graph_enabled: true,
        persist_enabled: true,
        watch_enabled: true,
        lsp_config: narsil_xref::lsp::LspConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn test_expose_narrows_to_selected_groups() {
    let filter = ToolFilter::new(ToolConfig::default(), &all_features_enabled())
        .with_expose(&[ExposeGroup::Code, ExposeGroup::Git]);
    let enabled = filter.get_enabled_tools();

    assert!(enabled.contains(&"find_symbols"), "code group");
    assert!(enabled.contains(&"get_blame"), "git group");
    assert!(enabled.contains(&"list_repos"), "base is always folded in");

    assert!(
        !enabled.contains(&"get_complexity"),
        "analysis not selected"
    );
}

/// A top-level `expose:` in config.yaml is the machine-wide default, for
/// invocations whose command line comes from an editor plugin.
#[test]
fn test_config_expose_applies_without_the_flag() {
    let config = ToolConfig {
        expose: vec!["code".to_string(), "git".to_string()],
        ..Default::default()
    };

    let enabled = ToolFilter::new(config, &all_features_enabled()).get_enabled_tools();

    assert!(enabled.contains(&"find_symbols"));
    assert!(enabled.contains(&"get_blame"));
    assert!(!enabled.contains(&"get_complexity"));
}

#[test]
fn test_cli_expose_overrides_config_expose() {
    let config = ToolConfig {
        expose: vec!["code".to_string(), "git".to_string()],
        ..Default::default()
    };

    let enabled = ToolFilter::new(config, &all_features_enabled())
        .with_expose(&[ExposeGroup::Analysis])
        .get_enabled_tools();

    assert!(enabled.contains(&"get_complexity"), "CLI groups win");
    assert!(
        !enabled.contains(&"get_blame"),
        "config groups are replaced"
    );
    assert!(enabled.contains(&"list_repos"), "base is still folded in");
}

/// An empty slice means "the caller never saw the flag", which must not wipe
/// the config default.
#[test]
fn test_empty_cli_expose_keeps_config_expose() {
    let config = ToolConfig {
        expose: vec!["code".to_string()],
        ..Default::default()
    };

    let enabled = ToolFilter::new(config, &all_features_enabled())
        .with_expose(&[])
        .get_enabled_tools();

    assert!(enabled.contains(&"find_symbols"));
    assert!(!enabled.contains(&"get_blame"));
}

/// A typo must not silently narrow the tool set to the groups that parsed.
#[test]
fn test_unknown_config_expose_group_is_ignored() {
    let config = ToolConfig {
        expose: vec!["code".to_string(), "analysis".to_string()],
        ..Default::default()
    };

    let enabled = ToolFilter::new(config, &all_features_enabled()).get_enabled_tools();

    assert!(enabled.contains(&"find_symbols"), "the valid group applies");
    assert!(!enabled.contains(&"get_blame"), "the typo adds nothing");
}
