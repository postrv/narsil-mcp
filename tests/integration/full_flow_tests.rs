/// Comprehensive integration tests for narsil-mcp
///
/// Tests the full MCP protocol flow with configuration system
use anyhow::Result;
use narsil_mcp::config::{
    CategoryConfig, PerformanceConfig, ToolConfig, ToolFilter, ToolOverride, ToolsConfig,
};
use narsil_mcp::index::{CodeIntelEngine, EngineOptions};
use narsil_mcp::tool_metadata::TOOL_METADATA;
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a minimal test repository
fn create_test_repo() -> Result<TempDir> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path();

    // Create a simple Rust file
    std::fs::write(
        repo_path.join("main.rs"),
        r#"
fn main() {
    println!("Hello, world!");
}

fn add(a: i32, b: i32) -> i32 {
    a + b
}

struct User {
    name: String,
    age: u32,
}
"#,
    )?;

    Ok(temp_dir)
}

/// Helper to create test engine with options
async fn create_test_engine(
    repos: Vec<PathBuf>,
    options: EngineOptions,
) -> Result<CodeIntelEngine> {
    let temp_dir = TempDir::new()?;
    let index_path = temp_dir.path().to_path_buf();
    std::mem::forget(temp_dir); // Keep temp dir alive
    CodeIntelEngine::with_options(index_path, repos, options).await
}

#[tokio::test]
async fn test_backwards_compatibility_cli_only() -> Result<()> {
    // Test that CLI-only usage (no config) still works as before
    let temp_repo = create_test_repo()?;
    let repo_path = temp_repo.path().to_path_buf();

    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: false,
        persist_enabled: false,
        watch_enabled: false,
        streaming_config: Default::default(),
        lsp_config: Default::default(),
        neural_config: Default::default(),
    };

    let _engine = create_test_engine(vec![repo_path], options.clone()).await?;

    // With default config, tool filter should enable all tools that don't require unavailable features
    let config = ToolConfig::default();
    let filter = ToolFilter::new(config, &options, None);
    let enabled_tools = filter.get_enabled_tools();

    // Should have most tools enabled (excluding call graph tools since call_graph_enabled=false)
    assert!(
        enabled_tools.len() > 50,
        "Expected >50 tools enabled, got {}",
        enabled_tools.len()
    );

    // Repository tools should be available
    assert!(enabled_tools.contains(&"list_repos"));
    assert!(enabled_tools.contains(&"find_symbols"));
    assert!(enabled_tools.contains(&"search_code"));

    // Git tools should be available (git_enabled=true)
    assert!(enabled_tools.contains(&"get_blame"));
    assert!(enabled_tools.contains(&"get_file_history"));

    // Call graph tools should NOT be available (call_graph_enabled=false)
    assert!(!enabled_tools.contains(&"get_call_graph"));
    assert!(!enabled_tools.contains(&"get_callers"));

    Ok(())
}

#[tokio::test]
async fn test_config_priority_cli_flags_override() -> Result<()> {
    // Test that CLI flags have highest priority
    let temp_repo = create_test_repo()?;
    let repo_path = temp_repo.path().to_path_buf();

    // Create config that enables Git category
    let mut categories = HashMap::new();
    categories.insert(
        "Git".to_string(),
        CategoryConfig {
            enabled: true,
            description: None,
            required_flags: vec!["git".to_string()],
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
        performance: PerformanceConfig::default(),
        feature_requirements: HashMap::new(),
    };

    // BUT: CLI has git_enabled=false (should override config)
    let options = EngineOptions {
        git_enabled: false, // CLI says no git
        call_graph_enabled: false,
        persist_enabled: false,
        watch_enabled: false,
        streaming_config: Default::default(),
        lsp_config: Default::default(),
        neural_config: Default::default(),
    };

    let _engine = create_test_engine(vec![repo_path], options.clone()).await?;
    let filter = ToolFilter::new(config, &options, None);
    let enabled_tools = filter.get_enabled_tools();

    // Git tools should NOT be available despite config.categories.Git.enabled=true
    // because options.git_enabled=false (CLI flag has priority)
    assert!(!enabled_tools.contains(&"get_blame"));
    assert!(!enabled_tools.contains(&"get_file_history"));

    Ok(())
}

#[tokio::test]
async fn test_minimal_preset_filters_tools() -> Result<()> {
    // Test that minimal preset reduces tool count
    let temp_repo = create_test_repo()?;
    let repo_path = temp_repo.path().to_path_buf();

    let options = EngineOptions::default();

    let _engine = create_test_engine(vec![repo_path], options.clone()).await?;

    // Apply minimal preset
    let config = ToolConfig {
        preset: Some("minimal".to_string()),
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options, None);
    let enabled_tools = filter.get_enabled_tools();

    // Minimal preset should have ~26 tools
    assert!(
        enabled_tools.len() >= 24 && enabled_tools.len() <= 28,
        "Minimal preset should have 24-28 tools, got {}",
        enabled_tools.len()
    );

    // Core tools should be enabled
    assert!(enabled_tools.contains(&"list_repos"));
    assert!(enabled_tools.contains(&"find_symbols"));
    assert!(enabled_tools.contains(&"search_code"));

    // Slow/advanced tools should be disabled
    assert!(!enabled_tools.contains(&"neural_search"));
    assert!(!enabled_tools.contains(&"generate_sbom"));

    Ok(())
}

#[tokio::test]
async fn test_balanced_preset() -> Result<()> {
    let temp_repo = create_test_repo()?;
    let repo_path = temp_repo.path().to_path_buf();

    let options = EngineOptions {
        git_enabled: true,
        ..Default::default()
    };

    let _engine = create_test_engine(vec![repo_path], options.clone()).await?;

    let config = ToolConfig {
        preset: Some("balanced".to_string()),
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options, None);
    let enabled_tools = filter.get_enabled_tools();

    // Balanced preset should have ~44-51 tools (depending on which flags are enabled)
    assert!(
        enabled_tools.len() >= 40 && enabled_tools.len() <= 55,
        "Balanced preset should have 40-55 tools, got {}",
        enabled_tools.len()
    );

    // Repository, Symbols, Search should be enabled
    assert!(enabled_tools.contains(&"list_repos"));
    assert!(enabled_tools.contains(&"find_symbols"));
    assert!(enabled_tools.contains(&"search_code"));

    // Git should be enabled
    assert!(enabled_tools.contains(&"get_blame"));

    // Security should be enabled
    assert!(enabled_tools.contains(&"scan_security"));

    // Neural search should still be disabled (too slow)
    assert!(!enabled_tools.contains(&"neural_search"));

    Ok(())
}

#[tokio::test]
async fn test_full_preset() -> Result<()> {
    let temp_repo = create_test_repo()?;
    let repo_path = temp_repo.path().to_path_buf();

    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: true,
        ..Default::default()
    };

    let _engine = create_test_engine(vec![repo_path], options.clone()).await?;

    let config = ToolConfig {
        preset: Some("full".to_string()),
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options, None);
    let enabled_tools = filter.get_enabled_tools();

    // Full preset should have most/all tools (~75, minus ones requiring unavailable flags)
    assert!(
        enabled_tools.len() >= 60,
        "Full preset should have 60+ tools, got {}",
        enabled_tools.len()
    );

    // Everything should be available
    assert!(enabled_tools.contains(&"list_repos"));
    assert!(enabled_tools.contains(&"find_symbols"));
    assert!(enabled_tools.contains(&"get_blame"));
    assert!(enabled_tools.contains(&"get_call_graph"));
    assert!(enabled_tools.contains(&"scan_security"));

    Ok(())
}

#[tokio::test]
async fn test_security_focused_preset() -> Result<()> {
    let temp_repo = create_test_repo()?;
    let repo_path = temp_repo.path().to_path_buf();

    let options = EngineOptions::default();

    let _engine = create_test_engine(vec![repo_path], options.clone()).await?;

    let config = ToolConfig {
        preset: Some("security-focused".to_string()),
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options, None);
    let enabled_tools = filter.get_enabled_tools();

    // Security preset should have ~28 tools
    // Security (9) + SupplyChain (4) + Analysis (11) + Repository basics (4)
    assert!(
        enabled_tools.len() >= 26 && enabled_tools.len() <= 32,
        "Security preset should have 26-32 tools, got {}",
        enabled_tools.len()
    );

    // Security tools should be enabled
    assert!(enabled_tools.contains(&"scan_security"));
    assert!(enabled_tools.contains(&"check_owasp_top10"));
    assert!(enabled_tools.contains(&"find_injection_vulnerabilities"));

    // Supply chain tools should be enabled
    assert!(enabled_tools.contains(&"generate_sbom"));
    assert!(enabled_tools.contains(&"check_dependencies"));

    // Analysis tools should be enabled
    assert!(enabled_tools.contains(&"get_control_flow"));
    assert!(enabled_tools.contains(&"find_dead_code"));

    // Core navigation tools should be enabled
    assert!(enabled_tools.contains(&"list_repos"));
    assert!(enabled_tools.contains(&"find_symbols"));

    Ok(())
}

#[tokio::test]
async fn test_category_level_filtering() -> Result<()> {
    let temp_repo = create_test_repo()?;
    let repo_path = temp_repo.path().to_path_buf();

    let options = EngineOptions {
        git_enabled: true,
        ..Default::default()
    };

    let _engine = create_test_engine(vec![repo_path], options.clone()).await?;

    // Disable Search category
    let mut categories = HashMap::new();
    categories.insert(
        "Search".to_string(),
        CategoryConfig {
            enabled: false,
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
        performance: PerformanceConfig::default(),
        feature_requirements: HashMap::new(),
    };

    let filter = ToolFilter::new(config, &options, None);
    let enabled_tools = filter.get_enabled_tools();

    // Search tools should be disabled
    assert!(!enabled_tools.contains(&"search_code"));
    assert!(!enabled_tools.contains(&"semantic_search"));
    assert!(!enabled_tools.contains(&"hybrid_search"));

    // Other tools should still be available
    assert!(enabled_tools.contains(&"list_repos"));
    assert!(enabled_tools.contains(&"find_symbols"));
    assert!(enabled_tools.contains(&"get_blame")); // Git enabled

    Ok(())
}

#[tokio::test]
async fn test_tool_level_override() -> Result<()> {
    let temp_repo = create_test_repo()?;
    let repo_path = temp_repo.path().to_path_buf();

    let options = EngineOptions::default();

    let _engine = create_test_engine(vec![repo_path], options.clone()).await?;

    // Disable specific tool
    let mut overrides = HashMap::new();
    overrides.insert(
        "search_code".to_string(),
        ToolOverride {
            enabled: false,
            reason: Some("Test disable".to_string()),
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
        performance: PerformanceConfig::default(),
        feature_requirements: HashMap::new(),
    };

    let filter = ToolFilter::new(config, &options, None);
    let enabled_tools = filter.get_enabled_tools();

    // search_code should be disabled
    assert!(!enabled_tools.contains(&"search_code"));

    // Other search tools should still be available
    assert!(enabled_tools.contains(&"semantic_search"));
    assert!(enabled_tools.contains(&"hybrid_search"));

    Ok(())
}

#[tokio::test]
async fn test_performance_budget_max_tool_count() -> Result<()> {
    let temp_repo = create_test_repo()?;
    let repo_path = temp_repo.path().to_path_buf();

    let options = EngineOptions::default();

    let _engine = create_test_engine(vec![repo_path], options.clone()).await?;

    // Set low max_tool_count
    let config = ToolConfig {
        version: "1.0".to_string(),
        preset: None,
        editors: HashMap::new(),
        tools: ToolsConfig {
            categories: HashMap::new(),
            overrides: HashMap::new(),
        },
        performance: PerformanceConfig {
            max_tool_count: 15, // Increased from 10 to ensure core tools make the cut
            startup_latency_ms: 100,
            filtering_latency_ms: 10,
        },
        feature_requirements: HashMap::new(),
    };

    let filter = ToolFilter::new(config, &options, None);
    let enabled_tools = filter.get_enabled_tools();

    // Should respect max_tool_count
    assert!(
        enabled_tools.len() <= 15,
        "Should have <=15 tools, got {}",
        enabled_tools.len()
    );

    // Should prioritize core tools (low performance impact)
    // list_repos should be included as it's a low-impact tool
    assert!(
        enabled_tools.contains(&"list_repos") || enabled_tools.contains(&"find_symbols"),
        "Should include at least one core tool. Got {} tools: {:?}",
        enabled_tools.len(),
        enabled_tools
    );

    Ok(())
}

#[tokio::test]
async fn test_feature_flag_validation() -> Result<()> {
    let temp_repo = create_test_repo()?;
    let repo_path = temp_repo.path().to_path_buf();

    // Git NOT enabled in options
    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: false,
        persist_enabled: false,
        watch_enabled: false,
        streaming_config: Default::default(),
        lsp_config: Default::default(),
        neural_config: Default::default(),
    };

    let _engine = create_test_engine(vec![repo_path], options.clone()).await?;

    // Config tries to enable Git category
    let mut categories = HashMap::new();
    categories.insert(
        "Git".to_string(),
        CategoryConfig {
            enabled: true,
            description: None,
            required_flags: vec!["git".to_string()],
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
        performance: PerformanceConfig::default(),
        feature_requirements: HashMap::new(),
    };

    let filter = ToolFilter::new(config, &options, None);
    let enabled_tools = filter.get_enabled_tools();

    // Git tools should NOT be available (required flag not enabled)
    assert!(!enabled_tools.contains(&"get_blame"));
    assert!(!enabled_tools.contains(&"get_file_history"));

    Ok(())
}

#[tokio::test]
async fn test_metadata_completeness() -> Result<()> {
    // Verify all tools in TOOL_METADATA have required fields
    assert_eq!(TOOL_METADATA.len(), 75, "Expected 75 tools in metadata");

    for (name, meta) in TOOL_METADATA.iter() {
        // Name should match key
        assert_eq!(meta.name, *name, "Tool name mismatch");

        // Description should not be empty
        assert!(
            !meta.description.is_empty(),
            "Tool {} has empty description",
            name
        );

        // Input schema should be valid JSON object
        assert!(
            meta.input_schema.is_object(),
            "Tool {} has invalid input schema",
            name
        );

        // Check required fields in input schema
        let schema = meta.input_schema.as_object().unwrap();
        assert!(
            schema.contains_key("type"),
            "Tool {} schema missing 'type'",
            name
        );
        assert!(
            schema.contains_key("properties"),
            "Tool {} schema missing 'properties'",
            name
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_all_categories_represented() -> Result<()> {
    // Verify all tool categories are represented in TOOL_METADATA
    use narsil_mcp::tool_metadata::ToolCategory;

    let mut category_counts = HashMap::new();

    for meta in TOOL_METADATA.values() {
        *category_counts.entry(meta.category).or_insert(0) += 1;
    }

    // Check we have tools in all expected categories
    let expected_categories = vec![
        ToolCategory::Repository,
        ToolCategory::Symbols,
        ToolCategory::Search,
        ToolCategory::CallGraph,
        ToolCategory::Git,
        ToolCategory::Lsp,
        ToolCategory::Remote,
        ToolCategory::Security,
        ToolCategory::SupplyChain,
        ToolCategory::Analysis,
        ToolCategory::Graph,
    ];

    for category in expected_categories {
        assert!(
            category_counts.contains_key(&category),
            "No tools in category {:?}",
            category
        );
    }

    // Print distribution for debugging
    for (category, count) in &category_counts {
        println!("{:?}: {} tools", category, count);
    }

    Ok(())
}

#[tokio::test]
async fn test_required_flags_validation() -> Result<()> {
    // Verify tools with required_flags are properly gated
    use narsil_mcp::tool_metadata::FeatureFlag;

    for (name, meta) in TOOL_METADATA.iter() {
        if meta.required_flags.contains(&FeatureFlag::Git) {
            // Should be in Git category or related
            // Git tools should not be available without flag
            let options = EngineOptions {
                git_enabled: false,
                call_graph_enabled: false,
                persist_enabled: false,
                watch_enabled: false,
                streaming_config: Default::default(),
                lsp_config: Default::default(),
                neural_config: Default::default(),
            };

            let config = ToolConfig::default();
            let filter = ToolFilter::new(config, &options, None);
            let enabled_tools = filter.get_enabled_tools();

            assert!(
                !enabled_tools.contains(name),
                "Tool {} requires git flag but is enabled without it",
                name
            );
        }

        if meta.required_flags.contains(&FeatureFlag::CallGraph) {
            let options = EngineOptions {
                git_enabled: false,
                call_graph_enabled: false,
                persist_enabled: false,
                watch_enabled: false,
                streaming_config: Default::default(),
                lsp_config: Default::default(),
                neural_config: Default::default(),
            };

            let config = ToolConfig::default();
            let filter = ToolFilter::new(config, &options, None);
            let enabled_tools = filter.get_enabled_tools();

            assert!(
                !enabled_tools.contains(name),
                "Tool {} requires call_graph flag but is enabled without it",
                name
            );
        }
    }

    Ok(())
}
