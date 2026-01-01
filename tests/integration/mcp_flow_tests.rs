/// End-to-end MCP protocol flow tests
///
/// These tests verify the complete MCP interaction flow:
/// 1. Server initialization
/// 2. Client identification
/// 3. Tools list request
/// 4. Filtered tool response
use narsil_mcp::config::{ClientInfo, ConfigLoader, ToolFilter};
use narsil_mcp::index::EngineOptions;
use narsil_mcp::tool_metadata::TOOL_METADATA;

/// Test that the full MCP flow works correctly with VS Code
#[test]
fn test_full_mcp_flow_vscode() {
    // Simulate MCP initialize with VS Code client info
    let client_info = ClientInfo {
        name: "vscode".to_string(),
        version: Some("1.85.0".to_string()),
    };

    // Load config
    let config = ConfigLoader::new().load().unwrap();

    // Create engine options (default - no special flags)
    let options = EngineOptions::default();

    // Create tool filter (this happens in handle_tools_list)
    let filter = ToolFilter::new(config, &options, Some(client_info));

    // Get enabled tools
    let enabled_tools = filter.get_enabled_tools();

    // VS Code should get balanced preset (30-40 tools without feature flags)
    assert!(
        enabled_tools.len() >= 30 && enabled_tools.len() <= 40,
        "VS Code should get 30-40 tools in balanced preset (without flags), got {}",
        enabled_tools.len()
    );

    // Verify essential tools are present
    assert!(enabled_tools.contains(&"list_repos"));
    assert!(enabled_tools.contains(&"find_symbols"));
    assert!(enabled_tools.contains(&"search_code"));

    // Verify slow tools are excluded
    assert!(!enabled_tools.contains(&"neural_search"));
}

/// Test that the full MCP flow works correctly with Zed
#[test]
fn test_full_mcp_flow_zed() {
    let client_info = ClientInfo {
        name: "zed".to_string(),
        version: Some("0.120.0".to_string()),
    };

    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));

    let enabled_tools = filter.get_enabled_tools();

    // Zed should get minimal preset (20-30 tools)
    assert!(
        enabled_tools.len() >= 20 && enabled_tools.len() <= 30,
        "Zed should get 20-30 tools in minimal preset, got {}",
        enabled_tools.len()
    );

    // Essential tools present
    assert!(enabled_tools.contains(&"list_repos"));
    assert!(enabled_tools.contains(&"find_symbols"));

    // Git tools excluded (not in minimal)
    assert!(!enabled_tools.contains(&"get_blame"));

    // Security tools excluded
    assert!(!enabled_tools.contains(&"scan_security"));
}

/// Test that the full MCP flow works correctly with Claude Desktop
#[test]
fn test_full_mcp_flow_claude_desktop() {
    let client_info = ClientInfo {
        name: "claude-desktop".to_string(),
        version: Some("1.0.0".to_string()),
    };

    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));

    let enabled_tools = filter.get_enabled_tools();

    // Claude Desktop should get full preset (50-60 tools without feature flags)
    assert!(
        enabled_tools.len() >= 50 && enabled_tools.len() <= 60,
        "Claude Desktop should get 50-60 tools in full preset (without flags), got {}",
        enabled_tools.len()
    );

    // All tool types should be available
    assert!(enabled_tools.contains(&"list_repos"));
    assert!(enabled_tools.contains(&"find_symbols"));
    assert!(enabled_tools.contains(&"search_code"));
    assert!(enabled_tools.contains(&"semantic_search"));
    assert!(enabled_tools.contains(&"scan_security"));
}

/// Test that feature flags still work with presets
#[test]
fn test_mcp_flow_with_git_enabled() {
    let client_info = ClientInfo {
        name: "vscode".to_string(),
        version: None,
    };

    let config = ConfigLoader::new().load().unwrap();

    let options = EngineOptions {
        git_enabled: true,
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options, Some(client_info));
    let enabled_tools = filter.get_enabled_tools();

    // Git tools should be available with --git flag
    assert!(
        enabled_tools.contains(&"get_blame"),
        "Git tools should be enabled with --git flag"
    );
    assert!(enabled_tools.contains(&"get_file_history"));
}

/// Test that feature flags are respected even with presets
#[test]
fn test_mcp_flow_git_disabled_despite_preset() {
    let client_info = ClientInfo {
        name: "claude-desktop".to_string(), // Full preset
        version: None,
    };

    let config = ConfigLoader::new().load().unwrap();

    let options = EngineOptions {
        git_enabled: false,
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options, Some(client_info));
    let enabled_tools = filter.get_enabled_tools();

    // Git tools should NOT be available even with full preset
    assert!(
        !enabled_tools.contains(&"get_blame"),
        "Git tools should respect feature flags even in full preset"
    );
    assert!(!enabled_tools.contains(&"get_file_history"));
}

/// Test backward compatibility - no client info should work
#[test]
fn test_mcp_flow_no_client_info() {
    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();

    // No client info = None
    let filter = ToolFilter::new(config, &options, None);
    let enabled_tools = filter.get_enabled_tools();

    // Should default to full preset (50-60 tools without flags)
    assert!(
        enabled_tools.len() >= 50 && enabled_tools.len() <= 60,
        "No client info should default to full preset, got {}",
        enabled_tools.len()
    );
}

/// Test that all tools have valid metadata
#[test]
fn test_all_tools_have_metadata() {
    // This verifies that every tool we might return has metadata
    for (tool_name, _) in TOOL_METADATA.iter() {
        assert!(!tool_name.is_empty(), "Tool name should not be empty");
    }

    // Verify we have a reasonable number of tools
    assert!(
        TOOL_METADATA.len() >= 70,
        "Should have at least 70 tools in metadata"
    );
}

/// Test that presets respect performance budgets
#[test]
fn test_performance_budget_with_presets() {
    use narsil_mcp::config::schema::ToolConfig;

    let client_info = ClientInfo {
        name: "claude-desktop".to_string(), // Full preset
        version: None,
    };

    let mut config = ToolConfig::default();
    config.performance.max_tool_count = 30; // Strict budget

    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));
    let enabled_tools = filter.get_enabled_tools();

    // Should respect budget even with full preset
    assert!(
        enabled_tools.len() <= 30,
        "Performance budget should override preset, got {} tools",
        enabled_tools.len()
    );
}

/// Test sequential client detection (simulate server reuse)
#[test]
fn test_multiple_clients_sequential() {
    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();

    // First client: VS Code
    let vscode_client = ClientInfo {
        name: "vscode".to_string(),
        version: None,
    };
    let filter1 = ToolFilter::new(config.clone(), &options, Some(vscode_client));
    let vscode_tools = filter1.get_enabled_tools();

    // Second client: Zed
    let zed_client = ClientInfo {
        name: "zed".to_string(),
        version: None,
    };
    let filter2 = ToolFilter::new(config.clone(), &options, Some(zed_client));
    let zed_tools = filter2.get_enabled_tools();

    // They should get different tool counts
    assert_ne!(
        vscode_tools.len(),
        zed_tools.len(),
        "Different editors should get different tool counts"
    );

    // VS Code should have more tools than Zed
    assert!(
        vscode_tools.len() > zed_tools.len(),
        "VS Code (balanced) should have more tools than Zed (minimal)"
    );
}

/// Test that JetBrains IDEs get balanced preset
#[test]
fn test_jetbrains_ides() {
    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();

    for ide in &["intellij", "pycharm", "webstorm", "rustrover"] {
        let client_info = ClientInfo {
            name: ide.to_string(),
            version: None,
        };

        let filter = ToolFilter::new(config.clone(), &options, Some(client_info.clone()));
        let enabled_tools = filter.get_enabled_tools();

        assert!(
            enabled_tools.len() >= 30 && enabled_tools.len() <= 40,
            "{} should get balanced preset (without flags), got {} tools",
            ide,
            enabled_tools.len()
        );
    }
}

/// Test that Vim/Neovim get minimal preset
#[test]
fn test_vim_editors() {
    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();

    for editor in &["vim", "nvim", "neovim"] {
        let client_info = ClientInfo {
            name: editor.to_string(),
            version: None,
        };

        let filter = ToolFilter::new(config.clone(), &options, Some(client_info.clone()));
        let enabled_tools = filter.get_enabled_tools();

        assert!(
            enabled_tools.len() >= 20 && enabled_tools.len() <= 30,
            "{} should get minimal preset, got {} tools",
            editor,
            enabled_tools.len()
        );
    }
}

/// Test that CLI --preset flag overrides editor-based preset detection
///
/// This tests the behavior added for Issue #: CLI preset flag should
/// take priority over automatic editor detection.
#[test]
fn test_cli_preset_overrides_editor_detection() {
    use narsil_mcp::config::schema::ToolConfig;

    // Simulate Zed (would normally get minimal preset)
    let client_info = ClientInfo {
        name: "zed".to_string(),
        version: Some("0.120.0".to_string()),
    };

    // But config has preset=full (simulating --preset full CLI flag)
    let config = ToolConfig {
        preset: Some("full".to_string()),
        ..Default::default()
    };

    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));
    let enabled_tools = filter.get_enabled_tools();

    // Should get full preset (50-60 tools), NOT minimal preset (20-30)
    assert!(
        enabled_tools.len() >= 50 && enabled_tools.len() <= 60,
        "CLI preset=full should override Zed's default minimal preset, got {} tools",
        enabled_tools.len()
    );
}

/// Test that CLI --preset flag works with all valid presets
#[test]
fn test_cli_preset_all_values() {
    use narsil_mcp::config::schema::ToolConfig;

    let options = EngineOptions::default();

    // Test minimal preset via CLI
    let config = ToolConfig {
        preset: Some("minimal".to_string()),
        ..Default::default()
    };
    let filter = ToolFilter::new(config, &options, None);
    let minimal_tools = filter.get_enabled_tools();
    assert!(
        minimal_tools.len() >= 20 && minimal_tools.len() <= 30,
        "minimal preset should have 20-30 tools, got {}",
        minimal_tools.len()
    );

    // Test balanced preset via CLI
    let config = ToolConfig {
        preset: Some("balanced".to_string()),
        ..Default::default()
    };
    let filter = ToolFilter::new(config, &options, None);
    let balanced_tools = filter.get_enabled_tools();
    assert!(
        balanced_tools.len() >= 30 && balanced_tools.len() <= 50,
        "balanced preset should have 30-50 tools, got {}",
        balanced_tools.len()
    );

    // Test full preset via CLI
    let config = ToolConfig {
        preset: Some("full".to_string()),
        ..Default::default()
    };
    let filter = ToolFilter::new(config, &options, None);
    let full_tools = filter.get_enabled_tools();
    assert!(
        full_tools.len() >= 50 && full_tools.len() <= 60,
        "full preset should have 50-60 tools, got {}",
        full_tools.len()
    );

    // Test security-focused preset via CLI
    let config = ToolConfig {
        preset: Some("security-focused".to_string()),
        ..Default::default()
    };
    let filter = ToolFilter::new(config, &options, None);
    let security_tools = filter.get_enabled_tools();
    assert!(
        security_tools.len() >= 25 && security_tools.len() <= 40,
        "security-focused preset should have 25-40 tools, got {}",
        security_tools.len()
    );
}

/// Test that CLI --preset with invalid value falls back to full
#[test]
fn test_cli_preset_invalid_value_fallback() {
    use narsil_mcp::config::schema::ToolConfig;

    let config = ToolConfig {
        preset: Some("invalid-preset-name".to_string()),
        ..Default::default()
    };

    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, None);
    let enabled_tools = filter.get_enabled_tools();

    // Invalid preset should fall back to Full
    assert!(
        enabled_tools.len() >= 50 && enabled_tools.len() <= 60,
        "Invalid preset should fall back to Full, got {} tools",
        enabled_tools.len()
    );
}

/// Test preset priority: CLI preset > config file preset > editor detection
#[test]
fn test_preset_priority_chain() {
    use narsil_mcp::config::schema::ToolConfig;

    // Claude Desktop (would get full preset via editor detection)
    let client_info = ClientInfo {
        name: "claude-desktop".to_string(),
        version: None,
    };

    // Config specifies minimal (simulating --preset minimal CLI flag)
    let config = ToolConfig {
        preset: Some("minimal".to_string()),
        ..Default::default()
    };

    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));
    let enabled_tools = filter.get_enabled_tools();

    // Config preset should win over Claude Desktop's default full preset
    assert!(
        enabled_tools.len() >= 20 && enabled_tools.len() <= 30,
        "Config preset (minimal) should override Claude Desktop (full), got {} tools",
        enabled_tools.len()
    );
}
