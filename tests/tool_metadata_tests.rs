/// Tests for tool metadata registry
///
/// These tests verify that all 76 tools have complete metadata
/// and that the metadata system works correctly.
use narsil_mcp::tool_metadata::{
    FeatureFlag, PerformanceImpact, StabilityLevel, ToolCategory, TOOL_METADATA,
};
use std::collections::HashSet;

#[test]
fn test_tool_metadata_complete() {
    // All 76 tools should have metadata
    assert_eq!(
        TOOL_METADATA.len(),
        76,
        "Expected 76 tools to have metadata"
    );

    // Each tool should have complete, valid metadata
    for (name, meta) in TOOL_METADATA.iter() {
        assert_eq!(
            meta.name, *name,
            "Tool name in metadata should match registry key"
        );
        assert!(
            !meta.description.is_empty(),
            "Tool {} should have a description",
            name
        );
        assert!(
            !meta.input_schema.is_null(),
            "Tool {} should have an input schema",
            name
        );

        // Verify input schema is a valid object
        assert!(
            meta.input_schema.is_object(),
            "Tool {} input schema should be an object",
            name
        );
        let schema = meta.input_schema.as_object().unwrap();
        assert!(
            schema.contains_key("type"),
            "Tool {} schema should have 'type' field",
            name
        );
        assert!(
            schema.contains_key("properties"),
            "Tool {} schema should have 'properties' field",
            name
        );
    }
}

#[test]
fn test_tool_categories_complete() {
    // Verify all expected categories are represented
    let categories: HashSet<ToolCategory> =
        TOOL_METADATA.values().map(|meta| meta.category).collect();

    assert!(categories.contains(&ToolCategory::Repository));
    assert!(categories.contains(&ToolCategory::Symbols));
    assert!(categories.contains(&ToolCategory::Search));
    assert!(categories.contains(&ToolCategory::CallGraph));
    assert!(categories.contains(&ToolCategory::Git));
    assert!(categories.contains(&ToolCategory::Lsp));
    assert!(categories.contains(&ToolCategory::Remote));
    assert!(categories.contains(&ToolCategory::Security));
    assert!(categories.contains(&ToolCategory::SupplyChain));
    assert!(categories.contains(&ToolCategory::Analysis));
}

#[test]
fn test_feature_flag_requirements() {
    // Git tools should require Git flag
    let git_tools = vec![
        "get_blame",
        "get_file_history",
        "get_recent_changes",
        "get_hotspots",
        "get_contributors",
        "get_commit_diff",
        "get_symbol_history",
        "get_branch_info",
        "get_modified_files",
    ];

    for tool_name in git_tools {
        let meta = TOOL_METADATA
            .get(tool_name)
            .unwrap_or_else(|| panic!("Git tool {} should have metadata", tool_name));
        assert!(
            meta.required_flags.contains(&FeatureFlag::Git),
            "Git tool {} should require Git flag",
            tool_name
        );
    }

    // Call graph tools should require CallGraph flag
    let callgraph_tools = vec![
        "get_call_graph",
        "get_callers",
        "get_callees",
        "find_call_path",
        "get_complexity",
        "get_function_hotspots",
    ];

    for tool_name in callgraph_tools {
        let meta = TOOL_METADATA
            .get(tool_name)
            .unwrap_or_else(|| panic!("CallGraph tool {} should have metadata", tool_name));
        assert!(
            meta.required_flags.contains(&FeatureFlag::CallGraph),
            "CallGraph tool {} should require CallGraph flag",
            tool_name
        );
    }
}

#[test]
fn test_tool_availability() {
    let mut enabled_flags = HashSet::new();
    enabled_flags.insert(FeatureFlag::Git);

    // Git tools should be available
    let git_meta = TOOL_METADATA.get("get_blame").unwrap();
    assert!(git_meta.is_available(&enabled_flags));

    // Call graph tools should NOT be available
    let callgraph_meta = TOOL_METADATA.get("get_call_graph").unwrap();
    assert!(!callgraph_meta.is_available(&enabled_flags));

    // Always-available tools should be available
    let repo_meta = TOOL_METADATA.get("list_repos").unwrap();
    assert!(repo_meta.is_available(&enabled_flags));
}

#[test]
fn test_tool_search_by_query() {
    // Search by name
    let list_repos = TOOL_METADATA.get("list_repos").unwrap();
    assert!(list_repos.matches_query("list"));
    assert!(list_repos.matches_query("repos"));

    // Search by description
    assert!(list_repos.matches_query("repository"));

    // Search by tag
    assert!(list_repos.matches_query("repository"));

    // Case insensitive
    assert!(list_repos.matches_query("LIST"));
    assert!(list_repos.matches_query("REPOS"));
}

#[test]
fn test_stability_levels() {
    // Count tools by stability level
    let stable_count = TOOL_METADATA
        .values()
        .filter(|meta| meta.stability == StabilityLevel::Stable)
        .count();

    // Most tools should be stable
    assert!(
        stable_count >= 60,
        "Most tools should be stable, got {}",
        stable_count
    );
}

#[test]
fn test_performance_indicators() {
    // Neural search should be marked as high performance impact
    let neural_search = TOOL_METADATA.get("neural_search");
    if let Some(meta) = neural_search {
        assert_eq!(
            meta.performance,
            PerformanceImpact::High,
            "neural_search should have high performance impact"
        );
    }

    // list_repos should be low performance impact
    let list_repos = TOOL_METADATA.get("list_repos").unwrap();
    assert_eq!(
        list_repos.performance,
        PerformanceImpact::Low,
        "list_repos should have low performance impact"
    );
}

#[test]
fn test_api_key_requirements() {
    // Neural tools should require API keys
    if let Some(neural_search) = TOOL_METADATA.get("neural_search") {
        assert!(
            neural_search.requires_api_key,
            "neural_search should require API key"
        );
    }

    // Most tools should NOT require API keys
    let list_repos = TOOL_METADATA.get("list_repos").unwrap();
    assert!(!list_repos.requires_api_key);
}

#[test]
fn test_tool_aliases() {
    // Verify aliases work for discoverability
    let list_repos = TOOL_METADATA.get("list_repos").unwrap();
    assert!(
        !list_repos.aliases.is_empty(),
        "list_repos should have aliases for discoverability"
    );
}

#[test]
fn test_category_counts() {
    // Verify expected tool counts per category
    let count_by_category = |cat: ToolCategory| {
        TOOL_METADATA
            .values()
            .filter(|meta| meta.category == cat)
            .count()
    };

    assert_eq!(
        count_by_category(ToolCategory::Repository),
        10,
        "Repository category should have 10 tools"
    );
    assert_eq!(
        count_by_category(ToolCategory::Symbols),
        7,
        "Symbols category should have 7 tools"
    );
    assert_eq!(
        count_by_category(ToolCategory::Search),
        12,
        "Search category should have 12 tools"
    );
    assert_eq!(
        count_by_category(ToolCategory::CallGraph),
        6,
        "CallGraph category should have 6 tools"
    );
    assert_eq!(
        count_by_category(ToolCategory::Git),
        9,
        "Git category should have 9 tools"
    );
    assert_eq!(
        count_by_category(ToolCategory::Lsp),
        3,
        "LSP category should have 3 tools"
    );
    assert_eq!(
        count_by_category(ToolCategory::Remote),
        3,
        "Remote category should have 3 tools"
    );
    assert_eq!(
        count_by_category(ToolCategory::Security),
        9,
        "Security category should have 9 tools"
    );
    assert_eq!(
        count_by_category(ToolCategory::SupplyChain),
        4,
        "SupplyChain category should have 4 tools"
    );
    assert_eq!(
        count_by_category(ToolCategory::Analysis),
        12,
        "Analysis category should have 12 tools"
    );
    // Graph category has 1-2 tools
    let graph_count = count_by_category(ToolCategory::Graph);
    assert!(
        (1..=2).contains(&graph_count),
        "Graph category should have 1-2 tools"
    );
}
