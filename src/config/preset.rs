/// Preset configurations for different use cases
///
/// Presets define curated tool selections optimized for specific scenarios:
/// - **Minimal**: Fast, lightweight (Zed, quick edits) - 20-30 tools
/// - **Balanced**: Good defaults (VS Code, IntelliJ) - 40-50 tools
/// - **Full**: Everything (Claude Desktop, analysis) - 70+ tools
/// - **SecurityFocused**: Security and supply chain tools - ~30 tools
use std::collections::HashSet;

/// Available preset configurations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Preset {
    /// Minimal tool set - essential tools only (20-30 tools)
    /// - Repository operations
    /// - Symbol search
    /// - Basic code search
    Minimal,

    /// Balanced tool set - good defaults for most IDEs (40-50 tools)
    /// - All Minimal tools
    /// - Git integration
    /// - LSP integration
    /// - Some security tools
    Balanced,

    /// Full tool set - all available tools (70+ tools)
    /// - All tools enabled
    Full,

    /// Security-focused tool set - security and supply chain (~30 tools)
    /// - Repository basics
    /// - Security scanning
    /// - Supply chain analysis
    /// - Code analysis
    SecurityFocused,
}

impl Preset {
    /// Parse a preset from a string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "minimal" => Some(Preset::Minimal),
            "balanced" => Some(Preset::Balanced),
            "full" => Some(Preset::Full),
            "security-focused" | "security_focused" => Some(Preset::SecurityFocused),
            _ => None,
        }
    }

    /// Get the set of enabled tool names for this preset
    ///
    /// Returns a HashSet of tool names that should be enabled.
    /// Tools not in this set will be filtered out (unless required by feature flags).
    pub fn get_enabled_tools(&self) -> HashSet<&'static str> {
        match self {
            Preset::Minimal => Self::minimal_tools(),
            Preset::Balanced => Self::balanced_tools(),
            Preset::Full => Self::full_tools(),
            Preset::SecurityFocused => Self::security_focused_tools(),
        }
    }

    /// Get the set of explicitly disabled tools for this preset
    ///
    /// These tools will be disabled even if they would otherwise be enabled
    /// by category or feature flags.
    pub fn get_disabled_tools(&self) -> HashSet<&'static str> {
        match self {
            Preset::Minimal => {
                // Disable slow/advanced tools
                [
                    "neural_search",
                    "find_semantic_clones",
                    "generate_sbom",
                    "check_dependencies",
                    "check_licenses",
                    "scan_security",
                    "check_owasp_top10",
                    "check_cwe_top25",
                ]
                .iter()
                .copied()
                .collect()
            }
            Preset::Balanced => {
                // Disable only the slowest tools
                ["neural_search", "find_semantic_clones"]
                    .iter()
                    .copied()
                    .collect()
            }
            Preset::Full => HashSet::new(), // Nothing disabled
            Preset::SecurityFocused => {
                // Disable neural and some graph tools
                ["neural_search", "find_semantic_clones", "get_call_graph"]
                    .iter()
                    .copied()
                    .collect()
            }
        }
    }

    /// Minimal preset tools (20-30 tools)
    fn minimal_tools() -> HashSet<&'static str> {
        [
            // Repository & Files (10 tools)
            "list_repos",
            "get_project_structure",
            "get_file",
            "get_excerpt",
            "reindex",
            "discover_repos",
            "validate_repo",
            "get_index_status",
            "get_incremental_status",
            "get_metrics",
            // Symbols (7 tools)
            "find_symbols",
            "get_symbol_definition",
            "find_references",
            "get_dependencies",
            "find_symbol_usages",
            "get_export_map",
            "workspace_symbol_search",
            // Search (basic, 6 tools)
            "search_code",
            "semantic_search",
            "hybrid_search",
            "search_chunks",
            "get_chunk_stats",
            "get_chunks",
            // LSP (3 tools - basic, not dependent on --lsp flag)
            "get_hover_info",
            "get_type_info",
            "go_to_definition",
        ]
        .iter()
        .copied()
        .collect()
    }

    /// Balanced preset tools (40-50 tools)
    fn balanced_tools() -> HashSet<&'static str> {
        let mut tools = Self::minimal_tools();

        // Add git tools (requires --git flag)
        tools.extend([
            "get_blame",
            "get_file_history",
            "get_recent_changes",
            "get_hotspots",
            "get_contributors",
            "get_commit_diff",
            "get_symbol_history",
            "get_branch_info",
            "get_modified_files",
        ]);

        // Add more search tools
        tools.extend([
            "find_similar_code",
            "find_similar_to_symbol",
            "get_embedding_stats",
        ]);

        // Add some call graph tools (requires --call-graph flag)
        tools.extend([
            "get_call_graph",
            "get_callers",
            "get_callees",
            "find_call_path",
            "get_complexity",
            "get_function_hotspots",
        ]);

        // Add security essentials
        tools.extend(["scan_security", "find_injection_vulnerabilities"]);

        // Add code analysis basics
        tools.extend([
            "get_control_flow",
            "find_dead_code",
            "get_data_flow",
            "get_import_graph",
            "find_circular_imports",
            "review_change",
            "impact_of",
            "security_gate",
        ]);

        tools
    }

    /// Full preset tools (70+ tools) - all tools
    fn full_tools() -> HashSet<&'static str> {
        // Return empty set to signal "enable all"
        // ToolFilter will interpret this specially
        HashSet::new()
    }

    /// Security-focused preset tools (~30 tools)
    fn security_focused_tools() -> HashSet<&'static str> {
        [
            // Repository basics
            "list_repos",
            "get_project_structure",
            "get_file",
            "get_excerpt",
            "get_index_status",
            // Symbols for analysis
            "find_symbols",
            "get_symbol_definition",
            "find_references",
            // Search
            "search_code",
            "search_chunks",
            // Security tools (9)
            "scan_security",
            "check_owasp_top10",
            "check_cwe_top25",
            "find_injection_vulnerabilities",
            "trace_taint",
            "get_taint_sources",
            "get_security_summary",
            "explain_vulnerability",
            "suggest_fix",
            // Supply chain (4)
            "generate_sbom",
            "check_dependencies",
            "check_licenses",
            "find_upgrade_path",
            // Code analysis (useful for security)
            "get_control_flow",
            "find_dead_code",
            "get_data_flow",
            "get_reaching_definitions",
            "find_uninitialized",
            "find_dead_stores",
            "infer_types",
            "check_type_errors",
            "get_typed_taint_flow",
            "review_change",
            "security_gate",
        ]
        .iter()
        .copied()
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_preset_size() {
        let tools = Preset::Minimal.get_enabled_tools();
        assert!(
            tools.len() >= 20 && tools.len() <= 30,
            "Minimal preset should have 20-30 tools, got {}",
            tools.len()
        );
    }

    #[test]
    fn test_balanced_preset_size() {
        let tools = Preset::Balanced.get_enabled_tools();
        assert!(
            tools.len() >= 40 && tools.len() <= 60,
            "Balanced preset should have 40-60 tools, got {}",
            tools.len()
        );
    }

    #[test]
    fn test_minimal_includes_essentials() {
        let tools = Preset::Minimal.get_enabled_tools();
        assert!(tools.contains(&"list_repos"));
        assert!(tools.contains(&"find_symbols"));
        assert!(tools.contains(&"search_code"));
    }

    #[test]
    fn test_minimal_excludes_advanced() {
        let disabled = Preset::Minimal.get_disabled_tools();
        assert!(disabled.contains(&"neural_search"));
        assert!(disabled.contains(&"generate_sbom"));
    }

    #[test]
    fn test_balanced_includes_git() {
        let tools = Preset::Balanced.get_enabled_tools();
        assert!(tools.contains(&"get_blame"));
        assert!(tools.contains(&"get_file_history"));
    }

    #[test]
    fn test_balanced_excludes_neural() {
        let disabled = Preset::Balanced.get_disabled_tools();
        assert!(disabled.contains(&"neural_search"));
    }

    #[test]
    fn test_full_enables_all() {
        let tools = Preset::Full.get_enabled_tools();
        // Empty set means "enable all"
        assert!(tools.is_empty());
    }

    #[test]
    fn test_full_no_disabled() {
        let disabled = Preset::Full.get_disabled_tools();
        assert!(disabled.is_empty());
    }

    #[test]
    fn test_security_includes_security_tools() {
        let tools = Preset::SecurityFocused.get_enabled_tools();
        assert!(tools.contains(&"scan_security"));
        assert!(tools.contains(&"check_owasp_top10"));
        assert!(tools.contains(&"generate_sbom"));
        assert!(tools.contains(&"check_dependencies"));
    }

    #[test]
    fn test_security_excludes_neural() {
        let disabled = Preset::SecurityFocused.get_disabled_tools();
        assert!(disabled.contains(&"neural_search"));
    }

    #[test]
    fn test_parse() {
        assert_eq!(Preset::parse("minimal"), Some(Preset::Minimal));
        assert_eq!(Preset::parse("MINIMAL"), Some(Preset::Minimal));
        assert_eq!(Preset::parse("balanced"), Some(Preset::Balanced));
        assert_eq!(Preset::parse("full"), Some(Preset::Full));
        assert_eq!(
            Preset::parse("security-focused"),
            Some(Preset::SecurityFocused)
        );
        assert_eq!(
            Preset::parse("security_focused"),
            Some(Preset::SecurityFocused)
        );
        assert_eq!(Preset::parse("unknown"), None);
    }
}
