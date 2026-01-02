/// Tool filtering based on configuration and feature flags
///
/// Converts EngineOptions and ToolConfig into a filtered list of enabled tools.
/// Must complete in <1ms for responsive tool list queries.
use crate::config::editor::get_editor_preset_or_full;
use crate::config::preset::Preset;
use crate::config::schema::ToolConfig;
use crate::index::EngineOptions;
use crate::tool_metadata::{FeatureFlag, PerformanceImpact, ToolMetadata, TOOL_METADATA};
use std::collections::HashSet;

/// Client information from MCP initialize
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub name: String,
    pub version: Option<String>,
}

/// Tool filter that applies configuration to determine enabled tools
pub struct ToolFilter {
    config: ToolConfig,
    enabled_flags: HashSet<FeatureFlag>,
    preset: Preset,
}

impl ToolFilter {
    /// Create a new tool filter
    pub fn new(
        config: ToolConfig,
        engine_options: &EngineOptions,
        client_info: Option<ClientInfo>,
    ) -> Self {
        let enabled_flags = Self::convert_engine_options(engine_options);

        // Determine preset with priority: config.preset > client_info > Full
        let preset = if let Some(ref preset_str) = config.preset {
            // Config preset has highest priority
            Preset::parse(preset_str).unwrap_or(Preset::Full)
        } else if let Some(ref client) = client_info {
            // Fall back to client-based preset
            get_editor_preset_or_full(&client.name)
        } else {
            // Default to full preset
            Preset::Full
        };

        Self {
            config,
            enabled_flags,
            preset,
        }
    }

    /// Convert EngineOptions to a set of FeatureFlags
    pub fn convert_engine_options(options: &EngineOptions) -> HashSet<FeatureFlag> {
        let mut flags = HashSet::new();

        if options.git_enabled {
            flags.insert(FeatureFlag::Git);
        }
        if options.call_graph_enabled {
            flags.insert(FeatureFlag::CallGraph);
        }
        if options.persist_enabled {
            flags.insert(FeatureFlag::Persist);
        }
        if options.watch_enabled {
            flags.insert(FeatureFlag::Watch);
        }
        if options.lsp_config.enabled {
            flags.insert(FeatureFlag::Lsp);
        }
        if options.neural_config.enabled {
            flags.insert(FeatureFlag::Neural);
        }
        // Remote flag would be set via engine options if there's a remote field
        // For now, we'll check the neural_config backend or other indicators
        // This can be extended as needed

        flags
    }

    /// Get the list of enabled tools based on configuration and flags
    pub fn get_enabled_tools(&self) -> Vec<&'static str> {
        let mut enabled_tools = Vec::new();

        // Iterate through all tools in the metadata registry
        for (tool_name, metadata) in TOOL_METADATA.iter() {
            if self.is_tool_enabled(tool_name, metadata) {
                enabled_tools.push(*tool_name);
            }
        }

        // Apply performance budget
        self.apply_performance_budget(enabled_tools)
    }

    /// Check if a specific tool should be enabled
    fn is_tool_enabled(&self, tool_name: &str, metadata: &ToolMetadata) -> bool {
        // 1. Check tool-level override first (highest priority)
        if let Some(override_config) = self.config.tools.overrides.get(tool_name) {
            if !override_config.enabled {
                return false; // Explicitly disabled
            }
            // If explicitly enabled via override, still need to check required flags
        }

        // 2. Check if preset explicitly disables this tool
        let disabled_by_preset = self.preset.get_disabled_tools();
        if disabled_by_preset.contains(tool_name) {
            return false; // Disabled by preset
        }

        // 3. Check if preset has an enabled whitelist
        let enabled_by_preset = self.preset.get_enabled_tools();
        if !enabled_by_preset.is_empty() {
            // Preset has a whitelist (not Full preset)
            if !enabled_by_preset.contains(tool_name) {
                return false; // Not in whitelist
            }
        }
        // If preset is Full (empty whitelist), all tools are allowed

        // 4. Check if tool's category is enabled
        let category_name = format!("{:?}", metadata.category);
        if let Some(category_config) = self.config.tools.categories.get(&category_name) {
            if !category_config.enabled {
                return false; // Category disabled
            }
        }

        // 5. Check required feature flags
        if !metadata.required_flags.is_empty() {
            // Tool requires specific flags - must have ALL of them
            for required_flag in &metadata.required_flags {
                if !self.enabled_flags.contains(required_flag) {
                    return false; // Missing required flag
                }
            }
        }

        // 6. All checks passed
        true
    }

    /// Apply performance budget (max_tool_count)
    fn apply_performance_budget(&self, mut tools: Vec<&'static str>) -> Vec<&'static str> {
        let max_count = self.config.performance.max_tool_count;

        if tools.len() <= max_count {
            return tools; // Under budget, no trimming needed
        }

        // Prioritize tools by performance impact (Low > Medium > High)
        // Use tool name as secondary key for deterministic ordering
        // (DashMap iteration order is non-deterministic)
        tools.sort_by_key(|tool_name| {
            TOOL_METADATA
                .get(tool_name)
                .map(|meta| {
                    (
                        match meta.performance {
                            PerformanceImpact::Low => 0,
                            PerformanceImpact::Medium => 1,
                            PerformanceImpact::High => 2,
                        },
                        *tool_name, // Secondary sort by name for determinism
                    )
                })
                .unwrap_or((999, *tool_name)) // Unknown tools go last
        });

        // Take top N tools
        tools.truncate(max_count);
        tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{CategoryConfig, ToolOverride};
    use std::collections::HashMap;

    #[test]
    fn test_convert_engine_options_all_enabled() {
        let options = EngineOptions {
            git_enabled: true,
            call_graph_enabled: true,
            persist_enabled: true,
            watch_enabled: true,
            lsp_config: crate::lsp::LspConfig {
                enabled: true,
                ..Default::default()
            },
            neural_config: crate::neural::NeuralConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let flags = ToolFilter::convert_engine_options(&options);

        assert_eq!(flags.len(), 6);
        assert!(flags.contains(&FeatureFlag::Git));
        assert!(flags.contains(&FeatureFlag::CallGraph));
        assert!(flags.contains(&FeatureFlag::Persist));
        assert!(flags.contains(&FeatureFlag::Watch));
        assert!(flags.contains(&FeatureFlag::Lsp));
        assert!(flags.contains(&FeatureFlag::Neural));
    }

    #[test]
    fn test_convert_engine_options_none_enabled() {
        let options = EngineOptions::default();
        let flags = ToolFilter::convert_engine_options(&options);
        assert_eq!(flags.len(), 0);
    }

    #[test]
    fn test_is_tool_enabled_basic() {
        let config = ToolConfig::default();
        let options = EngineOptions::default();
        let filter = ToolFilter::new(config, &options, None);

        // list_repos requires no flags, should be enabled
        let meta = TOOL_METADATA.get("list_repos").unwrap();
        assert!(filter.is_tool_enabled("list_repos", meta));
    }

    #[test]
    fn test_is_tool_enabled_with_flag() {
        let config = ToolConfig::default();
        let options = EngineOptions {
            git_enabled: true,
            ..Default::default()
        };

        let filter = ToolFilter::new(config, &options, None);

        // get_blame requires Git flag
        let meta = TOOL_METADATA.get("get_blame").unwrap();
        assert!(filter.is_tool_enabled("get_blame", meta));
    }

    #[test]
    fn test_is_tool_enabled_without_required_flag() {
        let config = ToolConfig::default();
        let options = EngineOptions::default(); // git_enabled = false

        let filter = ToolFilter::new(config, &options, None);

        // get_blame requires Git flag
        let meta = TOOL_METADATA.get("get_blame").unwrap();
        assert!(!filter.is_tool_enabled("get_blame", meta));
    }

    #[test]
    fn test_is_tool_enabled_category_disabled() {
        let mut config = ToolConfig::default();
        config.tools.categories.insert(
            "Git".to_string(),
            CategoryConfig {
                enabled: false,
                description: None,
                required_flags: vec![],
                config: HashMap::new(),
            },
        );

        let options = EngineOptions {
            git_enabled: true, // Flag enabled, but category disabled
            ..Default::default()
        };

        let filter = ToolFilter::new(config, &options, None);

        let meta = TOOL_METADATA.get("get_blame").unwrap();
        assert!(!filter.is_tool_enabled("get_blame", meta));
    }

    #[test]
    fn test_is_tool_enabled_override_disabled() {
        let mut config = ToolConfig::default();
        config.tools.overrides.insert(
            "list_repos".to_string(),
            ToolOverride {
                enabled: false,
                reason: Some("Test".to_string()),
                required_flags: vec![],
                config: HashMap::new(),
                performance_impact: None,
                requires_api_key: false,
            },
        );

        let options = EngineOptions::default();
        let filter = ToolFilter::new(config, &options, None);

        let meta = TOOL_METADATA.get("list_repos").unwrap();
        assert!(!filter.is_tool_enabled("list_repos", meta));
    }

    #[test]
    fn test_apply_performance_budget() {
        let mut config = ToolConfig::default();
        config.performance.max_tool_count = 5;

        let options = EngineOptions::default();
        let filter = ToolFilter::new(config, &options, None);

        let tools = vec![
            "list_repos",
            "find_symbols",
            "search_code",
            "get_file",
            "get_project_structure",
            "find_references",
            "get_dependencies",
        ];

        let filtered = filter.apply_performance_budget(tools);
        assert_eq!(filtered.len(), 5);
    }

    #[test]
    fn test_performance_budget_prioritizes_low_impact() {
        let mut config = ToolConfig::default();
        config.performance.max_tool_count = 10;

        let options = EngineOptions {
            git_enabled: true,
            call_graph_enabled: true,
            neural_config: crate::neural::NeuralConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let filter = ToolFilter::new(config, &options, None);
        let enabled = filter.get_enabled_tools();

        assert!(enabled.len() <= 10);

        // Check that low-impact tools are prioritized over high-impact ones
        let mut low_impact_count = 0;
        let mut high_impact_count = 0;

        for tool_name in &enabled {
            if let Some(meta) = TOOL_METADATA.get(tool_name) {
                match meta.performance {
                    PerformanceImpact::Low => low_impact_count += 1,
                    PerformanceImpact::High => high_impact_count += 1,
                    _ => {}
                }
            }
        }

        // Should have more low-impact tools than high-impact tools
        assert!(
            low_impact_count >= high_impact_count,
            "Should prioritize low-impact tools: low={}, high={}",
            low_impact_count,
            high_impact_count
        );
    }
}
