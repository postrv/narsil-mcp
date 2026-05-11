/// Configuration schema structures
///
/// These structures define the YAML configuration format for narsil-mcp.
/// They are designed to be serialized/deserialized with serde.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Default version for configuration
fn default_version() -> String {
    "1.0".to_string()
}

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    /// Configuration version (currently "1.0")
    #[serde(default = "default_version")]
    pub version: String,

    /// Optional preset name (minimal, balanced, full, security-focused)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,

    /// Editor-specific configurations (optional)
    #[serde(default)]
    pub editors: HashMap<String, serde_json::Value>,

    /// Named repository profiles for reusable workspace path sets.
    #[serde(default)]
    pub profiles: HashMap<String, RepoProfile>,

    /// Tool configuration (categories and overrides)
    /// Defaults to empty config when using preset-only configurations
    #[serde(default)]
    pub tools: ToolsConfig,

    /// Performance budgets and limits
    #[serde(default)]
    pub performance: PerformanceConfig,

    /// Feature flag requirements (optional)
    #[serde(default)]
    pub feature_requirements: HashMap<String, serde_json::Value>,
}

impl Default for ToolConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            preset: None,
            editors: HashMap::new(),
            profiles: HashMap::new(),
            tools: ToolsConfig::default(),
            performance: PerformanceConfig::default(),
            feature_requirements: HashMap::new(),
        }
    }
}

/// Named workspace profile selected with `--profile NAME`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoProfile {
    /// Repository paths to index when this profile is selected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<PathBuf>,

    /// Optional directory to auto-discover repositories from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discover: Option<PathBuf>,

    /// Optional tool preset to apply with this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,

    /// Enable git integration for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<bool>,

    /// Enable call graph analysis for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_graph: Option<bool>,

    /// Enable persistent index storage for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persist: Option<bool>,

    /// Enable watch mode for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch: Option<bool>,

    /// Enable LSP integration for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lsp: Option<bool>,

    /// Enable remote GitHub repository support for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<bool>,

    /// Enable neural search for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub neural: Option<bool>,

    /// Enable graph/SPARQL/CCG tools for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<bool>,
}

/// Tools configuration (categories and overrides)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsConfig {
    /// Category-level configuration
    #[serde(default)]
    pub categories: HashMap<String, CategoryConfig>,

    /// Individual tool overrides
    #[serde(default)]
    pub overrides: HashMap<String, ToolOverride>,
}

/// Category-level configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryConfig {
    /// Whether this category is enabled
    pub enabled: bool,

    /// Optional description of the category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Required feature flags for this category
    #[serde(default)]
    pub required_flags: Vec<String>,

    /// Additional category-specific configuration
    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,
}

/// Individual tool override configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOverride {
    /// Whether this tool is enabled
    pub enabled: bool,

    /// Optional reason for the override
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Required feature flags for this tool
    #[serde(default)]
    pub required_flags: Vec<String>,

    /// Tool-specific configuration
    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,

    /// Performance impact indicator (low, medium, high)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub performance_impact: Option<String>,

    /// Whether this tool requires an API key
    #[serde(default)]
    pub requires_api_key: bool,
}

/// Performance configuration with budgets and limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum number of tools to expose
    #[serde(default = "default_max_tool_count")]
    pub max_tool_count: usize,

    /// Maximum acceptable startup latency in milliseconds
    #[serde(default = "default_startup_latency")]
    pub startup_latency_ms: u64,

    /// Maximum acceptable filtering latency in milliseconds
    #[serde(default = "default_filtering_latency")]
    pub filtering_latency_ms: u64,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            // Sized to comfortably hold the full MCP tool registry (90 today)
            // with headroom; raise as new tools land. The Full preset bypasses
            // this cap entirely (see `ToolFilter::get_enabled_tools`).
            max_tool_count: 128,
            startup_latency_ms: 10,
            filtering_latency_ms: 1,
        }
    }
}

fn default_max_tool_count() -> usize {
    128
}

fn default_startup_latency() -> u64 {
    10
}

fn default_filtering_latency() -> u64 {
    1
}

impl ToolConfig {
    /// Check if a specific category is enabled
    pub fn is_category_enabled(&self, category: &str) -> bool {
        self.tools
            .categories
            .get(category)
            .map(|c| c.enabled)
            .unwrap_or(true) // Default to enabled if not specified
    }

    /// Check if a specific tool is enabled (considering overrides)
    pub fn is_tool_enabled(&self, tool_name: &str) -> bool {
        self.tools
            .overrides
            .get(tool_name)
            .map(|o| o.enabled)
            .unwrap_or(true) // Default to enabled if not overridden
    }

    /// Get the performance impact for a tool if specified
    pub fn get_tool_performance_impact(&self, tool_name: &str) -> Option<&str> {
        self.tools
            .overrides
            .get(tool_name)
            .and_then(|o| o.performance_impact.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_performance_config() {
        let perf = PerformanceConfig::default();
        assert_eq!(perf.max_tool_count, 128);
        assert_eq!(perf.startup_latency_ms, 10);
        assert_eq!(perf.filtering_latency_ms, 1);
    }

    #[test]
    fn test_default_tool_config() {
        let config = ToolConfig::default();
        assert_eq!(config.version, "1.0");
        assert!(config.profiles.is_empty());
        assert!(config.tools.categories.is_empty());
        assert!(config.tools.overrides.is_empty());
    }

    #[test]
    fn test_category_enabled_default() {
        let config = ToolConfig::default();
        // Categories not specified should default to enabled
        assert!(config.is_category_enabled("Repository"));
    }

    #[test]
    fn test_tool_enabled_default() {
        let config = ToolConfig::default();
        // Tools not overridden should default to enabled
        assert!(config.is_tool_enabled("list_repos"));
    }

    #[test]
    fn test_preset_only_config() {
        // Issue #5: Preset-only configs should parse without requiring tools field
        let yaml = r#"
version: "1.0"
preset: "full"
"#;
        let config: ToolConfig = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(config.version, "1.0");
        assert_eq!(config.preset, Some("full".to_string()));
        assert!(config.tools.categories.is_empty());
        assert!(config.tools.overrides.is_empty());
    }

    #[test]
    fn test_repo_profile_config() {
        let yaml = r#"
version: "1.0"
profiles:
  work:
    repos:
      - ~/src/api
      - ~/src/web
    git: true
    call_graph: true
    preset: balanced
"#;
        let config: ToolConfig = serde_saphyr::from_str(yaml).unwrap();
        let profile = config.profiles.get("work").unwrap();
        assert_eq!(profile.repos.len(), 2);
        assert_eq!(profile.git, Some(true));
        assert_eq!(profile.call_graph, Some(true));
        assert_eq!(profile.preset.as_deref(), Some("balanced"));
    }

    #[test]
    fn test_minimal_preset_config() {
        // Even more minimal - just preset
        let yaml = r#"preset: "minimal""#;
        let config: ToolConfig = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(config.preset, Some("minimal".to_string()));
        assert_eq!(config.version, "1.0"); // Should use default
    }
}
