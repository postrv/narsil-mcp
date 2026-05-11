/// Configuration loading and merging
///
/// Loads configuration from multiple sources with the following priority:
/// 1. CLI flags (handled elsewhere)
/// 2. Environment variables
/// 3. Project config (.narsil.yaml in repo root)
/// 4. User config (~/.config/narsil-mcp/config.yaml)
/// 5. Default config (built-in)
use super::schema::{PerformanceConfig, ToolConfig, ToolOverride};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Default configuration embedded in the binary
const DEFAULT_CONFIG: &str = r#"
version: "1.0"
tools:
  categories:
    Repository:
      enabled: true
      description: "Repository and file operations"
    Symbols:
      enabled: true
      description: "Symbol search and navigation"
    Search:
      enabled: true
      description: "Code search capabilities"
    CallGraph:
      enabled: true
      description: "Call graph analysis (requires --call-graph)"
      required_flags: ["call_graph"]
    Git:
      enabled: true
      description: "Git integration (requires --git)"
      required_flags: ["git"]
    LSP:
      enabled: true
      description: "LSP integration (enhanced with --lsp)"
    Remote:
      enabled: true
      description: "Remote repository support (requires --remote)"
      required_flags: ["remote"]
    Security:
      enabled: true
      description: "Security vulnerability scanning"
    SupplyChain:
      enabled: true
      description: "Supply chain analysis"
    Analysis:
      enabled: true
      description: "Code analysis tools"
    Graph:
      enabled: true
      description: "Graph visualization"
  overrides: {}
profiles: {}
performance:
  max_tool_count: 128
  startup_latency_ms: 10
  filtering_latency_ms: 1
"#;

/// Configuration loader with multi-source support
pub struct ConfigLoader {
    /// Default configuration
    pub default_config: ToolConfig,

    /// Optional user config path override
    user_config_path: Option<PathBuf>,

    /// Optional project config path override
    project_config_path: Option<PathBuf>,
}

impl ConfigLoader {
    /// Create a new config loader with default settings
    pub fn new() -> Self {
        let default_config =
            serde_saphyr::from_str(DEFAULT_CONFIG).expect("Default config should always be valid");

        Self {
            default_config,
            user_config_path: None,
            project_config_path: None,
        }
    }

    /// Create a loader with a custom user config path
    pub fn with_user_config_path(mut self, path: Option<PathBuf>) -> Self {
        self.user_config_path = path;
        self
    }

    /// Create a loader with a custom project config path
    pub fn with_project_config_path(mut self, path: Option<PathBuf>) -> Self {
        self.project_config_path = path;
        self
    }

    /// Load configuration with priority merging
    pub fn load(&self) -> Result<ToolConfig> {
        let mut config = self.default_config.clone();

        // Try to load user config
        if let Some(user_config) = self.load_user_config()? {
            config = Self::merge_configs(config, user_config);
        }

        // Try to load project config
        if let Some(project_config) = self.load_project_config()? {
            config = Self::merge_configs(config, project_config);
        }

        // Apply environment variable overrides
        Self::apply_env_overrides(&mut config)?;

        Ok(config)
    }

    /// Get the default user config path for the current platform
    ///
    /// Returns the platform-specific configuration directory:
    /// - macOS: ~/Library/Application Support/narsil-mcp/config.yaml
    /// - Linux: ~/.config/narsil-mcp/config.yaml
    /// - Windows: %APPDATA%\narsil-mcp\config.yaml
    pub fn get_default_user_config_path(&self) -> PathBuf {
        use directories::ProjectDirs;

        if let Some(proj_dirs) = ProjectDirs::from("com", "anthropic", "narsil-mcp") {
            proj_dirs.config_dir().join("config.yaml")
        } else {
            // Fallback to .config in home directory
            if let Some(home) = std::env::var_os("HOME") {
                PathBuf::from(home)
                    .join(".config")
                    .join("narsil-mcp")
                    .join("config.yaml")
            } else {
                PathBuf::from("config.yaml")
            }
        }
    }

    /// Load configuration from a specific path
    ///
    /// This is useful for testing or when you want to load a specific config file
    pub fn load_from_path(&self, path: &Path) -> Result<ToolConfig> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: ToolConfig = serde_saphyr::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        Ok(config)
    }

    /// Load user configuration from ~/.config/narsil-mcp/config.yaml
    fn load_user_config(&self) -> Result<Option<ToolConfig>> {
        use std::env;

        let path = if let Some(ref path) = self.user_config_path {
            path.clone()
        } else if let Ok(custom_path) = env::var("NARSIL_CONFIG_PATH") {
            // Check for custom config path from environment
            PathBuf::from(custom_path)
        } else {
            use directories::ProjectDirs;
            let proj_dirs = ProjectDirs::from("com", "anthropic", "narsil-mcp")
                .context("Could not determine user config directory")?;
            proj_dirs.config_dir().join("config.yaml")
        };

        self.load_config_file(&path)
    }

    /// Load project configuration from .narsil.yaml in repo root
    fn load_project_config(&self) -> Result<Option<ToolConfig>> {
        let path = if let Some(ref path) = self.project_config_path {
            path.clone()
        } else {
            // Look for .narsil.yaml in current directory
            PathBuf::from(".narsil.yaml")
        };

        self.load_config_file(&path)
    }

    /// Load configuration from a file if it exists
    fn load_config_file(&self, path: &Path) -> Result<Option<ToolConfig>> {
        if !path.exists() {
            return Ok(None);
        }

        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: ToolConfig = serde_saphyr::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        Ok(Some(config))
    }

    /// Merge two configurations (second takes priority)
    fn merge_configs(mut base: ToolConfig, overlay: ToolConfig) -> ToolConfig {
        // Overlay version if specified
        if !overlay.version.is_empty() {
            base.version = overlay.version;
        }

        // Overlay preset if specified
        if overlay.preset.is_some() {
            base.preset = overlay.preset;
        }

        // Merge editors
        for (name, config) in overlay.editors {
            base.editors.insert(name, config);
        }

        // Merge named repository profiles
        for (name, profile) in overlay.profiles {
            base.profiles.insert(name, profile);
        }

        // Merge categories
        for (name, config) in overlay.tools.categories {
            base.tools.categories.insert(name, config);
        }

        // Merge overrides
        for (name, override_config) in overlay.tools.overrides {
            base.tools.overrides.insert(name, override_config);
        }

        // Merge performance config (overlay takes precedence over the default).
        if overlay.performance.max_tool_count != PerformanceConfig::default().max_tool_count {
            base.performance.max_tool_count = overlay.performance.max_tool_count;
        }
        if overlay.performance.startup_latency_ms != PerformanceConfig::default().startup_latency_ms
        {
            base.performance.startup_latency_ms = overlay.performance.startup_latency_ms;
        }
        if overlay.performance.filtering_latency_ms
            != PerformanceConfig::default().filtering_latency_ms
        {
            base.performance.filtering_latency_ms = overlay.performance.filtering_latency_ms;
        }

        // Merge feature requirements
        for (name, req) in overlay.feature_requirements {
            base.feature_requirements.insert(name, req);
        }

        base
    }

    /// Apply environment variable overrides.
    ///
    /// Each variable is treated as **unset** when its value is empty or
    /// whitespace-only. This avoids the trap where a shell wrapper that always
    /// `export`s `NARSIL_ENABLED_CATEGORIES` (even when no categories are
    /// requested) used to disable every category and leave only the handful of
    /// flag-less tools visible — see issue #23.
    fn apply_env_overrides(config: &mut ToolConfig) -> Result<()> {
        use std::env;

        // NARSIL_PRESET - Apply a preset configuration
        if let Some(preset) = env::var("NARSIL_PRESET").ok().and_then(non_empty) {
            config.preset = Some(preset);
        }

        // NARSIL_ENABLED_CATEGORIES - comma-separated list of categories to enable
        if let Some(categories) = env::var("NARSIL_ENABLED_CATEGORIES")
            .ok()
            .and_then(non_empty)
        {
            let names: Vec<String> = categories
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            // Only modify the config if the caller actually named at least one
            // category — an env var that is set but contains only commas /
            // whitespace is treated as "unset", matching the empty-string case.
            if !names.is_empty() {
                // Disable all categories first
                for cat in config.tools.categories.values_mut() {
                    cat.enabled = false;
                }

                // Enable specified categories
                for name in names {
                    if let Some(cat) = config.tools.categories.get_mut(&name) {
                        cat.enabled = true;
                    } else {
                        use crate::config::schema::CategoryConfig;
                        config.tools.categories.insert(
                            name,
                            CategoryConfig {
                                enabled: true,
                                description: None,
                                required_flags: vec![],
                                config: HashMap::new(),
                            },
                        );
                    }
                }
            }
        }

        // NARSIL_DISABLED_TOOLS - comma-separated list of tools to disable
        if let Some(tools) = env::var("NARSIL_DISABLED_TOOLS").ok().and_then(non_empty) {
            for name in tools.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                config.tools.overrides.insert(
                    name.to_string(),
                    ToolOverride {
                        enabled: false,
                        reason: Some("Disabled via environment variable".to_string()),
                        required_flags: vec![],
                        config: HashMap::new(),
                        performance_impact: None,
                        requires_api_key: false,
                    },
                );
            }
        }

        Ok(())
    }
}

/// Trim a value and return `Some` only if non-empty. Used to treat empty /
/// whitespace-only environment variables as if they were unset.
fn non_empty(s: String) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::CategoryConfig;
    use std::sync::Mutex;

    /// Tests that mutate `NARSIL_*` environment variables share process-wide
    /// state and must run sequentially. Without this lock, parallel test
    /// execution races between `set_var` and `apply_env_overrides` and
    /// produces flaky failures.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_default_config_parses() {
        let config: ToolConfig = serde_saphyr::from_str(DEFAULT_CONFIG).unwrap();
        assert_eq!(config.version, "1.0");
        assert!(config.tools.categories.contains_key("Repository"));
        assert!(config.tools.categories.contains_key("Symbols"));
        assert!(config.tools.categories.contains_key("Search"));
    }

    #[test]
    fn test_new_loader() {
        let loader = ConfigLoader::new();
        assert_eq!(loader.default_config.version, "1.0");
    }

    #[test]
    fn test_load_default() {
        let loader = ConfigLoader::new();
        let config = loader.load().unwrap();
        assert_eq!(config.version, "1.0");
        assert!(!config.tools.categories.is_empty());
    }

    #[test]
    fn test_merge_configs() {
        let mut base = ToolConfig::default();
        base.tools.categories.insert(
            "Repository".to_string(),
            CategoryConfig {
                enabled: true,
                description: Some("Base".to_string()),
                required_flags: vec![],
                config: HashMap::new(),
            },
        );

        let mut overlay = ToolConfig::default();
        overlay.tools.categories.insert(
            "Repository".to_string(),
            CategoryConfig {
                enabled: false,
                description: Some("Overlay".to_string()),
                required_flags: vec![],
                config: HashMap::new(),
            },
        );

        let merged = ConfigLoader::merge_configs(base, overlay);

        // Overlay should win
        let repo_cat = merged.tools.categories.get("Repository").unwrap();
        assert!(!repo_cat.enabled);
        assert_eq!(repo_cat.description.as_ref().unwrap(), "Overlay");
    }

    #[test]
    fn test_merge_profiles() {
        let base = ToolConfig::default();
        let mut overlay = ToolConfig::default();
        overlay.profiles.insert(
            "work".to_string(),
            crate::config::schema::RepoProfile {
                repos: vec![PathBuf::from("~/src/work")],
                git: Some(true),
                ..Default::default()
            },
        );

        let merged = ConfigLoader::merge_configs(base, overlay);
        assert!(merged.profiles.contains_key("work"));
        assert_eq!(merged.profiles["work"].git, Some(true));
    }

    #[test]
    fn test_env_var_override() {
        use std::env;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let mut config = ToolConfig::default();
        config.tools.categories.insert(
            "Repository".to_string(),
            CategoryConfig {
                enabled: true,
                description: None,
                required_flags: vec![],
                config: HashMap::new(),
            },
        );
        config.tools.categories.insert(
            "Search".to_string(),
            CategoryConfig {
                enabled: true,
                description: None,
                required_flags: vec![],
                config: HashMap::new(),
            },
        );

        // Set env var to enable only Repository
        env::set_var("NARSIL_ENABLED_CATEGORIES", "Repository");

        ConfigLoader::apply_env_overrides(&mut config).unwrap();

        assert!(config.tools.categories.get("Repository").unwrap().enabled);
        assert!(!config.tools.categories.get("Search").unwrap().enabled);

        // Clean up
        env::remove_var("NARSIL_ENABLED_CATEGORIES");
    }

    /// Helper that builds a config with the standard set of categories all enabled.
    fn config_with_all_default_categories() -> ToolConfig {
        let mut config = ToolConfig::default();
        for name in ["Repository", "Symbols", "Search", "Git", "Lsp", "Remote"] {
            config.tools.categories.insert(
                name.to_string(),
                CategoryConfig {
                    enabled: true,
                    description: None,
                    required_flags: vec![],
                    config: HashMap::new(),
                },
            );
        }
        config
    }

    /// Issue #23 root cause: an empty `NARSIL_ENABLED_CATEGORIES` (e.g. set by a
    /// shell wrapper that always exports the var even when no categories are
    /// requested) used to take the disable-everything code path, leaving the
    /// server with zero enabled categories and thus only flag-less tools visible.
    #[test]
    fn test_env_var_empty_categories_is_noop() {
        use std::env;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut config = config_with_all_default_categories();
        env::set_var("NARSIL_ENABLED_CATEGORIES", "");

        ConfigLoader::apply_env_overrides(&mut config).unwrap();

        env::remove_var("NARSIL_ENABLED_CATEGORIES");

        for cat in ["Repository", "Symbols", "Search", "Git", "Lsp", "Remote"] {
            assert!(
                config.tools.categories.get(cat).unwrap().enabled,
                "{cat} should remain enabled when NARSIL_ENABLED_CATEGORIES is empty"
            );
        }
    }

    /// Whitespace-only env value should behave the same as empty.
    #[test]
    fn test_env_var_whitespace_only_categories_is_noop() {
        use std::env;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut config = config_with_all_default_categories();
        env::set_var("NARSIL_ENABLED_CATEGORIES", "   ");

        ConfigLoader::apply_env_overrides(&mut config).unwrap();

        env::remove_var("NARSIL_ENABLED_CATEGORIES");

        assert!(config.tools.categories.get("Repository").unwrap().enabled);
        assert!(config.tools.categories.get("Symbols").unwrap().enabled);
    }

    /// Empty segments inside a comma list should be skipped, not inserted as
    /// empty-named categories.
    #[test]
    fn test_env_var_categories_filters_empty_segments() {
        use std::env;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut config = config_with_all_default_categories();
        env::set_var("NARSIL_ENABLED_CATEGORIES", "Repository,,Symbols,");

        ConfigLoader::apply_env_overrides(&mut config).unwrap();

        env::remove_var("NARSIL_ENABLED_CATEGORIES");

        assert!(config.tools.categories.get("Repository").unwrap().enabled);
        assert!(config.tools.categories.get("Symbols").unwrap().enabled);
        assert!(!config.tools.categories.get("Search").unwrap().enabled);
        // No phantom empty-named entry should be inserted.
        assert!(!config.tools.categories.contains_key(""));
    }

    /// `NARSIL_PRESET=""` should be ignored, not stored as a literal empty preset
    /// string (which would later parse as Preset::Full but with confusing
    /// telemetry).
    #[test]
    fn test_env_var_preset_skips_empty() {
        use std::env;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut config = ToolConfig::default();
        env::set_var("NARSIL_PRESET", "");

        ConfigLoader::apply_env_overrides(&mut config).unwrap();

        env::remove_var("NARSIL_PRESET");

        assert!(
            config.preset.is_none(),
            "empty NARSIL_PRESET should leave preset unset, got {:?}",
            config.preset
        );
    }

    /// `NARSIL_DISABLED_TOOLS` should drop empty segments; an empty list should
    /// not insert an empty-named override.
    #[test]
    fn test_env_var_disabled_tools_filters_empty() {
        use std::env;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut config = ToolConfig::default();
        env::set_var("NARSIL_DISABLED_TOOLS", "foo,,bar,");

        ConfigLoader::apply_env_overrides(&mut config).unwrap();

        env::remove_var("NARSIL_DISABLED_TOOLS");

        assert!(config.tools.overrides.contains_key("foo"));
        assert!(config.tools.overrides.contains_key("bar"));
        assert!(!config.tools.overrides.contains_key(""));
    }
}
