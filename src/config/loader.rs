/// Configuration loading and merging
///
/// Loads configuration from multiple sources with the following priority:
/// 1. CLI flags (handled elsewhere)
/// 2. Environment variables
/// 3. Project config (.narsil.yaml in repo root)
/// 4. User config (~/.config/narsil-mcp/config.yaml)
/// 5. Default config (built-in)
use super::schema::{ToolConfig, ToolOverride};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Default configuration embedded in the binary
const DEFAULT_CONFIG: &str = r#"
version: "1.0"
tools:
  overrides: {}
profiles: {}
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

        if overlay.adopted_repo_ttl_days.is_some() {
            base.adopted_repo_ttl_days = overlay.adopted_repo_ttl_days;
        }
        if overlay.memory_soft_limit.is_some() {
            base.memory_soft_limit = overlay.memory_soft_limit;
        }
        if overlay.memory_hard_limit.is_some() {
            base.memory_hard_limit = overlay.memory_hard_limit;
        }
        if overlay.memory_soft_limit_interval_secs.is_some() {
            base.memory_soft_limit_interval_secs = overlay.memory_soft_limit_interval_secs;
        }
        if overlay.sse_url.is_some() {
            base.sse_url = overlay.sse_url;
        }

        // Overlay expose groups if specified. Replaced wholesale rather than
        // appended: "expose these groups" is an absolute statement, and a
        // project config that unions with the user config could only ever
        // widen the tool set.
        if !overlay.expose.is_empty() {
            base.expose = overlay.expose;
        }

        // Merge named repository profiles
        for (name, profile) in overlay.profiles {
            base.profiles.insert(name, profile);
        }

        // Merge overrides
        for (name, override_config) in overlay.tools.overrides {
            base.tools.overrides.insert(name, override_config);
        }

        base
    }

    /// Apply environment variable overrides.
    ///
    /// A variable is treated as **unset** when its value is empty or
    /// whitespace-only, so a shell wrapper that always `export`s it does not
    /// change the config.
    fn apply_env_overrides(config: &mut ToolConfig) -> Result<()> {
        use std::env;

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
        assert!(config.tools.overrides.is_empty());
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
    }

    #[test]
    fn test_merge_configs() {
        let override_for = |enabled: bool, reason: &str| ToolOverride {
            enabled,
            reason: Some(reason.to_string()),
            required_flags: vec![],
            config: HashMap::new(),
            performance_impact: None,
            requires_api_key: false,
        };
        let mut base = ToolConfig::default();
        base.tools
            .overrides
            .insert("get_blame".to_string(), override_for(true, "Base"));

        let mut overlay = ToolConfig::default();
        overlay
            .tools
            .overrides
            .insert("get_blame".to_string(), override_for(false, "Overlay"));

        let merged = ConfigLoader::merge_configs(base, overlay);

        // Overlay should win
        let blame = merged.tools.overrides.get("get_blame").unwrap();
        assert!(!blame.enabled);
        assert_eq!(blame.reason.as_ref().unwrap(), "Overlay");
    }

    #[test]
    fn test_merge_profiles() {
        let base = ToolConfig::default();
        let mut overlay = ToolConfig::default();
        overlay.profiles.insert(
            "work".to_string(),
            crate::config::schema::RepoProfile {
                repos: vec![crate::config::schema::RepoEntry::Path(PathBuf::from(
                    "~/src/work",
                ))],
                git: Some(true),
                ..Default::default()
            },
        );

        let merged = ConfigLoader::merge_configs(base, overlay);
        assert!(merged.profiles.contains_key("work"));
        assert_eq!(merged.profiles["work"].git, Some(true));
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
