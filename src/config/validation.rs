/// Configuration validation
///
/// Validates configuration files to catch errors early and provide
/// helpful error messages.
use super::schema::ToolConfig;
use crate::tool_metadata::TOOL_METADATA;
use anyhow::{bail, Result};

/// Supported configuration versions
const SUPPORTED_VERSIONS: &[&str] = &["1.0"];

/// Validate a configuration
pub fn validate_config(config: &ToolConfig) -> Result<()> {
    validate_version(config)?;
    validate_profiles(config)?;
    validate_overrides(config)?;
    Ok(())
}

/// Validate configuration version
fn validate_version(config: &ToolConfig) -> Result<()> {
    if !SUPPORTED_VERSIONS.contains(&config.version.as_str()) {
        bail!(
            "Unsupported configuration version '{}'. Supported versions: {}",
            config.version,
            SUPPORTED_VERSIONS.join(", ")
        );
    }
    Ok(())
}

/// Validate named repository profiles.
fn validate_profiles(config: &ToolConfig) -> Result<()> {
    for (name, profile) in &config.profiles {
        if name.trim().is_empty() {
            bail!("Profile names must not be empty");
        }

        if profile.repos.is_empty() && profile.discover.is_none() {
            bail!(
                "Profile '{}' must define at least one repo path or a discover path",
                name
            );
        }
    }

    Ok(())
}

/// Validate tool overrides
fn validate_overrides(config: &ToolConfig) -> Result<()> {
    for tool_name in config.tools.overrides.keys() {
        if !TOOL_METADATA.contains_key(tool_name.as_str()) {
            eprintln!(
                "Warning: Unknown tool '{}' in overrides. This tool may not exist or may be from a newer version.",
                tool_name
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::ToolsConfig;
    use std::collections::HashMap;

    #[test]
    fn test_validate_valid_version() {
        let config = ToolConfig {
            version: "1.0".to_string(),
            expose: Vec::new(),
            adopted_repo_ttl_days: None,
            memory_soft_limit: None,
            memory_hard_limit: None,
            memory_soft_limit_interval_secs: None,
            sse_url: None,
            profiles: HashMap::new(),
            tools: ToolsConfig {
                overrides: HashMap::new(),
            },
        };

        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_invalid_version() {
        let config = ToolConfig {
            version: "999.0".to_string(),
            expose: Vec::new(),
            adopted_repo_ttl_days: None,
            memory_soft_limit: None,
            memory_hard_limit: None,
            memory_soft_limit_interval_secs: None,
            sse_url: None,
            profiles: HashMap::new(),
            tools: ToolsConfig {
                overrides: HashMap::new(),
            },
        };

        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_unknown_tool_warns() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "nonexistent_tool".to_string(),
            crate::config::schema::ToolOverride {
                enabled: false,
                reason: None,
                required_flags: vec![],
                config: HashMap::new(),
                performance_impact: None,
                requires_api_key: false,
            },
        );

        let config = ToolConfig {
            version: "1.0".to_string(),
            expose: Vec::new(),
            adopted_repo_ttl_days: None,
            memory_soft_limit: None,
            memory_hard_limit: None,
            memory_soft_limit_interval_secs: None,
            sse_url: None,
            profiles: HashMap::new(),
            tools: ToolsConfig { overrides },
        };

        // Should succeed but print warning
        assert!(validate_config(&config).is_ok());
    }
}
