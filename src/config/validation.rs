/// Configuration validation
///
/// Validates configuration files to catch errors early and provide
/// helpful error messages.
use super::schema::ToolConfig;
use crate::tool_metadata::TOOL_METADATA;
use anyhow::{bail, Result};
use std::collections::HashSet;

/// Supported configuration versions
const SUPPORTED_VERSIONS: &[&str] = &["1.0"];

/// Validate a configuration
pub fn validate_config(config: &ToolConfig) -> Result<()> {
    validate_version(config)?;
    validate_profiles(config)?;
    validate_categories(config)?;
    validate_overrides(config)?;
    validate_performance(config)?;
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

/// Validate category configurations
fn validate_categories(config: &ToolConfig) -> Result<()> {
    let valid_categories: HashSet<String> = [
        "Repository",
        "Symbols",
        "Search",
        "CallGraph",
        "Git",
        "LSP",
        "Remote",
        "Security",
        "SupplyChain",
        "Analysis",
        "Graph",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    for category_name in config.tools.categories.keys() {
        if !valid_categories.contains(category_name) {
            eprintln!(
                "Warning: Unknown category '{}' in configuration. This may be from a newer version.",
                category_name
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

/// Validate performance configuration
fn validate_performance(config: &ToolConfig) -> Result<()> {
    if config.performance.max_tool_count == 0 {
        bail!("Performance budget 'max_tool_count' must be greater than 0");
    }

    if config.performance.max_tool_count > 200 {
        eprintln!(
            "Warning: max_tool_count of {} is very high. This may impact editor performance.",
            config.performance.max_tool_count
        );
    }

    if config.performance.startup_latency_ms > 1000 {
        eprintln!(
            "Warning: startup_latency_ms of {} is very high. This may cause initialization timeouts.",
            config.performance.startup_latency_ms
        );
    }

    if config.performance.filtering_latency_ms > 100 {
        eprintln!(
            "Warning: filtering_latency_ms of {} is very high. This may cause tool list delays.",
            config.performance.filtering_latency_ms
        );
    }

    Ok(())
}

/// Validate that required flags are properly configured
pub fn validate_feature_flags(config: &ToolConfig, enabled_flags: &HashSet<String>) -> Result<()> {
    // Check if categories require flags that aren't enabled
    for (category_name, category_config) in &config.tools.categories {
        if !category_config.enabled {
            continue;
        }

        for required_flag in &category_config.required_flags {
            if !enabled_flags.contains(required_flag) {
                eprintln!(
                    "Warning: Category '{}' requires flag '{}' which is not enabled. Tools in this category will not be available.",
                    category_name, required_flag
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{CategoryConfig, PerformanceConfig, ToolsConfig};
    use std::collections::HashMap;

    #[test]
    fn test_validate_valid_version() {
        let config = ToolConfig {
            version: "1.0".to_string(),
            preset: None,
            editors: HashMap::new(),
            profiles: HashMap::new(),
            tools: ToolsConfig {
                categories: HashMap::new(),
                overrides: HashMap::new(),
            },
            performance: PerformanceConfig::default(),
            feature_requirements: HashMap::new(),
        };

        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_invalid_version() {
        let config = ToolConfig {
            version: "999.0".to_string(),
            preset: None,
            editors: HashMap::new(),
            profiles: HashMap::new(),
            tools: ToolsConfig {
                categories: HashMap::new(),
                overrides: HashMap::new(),
            },
            performance: PerformanceConfig::default(),
            feature_requirements: HashMap::new(),
        };

        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_invalid_performance() {
        let config = ToolConfig {
            version: "1.0".to_string(),
            preset: None,
            editors: HashMap::new(),
            profiles: HashMap::new(),
            tools: ToolsConfig {
                categories: HashMap::new(),
                overrides: HashMap::new(),
            },
            performance: PerformanceConfig {
                max_tool_count: 0, // Invalid
                startup_latency_ms: 10,
                filtering_latency_ms: 1,
            },
            feature_requirements: HashMap::new(),
        };

        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_unknown_category_warns() {
        let mut categories = HashMap::new();
        categories.insert(
            "UnknownCategory".to_string(),
            CategoryConfig {
                enabled: true,
                description: None,
                required_flags: vec![],
                config: HashMap::new(),
            },
        );

        let config = ToolConfig {
            version: "1.0".to_string(),
            preset: None,
            editors: HashMap::new(),
            profiles: HashMap::new(),
            tools: ToolsConfig {
                categories,
                overrides: HashMap::new(),
            },
            performance: PerformanceConfig::default(),
            feature_requirements: HashMap::new(),
        };

        // Should succeed but print warning
        assert!(validate_config(&config).is_ok());
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
            preset: None,
            editors: HashMap::new(),
            profiles: HashMap::new(),
            tools: ToolsConfig {
                categories: HashMap::new(),
                overrides,
            },
            performance: PerformanceConfig::default(),
            feature_requirements: HashMap::new(),
        };

        // Should succeed but print warning
        assert!(validate_config(&config).is_ok());
    }
}
