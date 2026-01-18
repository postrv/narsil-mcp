use crate::config::schema::ToolConfig;
use crate::config::{validate_config, ConfigLoader};
use crate::tool_metadata::TOOL_METADATA;
use anyhow::{Context, Result};
use std::io::Write;
use std::path::PathBuf;

/// Config CLI subcommands
#[derive(Debug, clap::Subcommand)]
pub enum ConfigCommand {
    /// Show the current effective configuration
    Show {
        /// Output format (yaml or json)
        #[arg(long, default_value = "yaml")]
        format: OutputFormat,

        /// Show configuration for specific repository
        #[arg(long)]
        repo: Option<PathBuf>,
    },

    /// Validate a configuration file
    Validate {
        /// Path to config file to validate
        path: PathBuf,

        /// Show verbose validation errors
        #[arg(short, long)]
        verbose: bool,
    },

    /// Initialize a new configuration file
    Init {
        /// Apply a specific preset (minimal, balanced, full, security-focused)
        #[arg(long)]
        preset: Option<String>,

        /// Create project config (.narsil.yaml) instead of user config
        #[arg(long)]
        project: bool,

        /// Create user config (~/.config/narsil-mcp/config.yaml)
        #[arg(long)]
        user: bool,

        /// Run the neural API key setup wizard
        #[arg(long)]
        neural: bool,
    },

    /// Apply a preset to configuration
    Preset {
        /// Preset name (minimal, balanced, full, security-focused)
        preset: String,

        /// Apply to project config instead of user config
        #[arg(long)]
        project: bool,
    },

    /// Export the current effective configuration
    Export {
        /// Include resolved preset settings
        #[arg(long)]
        resolved: bool,

        /// Output format (yaml or json)
        #[arg(long, default_value = "yaml")]
        format: OutputFormat,
    },
}

/// Tools CLI subcommands
#[derive(Debug, clap::Subcommand)]
pub enum ToolsCommand {
    /// List available tools
    List {
        /// Filter by category
        #[arg(long)]
        category: Option<String>,

        /// Output format (table, json, yaml)
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },

    /// Search for tools by name or description
    Search {
        /// Search query
        query: String,

        /// Output format (table, json, yaml)
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },

    /// Show detailed information about a specific tool
    Show {
        /// Tool name
        tool: String,

        /// Output format (yaml, json)
        #[arg(long, default_value = "yaml")]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, PartialEq, clap::ValueEnum)]
pub enum OutputFormat {
    Yaml,
    Json,
    Table,
}

/// Handle config subcommands
pub async fn handle_config_command(cmd: ConfigCommand) -> Result<()> {
    match cmd {
        ConfigCommand::Show { format, repo } => cmd_show(format, repo),
        ConfigCommand::Validate { path, verbose } => cmd_validate(path, verbose),
        ConfigCommand::Init {
            preset,
            project,
            user,
            neural,
        } => cmd_init(preset, project, user, neural).await,
        ConfigCommand::Preset { preset, project } => cmd_preset(preset, project),
        ConfigCommand::Export { resolved, format } => cmd_export(resolved, format),
    }
}

/// Handle tools subcommands
pub fn handle_tools_command(cmd: ToolsCommand) -> Result<()> {
    match cmd {
        ToolsCommand::List { category, format } => cmd_tools_list(category, format),
        ToolsCommand::Search { query, format } => cmd_tools_search(query, format),
        ToolsCommand::Show { tool, format } => cmd_tools_show(tool, format),
    }
}

fn cmd_show(format: OutputFormat, _repo: Option<PathBuf>) -> Result<()> {
    let loader = ConfigLoader::new();
    let config = loader.load().context("Failed to load configuration")?;

    match format {
        OutputFormat::Yaml => {
            let yaml = serde_yaml::to_string(&config)?;
            println!("{}", yaml);
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&config)?;
            println!("{}", json);
        }
        OutputFormat::Table => {
            println!("Current Configuration:");
            println!("=====================");
            println!("Version: {}", config.version);
            if let Some(preset) = &config.preset {
                println!("Preset: {}", preset);
            }
            println!("\nEnabled Categories:");
            for (name, category) in &config.tools.categories {
                if category.enabled {
                    println!(
                        "  - {} ({})",
                        name,
                        category.description.as_deref().unwrap_or("")
                    );
                }
            }
            println!("\nDisabled Categories:");
            for (name, category) in &config.tools.categories {
                if !category.enabled {
                    println!("  - {}", name);
                }
            }
            if !config.tools.overrides.is_empty() {
                println!("\nTool Overrides:");
                for (name, override_cfg) in &config.tools.overrides {
                    println!(
                        "  - {}: {} {}",
                        name,
                        if override_cfg.enabled {
                            "enabled"
                        } else {
                            "disabled"
                        },
                        override_cfg
                            .reason
                            .as_deref()
                            .map(|r| format!("({})", r))
                            .unwrap_or_default()
                    );
                }
            }
        }
    }

    Ok(())
}

fn cmd_validate(path: PathBuf, verbose: bool) -> Result<()> {
    // Read and parse the file
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config file: {:?}", path))?;

    let config: ToolConfig =
        serde_yaml::from_str(&content).context("Failed to parse YAML config")?;

    // Validate the config
    match validate_config(&config) {
        Ok(_) => {
            println!("✓ Configuration is valid: {:?}", path);
            if verbose {
                println!("\nConfiguration summary:");
                println!("  Version: {}", config.version);
                println!("  Categories: {}", config.tools.categories.len());
                println!("  Tool overrides: {}", config.tools.overrides.len());
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("✗ Configuration validation failed: {:?}", path);
            if verbose {
                eprintln!("\nError details:");
                eprintln!("  {:#}", e);
            } else {
                eprintln!("  {}", e);
                eprintln!("\nUse --verbose for detailed error information");
            }
            std::process::exit(1);
        }
    }
}

async fn cmd_init(preset: Option<String>, project: bool, user: bool, neural: bool) -> Result<()> {
    // If --neural flag is set, run the neural API key wizard instead
    if neural {
        use crate::config::wizard::NeuralWizard;
        let wizard = NeuralWizard::new();
        return wizard.run().await;
    }
    // Determine target path
    let target_path = if project {
        PathBuf::from(".narsil.yaml")
    } else if user {
        get_user_config_path()?
    } else {
        // Interactive: ask user
        println!("Where should the config be created?");
        println!("  1. User config (~/.config/narsil-mcp/config.yaml) - applies to all projects");
        println!("  2. Project config (.narsil.yaml) - applies to this project only");
        print!("Choice [1]: ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let choice = input.trim();

        if choice == "2" {
            PathBuf::from(".narsil.yaml")
        } else {
            get_user_config_path()?
        }
    };

    // Check if file exists
    if target_path.exists() {
        eprintln!(
            "Error: Configuration file already exists: {:?}",
            target_path
        );
        eprintln!("Remove it first or use 'config preset' to update");
        std::process::exit(1);
    }

    // Determine preset
    let preset_name = if let Some(p) = preset {
        p
    } else {
        // Interactive: ask user
        println!("\nWhich preset would you like to use?");
        println!("  1. minimal - Fast, lightweight (20-30 tools)");
        println!("  2. balanced - Full-featured for IDEs (40-50 tools) [default]");
        println!("  3. full - All tools (70+ tools)");
        println!("  4. security-focused - Security and supply chain (~35 tools)");
        print!("Choice [2]: ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let choice = input.trim();

        match choice {
            "1" => "minimal".to_string(),
            "3" => "full".to_string(),
            "4" => "security-focused".to_string(),
            _ => "balanced".to_string(),
        }
    };

    // Validate preset name
    if !["minimal", "balanced", "full", "security-focused"].contains(&preset_name.as_str()) {
        eprintln!(
            "Error: Invalid preset '{}'. Valid presets: minimal, balanced, full, security-focused",
            preset_name
        );
        std::process::exit(1);
    }

    // Read example config from examples/configs/
    let example_path = PathBuf::from("examples/configs").join(format!("{}.yaml", preset_name));
    let content = if example_path.exists() {
        std::fs::read_to_string(&example_path)
            .with_context(|| format!("Failed to read example config: {:?}", example_path))?
    } else {
        // Fallback: generate minimal config
        format!(
            r#"version: "1.0"
preset: "{}"
"#,
            preset_name
        )
    };

    // Create parent directory if needed
    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write config
    std::fs::write(&target_path, content)
        .with_context(|| format!("Failed to write config file: {:?}", target_path))?;

    println!("✓ Created configuration file: {:?}", target_path);
    println!("\nNext steps:");
    println!("  1. Edit the config file to customize settings");
    println!(
        "  2. Validate: narsil-mcp config validate {:?}",
        target_path
    );
    println!("  3. Start server: narsil-mcp --repos ~/project");

    Ok(())
}

fn cmd_preset(preset: String, project: bool) -> Result<()> {
    // Validate preset name
    if !["minimal", "balanced", "full", "security-focused"].contains(&preset.as_str()) {
        eprintln!(
            "Error: Invalid preset '{}'. Valid presets: minimal, balanced, full, security-focused",
            preset
        );
        std::process::exit(1);
    }

    let target_path = if project {
        PathBuf::from(".narsil.yaml")
    } else {
        get_user_config_path()?
    };

    // Read example config
    let example_path = PathBuf::from("examples/configs").join(format!("{}.yaml", preset));
    let content = if example_path.exists() {
        std::fs::read_to_string(&example_path)?
    } else {
        format!(
            r#"version: "1.0"
preset: "{}"
"#,
            preset
        )
    };

    // Create parent directory if needed
    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write config (overwrite existing)
    std::fs::write(&target_path, content)?;

    println!("✓ Applied '{}' preset to: {:?}", preset, target_path);
    println!("\nPreset summary:");
    match preset.as_str() {
        "minimal" => println!("  20-30 tools for fast, lightweight editing"),
        "balanced" => println!("  40-50 tools for full-featured IDE development"),
        "full" => println!("  All 79 tools for comprehensive analysis"),
        "security-focused" => println!("  ~35 tools for security auditing"),
        _ => {}
    }

    Ok(())
}

fn cmd_export(resolved: bool, format: OutputFormat) -> Result<()> {
    let loader = ConfigLoader::new();
    let config = loader.load()?;

    if resolved {
        // If a preset is specified, note that it's been resolved
        if let Some(preset) = &config.preset {
            eprintln!("# Configuration with '{}' preset resolved", preset);
        }
    }

    match format {
        OutputFormat::Yaml => {
            let yaml = serde_yaml::to_string(&config)?;
            println!("{}", yaml);
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&config)?;
            println!("{}", json);
        }
        OutputFormat::Table => {
            eprintln!("Error: table format not supported for export, use yaml or json");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn cmd_tools_list(category: Option<String>, format: OutputFormat) -> Result<()> {
    let tools: Vec<_> = if let Some(cat) = category {
        TOOL_METADATA
            .iter()
            .filter(|(_, meta)| meta.category.to_string() == cat)
            .collect()
    } else {
        TOOL_METADATA.iter().collect()
    };

    match format {
        OutputFormat::Table => {
            println!("Available Tools ({} total):", tools.len());
            println!("{:-<80}", "");
            for (name, meta) in tools {
                println!("{:<30} {:<15} {}", name, meta.category, meta.description);
            }
        }
        OutputFormat::Yaml => {
            let tools_data: Vec<_> = tools
                .iter()
                .map(|(name, meta)| {
                    serde_json::json!({
                        "name": name,
                        "category": meta.category.to_string(),
                        "description": meta.description,
                        "stability": format!("{:?}", meta.stability),
                        "performance": format!("{:?}", meta.performance),
                    })
                })
                .collect();
            let yaml = serde_yaml::to_string(&tools_data)?;
            println!("{}", yaml);
        }
        OutputFormat::Json => {
            let tools_data: Vec<_> = tools
                .iter()
                .map(|(name, meta)| {
                    serde_json::json!({
                        "name": name,
                        "category": meta.category.to_string(),
                        "description": meta.description,
                        "stability": format!("{:?}", meta.stability),
                        "performance": format!("{:?}", meta.performance),
                    })
                })
                .collect();
            let json = serde_json::to_string_pretty(&tools_data)?;
            println!("{}", json);
        }
    }

    Ok(())
}

fn cmd_tools_search(query: String, format: OutputFormat) -> Result<()> {
    let query_lower = query.to_lowercase();
    let matching_tools: Vec<_> = TOOL_METADATA
        .iter()
        .filter(|(name, meta)| {
            name.to_lowercase().contains(&query_lower)
                || meta.description.to_lowercase().contains(&query_lower)
                || meta
                    .category
                    .to_string()
                    .to_lowercase()
                    .contains(&query_lower)
        })
        .collect();

    if matching_tools.is_empty() {
        println!("No tools found matching '{}'", query);
        return Ok(());
    }

    match format {
        OutputFormat::Table => {
            println!(
                "Tools matching '{}' ({} found):",
                query,
                matching_tools.len()
            );
            println!("{:-<80}", "");
            for (name, meta) in matching_tools {
                println!("{:<30} {:<15} {}", name, meta.category, meta.description);
            }
        }
        OutputFormat::Yaml | OutputFormat::Json => {
            let tools_data: Vec<_> = matching_tools
                .iter()
                .map(|(name, meta)| {
                    serde_json::json!({
                        "name": name,
                        "category": meta.category.to_string(),
                        "description": meta.description,
                    })
                })
                .collect();

            if format == OutputFormat::Yaml {
                let yaml = serde_yaml::to_string(&tools_data)?;
                println!("{}", yaml);
            } else {
                let json = serde_json::to_string_pretty(&tools_data)?;
                println!("{}", json);
            }
        }
    }

    Ok(())
}

fn cmd_tools_show(tool: String, format: OutputFormat) -> Result<()> {
    let meta = TOOL_METADATA
        .get(tool.as_str())
        .with_context(|| format!("Tool '{}' not found", tool))?;

    match format {
        OutputFormat::Yaml => {
            let data = serde_json::json!({
                "name": tool,
                "description": meta.description,
                "category": meta.category.to_string(),
                "stability": format!("{:?}", meta.stability),
                "performance": format!("{:?}", meta.performance),
                "requires_api_key": meta.requires_api_key,
                "required_flags": meta.required_flags.iter().map(|f| format!("{:?}", f)).collect::<Vec<_>>(),
                "input_schema": meta.input_schema,
            });
            let yaml = serde_yaml::to_string(&data)?;
            println!("{}", yaml);
        }
        OutputFormat::Json => {
            let data = serde_json::json!({
                "name": tool,
                "description": meta.description,
                "category": meta.category.to_string(),
                "stability": format!("{:?}", meta.stability),
                "performance": format!("{:?}", meta.performance),
                "requires_api_key": meta.requires_api_key,
                "required_flags": meta.required_flags.iter().map(|f| format!("{:?}", f)).collect::<Vec<_>>(),
                "input_schema": meta.input_schema,
            });
            let json = serde_json::to_string_pretty(&data)?;
            println!("{}", json);
        }
        OutputFormat::Table => {
            println!("Tool: {}", tool);
            println!("{:-<80}", "");
            println!("Description: {}", meta.description);
            println!("Category: {}", meta.category);
            println!("Stability: {:?}", meta.stability);
            println!("Performance: {:?}", meta.performance);
            println!("Requires API Key: {}", meta.requires_api_key);
            if !meta.required_flags.is_empty() {
                println!("Required Flags: {:?}", meta.required_flags);
            }
            println!("\nInput Schema:");
            println!("{}", serde_json::to_string_pretty(&meta.input_schema)?);
        }
    }

    Ok(())
}

fn get_user_config_path() -> Result<PathBuf> {
    if let Ok(custom) = std::env::var("NARSIL_CONFIG_PATH") {
        Ok(PathBuf::from(custom))
    } else {
        use directories::ProjectDirs;
        let proj_dirs = ProjectDirs::from("com", "anthropic", "narsil-mcp")
            .context("Failed to determine config directory")?;
        Ok(proj_dirs.config_dir().join("config.yaml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_user_config_path() {
        let path = get_user_config_path().unwrap();
        assert!(path.to_string_lossy().contains("narsil-mcp"));
        assert!(path.to_string_lossy().ends_with("config.yaml"));
    }

    #[test]
    fn test_output_format_variants() {
        // Ensure OutputFormat enum has expected variants
        let _ = OutputFormat::Yaml;
        let _ = OutputFormat::Json;
        let _ = OutputFormat::Table;
    }
}
