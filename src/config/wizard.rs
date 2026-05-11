use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use super::editor::{detect_available_editors, EditorConfig, EditorType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiProvider {
    Voyage,
    OpenAI,
    Custom,
}

impl ApiProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "voyage" | "1" => Some(ApiProvider::Voyage),
            "openai" | "2" => Some(ApiProvider::OpenAI),
            "custom" | "3" => Some(ApiProvider::Custom),
            _ => None,
        }
    }

    pub fn env_var_name(&self) -> &'static str {
        match self {
            ApiProvider::Voyage => "VOYAGE_API_KEY",
            ApiProvider::OpenAI => "OPENAI_API_KEY",
            ApiProvider::Custom => "EMBEDDING_API_KEY",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ApiProvider::Voyage => "Voyage AI",
            ApiProvider::OpenAI => "OpenAI",
            ApiProvider::Custom => "Custom Endpoint",
        }
    }
}

pub struct NeuralWizard;

impl Default for NeuralWizard {
    fn default() -> Self {
        NeuralWizard
    }
}

impl NeuralWizard {
    pub fn new() -> Self {
        NeuralWizard
    }

    /// Run the interactive wizard
    pub async fn run(&self) -> Result<()> {
        println!("\n🧙 Neural Embedding API Key Setup Wizard\n");
        println!("This wizard will help you configure neural embedding for narsil-mcp.");
        println!("Neural embeddings enable advanced code similarity search.\n");

        // Step 1: Detect available editors
        let editors = detect_available_editors();
        let available_editors: Vec<_> = editors.iter().filter(|e| e.exists).collect();

        if available_editors.is_empty() {
            println!("⚠️  No supported editor config files found.");
            println!("   Supported editors: Claude Desktop, Claude Code, Zed, VS Code, JetBrains");
            println!("   Please create a config file manually or run this wizard from your");
            println!("   project directory (for VS Code/JetBrains).\n");
            return Ok(());
        }

        // Step 2: Select editor
        println!("Available editors:\n");
        for (i, editor) in available_editors.iter().enumerate() {
            println!(
                "  {}. {} ({})",
                i + 1,
                editor.editor_type,
                editor.config_path.display()
            );
        }

        let selected_editor = self.prompt_for_editor(&available_editors)?;

        // Step 3: Select provider
        println!("\nSelect your embedding provider:\n");
        println!("  1. Voyage AI (recommended for code, voyage-code-2)");
        println!("  2. OpenAI (text-embedding-3-small or ada-002)");
        println!("  3. Custom endpoint (self-hosted or other provider)\n");

        let provider = self.prompt_for_provider()?;

        // Step 4: Get API key
        println!("\nEnter your {} API key:", provider.display_name());
        println!("(The key will be stored in your editor's config file)\n");

        let api_key = self.prompt_for_api_key(provider)?;

        // Step 5: Validate key (optional, can be slow)
        println!("\nValidate API key? (y/n) [y]: ");
        io::stdout().flush()?;
        let mut validate = String::new();
        io::stdin().read_line(&mut validate)?;
        let validate = validate.trim().is_empty() || validate.trim().to_lowercase() == "y";

        if validate {
            print!("Validating API key... ");
            io::stdout().flush()?;
            match self.validate_api_key(&api_key, provider).await {
                Ok(_) => println!("✅ Valid!"),
                Err(e) => {
                    println!("❌ Failed: {}", e);
                    println!("Continue anyway? (y/n) [n]: ");
                    io::stdout().flush()?;
                    let mut cont = String::new();
                    io::stdin().read_line(&mut cont)?;
                    if cont.trim().to_lowercase() != "y" {
                        return Ok(());
                    }
                }
            }
        }

        // Step 6: Add to editor config
        println!(
            "\nAdding API key to {}...",
            selected_editor.config_path.display()
        );

        self.add_to_editor_config(
            &selected_editor.config_path,
            provider.env_var_name(),
            &api_key,
        )
        .await?;

        println!("\n✅ Success! Neural embeddings are now configured.");
        println!("\nNext steps:");
        println!("  1. Restart your editor to pick up the new config");
        println!("  2. Run narsil-mcp with the --neural flag:");
        println!("     narsil-mcp --repos ~/code --neural\n");

        Ok(())
    }

    fn prompt_for_editor<'a>(&self, editors: &'a [&EditorConfig]) -> Result<&'a EditorConfig> {
        print!("Select editor (1-{}): ", editors.len());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let choice: usize = input.trim().parse().context("Invalid selection")?;

        editors
            .get(choice - 1)
            .copied()
            .context("Invalid editor number")
    }

    fn prompt_for_provider(&self) -> Result<ApiProvider> {
        print!("Select provider (1-3): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        ApiProvider::parse(input.trim()).context("Invalid provider selection")
    }

    fn prompt_for_api_key(&self, provider: ApiProvider) -> Result<String> {
        print!("API key: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let key = Self::sanitize_api_key(input.trim());

        // Validate format
        if !Self::validate_key_format(&key, provider) {
            anyhow::bail!("Invalid API key format for {}", provider.display_name());
        }

        Ok(key)
    }

    pub fn sanitize_api_key(key: &str) -> String {
        key.trim().trim_matches('"').trim_matches('\'').to_string()
    }

    pub fn validate_key_format(key: &str, provider: ApiProvider) -> bool {
        match provider {
            ApiProvider::Voyage => key.starts_with("pa-") && key.len() > 10,
            ApiProvider::OpenAI => key.starts_with("sk-") && key.len() > 10,
            ApiProvider::Custom => !key.is_empty(),
        }
    }

    async fn validate_api_key(&self, _key: &str, _provider: ApiProvider) -> Result<()> {
        // The wizard keeps setup offline; provider-side validation happens
        // when embeddings are first used.
        Ok(())
    }

    pub async fn add_to_editor_config(
        &self,
        config_path: &Path,
        env_var_name: &str,
        api_key: &str,
    ) -> Result<()> {
        // Create parent directories if needed
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Read existing config or create new
        let mut config: Value = if config_path.exists() {
            let content = fs::read_to_string(config_path).context("Failed to read config file")?;
            serde_json::from_str(&content).context("Failed to parse existing config as JSON")?
        } else {
            json!({})
        };

        // Determine the config key based on editor type
        let editor_type = self.detect_editor_type(config_path)?;
        let server_key = Self::get_config_key_for_editor(editor_type);

        // Ensure the server entry exists
        if config.get(server_key).is_none() {
            config[server_key] = json!({});
        }

        // Ensure narsil-mcp server exists
        if config[server_key].get("narsil-mcp").is_none() {
            config[server_key]["narsil-mcp"] = json!({
                "command": "narsil-mcp",
                "args": ["--repos", ".", "--neural"]
            });
        }

        // Add/update env section
        if config[server_key]["narsil-mcp"].get("env").is_none() {
            config[server_key]["narsil-mcp"]["env"] = json!({});
        }

        config[server_key]["narsil-mcp"]["env"][env_var_name] = json!(api_key);

        // Write back
        let pretty = serde_json::to_string_pretty(&config)?;
        fs::write(config_path, pretty)?;

        Ok(())
    }

    fn detect_editor_type(&self, config_path: &Path) -> Result<EditorType> {
        let path_str = config_path.to_string_lossy();
        let filename = config_path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("");

        // Check by filename first
        if filename == "claude_desktop_config.json" {
            Ok(EditorType::ClaudeDesktop)
        } else if filename == "claude_code_config.json" {
            Ok(EditorType::ClaudeCode)
        } else if filename == "settings.json" && path_str.contains("zed") {
            Ok(EditorType::Zed)
        } else if filename == "settings.json" {
            // Assume Zed if just "settings.json"
            Ok(EditorType::Zed)
        } else if filename == "mcp.json" && path_str.contains(".vscode") {
            Ok(EditorType::VSCode)
        } else if filename == "mcp.json" && path_str.contains(".idea") {
            Ok(EditorType::JetBrains)
        } else if filename == "mcp.json" {
            // Default to VS Code for generic mcp.json
            Ok(EditorType::VSCode)
        } else if path_str.contains("zed") {
            Ok(EditorType::Zed)
        } else if path_str.contains(".vscode") {
            Ok(EditorType::VSCode)
        } else if path_str.contains(".idea") {
            Ok(EditorType::JetBrains)
        } else {
            anyhow::bail!("Unknown editor config path: {}", path_str)
        }
    }

    pub fn get_config_key_for_editor(editor_type: EditorType) -> &'static str {
        match editor_type {
            EditorType::ClaudeDesktop | EditorType::ClaudeCode => "mcpServers",
            EditorType::Zed => "context_servers",
            EditorType::VSCode | EditorType::JetBrains => "servers",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_provider_parse() {
        assert_eq!(ApiProvider::parse("voyage"), Some(ApiProvider::Voyage));
        assert_eq!(ApiProvider::parse("1"), Some(ApiProvider::Voyage));
        assert_eq!(ApiProvider::parse("openai"), Some(ApiProvider::OpenAI));
        assert_eq!(ApiProvider::parse("2"), Some(ApiProvider::OpenAI));
        assert_eq!(ApiProvider::parse("custom"), Some(ApiProvider::Custom));
        assert_eq!(ApiProvider::parse("invalid"), None);
    }

    #[test]
    fn test_env_var_name() {
        assert_eq!(ApiProvider::Voyage.env_var_name(), "VOYAGE_API_KEY");
        assert_eq!(ApiProvider::OpenAI.env_var_name(), "OPENAI_API_KEY");
        assert_eq!(ApiProvider::Custom.env_var_name(), "EMBEDDING_API_KEY");
    }

    #[test]
    fn test_validate_key_format() {
        assert!(NeuralWizard::validate_key_format(
            "pa-abc123456",
            ApiProvider::Voyage
        ));
        assert!(!NeuralWizard::validate_key_format(
            "invalid",
            ApiProvider::Voyage
        ));
        assert!(!NeuralWizard::validate_key_format(
            "pa-short",
            ApiProvider::Voyage
        )); // too short

        assert!(NeuralWizard::validate_key_format(
            "sk-abc123xyz",
            ApiProvider::OpenAI
        ));
        assert!(!NeuralWizard::validate_key_format(
            "invalid",
            ApiProvider::OpenAI
        ));
        assert!(!NeuralWizard::validate_key_format(
            "sk-short",
            ApiProvider::OpenAI
        )); // too short

        assert!(NeuralWizard::validate_key_format(
            "anything",
            ApiProvider::Custom
        ));
        assert!(!NeuralWizard::validate_key_format("", ApiProvider::Custom));
    }

    #[test]
    fn test_sanitize_api_key() {
        assert_eq!(NeuralWizard::sanitize_api_key("  pa-abc  "), "pa-abc");
        assert_eq!(NeuralWizard::sanitize_api_key("\"pa-abc\""), "pa-abc");
        assert_eq!(NeuralWizard::sanitize_api_key("'pa-abc'"), "pa-abc");
    }

    #[test]
    fn test_get_config_key() {
        assert_eq!(
            NeuralWizard::get_config_key_for_editor(EditorType::ClaudeDesktop),
            "mcpServers"
        );
        assert_eq!(
            NeuralWizard::get_config_key_for_editor(EditorType::Zed),
            "context_servers"
        );
        assert_eq!(
            NeuralWizard::get_config_key_for_editor(EditorType::VSCode),
            "servers"
        );
    }
}
