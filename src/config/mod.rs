/// Configuration system for narsil-xref
///
/// This module provides a flexible configuration system that supports:
/// - YAML configuration files
/// - Multi-source config loading (default, user, project)
/// - Configuration validation
/// - Environment variable overrides
///
/// Configuration priority (highest to lowest):
/// 1. CLI flags (handled in main.rs)
/// 2. Environment variables (NARSIL_*)
/// 3. Project config (.narsil.yaml in repo root)
/// 4. User config (~/.config/narsil-xref/config.yaml)
/// 5. Default config (built-in)
pub mod cli;
pub mod expose;
pub mod filter;
pub mod loader;
pub mod schema;
pub mod validation;

// Re-export main types used by other modules and tests
pub use cli::{handle_config_command, handle_tools_command, ConfigCommand, ToolsCommand};
pub use expose::ExposeGroup;
pub use filter::ToolFilter;
pub use loader::ConfigLoader;
pub use validation::validate_config;

// Schema types are available at narsil_xref::config::schema::{ToolOverride, ...}
// for programmatic configuration construction.
