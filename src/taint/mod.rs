//! Taint Analysis module for security vulnerability detection.
//!
//! This module provides taint tracking capabilities to detect injection
//! vulnerabilities, data leaks, and missing sanitization in code.
//!
//! # Features
//! - Taint source identification (user input, file reads, network data)
//! - Taint sink detection (SQL queries, command execution, HTML output)
//! - Taint propagation through data flow
//! - Sanitizer recognition
//! - Vulnerability detection (SQL injection, XSS, command injection, path traversal)
//!
//! # Architecture
//!
//! The taint analysis module is organized into three submodules:
//!
//! - [`types`] - Core data types (sources, sinks, flows, vulnerabilities)
//! - [`patterns`] - Pattern definitions for identifying sources, sinks, and sanitizers
//! - [`analyzer`] - The main analysis engine
//!
//! # Usage
//!
//! The main entry point is [`analyze_code`] for simple analysis, or
//! [`analyzer::TaintAnalyzer`] for detailed control:
//!
//! ```
//! use narsil_mcp::taint::analyze_code;
//!
//! // Analyze Python code for taint flows
//! let code = r#"
//! user_input = request.args.get('q')
//! cursor.execute(user_input)
//! "#;
//!
//! let result = analyze_code(code, "app.py");
//! println!("Found {} vulnerabilities", result.vulnerabilities.len());
//! ```
//!
//! # Supported Languages
//!
//! The taint analyzer supports patterns for:
//! - Python (Flask, Django)
//! - JavaScript/TypeScript (Express, Node.js)
//! - Rust (Actix, SQLx)
//! - Go (net/http)
//! - Java (Servlet, Spring)
//! - C# (ASP.NET)
//! - PHP
//! - Ruby (Rails)
//! - Kotlin

pub mod analyzer;
pub mod patterns;
pub mod types;

// Re-export the main public API
pub use analyzer::analyze_code;

// Re-export types used throughout the crate
pub use types::{
    Confidence, Severity, SourceKind, TaintAnalysisResult, TaintFlow, TaintSource,
    VulnerabilityKind,
};

// Re-export configuration types
pub use patterns::{TaintConfig, TaintConfigError};

/// Analyze code with a custom taint configuration.
///
/// This function allows using custom sources, sinks, and sanitizers
/// loaded from a YAML configuration string.
///
/// # Arguments
///
/// * `source_code` - The source code to analyze
/// * `file_path` - The file path (used for language detection and reporting)
/// * `yaml_config` - Optional YAML configuration for custom patterns
///
/// # Returns
///
/// A `Result` containing the `TaintAnalysisResult` or a `TaintConfigError` if
/// the configuration is invalid.
///
/// # Examples
///
/// ```
/// use narsil_mcp::taint::analyze_code_with_config;
///
/// let code = "user_input = custom_source(); dangerous_sink(user_input)";
/// let config = r#"
/// sources:
///   - name: custom_source
///     function_patterns:
///       - "custom_source("
///     languages:
///       - python
/// "#;
///
/// let result = analyze_code_with_config(code, "app.py", Some(config));
/// ```
pub fn analyze_code_with_config(
    source_code: &str,
    file_path: &str,
    yaml_config: Option<&str>,
) -> Result<TaintAnalysisResult, TaintConfigError> {
    let config = match yaml_config {
        Some(yaml) => TaintConfig::from_yaml(yaml)?,
        None => TaintConfig::default(),
    };

    let language = analyzer::detect_language(file_path);
    let analyzer = analyzer::TaintAnalyzer::with_config(language, config);
    Ok(analyzer.analyze_code(source_code, file_path))
}
