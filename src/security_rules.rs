//! Security Rules Engine for configurable vulnerability detection.
//!
//! This module provides a configurable security scanning engine with:
//! - YAML/TOML-based rule definitions
//! - Pattern-based detection
//! - Taint flow rules
//! - Control flow rules
//! - Built-in OWASP Top 10 and CWE Top 25 coverage
//!
//! # Rule Types
//! - **Pattern**: Regex-based pattern matching for anti-patterns
//! - **TaintFlow**: Source-to-sink taint tracking
//! - **ControlFlow**: Required operations before sensitive calls
//! - **Typestate**: State machine validation (future)

use crate::taint::{self, Confidence, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Check if a file path appears to be a test file.
///
/// This is used to exclude test files from security scanning by default,
/// as test files often contain intentional vulnerable code patterns for testing.
///
/// # Examples
/// ```
/// use narsil_mcp::security_rules::is_test_file;
/// assert!(is_test_file("tests/integration_tests.rs"));
/// assert!(is_test_file("src/foo_test.rs"));
/// assert!(!is_test_file("src/main.rs"));
/// ```
pub fn is_test_file(path: &str) -> bool {
    let path_lower = path.to_lowercase();

    // Directory patterns that indicate test code
    if path_lower.contains("/tests/")
        || path_lower.contains("/test/")
        || path_lower.contains("/__tests__/")
        || path_lower.contains("/fixtures/")
        || path_lower.contains("/testdata/")
        || path_lower.contains("/test_data/")
        || path_lower.contains("/mocks/")
        || path_lower.contains("/__mocks__/")
        || path_lower.contains("/spec/")
        // Also catch test-fixtures at start of path or after a slash
        || path_lower.starts_with("test-fixtures/")
        || path_lower.contains("/test-fixtures/")
        // Security test sample directories
        || path_lower.contains("/security/vulnerable")
        || path_lower.contains("/vulnerable/")
    {
        return true;
    }

    // File name patterns
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Rust test files
    if file_name.ends_with("_test.rs") || file_name.ends_with("_tests.rs") {
        return true;
    }

    // JavaScript/TypeScript test files
    if file_name.ends_with(".test.js")
        || file_name.ends_with(".test.ts")
        || file_name.ends_with(".test.jsx")
        || file_name.ends_with(".test.tsx")
        || file_name.ends_with(".spec.js")
        || file_name.ends_with(".spec.ts")
        || file_name.ends_with(".spec.jsx")
        || file_name.ends_with(".spec.tsx")
    {
        return true;
    }

    // Python test files
    if file_name.starts_with("test_") || file_name.ends_with("_test.py") {
        return true;
    }

    // Go test files
    if file_name.ends_with("_test.go") {
        return true;
    }

    // Java test files
    if file_name.ends_with("test.java") && file_name != "test.java" {
        return true;
    }

    // Files explicitly named as vulnerable samples
    if file_name.starts_with("vulnerable.") || file_name.starts_with("insecure.") {
        return true;
    }

    false
}

/// Check if a file is a security rule definition or exemplar file.
///
/// These files intentionally contain security patterns (like "md5", "password",
/// regex patterns for detecting vulnerabilities) and should be excluded from
/// scanning to avoid false positives.
///
/// # Examples
/// ```
/// use narsil_mcp::security_rules::is_security_exemplar_file;
/// assert!(is_security_exemplar_file("src/security_rules.rs"));
/// assert!(is_security_exemplar_file("rules/owasp-top10.yaml"));
/// assert!(!is_security_exemplar_file("src/main.rs"));
/// ```
pub fn is_security_exemplar_file(path: &str) -> bool {
    let path_lower = path.to_lowercase();

    // File name patterns for security rule definitions
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Security rule definition files
    if file_name == "security_rules.rs"
        || file_name == "security_config.rs"
        || file_name == "taint.rs"
    {
        return true;
    }

    // YAML/TOML rule definition files in rules/ directory
    if path_lower.contains("/rules/")
        && (file_name.ends_with(".yaml")
            || file_name.ends_with(".yml")
            || file_name.ends_with(".toml"))
    {
        return true;
    }

    // Common security rule file patterns
    if file_name.contains("security_rule")
        || file_name.contains("vuln_pattern")
        || file_name.contains("owasp")
        || file_name.contains("cwe-")
        || file_name.contains("cwe_")
    {
        return true;
    }

    false
}

/// Unique identifier for a security rule
pub type RuleId = String;

/// A security rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRule {
    /// Unique rule identifier (e.g., "OWASP-A03-001")
    pub id: RuleId,
    /// Human-readable rule name
    pub name: String,
    /// Severity of findings from this rule
    pub severity: Severity,
    /// Related CWE IDs
    #[serde(default)]
    pub cwe: Vec<String>,
    /// Related OWASP Top 10 categories
    #[serde(default)]
    pub owasp: Vec<String>,
    /// The type of rule and its configuration
    pub rule_type: RuleType,
    /// Languages this rule applies to (empty = all)
    #[serde(default)]
    pub languages: Vec<String>,
    /// Message to display when rule matches
    pub message: String,
    /// Suggested remediation
    #[serde(default)]
    pub remediation: String,
    /// Whether this rule is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Tags for filtering rules
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_enabled() -> bool {
    true
}

/// Types of security rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleType {
    /// Pattern-based detection using regex
    Pattern {
        /// Regex patterns to match (any match triggers rule)
        patterns: Vec<String>,
        /// Optional patterns that indicate safe usage (suppress finding)
        #[serde(default)]
        safe_patterns: Vec<String>,
    },
    /// Taint flow analysis from sources to sinks
    TaintFlow {
        /// Taint source patterns
        sources: Vec<String>,
        /// Taint sink patterns
        sinks: Vec<String>,
        /// Sanitizer patterns that break the flow
        #[serde(default)]
        sanitizers: Vec<String>,
    },
    /// Control flow requirements (operation A must happen before B)
    ControlFlow {
        /// Operations that must precede the sink
        required_before: Vec<String>,
        /// The sensitive operation (sink)
        sink: String,
    },
    /// Secret/credential detection
    Secret {
        /// Regex patterns for secrets
        patterns: Vec<String>,
        /// Entropy threshold (0.0-1.0) for random string detection
        #[serde(default)]
        entropy_threshold: Option<f64>,
    },
    /// Cryptographic misuse detection
    Crypto {
        /// Deprecated/weak algorithms
        weak_algorithms: Vec<String>,
        /// Insecure modes
        insecure_modes: Vec<String>,
        /// Insufficient key sizes
        min_key_size: Option<u32>,
    },
}

/// A security finding from rule evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Rule that triggered this finding
    pub rule_id: RuleId,
    /// Rule name
    pub rule_name: String,
    /// Severity of the finding
    pub severity: Severity,
    /// Confidence level
    pub confidence: Confidence,
    /// File where finding was detected
    pub file_path: String,
    /// Line number (1-indexed)
    pub line: usize,
    /// Column number (1-indexed)
    pub column: usize,
    /// End line
    pub end_line: usize,
    /// End column
    pub end_column: usize,
    /// Code snippet that triggered the finding
    pub snippet: String,
    /// Detailed message
    pub message: String,
    /// Suggested fix
    pub remediation: String,
    /// Related CWE IDs
    pub cwe: Vec<String>,
    /// Related OWASP categories
    pub owasp: Vec<String>,
    /// Additional context
    #[serde(default)]
    pub context: HashMap<String, String>,
}

/// A ruleset containing multiple rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ruleset {
    /// Ruleset name
    pub name: String,
    /// Ruleset version
    pub version: String,
    /// Description
    #[serde(default)]
    pub description: String,
    /// Rules in this set
    pub rules: Vec<SecurityRule>,
}

/// Security Rules Engine for scanning code
pub struct SecurityRulesEngine {
    /// Loaded rules indexed by ID
    rules: HashMap<RuleId, SecurityRule>,
    /// Compiled pattern matchers
    pattern_cache: HashMap<String, Regex>,
    /// Rules grouped by language
    rules_by_language: HashMap<String, Vec<RuleId>>,
    /// OWASP Top 10 rules
    owasp_rules: Vec<RuleId>,
    /// CWE Top 25 rules
    cwe_top25_rules: Vec<RuleId>,
}

impl Default for SecurityRulesEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityRulesEngine {
    /// Create a new security rules engine with built-in rules
    pub fn new() -> Self {
        let mut engine = Self {
            rules: HashMap::new(),
            pattern_cache: HashMap::new(),
            rules_by_language: HashMap::new(),
            owasp_rules: Vec::new(),
            cwe_top25_rules: Vec::new(),
        };
        engine.load_builtin_rules();

        // Load bundled YAML rulesets
        engine.load_bundled_yaml_rules();

        engine
    }

    /// Load bundled YAML rules from the rules/ directory (embedded at compile time)
    fn load_bundled_yaml_rules(&mut self) {
        // OWASP Top 10 rules (includes Go, Java, C#, Ruby, Kotlin, PHP, TypeScript)
        let owasp_yaml = include_str!("../rules/owasp-top10.yaml");
        if let Err(e) = self.load_ruleset_yaml(owasp_yaml) {
            eprintln!("Warning: Failed to load OWASP rules: {}", e);
        }

        // CWE Top 25 rules (includes Rust rules)
        let cwe_yaml = include_str!("../rules/cwe-top25.yaml");
        if let Err(e) = self.load_ruleset_yaml(cwe_yaml) {
            eprintln!("Warning: Failed to load CWE rules: {}", e);
        }

        // Bash security rules
        let bash_yaml = include_str!("../rules/bash.yaml");
        if let Err(e) = self.load_ruleset_yaml(bash_yaml) {
            eprintln!("Warning: Failed to load Bash rules: {}", e);
        }

        // Go-specific security rules
        let go_yaml = include_str!("../rules/go.yaml");
        if let Err(e) = self.load_ruleset_yaml(go_yaml) {
            eprintln!("Warning: Failed to load Go rules: {}", e);
        }

        // Java-specific security rules
        let java_yaml = include_str!("../rules/java.yaml");
        if let Err(e) = self.load_ruleset_yaml(java_yaml) {
            eprintln!("Warning: Failed to load Java rules: {}", e);
        }

        // C#-specific security rules
        let csharp_yaml = include_str!("../rules/csharp.yaml");
        if let Err(e) = self.load_ruleset_yaml(csharp_yaml) {
            eprintln!("Warning: Failed to load C# rules: {}", e);
        }

        // Kotlin-specific security rules
        let kotlin_yaml = include_str!("../rules/kotlin.yaml");
        if let Err(e) = self.load_ruleset_yaml(kotlin_yaml) {
            eprintln!("Warning: Failed to load Kotlin rules: {}", e);
        }

        // Configuration security rules (YAML misconfigurations)
        let config_yaml = include_str!("../rules/config.yaml");
        if let Err(e) = self.load_ruleset_yaml(config_yaml) {
            eprintln!("Warning: Failed to load Config rules: {}", e);
        }

        // Infrastructure as Code security rules (Docker, K8s, Terraform, CloudFormation)
        let iac_yaml = include_str!("../rules/iac.yaml");
        if let Err(e) = self.load_ruleset_yaml(iac_yaml) {
            eprintln!("Warning: Failed to load IaC rules: {}", e);
        }

        // Rust-specific security rules (extends RUST-001..003 in cwe-top25.yaml)
        let rust_yaml = include_str!("../rules/rust.yaml");
        if let Err(e) = self.load_ruleset_yaml(rust_yaml) {
            eprintln!("Warning: Failed to load Rust rules: {}", e);
        }

        // Elixir-specific security rules
        let elixir_yaml = include_str!("../rules/elixir.yaml");
        if let Err(e) = self.load_ruleset_yaml(elixir_yaml) {
            eprintln!("Warning: Failed to load Elixir rules: {}", e);
        }
    }

    /// Load a ruleset from YAML string
    pub fn load_ruleset_yaml(&mut self, yaml: &str) -> Result<usize, String> {
        let ruleset: Ruleset = serde_saphyr::from_str(yaml)
            .map_err(|e| format!("Failed to parse YAML ruleset: {}", e))?;

        let count = ruleset.rules.len();
        for rule in ruleset.rules {
            self.add_rule(rule);
        }
        Ok(count)
    }

    /// Load a ruleset from TOML string
    pub fn load_ruleset_toml(&mut self, toml_str: &str) -> Result<usize, String> {
        let ruleset: Ruleset =
            toml::from_str(toml_str).map_err(|e| format!("Failed to parse TOML ruleset: {}", e))?;

        let count = ruleset.rules.len();
        for rule in ruleset.rules {
            self.add_rule(rule);
        }
        Ok(count)
    }

    /// Add a single rule
    pub fn add_rule(&mut self, rule: SecurityRule) {
        // Pre-compile patterns
        if let RuleType::Pattern {
            ref patterns,
            ref safe_patterns,
        } = rule.rule_type
        {
            for pattern in patterns.iter().chain(safe_patterns.iter()) {
                if !self.pattern_cache.contains_key(pattern) {
                    if let Ok(re) = Regex::new(pattern) {
                        self.pattern_cache.insert(pattern.clone(), re);
                    }
                }
            }
        }

        // Index by language
        if rule.languages.is_empty() {
            // Applies to all languages
            self.rules_by_language
                .entry("*".to_string())
                .or_default()
                .push(rule.id.clone());
        } else {
            for lang in &rule.languages {
                self.rules_by_language
                    .entry(lang.clone())
                    .or_default()
                    .push(rule.id.clone());
            }
        }

        // Index by OWASP
        if !rule.owasp.is_empty() {
            self.owasp_rules.push(rule.id.clone());
        }

        // Index by CWE (check if it's in CWE Top 25)
        for cwe in &rule.cwe {
            if is_cwe_top25(cwe) {
                self.cwe_top25_rules.push(rule.id.clone());
                break;
            }
        }

        self.rules.insert(rule.id.clone(), rule);
    }

    /// Scan code for security issues
    pub fn scan(&self, code: &str, file_path: &str, language: &str) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // Get applicable rules
        let rule_ids = self.get_applicable_rules(language);

        for rule_id in rule_ids {
            if let Some(rule) = self.rules.get(&rule_id) {
                if !rule.enabled {
                    continue;
                }

                let rule_findings = self.evaluate_rule(rule, code, file_path);
                findings.extend(rule_findings);
            }
        }

        // Sort by severity (Critical first)
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings
    }

    /// Scan for OWASP Top 10 issues only
    pub fn scan_owasp_top10(
        &self,
        code: &str,
        file_path: &str,
        language: &str,
    ) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        for rule_id in &self.owasp_rules {
            if let Some(rule) = self.rules.get(rule_id) {
                if !rule.enabled {
                    continue;
                }
                if !rule.languages.is_empty() && !rule.languages.contains(&language.to_string()) {
                    continue;
                }
                let rule_findings = self.evaluate_rule(rule, code, file_path);
                findings.extend(rule_findings);
            }
        }

        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings
    }

    /// Scan for CWE Top 25 issues only
    pub fn scan_cwe_top25(
        &self,
        code: &str,
        file_path: &str,
        language: &str,
    ) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        for rule_id in &self.cwe_top25_rules {
            if let Some(rule) = self.rules.get(rule_id) {
                if !rule.enabled {
                    continue;
                }
                if !rule.languages.is_empty() && !rule.languages.contains(&language.to_string()) {
                    continue;
                }
                let rule_findings = self.evaluate_rule(rule, code, file_path);
                findings.extend(rule_findings);
            }
        }

        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings
    }

    /// Scan using only rules that match any of the specified tags
    /// Tags can be rule categories like "crypto", "injection", "secrets", "memory", etc.
    pub fn scan_with_tags(
        &self,
        code: &str,
        file_path: &str,
        language: &str,
        tags: &[&str],
    ) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        for rule in self.rules.values() {
            if !rule.enabled {
                continue;
            }

            // Check if rule applies to this language
            if !rule.languages.is_empty() && !rule.languages.contains(&language.to_string()) {
                continue;
            }

            // Check if rule has any of the requested tags
            let has_matching_tag = rule.tags.iter().any(|t| tags.contains(&t.as_str()));
            if !has_matching_tag {
                continue;
            }

            let rule_findings = self.evaluate_rule(rule, code, file_path);
            findings.extend(rule_findings);
        }

        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings
    }

    /// Get all available tags across all rules
    pub fn available_tags(&self) -> Vec<String> {
        let mut tags: std::collections::HashSet<String> = std::collections::HashSet::new();
        for rule in self.rules.values() {
            for tag in &rule.tags {
                tags.insert(tag.clone());
            }
        }
        let mut result: Vec<_> = tags.into_iter().collect();
        result.sort();
        result
    }

    /// Get applicable rules for a language
    fn get_applicable_rules(&self, language: &str) -> Vec<RuleId> {
        let mut rules = Vec::new();

        // Add universal rules
        if let Some(universal) = self.rules_by_language.get("*") {
            rules.extend(universal.clone());
        }

        // Add language-specific rules
        if let Some(lang_rules) = self.rules_by_language.get(language) {
            rules.extend(lang_rules.clone());
        }

        rules
    }

    /// Evaluate a single rule against code
    fn evaluate_rule(
        &self,
        rule: &SecurityRule,
        code: &str,
        file_path: &str,
    ) -> Vec<SecurityFinding> {
        match &rule.rule_type {
            RuleType::Pattern {
                patterns,
                safe_patterns,
            } => self.evaluate_pattern_rule(rule, code, file_path, patterns, safe_patterns),
            RuleType::TaintFlow {
                sources,
                sinks,
                sanitizers,
            } => self.evaluate_taint_rule(rule, code, file_path, sources, sinks, sanitizers),
            RuleType::ControlFlow {
                required_before,
                sink,
            } => self.evaluate_control_flow_rule(rule, code, file_path, required_before, sink),
            RuleType::Secret {
                patterns,
                entropy_threshold,
            } => self.evaluate_secret_rule(rule, code, file_path, patterns, *entropy_threshold),
            RuleType::Crypto {
                weak_algorithms,
                insecure_modes,
                min_key_size,
            } => self.evaluate_crypto_rule(
                rule,
                code,
                file_path,
                weak_algorithms,
                insecure_modes,
                *min_key_size,
            ),
        }
    }

    /// Evaluate pattern-based rule
    fn evaluate_pattern_rule(
        &self,
        rule: &SecurityRule,
        code: &str,
        file_path: &str,
        patterns: &[String],
        safe_patterns: &[String],
    ) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = code.lines().collect();

        for pattern in patterns {
            if let Some(re) = self.pattern_cache.get(pattern) {
                for mat in re.find_iter(code) {
                    let start_byte = mat.start();
                    let end_byte = mat.end();

                    // Get line and column
                    let (line, col) = byte_to_line_col(code, start_byte);
                    let (end_line, end_col) = byte_to_line_col(code, end_byte);

                    // Check if this is suppressed by a safe pattern
                    let line_text = lines.get(line.saturating_sub(1)).unwrap_or(&"");
                    let is_safe = safe_patterns.iter().any(|sp| {
                        self.pattern_cache
                            .get(sp)
                            .map(|re| re.is_match(line_text))
                            .unwrap_or(false)
                    });

                    if is_safe {
                        continue;
                    }

                    findings.push(SecurityFinding {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: rule.severity,
                        confidence: Confidence::Medium,
                        file_path: file_path.to_string(),
                        line,
                        column: col,
                        end_line,
                        end_column: end_col,
                        snippet: mat.as_str().to_string(),
                        message: rule.message.clone(),
                        remediation: rule.remediation.clone(),
                        cwe: rule.cwe.clone(),
                        owasp: rule.owasp.clone(),
                        context: HashMap::new(),
                    });
                }
            }
        }

        findings
    }

    /// Evaluate taint flow rule
    fn evaluate_taint_rule(
        &self,
        rule: &SecurityRule,
        code: &str,
        file_path: &str,
        _sources: &[String],
        _sinks: &[String],
        _sanitizers: &[String],
    ) -> Vec<SecurityFinding> {
        // Use the existing taint analyzer
        let taint_result = taint::analyze_code(code, file_path);

        let mut findings = Vec::new();

        // Map vulnerabilities (unsanitized taint flows) to security findings
        for flow in taint_result.vulnerabilities {
            if let Some(ref vuln_kind) = flow.vulnerability {
                findings.push(SecurityFinding {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: flow.severity.unwrap_or(Severity::Medium),
                    confidence: flow.confidence,
                    file_path: flow.sink.file_path.clone(),
                    line: flow.sink.line,
                    column: 1,
                    end_line: flow.sink.line,
                    end_column: 80,
                    snippet: flow.sink.code.clone(),
                    message: format!(
                        "{}: {} flows to {}",
                        vuln_kind.display_name(),
                        flow.source.variable,
                        flow.sink.function
                    ),
                    remediation: rule.remediation.clone(),
                    cwe: vuln_kind
                        .cwe_id()
                        .map(|s| s.to_string())
                        .into_iter()
                        .collect(),
                    owasp: vuln_kind
                        .owasp_category()
                        .map(|s| s.to_string())
                        .into_iter()
                        .collect(),
                    context: HashMap::new(),
                });
            }
        }

        findings
    }

    /// Evaluate control flow rule
    fn evaluate_control_flow_rule(
        &self,
        rule: &SecurityRule,
        code: &str,
        file_path: &str,
        required_before: &[String],
        sink: &str,
    ) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = code.lines().collect();

        // Compile patterns
        let sink_re = match Regex::new(sink) {
            Ok(re) => re,
            Err(_) => return findings,
        };

        let required_patterns: Vec<Regex> = required_before
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        // Find all sink locations
        for (line_idx, line) in lines.iter().enumerate() {
            if sink_re.is_match(line) {
                // Check if any required operation appears before this line
                let has_required = lines[..line_idx]
                    .iter()
                    .any(|prev_line| required_patterns.iter().any(|re| re.is_match(prev_line)));

                if !has_required {
                    findings.push(SecurityFinding {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: rule.severity,
                        confidence: Confidence::Medium,
                        file_path: file_path.to_string(),
                        line: line_idx + 1,
                        column: 1,
                        end_line: line_idx + 1,
                        end_column: line.len(),
                        snippet: line.to_string(),
                        message: rule.message.clone(),
                        remediation: rule.remediation.clone(),
                        cwe: rule.cwe.clone(),
                        owasp: rule.owasp.clone(),
                        context: HashMap::new(),
                    });
                }
            }
        }

        findings
    }

    /// Evaluate secret detection rule
    fn evaluate_secret_rule(
        &self,
        rule: &SecurityRule,
        code: &str,
        file_path: &str,
        patterns: &[String],
        entropy_threshold: Option<f64>,
    ) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // Pattern-based secret detection
        for pattern in patterns {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(code) {
                    let start_byte = mat.start();
                    let (line, col) = byte_to_line_col(code, start_byte);

                    // Check entropy if threshold specified
                    let matched_text = mat.as_str();
                    if let Some(threshold) = entropy_threshold {
                        let entropy = calculate_entropy(matched_text);
                        if entropy < threshold {
                            continue;
                        }
                    }

                    findings.push(SecurityFinding {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: rule.severity,
                        confidence: Confidence::High,
                        file_path: file_path.to_string(),
                        line,
                        column: col,
                        end_line: line,
                        end_column: col + matched_text.len(),
                        snippet: redact_secret(matched_text),
                        message: rule.message.clone(),
                        remediation: rule.remediation.clone(),
                        cwe: rule.cwe.clone(),
                        owasp: rule.owasp.clone(),
                        context: HashMap::new(),
                    });
                }
            }
        }

        findings
    }

    /// Evaluate cryptographic misuse rule
    fn evaluate_crypto_rule(
        &self,
        rule: &SecurityRule,
        code: &str,
        file_path: &str,
        weak_algorithms: &[String],
        insecure_modes: &[String],
        _min_key_size: Option<u32>,
    ) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // Check for weak algorithms
        for algo in weak_algorithms {
            if let Ok(re) = Regex::new(&format!(r"(?i)\b{}\b", regex::escape(algo))) {
                for mat in re.find_iter(code) {
                    let (line, col) = byte_to_line_col(code, mat.start());
                    findings.push(SecurityFinding {
                        rule_id: rule.id.clone(),
                        rule_name: format!("{} - Weak Algorithm", rule.name),
                        severity: rule.severity,
                        confidence: Confidence::High,
                        file_path: file_path.to_string(),
                        line,
                        column: col,
                        end_line: line,
                        end_column: col + mat.len(),
                        snippet: mat.as_str().to_string(),
                        message: format!("Use of weak/deprecated algorithm: {}", algo),
                        remediation: rule.remediation.clone(),
                        cwe: rule.cwe.clone(),
                        owasp: rule.owasp.clone(),
                        context: HashMap::new(),
                    });
                }
            }
        }

        // Check for insecure modes
        for mode in insecure_modes {
            if let Ok(re) = Regex::new(&format!(r"(?i)\b{}\b", regex::escape(mode))) {
                for mat in re.find_iter(code) {
                    let (line, col) = byte_to_line_col(code, mat.start());
                    findings.push(SecurityFinding {
                        rule_id: rule.id.clone(),
                        rule_name: format!("{} - Insecure Mode", rule.name),
                        severity: rule.severity,
                        confidence: Confidence::High,
                        file_path: file_path.to_string(),
                        line,
                        column: col,
                        end_line: line,
                        end_column: col + mat.len(),
                        snippet: mat.as_str().to_string(),
                        message: format!("Use of insecure cryptographic mode: {}", mode),
                        remediation: rule.remediation.clone(),
                        cwe: rule.cwe.clone(),
                        owasp: rule.owasp.clone(),
                        context: HashMap::new(),
                    });
                }
            }
        }

        findings
    }

    /// Get all rules
    pub fn get_rules(&self) -> Vec<&SecurityRule> {
        self.rules.values().collect()
    }

    /// Get rule by ID
    pub fn get_rule(&self, id: &str) -> Option<&SecurityRule> {
        self.rules.get(id)
    }

    /// Get explanation for a vulnerability
    pub fn explain_vulnerability(&self, rule_id: &str) -> Option<VulnerabilityExplanation> {
        let rule = self.rules.get(rule_id)?;

        Some(VulnerabilityExplanation {
            rule_id: rule.id.clone(),
            name: rule.name.clone(),
            severity: rule.severity,
            description: rule.message.clone(),
            cwe: rule.cwe.clone(),
            owasp: rule.owasp.clone(),
            remediation: rule.remediation.clone(),
            examples: get_vulnerability_examples(&rule.id),
            references: get_vulnerability_references(&rule.cwe, &rule.owasp),
        })
    }

    /// Suggest fixes for a finding
    pub fn suggest_fix(&self, finding: &SecurityFinding, code: &str) -> Vec<SuggestedFix> {
        let mut fixes = Vec::new();

        // Get rule for context
        if let Some(rule) = self.rules.get(&finding.rule_id) {
            match &rule.rule_type {
                RuleType::Pattern { .. } => {
                    fixes.extend(suggest_pattern_fixes(finding, code));
                }
                RuleType::TaintFlow { sanitizers, .. } => {
                    fixes.extend(suggest_sanitizer_fixes(finding, sanitizers));
                }
                RuleType::Secret { .. } => {
                    fixes.push(SuggestedFix {
                        description: "Move secret to environment variable".to_string(),
                        diff: format!(
                            "- {}\n+ std::env::var(\"SECRET_KEY\").expect(\"SECRET_KEY not set\")",
                            finding.snippet
                        ),
                        confidence: Confidence::High,
                    });
                }
                RuleType::Crypto { .. } => {
                    fixes.extend(suggest_crypto_fixes(finding));
                }
                RuleType::ControlFlow {
                    required_before, ..
                } => {
                    fixes.push(SuggestedFix {
                        description: format!(
                            "Add required check before this operation: {}",
                            required_before.join(" or ")
                        ),
                        diff: format!(
                            "+ // Add: {}\n  {}",
                            required_before.join(" or "),
                            finding.snippet
                        ),
                        confidence: Confidence::Medium,
                    });
                }
            }
        }

        if fixes.is_empty() {
            fixes.push(SuggestedFix {
                description: finding.remediation.clone(),
                diff: String::new(),
                confidence: Confidence::Low,
            });
        }

        fixes
    }

    /// Load built-in security rules
    fn load_builtin_rules(&mut self) {
        // OWASP Top 10 2021 Rules
        self.load_owasp_rules();

        // CWE Top 25 Rules
        self.load_cwe_top25_rules();

        // Cryptographic Rules
        self.load_crypto_rules();

        // Secret Detection Rules
        self.load_secret_rules();
    }

    fn load_owasp_rules(&mut self) {
        // A01:2021 - Broken Access Control
        self.add_rule(SecurityRule {
            id: "OWASP-A01-001".to_string(),
            name: "Missing Authorization Check".to_string(),
            severity: Severity::High,
            cwe: vec!["CWE-862".to_string(), "CWE-863".to_string()],
            owasp: vec!["A01:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"@app\.route.*\n(?:(?!@login_required|@auth\.required|@requires_auth).)*.def"
                        .to_string(),
                    r"router\.(get|post|put|delete)\([^)]+\)(?!\.middleware)".to_string(),
                ],
                safe_patterns: vec![
                    r"@login_required".to_string(),
                    r"@auth_required".to_string(),
                    r"\.middleware\(auth".to_string(),
                ],
            },
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
            message: "Route handler may be missing authorization check".to_string(),
            remediation:
                "Add authentication/authorization middleware or decorator to protect this endpoint"
                    .to_string(),
            enabled: true,
            tags: vec!["auth".to_string(), "access-control".to_string()],
        });

        // A02:2021 - Cryptographic Failures
        self.add_rule(SecurityRule {
            id: "OWASP-A02-001".to_string(),
            name: "Weak Cryptographic Algorithm".to_string(),
            severity: Severity::High,
            cwe: vec!["CWE-327".to_string(), "CWE-328".to_string()],
            owasp: vec!["A02:2021".to_string()],
            rule_type: RuleType::Crypto {
                weak_algorithms: vec![
                    "MD5".to_string(),
                    "SHA1".to_string(),
                    "DES".to_string(),
                    "3DES".to_string(),
                    "RC4".to_string(),
                    "RC2".to_string(),
                ],
                insecure_modes: vec!["ECB".to_string()],
                min_key_size: Some(128),
            },
            languages: vec![],
            message: "Use of weak cryptographic algorithm detected".to_string(),
            remediation: "Use strong algorithms like SHA-256, SHA-512, AES-256, or ChaCha20"
                .to_string(),
            enabled: true,
            tags: vec!["crypto".to_string()],
        });

        // A03:2021 - Injection
        self.add_rule(SecurityRule {
            id: "OWASP-A03-001".to_string(),
            name: "SQL Injection".to_string(),
            severity: Severity::Critical,
            cwe: vec!["CWE-89".to_string()],
            owasp: vec!["A03:2021".to_string()],
            rule_type: RuleType::TaintFlow {
                sources: vec![
                    "request.args".to_string(),
                    "request.form".to_string(),
                    "req.query".to_string(),
                    "req.body".to_string(),
                ],
                sinks: vec![
                    "execute".to_string(),
                    "query".to_string(),
                    "raw".to_string(),
                ],
                sanitizers: vec![
                    "parameterized".to_string(),
                    "prepared".to_string(),
                    "escape".to_string(),
                ],
            },
            languages: vec![],
            message: "Potential SQL injection vulnerability".to_string(),
            remediation:
                "Use parameterized queries or prepared statements instead of string concatenation"
                    .to_string(),
            enabled: true,
            tags: vec!["injection".to_string(), "sql".to_string()],
        });

        self.add_rule(SecurityRule {
            id: "OWASP-A03-002".to_string(),
            name: "Command Injection".to_string(),
            severity: Severity::Critical,
            cwe: vec!["CWE-78".to_string()],
            owasp: vec!["A03:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True".to_string(),
                    r"os\.system\([^)]*\+".to_string(),
                    r"exec\([^)]*\+".to_string(),
                    r"child_process\.exec\([^)]*\+".to_string(),
                ],
                safe_patterns: vec![r"shlex\.quote".to_string(), r"escapeshellarg".to_string()],
            },
            languages: vec!["python".to_string(), "javascript".to_string()],
            message: "Potential command injection vulnerability".to_string(),
            remediation:
                "Avoid shell=True, use subprocess with list arguments, and sanitize all inputs"
                    .to_string(),
            enabled: true,
            tags: vec!["injection".to_string(), "command".to_string()],
        });

        self.add_rule(SecurityRule {
            id: "OWASP-A03-003".to_string(),
            name: "Cross-Site Scripting (XSS)".to_string(),
            severity: Severity::High,
            cwe: vec!["CWE-79".to_string()],
            owasp: vec!["A03:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"innerHTML\s*=".to_string(),
                    r"document\.write\(".to_string(),
                    r"v-html\s*=".to_string(),
                    r"dangerouslySetInnerHTML".to_string(),
                    r"\|safe\}".to_string(),
                ],
                safe_patterns: vec![
                    r"DOMPurify\.sanitize".to_string(),
                    r"escapeHtml".to_string(),
                ],
            },
            languages: vec!["javascript".to_string(), "typescript".to_string()],
            message: "Potential XSS vulnerability from unsanitized HTML output".to_string(),
            remediation:
                "Sanitize user input using DOMPurify or similar library before inserting into DOM"
                    .to_string(),
            enabled: true,
            tags: vec!["injection".to_string(), "xss".to_string()],
        });

        // A04:2021 - Insecure Design (Security Misconfiguration)
        self.add_rule(SecurityRule {
            id: "OWASP-A04-001".to_string(),
            name: "Debug Mode Enabled".to_string(),
            severity: Severity::Medium,
            cwe: vec!["CWE-489".to_string()],
            owasp: vec!["A04:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"DEBUG\s*=\s*True".to_string(),
                    r"app\.debug\s*=\s*True".to_string(),
                    r#""debug":\s*true"#.to_string(),
                ],
                safe_patterns: vec![],
            },
            languages: vec!["python".to_string(), "javascript".to_string()],
            message: "Debug mode appears to be enabled".to_string(),
            remediation: "Disable debug mode in production environments".to_string(),
            enabled: true,
            tags: vec!["config".to_string()],
        });

        // A05:2021 - Security Misconfiguration
        self.add_rule(SecurityRule {
            id: "OWASP-A05-001".to_string(),
            name: "CORS Misconfiguration".to_string(),
            severity: Severity::Medium,
            cwe: vec!["CWE-942".to_string()],
            owasp: vec!["A05:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"Access-Control-Allow-Origin.*\*".to_string(),
                    r"cors\(\s*\)".to_string(),
                    r"origin:\s*true".to_string(),
                    r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True".to_string(),
                ],
                safe_patterns: vec![],
            },
            languages: vec![],
            message: "Overly permissive CORS configuration".to_string(),
            remediation:
                "Restrict CORS to specific trusted origins instead of allowing all origins"
                    .to_string(),
            enabled: true,
            tags: vec!["cors".to_string(), "config".to_string()],
        });

        // A06:2021 - Vulnerable and Outdated Components
        // (Handled by supply chain module in Phase 5)

        // A07:2021 - Identification and Authentication Failures
        self.add_rule(SecurityRule {
            id: "OWASP-A07-001".to_string(),
            name: "Hardcoded Credentials".to_string(),
            severity: Severity::Critical,
            cwe: vec!["CWE-798".to_string()],
            owasp: vec!["A07:2021".to_string()],
            rule_type: RuleType::Secret {
                patterns: vec![
                    r#"(?i)password\s*=\s*['"][^'"]{8,}['"]"#.to_string(),
                    r#"(?i)api_?key\s*=\s*['"][^'"]{16,}['"]"#.to_string(),
                    r#"(?i)secret\s*=\s*['"][^'"]{8,}['"]"#.to_string(),
                    r#"(?i)token\s*=\s*['"][^'"]{16,}['"]"#.to_string(),
                ],
                entropy_threshold: Some(3.5),
            },
            languages: vec![],
            message: "Hardcoded credential detected".to_string(),
            remediation: "Move credentials to environment variables or secure secrets management"
                .to_string(),
            enabled: true,
            tags: vec!["secrets".to_string(), "credentials".to_string()],
        });

        self.add_rule(SecurityRule {
            id: "OWASP-A07-002".to_string(),
            name: "Weak Password Requirements".to_string(),
            severity: Severity::Medium,
            cwe: vec!["CWE-521".to_string()],
            owasp: vec!["A07:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"min_?length\s*[=:]\s*[1-7]\b".to_string(),
                    r"minLength\s*[=:]\s*[1-7]\b".to_string(),
                ],
                safe_patterns: vec![],
            },
            languages: vec![],
            message: "Password minimum length requirement appears too short".to_string(),
            remediation: "Require passwords of at least 8 characters, preferably 12+".to_string(),
            enabled: true,
            tags: vec!["auth".to_string(), "password".to_string()],
        });

        // A08:2021 - Software and Data Integrity Failures
        self.add_rule(SecurityRule {
            id: "OWASP-A08-001".to_string(),
            name: "Insecure Deserialization".to_string(),
            severity: Severity::Critical,
            cwe: vec!["CWE-502".to_string()],
            owasp: vec!["A08:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"pickle\.loads?\(".to_string(),
                    r"yaml\.load\([^)]*Loader\s*=\s*yaml\.Loader".to_string(),
                    r"yaml\.unsafe_load".to_string(),
                    r"Marshal\.load".to_string(),
                    r"unserialize\(".to_string(),
                    r"JSON\.parse.*eval".to_string(),
                ],
                safe_patterns: vec![r"yaml\.safe_load".to_string()],
            },
            languages: vec!["python".to_string(), "ruby".to_string(), "php".to_string()],
            message: "Insecure deserialization detected".to_string(),
            remediation: "Use safe deserialization methods and validate input before deserializing"
                .to_string(),
            enabled: true,
            tags: vec!["deserialization".to_string()],
        });

        // A09:2021 - Security Logging and Monitoring Failures
        self.add_rule(SecurityRule {
            id: "OWASP-A09-001".to_string(),
            name: "Sensitive Data in Logs".to_string(),
            severity: Severity::Medium,
            cwe: vec!["CWE-532".to_string()],
            owasp: vec!["A09:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"(?i)log.*password".to_string(),
                    r"(?i)print.*password".to_string(),
                    r"(?i)console\.log.*password".to_string(),
                    r"(?i)log.*credit.?card".to_string(),
                    r"(?i)log.*ssn".to_string(),
                ],
                safe_patterns: vec![],
            },
            languages: vec![],
            message: "Potential sensitive data being logged".to_string(),
            remediation: "Remove sensitive data from logs or mask it appropriately".to_string(),
            enabled: true,
            tags: vec!["logging".to_string(), "privacy".to_string()],
        });

        // A10:2021 - Server-Side Request Forgery (SSRF)
        self.add_rule(SecurityRule {
            id: "OWASP-A10-001".to_string(),
            name: "Server-Side Request Forgery".to_string(),
            severity: Severity::High,
            cwe: vec!["CWE-918".to_string()],
            owasp: vec!["A10:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"requests\.(get|post|put|delete)\([^)]*request\.(args|form|data)".to_string(),
                    r"urllib\.request\.urlopen\([^)]*request".to_string(),
                    r"fetch\([^)]*req\.(query|body|params)".to_string(),
                    r"http\.request\([^)]*req\.".to_string(),
                ],
                safe_patterns: vec![r"validate_url".to_string(), r"allowed_hosts".to_string()],
            },
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
            message: "Potential SSRF vulnerability - user input used in URL".to_string(),
            remediation: "Validate and whitelist allowed URLs/hosts before making requests"
                .to_string(),
            enabled: true,
            tags: vec!["ssrf".to_string(), "network".to_string()],
        });
    }

    fn load_cwe_top25_rules(&mut self) {
        // CWE-787: Out-of-bounds Write
        self.add_rule(SecurityRule {
            id: "CWE-787-001".to_string(),
            name: "Potential Buffer Overflow".to_string(),
            severity: Severity::Critical,
            cwe: vec!["CWE-787".to_string()],
            owasp: vec![],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"strcpy\s*\(".to_string(),
                    r"strcat\s*\(".to_string(),
                    r"sprintf\s*\(".to_string(),
                    r"gets\s*\(".to_string(),
                ],
                safe_patterns: vec![
                    r"strncpy".to_string(),
                    r"strncat".to_string(),
                    r"snprintf".to_string(),
                ],
            },
            languages: vec!["c".to_string(), "cpp".to_string()],
            message: "Use of unsafe string function that can cause buffer overflow".to_string(),
            remediation: "Use bounded string functions (strncpy, snprintf) instead".to_string(),
            enabled: true,
            tags: vec!["memory".to_string(), "buffer".to_string()],
        });

        // CWE-79: XSS (already covered in OWASP A03)

        // CWE-89: SQL Injection (already covered in OWASP A03)

        // CWE-416: Use After Free
        self.add_rule(SecurityRule {
            id: "CWE-416-001".to_string(),
            name: "Potential Use After Free".to_string(),
            severity: Severity::Critical,
            cwe: vec!["CWE-416".to_string()],
            owasp: vec![],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"free\s*\([^)]+\)[^;]*\n[^}]*\1".to_string(), // Simplified pattern
                ],
                safe_patterns: vec![r"= NULL".to_string(), r"= nullptr".to_string()],
            },
            languages: vec!["c".to_string(), "cpp".to_string()],
            message: "Potential use-after-free vulnerability".to_string(),
            remediation: "Set pointers to NULL after freeing and check before use".to_string(),
            enabled: true,
            tags: vec!["memory".to_string()],
        });

        // CWE-78: OS Command Injection (already covered in OWASP A03)

        // CWE-20: Improper Input Validation
        self.add_rule(SecurityRule {
            id: "CWE-20-001".to_string(),
            name: "Missing Input Validation".to_string(),
            severity: Severity::Medium,
            cwe: vec!["CWE-20".to_string()],
            owasp: vec!["A03:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"int\([^)]*request\.".to_string(),
                    r"parseInt\([^)]*req\.".to_string(),
                    r"float\([^)]*request\.".to_string(),
                ],
                safe_patterns: vec![
                    r"try\s*:".to_string(),
                    r"catch".to_string(),
                    r"isNaN".to_string(),
                ],
            },
            languages: vec!["python".to_string(), "javascript".to_string()],
            message: "User input converted without validation".to_string(),
            remediation: "Validate and sanitize all user input before processing".to_string(),
            enabled: true,
            tags: vec!["validation".to_string()],
        });

        // CWE-125: Out-of-bounds Read
        self.add_rule(SecurityRule {
            id: "CWE-125-001".to_string(),
            name: "Potential Out-of-bounds Read".to_string(),
            severity: Severity::High,
            cwe: vec!["CWE-125".to_string()],
            owasp: vec![],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"\[.*\]\s*//.*user.*input".to_string(),
                    r"memcpy\([^,]+,[^,]+,\s*\w+\s*\)".to_string(),
                ],
                safe_patterns: vec![r"bounds_check".to_string(), r"\.len\(\)".to_string()],
            },
            languages: vec!["c".to_string(), "cpp".to_string(), "rust".to_string()],
            message: "Potential out-of-bounds read".to_string(),
            remediation: "Always validate array indices and buffer sizes before access".to_string(),
            enabled: true,
            tags: vec!["memory".to_string()],
        });

        // CWE-22: Path Traversal
        self.add_rule(SecurityRule {
            id: "CWE-22-001".to_string(),
            name: "Path Traversal".to_string(),
            severity: Severity::High,
            cwe: vec!["CWE-22".to_string()],
            owasp: vec!["A01:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"open\([^)]*request\.".to_string(),
                    r"readFile\([^)]*req\.".to_string(),
                    r"os\.path\.join\([^)]*request\.".to_string(),
                    r"Path\([^)]*request\.".to_string(),
                ],
                safe_patterns: vec![
                    r"os\.path\.basename".to_string(),
                    r"secure_filename".to_string(),
                    r"realpath".to_string(),
                ],
            },
            languages: vec!["python".to_string(), "javascript".to_string()],
            message: "User input used in file path without sanitization".to_string(),
            remediation: "Sanitize file paths and use basename, realpath, or whitelist validation"
                .to_string(),
            enabled: true,
            tags: vec!["path".to_string(), "filesystem".to_string()],
        });

        // CWE-352: CSRF
        self.add_rule(SecurityRule {
            id: "CWE-352-001".to_string(),
            name: "Missing CSRF Protection".to_string(),
            severity: Severity::High,
            cwe: vec!["CWE-352".to_string()],
            owasp: vec!["A01:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"@app\.route.*methods.*POST(?!.*csrf)".to_string(),
                    r"router\.post\([^)]+\)(?!.*csrf)".to_string(),
                ],
                safe_patterns: vec![
                    r"csrf_protect".to_string(),
                    r"@csrf_exempt".to_string(), // Intentional exemption
                    r"csurf".to_string(),
                ],
            },
            languages: vec!["python".to_string(), "javascript".to_string()],
            message: "POST endpoint may be missing CSRF protection".to_string(),
            remediation: "Add CSRF token validation to state-changing endpoints".to_string(),
            enabled: true,
            tags: vec!["csrf".to_string(), "auth".to_string()],
        });

        // CWE-434: Unrestricted File Upload
        self.add_rule(SecurityRule {
            id: "CWE-434-001".to_string(),
            name: "Unrestricted File Upload".to_string(),
            severity: Severity::High,
            cwe: vec!["CWE-434".to_string()],
            owasp: vec!["A04:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"request\.files\[[^\]]+\]\.save\(".to_string(),
                    r"multer\(\s*\)".to_string(),
                    r"file\.mv\(".to_string(),
                ],
                safe_patterns: vec![
                    r"allowed_extensions".to_string(),
                    r"fileFilter".to_string(),
                    r"mimetype".to_string(),
                ],
            },
            languages: vec!["python".to_string(), "javascript".to_string()],
            message: "File upload without apparent restriction on file type".to_string(),
            remediation: "Validate file type, extension, and content before saving uploaded files"
                .to_string(),
            enabled: true,
            tags: vec!["upload".to_string(), "filesystem".to_string()],
        });

        // CWE-476: NULL Pointer Dereference
        self.add_rule(SecurityRule {
            id: "CWE-476-001".to_string(),
            name: "Potential NULL Pointer Dereference".to_string(),
            severity: Severity::High,
            cwe: vec!["CWE-476".to_string()],
            owasp: vec![],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"\*\w+\s*=.*malloc.*\n[^}]*\*\w+".to_string(), // Simplified
                ],
                safe_patterns: vec![
                    r"if\s*\(\s*\w+\s*==\s*NULL".to_string(),
                    r"if\s*\(\s*!\s*\w+\s*\)".to_string(),
                ],
            },
            languages: vec!["c".to_string(), "cpp".to_string()],
            message: "Potential null pointer dereference".to_string(),
            remediation: "Check pointer for NULL before dereferencing".to_string(),
            enabled: true,
            tags: vec!["memory".to_string(), "null".to_string()],
        });
    }

    fn load_crypto_rules(&mut self) {
        // Random number generation
        self.add_rule(SecurityRule {
            id: "CRYPTO-001".to_string(),
            name: "Insecure Random Number Generator".to_string(),
            severity: Severity::High,
            cwe: vec!["CWE-330".to_string(), "CWE-338".to_string()],
            owasp: vec!["A02:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"random\.random\(\)".to_string(),
                    r"Math\.random\(\)".to_string(),
                    r"rand\(\)".to_string(),
                    r"srand\(".to_string(),
                ],
                safe_patterns: vec![
                    r"secrets\.".to_string(),
                    r"crypto\.randomBytes".to_string(),
                    r"SecureRandom".to_string(),
                ],
            },
            languages: vec!["python".to_string(), "javascript".to_string(), "c".to_string()],
            message: "Use of non-cryptographic random number generator for security purposes".to_string(),
            remediation: "Use cryptographically secure RNG: secrets (Python), crypto.randomBytes (Node), or /dev/urandom".to_string(),
            enabled: true,
            tags: vec!["crypto".to_string(), "random".to_string()],
        });

        // Hardcoded IV/Salt
        self.add_rule(SecurityRule {
            id: "CRYPTO-002".to_string(),
            name: "Hardcoded IV or Salt".to_string(),
            severity: Severity::High,
            cwe: vec!["CWE-329".to_string()],
            owasp: vec!["A02:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r#"(?i)iv\s*=\s*['"][0-9a-f]+['"]"#.to_string(),
                    r#"(?i)salt\s*=\s*['"][^'"]+['"]"#.to_string(),
                    r#"(?i)nonce\s*=\s*['"][0-9a-f]+['"]"#.to_string(),
                ],
                safe_patterns: vec![],
            },
            languages: vec![],
            message: "Hardcoded initialization vector or salt detected".to_string(),
            remediation: "Generate unique random IV/salt for each encryption operation".to_string(),
            enabled: true,
            tags: vec!["crypto".to_string()],
        });

        // Insufficient key derivation
        self.add_rule(SecurityRule {
            id: "CRYPTO-003".to_string(),
            name: "Weak Key Derivation".to_string(),
            severity: Severity::Medium,
            cwe: vec!["CWE-916".to_string()],
            owasp: vec!["A02:2021".to_string()],
            rule_type: RuleType::Pattern {
                patterns: vec![
                    r"hashlib\.(md5|sha1)\([^)]*\.encode".to_string(),
                    r#"crypto\.createHash\(['"]md5"#.to_string(),
                    r#"MessageDigest\.getInstance\(['"]MD5"#.to_string(),
                ],
                safe_patterns: vec![
                    r"pbkdf2".to_string(),
                    r"bcrypt".to_string(),
                    r"argon2".to_string(),
                    r"scrypt".to_string(),
                ],
            },
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "java".to_string(),
            ],
            message: "Using weak hash for key derivation".to_string(),
            remediation: "Use PBKDF2, bcrypt, scrypt, or Argon2 for password/key derivation"
                .to_string(),
            enabled: true,
            tags: vec!["crypto".to_string(), "password".to_string()],
        });
    }

    fn load_secret_rules(&mut self) {
        // AWS Keys
        self.add_rule(SecurityRule {
            id: "SECRET-001".to_string(),
            name: "AWS Access Key".to_string(),
            severity: Severity::Critical,
            cwe: vec!["CWE-798".to_string()],
            owasp: vec!["A07:2021".to_string()],
            rule_type: RuleType::Secret {
                patterns: vec![
                    r"AKIA[0-9A-Z]{16}".to_string(),
                    r#"(?i)aws_access_key_id\s*=\s*['"]?AKIA[0-9A-Z]{16}"#.to_string(),
                ],
                entropy_threshold: None,
            },
            languages: vec![],
            message: "AWS Access Key ID detected".to_string(),
            remediation:
                "Remove the key, rotate it immediately, and use IAM roles or environment variables"
                    .to_string(),
            enabled: true,
            tags: vec!["secrets".to_string(), "aws".to_string()],
        });

        // GitHub Token
        self.add_rule(SecurityRule {
            id: "SECRET-002".to_string(),
            name: "GitHub Token".to_string(),
            severity: Severity::Critical,
            cwe: vec!["CWE-798".to_string()],
            owasp: vec!["A07:2021".to_string()],
            rule_type: RuleType::Secret {
                patterns: vec![
                    r"ghp_[0-9a-zA-Z]{36}".to_string(),
                    r"gho_[0-9a-zA-Z]{36}".to_string(),
                    r"ghu_[0-9a-zA-Z]{36}".to_string(),
                    r"ghs_[0-9a-zA-Z]{36}".to_string(),
                    r"ghr_[0-9a-zA-Z]{36}".to_string(),
                ],
                entropy_threshold: None,
            },
            languages: vec![],
            message: "GitHub token detected".to_string(),
            remediation:
                "Remove the token, revoke it, and use environment variables or secrets management"
                    .to_string(),
            enabled: true,
            tags: vec!["secrets".to_string(), "github".to_string()],
        });

        // Generic API Key
        self.add_rule(SecurityRule {
            id: "SECRET-003".to_string(),
            name: "Generic API Key".to_string(),
            severity: Severity::High,
            cwe: vec!["CWE-798".to_string()],
            owasp: vec!["A07:2021".to_string()],
            rule_type: RuleType::Secret {
                patterns: vec![
                    r#"(?i)api[_-]?key\s*[=:]\s*['"]([a-zA-Z0-9]{32,})['"]"#.to_string(),
                    r#"(?i)apikey\s*[=:]\s*['"]([a-zA-Z0-9]{32,})['"]"#.to_string(),
                ],
                entropy_threshold: Some(4.0),
            },
            languages: vec![],
            message: "Potential API key detected".to_string(),
            remediation: "Move API keys to environment variables or secrets management".to_string(),
            enabled: true,
            tags: vec!["secrets".to_string(), "api".to_string()],
        });

        // Private Key
        self.add_rule(SecurityRule {
            id: "SECRET-004".to_string(),
            name: "Private Key".to_string(),
            severity: Severity::Critical,
            cwe: vec!["CWE-321".to_string()],
            owasp: vec!["A07:2021".to_string()],
            rule_type: RuleType::Secret {
                patterns: vec![
                    r"-----BEGIN RSA PRIVATE KEY-----".to_string(),
                    r"-----BEGIN EC PRIVATE KEY-----".to_string(),
                    r"-----BEGIN PRIVATE KEY-----".to_string(),
                    r"-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
                ],
                entropy_threshold: None,
            },
            languages: vec![],
            message: "Private key detected in code".to_string(),
            remediation: "Never commit private keys. Use secure key management systems".to_string(),
            enabled: true,
            tags: vec!["secrets".to_string(), "crypto".to_string()],
        });

        // JWT Secret
        self.add_rule(SecurityRule {
            id: "SECRET-005".to_string(),
            name: "JWT Secret".to_string(),
            severity: Severity::Critical,
            cwe: vec!["CWE-798".to_string()],
            owasp: vec!["A07:2021".to_string()],
            rule_type: RuleType::Secret {
                patterns: vec![
                    r#"(?i)jwt[_-]?secret\s*[=:]\s*['"]([^'"]{16,})['"]"#.to_string(),
                    r#"(?i)secret[_-]?key\s*[=:]\s*['"]([^'"]{16,})['"]"#.to_string(),
                ],
                entropy_threshold: Some(3.5),
            },
            languages: vec![],
            message: "JWT or session secret detected".to_string(),
            remediation:
                "Move secrets to environment variables and ensure they are strong (256+ bits)"
                    .to_string(),
            enabled: true,
            tags: vec!["secrets".to_string(), "jwt".to_string()],
        });
    }
}

/// Vulnerability explanation with examples and references
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityExplanation {
    pub rule_id: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
    pub cwe: Vec<String>,
    pub owasp: Vec<String>,
    pub remediation: String,
    pub examples: Vec<CodeExample>,
    pub references: Vec<String>,
}

/// Code example (vulnerable and fixed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeExample {
    pub language: String,
    pub vulnerable: String,
    pub fixed: String,
    pub explanation: String,
}

/// Suggested fix for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedFix {
    pub description: String,
    pub diff: String,
    pub confidence: Confidence,
}

// Helper functions

/// Check if a CWE is in the Top 25
fn is_cwe_top25(cwe: &str) -> bool {
    const CWE_TOP25: &[&str] = &[
        "CWE-787", "CWE-79", "CWE-89", "CWE-416", "CWE-78", "CWE-20", "CWE-125", "CWE-22",
        "CWE-352", "CWE-434", "CWE-862", "CWE-476", "CWE-287", "CWE-190", "CWE-502", "CWE-77",
        "CWE-119", "CWE-798", "CWE-918", "CWE-306", "CWE-362", "CWE-269", "CWE-94", "CWE-863",
        "CWE-276",
    ];
    CWE_TOP25.contains(&cwe)
}

/// Convert byte offset to line and column
fn byte_to_line_col(code: &str, byte_offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;

    for (i, ch) in code.chars().enumerate() {
        if i >= byte_offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }

    (line, col)
}

/// Calculate Shannon entropy of a string
fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    for ch in s.chars() {
        *freq.entry(ch).or_insert(0) += 1;
    }

    let len = s.len() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Redact a secret for safe display
fn redact_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        "*".repeat(secret.len())
    } else {
        format!("{}...{}", &secret[..4], &secret[secret.len() - 4..])
    }
}

/// Get example code for a vulnerability type
fn get_vulnerability_examples(rule_id: &str) -> Vec<CodeExample> {
    match rule_id {
        "OWASP-A03-001" => vec![
            CodeExample {
                language: "python".to_string(),
                vulnerable: r#"query = f"SELECT * FROM users WHERE name = '{user_input}'"
cursor.execute(query)"#
                    .to_string(),
                fixed: r#"cursor.execute("SELECT * FROM users WHERE name = %s", [user_input])"#
                    .to_string(),
                explanation: "Use parameterized queries to prevent SQL injection".to_string(),
            },
            CodeExample {
                language: "javascript".to_string(),
                vulnerable: r#"const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
db.query(query);"#
                    .to_string(),
                fixed: r#"db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);"#
                    .to_string(),
                explanation: "Use prepared statements with placeholders".to_string(),
            },
        ],
        "OWASP-A03-003" => vec![CodeExample {
            language: "javascript".to_string(),
            vulnerable: r#"element.innerHTML = userInput;"#.to_string(),
            fixed: r#"element.textContent = userInput;
// Or use: element.innerHTML = DOMPurify.sanitize(userInput);"#
                .to_string(),
            explanation: "Use textContent for plain text, or sanitize HTML with DOMPurify"
                .to_string(),
        }],
        "OWASP-A07-001" => vec![CodeExample {
            language: "python".to_string(),
            vulnerable: r#"DATABASE_PASSWORD = "super_secret_123""#.to_string(),
            fixed: r#"import os
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")"#
                .to_string(),
            explanation: "Store secrets in environment variables, not in code".to_string(),
        }],
        _ => vec![],
    }
}

/// Get reference URLs for vulnerability types
fn get_vulnerability_references(cwe: &[String], owasp: &[String]) -> Vec<String> {
    let mut refs = Vec::new();

    for cwe_id in cwe {
        refs.push(format!(
            "https://cwe.mitre.org/data/definitions/{}.html",
            cwe_id.trim_start_matches("CWE-")
        ));
    }

    for owasp_cat in owasp {
        refs.push(format!(
            "https://owasp.org/Top10/{}",
            owasp_cat.replace(":", "_")
        ));
    }

    refs
}

/// Suggest fixes for pattern-based findings
fn suggest_pattern_fixes(finding: &SecurityFinding, _code: &str) -> Vec<SuggestedFix> {
    // Context-specific fixes based on rule
    match finding.rule_id.as_str() {
        id if id.contains("A03-003") => vec![SuggestedFix {
            description: "Use textContent instead of innerHTML".to_string(),
            diff: format!(
                "- {}\n+ {}",
                finding.snippet,
                finding.snippet.replace("innerHTML", "textContent")
            ),
            confidence: Confidence::Medium,
        }],
        _ => vec![],
    }
}

/// Suggest sanitizer-based fixes based on the finding context
fn suggest_sanitizer_fixes(finding: &SecurityFinding, sanitizers: &[String]) -> Vec<SuggestedFix> {
    sanitizers
        .iter()
        .map(|s| {
            // Provide context-aware suggestions based on the snippet
            let sanitized_snippet = if finding.snippet.contains('=') {
                // If it's an assignment, suggest wrapping the RHS
                let parts: Vec<&str> = finding.snippet.splitn(2, '=').collect();
                if parts.len() == 2 {
                    format!("{} = {}({})", parts[0].trim(), s, parts[1].trim())
                } else {
                    format!("{}({})", s, finding.snippet)
                }
            } else {
                format!("{}({})", s, finding.snippet)
            };

            SuggestedFix {
                description: format!("Apply sanitizer: {} to {}", s, finding.rule_name),
                diff: format!("- {}\n+ {}", finding.snippet, sanitized_snippet),
                confidence: Confidence::Medium,
            }
        })
        .collect()
}

/// Suggest crypto fixes
fn suggest_crypto_fixes(finding: &SecurityFinding) -> Vec<SuggestedFix> {
    let mut fixes = Vec::new();

    if finding.snippet.to_lowercase().contains("md5") {
        fixes.push(SuggestedFix {
            description: "Replace MD5 with SHA-256".to_string(),
            diff: finding
                .snippet
                .replace("md5", "sha256")
                .replace("MD5", "SHA256"),
            confidence: Confidence::High,
        });
    }

    if finding.snippet.to_lowercase().contains("sha1") {
        fixes.push(SuggestedFix {
            description: "Replace SHA1 with SHA-256".to_string(),
            diff: finding
                .snippet
                .replace("sha1", "sha256")
                .replace("SHA1", "SHA256"),
            confidence: Confidence::High,
        });
    }

    fixes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint::analyzer::detect_language;

    #[test]
    fn test_engine_creation() {
        let engine = SecurityRulesEngine::new();
        assert!(!engine.rules.is_empty());
        assert!(!engine.owasp_rules.is_empty());
        assert!(!engine.cwe_top25_rules.is_empty());
    }

    #[test]
    fn test_sql_injection_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
def search(request):
    query = f"SELECT * FROM users WHERE name = '{request.GET['q']}'"
    cursor.execute(query)
"#;
        let findings = engine.scan(code, "test.py", "python");
        assert!(findings
            .iter()
            .any(|f| f.cwe.contains(&"CWE-89".to_string())));
    }

    #[test]
    fn test_xss_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
element.innerHTML = userInput;
"#;
        let findings = engine.scan(code, "test.js", "javascript");
        assert!(findings.iter().any(|f| f.rule_id.contains("A03-003")));
    }

    #[test]
    fn test_hardcoded_password_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
password = "supersecretpassword123"
api_key = "sk_test_EXAMPLE_KEY_FOR_TESTING_ONLY_1234"
"#;
        let findings = engine.scan(code, "config.py", "python");
        assert!(findings.iter().any(|f| f.rule_id.contains("A07-001")));
    }

    #[test]
    fn test_aws_key_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
"#;
        let findings = engine.scan(code, "config.py", "python");
        assert!(findings.iter().any(|f| f.rule_id == "SECRET-001"));
    }

    #[test]
    fn test_github_token_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"#;
        let findings = engine.scan(code, "config.py", "python");
        assert!(findings.iter().any(|f| f.rule_id == "SECRET-002"));
    }

    #[test]
    fn test_weak_crypto_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
import hashlib
hash = hashlib.md5(password.encode())
"#;
        let findings = engine.scan(code, "auth.py", "python");
        assert!(findings
            .iter()
            .any(|f| f.cwe.contains(&"CWE-327".to_string())
                || f.cwe.contains(&"CWE-916".to_string())));
    }

    #[test]
    fn test_insecure_random_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
import random
token = random.random()
"#;
        let findings = engine.scan(code, "auth.py", "python");
        assert!(findings.iter().any(|f| f.rule_id == "CRYPTO-001"));
    }

    #[test]
    fn test_private_key_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2mKqH...
-----END RSA PRIVATE KEY-----"""
"#;
        let findings = engine.scan(code, "config.py", "python");
        assert!(findings.iter().any(|f| f.rule_id == "SECRET-004"));
    }

    #[test]
    fn test_debug_mode_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
DEBUG = True
app.debug = True
"#;
        let findings = engine.scan(code, "settings.py", "python");
        assert!(findings.iter().any(|f| f.rule_id == "OWASP-A04-001"));
    }

    #[test]
    fn test_cors_misconfiguration() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
Access-Control-Allow-Origin: *
"#;
        let findings = engine.scan(code, "server.js", "javascript");
        assert!(findings.iter().any(|f| f.rule_id == "OWASP-A05-001"));
    }

    #[test]
    fn test_buffer_overflow_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
strcpy(dest, src);
sprintf(buffer, "%s", input);
"#;
        let findings = engine.scan(code, "vulnerable.c", "c");
        assert!(findings.iter().any(|f| f.rule_id == "CWE-787-001"));
    }

    #[test]
    fn test_insecure_deserialization() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
import pickle
data = pickle.loads(user_input)
"#;
        let findings = engine.scan(code, "handler.py", "python");
        assert!(findings.iter().any(|f| f.rule_id == "OWASP-A08-001"));
    }

    #[test]
    fn test_path_traversal_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
file = open(request.args.get('filename'))
"#;
        let findings = engine.scan(code, "handler.py", "python");
        assert!(findings
            .iter()
            .any(|f| f.cwe.contains(&"CWE-22".to_string())));
    }

    #[test]
    fn test_yaml_ruleset_loading() {
        let mut engine = SecurityRulesEngine::new();
        let yaml = r#"
name: Custom Rules
version: "1.0"
description: Test ruleset
rules:
  - id: CUSTOM-001
    name: Test Rule
    severity: High
    cwe: ["CWE-123"]
    owasp: ["A01:2021"]
    rule_type:
      type: pattern
      patterns:
        - "dangerous_function\\("
      safe_patterns: []
    languages: []
    message: "Dangerous function detected"
    remediation: "Don't use dangerous functions"
    enabled: true
    tags: ["test"]
"#;
        let count = engine.load_ruleset_yaml(yaml).unwrap();
        assert_eq!(count, 1);
        assert!(engine.get_rule("CUSTOM-001").is_some());
    }

    #[test]
    fn test_owasp_scan() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
password = "hardcoded123"
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"#;
        let findings = engine.scan_owasp_top10(code, "test.py", "python");
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| !f.owasp.is_empty()));
    }

    #[test]
    fn test_cwe_top25_scan() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
strcpy(dest, src);
"#;
        let findings = engine.scan_cwe_top25(code, "test.c", "c");
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_explain_vulnerability() {
        let engine = SecurityRulesEngine::new();
        let explanation = engine.explain_vulnerability("OWASP-A03-001");
        assert!(explanation.is_some());
        let exp = explanation.unwrap();
        assert_eq!(exp.name, "SQL Injection");
        assert!(!exp.examples.is_empty());
    }

    #[test]
    fn test_suggest_fix() {
        let engine = SecurityRulesEngine::new();
        let finding = SecurityFinding {
            rule_id: "OWASP-A03-003".to_string(),
            rule_name: "XSS".to_string(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            file_path: "test.js".to_string(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 20,
            snippet: "element.innerHTML = userInput;".to_string(),
            message: "XSS".to_string(),
            remediation: "Use textContent".to_string(),
            cwe: vec!["CWE-79".to_string()],
            owasp: vec!["A03:2021".to_string()],
            context: HashMap::new(),
        };
        let fixes = engine.suggest_fix(&finding, "element.innerHTML = userInput;");
        assert!(!fixes.is_empty());
    }

    #[test]
    fn test_entropy_calculation() {
        // Random-looking string should have high entropy
        let high_entropy = calculate_entropy("aB3$xY9@kL2#mN5");
        assert!(high_entropy > 3.0);

        // Repetitive string should have low entropy
        let low_entropy = calculate_entropy("aaaaaaaaaa");
        assert!(low_entropy < 1.0);
    }

    #[test]
    fn test_secret_redaction() {
        assert_eq!(redact_secret("short"), "*****");
        assert_eq!(redact_secret("longsecretvalue123"), "long...e123"); // First 4 + ... + last 4
    }

    #[test]
    fn test_language_detection() {
        assert_eq!(detect_language("test.py"), "python");
        assert_eq!(detect_language("test.rs"), "rust");
        assert_eq!(detect_language("test.js"), "javascript");
        assert_eq!(detect_language("test.ts"), "typescript");
        assert_eq!(detect_language("test.go"), "go");
        assert_eq!(detect_language("test.c"), "c");
        assert_eq!(detect_language("test.cpp"), "cpp");
    }

    #[test]
    fn test_byte_to_line_col() {
        let code = "line1\nline2\nline3";
        assert_eq!(byte_to_line_col(code, 0), (1, 1));
        assert_eq!(byte_to_line_col(code, 6), (2, 1));
        assert_eq!(byte_to_line_col(code, 8), (2, 3));
    }

    #[test]
    fn test_cwe_top25_check() {
        assert!(is_cwe_top25("CWE-787"));
        assert!(is_cwe_top25("CWE-79"));
        assert!(is_cwe_top25("CWE-89"));
        assert!(!is_cwe_top25("CWE-999999"));
    }

    #[test]
    fn test_severity_ordering() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
password = "secret123"
DEBUG = True
"#;
        let findings = engine.scan(code, "test.py", "python");
        // Findings should be sorted by severity (highest first)
        for window in findings.windows(2) {
            assert!(window[0].severity >= window[1].severity);
        }
    }

    #[test]
    fn test_safe_pattern_suppression() {
        let engine = SecurityRulesEngine::new();
        // Code with secure random should not trigger
        let safe_code = r#"
import secrets
token = secrets.token_hex(32)
"#;
        let findings = engine.scan(safe_code, "test.py", "python");
        assert!(findings.iter().all(|f| f.rule_id != "CRYPTO-001"));
    }

    #[test]
    fn test_is_test_file_directories() {
        // Test directory patterns (must have slash before directory name)
        assert!(is_test_file("project/tests/integration_tests.rs"));
        assert!(is_test_file("src/test/java/MyTest.java"));
        assert!(is_test_file("src/__tests__/Component.test.js"));
        assert!(is_test_file("project/fixtures/sample_data.py"));
        assert!(is_test_file("project/testdata/input.json"));
        assert!(is_test_file("project/test_data/expected.txt"));
        assert!(is_test_file("src/mocks/api.js"));
        assert!(is_test_file("src/__mocks__/fs.js"));
        assert!(is_test_file("project/spec/helpers/test_helper.rb"));
    }

    #[test]
    fn test_is_test_file_rust() {
        assert!(is_test_file("src/foo_test.rs"));
        assert!(is_test_file("src/integration_tests.rs"));
        assert!(!is_test_file("src/main.rs"));
        assert!(!is_test_file("src/lib.rs"));
        assert!(!is_test_file("src/testing.rs")); // Contains "test" but not a test file
    }

    #[test]
    fn test_is_test_file_javascript() {
        assert!(is_test_file("component.test.js"));
        assert!(is_test_file("utils.test.ts"));
        assert!(is_test_file("component.spec.js"));
        assert!(is_test_file("utils.spec.ts"));
        assert!(is_test_file("App.test.tsx"));
        assert!(is_test_file("App.spec.jsx"));
        assert!(!is_test_file("src/index.js"));
        assert!(!is_test_file("src/contest.js")); // Contains "test" substring
    }

    #[test]
    fn test_is_test_file_python() {
        assert!(is_test_file("test_utils.py"));
        assert!(is_test_file("test_api.py"));
        assert!(is_test_file("utils_test.py"));
        assert!(!is_test_file("src/main.py"));
        assert!(!is_test_file("contest.py")); // Starts with "con", ends with "test"
    }

    #[test]
    fn test_is_test_file_go() {
        assert!(is_test_file("main_test.go"));
        assert!(is_test_file("utils_test.go"));
        assert!(!is_test_file("main.go"));
    }

    #[test]
    fn test_is_test_file_java() {
        assert!(is_test_file("UserServiceTest.java"));
        assert!(is_test_file("ApiTest.java"));
        assert!(!is_test_file("Test.java")); // Just "Test.java" is often a valid class
        assert!(!is_test_file("Main.java"));
    }

    #[test]
    fn test_is_test_file_negative_cases() {
        // Should NOT match these
        assert!(!is_test_file("src/main.rs"));
        assert!(!is_test_file("src/lib.rs"));
        assert!(!is_test_file("src/testing_utils.rs")); // Contains "testing" but not test file pattern
        assert!(!is_test_file("app/contest.js")); // Contains "test" substring
        assert!(!is_test_file("src/latest_results.py")); // Contains "test" substring
    }

    #[test]
    fn test_is_test_file_test_fixtures() {
        // Test new test-fixtures patterns
        assert!(is_test_file("test-fixtures/security/vulnerable.php"));
        assert!(is_test_file("test-fixtures/sample.rs"));
        assert!(is_test_file("/path/to/test-fixtures/vulnerable.go"));
        assert!(is_test_file("project/test-fixtures/data.json"));
        // Security test sample directories
        assert!(is_test_file("src/security/vulnerable.ts"));
        assert!(is_test_file("project/vulnerable/sample.py"));
        // Files named vulnerable.*
        assert!(is_test_file("vulnerable.php"));
        assert!(is_test_file("src/vulnerable.java"));
        assert!(is_test_file("insecure.go"));
        assert!(is_test_file("path/to/insecure.rb"));
    }

    #[test]
    fn test_is_security_exemplar_file() {
        // Security rule definition files
        assert!(is_security_exemplar_file("src/security_rules.rs"));
        assert!(is_security_exemplar_file("/path/to/security_rules.rs"));
        assert!(is_security_exemplar_file("src/security_config.rs"));
        assert!(is_security_exemplar_file("src/taint.rs"));
        // Rules directory YAML files
        assert!(is_security_exemplar_file("rules/owasp-top10.yaml"));
        assert!(is_security_exemplar_file("rules/cwe-top25.yaml"));
        assert!(is_security_exemplar_file("project/rules/secrets.yml"));
        // Files with security rule patterns in name
        assert!(is_security_exemplar_file("security_rules_v2.rs"));
        assert!(is_security_exemplar_file("owasp_checker.py"));
        assert!(is_security_exemplar_file("cwe-89-detection.rs"));
        // Should NOT match regular files
        assert!(!is_security_exemplar_file("src/main.rs"));
        assert!(!is_security_exemplar_file("src/index.js"));
        assert!(!is_security_exemplar_file("src/security.rs")); // security but not security_rules
        assert!(!is_security_exemplar_file("rules.yaml")); // yaml but not in rules/ dir
    }

    #[test]
    fn test_bash_rules_loading() {
        let mut engine = SecurityRulesEngine::new();
        let bash_yaml = include_str!("../rules/bash.yaml");
        let count = engine.load_ruleset_yaml(bash_yaml).unwrap();
        assert_eq!(count, 5, "bash.yaml should contain 5 rules");

        // Verify all rules loaded
        assert!(engine.get_rule("BASH-001").is_some());
        assert!(engine.get_rule("BASH-002").is_some());
        assert!(engine.get_rule("BASH-003").is_some());
        assert!(engine.get_rule("BASH-004").is_some());
        assert!(engine.get_rule("BASH-005").is_some());
    }

    #[test]
    fn test_bash_unquoted_variable_detection() {
        let mut engine = SecurityRulesEngine::new();
        let bash_yaml = include_str!("../rules/bash.yaml");
        engine.load_ruleset_yaml(bash_yaml).unwrap();

        let code = r#"
eval $command_from_env
echo "${safe_var}"
"#;
        let findings = engine.scan(code, "script.sh", "bash");
        assert!(
            findings.iter().any(|f| f.rule_id == "BASH-001"),
            "Should detect unquoted eval variable"
        );
    }

    #[test]
    fn test_bash_insecure_curl_detection() {
        let mut engine = SecurityRulesEngine::new();
        let bash_yaml = include_str!("../rules/bash.yaml");
        engine.load_ruleset_yaml(bash_yaml).unwrap();

        let code = "curl -k https://api.example.com/data";
        let findings = engine.scan(code, "deploy.sh", "bash");
        assert!(
            findings.iter().any(|f| f.rule_id == "BASH-003"),
            "Should detect insecure curl -k flag"
        );
    }

    #[test]
    fn test_bash_world_writable_detection() {
        let mut engine = SecurityRulesEngine::new();
        let bash_yaml = include_str!("../rules/bash.yaml");
        engine.load_ruleset_yaml(bash_yaml).unwrap();

        let code = "chmod 777 /var/www/app";
        let findings = engine.scan(code, "setup.sh", "bash");
        assert!(
            findings.iter().any(|f| f.rule_id == "BASH-004"),
            "Should detect chmod 777"
        );
    }

    #[test]
    fn test_rust_rules_loading() {
        let mut engine = SecurityRulesEngine::new();
        let cwe_yaml = include_str!("../rules/cwe-top25.yaml");
        let count = engine.load_ruleset_yaml(cwe_yaml).unwrap();
        assert!(
            count >= 19,
            "cwe-top25.yaml should contain at least 19 rules"
        );

        // Verify Rust rules loaded
        assert!(
            engine.get_rule("RUST-001").is_some(),
            "RUST-001 should exist"
        );
        assert!(
            engine.get_rule("RUST-002").is_some(),
            "RUST-002 should exist"
        );
        assert!(
            engine.get_rule("RUST-003").is_some(),
            "RUST-003 should exist"
        );
    }

    #[test]
    fn test_rust_unsafe_detection() {
        let mut engine = SecurityRulesEngine::new();
        let cwe_yaml = include_str!("../rules/cwe-top25.yaml");
        engine.load_ruleset_yaml(cwe_yaml).unwrap();

        let code = r#"
fn process() {
    unsafe {
        // risky code
    }
}
"#;
        let findings = engine.scan(code, "lib.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-001"),
            "Should detect unsafe block"
        );
    }

    #[test]
    fn test_rust_unwrap_detection() {
        let mut engine = SecurityRulesEngine::new();
        let cwe_yaml = include_str!("../rules/cwe-top25.yaml");
        engine.load_ruleset_yaml(cwe_yaml).unwrap();

        let code = r#"
let value = data.parse::<i32>().unwrap();
let other = option.expect("error");
"#;
        let findings = engine.scan(code, "parser.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-002"),
            "Should detect unwrap usage"
        );
    }

    #[test]
    fn test_rust_raw_pointer_detection() {
        let mut engine = SecurityRulesEngine::new();
        let cwe_yaml = include_str!("../rules/cwe-top25.yaml");
        engine.load_ruleset_yaml(cwe_yaml).unwrap();

        let code = r#"
let ptr = &x as *const i32;
let raw = slice.as_ptr();
std::ptr::read(ptr);
"#;
        let findings = engine.scan(code, "ffi.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-003"),
            "Should detect raw pointer usage"
        );
    }

    #[test]
    fn test_go_rules_loading() {
        let mut engine = SecurityRulesEngine::new();
        let owasp_yaml = include_str!("../rules/owasp-top10.yaml");
        engine.load_ruleset_yaml(owasp_yaml).unwrap();

        assert!(engine.get_rule("GO-001").is_some(), "GO-001 should exist");
        assert!(engine.get_rule("GO-002").is_some(), "GO-002 should exist");
        assert!(engine.get_rule("GO-003").is_some(), "GO-003 should exist");
        assert!(engine.get_rule("GO-004").is_some(), "GO-004 should exist");
        assert!(engine.get_rule("GO-005").is_some(), "GO-005 should exist");
    }

    #[test]
    fn test_go_sql_injection_detection() {
        let mut engine = SecurityRulesEngine::new();
        let owasp_yaml = include_str!("../rules/owasp-top10.yaml");
        engine.load_ruleset_yaml(owasp_yaml).unwrap();

        let code = r#"
query := fmt.Sprintf("SELECT * FROM users WHERE name = %s", name)
"#;
        let findings = engine.scan(code, "db.go", "go");
        assert!(
            findings.iter().any(|f| f.rule_id == "GO-001"),
            "Should detect Go SQL injection via fmt.Sprintf"
        );
    }

    #[test]
    fn test_go_insecure_tls_detection() {
        let mut engine = SecurityRulesEngine::new();
        let owasp_yaml = include_str!("../rules/owasp-top10.yaml");
        engine.load_ruleset_yaml(owasp_yaml).unwrap();

        let code = r#"
tlsConfig := &tls.Config{
    InsecureSkipVerify: true,
}
"#;
        let findings = engine.scan(code, "client.go", "go");
        assert!(
            findings.iter().any(|f| f.rule_id == "GO-002"),
            "Should detect Go insecure TLS"
        );
    }

    #[test]
    fn test_go_weak_crypto_detection() {
        let mut engine = SecurityRulesEngine::new();
        let owasp_yaml = include_str!("../rules/owasp-top10.yaml");
        engine.load_ruleset_yaml(owasp_yaml).unwrap();

        let code = r#"
import "crypto/md5"
h := md5.New()
"#;
        let findings = engine.scan(code, "hash.go", "go");
        assert!(
            findings.iter().any(|f| f.rule_id == "GO-005"),
            "Should detect Go weak crypto"
        );
    }

    #[test]
    fn test_java_sql_injection_detection() {
        let mut engine = SecurityRulesEngine::new();
        let owasp_yaml = include_str!("../rules/owasp-top10.yaml");
        engine.load_ruleset_yaml(owasp_yaml).unwrap();

        let code = r#"
String query = "SELECT * FROM users WHERE id = " + userId;
stmt.executeQuery(query);
"#;
        let findings = engine.scan(code, "UserDao.java", "java");
        assert!(
            findings.iter().any(|f| f.rule_id == "JAVA-001"),
            "Should detect Java SQL injection"
        );
    }

    #[test]
    fn test_csharp_sql_injection_detection() {
        let mut engine = SecurityRulesEngine::new();
        let owasp_yaml = include_str!("../rules/owasp-top10.yaml");
        engine.load_ruleset_yaml(owasp_yaml).unwrap();

        let code = r#"
var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + userId);
"#;
        let findings = engine.scan(code, "UserService.cs", "csharp");
        assert!(
            findings.iter().any(|f| f.rule_id == "CSHARP-001"),
            "Should detect C# SQL injection"
        );
    }

    #[test]
    fn test_ruby_sql_injection_detection() {
        let mut engine = SecurityRulesEngine::new();
        let owasp_yaml = include_str!("../rules/owasp-top10.yaml");
        engine.load_ruleset_yaml(owasp_yaml).unwrap();

        let code = r#"
User.where("name = '#{params[:name]}'")
"#;
        let findings = engine.scan(code, "user_controller.rb", "ruby");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUBY-001"),
            "Should detect Ruby SQL injection"
        );
    }

    #[test]
    fn test_kotlin_webview_detection() {
        let mut engine = SecurityRulesEngine::new();
        let owasp_yaml = include_str!("../rules/owasp-top10.yaml");
        engine.load_ruleset_yaml(owasp_yaml).unwrap();

        let code = r#"
webView.settings.setJavaScriptEnabled(true)
"#;
        let findings = engine.scan(code, "MainActivity.kt", "kotlin");
        assert!(
            findings.iter().any(|f| f.rule_id == "KOTLIN-002"),
            "Should detect Kotlin WebView JavaScript enabled"
        );
    }

    #[test]
    fn test_php_sql_injection_detection() {
        let mut engine = SecurityRulesEngine::new();
        let owasp_yaml = include_str!("../rules/owasp-top10.yaml");
        engine.load_ruleset_yaml(owasp_yaml).unwrap();

        let code = r#"
$result = mysql_query("SELECT * FROM users WHERE id = " . $_GET['id']);
"#;
        let findings = engine.scan(code, "user.php", "php");
        assert!(
            findings.iter().any(|f| f.rule_id == "PHP-001"),
            "Should detect PHP SQL injection"
        );
    }

    #[test]
    fn test_typescript_any_type_detection() {
        let mut engine = SecurityRulesEngine::new();
        let owasp_yaml = include_str!("../rules/owasp-top10.yaml");
        engine.load_ruleset_yaml(owasp_yaml).unwrap();

        let code = r#"
function process(data: any): any {
    return data as any;
}
"#;
        let findings = engine.scan(code, "utils.ts", "typescript");
        assert!(
            findings.iter().any(|f| f.rule_id == "TS-001"),
            "Should detect TypeScript any type usage"
        );
    }

    #[test]
    fn test_all_language_rules_loading() {
        let mut engine = SecurityRulesEngine::new();
        let owasp_yaml = include_str!("../rules/owasp-top10.yaml");
        let count = engine.load_ruleset_yaml(owasp_yaml).unwrap();

        // Should have at least 48 rules (original 18 + Go 5 + Java 5 + C# 5 + Ruby 5 + Kotlin 5 + PHP 6 + TS 2 = 51, but some may be disabled)
        assert!(
            count >= 48,
            "owasp-top10.yaml should have at least 48 rules, got {}",
            count
        );

        // Verify key rules from each language
        assert!(engine.get_rule("GO-001").is_some(), "Go rules should exist");
        assert!(
            engine.get_rule("JAVA-001").is_some(),
            "Java rules should exist"
        );
        assert!(
            engine.get_rule("CSHARP-001").is_some(),
            "C# rules should exist"
        );
        assert!(
            engine.get_rule("RUBY-001").is_some(),
            "Ruby rules should exist"
        );
        assert!(
            engine.get_rule("KOTLIN-001").is_some(),
            "Kotlin rules should exist"
        );
        assert!(
            engine.get_rule("PHP-001").is_some(),
            "PHP rules should exist"
        );
        assert!(
            engine.get_rule("TS-001").is_some(),
            "TypeScript rules should exist"
        );
    }

    #[test]
    fn test_bundled_rules_loaded_automatically() {
        // Verify that SecurityRulesEngine::new() automatically loads all bundled YAML rules
        let engine = SecurityRulesEngine::new();

        // Check that rules from owasp-top10.yaml are loaded
        assert!(
            engine.get_rule("GO-001").is_some(),
            "Go SQL injection rule should be auto-loaded"
        );
        assert!(
            engine.get_rule("JAVA-001").is_some(),
            "Java SQL injection rule should be auto-loaded"
        );
        assert!(
            engine.get_rule("PHP-001").is_some(),
            "PHP SQL injection rule should be auto-loaded"
        );
        assert!(
            engine.get_rule("TS-001").is_some(),
            "TypeScript any type rule should be auto-loaded"
        );

        // Check that rules from cwe-top25.yaml are loaded
        assert!(
            engine.get_rule("RUST-001").is_some(),
            "Rust unsafe rule should be auto-loaded"
        );
        assert!(
            engine.get_rule("RUST-002").is_some(),
            "Rust unwrap rule should be auto-loaded"
        );

        // Check that rules from bash.yaml are loaded
        assert!(
            engine.get_rule("BASH-001").is_some(),
            "Bash command injection rule should be auto-loaded"
        );

        // Verify scanning works without manual YAML loading
        let rust_code = "unsafe { std::ptr::null::<i32>(); }";
        let findings = engine.scan(rust_code, "test.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-001"),
            "Should detect Rust unsafe block with auto-loaded rules"
        );
    }

    // ============= Go Language-Specific Rules Tests =============

    #[test]
    fn test_go_rules_loading_from_dedicated_file() {
        let engine = SecurityRulesEngine::new();
        // Verify new Go-specific rules are loaded
        assert!(
            engine.get_rule("GO-006").is_some(),
            "GO-006 (goroutine race) should exist"
        );
        assert!(
            engine.get_rule("GO-007").is_some(),
            "GO-007 (unsafe pointer) should exist"
        );
    }

    #[test]
    fn test_go_goroutine_race_detection() {
        let engine = SecurityRulesEngine::new();

        // Bad: Writing to shared variable in goroutine without synchronization
        let code = r#"
var counter int

func increment() {
    go func() {
        counter++  // BAD: Data race
    }()
}
"#;
        let findings = engine.scan(code, "race.go", "go");
        assert!(
            findings.iter().any(|f| f.rule_id == "GO-006"),
            "Should detect goroutine data race pattern"
        );
    }

    #[test]
    fn test_go_unsafe_pointer_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
import "unsafe"

func convert(p *int) uintptr {
    return uintptr(unsafe.Pointer(p))  // BAD: unsafe pointer conversion
}
"#;
        let findings = engine.scan(code, "unsafe.go", "go");
        assert!(
            findings.iter().any(|f| f.rule_id == "GO-007"),
            "Should detect Go unsafe pointer usage"
        );
    }

    // ============= Java Language-Specific Rules Tests =============

    #[test]
    fn test_java_rules_loading_from_dedicated_file() {
        let engine = SecurityRulesEngine::new();
        assert!(
            engine.get_rule("JAVA-006").is_some(),
            "JAVA-006 (JNDI injection) should exist"
        );
        assert!(
            engine.get_rule("JAVA-007").is_some(),
            "JAVA-007 (expression language injection) should exist"
        );
    }

    #[test]
    fn test_java_jndi_injection_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
InitialContext ctx = new InitialContext();
ctx.lookup(userInput);  // BAD: JNDI injection
"#;
        let findings = engine.scan(code, "JndiService.java", "java");
        assert!(
            findings.iter().any(|f| f.rule_id == "JAVA-006"),
            "Should detect Java JNDI injection"
        );
    }

    #[test]
    fn test_java_expression_language_injection_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
ValueExpression ve = factory.createValueExpression(ctx, userInput, String.class);
"#;
        let findings = engine.scan(code, "ElService.java", "java");
        assert!(
            findings.iter().any(|f| f.rule_id == "JAVA-007"),
            "Should detect Java Expression Language injection"
        );
    }

    // ============= C# Language-Specific Rules Tests =============

    #[test]
    fn test_csharp_rules_loading_from_dedicated_file() {
        let engine = SecurityRulesEngine::new();
        assert!(
            engine.get_rule("CSHARP-006").is_some(),
            "CSHARP-006 (dynamic LINQ) should exist"
        );
        assert!(
            engine.get_rule("CSHARP-007").is_some(),
            "CSHARP-007 (.NET config debug mode) should exist"
        );
    }

    #[test]
    fn test_csharp_dynamic_linq_injection_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
var result = db.Users.Where(userInput).ToList();
"#;
        let findings = engine.scan(code, "UserService.cs", "csharp");
        assert!(
            findings.iter().any(|f| f.rule_id == "CSHARP-006"),
            "Should detect C# dynamic LINQ injection"
        );
    }

    #[test]
    fn test_csharp_debug_config_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
<compilation debug="true" targetFramework="4.8">
"#;
        let findings = engine.scan(code, "web.config", "csharp");
        assert!(
            findings.iter().any(|f| f.rule_id == "CSHARP-007"),
            "Should detect C# debug mode in config"
        );
    }

    #[test]
    fn test_csharp_custom_errors_off_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
<customErrors mode="Off"/>
"#;
        let findings = engine.scan(code, "web.config", "csharp");
        assert!(
            findings.iter().any(|f| f.rule_id == "CSHARP-008"),
            "Should detect C# customErrors mode Off"
        );
    }

    // ============= Kotlin Language-Specific Rules Tests =============

    #[test]
    fn test_kotlin_rules_loading_from_dedicated_file() {
        let engine = SecurityRulesEngine::new();
        assert!(
            engine.get_rule("KOTLIN-006").is_some(),
            "KOTLIN-006 (null safety bypass) should exist"
        );
        assert!(
            engine.get_rule("KOTLIN-007").is_some(),
            "KOTLIN-007 (GlobalScope) should exist"
        );
    }

    #[test]
    fn test_kotlin_null_safety_bypass_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
val name = nullableValue!!  // BAD: Force unwrap
"#;
        let findings = engine.scan(code, "User.kt", "kotlin");
        assert!(
            findings.iter().any(|f| f.rule_id == "KOTLIN-006"),
            "Should detect Kotlin !! operator (null safety bypass)"
        );
    }

    #[test]
    fn test_kotlin_lateinit_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
class User {
    lateinit var name: String  // WARNING: potential UninitializedPropertyAccessException
}
"#;
        let findings = engine.scan(code, "User.kt", "kotlin");
        assert!(
            findings.iter().any(|f| f.rule_id == "KOTLIN-008"),
            "Should detect Kotlin lateinit usage"
        );
    }

    #[test]
    fn test_kotlin_globalscope_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
GlobalScope.launch {
    doWork()  // BAD: Unstructured concurrency
}
"#;
        let findings = engine.scan(code, "Service.kt", "kotlin");
        assert!(
            findings.iter().any(|f| f.rule_id == "KOTLIN-007"),
            "Should detect Kotlin GlobalScope usage"
        );
    }

    #[test]
    fn test_all_new_language_rules_count() {
        let engine = SecurityRulesEngine::new();

        // Count new rules (GO-006+, JAVA-006+, CSHARP-006+, KOTLIN-006+)
        let mut new_rule_count = 0;
        for rule_id in [
            "GO-006",
            "GO-007",
            "JAVA-006",
            "JAVA-007",
            "CSHARP-006",
            "CSHARP-007",
            "CSHARP-008",
            "KOTLIN-006",
            "KOTLIN-007",
            "KOTLIN-008",
        ] {
            if engine.get_rule(rule_id).is_some() {
                new_rule_count += 1;
            }
        }
        assert!(
            new_rule_count >= 10,
            "Should have at least 10 new language-specific rules, got {}",
            new_rule_count
        );
    }

    // ============= Configuration Security Rules Tests =============

    #[test]
    fn test_config_rules_loading() {
        let engine = SecurityRulesEngine::new();
        // Verify config rules are loaded
        assert!(
            engine.get_rule("CONFIG-001").is_some(),
            "CONFIG-001 (debug mode) should exist"
        );
        assert!(
            engine.get_rule("CONFIG-007").is_some(),
            "CONFIG-007 (default credentials) should exist"
        );
        assert!(
            engine.get_rule("CONFIG-012").is_some(),
            "CONFIG-012 (exposed secrets) should exist"
        );
    }

    #[test]
    fn test_config_debug_mode_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
debug: true
debug_mode: true
FLASK_DEBUG: 1
NODE_ENV: "development"
"#;
        let findings = engine.scan(code, "config.yaml", "yaml");
        assert!(
            findings.iter().any(|f| f.rule_id == "CONFIG-001"),
            "Should detect debug mode enabled"
        );
    }

    #[test]
    fn test_config_cors_wildcard_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
cors:
  origin: "*"
  allowed_origins: ["*"]
CORS_ORIGIN_ALLOW_ALL: True
"#;
        let findings = engine.scan(code, "config.yaml", "yaml");
        assert!(
            findings.iter().any(|f| f.rule_id == "CONFIG-003"),
            "Should detect CORS wildcard origin"
        );
    }

    #[test]
    fn test_config_default_credentials_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
database:
  username: "admin"
  password: "password"
  user: "root"
DB_PASSWORD: "admin"
"#;
        let findings = engine.scan(code, "config.yaml", "yaml");
        assert!(
            findings.iter().any(|f| f.rule_id == "CONFIG-007"),
            "Should detect default credentials"
        );
    }

    #[test]
    fn test_config_disabled_security_features_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
security:
  csrf:
    enabled: false
  xss_protection: false
WTF_CSRF_ENABLED: False
"#;
        let findings = engine.scan(code, "config.yaml", "yaml");
        assert!(
            findings.iter().any(|f| f.rule_id == "CONFIG-008"),
            "Should detect disabled security features"
        );
    }

    // ============= Infrastructure as Code Security Rules Tests =============

    #[test]
    fn test_iac_rules_loading() {
        let engine = SecurityRulesEngine::new();
        // Verify IaC rules are loaded
        assert!(
            engine.get_rule("IAC-001").is_some(),
            "IAC-001 (docker root) should exist"
        );
        assert!(
            engine.get_rule("IAC-007").is_some(),
            "IAC-007 (k8s host network) should exist"
        );
        assert!(
            engine.get_rule("IAC-015").is_some(),
            "IAC-015 (terraform s3 public) should exist"
        );
        assert!(
            engine.get_rule("IAC-023").is_some(),
            "IAC-023 (cfn s3 public) should exist"
        );
    }

    #[test]
    fn test_docker_running_as_root_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
FROM ubuntu:latest
USER root
RUN apt-get update
CMD ["nginx"]
"#;
        let findings = engine.scan(code, "Dockerfile", "dockerfile");
        assert!(
            findings.iter().any(|f| f.rule_id == "IAC-001"),
            "Should detect Docker running as root"
        );
    }

    #[test]
    fn test_docker_latest_tag_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
FROM ubuntu:latest
FROM nginx
image: myapp:latest
"#;
        let findings = engine.scan(code, "Dockerfile", "dockerfile");
        assert!(
            findings.iter().any(|f| f.rule_id == "IAC-002"),
            "Should detect Docker latest tag usage"
        );
    }

    #[test]
    fn test_docker_privileged_container_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
services:
  app:
    image: myapp
    privileged: true
"#;
        let findings = engine.scan(code, "docker-compose.yaml", "yaml");
        assert!(
            findings.iter().any(|f| f.rule_id == "IAC-003"),
            "Should detect Docker privileged container"
        );
    }

    #[test]
    fn test_k8s_host_network_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
  - name: app
    image: nginx
"#;
        let findings = engine.scan(code, "pod.yaml", "yaml");
        assert!(
            findings.iter().any(|f| f.rule_id == "IAC-007"),
            "Should detect K8s host network enabled"
        );
    }

    #[test]
    fn test_k8s_dangerous_capabilities_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      capabilities:
        add:
        - SYS_ADMIN
"#;
        let findings = engine.scan(code, "pod.yaml", "yaml");
        assert!(
            findings.iter().any(|f| f.rule_id == "IAC-010"),
            "Should detect K8s dangerous capabilities"
        );
    }

    #[test]
    fn test_terraform_s3_public_access_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read-write"
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id
  block_public_acls = false
}
"#;
        let findings = engine.scan(code, "main.tf", "terraform");
        assert!(
            findings.iter().any(|f| f.rule_id == "IAC-015"),
            "Should detect Terraform S3 public access"
        );
    }

    #[test]
    fn test_terraform_security_group_open_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
resource "aws_security_group" "allow_all" {
  name = "allow_all"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;
        let findings = engine.scan(code, "main.tf", "terraform");
        assert!(
            findings.iter().any(|f| f.rule_id == "IAC-017"),
            "Should detect Terraform wide-open security group"
        );
    }

    #[test]
    fn test_terraform_hardcoded_credentials_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_db_instance" "db" {
  password = "SuperSecretPassword123!"
}
"#;
        let findings = engine.scan(code, "main.tf", "terraform");
        assert!(
            findings.iter().any(|f| f.rule_id == "IAC-020"),
            "Should detect Terraform hardcoded credentials"
        );
    }

    #[test]
    fn test_cfn_s3_public_access_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
      AccessControl: PublicReadWrite
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
"#;
        let findings = engine.scan(code, "template.yaml", "yaml");
        assert!(
            findings.iter().any(|f| f.rule_id == "IAC-023"),
            "Should detect CloudFormation S3 public access"
        );
    }

    #[test]
    fn test_cfn_hardcoded_secrets_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
Resources:
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUserPassword: "MySuperSecretPassword"
"#;
        let findings = engine.scan(code, "template.yaml", "yaml");
        assert!(
            findings.iter().any(|f| f.rule_id == "IAC-026"),
            "Should detect CloudFormation hardcoded secrets"
        );
    }

    #[test]
    fn test_cfn_iam_wildcard_permissions_detection() {
        let engine = SecurityRulesEngine::new();

        let code = r#"
Resources:
  Policy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
"#;
        let findings = engine.scan(code, "template.yaml", "yaml");
        assert!(
            findings.iter().any(|f| f.rule_id == "IAC-027"),
            "Should detect CloudFormation IAM wildcard permissions"
        );
    }

    #[test]
    fn test_config_and_iac_rules_count() {
        let engine = SecurityRulesEngine::new();

        // Count config rules (CONFIG-001 through CONFIG-015)
        let mut config_rule_count = 0;
        for i in 1..=15 {
            let rule_id = format!("CONFIG-{:03}", i);
            if engine.get_rule(&rule_id).is_some() {
                config_rule_count += 1;
            }
        }
        assert!(
            config_rule_count >= 15,
            "Should have at least 15 config rules, got {}",
            config_rule_count
        );

        // Count IaC rules (IAC-001 through IAC-032)
        let mut iac_rule_count = 0;
        for i in 1..=32 {
            let rule_id = format!("IAC-{:03}", i);
            if engine.get_rule(&rule_id).is_some() {
                iac_rule_count += 1;
            }
        }
        assert!(
            iac_rule_count >= 32,
            "Should have at least 32 IaC rules, got {}",
            iac_rule_count
        );
    }

    // ========================================================================
    // Rust Security Rules Tests
    // ========================================================================

    #[test]
    fn test_rust_extended_rules_loading() {
        let engine = SecurityRulesEngine::new();
        // Verify all 18 Rust-specific rules loaded (RUST-004 through RUST-021)
        for id in 4..=21 {
            let rule_id = format!("RUST-{:03}", id);
            assert!(
                engine.get_rule(&rule_id).is_some(),
                "Rule {} should be loaded",
                rule_id
            );
        }
    }

    #[test]
    fn test_rust_rules_language_filtering() {
        let engine = SecurityRulesEngine::new();
        // Rust rules should only apply to Rust code
        let rust_code = r#"
let cmd = user_input;
Command::new(cmd).output().unwrap();
"#;
        let rust_findings = engine.scan(rust_code, "main.rs", "rust");
        let py_findings = engine.scan(rust_code, "main.py", "python");

        let rust_rule_count = rust_findings
            .iter()
            .filter(|f| f.rule_id.starts_with("RUST-"))
            .count();
        let py_rule_count = py_findings
            .iter()
            .filter(|f| f.rule_id.starts_with("RUST-"))
            .count();

        assert!(
            rust_rule_count > py_rule_count,
            "Rust rules should fire more on .rs files than .py files"
        );
    }

    #[test]
    fn test_rust_command_injection_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
use std::process::Command;
let user_cmd = get_user_input();
let output = Command::new(user_cmd).output().unwrap();
"#;
        let findings = engine.scan(vulnerable_code, "main.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-004"),
            "Should detect command injection via variable in Command::new: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_command_injection_safe_pattern() {
        let engine = SecurityRulesEngine::new();
        let safe_code = r#"
use std::process::Command;
let output = Command::new("ls").arg("-la").output().unwrap();
"#;
        let findings = engine.scan(safe_code, "main.rs", "rust");
        assert!(
            !findings.iter().any(|f| f.rule_id == "RUST-004"),
            "Should NOT detect command injection with string literal Command::new"
        );
    }

    #[test]
    fn test_rust_sql_injection_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
let query = format!("SELECT * FROM users WHERE name = '{}'", user_input);
conn.execute(&query).unwrap();
"#;
        let findings = engine.scan(vulnerable_code, "db.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-005"),
            "Should detect SQL injection via format! with SELECT: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_sql_injection_safe_pattern() {
        let engine = SecurityRulesEngine::new();
        let safe_code = r#"
let result = sqlx::query!("SELECT * FROM users WHERE id = $1", user_id)
    .fetch_one(&pool)
    .await?;
"#;
        let findings = engine.scan(safe_code, "db.rs", "rust");
        assert!(
            !findings.iter().any(|f| f.rule_id == "RUST-005"),
            "Should NOT detect SQL injection with sqlx::query! macro"
        );
    }

    #[test]
    fn test_rust_transmute_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
let value: u64 = unsafe { std::mem::transmute(some_f64) };
"#;
        let findings = engine.scan(vulnerable_code, "convert.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-006"),
            "Should detect transmute usage: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_transmute_safe_with_safety_comment() {
        let engine = SecurityRulesEngine::new();
        // Safe pattern check is per-line, so SAFETY: must be on same line as the match
        let safe_code = r#"
let value: u64 = unsafe { std::mem::transmute(some_f64) }; // SAFETY: same size and alignment
"#;
        let findings = engine.scan(safe_code, "convert.rs", "rust");
        assert!(
            !findings.iter().any(|f| f.rule_id == "RUST-006"),
            "Should NOT flag transmute with SAFETY comment on same line"
        );
    }

    #[test]
    fn test_rust_manual_memory_management_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
let raw = Box::into_raw(boxed_value);
let recovered = unsafe { Box::from_raw(raw) };
std::mem::forget(some_value);
"#;
        let findings = engine.scan(vulnerable_code, "mem.rs", "rust");
        let manual_mem_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "RUST-007")
            .collect();
        assert!(
            manual_mem_findings.len() >= 2,
            "Should detect Box::into_raw/from_raw and mem::forget: {:?}",
            manual_mem_findings
        );
    }

    #[test]
    fn test_rust_unchecked_arithmetic_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
let result = value.wrapping_add(other);
let result2 = unsafe { value.unchecked_mul(other) };
"#;
        let findings = engine.scan(code, "math.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-008"),
            "Should detect wrapping/unchecked arithmetic: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_hardcoded_secret_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
const API_KEY: &str = "hardcoded_secret_value_that_should_not_be_here";
static SECRET_TOKEN: &str = "my_super_secret_token_value";
"#;
        let findings = engine.scan(vulnerable_code, "config.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-009"),
            "Should detect hardcoded secrets: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_hardcoded_secret_safe_env() {
        let engine = SecurityRulesEngine::new();
        let safe_code = r#"
let api_key = std::env::var("API_KEY").expect("API_KEY must be set");
"#;
        let findings = engine.scan(safe_code, "config.rs", "rust");
        assert!(
            !findings.iter().any(|f| f.rule_id == "RUST-009"),
            "Should NOT flag env::var usage as hardcoded secret"
        );
    }

    #[test]
    fn test_rust_weak_hash_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
use md5;
let hash = md5::compute(password);
"#;
        let findings = engine.scan(vulnerable_code, "auth.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-010"),
            "Should detect MD5 usage: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_weak_hash_safe_sha256() {
        let engine = SecurityRulesEngine::new();
        let safe_code = r#"
use sha2::{Sha256, Digest};
let hash = Sha256::new().chain_update(data).finalize();
"#;
        let findings = engine.scan(safe_code, "auth.rs", "rust");
        assert!(
            !findings.iter().any(|f| f.rule_id == "RUST-010"),
            "Should NOT flag SHA-256 usage"
        );
    }

    #[test]
    fn test_rust_ffi_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
extern "C" {
    fn external_function(ptr: *const c_void) -> i32;
}
let c_string = CString::new("hello").unwrap();
"#;
        let findings = engine.scan(code, "ffi.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-012"),
            "Should detect FFI boundary: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_path_traversal_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
let user_path = get_input();
let contents = fs::read_to_string(user_path)?;
let file = File::open(user_path)?;
"#;
        let findings = engine.scan(vulnerable_code, "handler.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-013"),
            "Should detect path traversal via variable: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_path_traversal_safe_with_canonicalize() {
        let engine = SecurityRulesEngine::new();
        let safe_code = r#"
let canonical = Path::new(user_path).canonicalize()?;
if canonical.starts_with("/safe/dir") {
    let contents = fs::read_to_string(&canonical)?;
}
"#;
        let findings = engine.scan(safe_code, "handler.rs", "rust");
        let path_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "RUST-013")
            .collect();
        // canonicalize and starts_with are safe patterns — there may still be
        // findings on the fs::read_to_string line but the safe_patterns should
        // suppress them when they appear on the same line
        assert!(
            path_findings.len() <= 1,
            "Should suppress most path traversal findings with canonicalize: {:?}",
            path_findings
        );
    }

    #[test]
    fn test_rust_tls_verification_disabled() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
let client = reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .build()?;
"#;
        let findings = engine.scan(vulnerable_code, "http.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-017"),
            "Should detect disabled TLS verification: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_redos_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
let pattern = get_user_pattern();
let re = Regex::new(&pattern)?;
"#;
        let findings = engine.scan(vulnerable_code, "search.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-018"),
            "Should detect user-controlled regex pattern: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_redos_safe_literal_pattern() {
        let engine = SecurityRulesEngine::new();
        let safe_code = r#"
let re = Regex::new(r"^\d{4}-\d{2}-\d{2}$")?;
"#;
        let findings = engine.scan(safe_code, "search.rs", "rust");
        assert!(
            !findings.iter().any(|f| f.rule_id == "RUST-018"),
            "Should NOT flag literal regex pattern"
        );
    }

    #[test]
    fn test_rust_static_mut_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
static mut GLOBAL_COUNTER: u64 = 0;
"#;
        let findings = engine.scan(code, "lib.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-019"),
            "Should detect static mut: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_ssrf_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
let url = get_user_url();
let response = reqwest::get(url).await?;
"#;
        let findings = engine.scan(vulnerable_code, "fetch.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-020"),
            "Should detect SSRF via user-controlled URL: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_unsafe_slice_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
let value = unsafe { *slice.get_unchecked(index) };
let ptr_slice = unsafe { std::slice::from_raw_parts(ptr, len) };
"#;
        let findings = engine.scan(code, "buffer.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-021"),
            "Should detect unsafe slice operations: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rust_deserialization_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
let data: UserData = serde_json::from_str(&body)?;
let config: Config = serde_saphyr::from_str(&contents)?;
"#;
        let findings = engine.scan(code, "api.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-016"),
            "Should detect deserialization: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    // ========================================================================
    // Elixir Security Rules Tests
    // ========================================================================

    #[test]
    fn test_elixir_rules_loading() {
        let engine = SecurityRulesEngine::new();
        // Verify all 18 Elixir rules loaded (EX-001 through EX-018)
        for id in 1..=18 {
            let rule_id = format!("EX-{:03}", id);
            assert!(
                engine.get_rule(&rule_id).is_some(),
                "Rule {} should be loaded",
                rule_id
            );
        }
    }

    #[test]
    fn test_elixir_rules_language_filtering() {
        let engine = SecurityRulesEngine::new();
        // Elixir rules should only apply to Elixir code
        let elixir_code = r#"
atom = String.to_atom(user_input)
"#;
        let ex_findings = engine.scan(elixir_code, "lib/app.ex", "elixir");
        let py_findings = engine.scan(elixir_code, "app.py", "python");

        let ex_rule_count = ex_findings
            .iter()
            .filter(|f| f.rule_id.starts_with("EX-"))
            .count();
        let py_rule_count = py_findings
            .iter()
            .filter(|f| f.rule_id.starts_with("EX-"))
            .count();

        assert!(
            ex_rule_count > py_rule_count,
            "Elixir rules should fire on .ex files but not .py files"
        );
    }

    #[test]
    fn test_elixir_atom_exhaustion_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
defmodule MyApp.Handler do
  def handle(params) do
    key = String.to_atom(params["key"])
    Map.get(data, key)
  end
end
"#;
        let findings = engine.scan(vulnerable_code, "lib/handler.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-001"),
            "Should detect String.to_atom: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_atom_exhaustion_erlang_variant() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
key = :erlang.binary_to_atom(user_input, :utf8)
"#;
        let findings = engine.scan(vulnerable_code, "lib/handler.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-001"),
            "Should detect :erlang.binary_to_atom: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_atom_exhaustion_safe_pattern() {
        let engine = SecurityRulesEngine::new();
        let safe_code = r#"
key = String.to_existing_atom(params["key"])
"#;
        let findings = engine.scan(safe_code, "lib/handler.ex", "elixir");
        assert!(
            !findings.iter().any(|f| f.rule_id == "EX-001"),
            "Should NOT flag String.to_existing_atom"
        );
    }

    #[test]
    fn test_elixir_unsafe_deserialization_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
defmodule MyApp.API do
  def handle_request(data) do
    term = :erlang.binary_to_term(data)
    process(term)
  end
end
"#;
        let findings = engine.scan(vulnerable_code, "lib/api.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-002"),
            "Should detect binary_to_term: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_unsafe_deserialization_safe_plug_crypto() {
        let engine = SecurityRulesEngine::new();
        let safe_code = r#"
term = Plug.Crypto.non_executable_binary_to_term(data, [:safe])
"#;
        let findings = engine.scan(safe_code, "lib/api.ex", "elixir");
        assert!(
            !findings.iter().any(|f| f.rule_id == "EX-002"),
            "Should NOT flag Plug.Crypto.non_executable_binary_to_term"
        );
    }

    #[test]
    fn test_elixir_code_injection_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
defmodule MyApp.Eval do
  def run(user_code) do
    {result, _} = Code.eval_string(user_code)
    result
  end
end
"#;
        let findings = engine.scan(vulnerable_code, "lib/eval.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-003"),
            "Should detect Code.eval_string: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_command_injection_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
defmodule MyApp.Shell do
  def execute(user_command) do
    {output, 0} = System.cmd(user_command, [])
    output
  end
end
"#;
        let findings = engine.scan(vulnerable_code, "lib/shell.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-004"),
            "Should detect System.cmd: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_os_cmd_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
result = :os.cmd(String.to_charlist(user_input))
"#;
        let findings = engine.scan(vulnerable_code, "lib/shell.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-004"),
            "Should detect :os.cmd: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_sql_injection_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
defmodule MyApp.Users do
  def search(term) do
    query = "SELECT * FROM users WHERE name = '#{term}'"
    Ecto.Adapters.SQL.query(Repo, query)
  end
end
"#;
        let findings = engine.scan(vulnerable_code, "lib/users.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-005"),
            "Should detect SQL injection via string interpolation: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_sql_injection_safe_ecto_query() {
        let engine = SecurityRulesEngine::new();
        let safe_code = r#"
defmodule MyApp.Users do
  import Ecto.Query

  def search(term) do
    from u in User,
      where: u.name == ^term,
      select: u
    |> Repo.all()
  end
end
"#;
        let findings = engine.scan(safe_code, "lib/users.ex", "elixir");
        assert!(
            !findings.iter().any(|f| f.rule_id == "EX-005"),
            "Should NOT flag Ecto query DSL"
        );
    }

    #[test]
    fn test_elixir_xss_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
defmodule MyAppWeb.PageController do
  def show(conn, %{"content" => content}) do
    html = Phoenix.HTML.raw(content)
    render(conn, "show.html", content: html)
  end
end
"#;
        let findings = engine.scan(vulnerable_code, "lib/page_controller.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-006"),
            "Should detect Phoenix.HTML.raw with user content: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_path_traversal_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
defmodule MyApp.Files do
  def read(user_path) do
    File.read(user_path)
  end
end
"#;
        let findings = engine.scan(vulnerable_code, "lib/files.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-007"),
            "Should detect File.read with variable path: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_path_traversal_safe_literal() {
        let engine = SecurityRulesEngine::new();
        let safe_code = r#"
content = File.read!("priv/static/data.json")
"#;
        let findings = engine.scan(safe_code, "lib/files.ex", "elixir");
        assert!(
            !findings.iter().any(|f| f.rule_id == "EX-007"),
            "Should NOT flag File.read! with literal path"
        );
    }

    #[test]
    fn test_elixir_hardcoded_secrets_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
config :my_app, MyAppWeb.Endpoint,
  secret_key_base: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" # gitleaks:allow
"#;
        let findings = engine.scan(vulnerable_code, "config/config.exs", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-008"),
            "Should detect hardcoded secret_key_base: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_hardcoded_secrets_safe_env() {
        let engine = SecurityRulesEngine::new();
        let safe_code = r#"
config :my_app, MyAppWeb.Endpoint,
  secret_key_base: System.get_env("SECRET_KEY_BASE")
"#;
        let findings = engine.scan(safe_code, "config/runtime.exs", "elixir");
        assert!(
            !findings.iter().any(|f| f.rule_id == "EX-008"),
            "Should NOT flag System.get_env for secrets"
        );
    }

    #[test]
    fn test_elixir_eex_injection_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
defmodule MyApp.Template do
  def render(template_string) do
    EEx.eval_string(template_string)
  end
end
"#;
        let findings = engine.scan(vulnerable_code, "lib/template.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-012"),
            "Should detect EEx.eval_string: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_insecure_cookie_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
config :my_app, MyAppWeb.Endpoint,
  session: [
    store: :cookie,
    key: "_my_app_key",
    secure: false,
    http_only: false
  ]
"#;
        let findings = engine.scan(vulnerable_code, "config/config.exs", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-013"),
            "Should detect insecure cookie settings: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_erlang_distribution_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
Node.connect(:"other@192.168.1.100")
:erlang.set_cookie(node(), :my_secret_cookie)
"#;
        let findings = engine.scan(code, "lib/cluster.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-015"),
            "Should detect Erlang distribution usage: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_weak_crypto_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
hash = :crypto.hash(:md5, password)
"#;
        let findings = engine.scan(vulnerable_code, "lib/auth.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-016"),
            "Should detect MD5 usage: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_weak_crypto_safe_sha256() {
        let engine = SecurityRulesEngine::new();
        let safe_code = r#"
hash = :crypto.hash(:sha256, data)
"#;
        let findings = engine.scan(safe_code, "lib/auth.ex", "elixir");
        assert!(
            !findings.iter().any(|f| f.rule_id == "EX-016"),
            "Should NOT flag SHA-256 usage"
        );
    }

    #[test]
    fn test_elixir_sensitive_data_in_logs() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
Logger.info("User login with password: #{password}")
"#;
        let findings = engine.scan(vulnerable_code, "lib/auth.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-017"),
            "Should detect password in Logger output: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_rpc_detection() {
        let engine = SecurityRulesEngine::new();
        let code = r#"
:rpc.call(node, Module, :function, [args])
"#;
        let findings = engine.scan(code, "lib/cluster.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-010"),
            "Should detect :rpc.call: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elixir_open_redirect_detection() {
        let engine = SecurityRulesEngine::new();
        let vulnerable_code = r#"
def callback(conn, %{"redirect_to" => redirect_url}) do
  redirect(conn, external: redirect_url)
end
"#;
        let findings = engine.scan(vulnerable_code, "lib/controller.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-014"),
            "Should detect open redirect: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    // ========================================================================
    // Integration Tests — Real-World Code Patterns
    // ========================================================================

    #[test]
    fn test_integration_elixir_docker_backend_system_cmd() {
        // Pattern from a real Elixir Docker sandbox backend
        let engine = SecurityRulesEngine::new();
        let code = r#"
defmodule Krait.Sandbox.DockerBackend do
  def run_container(image, args) do
    case System.cmd("docker", args, stderr_to_stdout: true) do
      {output, 0} -> {:ok, output}
      {error, _code} -> {:error, error}
    end
  end

  def stop_container(container_id) do
    case System.cmd("docker", ["stop", container_id], stderr_to_stdout: true) do
      {_, 0} -> :ok
      _ -> :error
    end
  end
end
"#;
        let findings = engine.scan(code, "lib/sandbox/docker_backend.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-004"),
            "Should detect System.cmd in Docker backend: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_integration_elixir_file_operations_with_variable_path() {
        // Pattern from a real Elixir attestation/auth module
        let engine = SecurityRulesEngine::new();
        let code = r#"
defmodule Krait.Evolution.Attestation do
  def read_key(path) do
    case File.read(path) do
      {:ok, content} -> {:ok, content}
      {:error, reason} -> {:error, "Failed to read key: #{reason}"}
    end
  end
end
"#;
        let findings = engine.scan(code, "lib/evolution/attestation.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-007"),
            "Should detect File.read with variable path: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_integration_elixir_raw_sql_query() {
        // Pattern from a real Elixir release module
        let engine = SecurityRulesEngine::new();
        let code = r#"
defmodule Krait.Release do
  def check_db do
    case Ecto.Adapters.SQL.query(Krait.Repo, "SELECT 1") do
      {:ok, _} -> :ok
      {:error, _} -> :error
    end
  end
end
"#;
        let findings = engine.scan(code, "lib/release.ex", "elixir");
        assert!(
            findings.iter().any(|f| f.rule_id == "EX-005"),
            "Should detect Ecto.Adapters.SQL.query: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_integration_rust_nif_with_ffi() {
        // Pattern from a real Rust NIF for Elixir
        let engine = SecurityRulesEngine::new();
        let code = r#"
use rustler::{Env, NifResult, Term};
use std::ffi::CString;

extern "C" {
    fn tree_sitter_elixir() -> *const ();
}

#[rustler::nif(schedule = "DirtyCpu")]
fn quick_validate<'a>(env: Env<'a>, code: &str, language: &str) -> NifResult<Term<'a>> {
    let parsed = parse_code(code, language);
    Ok(parsed.encode(env))
}
"#;
        let findings = engine.scan(code, "native/krait_analyzer/src/lib.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-012"),
            "Should detect FFI boundary in NIF code: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_integration_rust_web_handler_with_deserialization() {
        // Pattern from a real Rust web API handler
        let engine = SecurityRulesEngine::new();
        let code = r#"
use axum::{Json, extract::Path};
use serde::Deserialize;

#[derive(Deserialize)]
struct CreateUser {
    name: String,
    email: String,
}

async fn create_user(Json(body): Json<CreateUser>) -> Result<Json<User>, ApiError> {
    let user_data: CreateUser = serde_json::from_str(&request_body)?;
    let user = db::insert_user(user_data).await?;
    Ok(Json(user))
}
"#;
        let findings = engine.scan(code, "src/handlers/users.rs", "rust");
        assert!(
            findings.iter().any(|f| f.rule_id == "RUST-016"),
            "Should detect serde_json::from_str in API handler: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_integration_rust_rules_count() {
        let engine = SecurityRulesEngine::new();
        let mut rust_rule_count = 0;
        for id in 1..=21 {
            let rule_id = format!("RUST-{:03}", id);
            if engine.get_rule(&rule_id).is_some() {
                rust_rule_count += 1;
            }
        }
        assert!(
            rust_rule_count >= 21,
            "Should have at least 21 Rust rules (3 from cwe-top25 + 18 from rust.yaml), got {}",
            rust_rule_count
        );
    }

    #[test]
    fn test_integration_elixir_rules_count() {
        let engine = SecurityRulesEngine::new();
        let mut elixir_rule_count = 0;
        for id in 1..=18 {
            let rule_id = format!("EX-{:03}", id);
            if engine.get_rule(&rule_id).is_some() {
                elixir_rule_count += 1;
            }
        }
        assert!(
            elixir_rule_count >= 18,
            "Should have at least 18 Elixir rules, got {}",
            elixir_rule_count
        );
    }
}
