//! Taint analysis types and data structures.
//!
//! This module contains all the core types used for taint analysis:
//! - Confidence and severity levels
//! - Source and sink kinds
//! - Vulnerability types
//! - Taint flow structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Confidence level for taint analysis results
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Confidence {
    /// Low confidence - may be false positive
    Low,
    /// Medium confidence
    Medium,
    /// High confidence - likely real vulnerability
    High,
}

/// Severity of a detected vulnerability
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Informational finding
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity - immediate action required
    Critical,
}

/// Types of taint sources
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceKind {
    /// HTTP request parameters, form data, URL params
    UserInput {
        /// Specific input type (query, body, header, cookie)
        input_type: String,
    },
    /// File content read
    FileRead,
    /// Database query results
    DatabaseQuery,
    /// Environment variables
    Environment,
    /// Network socket data
    Network,
    /// Command line arguments
    CommandArgs,
    /// Deserialized data
    Deserialization,
    /// User-defined custom source
    Custom { name: String },
}

impl SourceKind {
    /// Get display name for this source kind
    #[must_use]
    pub fn display_name(&self) -> String {
        match self {
            SourceKind::UserInput { input_type } => format!("User Input ({})", input_type),
            SourceKind::FileRead => "File Read".to_string(),
            SourceKind::DatabaseQuery => "Database Query".to_string(),
            SourceKind::Environment => "Environment Variable".to_string(),
            SourceKind::Network => "Network Data".to_string(),
            SourceKind::CommandArgs => "Command Args".to_string(),
            SourceKind::Deserialization => "Deserialized Data".to_string(),
            SourceKind::Custom { name } => format!("Custom ({})", name),
        }
    }
}

/// Types of taint sinks (dangerous operations)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkKind {
    /// SQL query execution - potential SQL injection
    SqlQuery,
    /// Shell command execution - potential command injection
    CommandExec,
    /// HTML/template output - potential XSS
    HtmlOutput,
    /// File system operations - potential path traversal
    FileWrite,
    /// File path operations - potential path traversal
    FilePath,
    /// Code evaluation (eval, exec) - potential code injection
    Eval,
    /// Object deserialization - potential object injection
    Deserialization,
    /// LDAP query - potential LDAP injection
    LdapQuery,
    /// XML parsing - potential XXE
    XmlParse,
    /// Regular expression - potential ReDoS
    Regex,
    /// Logging - potential log injection
    Logging,
    /// Redirect URL - potential open redirect
    Redirect,
    /// User-defined custom sink
    Custom { name: String },
}

impl SinkKind {
    /// Get the vulnerability type associated with this sink
    #[must_use]
    pub fn vulnerability_type(&self) -> VulnerabilityKind {
        match self {
            SinkKind::SqlQuery => VulnerabilityKind::SqlInjection,
            SinkKind::CommandExec => VulnerabilityKind::CommandInjection,
            SinkKind::HtmlOutput => VulnerabilityKind::Xss,
            SinkKind::FileWrite | SinkKind::FilePath => VulnerabilityKind::PathTraversal,
            SinkKind::Eval => VulnerabilityKind::CodeInjection,
            SinkKind::Deserialization => VulnerabilityKind::InsecureDeserialization,
            SinkKind::LdapQuery => VulnerabilityKind::LdapInjection,
            SinkKind::XmlParse => VulnerabilityKind::XxeInjection,
            SinkKind::Regex => VulnerabilityKind::ReDoS,
            SinkKind::Logging => VulnerabilityKind::LogInjection,
            SinkKind::Redirect => VulnerabilityKind::OpenRedirect,
            SinkKind::Custom { name } => VulnerabilityKind::Custom { name: name.clone() },
        }
    }

    /// Get display name for this sink kind
    #[must_use]
    pub fn display_name(&self) -> String {
        match self {
            SinkKind::SqlQuery => "SQL Query".to_string(),
            SinkKind::CommandExec => "Command Execution".to_string(),
            SinkKind::HtmlOutput => "HTML Output".to_string(),
            SinkKind::FileWrite => "File Write".to_string(),
            SinkKind::FilePath => "File Path".to_string(),
            SinkKind::Eval => "Code Eval".to_string(),
            SinkKind::Deserialization => "Deserialization".to_string(),
            SinkKind::LdapQuery => "LDAP Query".to_string(),
            SinkKind::XmlParse => "XML Parse".to_string(),
            SinkKind::Regex => "Regex".to_string(),
            SinkKind::Logging => "Logging".to_string(),
            SinkKind::Redirect => "Redirect".to_string(),
            SinkKind::Custom { name } => format!("Custom ({})", name),
        }
    }
}

/// Types of vulnerabilities detected
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VulnerabilityKind {
    /// SQL Injection (CWE-89)
    SqlInjection,
    /// Cross-Site Scripting (CWE-79)
    Xss,
    /// Command Injection (CWE-78)
    CommandInjection,
    /// Path Traversal (CWE-22)
    PathTraversal,
    /// Code Injection (CWE-94)
    CodeInjection,
    /// Insecure Deserialization (CWE-502)
    InsecureDeserialization,
    /// LDAP Injection (CWE-90)
    LdapInjection,
    /// XML External Entity (CWE-611)
    XxeInjection,
    /// Regular Expression DoS (CWE-1333)
    ReDoS,
    /// Log Injection (CWE-117)
    LogInjection,
    /// Open Redirect (CWE-601)
    OpenRedirect,
    /// Custom vulnerability type
    Custom { name: String },
}

impl VulnerabilityKind {
    /// Get CWE ID for this vulnerability
    #[must_use]
    pub fn cwe_id(&self) -> Option<&'static str> {
        match self {
            VulnerabilityKind::SqlInjection => Some("CWE-89"),
            VulnerabilityKind::Xss => Some("CWE-79"),
            VulnerabilityKind::CommandInjection => Some("CWE-78"),
            VulnerabilityKind::PathTraversal => Some("CWE-22"),
            VulnerabilityKind::CodeInjection => Some("CWE-94"),
            VulnerabilityKind::InsecureDeserialization => Some("CWE-502"),
            VulnerabilityKind::LdapInjection => Some("CWE-90"),
            VulnerabilityKind::XxeInjection => Some("CWE-611"),
            VulnerabilityKind::ReDoS => Some("CWE-1333"),
            VulnerabilityKind::LogInjection => Some("CWE-117"),
            VulnerabilityKind::OpenRedirect => Some("CWE-601"),
            VulnerabilityKind::Custom { .. } => None,
        }
    }

    /// Get OWASP Top 10 category if applicable
    #[must_use]
    pub fn owasp_category(&self) -> Option<&'static str> {
        match self {
            VulnerabilityKind::SqlInjection
            | VulnerabilityKind::CommandInjection
            | VulnerabilityKind::LdapInjection
            | VulnerabilityKind::XxeInjection => Some("A03:2021 - Injection"),
            VulnerabilityKind::Xss => Some("A03:2021 - Injection"),
            VulnerabilityKind::PathTraversal => Some("A01:2021 - Broken Access Control"),
            VulnerabilityKind::InsecureDeserialization => {
                Some("A08:2021 - Software and Data Integrity Failures")
            }
            VulnerabilityKind::OpenRedirect => Some("A01:2021 - Broken Access Control"),
            _ => None,
        }
    }

    /// Get default severity for this vulnerability type
    #[must_use]
    pub fn default_severity(&self) -> Severity {
        match self {
            VulnerabilityKind::SqlInjection => Severity::Critical,
            VulnerabilityKind::CommandInjection => Severity::Critical,
            VulnerabilityKind::CodeInjection => Severity::Critical,
            VulnerabilityKind::InsecureDeserialization => Severity::High,
            VulnerabilityKind::PathTraversal => Severity::High,
            VulnerabilityKind::Xss => Severity::High,
            VulnerabilityKind::XxeInjection => Severity::High,
            VulnerabilityKind::LdapInjection => Severity::High,
            VulnerabilityKind::OpenRedirect => Severity::Medium,
            VulnerabilityKind::LogInjection => Severity::Medium,
            VulnerabilityKind::ReDoS => Severity::Medium,
            VulnerabilityKind::Custom { .. } => Severity::Medium,
        }
    }

    /// Get display name
    #[must_use]
    pub fn display_name(&self) -> &str {
        match self {
            VulnerabilityKind::SqlInjection => "SQL Injection",
            VulnerabilityKind::Xss => "Cross-Site Scripting (XSS)",
            VulnerabilityKind::CommandInjection => "Command Injection",
            VulnerabilityKind::PathTraversal => "Path Traversal",
            VulnerabilityKind::CodeInjection => "Code Injection",
            VulnerabilityKind::InsecureDeserialization => "Insecure Deserialization",
            VulnerabilityKind::LdapInjection => "LDAP Injection",
            VulnerabilityKind::XxeInjection => "XXE Injection",
            VulnerabilityKind::ReDoS => "Regular Expression DoS",
            VulnerabilityKind::LogInjection => "Log Injection",
            VulnerabilityKind::OpenRedirect => "Open Redirect",
            VulnerabilityKind::Custom { name } => name,
        }
    }
}

/// A taint label attached to data
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintLabel {
    /// Kind of source that introduced this taint
    pub source_kind: SourceKind,
    /// Location where taint was introduced
    pub origin_file: String,
    /// Origin line number
    pub origin_line: usize,
    /// Variable that was tainted
    pub variable: String,
    /// Confidence level
    pub confidence: Confidence,
}

/// A taint source location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    /// Unique identifier
    pub id: String,
    /// Kind of source
    pub kind: SourceKind,
    /// File path
    pub file_path: String,
    /// Line number
    pub line: usize,
    /// Variable name that receives tainted data
    pub variable: String,
    /// Code snippet
    pub code: String,
    /// Confidence
    pub confidence: Confidence,
}

/// A taint sink location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    /// Unique identifier
    pub id: String,
    /// Kind of sink
    pub kind: SinkKind,
    /// File path
    pub file_path: String,
    /// Line number
    pub line: usize,
    /// Function/method being called
    pub function: String,
    /// Code snippet
    pub code: String,
    /// Which argument position is dangerous (0-indexed)
    pub dangerous_arg: usize,
}

/// A step in the taint propagation path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintStep {
    /// File path
    pub file_path: String,
    /// Line number
    pub line: usize,
    /// Code snippet
    pub code: String,
    /// Variable carrying taint at this step
    pub variable: String,
    /// Type of operation
    pub operation: TaintOperation,
}

/// Types of operations in taint propagation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintOperation {
    /// Source introduces taint
    Source,
    /// Assignment propagates taint
    Assignment,
    /// Function call (may propagate or sanitize)
    FunctionCall { function: String },
    /// String concatenation
    Concatenation,
    /// Array/object access
    PropertyAccess,
    /// Return from function
    Return,
    /// Sink receives taint
    Sink,
}

/// A sanitizer that removes taint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sanitizer {
    /// Sanitizer identifier
    pub id: String,
    /// Function name
    pub function: String,
    /// What kind of taint it sanitizes for
    pub sanitizes_for: Vec<SinkKind>,
    /// File path where used
    pub file_path: String,
    /// Line number
    pub line: usize,
}

/// A complete taint flow from source to sink
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    /// Unique identifier
    pub id: String,
    /// The taint source
    pub source: TaintSource,
    /// The taint sink
    pub sink: TaintSink,
    /// Path from source to sink
    pub path: Vec<TaintStep>,
    /// Sanitizers encountered (if any)
    pub sanitizers: Vec<Sanitizer>,
    /// Detected vulnerability (if unsanitized)
    pub vulnerability: Option<VulnerabilityKind>,
    /// Severity if vulnerable
    pub severity: Option<Severity>,
    /// Confidence level
    pub confidence: Confidence,
    /// Is the flow properly sanitized?
    pub is_sanitized: bool,
}

impl TaintFlow {
    /// Format as markdown
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        if let Some(ref vuln) = self.vulnerability {
            let severity_icon = match self.severity.unwrap_or(Severity::Medium) {
                Severity::Critical => "🔴",
                Severity::High => "🟠",
                Severity::Medium => "🟡",
                Severity::Low => "🔵",
                Severity::Info => "⚪",
            };

            md.push_str(&format!(
                "## {} {} ({})\n\n",
                severity_icon,
                vuln.display_name(),
                vuln.cwe_id().unwrap_or("N/A")
            ));

            if let Some(owasp) = vuln.owasp_category() {
                md.push_str(&format!("**OWASP**: {}\n\n", owasp));
            }
        } else if self.is_sanitized {
            md.push_str("## ✅ Sanitized Flow\n\n");
        }

        // Source
        md.push_str("### Source\n\n");
        md.push_str(&format!(
            "- **Type**: {}\n",
            self.source.kind.display_name()
        ));
        md.push_str(&format!(
            "- **Location**: `{}:{}`\n",
            self.source.file_path, self.source.line
        ));
        md.push_str(&format!("- **Variable**: `{}`\n", self.source.variable));
        md.push_str(&format!("- **Code**: `{}`\n\n", self.source.code));

        // Path
        if !self.path.is_empty() {
            md.push_str("### Data Flow Path\n\n");
            for (i, step) in self.path.iter().enumerate() {
                md.push_str(&format!(
                    "{}. **{}:{}** - `{}` ({:?})\n",
                    i + 1,
                    step.file_path,
                    step.line,
                    step.code,
                    step.operation
                ));
            }
            md.push('\n');
        }

        // Sanitizers
        if !self.sanitizers.is_empty() {
            md.push_str("### Sanitizers Applied\n\n");
            for san in &self.sanitizers {
                md.push_str(&format!(
                    "- `{}` at `{}:{}`\n",
                    san.function, san.file_path, san.line
                ));
            }
            md.push('\n');
        }

        // Sink
        md.push_str("### Sink\n\n");
        md.push_str(&format!("- **Type**: {}\n", self.sink.kind.display_name()));
        md.push_str(&format!(
            "- **Location**: `{}:{}`\n",
            self.sink.file_path, self.sink.line
        ));
        md.push_str(&format!("- **Function**: `{}`\n", self.sink.function));
        md.push_str(&format!("- **Code**: `{}`\n\n", self.sink.code));

        md
    }
}

/// Taint analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisResult {
    /// File or repository analyzed
    pub target: String,
    /// All identified sources
    pub sources: Vec<TaintSource>,
    /// All identified sinks
    pub sinks: Vec<TaintSink>,
    /// All taint flows found
    pub flows: Vec<TaintFlow>,
    /// Vulnerabilities found (unsanitized flows)
    pub vulnerabilities: Vec<TaintFlow>,
    /// Statistics
    pub stats: TaintStats,
}

/// Statistics from taint analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintStats {
    /// Number of files analyzed
    pub files_analyzed: usize,
    /// Number of functions analyzed
    pub functions_analyzed: usize,
    /// Number of sources found
    pub sources_found: usize,
    /// Number of sinks found
    pub sinks_found: usize,
    /// Number of flows found
    pub flows_found: usize,
    /// Number of vulnerabilities found
    pub vulnerabilities_found: usize,
    /// Number of sanitized flows
    pub sanitized_flows: usize,
    /// Analysis time in milliseconds
    pub analysis_time_ms: u64,
}

impl TaintAnalysisResult {
    /// Create a new taint analysis result
    #[must_use]
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            sources: Vec::new(),
            sinks: Vec::new(),
            flows: Vec::new(),
            vulnerabilities: Vec::new(),
            stats: TaintStats::default(),
        }
    }

    /// Format as markdown
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str(&format!("# Taint Analysis: {}\n\n", self.target));

        // Summary
        md.push_str("## Summary\n\n");
        md.push_str(&format!(
            "- **Files Analyzed**: {}\n",
            self.stats.files_analyzed
        ));
        md.push_str(&format!(
            "- **Sources Found**: {}\n",
            self.stats.sources_found
        ));
        md.push_str(&format!("- **Sinks Found**: {}\n", self.stats.sinks_found));
        md.push_str(&format!("- **Taint Flows**: {}\n", self.stats.flows_found));
        md.push_str(&format!(
            "- **Vulnerabilities**: {}\n",
            self.stats.vulnerabilities_found
        ));
        md.push_str(&format!(
            "- **Sanitized Flows**: {}\n\n",
            self.stats.sanitized_flows
        ));

        // Vulnerabilities
        if !self.vulnerabilities.is_empty() {
            md.push_str("## Vulnerabilities Found\n\n");

            // Group by severity
            let mut by_severity: HashMap<Severity, Vec<&TaintFlow>> = HashMap::new();
            for flow in &self.vulnerabilities {
                let sev = flow.severity.unwrap_or(Severity::Medium);
                by_severity.entry(sev).or_default().push(flow);
            }

            for severity in [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info,
            ] {
                if let Some(flows) = by_severity.get(&severity) {
                    for flow in flows {
                        md.push_str(&flow.to_markdown());
                        md.push_str("---\n\n");
                    }
                }
            }
        } else {
            md.push_str("## No Vulnerabilities Found\n\n");
            md.push_str("All taint flows are properly sanitized.\n\n");
        }

        // Sources summary
        if !self.sources.is_empty() {
            md.push_str("## Taint Sources\n\n");
            md.push_str("| Location | Type | Variable |\n");
            md.push_str("|----------|------|----------|\n");
            for source in &self.sources {
                md.push_str(&format!(
                    "| `{}:{}` | {} | `{}` |\n",
                    source.file_path,
                    source.line,
                    source.kind.display_name(),
                    source.variable
                ));
            }
            md.push('\n');
        }

        // Sinks summary
        if !self.sinks.is_empty() {
            md.push_str("## Taint Sinks\n\n");
            md.push_str("| Location | Type | Function |\n");
            md.push_str("|----------|------|----------|\n");
            for sink in &self.sinks {
                md.push_str(&format!(
                    "| `{}:{}` | {} | `{}` |\n",
                    sink.file_path,
                    sink.line,
                    sink.kind.display_name(),
                    sink.function
                ));
            }
        }

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_vulnerability_cwe() {
        assert_eq!(VulnerabilityKind::SqlInjection.cwe_id(), Some("CWE-89"));
        assert_eq!(VulnerabilityKind::Xss.cwe_id(), Some("CWE-79"));
        assert_eq!(VulnerabilityKind::CommandInjection.cwe_id(), Some("CWE-78"));
    }

    #[test]
    fn test_vulnerability_owasp() {
        assert!(VulnerabilityKind::SqlInjection.owasp_category().is_some());
        assert!(VulnerabilityKind::Xss.owasp_category().is_some());
    }

    #[test]
    fn test_source_kind_display() {
        let source = SourceKind::UserInput {
            input_type: "http".to_string(),
        };
        assert!(source.display_name().contains("User Input"));
    }

    #[test]
    fn test_sink_kind_display() {
        assert_eq!(SinkKind::SqlQuery.display_name(), "SQL Query");
        assert_eq!(SinkKind::CommandExec.display_name(), "Command Execution");
    }

    #[test]
    fn test_taint_flow_markdown() {
        let flow = TaintFlow {
            id: "test-1".to_string(),
            source: TaintSource {
                id: "src-1".to_string(),
                kind: SourceKind::UserInput {
                    input_type: "http".to_string(),
                },
                file_path: "test.py".to_string(),
                line: 10,
                variable: "user_input".to_string(),
                code: "user_input = request.args.get('q')".to_string(),
                confidence: Confidence::High,
            },
            sink: TaintSink {
                id: "sink-1".to_string(),
                kind: SinkKind::SqlQuery,
                file_path: "test.py".to_string(),
                line: 15,
                function: "execute".to_string(),
                code: "cursor.execute(query)".to_string(),
                dangerous_arg: 0,
            },
            path: vec![],
            sanitizers: vec![],
            vulnerability: Some(VulnerabilityKind::SqlInjection),
            severity: Some(Severity::Critical),
            confidence: Confidence::High,
            is_sanitized: false,
        };

        let md = flow.to_markdown();
        assert!(md.contains("SQL Injection"));
        assert!(md.contains("CWE-89"));
    }

    #[test]
    fn test_taint_analysis_result_markdown() {
        let result = TaintAnalysisResult::new("test.py");
        let md = result.to_markdown();
        assert!(md.contains("Taint Analysis: test.py"));
        assert!(md.contains("No Vulnerabilities Found"));
    }

    #[test]
    fn test_taint_stats_default() {
        let stats = TaintStats::default();
        assert_eq!(stats.files_analyzed, 0);
        assert_eq!(stats.vulnerabilities_found, 0);
    }
}
