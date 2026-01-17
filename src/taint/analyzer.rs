//! Taint analyzer implementation.
//!
//! This module contains the main taint analysis engine that:
//! - Finds taint sources in code
//! - Finds taint sinks in code
//! - Tracks taint flows from sources to sinks
//! - Detects sanitizers that clean tainted data

use std::collections::HashSet;

use super::patterns::{
    load_sanitizer_patterns, load_sink_patterns, load_source_patterns, SanitizerPattern,
    SinkPattern, SourcePattern,
};
use super::types::{
    TaintAnalysisResult, TaintFlow, TaintOperation, TaintSink, TaintSource, TaintStep,
};

/// Main taint analyzer
pub struct TaintAnalyzer {
    /// Source patterns
    source_patterns: Vec<SourcePattern>,
    /// Sink patterns
    sink_patterns: Vec<SinkPattern>,
    /// Sanitizer patterns
    sanitizer_patterns: Vec<SanitizerPattern>,
    /// Language being analyzed
    language: String,
}

impl TaintAnalyzer {
    /// Create a new taint analyzer with default patterns
    ///
    /// # Arguments
    ///
    /// * `language` - The programming language to analyze (e.g., "python", "javascript")
    ///
    /// # Examples
    ///
    /// ```
    /// use narsil_mcp::taint::analyzer::TaintAnalyzer;
    ///
    /// let analyzer = TaintAnalyzer::new("python");
    /// ```
    #[must_use]
    pub fn new(language: &str) -> Self {
        Self {
            source_patterns: load_source_patterns(),
            sink_patterns: load_sink_patterns(),
            sanitizer_patterns: load_sanitizer_patterns(),
            language: language.to_string(),
        }
    }

    /// Analyze code for taint flows
    ///
    /// # Arguments
    ///
    /// * `source_code` - The source code to analyze
    /// * `file_path` - The file path (used for reporting)
    ///
    /// # Returns
    ///
    /// A `TaintAnalysisResult` containing all identified sources, sinks, and flows
    #[must_use]
    pub fn analyze_code(&self, source_code: &str, file_path: &str) -> TaintAnalysisResult {
        let start_time = std::time::Instant::now();
        let mut result = TaintAnalysisResult::new(file_path);

        // Find sources
        result.sources = self.find_sources(source_code, file_path);
        result.stats.sources_found = result.sources.len();

        // Find sinks
        result.sinks = self.find_sinks(source_code, file_path);
        result.stats.sinks_found = result.sinks.len();

        // Find flows from sources to sinks
        result.flows = self.find_flows(source_code, file_path, &result.sources, &result.sinks);
        result.stats.flows_found = result.flows.len();

        // Separate vulnerabilities from sanitized flows
        for flow in &result.flows {
            if !flow.is_sanitized && flow.vulnerability.is_some() {
                result.vulnerabilities.push(flow.clone());
            } else if flow.is_sanitized {
                result.stats.sanitized_flows += 1;
            }
        }
        result.stats.vulnerabilities_found = result.vulnerabilities.len();

        result.stats.files_analyzed = 1;
        result.stats.analysis_time_ms = start_time.elapsed().as_millis() as u64;

        result
    }

    /// Find taint sources in code
    fn find_sources(&self, source_code: &str, file_path: &str) -> Vec<TaintSource> {
        let mut sources = Vec::new();
        let mut id_counter = 0;

        for (line_num, line) in source_code.lines().enumerate() {
            let line_num = line_num + 1; // 1-indexed

            for pattern in &self.source_patterns {
                // Check if pattern applies to this language
                if !pattern.languages.contains(&self.language) && !pattern.languages.is_empty() {
                    continue;
                }

                // Check property patterns
                for prop_pattern in &pattern.property_patterns {
                    if line.contains(prop_pattern) {
                        // Try to extract variable name
                        let variable = self
                            .extract_variable_from_assignment(line)
                            .unwrap_or_else(|| format!("var_{}", id_counter));

                        sources.push(TaintSource {
                            id: format!("src_{}", id_counter),
                            kind: pattern.kind.clone(),
                            file_path: file_path.to_string(),
                            line: line_num,
                            variable,
                            code: line.trim().chars().take(100).collect(),
                            confidence: pattern.confidence,
                        });
                        id_counter += 1;
                    }
                }

                // Check function patterns
                for func_pattern in &pattern.function_patterns {
                    if line.contains(func_pattern) {
                        let variable = self
                            .extract_variable_from_assignment(line)
                            .unwrap_or_else(|| format!("var_{}", id_counter));

                        sources.push(TaintSource {
                            id: format!("src_{}", id_counter),
                            kind: pattern.kind.clone(),
                            file_path: file_path.to_string(),
                            line: line_num,
                            variable,
                            code: line.trim().chars().take(100).collect(),
                            confidence: pattern.confidence,
                        });
                        id_counter += 1;
                    }
                }
            }
        }

        sources
    }

    /// Find taint sinks in code
    fn find_sinks(&self, source_code: &str, file_path: &str) -> Vec<TaintSink> {
        let mut sinks = Vec::new();
        let mut id_counter = 0;

        for (line_num, line) in source_code.lines().enumerate() {
            let line_num = line_num + 1;

            for pattern in &self.sink_patterns {
                if !pattern.languages.contains(&self.language) && !pattern.languages.is_empty() {
                    continue;
                }

                for func_pattern in &pattern.function_patterns {
                    if line.contains(func_pattern) {
                        sinks.push(TaintSink {
                            id: format!("sink_{}", id_counter),
                            kind: pattern.kind.clone(),
                            file_path: file_path.to_string(),
                            line: line_num,
                            function: func_pattern.trim_end_matches('(').to_string(),
                            code: line.trim().chars().take(100).collect(),
                            dangerous_arg: pattern.dangerous_arg,
                        });
                        id_counter += 1;
                    }
                }
            }
        }

        sinks
    }

    /// Find taint flows from sources to sinks
    fn find_flows(
        &self,
        source_code: &str,
        file_path: &str,
        sources: &[TaintSource],
        sinks: &[TaintSink],
    ) -> Vec<TaintFlow> {
        let mut flows = Vec::new();
        let lines: Vec<&str> = source_code.lines().collect();
        let mut flow_id = 0;

        for source in sources {
            // Track tainted variables
            let mut tainted_vars: HashSet<String> = HashSet::new();
            tainted_vars.insert(source.variable.clone());

            // Simple forward propagation through code
            for line_num in source.line..=lines.len() {
                let line_idx = line_num - 1;
                if line_idx >= lines.len() {
                    break;
                }
                let line = lines[line_idx];

                // Check for taint propagation (assignments)
                if let Some((lhs, rhs)) = self.parse_assignment(line) {
                    // If RHS contains tainted var, LHS becomes tainted
                    for tainted_var in tainted_vars.clone() {
                        if rhs.contains(&tainted_var) {
                            tainted_vars.insert(lhs.clone());
                        }
                    }
                }

                // Check if any tainted variable reaches a sink
                for sink in sinks {
                    if sink.line == line_num {
                        // Check if any tainted var is in the sink code
                        for tainted_var in &tainted_vars {
                            if sink.code.contains(tainted_var) {
                                // Check for sanitizers
                                let is_sanitized = self.check_sanitization(
                                    &lines,
                                    source.line,
                                    sink.line,
                                    tainted_var,
                                    &sink.kind,
                                );

                                let vulnerability = if is_sanitized {
                                    None
                                } else {
                                    Some(sink.kind.vulnerability_type())
                                };

                                let severity = vulnerability.as_ref().map(|v| v.default_severity());

                                let path =
                                    self.build_path(&lines, source, sink, tainted_var, file_path);

                                flows.push(TaintFlow {
                                    id: format!("flow_{}", flow_id),
                                    source: source.clone(),
                                    sink: sink.clone(),
                                    path,
                                    sanitizers: Vec::new(),
                                    vulnerability,
                                    severity,
                                    confidence: source.confidence,
                                    is_sanitized,
                                });
                                flow_id += 1;
                            }
                        }
                    }
                }
            }
        }

        flows
    }

    /// Check if a flow is sanitized
    fn check_sanitization(
        &self,
        lines: &[&str],
        source_line: usize,
        sink_line: usize,
        _variable: &str,
        sink_kind: &super::types::SinkKind,
    ) -> bool {
        for line_num in source_line..sink_line {
            if line_num > 0 && line_num <= lines.len() {
                let line = lines[line_num - 1];

                for pattern in &self.sanitizer_patterns {
                    if pattern.sanitizes_for.contains(sink_kind) {
                        for func_pattern in &pattern.function_patterns {
                            if line.contains(func_pattern) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Build the path from source to sink
    fn build_path(
        &self,
        lines: &[&str],
        source: &TaintSource,
        sink: &TaintSink,
        variable: &str,
        file_path: &str,
    ) -> Vec<TaintStep> {
        let mut path = Vec::new();

        // Add source
        path.push(TaintStep {
            file_path: file_path.to_string(),
            line: source.line,
            code: source.code.clone(),
            variable: source.variable.clone(),
            operation: TaintOperation::Source,
        });

        // Add intermediate steps where variable appears
        for line_num in (source.line + 1)..sink.line {
            if line_num > 0 && line_num <= lines.len() {
                let line = lines[line_num - 1];
                if line.contains(variable) {
                    let operation = if line.contains('=') {
                        TaintOperation::Assignment
                    } else if line.contains('(') {
                        TaintOperation::FunctionCall {
                            function: self.extract_function_name(line).unwrap_or_default(),
                        }
                    } else {
                        TaintOperation::Assignment
                    };

                    path.push(TaintStep {
                        file_path: file_path.to_string(),
                        line: line_num,
                        code: line.trim().chars().take(100).collect(),
                        variable: variable.to_string(),
                        operation,
                    });
                }
            }
        }

        // Add sink
        path.push(TaintStep {
            file_path: file_path.to_string(),
            line: sink.line,
            code: sink.code.clone(),
            variable: variable.to_string(),
            operation: TaintOperation::Sink,
        });

        path
    }

    /// Extract variable name from assignment
    fn extract_variable_from_assignment(&self, line: &str) -> Option<String> {
        // Handle various assignment patterns
        let line = line.trim();

        // Python/JS: var = ...
        if let Some(eq_pos) = line.find('=') {
            // Skip == and != comparisons
            if eq_pos > 0 {
                let before = line.chars().nth(eq_pos.saturating_sub(1));
                let after = line.chars().nth(eq_pos + 1);
                if before == Some('=') || before == Some('!') || after == Some('=') {
                    return None;
                }
            }
            if !line[..eq_pos].contains("==") && !line[..eq_pos].contains("!=") {
                let lhs = line[..eq_pos].trim();
                // Remove 'let', 'const', 'var', etc.
                let lhs = lhs
                    .trim_start_matches("let ")
                    .trim_start_matches("const ")
                    .trim_start_matches("var ")
                    .trim_start_matches("mut ")
                    .trim();
                // Get the variable name (first identifier)
                let var_name: String = lhs
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !var_name.is_empty() {
                    return Some(var_name);
                }
            }
        }

        None
    }

    /// Parse an assignment statement
    fn parse_assignment(&self, line: &str) -> Option<(String, String)> {
        let line = line.trim();

        if let Some(eq_pos) = line.find('=') {
            // Skip == and !=
            if eq_pos > 0 {
                let before = line.chars().nth(eq_pos.saturating_sub(1));
                let after = line.chars().nth(eq_pos + 1);
                if before == Some('=') || before == Some('!') || after == Some('=') {
                    return None;
                }
            }

            let lhs = line[..eq_pos].trim();
            let rhs = line[eq_pos + 1..].trim();

            // Clean up LHS
            let lhs = lhs
                .trim_start_matches("let ")
                .trim_start_matches("const ")
                .trim_start_matches("var ")
                .trim_start_matches("mut ")
                .trim();

            let var_name: String = lhs
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();

            if !var_name.is_empty() {
                return Some((var_name, rhs.to_string()));
            }
        }

        None
    }

    /// Extract function name from a line
    fn extract_function_name(&self, line: &str) -> Option<String> {
        // Look for pattern: name(
        if let Some(paren_pos) = line.find('(') {
            let before_paren = &line[..paren_pos];
            // Get the last identifier before (
            let name: String = before_paren
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
                .collect::<String>()
                .chars()
                .rev()
                .collect();

            if !name.is_empty() {
                return Some(name);
            }
        }
        None
    }
}

/// Convenience function to analyze Python code
///
/// # Examples
///
/// ```
/// use narsil_mcp::taint::analyzer::analyze_python;
///
/// let code = r#"
/// user_input = request.args.get('q')
/// cursor.execute(user_input)
/// "#;
/// let result = analyze_python(code, "test.py");
/// ```
#[must_use]
pub fn analyze_python(source_code: &str, file_path: &str) -> TaintAnalysisResult {
    let analyzer = TaintAnalyzer::new("python");
    analyzer.analyze_code(source_code, file_path)
}

/// Convenience function to analyze JavaScript code
#[must_use]
pub fn analyze_javascript(source_code: &str, file_path: &str) -> TaintAnalysisResult {
    let analyzer = TaintAnalyzer::new("javascript");
    analyzer.analyze_code(source_code, file_path)
}

/// Convenience function to analyze TypeScript code
#[must_use]
pub fn analyze_typescript(source_code: &str, file_path: &str) -> TaintAnalysisResult {
    let analyzer = TaintAnalyzer::new("typescript");
    analyzer.analyze_code(source_code, file_path)
}

/// Convenience function to analyze Rust code
#[must_use]
pub fn analyze_rust(source_code: &str, file_path: &str) -> TaintAnalysisResult {
    let analyzer = TaintAnalyzer::new("rust");
    analyzer.analyze_code(source_code, file_path)
}

/// Convenience function to analyze Go code
#[must_use]
pub fn analyze_go(source_code: &str, file_path: &str) -> TaintAnalysisResult {
    let analyzer = TaintAnalyzer::new("go");
    analyzer.analyze_code(source_code, file_path)
}

/// Detect language from file extension
///
/// # Examples
///
/// ```
/// use narsil_mcp::taint::analyzer::detect_language;
///
/// assert_eq!(detect_language("test.py"), "python");
/// assert_eq!(detect_language("app.js"), "javascript");
/// ```
#[must_use]
pub fn detect_language(file_path: &str) -> &'static str {
    if file_path.ends_with(".py") {
        "python"
    } else if file_path.ends_with(".js") {
        "javascript"
    } else if file_path.ends_with(".ts") || file_path.ends_with(".tsx") {
        "typescript"
    } else if file_path.ends_with(".rs") {
        "rust"
    } else if file_path.ends_with(".go") {
        "go"
    } else if file_path.ends_with(".java") {
        "java"
    } else if file_path.ends_with(".c") || file_path.ends_with(".h") {
        "c"
    } else if file_path.ends_with(".cpp") || file_path.ends_with(".hpp") {
        "cpp"
    } else if file_path.ends_with(".cs") {
        "csharp"
    } else if file_path.ends_with(".php") {
        "php"
    } else if file_path.ends_with(".rb") {
        "ruby"
    } else if file_path.ends_with(".kt") || file_path.ends_with(".kts") {
        "kotlin"
    } else {
        "unknown"
    }
}

/// Analyze code with auto-detected language
///
/// # Examples
///
/// ```
/// use narsil_mcp::taint::analyze_code;
///
/// let code = "user_input = request.args.get('q')";
/// let result = analyze_code(code, "test.py");
/// ```
#[must_use]
pub fn analyze_code(source_code: &str, file_path: &str) -> TaintAnalysisResult {
    let language = detect_language(file_path);
    let analyzer = TaintAnalyzer::new(language);
    analyzer.analyze_code(source_code, file_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_language() {
        assert_eq!(detect_language("test.py"), "python");
        assert_eq!(detect_language("app.js"), "javascript");
        assert_eq!(detect_language("main.ts"), "typescript");
        assert_eq!(detect_language("main.rs"), "rust");
        assert_eq!(detect_language("main.go"), "go");
        assert_eq!(detect_language("Main.java"), "java");
        assert_eq!(detect_language("Program.cs"), "csharp");
        assert_eq!(detect_language("index.php"), "php");
        assert_eq!(detect_language("app.rb"), "ruby");
        assert_eq!(detect_language("main.kt"), "kotlin");
        assert_eq!(detect_language("unknown.xyz"), "unknown");
    }

    #[test]
    fn test_analyze_python_sqli() {
        let code = r#"
from flask import request

user_input = request.args.get('q')
cursor.execute(user_input)
"#;
        let result = analyze_python(code, "test.py");
        assert!(!result.sources.is_empty(), "Should find sources");
        assert!(!result.sinks.is_empty(), "Should find sinks");
    }

    #[test]
    fn test_analyze_js_xss() {
        let code = r#"
const userInput = req.query.name;
document.innerHTML = userInput;
"#;
        let result = analyze_javascript(code, "test.js");
        assert!(!result.sources.is_empty(), "Should find sources");
        assert!(!result.sinks.is_empty(), "Should find sinks");
    }

    #[test]
    fn test_taint_analyzer_creation() {
        let analyzer = TaintAnalyzer::new("python");
        assert_eq!(analyzer.language, "python");
        assert!(!analyzer.source_patterns.is_empty());
        assert!(!analyzer.sink_patterns.is_empty());
        assert!(!analyzer.sanitizer_patterns.is_empty());
    }

    #[test]
    fn test_extract_variable_from_assignment() {
        let analyzer = TaintAnalyzer::new("python");

        assert_eq!(
            analyzer.extract_variable_from_assignment("x = 1"),
            Some("x".to_string())
        );
        assert_eq!(
            analyzer.extract_variable_from_assignment("let y = 2"),
            Some("y".to_string())
        );
        assert_eq!(
            analyzer.extract_variable_from_assignment("const z = 3"),
            Some("z".to_string())
        );
        assert_eq!(
            analyzer.extract_variable_from_assignment("var foo = bar"),
            Some("foo".to_string())
        );
        assert_eq!(analyzer.extract_variable_from_assignment("x == y"), None);
    }

    #[test]
    fn test_parse_assignment() {
        let analyzer = TaintAnalyzer::new("python");

        let result = analyzer.parse_assignment("x = foo + bar");
        assert!(result.is_some());
        let (lhs, rhs) = result.unwrap();
        assert_eq!(lhs, "x");
        assert_eq!(rhs, "foo + bar");

        // Should skip comparisons
        assert!(analyzer.parse_assignment("x == y").is_none());
        assert!(analyzer.parse_assignment("x != y").is_none());
    }

    #[test]
    fn test_sanitization_detection() {
        let code = r#"
user_input = request.args.get('q')
safe_input = html.escape(user_input)
element.innerHTML = safe_input
"#;
        let analyzer = TaintAnalyzer::new("python");
        let result = analyzer.analyze_code(code, "test.py");

        // The flow should be detected as sanitized
        for flow in &result.flows {
            if flow.sink.kind == super::super::types::SinkKind::HtmlOutput {
                assert!(flow.is_sanitized, "Flow should be sanitized");
            }
        }
    }

    #[test]
    fn test_command_injection_detection() {
        let code = r#"
user_input = request.args.get('cmd')
os.system(user_input)
"#;
        let result = analyze_python(code, "test.py");
        assert!(
            !result.vulnerabilities.is_empty(),
            "Should detect command injection"
        );
    }

    #[test]
    fn test_flow_building() {
        let code = r#"
user_input = request.args.get('q')
processed = user_input.strip()
cursor.execute(processed)
"#;
        let result = analyze_python(code, "test.py");

        for flow in &result.flows {
            assert!(!flow.path.is_empty(), "Flow should have a path");
            assert_eq!(flow.path.first().unwrap().operation, TaintOperation::Source);
            assert_eq!(flow.path.last().unwrap().operation, TaintOperation::Sink);
        }
    }

    #[test]
    fn test_extract_function_name() {
        let analyzer = TaintAnalyzer::new("python");

        assert_eq!(
            analyzer.extract_function_name("foo(x)"),
            Some("foo".to_string())
        );
        assert_eq!(
            analyzer.extract_function_name("obj.method(x)"),
            Some("obj.method".to_string())
        );
    }

    #[test]
    fn test_multiple_sources_same_file() {
        let code = r#"
a = request.args.get('a')
b = request.args.get('b')
c = request.args.get('c')
"#;
        let result = analyze_python(code, "test.py");
        assert_eq!(result.sources.len(), 3, "Should find 3 sources");
    }

    #[test]
    fn test_taint_stats() {
        let code = r#"
user_input = request.args.get('q')
cursor.execute(user_input)
"#;
        let result = analyze_python(code, "test.py");
        assert_eq!(result.stats.files_analyzed, 1);
        // analysis_time_ms is a u64, so we just verify it was recorded
        let _ = result.stats.analysis_time_ms;
    }

    #[test]
    fn test_go_analysis() {
        let code = r#"
query := r.URL.Query().Get("q")
db.Query(query)
"#;
        let result = analyze_go(code, "main.go");
        assert!(!result.sources.is_empty());
        assert!(!result.sinks.is_empty());
    }

    #[test]
    fn test_rust_analysis() {
        let code = r#"
let query = web::Query::<QueryParams>::extract(&req);
sqlx::query(&query.sql);
"#;
        let result = analyze_rust(code, "main.rs");
        assert!(!result.sources.is_empty());
    }

    #[test]
    fn test_typescript_analysis() {
        let code = r#"
const input = req.query.name;
res.send(input);
"#;
        let result = analyze_typescript(code, "app.ts");
        assert!(!result.sources.is_empty());
        assert!(!result.sinks.is_empty());
    }
}
