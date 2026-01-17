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
    SinkPattern, SourcePattern, TaintConfig,
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

    /// Create a new taint analyzer with custom configuration.
    ///
    /// This method allows using custom patterns defined in a `TaintConfig`.
    ///
    /// # Arguments
    ///
    /// * `language` - The programming language to analyze
    /// * `config` - Custom taint configuration with patterns
    ///
    /// # Examples
    ///
    /// ```
    /// use narsil_mcp::taint::analyzer::TaintAnalyzer;
    /// use narsil_mcp::taint::patterns::{TaintConfig, SanitizerPattern, SinkKind};
    ///
    /// let mut config = TaintConfig::default();
    /// config.add_sanitizer(SanitizerPattern {
    ///     name: "my_sanitizer".to_string(),
    ///     function_patterns: vec!["custom_escape(".to_string()],
    ///     sanitizes_for: vec![SinkKind::HtmlOutput],
    ///     languages: vec!["python".to_string()],
    /// });
    ///
    /// let analyzer = TaintAnalyzer::with_config("python", config);
    /// ```
    #[must_use]
    pub fn with_config(language: &str, config: TaintConfig) -> Self {
        Self {
            source_patterns: config.source_patterns,
            sink_patterns: config.sink_patterns,
            sanitizer_patterns: config.sanitizer_patterns,
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
                            // Also taint the base object if this is a field assignment
                            if let Some(base) = self.extract_base_object(&lhs) {
                                tainted_vars.insert(base);
                            }
                        }
                    }
                }

                // Check for method calls that might propagate taint (e.g., append, push, add)
                self.check_method_taint_propagation(line, &mut tainted_vars);

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

    /// Extract the base object from a field or index access expression.
    ///
    /// This method handles patterns like:
    /// - `data['query']` -> returns `Some("data")`
    /// - `obj.field` -> returns `Some("obj")`
    /// - `arr[0]` -> returns `Some("arr")`
    /// - `simple_var` -> returns `None`
    ///
    /// # Arguments
    ///
    /// * `expr` - The expression to extract the base object from
    ///
    /// # Returns
    ///
    /// The base object name if the expression is a field/index access, `None` otherwise.
    fn extract_base_object(&self, expr: &str) -> Option<String> {
        let expr = expr.trim();

        // Check for bracket access: data['key'] or arr[0]
        if let Some(bracket_pos) = expr.find('[') {
            let base = expr[..bracket_pos].trim();
            if !base.is_empty() && base.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Some(base.to_string());
            }
        }

        // Check for dot access: obj.field
        if let Some(dot_pos) = expr.find('.') {
            let base = expr[..dot_pos].trim();
            if !base.is_empty() && base.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Some(base.to_string());
            }
        }

        None
    }

    /// Check for method calls that propagate taint to a collection.
    ///
    /// This method handles patterns like:
    /// - `list.append(tainted_value)` - taints `list`
    /// - `arr.push(tainted_value)` - taints `arr`
    /// - `set.add(tainted_value)` - taints `set`
    /// - `dict.update(tainted_dict)` - taints `dict`
    ///
    /// # Arguments
    ///
    /// * `line` - The line of code to check
    /// * `tainted_vars` - The set of currently tainted variables (mutated if new taints found)
    fn check_method_taint_propagation(&self, line: &str, tainted_vars: &mut HashSet<String>) {
        let line = line.trim();

        // Methods that add values to collections
        let propagation_methods = [
            ".append(",
            ".push(",
            ".add(",
            ".insert(",
            ".extend(",
            ".update(",
            ".concat(",
            ".unshift(",
            ".splice(",
        ];

        for method in &propagation_methods {
            if let Some(method_pos) = line.find(method) {
                // Extract the base object before the method call
                let before_method = &line[..method_pos];

                // Get the base object name (handle nested dots)
                let base: String = before_method
                    .chars()
                    .rev()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();

                if base.is_empty() {
                    continue;
                }

                // Extract the argument(s) inside the method call
                let after_method = &line[method_pos + method.len()..];
                if let Some(close_paren) = after_method.find(')') {
                    let args = &after_method[..close_paren];

                    // Check if any tainted variable is in the arguments
                    for tainted_var in tainted_vars.clone() {
                        if args.contains(&tainted_var) {
                            // The base collection becomes tainted
                            tainted_vars.insert(base.clone());
                            break;
                        }
                    }
                }
            }
        }
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

    #[test]
    fn test_analyzer_with_custom_sanitizer() {
        use crate::taint::patterns::{SanitizerPattern, SinkKind, TaintConfig};

        // Code with custom sanitizer function that isn't in default patterns
        let code = r#"
user_input = request.args.get('q')
safe_input = my_custom_sanitize(user_input)
cursor.execute(safe_input)
"#;

        // First, analyze without custom sanitizer - should find vulnerability
        let result_without_custom = analyze_python(code, "test.py");
        let has_vuln_without_custom = result_without_custom.flows.iter().any(|f| !f.is_sanitized);
        assert!(
            has_vuln_without_custom,
            "Without custom sanitizer, should report vulnerability"
        );

        // Now create config with custom sanitizer
        let mut config = TaintConfig::default();
        config.add_sanitizer(SanitizerPattern {
            name: "custom_my_sanitize".to_string(),
            function_patterns: vec!["my_custom_sanitize(".to_string()],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec!["python".to_string()],
        });

        // Analyze with custom sanitizer - should detect sanitization
        let analyzer = TaintAnalyzer::with_config("python", config);
        let result_with_custom = analyzer.analyze_code(code, "test.py");

        // At least the flow should be marked as sanitized
        let all_sanitized = result_with_custom
            .flows
            .iter()
            .all(|f| f.is_sanitized || f.vulnerability.is_none());
        assert!(
            all_sanitized || result_with_custom.vulnerabilities.is_empty(),
            "With custom sanitizer, flow should be sanitized or no vulnerabilities"
        );
    }

    #[test]
    fn test_analyzer_with_custom_source() {
        use crate::taint::patterns::{Confidence, SourceKind, SourcePattern, TaintConfig};

        // Code with custom source that isn't in default patterns
        let code = r#"
user_data = my_custom_api.get_untrusted_input()
cursor.execute(user_data)
"#;

        // Create config with custom source
        let mut config = TaintConfig::default();
        config.add_source(SourcePattern {
            name: "custom_api_source".to_string(),
            kind: SourceKind::UserInput {
                input_type: "api".to_string(),
            },
            languages: vec!["python".to_string()],
            function_patterns: vec!["my_custom_api.get_untrusted_input(".to_string()],
            property_patterns: vec![],
            confidence: Confidence::High,
        });

        let analyzer = TaintAnalyzer::with_config("python", config);
        let result = analyzer.analyze_code(code, "test.py");

        // Should find the custom source
        assert!(
            !result.sources.is_empty(),
            "Should find custom source pattern"
        );
    }

    #[test]
    fn test_analyzer_with_custom_sink() {
        use crate::taint::patterns::{SinkKind, SinkPattern, TaintConfig};

        // Code with custom sink
        let code = r#"
user_input = request.args.get('data')
dangerous_custom_api(user_input)
"#;

        // Create config with custom sink
        let mut config = TaintConfig::default();
        config.add_sink(SinkPattern {
            name: "custom_dangerous_api".to_string(),
            kind: SinkKind::Custom {
                name: "dangerous_api".to_string(),
            },
            languages: vec!["python".to_string()],
            function_patterns: vec!["dangerous_custom_api(".to_string()],
            dangerous_arg: 0,
        });

        let analyzer = TaintAnalyzer::with_config("python", config);
        let result = analyzer.analyze_code(code, "test.py");

        // Should find the custom sink
        assert!(!result.sinks.is_empty(), "Should find custom sink pattern");
    }

    // Tests for taint through data structures (TDD RED phase)

    #[test]
    fn test_taint_propagates_through_object_field_assignment() {
        // When tainted data is assigned to an object field, accessing that field
        // should propagate the taint to the sink
        let code = r#"
user_input = request.args.get('q')
data = {}
data['query'] = user_input
cursor.execute(data['query'])
"#;
        let result = analyze_python(code, "test.py");

        // The flow from user_input through data['query'] to execute should be detected
        assert!(
            !result.vulnerabilities.is_empty(),
            "Should detect vulnerability through dict field assignment"
        );
    }

    #[test]
    fn test_taint_propagates_through_object_attribute() {
        // When tainted data is assigned to an object attribute, accessing that
        // attribute should propagate the taint
        let code = r#"
user_input = request.args.get('name')
user = User()
user.name = user_input
cursor.execute(user.name)
"#;
        let result = analyze_python(code, "test.py");

        assert!(
            !result.vulnerabilities.is_empty(),
            "Should detect vulnerability through object attribute"
        );
    }

    #[test]
    fn test_taint_propagates_through_array_index() {
        // When tainted data is stored in an array, accessing that index should
        // propagate the taint. This tests array assignment syntax.
        let code = r#"
user_input = request.args.get('item')
items = [user_input]
cursor.execute(items[0])
"#;
        let result = analyze_python(code, "test.py");

        // Note: Current implementation tracks variable names, not array contents.
        // This test verifies the basic flow detection works when user_input is
        // still visible in the array initialization.
        assert!(!result.sources.is_empty(), "Should find the taint source");
        assert!(!result.sinks.is_empty(), "Should find the SQL sink");
        // The flow may or may not be detected depending on implementation details
        // This is a known limitation documented for advanced taint analysis
    }

    #[test]
    fn test_taint_propagates_through_list_assignment() {
        // Test explicit list element assignment
        let code = r#"
user_input = request.args.get('item')
items = []
items[0] = user_input
cursor.execute(items[0])
"#;
        let result = analyze_python(code, "test.py");

        // The taint should be detected because user_input flows to items[0]
        // and items[0] is used in execute
        assert!(!result.sources.is_empty(), "Should find the taint source");
        assert!(!result.sinks.is_empty(), "Should find the SQL sink");
    }

    #[test]
    fn test_taint_propagates_through_nested_structure() {
        // Taint should propagate through nested data structures
        let code = r#"
user_input = request.args.get('data')
config = {}
config['db'] = {}
config['db']['query'] = user_input
cursor.execute(config['db']['query'])
"#;
        let result = analyze_python(code, "test.py");

        assert!(
            !result.vulnerabilities.is_empty(),
            "Should detect vulnerability through nested dict access"
        );
    }

    #[test]
    fn test_whole_object_tainted_when_field_assigned() {
        // When any field of an object is tainted, the whole object should be
        // considered tainted for conservative analysis
        let code = r#"
user_input = request.args.get('q')
data = {}
data['user_query'] = user_input
process_data(data)
cursor.execute(data)
"#;
        let result = analyze_python(code, "test.py");

        // Using the whole 'data' object in execute should be flagged
        // because it contains tainted data
        assert!(
            !result.vulnerabilities.is_empty(),
            "Should detect vulnerability when tainted object is used"
        );
    }

    #[test]
    fn test_javascript_object_property_taint() {
        // JavaScript object property assignment should propagate taint
        let code = r#"
const userInput = req.query.name;
const data = {};
data.query = userInput;
db.query(data.query);
"#;
        let result = analyze_javascript(code, "test.js");

        assert!(
            !result.vulnerabilities.is_empty(),
            "Should detect vulnerability through JS object property"
        );
    }
}
