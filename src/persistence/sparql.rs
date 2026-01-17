//! SPARQL query engine for executing queries against the RDF knowledge graph.
//!
//! This module provides a high-level interface for executing SPARQL queries
//! with support for timeouts, result limits, and parameterized query templates.
//!
//! # Features
//!
//! - Execute arbitrary SPARQL SELECT, ASK, and CONSTRUCT queries
//! - Query timeout protection for long-running queries
//! - Result limiting to prevent overwhelming responses
//! - Parameterized query templates for common code intelligence patterns
//!
//! # Example
//!
//! ```ignore
//! use narsil_mcp::persistence::sparql::{SparqlEngine, QueryOptions};
//! use narsil_mcp::persistence::KnowledgeGraph;
//!
//! let graph = KnowledgeGraph::in_memory().unwrap();
//! let engine = SparqlEngine::new(&graph);
//!
//! let options = QueryOptions::default()
//!     .with_timeout_ms(5000)
//!     .with_limit(100);
//!
//! let result = engine.query_select(
//!     "SELECT ?s ?p ?o WHERE { ?s ?p ?o }",
//!     &options,
//! ).unwrap();
//! ```

use anyhow::{anyhow, Result};
use oxigraph::model::Term;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::graph::KnowledgeGraph;

/// Default query timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Default maximum number of results to return.
pub const DEFAULT_RESULT_LIMIT: usize = 1000;

/// Maximum allowed timeout in milliseconds.
pub const MAX_TIMEOUT_MS: u64 = 300_000;

/// Maximum allowed result limit.
pub const MAX_RESULT_LIMIT: usize = 10_000;

/// Options for SPARQL query execution.
#[derive(Debug, Clone)]
pub struct QueryOptions {
    /// Timeout in milliseconds (default: 30000)
    pub timeout_ms: u64,
    /// Maximum number of results (default: 1000)
    pub limit: usize,
    /// Offset for pagination (default: 0)
    pub offset: usize,
    /// Format for output (default: json)
    pub format: OutputFormat,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_TIMEOUT_MS,
            limit: DEFAULT_RESULT_LIMIT,
            offset: 0,
            format: OutputFormat::Json,
        }
    }
}

impl QueryOptions {
    /// Creates options with a specific timeout.
    #[must_use]
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms.min(MAX_TIMEOUT_MS);
        self
    }

    /// Creates options with a specific result limit.
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit.min(MAX_RESULT_LIMIT);
        self
    }

    /// Creates options with a specific offset for pagination.
    #[must_use]
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    /// Creates options with a specific output format.
    #[must_use]
    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.format = format;
        self
    }
}

/// Output format for SPARQL query results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// JSON output (default)
    #[default]
    Json,
    /// Markdown table output
    Markdown,
    /// CSV output
    Csv,
}

impl std::str::FromStr for OutputFormat {
    type Err = anyhow::Error;

    /// Parses a format string.
    ///
    /// # Errors
    ///
    /// Returns an error if the format string is invalid.
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "markdown" | "md" => Ok(Self::Markdown),
            "csv" => Ok(Self::Csv),
            _ => Err(anyhow!(
                "Unknown format: {}. Valid formats: json, markdown, csv",
                s
            )),
        }
    }
}

/// Result of a SPARQL SELECT query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectResult {
    /// Variable names in the result set
    pub variables: Vec<String>,
    /// Result rows as maps of variable name to value
    pub rows: Vec<HashMap<String, SparqlValue>>,
    /// Total number of rows (before limit/offset)
    pub total_count: usize,
    /// Whether the results were truncated due to limit
    pub truncated: bool,
    /// Query execution time in milliseconds
    pub execution_time_ms: u64,
}

/// A SPARQL value that can be serialized.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum SparqlValue {
    /// IRI/URI value
    Uri(String),
    /// Literal string value
    Literal(String),
    /// Typed literal with datatype
    TypedLiteral { value: String, datatype: String },
    /// Language-tagged literal
    LangLiteral { value: String, language: String },
    /// Blank node
    BlankNode(String),
    /// Null/unbound value
    Null,
}

impl SparqlValue {
    /// Converts an Oxigraph Term to a SparqlValue.
    #[must_use]
    pub fn from_term(term: &Term) -> Self {
        match term {
            Term::NamedNode(n) => Self::Uri(n.as_str().to_string()),
            Term::BlankNode(b) => Self::BlankNode(b.as_str().to_string()),
            Term::Literal(l) => {
                if let Some(lang) = l.language() {
                    Self::LangLiteral {
                        value: l.value().to_string(),
                        language: lang.to_string(),
                    }
                } else if l.datatype().as_str() == "http://www.w3.org/2001/XMLSchema#string" {
                    Self::Literal(l.value().to_string())
                } else {
                    Self::TypedLiteral {
                        value: l.value().to_string(),
                        datatype: l.datatype().as_str().to_string(),
                    }
                }
            }
        }
    }

    /// Returns the value as a simple string representation.
    #[must_use]
    pub fn as_string(&self) -> String {
        match self {
            Self::Uri(s) | Self::Literal(s) | Self::BlankNode(s) => s.clone(),
            Self::TypedLiteral { value, .. } | Self::LangLiteral { value, .. } => value.clone(),
            Self::Null => "null".to_string(),
        }
    }
}

/// Result of a SPARQL ASK query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AskResult {
    /// The boolean result
    pub result: bool,
    /// Query execution time in milliseconds
    pub execution_time_ms: u64,
}

/// Predefined query templates for common code intelligence patterns.
#[derive(Debug, Clone)]
pub struct QueryTemplate {
    /// Template name
    pub name: &'static str,
    /// Human-readable description
    pub description: &'static str,
    /// SPARQL query with $variable placeholders
    pub template: &'static str,
    /// Required parameters
    pub parameters: &'static [&'static str],
}

/// SPARQL query engine wrapping a KnowledgeGraph.
///
/// Provides high-level query execution with timeout and result limiting.
pub struct SparqlEngine<'a> {
    graph: &'a KnowledgeGraph,
}

impl<'a> SparqlEngine<'a> {
    /// Creates a new SPARQL engine for the given knowledge graph.
    #[must_use]
    pub fn new(graph: &'a KnowledgeGraph) -> Self {
        Self { graph }
    }

    /// Executes a SPARQL SELECT query and returns the results.
    ///
    /// # Arguments
    ///
    /// * `sparql` - The SPARQL SELECT query
    /// * `options` - Query execution options (timeout, limit, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The query is invalid
    /// - The query times out
    /// - Query execution fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let result = engine.query_select(
    ///     "SELECT ?s ?p ?o WHERE { ?s ?p ?o } LIMIT 10",
    ///     &QueryOptions::default(),
    /// )?;
    /// ```
    pub fn query_select(&self, sparql: &str, options: &QueryOptions) -> Result<SelectResult> {
        let start = Instant::now();
        let timeout = Duration::from_millis(options.timeout_ms);

        // Execute the query
        let solutions = self.graph.query(sparql)?;

        // Check timeout before processing
        if start.elapsed() > timeout {
            return Err(anyhow!("Query timed out after {}ms", options.timeout_ms));
        }

        // Get total count
        let total_count = solutions.len();

        // Extract variable names from first solution
        let variables: Vec<String> = if let Some(first) = solutions.first() {
            first
                .variables()
                .iter()
                .map(|v| v.as_str().to_string())
                .collect()
        } else {
            Vec::new()
        };

        // Apply offset and limit
        let rows: Vec<HashMap<String, SparqlValue>> = solutions
            .into_iter()
            .skip(options.offset)
            .take(options.limit)
            .map(|solution| {
                variables
                    .iter()
                    .map(|var: &String| {
                        let value = solution
                            .get(var.as_str())
                            .map(SparqlValue::from_term)
                            .unwrap_or(SparqlValue::Null);
                        (var.clone(), value)
                    })
                    .collect()
            })
            .collect();

        let truncated = total_count > options.offset + options.limit;
        let execution_time_ms = start.elapsed().as_millis() as u64;

        Ok(SelectResult {
            variables,
            rows,
            total_count,
            truncated,
            execution_time_ms,
        })
    }

    /// Executes a SPARQL ASK query and returns the boolean result.
    ///
    /// # Arguments
    ///
    /// * `sparql` - The SPARQL ASK query
    /// * `options` - Query execution options (timeout, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if the query is invalid or execution fails.
    pub fn query_ask(&self, sparql: &str, options: &QueryOptions) -> Result<AskResult> {
        let start = Instant::now();
        let timeout = Duration::from_millis(options.timeout_ms);

        let result = self.graph.ask(sparql)?;

        if start.elapsed() > timeout {
            return Err(anyhow!("Query timed out after {}ms", options.timeout_ms));
        }

        Ok(AskResult {
            result,
            execution_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Executes a parameterized query template.
    ///
    /// # Arguments
    ///
    /// * `template` - The query template
    /// * `params` - Parameter values keyed by parameter name
    /// * `options` - Query execution options
    ///
    /// # Errors
    ///
    /// Returns an error if a required parameter is missing or query execution fails.
    pub fn query_template(
        &self,
        template: &QueryTemplate,
        params: &HashMap<String, String>,
        options: &QueryOptions,
    ) -> Result<SelectResult> {
        // Verify all required parameters are provided
        for param in template.parameters {
            if !params.contains_key(*param) {
                return Err(anyhow!(
                    "Missing required parameter '{}' for template '{}'",
                    param,
                    template.name
                ));
            }
        }

        // Substitute parameters in template
        let mut sparql = template.template.to_string();
        for (key, value) in params {
            // Escape the value for SPARQL (simple escaping for now)
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            sparql = sparql.replace(&format!("${}", key), &escaped);
        }

        self.query_select(&sparql, options)
    }

    /// Formats query results according to the output format.
    ///
    /// # Arguments
    ///
    /// * `result` - The query result to format
    /// * `format` - The output format
    ///
    /// # Errors
    ///
    /// Returns an error if formatting fails.
    pub fn format_result(result: &SelectResult, format: OutputFormat) -> Result<String> {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(result)
                .map_err(|e| anyhow!("JSON serialization failed: {}", e)),
            OutputFormat::Markdown => Ok(Self::format_markdown(result)),
            OutputFormat::Csv => Ok(Self::format_csv(result)),
        }
    }

    fn format_markdown(result: &SelectResult) -> String {
        if result.variables.is_empty() {
            return "No results".to_string();
        }

        let mut output = String::new();

        // Header row
        output.push_str("| ");
        output.push_str(&result.variables.join(" | "));
        output.push_str(" |\n");

        // Separator row
        output.push('|');
        for _ in &result.variables {
            output.push_str("---|");
        }
        output.push('\n');

        // Data rows
        for row in &result.rows {
            output.push_str("| ");
            let values: Vec<String> = result
                .variables
                .iter()
                .map(|var| {
                    row.get(var)
                        .map(|v| v.as_string())
                        .unwrap_or_else(|| "null".to_string())
                })
                .collect();
            output.push_str(&values.join(" | "));
            output.push_str(" |\n");
        }

        // Summary
        output.push_str(&format!(
            "\n*{} results ({}ms)*",
            result.total_count, result.execution_time_ms
        ));
        if result.truncated {
            output.push_str(" *(truncated)*");
        }

        output
    }

    fn format_csv(result: &SelectResult) -> String {
        if result.variables.is_empty() {
            return String::new();
        }

        let mut output = String::new();

        // Header row
        output.push_str(&result.variables.join(","));
        output.push('\n');

        // Data rows
        for row in &result.rows {
            let values: Vec<String> = result
                .variables
                .iter()
                .map(|var| {
                    let value = row
                        .get(var)
                        .map(|v| v.as_string())
                        .unwrap_or_else(|| "".to_string());
                    // CSV escape: wrap in quotes if contains comma, quote, or newline
                    if value.contains(',') || value.contains('"') || value.contains('\n') {
                        format!("\"{}\"", value.replace('"', "\"\""))
                    } else {
                        value
                    }
                })
                .collect();
            output.push_str(&values.join(","));
            output.push('\n');
        }

        output
    }
}

/// Predefined query templates for common code intelligence patterns.
pub mod templates {
    use super::*;

    /// Find all functions in a repository.
    pub const FIND_FUNCTIONS: QueryTemplate = QueryTemplate {
        name: "find_functions",
        description: "Find all functions in a repository",
        template: r#"
            PREFIX narsil: <https://narsilmcp.com/ontology/v1#>
            SELECT ?func ?name ?file ?startLine
            WHERE {
                ?func a narsil:Function ;
                      narsil:name ?name ;
                      narsil:filePath ?file ;
                      narsil:startLine ?startLine .
            }
            ORDER BY ?file ?startLine
        "#,
        parameters: &[],
    };

    /// Find functions by name pattern.
    pub const FIND_FUNCTIONS_BY_NAME: QueryTemplate = QueryTemplate {
        name: "find_functions_by_name",
        description: "Find functions matching a name pattern",
        template: r#"
            PREFIX narsil: <https://narsilmcp.com/ontology/v1#>
            SELECT ?func ?name ?file ?startLine
            WHERE {
                ?func a narsil:Function ;
                      narsil:name ?name ;
                      narsil:filePath ?file ;
                      narsil:startLine ?startLine .
                FILTER(CONTAINS(LCASE(?name), LCASE("$pattern")))
            }
            ORDER BY ?name
        "#,
        parameters: &["pattern"],
    };

    /// Find call relationships for a function.
    pub const FIND_CALLS: QueryTemplate = QueryTemplate {
        name: "find_calls",
        description: "Find what a function calls and what calls it",
        template: r#"
            PREFIX narsil: <https://narsilmcp.com/ontology/v1#>
            SELECT ?direction ?func ?name ?file
            WHERE {
                {
                    ?caller narsil:calls ?callee .
                    ?caller narsil:name "$function" .
                    ?callee narsil:name ?name ;
                            narsil:filePath ?file .
                    BIND("calls" AS ?direction)
                    BIND(?callee AS ?func)
                }
                UNION
                {
                    ?caller narsil:calls ?callee .
                    ?callee narsil:name "$function" .
                    ?caller narsil:name ?name ;
                            narsil:filePath ?file .
                    BIND("called_by" AS ?direction)
                    BIND(?caller AS ?func)
                }
            }
        "#,
        parameters: &["function"],
    };

    /// Find security findings by severity.
    pub const FIND_SECURITY_FINDINGS: QueryTemplate = QueryTemplate {
        name: "find_security_findings",
        description: "Find security findings at or above a severity threshold",
        template: r#"
            PREFIX narsil: <https://narsilmcp.com/ontology/v1#>
            SELECT ?finding ?rule ?severity ?file ?line ?message
            WHERE {
                ?finding a narsil:SecurityFinding ;
                         narsil:rule ?rule ;
                         narsil:severity ?severity ;
                         narsil:filePath ?file ;
                         narsil:line ?line ;
                         narsil:message ?message .
                FILTER(?severity IN ("critical", "high"$severity_filter))
            }
            ORDER BY DESC(?severity) ?file ?line
        "#,
        parameters: &["severity_filter"],
    };

    /// Find symbols in a specific file.
    pub const FIND_SYMBOLS_IN_FILE: QueryTemplate = QueryTemplate {
        name: "find_symbols_in_file",
        description: "Find all symbols defined in a specific file",
        template: r#"
            PREFIX narsil: <https://narsilmcp.com/ontology/v1#>
            SELECT ?symbol ?name ?kind ?startLine ?endLine
            WHERE {
                ?symbol narsil:filePath "$file" ;
                        narsil:name ?name ;
                        narsil:symbolKind ?kind ;
                        narsil:startLine ?startLine ;
                        narsil:endLine ?endLine .
            }
            ORDER BY ?startLine
        "#,
        parameters: &["file"],
    };

    /// Find imports between files.
    pub const FIND_IMPORTS: QueryTemplate = QueryTemplate {
        name: "find_imports",
        description: "Find import relationships for a file",
        template: r#"
            PREFIX narsil: <https://narsilmcp.com/ontology/v1#>
            SELECT ?direction ?file
            WHERE {
                {
                    ?source narsil:imports ?target .
                    ?source narsil:filePath "$file" .
                    ?target narsil:filePath ?file .
                    BIND("imports" AS ?direction)
                }
                UNION
                {
                    ?source narsil:imports ?target .
                    ?target narsil:filePath "$file" .
                    ?source narsil:filePath ?file .
                    BIND("imported_by" AS ?direction)
                }
            }
        "#,
        parameters: &["file"],
    };

    /// Get all available templates.
    #[must_use]
    pub fn all() -> Vec<&'static QueryTemplate> {
        vec![
            &FIND_FUNCTIONS,
            &FIND_FUNCTIONS_BY_NAME,
            &FIND_CALLS,
            &FIND_SECURITY_FINDINGS,
            &FIND_SYMBOLS_IN_FILE,
            &FIND_IMPORTS,
        ]
    }

    /// Get a template by name.
    #[must_use]
    pub fn get(name: &str) -> Option<&'static QueryTemplate> {
        all().into_iter().find(|t| t.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::NARSIL_BASE_IRI;
    use std::str::FromStr;

    fn create_test_graph() -> KnowledgeGraph {
        let graph = KnowledgeGraph::in_memory().unwrap();

        // Add some test data
        graph
            .add_triple(
                "https://narsilmcp.com/code/test/main",
                "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
                &format!("{NARSIL_BASE_IRI}Function"),
            )
            .unwrap();
        graph
            .add_triple_literal(
                "https://narsilmcp.com/code/test/main",
                &format!("{NARSIL_BASE_IRI}name"),
                "main",
            )
            .unwrap();
        graph
            .add_triple_literal(
                "https://narsilmcp.com/code/test/main",
                &format!("{NARSIL_BASE_IRI}filePath"),
                "src/main.rs",
            )
            .unwrap();
        graph
            .add_triple_int(
                "https://narsilmcp.com/code/test/main",
                &format!("{NARSIL_BASE_IRI}startLine"),
                1,
            )
            .unwrap();

        graph
            .add_triple(
                "https://narsilmcp.com/code/test/helper",
                "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
                &format!("{NARSIL_BASE_IRI}Function"),
            )
            .unwrap();
        graph
            .add_triple_literal(
                "https://narsilmcp.com/code/test/helper",
                &format!("{NARSIL_BASE_IRI}name"),
                "helper",
            )
            .unwrap();
        graph
            .add_triple_literal(
                "https://narsilmcp.com/code/test/helper",
                &format!("{NARSIL_BASE_IRI}filePath"),
                "src/lib.rs",
            )
            .unwrap();
        graph
            .add_triple_int(
                "https://narsilmcp.com/code/test/helper",
                &format!("{NARSIL_BASE_IRI}startLine"),
                10,
            )
            .unwrap();

        // Add call relationship
        graph
            .add_triple(
                "https://narsilmcp.com/code/test/main",
                &format!("{NARSIL_BASE_IRI}calls"),
                "https://narsilmcp.com/code/test/helper",
            )
            .unwrap();

        graph
    }

    #[test]
    fn test_select_query_basic() {
        let graph = create_test_graph();
        let engine = SparqlEngine::new(&graph);

        let result = engine
            .query_select(
                "SELECT ?s WHERE { ?s a <https://narsilmcp.com/ontology/v1#Function> }",
                &QueryOptions::default(),
            )
            .unwrap();

        assert_eq!(result.variables.len(), 1);
        assert_eq!(result.variables[0], "s");
        assert_eq!(result.rows.len(), 2);
        assert!(!result.truncated);
    }

    #[test]
    fn test_select_query_with_variables() {
        let graph = create_test_graph();
        let engine = SparqlEngine::new(&graph);

        let result = engine
            .query_select(
                &format!(
                    "SELECT ?name ?file WHERE {{
                        ?s a <{NARSIL_BASE_IRI}Function> ;
                           <{NARSIL_BASE_IRI}name> ?name ;
                           <{NARSIL_BASE_IRI}filePath> ?file .
                    }}"
                ),
                &QueryOptions::default(),
            )
            .unwrap();

        assert_eq!(result.variables.len(), 2);
        assert!(result.variables.contains(&"name".to_string()));
        assert!(result.variables.contains(&"file".to_string()));
        assert_eq!(result.rows.len(), 2);
    }

    #[test]
    fn test_select_query_with_limit() {
        let graph = create_test_graph();
        let engine = SparqlEngine::new(&graph);

        let options = QueryOptions::default().with_limit(1);
        let result = engine
            .query_select(
                "SELECT ?s WHERE { ?s a <https://narsilmcp.com/ontology/v1#Function> }",
                &options,
            )
            .unwrap();

        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.total_count, 2);
        assert!(result.truncated);
    }

    #[test]
    fn test_select_query_with_offset() {
        let graph = create_test_graph();
        let engine = SparqlEngine::new(&graph);

        let options = QueryOptions::default().with_offset(1);
        let result = engine
            .query_select(
                "SELECT ?s WHERE { ?s a <https://narsilmcp.com/ontology/v1#Function> }",
                &options,
            )
            .unwrap();

        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.total_count, 2);
        assert!(!result.truncated);
    }

    #[test]
    fn test_ask_query() {
        let graph = create_test_graph();
        let engine = SparqlEngine::new(&graph);

        let result = engine
            .query_ask(
                &format!(
                    "ASK {{ <https://narsilmcp.com/code/test/main> <{NARSIL_BASE_IRI}calls> ?x }}"
                ),
                &QueryOptions::default(),
            )
            .unwrap();

        assert!(result.result);

        let result2 = engine
            .query_ask(
                &format!(
                    "ASK {{ <https://narsilmcp.com/code/test/helper> <{NARSIL_BASE_IRI}calls> ?x }}"
                ),
                &QueryOptions::default(),
            )
            .unwrap();

        assert!(!result2.result);
    }

    #[test]
    fn test_invalid_query() {
        let graph = create_test_graph();
        let engine = SparqlEngine::new(&graph);

        let result = engine.query_select("INVALID QUERY", &QueryOptions::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_query_options_builder() {
        let options = QueryOptions::default()
            .with_timeout_ms(10_000)
            .with_limit(500)
            .with_offset(10)
            .with_format(OutputFormat::Markdown);

        assert_eq!(options.timeout_ms, 10_000);
        assert_eq!(options.limit, 500);
        assert_eq!(options.offset, 10);
        assert_eq!(options.format, OutputFormat::Markdown);
    }

    #[test]
    fn test_query_options_limits() {
        // Test that values are clamped to max
        let options = QueryOptions::default()
            .with_timeout_ms(1_000_000)
            .with_limit(100_000);

        assert_eq!(options.timeout_ms, MAX_TIMEOUT_MS);
        assert_eq!(options.limit, MAX_RESULT_LIMIT);
    }

    #[test]
    fn test_format_json() {
        let result = SelectResult {
            variables: vec!["name".to_string()],
            rows: vec![{
                let mut row = HashMap::new();
                row.insert("name".to_string(), SparqlValue::Literal("test".to_string()));
                row
            }],
            total_count: 1,
            truncated: false,
            execution_time_ms: 10,
        };

        let output = SparqlEngine::format_result(&result, OutputFormat::Json).unwrap();
        assert!(output.contains("\"name\""));
        assert!(output.contains("\"test\""));
    }

    #[test]
    fn test_format_markdown() {
        let result = SelectResult {
            variables: vec!["name".to_string(), "value".to_string()],
            rows: vec![{
                let mut row = HashMap::new();
                row.insert("name".to_string(), SparqlValue::Literal("test".to_string()));
                row.insert("value".to_string(), SparqlValue::Literal("42".to_string()));
                row
            }],
            total_count: 1,
            truncated: false,
            execution_time_ms: 10,
        };

        let output = SparqlEngine::format_result(&result, OutputFormat::Markdown).unwrap();
        assert!(output.contains("| name | value |"));
        assert!(output.contains("---|"));
        assert!(output.contains("| test | 42 |"));
    }

    #[test]
    fn test_format_csv() {
        let result = SelectResult {
            variables: vec!["name".to_string(), "value".to_string()],
            rows: vec![{
                let mut row = HashMap::new();
                row.insert("name".to_string(), SparqlValue::Literal("test".to_string()));
                row.insert("value".to_string(), SparqlValue::Literal("42".to_string()));
                row
            }],
            total_count: 1,
            truncated: false,
            execution_time_ms: 10,
        };

        let output = SparqlEngine::format_result(&result, OutputFormat::Csv).unwrap();
        assert!(output.contains("name,value"));
        assert!(output.contains("test,42"));
    }

    #[test]
    fn test_sparql_value_from_term_uri() {
        use oxigraph::model::NamedNode;
        let node = NamedNode::new("https://example.com/test").unwrap();
        let term = Term::NamedNode(node);
        let value = SparqlValue::from_term(&term);
        assert_eq!(
            value,
            SparqlValue::Uri("https://example.com/test".to_string())
        );
    }

    #[test]
    fn test_sparql_value_from_term_literal() {
        use oxigraph::model::Literal;
        let literal = Literal::new_simple_literal("hello");
        let term = Term::Literal(literal);
        let value = SparqlValue::from_term(&term);
        assert_eq!(value, SparqlValue::Literal("hello".to_string()));
    }

    #[test]
    fn test_output_format_from_str() {
        assert_eq!(OutputFormat::from_str("json").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str("JSON").unwrap(), OutputFormat::Json);
        assert_eq!(
            OutputFormat::from_str("markdown").unwrap(),
            OutputFormat::Markdown
        );
        assert_eq!(
            OutputFormat::from_str("md").unwrap(),
            OutputFormat::Markdown
        );
        assert_eq!(OutputFormat::from_str("csv").unwrap(), OutputFormat::Csv);
        assert!(OutputFormat::from_str("invalid").is_err());
    }

    #[test]
    fn test_query_templates_list() {
        let templates = templates::all();
        assert!(!templates.is_empty());
        assert!(templates.iter().any(|t| t.name == "find_functions"));
        assert!(templates.iter().any(|t| t.name == "find_calls"));
    }

    #[test]
    fn test_query_template_get() {
        let template = templates::get("find_functions");
        assert!(template.is_some());
        assert_eq!(template.unwrap().name, "find_functions");

        let missing = templates::get("nonexistent");
        assert!(missing.is_none());
    }

    #[test]
    fn test_query_template_missing_param() {
        let graph = create_test_graph();
        let engine = SparqlEngine::new(&graph);

        let template = templates::get("find_functions_by_name").unwrap();
        let params = HashMap::new(); // Missing required 'pattern' param

        let result = engine.query_template(template, &params, &QueryOptions::default());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Missing required parameter"));
    }

    #[test]
    fn test_query_template_with_params() {
        let graph = create_test_graph();
        let engine = SparqlEngine::new(&graph);

        let template = templates::get("find_functions_by_name").unwrap();
        let mut params = HashMap::new();
        params.insert("pattern".to_string(), "main".to_string());

        let result = engine.query_template(template, &params, &QueryOptions::default());
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.rows.len(), 1);
    }
}
