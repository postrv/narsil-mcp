//! RDF transformation module for converting code intelligence data to RDF triples.
//!
//! This module provides functions to transform various code analysis results
//! into RDF triples compatible with the narsil ontology.
//!
//! # Transformations
//!
//! - [`SymbolTransformer`] - Converts [`Symbol`] structs to RDF triples
//! - [`CallGraphTransformer`] - Converts call graph edges to RDF triples
//! - [`SecurityFindingTransformer`] - Converts security findings to RDF triples
//! - [`ImportTransformer`] - Converts import relationships to RDF triples
//!
//! # Example
//!
//! ```ignore
//! use narsil_mcp::persistence::{KnowledgeGraph, transform::SymbolTransformer};
//! use narsil_mcp::symbols::{Symbol, SymbolKind};
//!
//! let graph = KnowledgeGraph::in_memory().unwrap();
//! let symbol = Symbol {
//!     name: "main".to_string(),
//!     kind: SymbolKind::Function,
//!     file_path: "src/main.rs".to_string(),
//!     start_line: 1,
//!     end_line: 10,
//!     signature: Some("fn main()".to_string()),
//!     qualified_name: None,
//!     doc_comment: None,
//! };
//!
//! SymbolTransformer::transform(&graph, "my-repo", &symbol).unwrap();
//! ```

use anyhow::Result;
use oxigraph::model::vocab;

use crate::callgraph::{CallEdge, CallNode};
use crate::persistence::graph::{KnowledgeGraph, CODE_BASE_IRI, NARSIL_BASE_IRI};
use crate::security_rules::SecurityFinding;
use crate::symbols::{Symbol, SymbolKind};
use crate::taint::{Confidence, Severity};

/// Transformer for converting [`Symbol`] structs to RDF triples.
///
/// Symbols are converted to instances of the appropriate narsil ontology class
/// based on their [`SymbolKind`], with all metadata preserved as data properties.
pub struct SymbolTransformer;

impl SymbolTransformer {
    /// Transforms a symbol into RDF triples in the knowledge graph.
    ///
    /// # Arguments
    ///
    /// * `graph` - The knowledge graph to add triples to
    /// * `repo` - Repository name for namespacing
    /// * `symbol` - The symbol to transform
    ///
    /// # Returns
    ///
    /// The IRI of the created symbol node.
    ///
    /// # Errors
    ///
    /// Returns an error if triple insertion fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let symbol = Symbol {
    ///     name: "MyStruct".to_string(),
    ///     kind: SymbolKind::Struct,
    ///     file_path: "src/lib.rs".to_string(),
    ///     start_line: 10,
    ///     end_line: 20,
    ///     signature: None,
    ///     qualified_name: Some("crate::MyStruct".to_string()),
    ///     doc_comment: Some("A struct for testing".to_string()),
    /// };
    /// let iri = SymbolTransformer::transform(&graph, "my-repo", &symbol)?;
    /// ```
    pub fn transform(graph: &KnowledgeGraph, repo: &str, symbol: &Symbol) -> Result<String> {
        // Create a unique IRI for this symbol
        let symbol_path = format!(
            "{}::{}_L{}",
            symbol.file_path, symbol.name, symbol.start_line
        );
        let subject_iri = format!("{CODE_BASE_IRI}{repo}/{}", url_encode(&symbol_path));

        // Determine the RDF class based on symbol kind
        let rdf_class = symbol_kind_to_rdf_class(&symbol.kind);
        let class_iri = format!("{NARSIL_BASE_IRI}{rdf_class}");

        // Add type triple
        graph.add_triple(&subject_iri, vocab::rdf::TYPE.as_str(), &class_iri)?;

        // Add name property
        graph.add_triple_literal(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}name"),
            &symbol.name,
        )?;

        // Add file path
        graph.add_triple_literal(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}filePath"),
            &symbol.file_path,
        )?;

        // Add line numbers
        graph.add_triple_int(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}startLine"),
            symbol.start_line as i64,
        )?;
        graph.add_triple_int(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}endLine"),
            symbol.end_line as i64,
        )?;

        // Add symbol kind as string
        graph.add_triple_literal(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}symbolKind"),
            &format!("{:?}", symbol.kind),
        )?;

        // Add optional signature
        if let Some(ref sig) = symbol.signature {
            graph.add_triple_literal(&subject_iri, &format!("{NARSIL_BASE_IRI}signature"), sig)?;
        }

        // Add optional doc comment
        if let Some(ref doc) = symbol.doc_comment {
            graph.add_triple_literal(&subject_iri, &format!("{NARSIL_BASE_IRI}docComment"), doc)?;
        }

        // Add optional qualified name
        if let Some(ref qname) = symbol.qualified_name {
            graph.add_triple_literal(
                &subject_iri,
                &format!("{NARSIL_BASE_IRI}qualifiedName"),
                qname,
            )?;
        }

        // Link to file node
        let file_iri = format!(
            "{CODE_BASE_IRI}{repo}/file/{}",
            url_encode(&symbol.file_path)
        );
        graph.add_triple(
            &file_iri,
            &format!("{NARSIL_BASE_IRI}definesSymbol"),
            &subject_iri,
        )?;

        Ok(subject_iri)
    }

    /// Transforms multiple symbols into RDF triples.
    ///
    /// # Arguments
    ///
    /// * `graph` - The knowledge graph to add triples to
    /// * `repo` - Repository name for namespacing
    /// * `symbols` - Iterator of symbols to transform
    ///
    /// # Returns
    ///
    /// A vector of IRIs for the created symbol nodes.
    ///
    /// # Errors
    ///
    /// Returns an error if any triple insertion fails.
    pub fn transform_many<'a>(
        graph: &KnowledgeGraph,
        repo: &str,
        symbols: impl Iterator<Item = &'a Symbol>,
    ) -> Result<Vec<String>> {
        symbols.map(|s| Self::transform(graph, repo, s)).collect()
    }
}

/// Transformer for converting call graph data to RDF triples.
///
/// Call graph edges are represented using the `narsil:calls` predicate,
/// connecting function nodes in the RDF graph.
pub struct CallGraphTransformer;

impl CallGraphTransformer {
    /// Transforms a call graph node into RDF triples.
    ///
    /// # Arguments
    ///
    /// * `graph` - The knowledge graph to add triples to
    /// * `repo` - Repository name for namespacing
    /// * `node` - The call node to transform
    ///
    /// # Returns
    ///
    /// The IRI of the created function node.
    ///
    /// # Errors
    ///
    /// Returns an error if triple insertion fails.
    pub fn transform_node(graph: &KnowledgeGraph, repo: &str, node: &CallNode) -> Result<String> {
        let subject_iri = format!(
            "{CODE_BASE_IRI}{repo}/func/{}",
            url_encode(&format!("{}::{}@L{}", node.file_path, node.name, node.line))
        );

        // Add type triple (Function)
        graph.add_triple(
            &subject_iri,
            vocab::rdf::TYPE.as_str(),
            &format!("{NARSIL_BASE_IRI}Function"),
        )?;

        // Add name
        graph.add_triple_literal(&subject_iri, &format!("{NARSIL_BASE_IRI}name"), &node.name)?;

        // Add file path
        graph.add_triple_literal(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}filePath"),
            &node.file_path,
        )?;

        // Add line number
        graph.add_triple_int(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}startLine"),
            node.line as i64,
        )?;

        // Add metrics
        graph.add_triple_int(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}complexity"),
            node.metrics.cyclomatic as i64,
        )?;
        graph.add_triple_int(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}cognitiveComplexity"),
            node.metrics.cognitive as i64,
        )?;

        // Transform outgoing call edges
        for edge in &node.calls {
            Self::transform_edge(graph, repo, &subject_iri, edge)?;
        }

        Ok(subject_iri)
    }

    /// Transforms a call edge into RDF triples.
    ///
    /// # Arguments
    ///
    /// * `graph` - The knowledge graph to add triples to
    /// * `repo` - Repository name for namespacing
    /// * `caller_iri` - IRI of the calling function
    /// * `edge` - The call edge to transform
    ///
    /// # Errors
    ///
    /// Returns an error if triple insertion fails.
    pub fn transform_edge(
        graph: &KnowledgeGraph,
        repo: &str,
        caller_iri: &str,
        edge: &CallEdge,
    ) -> Result<()> {
        // Create target function IRI
        let target_iri = format!(
            "{CODE_BASE_IRI}{repo}/func/{}",
            url_encode(&format!(
                "{}::{}@L{}",
                edge.file_path, edge.target, edge.line
            ))
        );

        // Add calls relationship
        graph.add_triple(caller_iri, &format!("{NARSIL_BASE_IRI}calls"), &target_iri)?;

        // We could add call type as a reified statement, but for simplicity
        // we'll just use the basic relationship for now

        Ok(())
    }
}

/// Transformer for converting security findings to RDF triples.
///
/// Security findings are represented as instances of `narsil:SecurityFinding`
/// with all metadata preserved including severity, CWE IDs, and OWASP categories.
pub struct SecurityFindingTransformer;

impl SecurityFindingTransformer {
    /// Transforms a security finding into RDF triples.
    ///
    /// # Arguments
    ///
    /// * `graph` - The knowledge graph to add triples to
    /// * `repo` - Repository name for namespacing
    /// * `finding` - The security finding to transform
    ///
    /// # Returns
    ///
    /// The IRI of the created finding node.
    ///
    /// # Errors
    ///
    /// Returns an error if triple insertion fails.
    pub fn transform(
        graph: &KnowledgeGraph,
        repo: &str,
        finding: &SecurityFinding,
    ) -> Result<String> {
        // Create a unique IRI for this finding
        let finding_id = format!(
            "{}::{}@L{}C{}",
            finding.file_path, finding.rule_id, finding.line, finding.column
        );
        let subject_iri = format!("{CODE_BASE_IRI}{repo}/finding/{}", url_encode(&finding_id));

        // Add type triple
        graph.add_triple(
            &subject_iri,
            vocab::rdf::TYPE.as_str(),
            &format!("{NARSIL_BASE_IRI}SecurityFinding"),
        )?;

        // Add rule ID
        graph.add_triple_literal(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}ruleId"),
            &finding.rule_id.to_string(),
        )?;

        // Add rule name
        graph.add_triple_literal(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}name"),
            &finding.rule_name,
        )?;

        // Add severity
        graph.add_triple_literal(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}severity"),
            &severity_to_string(&finding.severity),
        )?;

        // Add confidence
        graph.add_triple_literal(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}confidence"),
            &confidence_to_string(&finding.confidence),
        )?;

        // Add file path
        graph.add_triple_literal(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}filePath"),
            &finding.file_path,
        )?;

        // Add line numbers
        graph.add_triple_int(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}startLine"),
            finding.line as i64,
        )?;
        graph.add_triple_int(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}endLine"),
            finding.end_line as i64,
        )?;

        // Add message
        graph.add_triple_literal(
            &subject_iri,
            &format!("{NARSIL_BASE_IRI}message"),
            &finding.message,
        )?;

        // Add CWE IDs
        for cwe in &finding.cwe {
            graph.add_triple_literal(&subject_iri, &format!("{NARSIL_BASE_IRI}cweId"), cwe)?;
        }

        // Add OWASP categories
        for owasp in &finding.owasp {
            graph.add_triple_literal(
                &subject_iri,
                &format!("{NARSIL_BASE_IRI}owaspCategory"),
                owasp,
            )?;
        }

        // Link to file node
        let file_iri = format!(
            "{CODE_BASE_IRI}{repo}/file/{}",
            url_encode(&finding.file_path)
        );
        graph.add_triple(
            &file_iri,
            &format!("{NARSIL_BASE_IRI}hasFinding"),
            &subject_iri,
        )?;

        Ok(subject_iri)
    }

    /// Transforms multiple security findings into RDF triples.
    ///
    /// # Arguments
    ///
    /// * `graph` - The knowledge graph to add triples to
    /// * `repo` - Repository name for namespacing
    /// * `findings` - Iterator of findings to transform
    ///
    /// # Returns
    ///
    /// A vector of IRIs for the created finding nodes.
    ///
    /// # Errors
    ///
    /// Returns an error if any triple insertion fails.
    pub fn transform_many<'a>(
        graph: &KnowledgeGraph,
        repo: &str,
        findings: impl Iterator<Item = &'a SecurityFinding>,
    ) -> Result<Vec<String>> {
        findings.map(|f| Self::transform(graph, repo, f)).collect()
    }
}

/// Transformer for converting import relationships to RDF triples.
///
/// Import relationships are represented using the `narsil:imports` predicate,
/// connecting file/module nodes in the RDF graph.
pub struct ImportTransformer;

impl ImportTransformer {
    /// Transforms an import relationship into RDF triples.
    ///
    /// # Arguments
    ///
    /// * `graph` - The knowledge graph to add triples to
    /// * `repo` - Repository name for namespacing
    /// * `source_file` - The file containing the import
    /// * `target_module` - The imported module/file path
    /// * `line` - Line number of the import statement
    ///
    /// # Errors
    ///
    /// Returns an error if triple insertion fails.
    pub fn transform(
        graph: &KnowledgeGraph,
        repo: &str,
        source_file: &str,
        target_module: &str,
        _line: usize,
    ) -> Result<()> {
        let source_iri = format!("{CODE_BASE_IRI}{repo}/file/{}", url_encode(source_file));
        let target_iri = format!("{CODE_BASE_IRI}{repo}/module/{}", url_encode(target_module));

        // Add imports relationship
        graph.add_triple(
            &source_iri,
            &format!("{NARSIL_BASE_IRI}imports"),
            &target_iri,
        )?;

        // Mark source as a File
        graph.add_triple(
            &source_iri,
            vocab::rdf::TYPE.as_str(),
            &format!("{NARSIL_BASE_IRI}File"),
        )?;

        // Mark target as a Module
        graph.add_triple(
            &target_iri,
            vocab::rdf::TYPE.as_str(),
            &format!("{NARSIL_BASE_IRI}Module"),
        )?;

        Ok(())
    }

    /// Transforms an import graph (edges) into RDF triples.
    ///
    /// # Arguments
    ///
    /// * `graph` - The knowledge graph to add triples to
    /// * `repo` - Repository name for namespacing
    /// * `edges` - Iterator of (source_file, target_module) tuples
    ///
    /// # Errors
    ///
    /// Returns an error if any triple insertion fails.
    pub fn transform_edges<'a>(
        graph: &KnowledgeGraph,
        repo: &str,
        edges: impl Iterator<Item = (&'a str, &'a str)>,
    ) -> Result<()> {
        for (source, target) in edges {
            Self::transform(graph, repo, source, target, 0)?;
        }
        Ok(())
    }
}

/// Transformer for converting repository metadata to RDF triples.
pub struct RepositoryTransformer;

impl RepositoryTransformer {
    /// Transforms repository metadata into RDF triples.
    ///
    /// # Arguments
    ///
    /// * `graph` - The knowledge graph to add triples to
    /// * `repo` - Repository name
    /// * `files` - Iterator of file paths in the repository
    ///
    /// # Returns
    ///
    /// The IRI of the created repository node.
    ///
    /// # Errors
    ///
    /// Returns an error if triple insertion fails.
    pub fn transform<'a>(
        graph: &KnowledgeGraph,
        repo: &str,
        files: impl Iterator<Item = &'a str>,
    ) -> Result<String> {
        let repo_iri = format!("{CODE_BASE_IRI}{repo}");

        // Add type triple
        graph.add_triple(
            &repo_iri,
            vocab::rdf::TYPE.as_str(),
            &format!("{NARSIL_BASE_IRI}Repository"),
        )?;

        // Add name
        graph.add_triple_literal(&repo_iri, &format!("{NARSIL_BASE_IRI}name"), repo)?;

        // Add containsFile relationships
        for file in files {
            let file_iri = format!("{CODE_BASE_IRI}{repo}/file/{}", url_encode(file));

            // Mark as File type
            graph.add_triple(
                &file_iri,
                vocab::rdf::TYPE.as_str(),
                &format!("{NARSIL_BASE_IRI}File"),
            )?;

            // Add file path
            graph.add_triple_literal(&file_iri, &format!("{NARSIL_BASE_IRI}filePath"), file)?;

            // Add containsFile relationship
            graph.add_triple(
                &repo_iri,
                &format!("{NARSIL_BASE_IRI}containsFile"),
                &file_iri,
            )?;
        }

        Ok(repo_iri)
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Converts a [`SymbolKind`] to the corresponding RDF class name.
fn symbol_kind_to_rdf_class(kind: &SymbolKind) -> &'static str {
    match kind {
        SymbolKind::Function => "Function",
        SymbolKind::Method => "Method",
        SymbolKind::Constructor => "Method",
        SymbolKind::Class => "Class",
        SymbolKind::Struct => "Struct",
        SymbolKind::Enum => "Enum",
        SymbolKind::Interface => "Trait",
        SymbolKind::Trait => "Trait",
        SymbolKind::Module => "Module",
        SymbolKind::Namespace => "Module",
        SymbolKind::Package => "Module",
        SymbolKind::Constant => "Constant",
        SymbolKind::Variable => "Variable",
        SymbolKind::Field => "Variable",
        SymbolKind::Parameter => "Variable",
        SymbolKind::TypeAlias => "Symbol",
        SymbolKind::Implementation => "Symbol",
        SymbolKind::Macro => "Symbol",
        SymbolKind::Unknown => "Symbol",
    }
}

/// Converts a [`Severity`] to its string representation.
fn severity_to_string(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "CRITICAL".to_string(),
        Severity::High => "HIGH".to_string(),
        Severity::Medium => "MEDIUM".to_string(),
        Severity::Low => "LOW".to_string(),
        Severity::Info => "INFO".to_string(),
    }
}

/// Converts a [`Confidence`] to its string representation.
fn confidence_to_string(confidence: &Confidence) -> String {
    match confidence {
        Confidence::High => "HIGH".to_string(),
        Confidence::Medium => "MEDIUM".to_string(),
        Confidence::Low => "LOW".to_string(),
    }
}

/// URL-encodes a path for use in IRIs.
fn url_encode(path: &str) -> String {
    path.replace('/', "%2F")
        .replace(':', "%3A")
        .replace('#', "%23")
        .replace(' ', "%20")
        .replace('@', "%40")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callgraph::{CallType, FunctionMetrics};
    use std::collections::HashMap;

    // ========================================================================
    // Symbol Transformation Tests
    // ========================================================================

    #[test]
    fn test_symbol_to_rdf_function() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let symbol = Symbol {
            name: "main".to_string(),
            kind: SymbolKind::Function,
            file_path: "src/main.rs".to_string(),
            start_line: 1,
            end_line: 10,
            signature: Some("fn main() -> Result<()>".to_string()),
            qualified_name: Some("crate::main".to_string()),
            doc_comment: Some("Entry point".to_string()),
        };

        let iri = SymbolTransformer::transform(&graph, "test-repo", &symbol).unwrap();

        // Verify the IRI format
        assert!(iri.starts_with(CODE_BASE_IRI));
        assert!(iri.contains("test-repo"));

        // Verify the symbol was created with correct type
        let has_function_type = graph
            .ask(&format!("ASK {{ <{iri}> a <{NARSIL_BASE_IRI}Function> }}"))
            .unwrap();
        assert!(has_function_type);

        // Verify name property
        let results = graph
            .query(&format!(
                "SELECT ?name WHERE {{ <{iri}> <{NARSIL_BASE_IRI}name> ?name }}"
            ))
            .unwrap();
        assert_eq!(results.len(), 1);

        // Verify signature property
        let has_signature = graph
            .ask(&format!(
                "ASK {{ <{iri}> <{NARSIL_BASE_IRI}signature> ?sig }}"
            ))
            .unwrap();
        assert!(has_signature);
    }

    #[test]
    fn test_symbol_to_rdf_struct() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let symbol = Symbol {
            name: "MyStruct".to_string(),
            kind: SymbolKind::Struct,
            file_path: "src/lib.rs".to_string(),
            start_line: 10,
            end_line: 20,
            signature: None,
            qualified_name: None,
            doc_comment: None,
        };

        let iri = SymbolTransformer::transform(&graph, "test-repo", &symbol).unwrap();

        // Verify it's typed as Struct
        let has_struct_type = graph
            .ask(&format!("ASK {{ <{iri}> a <{NARSIL_BASE_IRI}Struct> }}"))
            .unwrap();
        assert!(has_struct_type);
    }

    #[test]
    fn test_symbol_to_rdf_class() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let symbol = Symbol {
            name: "MyClass".to_string(),
            kind: SymbolKind::Class,
            file_path: "src/lib.py".to_string(),
            start_line: 5,
            end_line: 50,
            signature: None,
            qualified_name: None,
            doc_comment: Some("A test class".to_string()),
        };

        let iri = SymbolTransformer::transform(&graph, "test-repo", &symbol).unwrap();

        // Verify it's typed as Class
        let has_class_type = graph
            .ask(&format!("ASK {{ <{iri}> a <{NARSIL_BASE_IRI}Class> }}"))
            .unwrap();
        assert!(has_class_type);
    }

    #[test]
    fn test_symbol_to_rdf_links_to_file() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let symbol = Symbol {
            name: "test_func".to_string(),
            kind: SymbolKind::Function,
            file_path: "src/test.rs".to_string(),
            start_line: 1,
            end_line: 5,
            signature: None,
            qualified_name: None,
            doc_comment: None,
        };

        let symbol_iri = SymbolTransformer::transform(&graph, "test-repo", &symbol).unwrap();

        // Verify file -> symbol link exists
        let has_defines_symbol = graph
            .ask(&format!(
                "ASK {{ ?file <{NARSIL_BASE_IRI}definesSymbol> <{symbol_iri}> }}"
            ))
            .unwrap();
        assert!(has_defines_symbol);
    }

    #[test]
    fn test_transform_many_symbols() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let symbols = [
            Symbol {
                name: "func1".to_string(),
                kind: SymbolKind::Function,
                file_path: "src/lib.rs".to_string(),
                start_line: 1,
                end_line: 5,
                signature: None,
                qualified_name: None,
                doc_comment: None,
            },
            Symbol {
                name: "func2".to_string(),
                kind: SymbolKind::Function,
                file_path: "src/lib.rs".to_string(),
                start_line: 10,
                end_line: 15,
                signature: None,
                qualified_name: None,
                doc_comment: None,
            },
        ];

        let iris = SymbolTransformer::transform_many(&graph, "test-repo", symbols.iter()).unwrap();
        assert_eq!(iris.len(), 2);

        // Verify both are in the graph
        let count_result = graph
            .query(&format!(
                "SELECT ?s WHERE {{ ?s a <{NARSIL_BASE_IRI}Function> }}"
            ))
            .unwrap();
        assert_eq!(count_result.len(), 2);
    }

    // ========================================================================
    // Call Graph Transformation Tests
    // ========================================================================

    #[test]
    fn test_call_node_to_rdf() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let node = CallNode {
            name: "process".to_string(),
            file_path: "src/lib.rs".to_string(),
            line: 10,
            calls: vec![],
            called_by: vec![],
            metrics: FunctionMetrics {
                loc: 20,
                cyclomatic: 5,
                max_depth: 3,
                params: 2,
                returns: 1,
                cognitive: 8,
            },
        };

        let iri = CallGraphTransformer::transform_node(&graph, "test-repo", &node).unwrap();

        // Verify it's typed as Function
        let has_function_type = graph
            .ask(&format!("ASK {{ <{iri}> a <{NARSIL_BASE_IRI}Function> }}"))
            .unwrap();
        assert!(has_function_type);

        // Verify complexity metrics are stored
        let results = graph
            .query(&format!(
                "SELECT ?c WHERE {{ <{iri}> <{NARSIL_BASE_IRI}complexity> ?c }}"
            ))
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_call_edge_to_rdf() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        // Create a node with outgoing call
        let node = CallNode {
            name: "caller".to_string(),
            file_path: "src/lib.rs".to_string(),
            line: 10,
            calls: vec![CallEdge {
                target: "callee".to_string(),
                file_path: "src/lib.rs".to_string(),
                line: 15,
                column: 5,
                call_type: CallType::Direct,
                scope_hint: None,
            }],
            called_by: vec![],
            metrics: FunctionMetrics::default(),
        };

        let caller_iri = CallGraphTransformer::transform_node(&graph, "test-repo", &node).unwrap();

        // Verify calls relationship exists
        let has_call = graph
            .ask(&format!(
                "ASK {{ <{caller_iri}> <{NARSIL_BASE_IRI}calls> ?target }}"
            ))
            .unwrap();
        assert!(has_call);
    }

    #[test]
    fn test_transitive_calls_query() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        // Create a -> b -> c call chain
        let node_a = CallNode {
            name: "a".to_string(),
            file_path: "src/lib.rs".to_string(),
            line: 1,
            calls: vec![CallEdge {
                target: "b".to_string(),
                file_path: "src/lib.rs".to_string(),
                line: 10,
                column: 5,
                call_type: CallType::Direct,
                scope_hint: None,
            }],
            called_by: vec![],
            metrics: FunctionMetrics::default(),
        };

        let node_b = CallNode {
            name: "b".to_string(),
            file_path: "src/lib.rs".to_string(),
            line: 10,
            calls: vec![CallEdge {
                target: "c".to_string(),
                file_path: "src/lib.rs".to_string(),
                line: 20,
                column: 5,
                call_type: CallType::Direct,
                scope_hint: None,
            }],
            called_by: vec![],
            metrics: FunctionMetrics::default(),
        };

        let node_c = CallNode {
            name: "c".to_string(),
            file_path: "src/lib.rs".to_string(),
            line: 20,
            calls: vec![],
            called_by: vec![],
            metrics: FunctionMetrics::default(),
        };

        CallGraphTransformer::transform_node(&graph, "test-repo", &node_a).unwrap();
        CallGraphTransformer::transform_node(&graph, "test-repo", &node_b).unwrap();
        CallGraphTransformer::transform_node(&graph, "test-repo", &node_c).unwrap();

        // Query for transitive calls from 'a'
        // Note: This uses SPARQL property path (+)
        let results = graph
            .query(&format!(
                r#"
                SELECT ?target WHERE {{
                    ?a <{NARSIL_BASE_IRI}name> "a" .
                    ?a <{NARSIL_BASE_IRI}calls>+ ?target
                }}
            "#
            ))
            .unwrap();

        // Should find both 'b' and 'c' (transitive)
        assert_eq!(results.len(), 2);
    }

    // ========================================================================
    // Security Finding Transformation Tests
    // ========================================================================

    #[test]
    fn test_security_finding_to_rdf() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let finding = SecurityFinding {
            rule_id: "SQL-INJECT-001".into(),
            rule_name: "SQL Injection".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            file_path: "src/db.rs".to_string(),
            line: 42,
            column: 10,
            end_line: 42,
            end_column: 50,
            snippet: "query(&format!(\"SELECT * FROM users WHERE id = {}\", id))".to_string(),
            message: "Potential SQL injection vulnerability".to_string(),
            remediation: "Use parameterized queries".to_string(),
            cwe: vec!["CWE-89".to_string()],
            owasp: vec!["A03:2021".to_string()],
            context: HashMap::new(),
        };

        let iri = SecurityFindingTransformer::transform(&graph, "test-repo", &finding).unwrap();

        // Verify it's typed as SecurityFinding
        let has_finding_type = graph
            .ask(&format!(
                "ASK {{ <{iri}> a <{NARSIL_BASE_IRI}SecurityFinding> }}"
            ))
            .unwrap();
        assert!(has_finding_type);

        // Verify severity
        let results = graph
            .query(&format!(
                "SELECT ?sev WHERE {{ <{iri}> <{NARSIL_BASE_IRI}severity> ?sev }}"
            ))
            .unwrap();
        assert_eq!(results.len(), 1);

        // Verify CWE ID
        let has_cwe = graph
            .ask(&format!(
                "ASK {{ <{iri}> <{NARSIL_BASE_IRI}cweId> \"CWE-89\" }}"
            ))
            .unwrap();
        assert!(has_cwe);

        // Verify OWASP category
        let has_owasp = graph
            .ask(&format!(
                "ASK {{ <{iri}> <{NARSIL_BASE_IRI}owaspCategory> \"A03:2021\" }}"
            ))
            .unwrap();
        assert!(has_owasp);
    }

    #[test]
    fn test_security_finding_links_to_file() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let finding = SecurityFinding {
            rule_id: "XSS-001".into(),
            rule_name: "Cross-Site Scripting".to_string(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            file_path: "src/web.rs".to_string(),
            line: 100,
            column: 5,
            end_line: 100,
            end_column: 40,
            snippet: "innerHTML = user_input".to_string(),
            message: "Potential XSS vulnerability".to_string(),
            remediation: "Sanitize user input".to_string(),
            cwe: vec!["CWE-79".to_string()],
            owasp: vec!["A03:2021".to_string()],
            context: HashMap::new(),
        };

        let finding_iri =
            SecurityFindingTransformer::transform(&graph, "test-repo", &finding).unwrap();

        // Verify file -> finding link exists
        let has_finding_link = graph
            .ask(&format!(
                "ASK {{ ?file <{NARSIL_BASE_IRI}hasFinding> <{finding_iri}> }}"
            ))
            .unwrap();
        assert!(has_finding_link);
    }

    #[test]
    fn test_transform_many_findings() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let findings = [
            SecurityFinding {
                rule_id: "RULE-1".into(),
                rule_name: "Rule 1".to_string(),
                severity: Severity::Low,
                confidence: Confidence::Low,
                file_path: "src/a.rs".to_string(),
                line: 1,
                column: 1,
                end_line: 1,
                end_column: 10,
                snippet: "code".to_string(),
                message: "msg".to_string(),
                remediation: "fix".to_string(),
                cwe: vec![],
                owasp: vec![],
                context: HashMap::new(),
            },
            SecurityFinding {
                rule_id: "RULE-2".into(),
                rule_name: "Rule 2".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                file_path: "src/b.rs".to_string(),
                line: 5,
                column: 1,
                end_line: 5,
                end_column: 20,
                snippet: "code2".to_string(),
                message: "msg2".to_string(),
                remediation: "fix2".to_string(),
                cwe: vec![],
                owasp: vec![],
                context: HashMap::new(),
            },
        ];

        let iris = SecurityFindingTransformer::transform_many(&graph, "test-repo", findings.iter())
            .unwrap();
        assert_eq!(iris.len(), 2);
    }

    // ========================================================================
    // Import Transformation Tests
    // ========================================================================

    #[test]
    fn test_import_to_rdf() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        ImportTransformer::transform(
            &graph,
            "test-repo",
            "src/main.rs",
            "std::collections::HashMap",
            1,
        )
        .unwrap();

        // Verify imports relationship exists
        let has_import = graph
            .ask(&format!(
                "ASK {{ ?source <{NARSIL_BASE_IRI}imports> ?target }}"
            ))
            .unwrap();
        assert!(has_import);

        // Verify source is a File
        let source_is_file = graph
            .ask(&format!(
                "ASK {{ ?s <{NARSIL_BASE_IRI}imports> ?t . ?s a <{NARSIL_BASE_IRI}File> }}"
            ))
            .unwrap();
        assert!(source_is_file);

        // Verify target is a Module
        let target_is_module = graph
            .ask(&format!(
                "ASK {{ ?s <{NARSIL_BASE_IRI}imports> ?t . ?t a <{NARSIL_BASE_IRI}Module> }}"
            ))
            .unwrap();
        assert!(target_is_module);
    }

    #[test]
    fn test_transform_import_edges() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let edges = [
            ("src/main.rs", "std::io"),
            ("src/main.rs", "std::fs"),
            ("src/lib.rs", "crate::utils"),
        ];

        ImportTransformer::transform_edges(
            &graph,
            "test-repo",
            edges.iter().map(|(s, t)| (*s, *t)),
        )
        .unwrap();

        // Verify all imports exist
        let results = graph
            .query(&format!(
                "SELECT ?s ?t WHERE {{ ?s <{NARSIL_BASE_IRI}imports> ?t }}"
            ))
            .unwrap();
        assert_eq!(results.len(), 3);
    }

    // ========================================================================
    // Repository Transformation Tests
    // ========================================================================

    #[test]
    fn test_repository_to_rdf() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let files = ["src/main.rs", "src/lib.rs", "src/utils.rs"];
        let repo_iri =
            RepositoryTransformer::transform(&graph, "my-project", files.iter().copied()).unwrap();

        // Verify it's typed as Repository
        let has_repo_type = graph
            .ask(&format!(
                "ASK {{ <{repo_iri}> a <{NARSIL_BASE_IRI}Repository> }}"
            ))
            .unwrap();
        assert!(has_repo_type);

        // Verify containsFile relationships
        let results = graph
            .query(&format!(
                "SELECT ?f WHERE {{ <{repo_iri}> <{NARSIL_BASE_IRI}containsFile> ?f }}"
            ))
            .unwrap();
        assert_eq!(results.len(), 3);
    }

    // ========================================================================
    // Round-trip Serialization Tests
    // ========================================================================

    #[test]
    fn test_symbol_round_trip_turtle() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let symbol = Symbol {
            name: "roundtrip_func".to_string(),
            kind: SymbolKind::Function,
            file_path: "src/test.rs".to_string(),
            start_line: 1,
            end_line: 10,
            signature: Some("fn roundtrip_func()".to_string()),
            qualified_name: None,
            doc_comment: None,
        };

        SymbolTransformer::transform(&graph, "test-repo", &symbol).unwrap();

        // Export to Turtle
        let turtle = graph.export_turtle().unwrap();
        assert!(!turtle.is_empty());
        assert!(turtle.contains("roundtrip_func"));

        // Import into new graph
        let graph2 = KnowledgeGraph::in_memory().unwrap();
        graph2.import_turtle(&turtle).unwrap();

        // Verify data was preserved
        let has_function = graph2
            .ask(&format!(
                "ASK {{ ?s <{NARSIL_BASE_IRI}name> \"roundtrip_func\" }}"
            ))
            .unwrap();
        assert!(has_function);
    }

    #[test]
    fn test_finding_round_trip_nquads() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let finding = SecurityFinding {
            rule_id: "ROUND-TRIP-001".into(),
            rule_name: "Round Trip Test".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            file_path: "src/test.rs".to_string(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 10,
            snippet: "test".to_string(),
            message: "Round trip test message".to_string(),
            remediation: "None needed".to_string(),
            cwe: vec!["CWE-TEST".to_string()],
            owasp: vec![],
            context: HashMap::new(),
        };

        SecurityFindingTransformer::transform(&graph, "test-repo", &finding).unwrap();

        // Export to N-Quads
        let nquads = graph.export_nquads().unwrap();
        assert!(!nquads.is_empty());
        assert!(nquads.contains("ROUND-TRIP-001"));

        // Verify the format
        assert!(nquads.contains("<https://narsilmcp.com/"));
    }

    // ========================================================================
    // Helper Function Tests
    // ========================================================================

    #[test]
    fn test_symbol_kind_to_rdf_class() {
        assert_eq!(symbol_kind_to_rdf_class(&SymbolKind::Function), "Function");
        assert_eq!(symbol_kind_to_rdf_class(&SymbolKind::Method), "Method");
        assert_eq!(symbol_kind_to_rdf_class(&SymbolKind::Class), "Class");
        assert_eq!(symbol_kind_to_rdf_class(&SymbolKind::Struct), "Struct");
        assert_eq!(symbol_kind_to_rdf_class(&SymbolKind::Trait), "Trait");
        assert_eq!(symbol_kind_to_rdf_class(&SymbolKind::Module), "Module");
        assert_eq!(symbol_kind_to_rdf_class(&SymbolKind::Enum), "Enum");
        assert_eq!(symbol_kind_to_rdf_class(&SymbolKind::Constant), "Constant");
        assert_eq!(symbol_kind_to_rdf_class(&SymbolKind::Variable), "Variable");
    }

    #[test]
    fn test_severity_to_string() {
        assert_eq!(severity_to_string(&Severity::Critical), "CRITICAL");
        assert_eq!(severity_to_string(&Severity::High), "HIGH");
        assert_eq!(severity_to_string(&Severity::Medium), "MEDIUM");
        assert_eq!(severity_to_string(&Severity::Low), "LOW");
        assert_eq!(severity_to_string(&Severity::Info), "INFO");
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("src/main.rs"), "src%2Fmain.rs");
        assert_eq!(url_encode("mod::func"), "mod%3A%3Afunc");
        assert_eq!(url_encode("a#b"), "a%23b");
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("a@b"), "a%40b");
    }
}
