//! Knowledge graph implementation using Oxigraph.
//!
//! Provides persistent RDF triple storage with SPARQL query support.

use anyhow::{anyhow, Result};
use oxigraph::io::{RdfFormat, RdfParser, RdfSerializer};
use oxigraph::model::{vocab, GraphName, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
use oxigraph::sparql::{QueryResults, QuerySolution, SparqlEvaluator};
use oxigraph::store::Store;
use std::io::{BufReader, Cursor};
use std::path::Path;

use crate::persistence::ontology::NARSIL_ONTOLOGY;

/// Base IRI for the narsil ontology.
pub const NARSIL_BASE_IRI: &str = "https://narsilmcp.com/ontology/v1#";

/// Base IRI for code entities.
pub const CODE_BASE_IRI: &str = "https://narsilmcp.com/code/";

/// Knowledge graph backed by Oxigraph for storing code intelligence data.
///
/// The `KnowledgeGraph` provides a high-level API for:
/// - Adding and querying RDF triples
/// - Named graph support per repository
/// - SPARQL 1.1 query execution
/// - Import/export in various RDF formats
///
/// # Storage
///
/// Data is stored using RocksDB for persistence. Pass a path to `open()` to
/// specify the storage location. Use `in_memory()` for ephemeral storage.
///
/// # Named Graphs
///
/// Each repository is stored in its own named graph, enabling:
/// - Isolation between repositories
/// - Per-repository queries
/// - Efficient repository-level operations
///
/// # Example
///
/// ```ignore
/// use narsil_mcp::persistence::KnowledgeGraph;
/// use std::path::Path;
///
/// let graph = KnowledgeGraph::open(Path::new("/tmp/graph")).unwrap();
/// graph.add_triple(
///     "https://narsilmcp.com/code/repo/func",
///     "https://narsilmcp.com/ontology/v1#calls",
///     "https://narsilmcp.com/code/repo/other",
/// ).unwrap();
///
/// let results = graph.query("SELECT ?o WHERE { ?s <https://narsilmcp.com/ontology/v1#calls> ?o }").unwrap();
/// ```
pub struct KnowledgeGraph {
    store: Store,
}

impl std::fmt::Debug for KnowledgeGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnowledgeGraph")
            .field("len", &self.len())
            .finish()
    }
}

impl KnowledgeGraph {
    /// Opens or creates a persistent knowledge graph at the given path.
    ///
    /// # Arguments
    ///
    /// * `path` - Directory path for RocksDB storage
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be opened (e.g., permission denied,
    /// corrupted database).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let graph = KnowledgeGraph::open(Path::new("/tmp/narsil-graph")).unwrap();
    /// ```
    pub fn open(path: &Path) -> Result<Self> {
        let store = Store::open(path).map_err(|e| anyhow!("Failed to open store: {e}"))?;
        Ok(Self { store })
    }

    /// Creates an in-memory knowledge graph (non-persistent).
    ///
    /// Useful for testing or temporary analysis sessions.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let graph = KnowledgeGraph::in_memory().unwrap();
    /// // Data will be lost when graph is dropped
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be created.
    pub fn in_memory() -> Result<Self> {
        let store = Store::new().map_err(|e| anyhow!("Failed to create in-memory store: {e}"))?;
        Ok(Self { store })
    }

    /// Loads the narsil ontology into the graph.
    ///
    /// This adds the core vocabulary definitions (classes, properties) for
    /// code intelligence entities. Should be called once when setting up a
    /// new graph.
    ///
    /// # Errors
    ///
    /// Returns an error if the ontology cannot be parsed or loaded.
    pub fn load_ontology(&self) -> Result<()> {
        let parser = RdfParser::from_format(RdfFormat::Turtle)
            .with_base_iri(NARSIL_BASE_IRI)
            .map_err(|e| anyhow!("Invalid base IRI: {e}"))?;

        let reader = BufReader::new(Cursor::new(NARSIL_ONTOLOGY));
        let quads = parser.for_reader(reader);

        for quad_result in quads {
            let quad = quad_result.map_err(|e| anyhow!("Failed to parse ontology: {e}"))?;
            self.store
                .insert(&quad)
                .map_err(|e| anyhow!("Failed to insert quad: {e}"))?;
        }

        Ok(())
    }

    /// Creates a named node for a narsil ontology term.
    ///
    /// # Arguments
    ///
    /// * `local_name` - The local part of the IRI (e.g., "Function", "calls")
    ///
    /// # Panics
    ///
    /// Panics if the resulting IRI is invalid (should never happen with valid input).
    #[must_use]
    pub fn narsil_node(local_name: &str) -> NamedNode {
        NamedNode::new(format!("{NARSIL_BASE_IRI}{local_name}"))
            .expect("narsil IRI should be valid")
    }

    /// Creates a named node for a code entity.
    ///
    /// # Arguments
    ///
    /// * `repo` - Repository name
    /// * `path` - Path to the symbol (e.g., "src/main.rs::main")
    ///
    /// # Panics
    ///
    /// Panics if the resulting IRI is invalid.
    #[must_use]
    pub fn code_node(repo: &str, path: &str) -> NamedNode {
        // URL-encode the path to handle special characters
        let encoded_path = path
            .replace('/', "%2F")
            .replace(':', "%3A")
            .replace('#', "%23");
        NamedNode::new(format!("{CODE_BASE_IRI}{repo}/{encoded_path}"))
            .expect("code IRI should be valid")
    }

    /// Creates a graph name for a repository.
    ///
    /// Each repository gets its own named graph for isolation.
    ///
    /// # Arguments
    ///
    /// * `repo_name` - Name of the repository
    ///
    /// # Panics
    ///
    /// Panics if the resulting IRI is invalid.
    #[must_use]
    pub fn repo_graph(repo_name: &str) -> GraphName {
        GraphName::NamedNode(
            NamedNode::new(format!("{CODE_BASE_IRI}{repo_name}"))
                .expect("repo graph IRI should be valid"),
        )
    }

    /// Adds a triple to the default graph.
    ///
    /// # Arguments
    ///
    /// * `subject` - Subject IRI as string
    /// * `predicate` - Predicate IRI as string
    /// * `object` - Object IRI as string
    ///
    /// # Errors
    ///
    /// Returns an error if any IRI is invalid or insertion fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// graph.add_triple(
    ///     "https://narsilmcp.com/code/repo/main",
    ///     "https://narsilmcp.com/ontology/v1#calls",
    ///     "https://narsilmcp.com/code/repo/helper",
    /// ).unwrap();
    /// ```
    pub fn add_triple(&self, subject: &str, predicate: &str, object: &str) -> Result<()> {
        let subject =
            NamedNode::new(subject).map_err(|e| anyhow!("Invalid subject IRI '{subject}': {e}"))?;
        let predicate = NamedNode::new(predicate)
            .map_err(|e| anyhow!("Invalid predicate IRI '{predicate}': {e}"))?;
        let object =
            NamedNode::new(object).map_err(|e| anyhow!("Invalid object IRI '{object}': {e}"))?;

        let quad = Quad::new(subject, predicate, object, GraphName::DefaultGraph);
        self.store
            .insert(&quad)
            .map_err(|e| anyhow!("Failed to insert quad: {e}"))?;

        Ok(())
    }

    /// Adds a triple with a literal object value to the default graph.
    ///
    /// # Arguments
    ///
    /// * `subject` - Subject IRI as string
    /// * `predicate` - Predicate IRI as string
    /// * `value` - Literal value as string
    ///
    /// # Errors
    ///
    /// Returns an error if any IRI is invalid or insertion fails.
    pub fn add_triple_literal(&self, subject: &str, predicate: &str, value: &str) -> Result<()> {
        let subject =
            NamedNode::new(subject).map_err(|e| anyhow!("Invalid subject IRI '{subject}': {e}"))?;
        let predicate = NamedNode::new(predicate)
            .map_err(|e| anyhow!("Invalid predicate IRI '{predicate}': {e}"))?;
        let literal = Literal::new_simple_literal(value);

        let quad = Quad::new(subject, predicate, literal, GraphName::DefaultGraph);
        self.store
            .insert(&quad)
            .map_err(|e| anyhow!("Failed to insert quad: {e}"))?;

        Ok(())
    }

    /// Adds a triple with an integer literal object value.
    ///
    /// # Arguments
    ///
    /// * `subject` - Subject IRI as string
    /// * `predicate` - Predicate IRI as string
    /// * `value` - Integer value
    ///
    /// # Errors
    ///
    /// Returns an error if any IRI is invalid or insertion fails.
    pub fn add_triple_int(&self, subject: &str, predicate: &str, value: i64) -> Result<()> {
        let subject =
            NamedNode::new(subject).map_err(|e| anyhow!("Invalid subject IRI '{subject}': {e}"))?;
        let predicate = NamedNode::new(predicate)
            .map_err(|e| anyhow!("Invalid predicate IRI '{predicate}': {e}"))?;
        let literal = Literal::new_typed_literal(value.to_string(), vocab::xsd::INTEGER);

        let quad = Quad::new(subject, predicate, literal, GraphName::DefaultGraph);
        self.store
            .insert(&quad)
            .map_err(|e| anyhow!("Failed to insert quad: {e}"))?;

        Ok(())
    }

    /// Adds a quad (triple in a named graph).
    ///
    /// # Arguments
    ///
    /// * `subject` - Subject node
    /// * `predicate` - Predicate node
    /// * `object` - Object term (node or literal)
    /// * `graph` - Named graph
    ///
    /// # Errors
    ///
    /// Returns an error if insertion fails.
    pub fn add_quad(
        &self,
        subject: impl Into<NamedOrBlankNode>,
        predicate: NamedNode,
        object: impl Into<Term>,
        graph: GraphName,
    ) -> Result<()> {
        let quad = Quad::new(subject, predicate, object, graph);
        self.store
            .insert(&quad)
            .map_err(|e| anyhow!("Failed to insert quad: {e}"))?;
        Ok(())
    }

    /// Executes a SPARQL SELECT query and returns the results.
    ///
    /// # Arguments
    ///
    /// * `sparql` - SPARQL query string
    ///
    /// # Errors
    ///
    /// Returns an error if the query is invalid or execution fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let results = graph.query(
    ///     "SELECT ?s ?o WHERE { ?s <https://narsilmcp.com/ontology/v1#calls> ?o }"
    /// ).unwrap();
    /// for row in results {
    ///     println!("Subject: {:?}, Object: {:?}", row.get("s"), row.get("o"));
    /// }
    /// ```
    pub fn query(&self, sparql: &str) -> Result<Vec<QuerySolution>> {
        let results = SparqlEvaluator::new()
            .parse_query(sparql)
            .map_err(|e| anyhow!("Failed to parse query: {e}"))?
            .on_store(&self.store)
            .execute()
            .map_err(|e| anyhow!("Query execution failed: {e}"))?;

        match results {
            QueryResults::Solutions(solutions) => {
                let mut result_vec = Vec::new();
                for solution in solutions {
                    result_vec.push(solution.map_err(|e| anyhow!("Solution error: {e}"))?);
                }
                Ok(result_vec)
            }
            QueryResults::Boolean(_) => Err(anyhow!("Expected SELECT query, got ASK query")),
            QueryResults::Graph(_) => Err(anyhow!("Expected SELECT query, got CONSTRUCT query")),
        }
    }

    /// Executes a SPARQL ASK query and returns a boolean.
    ///
    /// # Arguments
    ///
    /// * `sparql` - SPARQL ASK query string
    ///
    /// # Errors
    ///
    /// Returns an error if the query is invalid or not an ASK query.
    pub fn ask(&self, sparql: &str) -> Result<bool> {
        let results = SparqlEvaluator::new()
            .parse_query(sparql)
            .map_err(|e| anyhow!("Failed to parse query: {e}"))?
            .on_store(&self.store)
            .execute()
            .map_err(|e| anyhow!("Query execution failed: {e}"))?;

        match results {
            QueryResults::Boolean(result) => Ok(result),
            _ => Err(anyhow!("Expected ASK query")),
        }
    }

    /// Clears all triples in a named graph.
    ///
    /// # Arguments
    ///
    /// * `graph` - Named graph to clear
    ///
    /// # Errors
    ///
    /// Returns an error if clearing fails.
    pub fn clear_graph(&self, graph: &GraphName) -> Result<()> {
        self.store
            .clear_graph(graph)
            .map_err(|e| anyhow!("Failed to clear graph: {e}"))?;
        Ok(())
    }

    /// Counts the number of triples in the store.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let count = graph.len();
    /// println!("Graph contains {} triples", count);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len().unwrap_or(0)
    }

    /// Returns true if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Exports the graph to Turtle format.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn export_turtle(&self) -> Result<String> {
        let mut buffer = Vec::new();
        {
            let mut serializer =
                RdfSerializer::from_format(RdfFormat::Turtle).for_writer(&mut buffer);

            for quad_result in self.store.iter() {
                let quad = quad_result.map_err(|e| anyhow!("Failed to read quad: {e}"))?;
                serializer
                    .serialize_quad(&quad)
                    .map_err(|e| anyhow!("Failed to serialize quad: {e}"))?;
            }

            serializer
                .finish()
                .map_err(|e| anyhow!("Failed to finish serialization: {e}"))?;
        }

        String::from_utf8(buffer).map_err(|e| anyhow!("Invalid UTF-8 in output: {e}"))
    }

    /// Exports the graph to N-Quads format.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn export_nquads(&self) -> Result<String> {
        let mut buffer = Vec::new();
        {
            let mut serializer =
                RdfSerializer::from_format(RdfFormat::NQuads).for_writer(&mut buffer);

            for quad_result in self.store.iter() {
                let quad = quad_result.map_err(|e| anyhow!("Failed to read quad: {e}"))?;
                serializer
                    .serialize_quad(&quad)
                    .map_err(|e| anyhow!("Failed to serialize quad: {e}"))?;
            }

            serializer
                .finish()
                .map_err(|e| anyhow!("Failed to finish serialization: {e}"))?;
        }

        String::from_utf8(buffer).map_err(|e| anyhow!("Invalid UTF-8 in output: {e}"))
    }

    /// Imports RDF data from Turtle format.
    ///
    /// # Arguments
    ///
    /// * `turtle` - Turtle-formatted RDF data
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or insertion fails.
    pub fn import_turtle(&self, turtle: &str) -> Result<()> {
        let parser = RdfParser::from_format(RdfFormat::Turtle)
            .with_base_iri(NARSIL_BASE_IRI)
            .map_err(|e| anyhow!("Invalid base IRI: {e}"))?;

        let reader = BufReader::new(Cursor::new(turtle));
        let quads = parser.for_reader(reader);

        for quad_result in quads {
            let quad = quad_result.map_err(|e| anyhow!("Failed to parse RDF: {e}"))?;
            self.store
                .insert(&quad)
                .map_err(|e| anyhow!("Failed to insert quad: {e}"))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_graph_creation() {
        let graph = KnowledgeGraph::in_memory().unwrap();
        assert!(graph.is_empty());
    }

    #[test]
    fn test_add_and_query_triple() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        graph
            .add_triple(
                "https://narsilmcp.com/code/repo/main",
                "https://narsilmcp.com/ontology/v1#calls",
                "https://narsilmcp.com/code/repo/helper",
            )
            .unwrap();

        assert_eq!(graph.len(), 1);

        let results = graph
            .query("SELECT ?o WHERE { <https://narsilmcp.com/code/repo/main> <https://narsilmcp.com/ontology/v1#calls> ?o }")
            .unwrap();

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_add_triple_with_literal() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        graph
            .add_triple_literal(
                "https://narsilmcp.com/code/repo/func",
                "https://narsilmcp.com/ontology/v1#signature",
                "fn main() -> Result<()>",
            )
            .unwrap();

        assert_eq!(graph.len(), 1);

        let results = graph
            .query("SELECT ?sig WHERE { <https://narsilmcp.com/code/repo/func> <https://narsilmcp.com/ontology/v1#signature> ?sig }")
            .unwrap();

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_add_triple_with_integer() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        graph
            .add_triple_int(
                "https://narsilmcp.com/code/repo/func",
                "https://narsilmcp.com/ontology/v1#complexity",
                15,
            )
            .unwrap();

        assert_eq!(graph.len(), 1);

        // Query for complexity > 10
        let results = graph
            .query("SELECT ?s ?c WHERE { ?s <https://narsilmcp.com/ontology/v1#complexity> ?c . FILTER(?c > 10) }")
            .unwrap();

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_ask_query() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        graph
            .add_triple(
                "https://narsilmcp.com/code/repo/a",
                "https://narsilmcp.com/ontology/v1#calls",
                "https://narsilmcp.com/code/repo/b",
            )
            .unwrap();

        let exists = graph
            .ask("ASK { <https://narsilmcp.com/code/repo/a> <https://narsilmcp.com/ontology/v1#calls> ?x }")
            .unwrap();

        assert!(exists);

        let not_exists = graph
            .ask("ASK { <https://narsilmcp.com/code/repo/b> <https://narsilmcp.com/ontology/v1#calls> ?x }")
            .unwrap();

        assert!(!not_exists);
    }

    #[test]
    fn test_named_graphs() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let repo1_graph = KnowledgeGraph::repo_graph("repo1");
        let repo2_graph = KnowledgeGraph::repo_graph("repo2");

        // Add to repo1 graph
        graph
            .add_quad(
                KnowledgeGraph::code_node("repo1", "main"),
                KnowledgeGraph::narsil_node("calls"),
                KnowledgeGraph::code_node("repo1", "helper"),
                repo1_graph.clone(),
            )
            .unwrap();

        // Add to repo2 graph
        graph
            .add_quad(
                KnowledgeGraph::code_node("repo2", "entry"),
                KnowledgeGraph::narsil_node("calls"),
                KnowledgeGraph::code_node("repo2", "process"),
                repo2_graph.clone(),
            )
            .unwrap();

        assert_eq!(graph.len(), 2);

        // Query only repo1 graph
        let results = graph
            .query(&format!(
                "SELECT ?s ?o FROM <{}> WHERE {{ ?s <{}calls> ?o }}",
                "https://narsilmcp.com/code/repo1", NARSIL_BASE_IRI
            ))
            .unwrap();

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_clear_graph() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let repo_graph = KnowledgeGraph::repo_graph("test-repo");

        graph
            .add_quad(
                KnowledgeGraph::code_node("test-repo", "main"),
                KnowledgeGraph::narsil_node("calls"),
                KnowledgeGraph::code_node("test-repo", "helper"),
                repo_graph.clone(),
            )
            .unwrap();

        assert_eq!(graph.len(), 1);

        graph.clear_graph(&repo_graph).unwrap();

        assert!(graph.is_empty());
    }

    #[test]
    fn test_export_turtle() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        graph
            .add_triple(
                "https://narsilmcp.com/code/repo/main",
                "https://narsilmcp.com/ontology/v1#calls",
                "https://narsilmcp.com/code/repo/helper",
            )
            .unwrap();

        let turtle = graph.export_turtle().unwrap();

        // Turtle output should contain the triple
        assert!(turtle.contains("narsilmcp.com/code/repo/main"));
        assert!(turtle.contains("narsilmcp.com/ontology/v1#calls"));
        assert!(turtle.contains("narsilmcp.com/code/repo/helper"));
    }

    #[test]
    fn test_export_nquads() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        graph
            .add_triple(
                "https://narsilmcp.com/code/repo/main",
                "https://narsilmcp.com/ontology/v1#calls",
                "https://narsilmcp.com/code/repo/helper",
            )
            .unwrap();

        let nquads = graph.export_nquads().unwrap();

        // N-Quads output should contain the triple
        assert!(nquads.contains("<https://narsilmcp.com/code/repo/main>"));
        assert!(nquads.contains("<https://narsilmcp.com/ontology/v1#calls>"));
        assert!(nquads.contains("<https://narsilmcp.com/code/repo/helper>"));
    }

    #[test]
    fn test_import_turtle() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        let turtle = r#"
            @prefix narsil: <https://narsilmcp.com/ontology/v1#> .
            @prefix code: <https://narsilmcp.com/code/> .

            code:repo%2Fmain narsil:calls code:repo%2Fhelper .
            code:repo%2Fmain narsil:signature "fn main()" .
        "#;

        graph.import_turtle(turtle).unwrap();

        assert_eq!(graph.len(), 2);
    }

    #[test]
    fn test_load_ontology() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        graph.load_ontology().unwrap();

        // Ontology should define the Function class
        let has_function_class = graph
            .ask(&format!(
                "ASK {{ <{NARSIL_BASE_IRI}Function> a <http://www.w3.org/2002/07/owl#Class> }}"
            ))
            .unwrap();

        assert!(has_function_class);
    }

    #[test]
    fn test_narsil_node_creation() {
        let node = KnowledgeGraph::narsil_node("calls");
        assert_eq!(node.as_str(), "https://narsilmcp.com/ontology/v1#calls");
    }

    #[test]
    fn test_code_node_creation() {
        let node = KnowledgeGraph::code_node("my-repo", "src/main.rs::main");
        // Path should be URL-encoded
        assert!(node.as_str().contains("my-repo"));
        assert!(node.as_str().contains("src%2Fmain.rs%3A%3Amain"));
    }

    #[test]
    fn test_persistent_storage() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test-graph");

        // Create graph and add data
        {
            let graph = KnowledgeGraph::open(&path).unwrap();
            graph
                .add_triple(
                    "https://narsilmcp.com/code/test/main",
                    "https://narsilmcp.com/ontology/v1#calls",
                    "https://narsilmcp.com/code/test/helper",
                )
                .unwrap();
            assert_eq!(graph.len(), 1);
        }

        // Reopen and verify data persisted
        {
            let graph = KnowledgeGraph::open(&path).unwrap();
            assert_eq!(graph.len(), 1);

            let exists = graph
                .ask("ASK { <https://narsilmcp.com/code/test/main> <https://narsilmcp.com/ontology/v1#calls> ?x }")
                .unwrap();
            assert!(exists);
        }
    }

    #[test]
    fn test_transitive_call_query() {
        let graph = KnowledgeGraph::in_memory().unwrap();

        // Build a call chain: a -> b -> c
        graph
            .add_triple(
                "https://narsilmcp.com/code/repo/a",
                "https://narsilmcp.com/ontology/v1#calls",
                "https://narsilmcp.com/code/repo/b",
            )
            .unwrap();
        graph
            .add_triple(
                "https://narsilmcp.com/code/repo/b",
                "https://narsilmcp.com/ontology/v1#calls",
                "https://narsilmcp.com/code/repo/c",
            )
            .unwrap();

        // Query transitive closure: what does 'a' eventually call?
        let results = graph
            .query(
                r#"
                SELECT ?target WHERE {
                    <https://narsilmcp.com/code/repo/a> <https://narsilmcp.com/ontology/v1#calls>+ ?target
                }
            "#,
            )
            .unwrap();

        // Should find both 'b' and 'c' (transitive)
        assert_eq!(results.len(), 2);
    }
}
