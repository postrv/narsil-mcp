//! Persistence layer using Oxigraph for RDF knowledge graph storage.
//!
//! This module provides a `KnowledgeGraph` struct that wraps an Oxigraph store
//! for persistent RDF triple storage with SPARQL query support.
//!
//! # Features
//!
//! - RDF triple storage with named graphs per repository
//! - SPARQL 1.1 query support
//! - Turtle, N-Quads, and RDF/XML serialization
//! - RocksDB-backed persistent storage
//!
//! # Example
//!
//! ```ignore
//! use narsil_mcp::persistence::KnowledgeGraph;
//! use std::path::Path;
//!
//! let graph = KnowledgeGraph::open(Path::new("/tmp/narsil-graph")).unwrap();
//! graph.add_triple(
//!     "https://narsilmcp.com/code/example/main",
//!     "https://narsilmcp.com/ontology/v1#calls",
//!     "https://narsilmcp.com/code/example/helper",
//! ).unwrap();
//! ```

#[cfg(feature = "graph")]
mod graph;

#[cfg(feature = "graph")]
mod transform;

#[cfg(feature = "graph")]
pub use graph::*;

#[cfg(feature = "graph")]
pub use transform::*;

// Re-export common types for use without the feature flag
pub mod ontology;
