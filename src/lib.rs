// Library exports for integration tests
#![recursion_limit = "256"]

// Core modules (always available)
pub mod cache;
pub mod callgraph;
pub mod cfg;
pub mod chunking;
pub mod config;
pub mod dfg;
pub mod embeddings;
pub mod extract;
pub mod hybrid_search;
pub mod incremental;
pub mod metrics;
pub mod parser;
pub mod repo;
pub mod search;
pub mod security_config;
pub mod security_rules;
pub mod supply_chain;
pub mod symbols;
pub mod taint;
pub mod tool_metadata;
pub mod type_inference;

// Native-only modules (require tokio, octocrab, lsp, etc.)
#[cfg(feature = "native")]
pub mod git;
#[cfg(feature = "native")]
pub mod index;
#[cfg(feature = "native")]
pub mod lsp;
#[cfg(feature = "native")]
pub mod mcp;
#[cfg(feature = "native")]
pub mod neural;
#[cfg(feature = "native")]
pub mod persist;
#[cfg(feature = "native")]
pub mod remote;
#[cfg(feature = "native")]
pub mod streaming;
#[cfg(feature = "native")]
pub mod tool_handlers;

// WASM module (only compiled when targeting wasm32)
#[cfg(feature = "wasm")]
pub mod wasm;
