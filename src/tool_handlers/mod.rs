//! Tool handlers for MCP protocol
//!
//! This module provides a trait-based architecture for handling MCP tool calls.
//! Each tool is implemented as a struct implementing the `ToolHandler` trait,
//! allowing for isolated testing and reduced complexity in the main MCP handler.

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

use crate::index::CodeIntelEngine;

mod analysis;
mod callgraph;
mod git;
pub mod graph;
mod lsp;
mod remote;
mod repo;
mod search;
mod security;
mod supply_chain;
mod symbols;

/// Trait for implementing tool handlers
///
/// Each tool handler extracts its arguments from JSON and calls the appropriate
/// engine method, returning the result as a string.
#[async_trait::async_trait]
pub trait ToolHandler: Send + Sync {
    /// Returns the tool name as it appears in MCP protocol
    fn name(&self) -> &'static str;

    /// Execute the tool with the given arguments
    ///
    /// # Arguments
    /// * `engine` - The code intel engine to use for operations
    /// * `args` - JSON arguments from the tool call
    ///
    /// # Returns
    /// The tool result as a string, or an error
    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String>;
}

/// Registry for tool handlers
///
/// Provides efficient dispatch from tool name to handler implementation.
pub struct ToolRegistry {
    handlers: HashMap<&'static str, Box<dyn ToolHandler>>,
}

impl ToolRegistry {
    /// Create a new registry with all standard handlers
    pub fn new() -> Self {
        let mut registry = Self {
            handlers: HashMap::new(),
        };

        // Register repository handlers
        registry.register(Box::new(repo::ListReposHandler));
        registry.register(Box::new(repo::GetProjectStructureHandler));
        registry.register(Box::new(repo::GetFileHandler));
        registry.register(Box::new(repo::GetExcerptHandler));
        registry.register(Box::new(repo::DiscoverReposHandler));
        registry.register(Box::new(repo::ValidateRepoHandler));
        registry.register(Box::new(repo::ReindexHandler));
        registry.register(Box::new(repo::GetIndexStatusHandler));
        registry.register(Box::new(repo::GetIncrementalStatusHandler));
        registry.register(Box::new(repo::GetMetricsHandler));

        // Register symbol handlers
        registry.register(Box::new(symbols::FindSymbolsHandler));
        registry.register(Box::new(symbols::GetSymbolDefinitionHandler));
        registry.register(Box::new(symbols::FindReferencesHandler));
        registry.register(Box::new(symbols::GetDependenciesHandler));
        registry.register(Box::new(symbols::FindSymbolUsagesHandler));
        registry.register(Box::new(symbols::GetExportMapHandler));
        registry.register(Box::new(symbols::WorkspaceSymbolSearchHandler));

        // Register search handlers
        registry.register(Box::new(search::SearchCodeHandler));
        registry.register(Box::new(search::SemanticSearchHandler));
        registry.register(Box::new(search::HybridSearchHandler));
        registry.register(Box::new(search::NeuralSearchHandler));
        registry.register(Box::new(search::SearchChunksHandler));
        registry.register(Box::new(search::FindSimilarCodeHandler));
        registry.register(Box::new(search::FindSimilarToSymbolHandler));
        registry.register(Box::new(search::FindSemanticClonesHandler));
        registry.register(Box::new(search::GetEmbeddingStatsHandler));
        registry.register(Box::new(search::GetNeuralStatsHandler));
        registry.register(Box::new(search::GetChunkStatsHandler));
        registry.register(Box::new(search::GetChunksHandler));

        // Register call graph handlers
        registry.register(Box::new(callgraph::GetCallGraphHandler));
        registry.register(Box::new(callgraph::GetCallersHandler));
        registry.register(Box::new(callgraph::GetCalleesHandler));
        registry.register(Box::new(callgraph::FindCallPathHandler));
        registry.register(Box::new(callgraph::GetComplexityHandler));
        registry.register(Box::new(callgraph::GetFunctionHotspotsHandler));

        // Register git handlers
        registry.register(Box::new(git::GetBlameHandler));
        registry.register(Box::new(git::GetFileHistoryHandler));
        registry.register(Box::new(git::GetRecentChangesHandler));
        registry.register(Box::new(git::GetHotspotsHandler));
        registry.register(Box::new(git::GetContributorsHandler));
        registry.register(Box::new(git::GetCommitDiffHandler));
        registry.register(Box::new(git::GetSymbolHistoryHandler));
        registry.register(Box::new(git::GetBranchInfoHandler));
        registry.register(Box::new(git::GetModifiedFilesHandler));

        // Register LSP handlers
        registry.register(Box::new(lsp::GetHoverInfoHandler));
        registry.register(Box::new(lsp::GetTypeInfoHandler));
        registry.register(Box::new(lsp::GoToDefinitionHandler));

        // Register remote handlers
        registry.register(Box::new(remote::AddRemoteRepoHandler));
        registry.register(Box::new(remote::ListRemoteFilesHandler));
        registry.register(Box::new(remote::GetRemoteFileHandler));

        // Register security handlers
        registry.register(Box::new(security::ScanSecurityHandler));
        registry.register(Box::new(security::CheckOwaspTop10Handler));
        registry.register(Box::new(security::CheckCweTop25Handler));
        registry.register(Box::new(security::FindInjectionVulnerabilitiesHandler));
        registry.register(Box::new(security::TraceTaintHandler));
        registry.register(Box::new(security::GetTaintSourcesHandler));
        registry.register(Box::new(security::GetSecuritySummaryHandler));
        registry.register(Box::new(security::ExplainVulnerabilityHandler));
        registry.register(Box::new(security::SuggestFixHandler));

        // Register supply chain handlers
        registry.register(Box::new(supply_chain::GenerateSbomHandler));
        registry.register(Box::new(supply_chain::CheckDependenciesHandler));
        registry.register(Box::new(supply_chain::CheckLicensesHandler));
        registry.register(Box::new(supply_chain::FindUpgradePathHandler));

        // Register analysis handlers
        registry.register(Box::new(analysis::GetControlFlowHandler));
        registry.register(Box::new(analysis::FindDeadCodeHandler));
        registry.register(Box::new(analysis::GetDataFlowHandler));
        registry.register(Box::new(analysis::GetReachingDefinitionsHandler));
        registry.register(Box::new(analysis::FindUninitializedHandler));
        registry.register(Box::new(analysis::FindDeadStoresHandler));
        registry.register(Box::new(analysis::InferTypesHandler));
        registry.register(Box::new(analysis::CheckTypeErrorsHandler));
        registry.register(Box::new(analysis::GetTypedTaintFlowHandler));
        registry.register(Box::new(analysis::GetImportGraphHandler));
        registry.register(Box::new(analysis::FindCircularImportsHandler));
        registry.register(Box::new(analysis::FindUnusedExportsHandler));

        // Register graph visualization handler
        registry.register(Box::new(graph::GetCodeGraphHandler));

        registry
    }

    /// Register a handler
    fn register(&mut self, handler: Box<dyn ToolHandler>) {
        self.handlers.insert(handler.name(), handler);
    }

    /// Dispatch a tool call to the appropriate handler
    ///
    /// # Arguments
    /// * `name` - The tool name
    /// * `engine` - The code intel engine
    /// * `args` - JSON arguments
    ///
    /// # Returns
    /// The tool result, or an error if the tool is unknown
    pub async fn dispatch(
        &self,
        name: &str,
        engine: &CodeIntelEngine,
        args: Value,
    ) -> Result<String> {
        self.handlers
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("Unknown tool: {}", name))?
            .execute(engine, args)
            .await
    }

    /// Check if a tool exists
    pub fn has_tool(&self, name: &str) -> bool {
        self.handlers.contains_key(name)
    }

    /// Get all registered tool names
    pub fn tool_names(&self) -> Vec<&'static str> {
        self.handlers.keys().copied().collect()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper trait for extracting arguments from JSON
pub trait ArgExtractor {
    fn get_str(&self, key: &str) -> Option<&str>;
    fn get_str_or(&self, key: &str, default: &str) -> String;
    fn get_u64(&self, key: &str) -> Option<u64>;
    fn get_u64_or(&self, key: &str, default: u64) -> u64;
    fn get_bool(&self, key: &str) -> Option<bool>;
    fn get_bool_or(&self, key: &str, default: bool) -> bool;
    fn get_array(&self, key: &str) -> Option<&Vec<Value>>;
}

impl ArgExtractor for Value {
    fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }

    fn get_str_or(&self, key: &str, default: &str) -> String {
        self.get_str(key).unwrap_or(default).to_string()
    }

    fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|v| v.as_u64())
    }

    fn get_u64_or(&self, key: &str, default: u64) -> u64 {
        self.get_u64(key).unwrap_or(default)
    }

    fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

    fn get_bool_or(&self, key: &str, default: bool) -> bool {
        self.get_bool(key).unwrap_or(default)
    }

    fn get_array(&self, key: &str) -> Option<&Vec<Value>> {
        self.get(key).and_then(|v| v.as_array())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = ToolRegistry::new();
        assert!(registry.has_tool("list_repos"));
        assert!(registry.has_tool("find_symbols"));
        assert!(registry.has_tool("search_code"));
        assert!(!registry.has_tool("nonexistent_tool"));
    }

    #[test]
    fn test_tool_names() {
        let registry = ToolRegistry::new();
        let names = registry.tool_names();
        assert!(names.contains(&"list_repos"));
        assert!(names.contains(&"get_file"));
    }

    #[test]
    fn test_arg_extractor() {
        let args = serde_json::json!({
            "repo": "test",
            "count": 5,
            "enabled": true
        });

        assert_eq!(args.get_str("repo"), Some("test"));
        assert_eq!(args.get_str("missing"), None);
        assert_eq!(args.get_str_or("missing", "default"), "default");

        assert_eq!(args.get_u64("count"), Some(5));
        assert_eq!(args.get_u64_or("missing", 10), 10);

        assert_eq!(args.get_bool("enabled"), Some(true));
        assert!(!args.get_bool_or("missing", false));
    }
}
