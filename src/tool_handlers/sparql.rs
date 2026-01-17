//! SPARQL query tool handlers
//!
//! These handlers are only available when the `graph` feature is enabled.

use anyhow::Result;
use serde_json::Value;

#[cfg(feature = "graph")]
use super::ArgExtractor;
use super::ToolHandler;
use crate::index::CodeIntelEngine;

/// Handler for sparql_query tool
pub struct SparqlQueryHandler;

#[async_trait::async_trait]
impl ToolHandler for SparqlQueryHandler {
    fn name(&self) -> &'static str {
        "sparql_query"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let query = args.get_str("query").unwrap_or("");
        let timeout_ms = args.get_u64("timeout_ms");
        let limit = args.get_u64("limit").map(|v| v as usize);
        let offset = args.get_u64("offset").map(|v| v as usize);
        let format = args.get_str("format");

        engine
            .sparql_query(query, timeout_ms, limit, offset, format)
            .await
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "SPARQL queries require the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

/// Handler for list_sparql_templates tool
pub struct ListSparqlTemplatesHandler;

#[async_trait::async_trait]
impl ToolHandler for ListSparqlTemplatesHandler {
    fn name(&self) -> &'static str {
        "list_sparql_templates"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        engine.list_sparql_templates().await
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "SPARQL templates require the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

/// Handler for run_sparql_template tool
pub struct RunSparqlTemplateHandler;

#[async_trait::async_trait]
impl ToolHandler for RunSparqlTemplateHandler {
    fn name(&self) -> &'static str {
        "run_sparql_template"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let template_name = args.get_str("template").unwrap_or("");
        let timeout_ms = args.get_u64("timeout_ms");
        let limit = args.get_u64("limit").map(|v| v as usize);
        let format = args.get_str("format");

        // Extract params from JSON object
        let params: std::collections::HashMap<String, String> = args
            .get("params")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        engine
            .run_sparql_template(template_name, params, timeout_ms, limit, format)
            .await
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "SPARQL templates require the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_names() {
        assert_eq!(SparqlQueryHandler.name(), "sparql_query");
        assert_eq!(ListSparqlTemplatesHandler.name(), "list_sparql_templates");
        assert_eq!(RunSparqlTemplateHandler.name(), "run_sparql_template");
    }
}
