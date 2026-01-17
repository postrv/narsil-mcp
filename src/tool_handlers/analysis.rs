//! Code analysis tool handlers (CFG, DFG, type inference)

use anyhow::Result;
use serde_json::Value;

use super::{ArgExtractor, ToolHandler};
use crate::index::CodeIntelEngine;

/// Handler for get_control_flow tool
pub struct GetControlFlowHandler;

#[async_trait::async_trait]
impl ToolHandler for GetControlFlowHandler {
    fn name(&self) -> &'static str {
        "get_control_flow"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let function = args.get_str("function").unwrap_or("");
        engine.get_control_flow(repo, path, function).await
    }
}

/// Handler for find_dead_code tool
pub struct FindDeadCodeHandler;

#[async_trait::async_trait]
impl ToolHandler for FindDeadCodeHandler {
    fn name(&self) -> &'static str {
        "find_dead_code"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let function = args.get_str("function");
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .find_dead_code(repo, path, function, exclude_tests)
            .await
    }
}

/// Handler for get_data_flow tool
pub struct GetDataFlowHandler;

#[async_trait::async_trait]
impl ToolHandler for GetDataFlowHandler {
    fn name(&self) -> &'static str {
        "get_data_flow"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let function = args.get_str("function").unwrap_or("");
        engine.get_data_flow(repo, path, function).await
    }
}

/// Handler for get_reaching_definitions tool
pub struct GetReachingDefinitionsHandler;

#[async_trait::async_trait]
impl ToolHandler for GetReachingDefinitionsHandler {
    fn name(&self) -> &'static str {
        "get_reaching_definitions"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let function = args.get_str("function").unwrap_or("");
        engine.get_reaching_definitions(repo, path, function).await
    }
}

/// Handler for find_uninitialized tool
pub struct FindUninitializedHandler;

#[async_trait::async_trait]
impl ToolHandler for FindUninitializedHandler {
    fn name(&self) -> &'static str {
        "find_uninitialized"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let function = args.get_str("function");
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .find_uninitialized(repo, path, function, exclude_tests)
            .await
    }
}

/// Handler for find_dead_stores tool
pub struct FindDeadStoresHandler;

#[async_trait::async_trait]
impl ToolHandler for FindDeadStoresHandler {
    fn name(&self) -> &'static str {
        "find_dead_stores"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let function = args.get_str("function");
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .find_dead_stores(repo, path, function, exclude_tests)
            .await
    }
}

/// Handler for infer_types tool
pub struct InferTypesHandler;

#[async_trait::async_trait]
impl ToolHandler for InferTypesHandler {
    fn name(&self) -> &'static str {
        "infer_types"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let function = args.get_str("function").unwrap_or("");
        engine.infer_types(repo, path, function).await
    }
}

/// Handler for check_type_errors tool
pub struct CheckTypeErrorsHandler;

#[async_trait::async_trait]
impl ToolHandler for CheckTypeErrorsHandler {
    fn name(&self) -> &'static str {
        "check_type_errors"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let exclude_tests = args.get_bool("exclude_tests");
        engine.check_type_errors(repo, path, exclude_tests).await
    }
}

/// Handler for get_typed_taint_flow tool
pub struct GetTypedTaintFlowHandler;

#[async_trait::async_trait]
impl ToolHandler for GetTypedTaintFlowHandler {
    fn name(&self) -> &'static str {
        "get_typed_taint_flow"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let source_line = args.get_u64_or("source_line", 1) as usize;
        engine.get_typed_taint_flow(repo, path, source_line).await
    }
}

/// Handler for get_import_graph tool
pub struct GetImportGraphHandler;

#[async_trait::async_trait]
impl ToolHandler for GetImportGraphHandler {
    fn name(&self) -> &'static str {
        "get_import_graph"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let file = args.get_str("file");
        let direction = args.get_str("direction").unwrap_or("both");
        engine.get_import_graph(repo, file, direction).await
    }
}

/// Handler for find_circular_imports tool
pub struct FindCircularImportsHandler;

#[async_trait::async_trait]
impl ToolHandler for FindCircularImportsHandler {
    fn name(&self) -> &'static str {
        "find_circular_imports"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let exclude_tests = args.get_bool("exclude_tests");
        engine.find_circular_imports(repo, exclude_tests).await
    }
}

/// Handler for find_unused_exports tool
pub struct FindUnusedExportsHandler;

#[async_trait::async_trait]
impl ToolHandler for FindUnusedExportsHandler {
    fn name(&self) -> &'static str {
        "find_unused_exports"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let exclude_entry_points = args.get_bool("exclude_entry_points").unwrap_or(true);
        let exclude_patterns: Vec<String> = args
            .get("exclude_patterns")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        engine
            .find_unused_exports(repo, exclude_entry_points, exclude_patterns)
            .await
    }
}
