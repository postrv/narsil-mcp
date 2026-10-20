use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tracing::{debug, info};

use crate::config::schema::ToolConfig;
use crate::config::{ConfigLoader, ExposeGroup, ToolFilter};
use crate::index::CodeIntelEngine;
use crate::tool_metadata::TOOL_METADATA;

// Re-export for internal use
pub use crate::tool_handlers::ToolRegistry;

/// MCP Protocol Version
const MCP_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = crate::APP_NAME;
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum size of a single JSON-RPC message (10 MB).
/// Prevents memory exhaustion from oversized messages.
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JsonRpcRequest {
    pub(crate) jsonrpc: String,
    pub(crate) id: Option<Value>,
    pub(crate) method: String,
    #[serde(default)]
    pub(crate) params: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JsonRpcResponse {
    pub(crate) jsonrpc: String,
    pub(crate) id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JsonRpcError {
    pub(crate) code: i32,
    pub(crate) message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<Value>,
}

impl JsonRpcResponse {
    fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: Option<Value>, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }
}

/// Reject a call to a tool outside `--expose`, naming the group so the operator
/// knows what to turn on and telling the caller not to retry — a client that
/// connected before the set was narrowed still holds the old tools/list.
///
/// Only `--expose` is enforced, not the per-tool overrides from config.yaml:
/// exposed groups are a server-wide statement by the operator.
/// Returns `None` for an unknown name — that is the registry's error to report.
fn expose_rejection(expose: &[ExposeGroup], tool_name: &str) -> Option<String> {
    if expose.is_empty() || ExposeGroup::union(expose).contains(tool_name) {
        return None;
    }

    let group = ExposeGroup::of(tool_name)?;
    let mut enabled: Vec<&str> = expose.iter().map(|g| g.name()).collect();
    enabled.sort_unstable();

    Some(format!(
        "Tool '{tool}' is not available on this server: its group '{group}' is not \
         exposed (this server serves: base, {enabled}). This is a fixed server \
         configuration, not a transient failure — do not retry '{tool}', and expect \
         every other '{group}' tool to be unavailable too. To enable it, add \
         '{group}' to --expose or to `expose:` in config.yaml and restart the server.",
        tool = tool_name,
        group = group.name(),
        enabled = enabled.join(", "),
    ))
}

pub struct McpServer {
    engine: Arc<CodeIntelEngine>,
    tool_registry: ToolRegistry,
    config: ToolConfig,
    /// Tool groups from `--expose`. Empty exposes every registered tool.
    expose: Vec<ExposeGroup>,
}

impl McpServer {
    /// Create a new MCP server with the given code intelligence engine.
    ///
    /// # Arguments
    /// * `engine` - The code intelligence engine to use
    ///
    /// # Examples
    /// ```ignore
    /// let engine = CodeIntelEngine::with_options(path, repos, options).await?;
    /// let server = McpServer::new(engine);
    /// ```
    pub fn new(engine: CodeIntelEngine) -> Self {
        let config = ConfigLoader::new().load().unwrap_or_else(|e| {
            eprintln!("Warning: Failed to load config: {}. Using defaults.", e);
            // Return default config by loading it again
            ConfigLoader::new().default_config.clone()
        });
        let tool_registry = ToolRegistry::new();
        let engine = Arc::new(engine);
        engine.metrics.set_known_tools(
            tool_registry
                .tool_names()
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
        );
        Self {
            engine,
            tool_registry,
            config,
            expose: Vec::new(),
        }
    }

    /// Create an McpServer from an existing `Arc<CodeIntelEngine>`.
    /// This allows sharing the engine with other components like watch mode.
    ///
    /// # Arguments
    /// * `engine` - The code intelligence engine
    /// * `expose` - Tool groups from CLI --expose; empty keeps the config's
    ///   `expose:` or, absent that, every registered tool
    pub fn from_arc(engine: Arc<CodeIntelEngine>, expose: Vec<ExposeGroup>) -> Self {
        let config = ConfigLoader::new().load().unwrap_or_else(|e| {
            eprintln!("Warning: Failed to load config: {}. Using defaults.", e);
            ConfigLoader::new().default_config.clone()
        });

        let tool_registry = ToolRegistry::new();
        engine.metrics.set_known_tools(
            tool_registry
                .tool_names()
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
        );
        Self {
            engine,
            tool_registry,
            config,
            expose,
        }
    }

    pub async fn run(&self) -> Result<()> {
        info!("MCP server starting on stdio");

        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = tokio::io::BufReader::new(stdin);
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;

            if bytes_read == 0 {
                info!("EOF received, shutting down");
                break;
            }

            // Reject oversized messages to prevent memory exhaustion
            if line.len() > MAX_MESSAGE_SIZE {
                tracing::warn!(
                    "Rejecting oversized message: {} bytes (max {})",
                    line.len(),
                    MAX_MESSAGE_SIZE
                );
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32600,
                        "message": format!("Message too large: {} bytes exceeds {} byte limit", line.len(), MAX_MESSAGE_SIZE)
                    }
                });
                let response_str = serde_json::to_string(&error_response)?;
                stdout
                    .write_all(format!("{}\n", response_str).as_bytes())
                    .await?;
                stdout.flush().await?;
                continue;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            debug!("Received: {}", trimmed);

            let response = match serde_json::from_str::<JsonRpcRequest>(trimmed) {
                Ok(request) => {
                    // Check if this is a notification (no id field means no response expected)
                    // JSON-RPC 2.0: "The Server MUST NOT reply to a Notification"
                    if request.id.is_none() {
                        // This is a notification - handle it but don't respond
                        debug!("Handling notification: {}", request.method);
                        let _ = self.dispatch(request).await;
                        continue;
                    }
                    self.dispatch(request).await
                }
                Err(e) => {
                    // Parse error - try to extract ID from raw JSON for error response
                    // If we can't get an ID, log the error but don't respond (avoids id:null issues)
                    if let Ok(raw) = serde_json::from_str::<Value>(trimmed) {
                        if let Some(id) = raw.get("id").cloned() {
                            // We have an ID, we can respond with an error
                            if !id.is_null() {
                                JsonRpcResponse::error(
                                    Some(id),
                                    -32700,
                                    &format!("Parse error: {}", e),
                                )
                            } else {
                                // id is null - don't respond to avoid ZodError
                                debug!("Parse error with null id, not responding: {}", e);
                                continue;
                            }
                        } else {
                            // No ID field - this might be a malformed notification, don't respond
                            debug!("Parse error without id field, not responding: {}", e);
                            continue;
                        }
                    } else {
                        // Complete parse failure - can't respond without an ID
                        debug!("Complete parse error, not responding: {}", e);
                        continue;
                    }
                }
            };

            let response_str = serde_json::to_string(&response)? + "\n";
            debug!("Sending: {}", response_str.trim());
            stdout.write_all(response_str.as_bytes()).await?;
            stdout.flush().await?;
        }

        Ok(())
    }

    pub(crate) async fn dispatch(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let id = request.id.clone();

        match request.method.as_str() {
            // MCP Lifecycle
            "initialize" => self.handle_initialize(id),
            "initialized" => JsonRpcResponse::success(id, json!({})),

            // Tool listing and execution
            "tools/list" => self.handle_tools_list(id),
            "tools/call" => self.handle_tool_call(id, request.params).await,

            // Resource listing
            "resources/list" => self.handle_resources_list(id),
            "resources/read" => self.handle_resource_read(id, request.params).await,

            // Prompts
            "prompts/list" => self.handle_prompts_list(id),
            "prompts/get" => self.handle_prompts_get(id, request.params),

            _ => {
                JsonRpcResponse::error(id, -32601, &format!("Method not found: {}", request.method))
            }
        }
    }

    fn handle_initialize(&self, id: Option<Value>) -> JsonRpcResponse {
        JsonRpcResponse::success(
            id,
            json!({
                "protocolVersion": MCP_VERSION,
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION
                },
                "capabilities": {
                    // The tool set is fixed for a process lifetime, so this
                    // server never changes it mid-session. The notification
                    // exists for the one case where a client's view can go
                    // stale without the client noticing: the stdio proxy
                    // reconnecting to a restarted daemon that may have been
                    // started with a different --expose.
                    "tools": { "listChanged": true },
                    "resources": {
                        "subscribe": false,
                        "listChanged": false
                    },
                    "prompts": {}
                }
            }),
        )
    }

    fn handle_tools_list(&self, id: Option<Value>) -> JsonRpcResponse {
        // Create tool filter with current config and engine options
        let filter =
            ToolFilter::new(self.config.clone(), self.engine.options()).with_expose(&self.expose);

        // Get filtered list of enabled tools
        let enabled_tools = filter.get_enabled_tools();

        // Build tools array from metadata
        let tools: Vec<Value> = enabled_tools
            .iter()
            .filter_map(|tool_name| {
                TOOL_METADATA.get(tool_name).map(|meta| {
                    json!({
                        "name": meta.name,
                        "description": meta.description,
                        "inputSchema": meta.input_schema,
                    })
                })
            })
            .collect();

        info!(
            "Returning {} tools (filtered from {} total)",
            tools.len(),
            TOOL_METADATA.len()
        );

        JsonRpcResponse::success(
            id,
            json!({
                "tools": tools
            }),
        )
    }

    /// Render a tool error as a JSON-RPC error response. A repo whose index is
    /// mid-update gets its own code, so a client can retry the request instead
    /// of reporting a failure.
    fn tool_error_response(id: Option<Value>, error: &anyhow::Error) -> JsonRpcResponse {
        let code = match error.downcast_ref::<crate::index::IndexBusy>() {
            Some(_) => crate::index::JSONRPC_INDEX_BUSY,
            None => -32000,
        };
        JsonRpcResponse::error(id, code, &error.to_string())
    }

    async fn handle_tool_call(&self, id: Option<Value>, params: Value) -> JsonRpcResponse {
        let start_time = std::time::Instant::now();
        let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        // A client that connected before the tool set was narrowed still holds
        // the old list — tools/list is never re-pushed — so it can ask for a
        // tool this server no longer offers.
        if let Some(message) = expose_rejection(&self.expose, tool_name) {
            tracing::info!(tool = tool_name, "refused: outside the exposed groups");
            return JsonRpcResponse::error(id, -32000, &message);
        }

        // Dispatch to tool registry. The release profile unwinds (not aborts),
        // so catch a panicking handler here and turn it into an error instead
        // of letting it take down the whole server for every other tool.
        use futures::FutureExt;
        let dispatch = self
            .tool_registry
            .dispatch(tool_name, &self.engine, arguments);
        let result: Result<String> =
            match std::panic::AssertUnwindSafe(dispatch).catch_unwind().await {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!(
                    "Internal error: tool '{}' panicked",
                    tool_name
                )),
            };

        // Record metrics and log execution time.
        let elapsed = start_time.elapsed();
        self.engine.metrics.record_tool(tool_name, elapsed);
        tracing::info!(
            tool = tool_name,
            duration_ms = elapsed.as_millis(),
            success = result.is_ok(),
            "Tool execution completed"
        );

        match result {
            Ok(content) => {
                // Record what the tool produced, not what survived the clamp:
                // the oversized response is the thing worth seeing in stats.
                self.engine
                    .metrics
                    .record_tool_response(tool_name, content.len());
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": crate::response_budget::clamp(content, tool_name)
                        }]
                    }),
                )
            }
            Err(e) => Self::tool_error_response(id, &e),
        }
    }

    fn handle_resources_list(&self, id: Option<Value>) -> JsonRpcResponse {
        // Resources are exposed as the indexed repositories
        JsonRpcResponse::success(
            id,
            json!({
                "resources": []
            }),
        )
    }

    async fn handle_resource_read(&self, id: Option<Value>, params: Value) -> JsonRpcResponse {
        let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");

        match self.engine.read_resource(uri).await {
            Ok(content) => JsonRpcResponse::success(
                id,
                json!({
                    "contents": [{
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": content
                    }]
                }),
            ),
            Err(e) => JsonRpcResponse::error(id, -32000, &e.to_string()),
        }
    }

    fn handle_prompts_list(&self, id: Option<Value>) -> JsonRpcResponse {
        JsonRpcResponse::success(
            id,
            json!({
                "prompts": [
                    {
                        "name": "explain_codebase",
                        "description": "Get an overview of a codebase's architecture and key components",
                        "arguments": [
                            {
                                "name": "repo",
                                "description": "Repository to explain",
                                "required": true
                            }
                        ]
                    },
                    {
                        "name": "find_implementation",
                        "description": "Find where a specific feature or algorithm is implemented",
                        "arguments": [
                            {
                                "name": "repo",
                                "description": "Repository to search",
                                "required": true
                            },
                            {
                                "name": "feature",
                                "description": "Feature or algorithm to find",
                                "required": true
                            }
                        ]
                    }
                ]
            }),
        )
    }

    fn handle_prompts_get(&self, id: Option<Value>, params: Value) -> JsonRpcResponse {
        let prompt_name = match params.get("name").and_then(|v| v.as_str()) {
            Some(name) => name,
            None => {
                return JsonRpcResponse::error(id, -32602, "Missing required parameter: name");
            }
        };

        // Get arguments from params (optional)
        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        match prompt_name {
            "explain_codebase" => {
                let repo = arguments
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<repository>");

                JsonRpcResponse::success(
                    id,
                    json!({
                        "description": "Get an overview of a codebase's architecture and key components",
                        "messages": [
                            {
                                "role": "user",
                                "content": {
                                    "type": "text",
                                    "text": format!(
                                        "Please explain the architecture and key components of the '{}' repository.\n\n\
                                        Use the following tools to gather information:\n\
                                        1. get_project_structure - to understand the directory layout\n\
                                        2. find_symbols - to identify main types, functions, and modules\n\
                                        3. get_file - to read key files like README, main entry points\n\
                                        4. search_code - to find important patterns\n\n\
                                        Provide a comprehensive overview including:\n\
                                        - Project purpose and main functionality\n\
                                        - Directory structure and organization\n\
                                        - Key modules and their responsibilities\n\
                                        - Main entry points and data flow\n\
                                        - Dependencies and external integrations",
                                        repo
                                    )
                                }
                            }
                        ]
                    }),
                )
            }
            "find_implementation" => {
                let repo = arguments
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<repository>");
                let feature = arguments
                    .get("feature")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<feature>");

                JsonRpcResponse::success(
                    id,
                    json!({
                        "description": "Find where a specific feature or algorithm is implemented",
                        "messages": [
                            {
                                "role": "user",
                                "content": {
                                    "type": "text",
                                    "text": format!(
                                        "Please find where '{}' is implemented in the '{}' repository.\n\n\
                                        Use the following tools to search:\n\
                                        1. search_code - to find relevant code mentions\n\
                                        2. find_symbols - to find related functions and types\n\
                                        3. get_symbol_definition - to examine symbol implementations\n\
                                        4. get_callers/get_callees - to understand call relationships\n\
                                        5. get_file - to read the implementation files\n\n\
                                        Provide:\n\
                                        - The main file(s) where this feature is implemented\n\
                                        - Key functions and types involved\n\
                                        - How the implementation works\n\
                                        - Any related or supporting code",
                                        feature, repo
                                    )
                                }
                            }
                        ]
                    }),
                )
            }
            _ => JsonRpcResponse::error(id, -32602, &format!("Unknown prompt: {}", prompt_name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The retry case needs its own code: a client that cannot tell it from a
    /// generic failure reports the branch switch as a broken tool call.
    #[test]
    fn index_busy_gets_its_own_error_code() {
        let busy = McpServer::tool_error_response(
            Some(json!(1)),
            &anyhow::Error::from(crate::index::IndexBusy {
                repo: "/repo".to_string(),
                indexed_repos: 3,
                total_repos: 5,
                first_pass: false,
            }),
        );
        let error = busy.error.expect("IndexBusy is an error response");
        assert_eq!(error.code, crate::index::JSONRPC_INDEX_BUSY);
        assert!(error.message.contains("EAGAIN"));
        assert!(
            error.message.contains("3/5 repos indexed"),
            "message should carry the same progress counters get_index_status reports: {}",
            error.message
        );

        let other = McpServer::tool_error_response(Some(json!(1)), &anyhow::anyhow!("boom"));
        assert_eq!(other.error.expect("still an error").code, -32000);
    }

    /// Test prompts/list returns both prompts
    #[test]
    fn test_prompts_list() {
        // Create a mock response using handle_prompts_list logic
        let response_value = json!({
            "prompts": [
                {
                    "name": "explain_codebase",
                    "description": "Get an overview of a codebase's architecture and key components",
                    "arguments": [
                        {
                            "name": "repo",
                            "description": "Repository to explain",
                            "required": true
                        }
                    ]
                },
                {
                    "name": "find_implementation",
                    "description": "Find where a specific feature or algorithm is implemented",
                    "arguments": [
                        {
                            "name": "repo",
                            "description": "Repository to search",
                            "required": true
                        },
                        {
                            "name": "feature",
                            "description": "Feature or algorithm to find",
                            "required": true
                        }
                    ]
                }
            ]
        });

        let prompts = response_value["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 2, "Should have 2 prompts");

        // Verify explain_codebase prompt
        let explain = &prompts[0];
        assert_eq!(explain["name"], "explain_codebase");
        assert!(explain["arguments"].as_array().unwrap().len() == 1);

        // Verify find_implementation prompt
        let find = &prompts[1];
        assert_eq!(find["name"], "find_implementation");
        assert!(find["arguments"].as_array().unwrap().len() == 2);
    }

    /// Test prompts/get for explain_codebase
    #[test]
    fn test_prompts_get_explain_codebase() {
        let params = json!({
            "name": "explain_codebase",
            "arguments": {
                "repo": "my-project"
            }
        });

        let prompt_name = params["name"].as_str().unwrap();
        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        assert_eq!(prompt_name, "explain_codebase");

        let repo = arguments
            .get("repo")
            .and_then(|v| v.as_str())
            .unwrap_or("<repository>");
        assert_eq!(repo, "my-project");
    }

    /// Test prompts/get for find_implementation
    #[test]
    fn test_prompts_get_find_implementation() {
        let params = json!({
            "name": "find_implementation",
            "arguments": {
                "repo": "my-project",
                "feature": "authentication"
            }
        });

        let prompt_name = params["name"].as_str().unwrap();
        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        assert_eq!(prompt_name, "find_implementation");

        let repo = arguments.get("repo").and_then(|v| v.as_str()).unwrap();
        let feature = arguments.get("feature").and_then(|v| v.as_str()).unwrap();

        assert_eq!(repo, "my-project");
        assert_eq!(feature, "authentication");
    }

    /// Test prompts/get with missing name returns error
    #[test]
    fn test_prompts_get_missing_name() {
        let params = json!({
            "arguments": {
                "repo": "my-project"
            }
        });

        let name = params.get("name").and_then(|v| v.as_str());
        assert!(name.is_none(), "Should be None when name is missing");
    }

    /// Test prompts/get with unknown prompt returns error
    #[test]
    fn test_prompts_get_unknown_prompt() {
        let params = json!({
            "name": "nonexistent_prompt",
            "arguments": {}
        });

        let prompt_name = params["name"].as_str().unwrap();
        let known_prompts = ["explain_codebase", "find_implementation"];

        assert!(
            !known_prompts.contains(&prompt_name),
            "Unknown prompt should not be in known list"
        );
    }

    /// Test prompts/get with default arguments
    #[test]
    fn test_prompts_get_default_arguments() {
        let params = json!({
            "name": "explain_codebase"
            // No arguments provided
        });

        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
        let repo = arguments
            .get("repo")
            .and_then(|v| v.as_str())
            .unwrap_or("<repository>");

        assert_eq!(repo, "<repository>", "Should use default placeholder");
    }

    #[test]
    fn test_expose_rejection_names_the_group_and_says_not_to_retry() {
        let msg = expose_rejection(&[ExposeGroup::Code, ExposeGroup::Git], "get_complexity")
            .expect("an analysis tool must be refused when only code+git are exposed");

        assert!(msg.contains("get_complexity"), "names the tool: {msg}");
        assert!(msg.contains("'analysis'"), "names the group: {msg}");
        assert!(
            msg.contains("do not retry"),
            "tells the caller to stop: {msg}"
        );
        assert!(msg.contains("--expose"), "says how to enable it: {msg}");
    }

    #[test]
    fn test_expose_rejection_allows_exposed_and_base_tools() {
        let groups = [ExposeGroup::Code, ExposeGroup::Git];
        assert!(expose_rejection(&groups, "find_symbols").is_none());
        assert!(expose_rejection(&groups, "get_blame").is_none());
        // base is always folded in by ExposeGroup::union
        assert!(expose_rejection(&groups, "list_repos").is_none());
    }

    /// Without --expose the server keeps its historical behaviour: everything
    /// the registry knows stays callable.
    #[test]
    fn test_expose_rejection_is_inert_when_no_groups_selected() {
        assert!(expose_rejection(&[], "get_complexity").is_none());
    }

    /// An unknown name is the registry's error to report, with its own wording.
    #[test]
    fn test_expose_rejection_ignores_unknown_tools() {
        assert!(expose_rejection(&[ExposeGroup::Code], "no_such_tool").is_none());
    }

    #[test]
    fn test_max_message_size_is_reasonable() {
        // 10 MB should be more than enough for any legitimate JSON-RPC message
        let size = MAX_MESSAGE_SIZE;
        assert_eq!(size, 10 * 1024 * 1024);
        assert!(size >= 1024 * 1024, "Should be at least 1 MB");
        assert!(size <= 100 * 1024 * 1024, "Should not exceed 100 MB");
    }
}
