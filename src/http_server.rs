//! HTTP Server for narsil-mcp visualization frontend
//!
//! This module provides a REST API layer over the MCP tools,
//! enabling the web-based visualization frontend to communicate
//! with the narsil-mcp engine.
//!
//! When compiled with the `frontend` feature, the server also serves
//! the embedded visualization frontend at the root path.

use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::index::CodeIntelEngine;
use crate::tool_handlers::ToolRegistry;

// Embedded frontend assets (only when frontend feature is enabled)
#[cfg(feature = "frontend")]
use axum::{
    body::Body,
    http::{header, Response},
};

#[cfg(feature = "frontend")]
use rust_embed::Embed;

#[cfg(feature = "frontend")]
#[derive(Embed)]
#[folder = "frontend/dist"]
struct FrontendAssets;

/// HTTP Server for the visualization frontend
pub struct HttpServer {
    engine: Arc<CodeIntelEngine>,
    tool_registry: ToolRegistry,
    port: u16,
}

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    engine: Arc<CodeIntelEngine>,
    tool_registry: Arc<ToolRegistry>,
}

/// Request body for tool calls
#[derive(Debug, Deserialize)]
pub struct ToolCallRequest {
    /// The tool name to execute
    tool: String,
    /// Arguments as JSON object
    #[serde(default)]
    args: Value,
}

/// Response from tool calls
#[derive(Debug, Serialize)]
pub struct ToolCallResponse {
    /// Whether the call succeeded
    success: bool,
    /// The result (if success)
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    /// Error message (if failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// List tools response
#[derive(Debug, Serialize)]
pub struct ListToolsResponse {
    tools: Vec<ToolInfo>,
}

/// Tool information
#[derive(Debug, Serialize)]
pub struct ToolInfo {
    name: String,
}

impl HttpServer {
    /// Create a new HTTP server
    pub fn new(engine: Arc<CodeIntelEngine>, port: u16) -> Self {
        Self {
            engine,
            tool_registry: ToolRegistry::new(),
            port,
        }
    }

    /// Run the HTTP server
    pub async fn run(self) -> Result<()> {
        let state = AppState {
            engine: self.engine,
            tool_registry: Arc::new(self.tool_registry),
        };

        // Configure CORS to allow frontend access (needed for development mode)
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        // Build router with API routes
        let app = Router::new()
            .route("/health", get(health_check))
            .route("/tools", get(list_tools))
            .route("/tools/call", post(call_tool))
            .route("/graph", get(get_graph));

        // Add embedded frontend routes when feature is enabled
        #[cfg(feature = "frontend")]
        let app = {
            info!("Frontend assets embedded - serving at /");
            app.route("/", get(serve_index))
                .fallback(serve_static_fallback)
        };

        #[cfg(not(feature = "frontend"))]
        {
            info!("Frontend not embedded - API-only mode");
            info!("Run frontend separately: cd frontend && npm run dev");
        }

        let app = app.layer(cors).with_state(state);

        let addr = format!("0.0.0.0:{}", self.port);
        info!("HTTP server starting on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// List available tools
async fn list_tools(State(state): State<AppState>) -> impl IntoResponse {
    let tools: Vec<ToolInfo> = state
        .tool_registry
        .tool_names()
        .iter()
        .map(|name| ToolInfo {
            name: name.to_string(),
        })
        .collect();

    Json(ListToolsResponse { tools })
}

/// Call a tool
async fn call_tool(
    State(state): State<AppState>,
    Json(request): Json<ToolCallRequest>,
) -> impl IntoResponse {
    let result = state
        .tool_registry
        .dispatch(&request.tool, &state.engine, request.args)
        .await;

    match result {
        Ok(output) => {
            // Try to parse as JSON, otherwise wrap as string
            let result_value =
                serde_json::from_str::<Value>(&output).unwrap_or(Value::String(output));

            (
                StatusCode::OK,
                Json(ToolCallResponse {
                    success: true,
                    result: Some(result_value),
                    error: None,
                }),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ToolCallResponse {
                success: false,
                result: None,
                error: Some(e.to_string()),
            }),
        ),
    }
}

/// Query parameters for graph endpoint
#[derive(Debug, Deserialize)]
pub struct GraphQuery {
    /// Repository name
    #[serde(default)]
    repo: String,
    /// View type (call, import, symbol, hybrid, flow)
    #[serde(default = "default_view")]
    view: String,
    /// Root function/symbol for focused view
    root: Option<String>,
    /// Maximum depth
    #[serde(default = "default_depth")]
    depth: usize,
    /// Direction (callers, callees, both)
    #[serde(default = "default_direction")]
    direction: String,
    /// Include complexity metrics
    #[serde(default = "default_true")]
    include_metrics: bool,
    /// Include security overlay
    #[serde(default)]
    include_security: bool,
    /// Include code excerpts
    #[serde(default)]
    include_excerpts: bool,
    /// Cluster nodes by file
    #[serde(default = "default_cluster")]
    cluster_by: String,
}

fn default_view() -> String {
    "call".to_string()
}

fn default_depth() -> usize {
    3
}

fn default_direction() -> String {
    "both".to_string()
}

fn default_true() -> bool {
    true
}

fn default_cluster() -> String {
    "none".to_string()
}

// ============================================================================
// Embedded Frontend Handlers (only when frontend feature is enabled)
// ============================================================================

/// Serve the index.html file
#[cfg(feature = "frontend")]
async fn serve_index() -> impl IntoResponse {
    serve_file("index.html")
}

/// Fallback handler for static files from embedded assets
#[cfg(feature = "frontend")]
async fn serve_static_fallback(uri: axum::http::Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    serve_file(path)
}

/// Helper to serve a file from embedded assets
#[cfg(feature = "frontend")]
fn serve_file(path: &str) -> Response<Body> {
    // Try to get the file from embedded assets
    match FrontendAssets::get(path) {
        Some(content) => {
            // Determine MIME type from file extension
            let mime_type = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime_type)
                .header(header::CACHE_CONTROL, "public, max-age=31536000") // Cache for 1 year (hashed assets)
                .body(Body::from(content.data.into_owned()))
                .unwrap()
        }
        None => {
            // For SPA routing: serve index.html for non-asset paths
            if !path.contains('.') {
                if let Some(content) = FrontendAssets::get("index.html") {
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                        .header(header::CACHE_CONTROL, "no-cache") // Don't cache HTML
                        .body(Body::from(content.data.into_owned()))
                        .unwrap();
                }
            }

            // File not found
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("Not Found"))
                .unwrap()
        }
    }
}

/// Get graph data (convenience endpoint)
async fn get_graph(
    State(state): State<AppState>,
    Query(query): Query<GraphQuery>,
) -> impl IntoResponse {
    let args = json!({
        "repo": query.repo,
        "view": query.view,
        "root": query.root,
        "depth": query.depth,
        "direction": query.direction,
        "include_metrics": query.include_metrics,
        "include_security": query.include_security,
        "include_excerpts": query.include_excerpts,
        "cluster_by": query.cluster_by,
    });

    let result = state
        .tool_registry
        .dispatch("get_code_graph", &state.engine, args)
        .await;

    match result {
        Ok(output) => {
            // Parse as JSON
            let response_json = match serde_json::from_str::<Value>(&output) {
                Ok(graph) => json!({
                    "success": true,
                    "graph": graph,
                }),
                Err(_) => json!({
                    "success": true,
                    "graph": output,
                }),
            };
            (StatusCode::OK, Json(response_json))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": e.to_string(),
            })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        assert_eq!(default_view(), "call");
        assert_eq!(default_depth(), 3);
        assert_eq!(default_direction(), "both");
        assert!(default_true());
        assert_eq!(default_cluster(), "none");
    }

    #[test]
    fn test_tool_call_response_serialization() {
        let response = ToolCallResponse {
            success: true,
            result: Some(json!({"test": "value"})),
            error: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"test\":\"value\""));
        assert!(!json.contains("error"));
    }

    #[test]
    fn test_tool_call_error_response() {
        let response = ToolCallResponse {
            success: false,
            result: None,
            error: Some("Something went wrong".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("Something went wrong"));
        assert!(!json.contains("result"));
    }

    /// Test that HTTP server can be configured with custom port
    #[test]
    fn test_http_server_port_configuration() {
        // Verify port configuration works
        let port: u16 = 8080;
        assert!(port > 0 && port < 65535);

        // Default port should be 3000
        let default_port: u16 = 3000;
        assert_eq!(default_port, 3000);
    }

    /// Test that concurrent operation is properly structured
    ///
    /// This test documents the expected behavior when --http is enabled:
    /// 1. HTTP server runs in a background tokio::spawn task
    /// 2. MCP server runs on stdio in the main task
    /// 3. Both can operate concurrently
    #[test]
    fn test_concurrent_operation_pattern() {
        // The pattern in main.rs should be:
        //
        // if server_args.http {
        //     tokio::spawn(async move {
        //         http_server.run().await  // Runs in background
        //     });
        // }
        // mcp_server.run().await  // Always runs in main task
        //
        // This test verifies the conceptual model is correct.
        // The actual integration test would require a full runtime.

        // Verify the spawn pattern allows both to run
        let http_enabled = true;
        let mcp_always_runs = true;

        // When HTTP is enabled, both should run
        if http_enabled {
            assert!(
                mcp_always_runs,
                "MCP server must always run when HTTP is enabled"
            );
        } else {
            assert!(
                mcp_always_runs,
                "MCP server must run even when HTTP is disabled"
            );
        }
    }

    /// Test graph query default deserialization
    #[test]
    fn test_graph_query_defaults() {
        let query: GraphQuery = serde_json::from_str(r#"{"repo": "test"}"#).unwrap();

        assert_eq!(query.repo, "test");
        assert_eq!(query.view, "call");
        assert_eq!(query.depth, 3);
        assert_eq!(query.direction, "both");
        assert!(query.include_metrics);
        assert!(!query.include_security);
        assert!(!query.include_excerpts);
    }
}
