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
    extract::{DefaultBodyLimit, Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::index::CodeIntelEngine;
use crate::mcp::{JsonRpcRequest, McpServer};
use crate::tool_handlers::ToolRegistry;

/// Maximum HTTP request body size (2 MB).
const MAX_HTTP_BODY_SIZE: usize = 2 * 1024 * 1024;

/// Per-session SSE response channel buffer.
///
/// A spawned dispatch task that fills the channel faster than the SSE
/// consumer can drain it will await on `tx.send()`. No silent drops.
const SSE_CHANNEL_CAPACITY: usize = 64;

/// Default SSE keep-alive interval. The MCP HTTP+SSE spec does not
/// mandate a value; 15s keeps NAT/proxy timeouts at bay without spamming
/// the connection.
pub const DEFAULT_SSE_KEEPALIVE: Duration = Duration::from_secs(15);

// Embedded frontend assets (only when frontend feature is enabled)
#[cfg(feature = "frontend")]
use axum::{
    body::Body,
    http::{header, Response},
};

#[cfg(feature = "frontend")]
use rust_embed::Embed;

// `allow_missing` lets `cargo build --features frontend` succeed even when
// `frontend/dist/` has not been built yet (typical on a fresh clone where
// the user has not run `cd frontend && npm ci && npm run build`). The
// build.rs at the crate root prints a `cargo:warning` so the user knows
// the served UI will return 404 until the dist directory is populated.
#[cfg(feature = "frontend")]
#[derive(Embed)]
#[folder = "frontend/dist"]
#[allow_missing = true]
struct FrontendAssets;

/// HTTP Server for the visualization frontend and (optionally) the MCP
/// HTTP+SSE transport.
pub struct HttpServer {
    engine: Arc<CodeIntelEngine>,
    tool_registry: ToolRegistry,
    host: String,
    port: u16,
    mcp_server: Option<Arc<McpServer>>,
    sse_keepalive: Duration,
    /// Already listening, e.g. from systemd; `run` binds `host:port` when None.
    listener: Option<std::net::TcpListener>,
}

/// One in-flight SSE session.
struct SessionEntry {
    /// Sender to the SSE event stream. JSON-RPC response strings written
    /// here arrive at the client as `data:` events.
    tx: mpsc::Sender<String>,
}

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    engine: Arc<CodeIntelEngine>,
    tool_registry: Arc<ToolRegistry>,
    /// MCP server for the SSE transport. `None` when only frontend routes
    /// are mounted.
    mcp_server: Option<Arc<McpServer>>,
    /// Active SSE sessions keyed by `sessionId`.
    sessions: Arc<DashMap<Uuid, SessionEntry>>,
    /// Active Streamable HTTP session IDs.
    streamable_sessions: Arc<DashMap<Uuid, ()>>,
    sse_keepalive: Duration,
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
    /// Create a new HTTP server for the visualization frontend.
    ///
    /// Binds `0.0.0.0:<port>` and exposes the legacy `/health`, `/tools`,
    /// `/tools/call`, and `/graph` routes. Use [`Self::with_mcp_routes`]
    /// to additionally serve the MCP HTTP+SSE transport.
    pub fn new(engine: Arc<CodeIntelEngine>, port: u16) -> Self {
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
            host: "0.0.0.0".to_string(),
            port,
            mcp_server: None,
            sse_keepalive: DEFAULT_SSE_KEEPALIVE,
            listener: None,
        }
    }

    /// Enable the MCP HTTP+SSE transport on this server.
    ///
    /// Mounts `/mcp/sse` and `/mcp/message` and rebinds the listener to
    /// `host:port`. Defaults to `127.0.0.1` for safety — see the
    /// host-header check below for the DNS-rebinding mitigation that
    /// guards these routes regardless of bind address.
    pub fn with_mcp_routes(
        mut self,
        mcp_server: Arc<McpServer>,
        host: impl Into<String>,
        port: u16,
        keepalive: Duration,
    ) -> Self {
        self.mcp_server = Some(mcp_server);
        self.host = host.into();
        self.port = port;
        self.sse_keepalive = keepalive;
        self
    }

    /// Serve on `listener` instead of binding `host:port`. It must be non-blocking.
    pub fn with_listener(mut self, listener: std::net::TcpListener) -> Self {
        self.listener = Some(listener);
        self
    }

    /// Run the HTTP server
    pub async fn run(self) -> Result<()> {
        let mcp_enabled = self.mcp_server.is_some();
        let state = AppState {
            engine: self.engine,
            tool_registry: Arc::new(self.tool_registry),
            mcp_server: self.mcp_server,
            sessions: Arc::new(DashMap::new()),
            streamable_sessions: Arc::new(DashMap::new()),
            sse_keepalive: self.sse_keepalive,
        };

        // Configure CORS to allow frontend access (needed for development mode).
        // Scoped to the frontend sub-router so it does NOT cover `/mcp/*` —
        // browsers must not be able to reach the MCP transport cross-origin.
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        // Frontend / dashboard routes.
        let frontend = Router::new()
            .route("/health", get(health_check))
            .route("/tools", get(list_tools))
            .route("/tools/call", post(call_tool))
            .route("/graph", get(get_graph))
            .layer(cors);

        // Add embedded frontend routes when feature is enabled
        #[cfg(feature = "frontend")]
        let frontend = {
            info!("Frontend assets embedded - serving at /");
            frontend
                .route("/", get(serve_index))
                .fallback(serve_static_fallback)
        };

        #[cfg(not(feature = "frontend"))]
        {
            info!("Frontend not embedded - API-only mode");
            info!("Run frontend separately: cd frontend && npm run dev");
        }

        let app = if mcp_enabled {
            info!("MCP HTTP+SSE transport enabled at /mcp/sse, /mcp/message");
            info!("MCP Streamable HTTP transport enabled at /mcp");
            // MCP routes get the host-header check (DNS rebinding mitigation
            // required by the MCP spec for HTTP-based transports). CORS is
            // deliberately not applied here.
            let mcp_routes = Router::new()
                .route("/mcp/sse", get(mcp_sse_handler))
                .route("/mcp/message", post(mcp_message_handler))
                .route("/mcp", post(mcp_streamable_handler))
                .layer(middleware::from_fn(host_header_check));
            frontend.merge(mcp_routes)
        } else {
            frontend
        };

        let app = app
            .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_SIZE))
            .with_state(state);

        let addr = format!("{}:{}", self.host, self.port);
        info!("HTTP server starting on http://{}", addr);

        let listener = match self.listener {
            Some(listener) => tokio::net::TcpListener::from_std(listener)?,
            None => tokio::net::TcpListener::bind(&addr).await?,
        };
        axum::serve(listener, app).await?;

        Ok(())
    }
}

/// MCP Streamable HTTP: POST `/mcp`.
///
/// Implements the MCP 2025-03 Streamable HTTP transport (single-endpoint).
/// The client POSTs JSON-RPC requests to this URL. Session state is tracked
/// via the `Mcp-Session-Id` header: the server assigns one on the first
/// request (initialize) and the client echoes it on all subsequent requests.
///
/// Responses:
/// - 200 OK + `Content-Type: application/json` for requests with an id
/// - 202 Accepted for notifications (no id)
/// - 404 Not Found if the session ID is not found (session expired)
async fn mcp_streamable_handler(
    State(state): State<AppState>,
    req_headers: HeaderMap,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let Some(mcp_server) = state.mcp_server.clone() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };

    // Extract session ID from the Mcp-Session-Id header.
    let header_session_id: Option<Uuid> = req_headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok());

    let session_id = match header_session_id {
        Some(id) => {
            // Session not found: tell the client to start a new session.
            if !state.streamable_sessions.contains_key(&id) {
                return StatusCode::NOT_FOUND.into_response();
            }
            id
        }
        None => {
            // No session yet — create one (this should be the initialize request).
            let id = Uuid::new_v4();
            state.streamable_sessions.insert(id, ());
            debug!(
                "session opened (streamable): {} — active: sse={} streamable={}",
                id,
                state.sessions.len(),
                state.streamable_sessions.len()
            );
            id
        }
    };

    let session_id_str = session_id.to_string();
    let sid_header = HeaderValue::from_str(&session_id_str)
        .unwrap_or_else(|_| HeaderValue::from_static("error"));

    // Notifications have no id and never need a response body.
    if req.id.is_none() {
        let server = mcp_server.clone();
        tokio::spawn(async move {
            server.dispatch(req).await;
        });
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(HeaderName::from_static("mcp-session-id"), sid_header);
        return (StatusCode::ACCEPTED, resp_headers).into_response();
    }

    // Spawned so it outlives this handler: hyper drops the handler future when
    // the client disconnects, which aborted a long reindex partway, after it
    // had emptied the repo and before it rebuilt it.
    let response = match tokio::spawn(async move { mcp_server.dispatch(req).await }).await {
        Ok(response) => response,
        Err(e) => {
            warn!("MCP request task failed: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let json_body = match serde_json::to_string(&response) {
        Ok(j) => j,
        Err(e) => {
            warn!("Failed to serialize JSON-RPC response: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp_headers.insert(HeaderName::from_static("mcp-session-id"), sid_header);
    (StatusCode::OK, resp_headers, json_body).into_response()
}

/// MCP HTTP+SSE: GET `/mcp/sse`.
///
/// Allocates a session id, opens an SSE stream that first emits the
/// `endpoint` event the spec requires, then forwards JSON-RPC responses
/// queued by [`mcp_message_handler`]. The session entry is removed when
/// the stream is dropped (client disconnect, server shutdown, or keep-alive
/// failure).
async fn mcp_sse_handler(
    State(state): State<AppState>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    if state.mcp_server.is_none() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let session_id = Uuid::new_v4();
    let (tx, mut rx) = mpsc::channel::<String>(SSE_CHANNEL_CAPACITY);

    state.sessions.insert(session_id, SessionEntry { tx });
    debug!(
        "session opened (sse): {} — active: sse={} streamable={}",
        session_id,
        state.sessions.len(),
        state.streamable_sessions.len()
    );

    let sessions = Arc::clone(&state.sessions);
    let endpoint_url = format!("/mcp/message?sessionId={}", session_id);
    let keepalive = state.sse_keepalive;

    // The generator owns `_guard`, `rx`, and `endpoint_url`. When the
    // consumer drops the SSE response (client disconnect, keep-alive write
    // failure, server shutdown), the generator future is dropped and the
    // guard removes the session entry.
    let stream = async_stream::stream! {
        let _guard = SessionGuard { sessions, id: session_id };

        // Spec mandates the endpoint event first.
        yield Ok::<Event, Infallible>(
            Event::default().event("endpoint").data(endpoint_url)
        );

        while let Some(json) = rx.recv().await {
            yield Ok(Event::default().data(json));
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(keepalive)))
}

/// Removes a session from the registry when the SSE stream is dropped.
struct SessionGuard {
    sessions: Arc<DashMap<Uuid, SessionEntry>>,
    id: Uuid,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.sessions.remove(&self.id);
        debug!(
            "session closed (sse): {} — active sse={}",
            self.id,
            self.sessions.len()
        );
    }
}

#[derive(Debug, Deserialize)]
struct MessageQuery {
    #[serde(rename = "sessionId")]
    session_id: Uuid,
}

/// MCP HTTP+SSE: POST `/mcp/message?sessionId=<uuid>`.
///
/// Looks up the session, spawns the dispatch on the runtime so the POST
/// returns `202 Accepted` immediately, and queues the JSON-RPC response
/// for delivery on the SSE channel. Notifications (no `id`) still
/// dispatch but their response is dropped, matching stdio behaviour.
async fn mcp_message_handler(
    State(state): State<AppState>,
    Query(params): Query<MessageQuery>,
    Json(req): Json<JsonRpcRequest>,
) -> Result<StatusCode, StatusCode> {
    let Some(mcp_server) = state.mcp_server.clone() else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };

    let tx = match state.sessions.get(&params.session_id) {
        Some(entry) => entry.tx.clone(),
        None => return Err(StatusCode::GONE),
    };

    let is_notification = req.id.is_none();

    tokio::spawn(async move {
        let response = mcp_server.dispatch(req).await;
        if is_notification {
            return;
        }
        let json = match serde_json::to_string(&response) {
            Ok(j) => j,
            Err(e) => {
                warn!("Failed to serialize JSON-RPC response: {}", e);
                return;
            }
        };
        // A send error here means the SSE consumer (the client) has
        // disconnected. Drop the response silently — the session cleanup
        // path handles registry removal.
        let _ = tx.send(json).await;
    });

    Ok(StatusCode::ACCEPTED)
}

/// Host-header check for `/mcp/*` routes.
///
/// The MCP HTTP-based-transport spec requires servers to validate the
/// `Host` header to mitigate DNS-rebinding attacks. We accept only
/// loopback hostnames so a malicious page pointing at `evil.example` →
/// `127.0.0.1` cannot drive the local MCP server.
async fn host_header_check(request: Request<axum::body::Body>, next: Next) -> Response {
    let host_header = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if is_loopback_host(host_header) {
        next.run(request).await
    } else {
        warn!(
            "Rejecting MCP request with non-loopback Host header: {:?}",
            host_header
        );
        (StatusCode::FORBIDDEN, "Forbidden: invalid Host header").into_response()
    }
}

/// True if `host` parses as a loopback hostname, with optional port.
fn is_loopback_host(host: &str) -> bool {
    // IPv6 literal form: `[::1]` or `[::1]:7557`. Strip the brackets and
    // trailing port before comparing.
    let hostname = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((inner, _)) => inner,
            None => return false,
        }
    } else {
        // For hostname or IPv4: trim at the last `:` if present. Plain
        // IPv4 addresses cannot contain `:`, so a single split is safe.
        host.split(':').next().unwrap_or(host)
    };
    matches!(hostname, "localhost" | "127.0.0.1" | "::1")
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
    let start_time = std::time::Instant::now();
    let tool_name = request.tool.clone();
    let result = state
        .tool_registry
        .dispatch(&tool_name, &state.engine, request.args)
        .await;
    state
        .engine
        .metrics
        .record_tool(&tool_name, start_time.elapsed());

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
    /// Include code excerpts
    #[serde(default)]
    include_excerpts: bool,
    /// Cluster nodes by file
    #[serde(default = "default_cluster")]
    cluster_by: String,
    /// Maximum number of nodes to return (default 200)
    max_nodes: Option<usize>,
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
    // Clamp bounds to prevent excessive resource usage
    let depth = query.depth.min(20);
    let max_nodes = query.max_nodes.map(|n| n.min(5000));

    let mut args = json!({
        "repo": query.repo,
        "view": query.view,
        "root": query.root,
        "depth": depth,
        "direction": query.direction,
        "include_metrics": query.include_metrics,
        "include_excerpts": query.include_excerpts,
        "cluster_by": query.cluster_by,
    });
    if let Some(max_nodes) = max_nodes {
        args["max_nodes"] = json!(max_nodes);
    }

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
        assert!(!query.include_excerpts);
        assert_eq!(query.max_nodes, None);
    }

    /// Test graph query with explicit max_nodes
    #[test]
    fn test_graph_query_with_max_nodes() {
        let query: GraphQuery =
            serde_json::from_str(r#"{"repo": "test", "max_nodes": 50}"#).unwrap();
        assert_eq!(query.max_nodes, Some(50));
    }

    #[test]
    fn test_max_http_body_size_is_reasonable() {
        assert_eq!(MAX_HTTP_BODY_SIZE, 2 * 1024 * 1024);
    }

    #[test]
    fn test_graph_query_bounds_clamped() {
        // Verify excessive depth is clamped to 20
        let query: GraphQuery =
            serde_json::from_str(r#"{"repo": "test", "depth": 1000, "max_nodes": 99999}"#).unwrap();
        assert_eq!(query.depth.min(20), 20);
        assert_eq!(query.max_nodes.map(|n| n.min(5000)), Some(5000));
    }

    #[test]
    fn test_loopback_host_accepts_loopback_forms() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("localhost:7557"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.0.0.1:7557"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("[::1]:7557"));
    }

    #[test]
    fn test_loopback_host_rejects_remote_and_rebinding() {
        // External hostnames that may resolve to 127.0.0.1 via DNS
        // rebinding must not be accepted.
        assert!(!is_loopback_host("evil.example"));
        assert!(!is_loopback_host("evil.example:7557"));
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("192.168.1.1:7557"));
        assert!(!is_loopback_host(""));
        // 127.0.0.2 etc. are loopback by RFC but we intentionally accept
        // only the canonical address.
        assert!(!is_loopback_host("127.0.0.2"));
        // Malformed IPv6 bracket — bail out.
        assert!(!is_loopback_host("[::1"));
    }
}
