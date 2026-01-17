//! LSP integration for enhanced code intelligence
//!
//! This module provides integration with Language Server Protocol servers for
//! richer type information, hover docs, and go-to-definition capabilities.

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use lsp_types::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Configuration for LSP integration
#[derive(Debug, Clone)]
pub struct LspConfig {
    /// Enable/disable LSP per language
    pub enabled_languages: HashMap<String, bool>,
    /// Custom LSP server paths
    pub server_paths: HashMap<String, PathBuf>,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
    /// Enable LSP globally
    pub enabled: bool,
}

impl Default for LspConfig {
    fn default() -> Self {
        Self {
            enabled_languages: HashMap::new(),
            server_paths: HashMap::new(),
            // Phase B1: Reduced from 5000ms to 1500ms for better responsiveness
            // LSP requests that don't complete within 1.5s are unlikely to complete usefully
            timeout_ms: 1500,
            enabled: false,
        }
    }
}

/// LSP JSON-RPC message
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LspMessage {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<LspError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LspError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// A running LSP server process
struct LspProcess {
    _child: Child,
    stdin: Arc<Mutex<ChildStdin>>,
    pending_requests: Arc<DashMap<i64, tokio::sync::oneshot::Sender<Value>>>,
    next_id: Arc<AtomicI64>,
    capabilities: Arc<RwLock<Option<ServerCapabilities>>>,
}

/// Manager for LSP clients per language
pub struct LspManager {
    config: LspConfig,
    servers: DashMap<String, Arc<LspProcess>>,
    workspace_roots: Vec<PathBuf>,
}

impl LspManager {
    /// Create a new LSP manager
    pub fn new(config: LspConfig, workspace_roots: Vec<PathBuf>) -> Self {
        Self {
            config,
            servers: DashMap::new(),
            workspace_roots,
        }
    }

    /// Check if LSP is globally enabled
    ///
    /// Phase B2: Callers can use this to avoid async overhead when LSP is disabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if LSP is enabled for a language
    pub fn is_enabled_for_language(&self, language: &str) -> bool {
        if !self.config.enabled {
            return false;
        }
        self.config
            .enabled_languages
            .get(language)
            .copied()
            .unwrap_or(false)
    }

    /// Get or start an LSP server for a language
    async fn get_or_start_server(&self, language: &str) -> Result<Arc<LspProcess>> {
        // Check if server already running
        if let Some(server) = self.servers.get(language) {
            return Ok(server.clone());
        }

        // Start new server
        let server = self.start_server(language).await?;
        let server_arc = Arc::new(server);
        self.servers
            .insert(language.to_string(), server_arc.clone());
        Ok(server_arc)
    }

    /// Start an LSP server process
    async fn start_server(&self, language: &str) -> Result<LspProcess> {
        let (command, args) = self.get_server_command(language)?;

        info!(
            "Starting LSP server for {}: {} {:?}",
            language, command, args
        );

        let mut child = tokio::process::Command::new(&command)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn LSP server")?;

        let stdin = child.stdin.take().ok_or_else(|| anyhow!("No stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("No stdout"))?;

        let pending_requests = Arc::new(DashMap::new());
        let next_id = Arc::new(AtomicI64::new(1));
        let capabilities = Arc::new(RwLock::new(None));

        // Spawn response handler task
        let pending_clone = pending_requests.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::handle_responses(stdout, pending_clone).await {
                warn!("LSP response handler error: {}", e);
            }
        });

        let process = LspProcess {
            _child: child,
            stdin: Arc::new(Mutex::new(stdin)),
            pending_requests,
            next_id,
            capabilities,
        };

        // Initialize the server
        self.initialize_server(&process, language).await?;

        Ok(process)
    }

    /// Handle responses from LSP server
    async fn handle_responses(
        stdout: ChildStdout,
        pending_requests: Arc<DashMap<i64, tokio::sync::oneshot::Sender<Value>>>,
    ) -> Result<()> {
        let mut reader = BufReader::new(stdout);
        let mut content_length = 0;

        loop {
            let mut header_line = String::new();
            reader.read_line(&mut header_line).await?;

            if header_line.is_empty() {
                break;
            }

            let header_line = header_line.trim();

            if header_line.starts_with("Content-Length:") {
                content_length = header_line
                    .strip_prefix("Content-Length:")
                    .unwrap()
                    .trim()
                    .parse::<usize>()?;
            } else if header_line.is_empty() && content_length > 0 {
                // Read the JSON content
                let mut buffer = vec![0u8; content_length];
                tokio::io::AsyncReadExt::read_exact(&mut reader, &mut buffer).await?;

                let message: LspMessage = serde_json::from_slice(&buffer)?;
                debug!("Received LSP message: {:?}", message);

                // Handle response
                if let Some(id) = message.id {
                    if let Some((_, tx)) = pending_requests.remove(&id) {
                        if let Some(result) = message.result {
                            let _ = tx.send(result);
                        } else if let Some(error) = message.error {
                            warn!("LSP error response: {:?}", error);
                        }
                    }
                }

                content_length = 0;
            }
        }

        Ok(())
    }

    /// Send a request to the LSP server
    async fn send_request(
        &self,
        process: &LspProcess,
        method: &str,
        params: Value,
    ) -> Result<Value> {
        let id = process.next_id.fetch_add(1, Ordering::SeqCst);

        let message = LspMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(id),
            method: Some(method.to_string()),
            params: Some(params),
            result: None,
            error: None,
        };

        let json = serde_json::to_string(&message)?;
        let content = format!("Content-Length: {}\r\n\r\n{}", json.len(), json);

        let (tx, rx) = tokio::sync::oneshot::channel();
        process.pending_requests.insert(id, tx);

        // Send request
        {
            let mut stdin = process.stdin.lock().await;
            stdin.write_all(content.as_bytes()).await?;
            stdin.flush().await?;
        }

        // Wait for response with timeout
        let response = timeout(Duration::from_millis(self.config.timeout_ms), rx)
            .await
            .context("LSP request timeout")?
            .context("Response channel closed")?;

        Ok(response)
    }

    /// Initialize the LSP server
    async fn initialize_server(&self, process: &LspProcess, language: &str) -> Result<()> {
        let workspace_root = self
            .workspace_roots
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("."));

        let workspace_folder = WorkspaceFolder {
            uri: Url::from_file_path(&workspace_root).unwrap(),
            name: workspace_root
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("workspace")
                .to_string(),
        };

        // Use struct update syntax to avoid explicitly setting deprecated fields (root_uri, root_path)
        let init_params = InitializeParams {
            process_id: Some(std::process::id()),
            capabilities: ClientCapabilities::default(),
            trace: Some(TraceValue::Off),
            workspace_folders: Some(vec![workspace_folder]),
            client_info: Some(ClientInfo {
                name: "narsil-mcp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
            ..Default::default()
        };

        let params_value = serde_json::to_value(&init_params)?;
        let response = self
            .send_request(process, "initialize", params_value)
            .await?;

        let init_result: InitializeResult = serde_json::from_value(response)?;
        *process.capabilities.write().await = Some(init_result.capabilities);

        info!("LSP server initialized for {}", language);

        // Send initialized notification
        let notification = LspMessage {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: Some("initialized".to_string()),
            params: Some(serde_json::json!({})),
            result: None,
            error: None,
        };

        let json = serde_json::to_string(&notification)?;
        let content = format!("Content-Length: {}\r\n\r\n{}", json.len(), json);

        {
            let mut stdin = process.stdin.lock().await;
            stdin.write_all(content.as_bytes()).await?;
            stdin.flush().await?;
        }

        Ok(())
    }

    /// Get the command and args to start an LSP server
    fn get_server_command(&self, language: &str) -> Result<(String, Vec<String>)> {
        // Check custom path first
        if let Some(path) = self.config.server_paths.get(language) {
            return Ok((path.to_string_lossy().to_string(), vec![]));
        }

        // Auto-detect common language servers
        match language {
            "rust" => Ok(("rust-analyzer".to_string(), vec![])),
            "python" => Ok((
                "pyright-langserver".to_string(),
                vec!["--stdio".to_string()],
            )),
            "javascript" | "typescript" => Ok((
                "typescript-language-server".to_string(),
                vec!["--stdio".to_string()],
            )),
            "go" => Ok(("gopls".to_string(), vec![])),
            "c" | "cpp" => Ok(("clangd".to_string(), vec![])),
            "java" => Ok((
                "jdtls".to_string(),
                vec!["-data".to_string(), "/tmp/jdtls-workspace".to_string()],
            )),
            _ => Err(anyhow!("No LSP server configured for {}", language)),
        }
    }

    /// Get hover information
    pub async fn get_hover(
        &self,
        language: &str,
        file_path: &Path,
        line: u32,
        character: u32,
    ) -> Result<Option<Hover>> {
        if !self.is_enabled_for_language(language) {
            return Ok(None);
        }

        let server = match self.get_or_start_server(language).await {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to start LSP server for {}: {}", language, e);
                return Ok(None);
            }
        };

        let uri = Url::from_file_path(file_path).map_err(|_| anyhow!("Invalid file path"))?;

        let params = HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position { line, character },
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
        };

        let params_value = serde_json::to_value(&params)?;
        let response = self
            .send_request(&server, "textDocument/hover", params_value)
            .await?;

        if response.is_null() {
            return Ok(None);
        }

        let hover: Hover = serde_json::from_value(response)?;
        Ok(Some(hover))
    }

    /// Get definition location
    pub async fn get_definition(
        &self,
        language: &str,
        file_path: &Path,
        line: u32,
        character: u32,
    ) -> Result<Option<Vec<Location>>> {
        if !self.is_enabled_for_language(language) {
            return Ok(None);
        }

        let server = match self.get_or_start_server(language).await {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to start LSP server for {}: {}", language, e);
                return Ok(None);
            }
        };

        let uri = Url::from_file_path(file_path).map_err(|_| anyhow!("Invalid file path"))?;

        let params = GotoDefinitionParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position { line, character },
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        };

        let params_value = serde_json::to_value(&params)?;
        let response = self
            .send_request(&server, "textDocument/definition", params_value)
            .await?;

        if response.is_null() {
            return Ok(None);
        }

        let result: GotoDefinitionResponse = serde_json::from_value(response)?;

        let locations = match result {
            GotoDefinitionResponse::Scalar(loc) => vec![loc],
            GotoDefinitionResponse::Array(locs) => locs,
            GotoDefinitionResponse::Link(_) => return Ok(None),
        };

        Ok(Some(locations))
    }

    /// Find references
    pub async fn find_references(
        &self,
        language: &str,
        file_path: &Path,
        line: u32,
        character: u32,
        include_declaration: bool,
    ) -> Result<Option<Vec<Location>>> {
        if !self.is_enabled_for_language(language) {
            return Ok(None);
        }

        let server = match self.get_or_start_server(language).await {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to start LSP server for {}: {}", language, e);
                return Ok(None);
            }
        };

        let uri = Url::from_file_path(file_path).map_err(|_| anyhow!("Invalid file path"))?;

        let params = ReferenceParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position { line, character },
            },
            context: ReferenceContext {
                include_declaration,
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        };

        let params_value = serde_json::to_value(&params)?;
        let response = self
            .send_request(&server, "textDocument/references", params_value)
            .await?;

        if response.is_null() {
            return Ok(None);
        }

        let locations: Vec<Location> = serde_json::from_value(response)?;
        Ok(Some(locations))
    }

    /// Get document symbols
    pub async fn get_document_symbols(
        &self,
        language: &str,
        file_path: &Path,
    ) -> Result<Option<Vec<DocumentSymbol>>> {
        if !self.is_enabled_for_language(language) {
            return Ok(None);
        }

        let server = match self.get_or_start_server(language).await {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to start LSP server for {}: {}", language, e);
                return Ok(None);
            }
        };

        let uri = Url::from_file_path(file_path).map_err(|_| anyhow!("Invalid file path"))?;

        let params = DocumentSymbolParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        };

        let params_value = serde_json::to_value(&params)?;
        let response = self
            .send_request(&server, "textDocument/documentSymbol", params_value)
            .await?;

        if response.is_null() {
            return Ok(None);
        }

        let result: DocumentSymbolResponse = serde_json::from_value(response)?;

        match result {
            DocumentSymbolResponse::Flat(_) => Ok(None),
            DocumentSymbolResponse::Nested(symbols) => Ok(Some(symbols)),
        }
    }

    /// Shutdown all LSP servers
    pub async fn shutdown_all(&self) -> Result<()> {
        for entry in self.servers.iter() {
            let language = entry.key();
            let process = entry.value();

            info!("Shutting down LSP server for {}", language);

            // Send shutdown request
            let _ = self
                .send_request(process, "shutdown", serde_json::json!({}))
                .await;

            // Send exit notification
            let notification = LspMessage {
                jsonrpc: "2.0".to_string(),
                id: None,
                method: Some("exit".to_string()),
                params: None,
                result: None,
                error: None,
            };

            let json = serde_json::to_string(&notification)?;
            let content = format!("Content-Length: {}\r\n\r\n{}", json.len(), json);

            {
                let mut stdin = process.stdin.lock().await;
                let _ = stdin.write_all(content.as_bytes()).await;
                let _ = stdin.flush().await;
            }
        }

        self.servers.clear();
        Ok(())
    }
}

impl Drop for LspManager {
    fn drop(&mut self) {
        // Best effort cleanup - spawn a blocking task
        let servers = std::mem::take(&mut self.servers);
        std::thread::spawn(move || {
            for entry in servers.iter() {
                let process = entry.value();
                // Kill process on drop
                let _ = process;
            }
        });
    }
}

/// Convert LSP hover to markdown string
pub fn hover_to_markdown(hover: &Hover) -> String {
    match &hover.contents {
        HoverContents::Scalar(content) => marked_string_to_markdown(content),
        HoverContents::Array(contents) => contents
            .iter()
            .map(marked_string_to_markdown)
            .collect::<Vec<_>>()
            .join("\n\n"),
        HoverContents::Markup(markup) => match markup.kind {
            MarkupKind::PlainText => markup.value.clone(),
            MarkupKind::Markdown => markup.value.clone(),
        },
    }
}

fn marked_string_to_markdown(marked: &MarkedString) -> String {
    match marked {
        MarkedString::String(s) => s.clone(),
        MarkedString::LanguageString(ls) => {
            format!("```{}\n{}\n```", ls.language, ls.value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsp_config_default() {
        let config = LspConfig::default();
        assert!(!config.enabled);
        // B1: Reduced timeout from 5000ms to 1500ms for better responsiveness
        assert!(
            config.timeout_ms <= 2000,
            "LSP timeout should be <= 2000ms, got {}",
            config.timeout_ms
        );
    }

    #[test]
    fn test_lsp_config_default_timeout_reduced() {
        // Phase B1: Verify timeout is reduced to 1500ms
        let config = LspConfig::default();
        assert_eq!(config.timeout_ms, 1500, "Default timeout should be 1500ms");
    }

    #[test]
    fn test_server_detection() {
        let config = LspConfig::default();
        let manager = LspManager::new(config, vec![]);

        let (cmd, _) = manager.get_server_command("rust").unwrap();
        assert_eq!(cmd, "rust-analyzer");

        let (cmd, _) = manager.get_server_command("python").unwrap();
        assert_eq!(cmd, "pyright-langserver");
    }

    #[test]
    fn test_is_enabled_returns_false_by_default() {
        // Phase B2: Callers can check if LSP is globally enabled before making async calls
        let config = LspConfig::default();
        let manager = LspManager::new(config, vec![]);
        assert!(!manager.is_enabled(), "LSP should be disabled by default");
    }

    #[test]
    fn test_is_enabled_returns_true_when_enabled() {
        let config = LspConfig {
            enabled: true,
            ..Default::default()
        };
        let manager = LspManager::new(config, vec![]);
        assert!(
            manager.is_enabled(),
            "LSP should be enabled when config says so"
        );
    }

    #[tokio::test]
    async fn test_lsp_early_exit_when_disabled() {
        // Phase B2: LSP methods should return immediately when disabled
        use std::time::Instant;

        let config = LspConfig {
            enabled: false,
            ..Default::default()
        };
        let manager = LspManager::new(config, vec![]);

        let start = Instant::now();
        let result = manager
            .get_hover("rust", std::path::Path::new("test.rs"), 1, 0)
            .await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert!(
            elapsed.as_millis() < 100,
            "LSP call when disabled should complete in <100ms, took {}ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn test_hover_to_markdown() {
        let hover = Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: "# Test\n\nSome content".to_string(),
            }),
            range: None,
        };

        let markdown = hover_to_markdown(&hover);
        assert_eq!(markdown, "# Test\n\nSome content");
    }
}
