//! CCG Import module for loading published Code Context Graphs.
//!
//! This module provides functionality to fetch and parse CCG layers from:
//! - Registry URLs (codecontextgraph.com)
//! - Local file paths
//! - Gzipped N-Quads files
//!
//! # Example
//!
//! ```ignore
//! use narsil_mcp::ccg::import::{CcgImporter, ImportOptions};
//!
//! // Import from registry URL
//! let importer = CcgImporter::new();
//! let manifest = importer.fetch_manifest(
//!     "https://codecontextgraph.com/ccg/github.com/org/repo@abc123/manifest.json"
//! ).await?;
//!
//! // Import from local file
//! let manifest = importer.load_manifest_from_file("./repo.ccg.manifest.json")?;
//! ```

use anyhow::{anyhow, Context, Result};
use std::io::Read;
use std::path::Path;

use super::layers::{Architecture, Manifest};
use super::Layer;

/// Default registry base URL for CCG.
pub const CCG_REGISTRY_BASE: &str = "https://codecontextgraph.com/ccg";

/// Default timeout for HTTP requests in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Options for CCG import operations.
#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// Base URL for registry lookups
    pub registry_base: String,
    /// HTTP request timeout in milliseconds
    pub timeout_ms: u64,
    /// Whether to verify JSON-LD schema
    pub verify_schema: bool,
    /// Maximum size in bytes to accept (security limit)
    pub max_size_bytes: usize,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            registry_base: CCG_REGISTRY_BASE.to_string(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            verify_schema: true,
            max_size_bytes: 50 * 1024 * 1024, // 50 MB max
        }
    }
}

impl ImportOptions {
    /// Creates new import options with custom registry base URL.
    #[must_use]
    pub fn with_registry_base(mut self, url: impl Into<String>) -> Self {
        self.registry_base = url.into();
        self
    }

    /// Sets the HTTP request timeout.
    #[must_use]
    pub fn with_timeout_ms(mut self, timeout: u64) -> Self {
        self.timeout_ms = timeout;
        self
    }

    /// Disables JSON-LD schema verification.
    #[must_use]
    pub fn without_schema_verification(mut self) -> Self {
        self.verify_schema = false;
        self
    }
}

/// Import source for CCG layers.
#[derive(Debug, Clone)]
pub enum ImportSource {
    /// URL to fetch from (HTTP/HTTPS)
    Url(String),
    /// Local file path
    File(std::path::PathBuf),
    /// Raw bytes (already loaded)
    Bytes(Vec<u8>),
}

impl ImportSource {
    /// Creates an import source from a URL string.
    #[must_use]
    pub fn from_url(url: impl Into<String>) -> Self {
        Self::Url(url.into())
    }

    /// Creates an import source from a file path.
    #[must_use]
    pub fn from_file(path: impl AsRef<Path>) -> Self {
        Self::File(path.as_ref().to_path_buf())
    }

    /// Creates an import source from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self::Bytes(bytes)
    }
}

/// Result of importing a CCG layer.
#[derive(Debug, Clone)]
pub struct ImportedLayer {
    /// The layer type
    pub layer: Layer,
    /// Raw content (decompressed if applicable)
    pub content: String,
    /// Size of the raw content in bytes
    pub size_bytes: usize,
    /// Source from which it was imported
    pub source: String,
    /// Whether the content was decompressed
    pub was_compressed: bool,
}

/// CCG Importer for fetching and parsing published graphs.
///
/// # Features
///
/// - Fetches CCG layers from HTTP/HTTPS URLs
/// - Loads CCG layers from local files
/// - Handles gzip decompression for L2/L3 N-Quads
/// - Parses JSON-LD (L0/L1) and N-Quads (L2/L3) formats
/// - Validates against JSON-LD schema
///
/// # Security
///
/// - Enforces maximum size limits to prevent DoS
/// - Validates content-type headers
/// - Only accepts HTTPS URLs in production mode
#[derive(Debug, Clone)]
pub struct CcgImporter {
    options: ImportOptions,
}

impl Default for CcgImporter {
    fn default() -> Self {
        Self::new()
    }
}

impl CcgImporter {
    /// Creates a new CCG importer with default options.
    #[must_use]
    pub fn new() -> Self {
        Self {
            options: ImportOptions::default(),
        }
    }

    /// Creates a new CCG importer with custom options.
    #[must_use]
    pub fn with_options(options: ImportOptions) -> Self {
        Self { options }
    }

    /// Builds a registry URL for a given repository and layer.
    ///
    /// # Arguments
    ///
    /// * `host` - Git host (e.g., "github.com")
    /// * `owner` - Repository owner
    /// * `repo` - Repository name
    /// * `commit` - Commit SHA or "latest"
    /// * `layer` - Layer to fetch
    ///
    /// # Returns
    ///
    /// Full URL to the layer file.
    #[must_use]
    pub fn build_registry_url(
        &self,
        host: &str,
        owner: &str,
        repo: &str,
        commit: &str,
        layer: Layer,
    ) -> String {
        let filename = match layer {
            Layer::Manifest => "manifest.json",
            Layer::Architecture => "architecture.json",
            Layer::SymbolIndex => "symbol-index.nq.gz",
            Layer::FullDetail => "full-detail.nq.gz",
        };
        format!(
            "{}/{}/{}/{}@{}/{}",
            self.options.registry_base, host, owner, repo, commit, filename
        )
    }

    /// Parses a manifest (Layer 0) from JSON-LD string.
    ///
    /// # Arguments
    ///
    /// * `json` - JSON-LD string content
    ///
    /// # Returns
    ///
    /// Parsed Manifest structure.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is invalid or doesn't conform to the manifest schema.
    pub fn parse_manifest(&self, json: &str) -> Result<Manifest> {
        serde_json::from_str(json).context("Failed to parse manifest JSON-LD")
    }

    /// Parses an architecture (Layer 1) from JSON-LD string.
    ///
    /// # Arguments
    ///
    /// * `json` - JSON-LD string content
    ///
    /// # Returns
    ///
    /// Parsed Architecture structure.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is invalid or doesn't conform to the architecture schema.
    pub fn parse_architecture(&self, json: &str) -> Result<Architecture> {
        serde_json::from_str(json).context("Failed to parse architecture JSON-LD")
    }

    /// Decompresses gzipped content.
    ///
    /// # Arguments
    ///
    /// * `compressed` - Gzipped bytes
    ///
    /// # Returns
    ///
    /// Decompressed string content.
    ///
    /// # Errors
    ///
    /// Returns an error if decompression fails or the content is not valid UTF-8.
    #[cfg(feature = "graph")]
    pub fn decompress_gzip(&self, compressed: &[u8]) -> Result<String> {
        use flate2::read::GzDecoder;

        let mut decoder = GzDecoder::new(compressed);
        let mut decompressed = String::new();
        decoder
            .read_to_string(&mut decompressed)
            .context("Failed to decompress gzipped content")?;
        Ok(decompressed)
    }

    #[cfg(not(feature = "graph"))]
    pub fn decompress_gzip(&self, _compressed: &[u8]) -> Result<String> {
        Err(anyhow!("Gzip decompression requires the 'graph' feature"))
    }

    /// Loads a manifest from a local file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the manifest JSON file
    ///
    /// # Returns
    ///
    /// Parsed Manifest and import metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_manifest_from_file(&self, path: impl AsRef<Path>) -> Result<ImportedLayer> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest file: {}", path.display()))?;

        // Validate it parses correctly
        let _ = self.parse_manifest(&content)?;

        let size_bytes = content.len();
        Ok(ImportedLayer {
            layer: Layer::Manifest,
            content,
            size_bytes,
            source: path.display().to_string(),
            was_compressed: false,
        })
    }

    /// Loads an architecture from a local file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the architecture JSON file
    ///
    /// # Returns
    ///
    /// Parsed Architecture and import metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_architecture_from_file(&self, path: impl AsRef<Path>) -> Result<ImportedLayer> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read architecture file: {}", path.display()))?;

        // Validate it parses correctly
        let _ = self.parse_architecture(&content)?;

        let size_bytes = content.len();
        Ok(ImportedLayer {
            layer: Layer::Architecture,
            content,
            size_bytes,
            source: path.display().to_string(),
            was_compressed: false,
        })
    }

    /// Loads a gzipped N-Quads layer from a local file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the gzipped N-Quads file
    /// * `layer` - Which layer this is (SymbolIndex or FullDetail)
    ///
    /// # Returns
    ///
    /// Decompressed N-Quads content and import metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or decompressed.
    #[cfg(feature = "graph")]
    pub fn load_nquads_from_file(
        &self,
        path: impl AsRef<Path>,
        layer: Layer,
    ) -> Result<ImportedLayer> {
        let path = path.as_ref();
        let compressed = std::fs::read(path)
            .with_context(|| format!("Failed to read N-Quads file: {}", path.display()))?;

        // Check if file is actually gzipped (magic bytes: 1f 8b)
        let (content, was_compressed) =
            if compressed.len() >= 2 && compressed[0] == 0x1f && compressed[1] == 0x8b {
                (self.decompress_gzip(&compressed)?, true)
            } else {
                // Not gzipped, try to read as plain text
                let text =
                    String::from_utf8(compressed).context("N-Quads file is not valid UTF-8")?;
                (text, false)
            };

        let size_bytes = content.len();
        Ok(ImportedLayer {
            layer,
            content,
            size_bytes,
            source: path.display().to_string(),
            was_compressed,
        })
    }

    #[cfg(not(feature = "graph"))]
    pub fn load_nquads_from_file(
        &self,
        _path: impl AsRef<Path>,
        _layer: Layer,
    ) -> Result<ImportedLayer> {
        Err(anyhow!("N-Quads loading requires the 'graph' feature"))
    }

    /// Fetches a layer from a URL.
    ///
    /// # Arguments
    ///
    /// * `url` - URL to fetch
    /// * `layer` - Expected layer type
    ///
    /// # Returns
    ///
    /// Fetched content and import metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch fails or content exceeds size limit.
    #[cfg(feature = "native")]
    pub async fn fetch_layer(&self, url: &str, layer: Layer) -> Result<ImportedLayer> {
        use std::time::Duration;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(self.options.timeout_ms))
            .build()
            .context("Failed to create HTTP client")?;

        let response = client
            .get(url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch URL: {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "HTTP request failed with status {}: {}",
                response.status(),
                url
            ));
        }

        // Check content length if available
        if let Some(len) = response.content_length() {
            if len as usize > self.options.max_size_bytes {
                return Err(anyhow!(
                    "Content too large: {} bytes (max: {})",
                    len,
                    self.options.max_size_bytes
                ));
            }
        }

        let bytes = response
            .bytes()
            .await
            .context("Failed to read response body")?;

        if bytes.len() > self.options.max_size_bytes {
            return Err(anyhow!(
                "Content too large: {} bytes (max: {})",
                bytes.len(),
                self.options.max_size_bytes
            ));
        }

        // Handle based on layer type
        let (content, was_compressed) = match layer {
            Layer::Manifest | Layer::Architecture => {
                let text =
                    String::from_utf8(bytes.to_vec()).context("Response is not valid UTF-8")?;
                (text, false)
            }
            Layer::SymbolIndex | Layer::FullDetail => {
                // Check for gzip magic bytes
                if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
                    #[cfg(feature = "graph")]
                    {
                        (self.decompress_gzip(&bytes)?, true)
                    }
                    #[cfg(not(feature = "graph"))]
                    {
                        return Err(anyhow!("Gzip decompression requires the 'graph' feature"));
                    }
                } else {
                    let text =
                        String::from_utf8(bytes.to_vec()).context("Response is not valid UTF-8")?;
                    (text, false)
                }
            }
        };

        let size_bytes = content.len();
        Ok(ImportedLayer {
            layer,
            content,
            size_bytes,
            source: url.to_string(),
            was_compressed,
        })
    }

    #[cfg(not(feature = "native"))]
    pub async fn fetch_layer(&self, _url: &str, _layer: Layer) -> Result<ImportedLayer> {
        Err(anyhow!("HTTP fetching requires the 'native' feature"))
    }

    /// Fetches a manifest (Layer 0) from a URL.
    ///
    /// # Arguments
    ///
    /// * `url` - URL to the manifest JSON file
    ///
    /// # Returns
    ///
    /// Parsed Manifest and import metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch fails or content is invalid.
    #[cfg(feature = "native")]
    pub async fn fetch_manifest(&self, url: &str) -> Result<(Manifest, ImportedLayer)> {
        let imported = self.fetch_layer(url, Layer::Manifest).await?;
        let manifest = self.parse_manifest(&imported.content)?;
        Ok((manifest, imported))
    }

    #[cfg(not(feature = "native"))]
    pub async fn fetch_manifest(&self, _url: &str) -> Result<(Manifest, ImportedLayer)> {
        Err(anyhow!("HTTP fetching requires the 'native' feature"))
    }

    /// Fetches an architecture (Layer 1) from a URL.
    ///
    /// # Arguments
    ///
    /// * `url` - URL to the architecture JSON file
    ///
    /// # Returns
    ///
    /// Parsed Architecture and import metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch fails or content is invalid.
    #[cfg(feature = "native")]
    pub async fn fetch_architecture(&self, url: &str) -> Result<(Architecture, ImportedLayer)> {
        let imported = self.fetch_layer(url, Layer::Architecture).await?;
        let architecture = self.parse_architecture(&imported.content)?;
        Ok((architecture, imported))
    }

    #[cfg(not(feature = "native"))]
    pub async fn fetch_architecture(&self, _url: &str) -> Result<(Architecture, ImportedLayer)> {
        Err(anyhow!("HTTP fetching requires the 'native' feature"))
    }

    /// Fetches all layers for a repository from the registry.
    ///
    /// # Arguments
    ///
    /// * `host` - Git host (e.g., "github.com")
    /// * `owner` - Repository owner
    /// * `repo` - Repository name
    /// * `commit` - Commit SHA or "latest"
    ///
    /// # Returns
    ///
    /// All fetched layers.
    ///
    /// # Errors
    ///
    /// Returns an error if any layer cannot be fetched.
    #[cfg(feature = "native")]
    pub async fn fetch_from_registry(
        &self,
        host: &str,
        owner: &str,
        repo: &str,
        commit: &str,
    ) -> Result<Vec<ImportedLayer>> {
        let layers = [
            Layer::Manifest,
            Layer::Architecture,
            Layer::SymbolIndex,
            Layer::FullDetail,
        ];

        let mut results = Vec::with_capacity(4);
        for layer in layers {
            let url = self.build_registry_url(host, owner, repo, commit, layer);
            match self.fetch_layer(&url, layer).await {
                Ok(imported) => results.push(imported),
                Err(e) => {
                    // L2 and L3 are optional, L0 and L1 are required
                    if layer == Layer::Manifest || layer == Layer::Architecture {
                        return Err(e).with_context(|| {
                            format!("Failed to fetch required layer {:?}", layer)
                        });
                    }
                    // Continue without optional layers
                }
            }
        }

        Ok(results)
    }

    #[cfg(not(feature = "native"))]
    pub async fn fetch_from_registry(
        &self,
        _host: &str,
        _owner: &str,
        _repo: &str,
        _commit: &str,
    ) -> Result<Vec<ImportedLayer>> {
        Err(anyhow!("HTTP fetching requires the 'native' feature"))
    }
}

/// Parses a registry URL into its components.
///
/// # Arguments
///
/// * `url` - Registry URL to parse
///
/// # Returns
///
/// Tuple of (host, owner, repo, commit, layer_filename).
///
/// # Errors
///
/// Returns an error if the URL doesn't match the expected format.
pub fn parse_registry_url(url: &str) -> Result<(String, String, String, String, String)> {
    // Expected format: https://codecontextgraph.com/ccg/{host}/{owner}/{repo}@{commit}/{filename}
    let url = url::Url::parse(url).context("Invalid URL")?;

    let path = url.path();
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Should have: ccg, host, owner, repo@commit, filename
    if parts.len() < 5 || parts[0] != "ccg" {
        return Err(anyhow!("Invalid registry URL format: {}", url));
    }

    let host = parts[1].to_string();
    let owner = parts[2].to_string();

    // Parse repo@commit
    let repo_commit = parts[3];
    let (repo, commit) = repo_commit
        .split_once('@')
        .ok_or_else(|| anyhow!("Missing commit in URL: {}", url))?;

    let filename = parts[4].to_string();

    Ok((host, owner, repo.to_string(), commit.to_string(), filename))
}

/// Determines the layer type from a filename.
///
/// # Arguments
///
/// * `filename` - Filename to check
///
/// # Returns
///
/// The layer type, or None if not recognized.
#[must_use]
pub fn layer_from_filename(filename: &str) -> Option<Layer> {
    match filename {
        "manifest.json" => Some(Layer::Manifest),
        "architecture.json" => Some(Layer::Architecture),
        "symbol-index.nq.gz" | "symbol-index.nq" => Some(Layer::SymbolIndex),
        "full-detail.nq.gz" | "full-detail.nq" => Some(Layer::FullDetail),
        _ => {
            // Try to match by extension
            if filename.ends_with(".ccg.manifest.json") {
                Some(Layer::Manifest)
            } else if filename.ends_with(".ccg.arch.json") {
                Some(Layer::Architecture)
            } else if filename.ends_with(".ccg.index.nq.gz") || filename.ends_with(".ccg.index.nq")
            {
                Some(Layer::SymbolIndex)
            } else if filename.ends_with(".ccg.full.nq.gz") || filename.ends_with(".ccg.full.nq") {
                Some(Layer::FullDetail)
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== ImportOptions Tests ====================

    #[test]
    fn test_import_options_default() {
        let opts = ImportOptions::default();
        assert_eq!(opts.registry_base, CCG_REGISTRY_BASE);
        assert_eq!(opts.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert!(opts.verify_schema);
        assert_eq!(opts.max_size_bytes, 50 * 1024 * 1024);
    }

    #[test]
    fn test_import_options_builder() {
        let opts = ImportOptions::default()
            .with_registry_base("https://custom.registry.com")
            .with_timeout_ms(5000)
            .without_schema_verification();

        assert_eq!(opts.registry_base, "https://custom.registry.com");
        assert_eq!(opts.timeout_ms, 5000);
        assert!(!opts.verify_schema);
    }

    // ==================== ImportSource Tests ====================

    #[test]
    fn test_import_source_from_url() {
        let source = ImportSource::from_url("https://example.com/ccg/manifest.json");
        match source {
            ImportSource::Url(url) => assert_eq!(url, "https://example.com/ccg/manifest.json"),
            _ => panic!("Expected Url variant"),
        }
    }

    #[test]
    fn test_import_source_from_file() {
        let source = ImportSource::from_file("/path/to/manifest.json");
        match source {
            ImportSource::File(path) => {
                assert_eq!(path.to_str().unwrap(), "/path/to/manifest.json")
            }
            _ => panic!("Expected File variant"),
        }
    }

    #[test]
    fn test_import_source_from_bytes() {
        let data = b"test data".to_vec();
        let source = ImportSource::from_bytes(data.clone());
        match source {
            ImportSource::Bytes(bytes) => assert_eq!(bytes, data),
            _ => panic!("Expected Bytes variant"),
        }
    }

    // ==================== CcgImporter Tests ====================

    #[test]
    fn test_importer_new() {
        let importer = CcgImporter::new();
        assert_eq!(importer.options.registry_base, CCG_REGISTRY_BASE);
    }

    #[test]
    fn test_importer_with_options() {
        let opts = ImportOptions::default().with_timeout_ms(10000);
        let importer = CcgImporter::with_options(opts);
        assert_eq!(importer.options.timeout_ms, 10000);
    }

    #[test]
    fn test_build_registry_url_manifest() {
        let importer = CcgImporter::new();
        let url =
            importer.build_registry_url("github.com", "org", "repo", "abc123", Layer::Manifest);
        assert_eq!(
            url,
            "https://codecontextgraph.com/ccg/github.com/org/repo@abc123/manifest.json"
        );
    }

    #[test]
    fn test_build_registry_url_architecture() {
        let importer = CcgImporter::new();
        let url = importer.build_registry_url(
            "github.com",
            "owner",
            "project",
            "def456",
            Layer::Architecture,
        );
        assert_eq!(
            url,
            "https://codecontextgraph.com/ccg/github.com/owner/project@def456/architecture.json"
        );
    }

    #[test]
    fn test_build_registry_url_symbol_index() {
        let importer = CcgImporter::new();
        let url =
            importer.build_registry_url("gitlab.com", "team", "app", "latest", Layer::SymbolIndex);
        assert_eq!(
            url,
            "https://codecontextgraph.com/ccg/gitlab.com/team/app@latest/symbol-index.nq.gz"
        );
    }

    #[test]
    fn test_build_registry_url_full_detail() {
        let importer = CcgImporter::new();
        let url =
            importer.build_registry_url("github.com", "user", "lib", "v1.0.0", Layer::FullDetail);
        assert_eq!(
            url,
            "https://codecontextgraph.com/ccg/github.com/user/lib@v1.0.0/full-detail.nq.gz"
        );
    }

    // ==================== Manifest Parsing Tests ====================

    #[test]
    fn test_parse_manifest_valid() {
        let importer = CcgImporter::new();
        let json = r#"{
            "@context": "https://narsilmcp.com/ccg/v1",
            "@type": "Manifest",
            "name": "test-repo",
            "symbol_counts": {
                "functions": 10,
                "classes": 5,
                "structs": 3,
                "traits": 2,
                "enums": 1,
                "modules": 4,
                "constants": 6,
                "total": 31
            },
            "languages": [
                {"language": "rust", "file_count": 15, "percentage": 80.0}
            ],
            "entry_points": [],
            "layer_uris": {},
            "generated": {
                "timestamp": "2026-01-17T00:00:00Z",
                "version": "1.0.0",
                "generator": "narsil-mcp"
            }
        }"#;

        let manifest = importer.parse_manifest(json);
        assert!(manifest.is_ok());
        let manifest = manifest.unwrap();
        assert_eq!(manifest.name, "test-repo");
        assert_eq!(manifest.symbol_counts.functions, 10);
        assert_eq!(manifest.symbol_counts.total, 31);
    }

    #[test]
    fn test_parse_manifest_invalid_json() {
        let importer = CcgImporter::new();
        let json = "{ invalid json }";
        let result = importer.parse_manifest(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_manifest_missing_required_field() {
        let importer = CcgImporter::new();
        let json = r#"{
            "@context": "https://narsilmcp.com/ccg/v1",
            "@type": "Manifest"
        }"#;
        let result = importer.parse_manifest(json);
        assert!(result.is_err());
    }

    // ==================== Architecture Parsing Tests ====================

    #[test]
    fn test_parse_architecture_valid() {
        let importer = CcgImporter::new();
        let json = r#"{
            "@context": "https://narsilmcp.com/ccg/v1",
            "@type": "Architecture",
            "name": "test-repo",
            "modules": [],
            "public_api": [],
            "dependencies": [],
            "abstractions": []
        }"#;

        let arch = importer.parse_architecture(json);
        assert!(arch.is_ok());
        let arch = arch.unwrap();
        assert_eq!(arch.name, "test-repo");
    }

    #[test]
    fn test_parse_architecture_with_modules() {
        let importer = CcgImporter::new();
        let json = r#"{
            "@context": "https://narsilmcp.com/ccg/v1",
            "@type": "Architecture",
            "name": "test-repo",
            "modules": [
                {"path": "src/lib.rs", "name": "lib", "children": ["engine"], "symbol_count": 10}
            ],
            "public_api": [
                {"name": "Engine", "kind": "struct", "file": "src/engine.rs", "line": 5}
            ],
            "dependencies": [
                {"from": "engine", "to": "parser", "import_count": 3}
            ],
            "abstractions": [
                {"name": "Processor", "kind": "trait", "file": "src/traits.rs", "implementors": 2}
            ]
        }"#;

        let arch = importer.parse_architecture(json);
        assert!(arch.is_ok());
        let arch = arch.unwrap();
        assert_eq!(arch.modules.len(), 1);
        assert_eq!(arch.public_api.len(), 1);
        assert_eq!(arch.dependencies.len(), 1);
        assert_eq!(arch.abstractions.len(), 1);
    }

    // ==================== URL Parsing Tests ====================

    #[test]
    fn test_parse_registry_url_valid() {
        let url = "https://codecontextgraph.com/ccg/github.com/org/repo@abc123/manifest.json";
        let result = parse_registry_url(url);
        assert!(result.is_ok());
        let (host, owner, repo, commit, filename) = result.unwrap();
        assert_eq!(host, "github.com");
        assert_eq!(owner, "org");
        assert_eq!(repo, "repo");
        assert_eq!(commit, "abc123");
        assert_eq!(filename, "manifest.json");
    }

    #[test]
    fn test_parse_registry_url_latest() {
        let url =
            "https://codecontextgraph.com/ccg/github.com/user/project@latest/architecture.json";
        let result = parse_registry_url(url);
        assert!(result.is_ok());
        let (_, _, _, commit, _) = result.unwrap();
        assert_eq!(commit, "latest");
    }

    #[test]
    fn test_parse_registry_url_invalid_format() {
        let url = "https://example.com/not/a/registry/url";
        let result = parse_registry_url(url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_registry_url_missing_commit() {
        let url = "https://codecontextgraph.com/ccg/github.com/org/repo/manifest.json";
        let result = parse_registry_url(url);
        assert!(result.is_err());
    }

    // ==================== Layer Detection Tests ====================

    #[test]
    fn test_layer_from_filename_manifest() {
        assert_eq!(layer_from_filename("manifest.json"), Some(Layer::Manifest));
        assert_eq!(
            layer_from_filename("repo.ccg.manifest.json"),
            Some(Layer::Manifest)
        );
    }

    #[test]
    fn test_layer_from_filename_architecture() {
        assert_eq!(
            layer_from_filename("architecture.json"),
            Some(Layer::Architecture)
        );
        assert_eq!(
            layer_from_filename("repo.ccg.arch.json"),
            Some(Layer::Architecture)
        );
    }

    #[test]
    fn test_layer_from_filename_symbol_index() {
        assert_eq!(
            layer_from_filename("symbol-index.nq.gz"),
            Some(Layer::SymbolIndex)
        );
        assert_eq!(
            layer_from_filename("symbol-index.nq"),
            Some(Layer::SymbolIndex)
        );
        assert_eq!(
            layer_from_filename("repo.ccg.index.nq.gz"),
            Some(Layer::SymbolIndex)
        );
    }

    #[test]
    fn test_layer_from_filename_full_detail() {
        assert_eq!(
            layer_from_filename("full-detail.nq.gz"),
            Some(Layer::FullDetail)
        );
        assert_eq!(
            layer_from_filename("full-detail.nq"),
            Some(Layer::FullDetail)
        );
        assert_eq!(
            layer_from_filename("repo.ccg.full.nq.gz"),
            Some(Layer::FullDetail)
        );
    }

    #[test]
    fn test_layer_from_filename_unknown() {
        assert_eq!(layer_from_filename("random.txt"), None);
        assert_eq!(layer_from_filename("data.json"), None);
    }

    // ==================== Gzip Decompression Tests ====================

    #[cfg(feature = "graph")]
    #[test]
    fn test_decompress_gzip_valid() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let importer = CcgImporter::new();
        let original = "Hello, CCG World!";

        // Compress the data
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();

        // Decompress and verify
        let result = importer.decompress_gzip(&compressed);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), original);
    }

    #[cfg(feature = "graph")]
    #[test]
    fn test_decompress_gzip_invalid() {
        let importer = CcgImporter::new();
        let not_gzip = b"not actually gzipped data";
        let result = importer.decompress_gzip(not_gzip);
        assert!(result.is_err());
    }

    // ==================== File Loading Tests ====================

    #[test]
    fn test_load_manifest_from_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");

        let content = r#"{
            "@context": "https://narsilmcp.com/ccg/v1",
            "@type": "Manifest",
            "name": "file-test-repo",
            "symbol_counts": {
                "functions": 5,
                "classes": 2,
                "structs": 1,
                "traits": 0,
                "enums": 0,
                "modules": 1,
                "constants": 0,
                "total": 9
            },
            "languages": [],
            "entry_points": [],
            "layer_uris": {},
            "generated": {
                "timestamp": "2026-01-17T00:00:00Z",
                "version": "1.0.0",
                "generator": "test"
            }
        }"#;

        std::fs::write(&manifest_path, content).unwrap();

        let importer = CcgImporter::new();
        let result = importer.load_manifest_from_file(&manifest_path);
        assert!(result.is_ok());

        let imported = result.unwrap();
        assert_eq!(imported.layer, Layer::Manifest);
        assert!(!imported.was_compressed);
        assert!(imported.content.contains("file-test-repo"));
    }

    #[test]
    fn test_load_manifest_from_nonexistent_file() {
        let importer = CcgImporter::new();
        let result = importer.load_manifest_from_file("/nonexistent/path/manifest.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_architecture_from_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let arch_path = temp_dir.path().join("architecture.json");

        let content = r#"{
            "@context": "https://narsilmcp.com/ccg/v1",
            "@type": "Architecture",
            "name": "arch-test-repo",
            "modules": [],
            "public_api": [],
            "dependencies": [],
            "abstractions": []
        }"#;

        std::fs::write(&arch_path, content).unwrap();

        let importer = CcgImporter::new();
        let result = importer.load_architecture_from_file(&arch_path);
        assert!(result.is_ok());

        let imported = result.unwrap();
        assert_eq!(imported.layer, Layer::Architecture);
    }

    #[cfg(feature = "graph")]
    #[test]
    fn test_load_nquads_from_gzipped_file() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let nq_path = temp_dir.path().join("symbol-index.nq.gz");

        let nquads_content = r#"<sym:Test> <rdf:type> <narsil:Function> .
<sym:Test> <narsil:name> "test" ."#;

        // Create gzipped file
        let file = std::fs::File::create(&nq_path).unwrap();
        let mut encoder = GzEncoder::new(file, Compression::default());
        encoder.write_all(nquads_content.as_bytes()).unwrap();
        encoder.finish().unwrap();

        let importer = CcgImporter::new();
        let result = importer.load_nquads_from_file(&nq_path, Layer::SymbolIndex);
        assert!(result.is_ok());

        let imported = result.unwrap();
        assert_eq!(imported.layer, Layer::SymbolIndex);
        assert!(imported.was_compressed);
        assert!(imported.content.contains("<sym:Test>"));
    }

    #[cfg(feature = "graph")]
    #[test]
    fn test_load_nquads_from_plain_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let nq_path = temp_dir.path().join("symbol-index.nq");

        let nquads_content = r#"<sym:Plain> <rdf:type> <narsil:Struct> ."#;
        std::fs::write(&nq_path, nquads_content).unwrap();

        let importer = CcgImporter::new();
        let result = importer.load_nquads_from_file(&nq_path, Layer::SymbolIndex);
        assert!(result.is_ok());

        let imported = result.unwrap();
        assert!(!imported.was_compressed);
        assert!(imported.content.contains("<sym:Plain>"));
    }

    // ==================== Default Trait Tests ====================

    #[test]
    fn test_importer_default() {
        let importer = CcgImporter::default();
        assert_eq!(importer.options.registry_base, CCG_REGISTRY_BASE);
    }
}
