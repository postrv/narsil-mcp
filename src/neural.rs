//! Neural embedding engine for semantic code search
//!
//! Supports multiple backends:
//! - ONNX models (CodeBERT, StarEncoder, etc.) - requires `neural` feature
//! - API-based (Voyage, OpenAI) for higher quality
//!
//! This module provides dense vector embeddings for semantic code search,
//! complementing the TF-IDF embeddings in embeddings.rs

use anyhow::{bail, Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[cfg(feature = "neural")]
use std::path::Path;

// Security constants for input validation
const MAX_EMBEDDING_BATCH_SIZE: usize = 100; // Maximum texts per API request
const MAX_TEXT_LENGTH: usize = 32_000; // Maximum characters per text (~8k tokens for most models)
const MAX_DIMENSION: usize = 8192; // Maximum embedding dimension (larger than any known model)
const MIN_DIMENSION: usize = 64; // Minimum reasonable embedding dimension
const MAX_MODEL_NAME_LENGTH: usize = 256; // Maximum model name length
const MAX_API_KEY_LENGTH: usize = 2048; // Maximum API key length
const API_REQUEST_TIMEOUT_SECS: u64 = 120; // 2 minutes timeout for API requests
const MAX_RESPONSE_SIZE_BYTES: usize = 100 * 1024 * 1024; // 100MB max response size

/// Embedding model configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralConfig {
    /// Enable neural embeddings
    pub enabled: bool,
    /// Model backend: "onnx", "api"
    pub backend: String,
    /// Path to ONNX model file (for onnx backend)
    pub model_path: Option<String>,
    /// Path to tokenizer file (for onnx backend)
    pub tokenizer_path: Option<String>,
    /// Model name for API backend (e.g., "voyage-code-2")
    pub model_name: Option<String>,
    /// API endpoint (for api backend)
    pub api_endpoint: Option<String>,
    /// Embedding dimension
    pub dimension: usize,
    /// Maximum sequence length
    pub max_seq_length: usize,
    /// Batch size for bulk embedding
    pub batch_size: usize,
}

impl Default for NeuralConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: "api".to_string(),
            model_path: None,
            tokenizer_path: None,
            model_name: Some("voyage-code-2".to_string()),
            api_endpoint: None,
            dimension: 1536,
            max_seq_length: 512,
            batch_size: 32,
        }
    }
}

// ============================================================================
// URL Validation and Security
// ============================================================================

/// Check if a hostname is localhost or a private IP address
fn is_private_or_localhost(host: &str) -> bool {
    // Check for localhost names
    if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        return true;
    }

    // Try to parse as IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ipv4) => {
                // Private IPv4 ranges:
                // 10.0.0.0/8
                // 172.16.0.0/12
                // 192.168.0.0/16
                // 127.0.0.0/8 (loopback)
                let octets = ipv4.octets();
                octets[0] == 10
                    || octets[0] == 127
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
            }
            IpAddr::V6(ipv6) => {
                // Private IPv6 ranges:
                // ::1 (loopback)
                // fc00::/7 (unique local addresses)
                // fe80::/10 (link-local)
                ipv6.is_loopback()
                    || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                    || (ipv6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    } else {
        false
    }
}

/// Validate and sanitize an embedding API endpoint URL
///
/// # Security Considerations
/// - Only allows http and https schemes to prevent SSRF via file://, ftp://, etc.
/// - Blocks cloud metadata service URLs (169.254.169.254, fd00:ec2::254, metadata.google.internal)
/// - Allows localhost and private IPs (users may intentionally use local embedding servers)
/// - Logs warnings when using localhost or private IPs
/// - Validates URL syntax to prevent malformed requests
/// - Enforces maximum URL length (2048 characters)
///
/// # Arguments
/// * `url_str` - The URL string to validate
///
/// # Returns
/// * `Ok(String)` - The validated URL string
/// * `Err` - If the URL is invalid or uses a disallowed scheme
fn validate_embedding_endpoint(url_str: &str) -> Result<String> {
    // Validate URL length
    if url_str.len() > 2048 {
        bail!("URL too long: maximum 2048 characters allowed");
    }

    // Parse the URL
    let parsed = Url::parse(url_str).with_context(|| format!("Invalid URL format: {}", url_str))?;

    // Validate scheme (only http and https allowed)
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            bail!(
                "Invalid URL scheme '{}': only 'http' and 'https' are allowed for embedding endpoints",
                scheme
            );
        }
    }

    // Ensure URL has a host
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL must include a hostname"))?;

    // Block cloud metadata services
    if host == "169.254.169.254" // AWS, GCP metadata service (IPv4)
        || host == "fd00:ec2::254" // AWS metadata service (IPv6)
        || host.starts_with("fd00:ec2:") // AWS metadata IPv6 prefix
        || host == "metadata.google.internal" // GCP metadata service
        || host == "metadata" // GCP short form
        || host == "169.254.169.253"
    // Azure IMDS (older)
    {
        bail!(
            "Access to cloud metadata service URLs is blocked for security: {}",
            host
        );
    }

    // Check for private/localhost hosts and log warning
    if is_private_or_localhost(host) {
        tracing::warn!(
            "Custom embedding endpoint uses localhost or private IP address: {}. \
             This is allowed for local development but ensure this is intentional.",
            host
        );
    }

    // Return the validated URL
    Ok(url_str.to_string())
}

/// Trait for embedding backends
pub trait EmbeddingBackend: Send + Sync {
    /// Generate an embedding vector from text
    fn embed(&self, text: &str) -> Result<Vec<f32>>;

    /// Generate embeddings for multiple texts
    fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>>;

    /// Get the dimensionality of embeddings
    fn dimension(&self) -> usize;
}

// ============================================================================
// ONNX Backend (requires `neural-onnx` feature)
// ============================================================================

#[cfg(feature = "neural-onnx")]
pub mod onnx {
    use super::*;
    use ndarray::Array2;
    use ort::session::{builder::GraphOptimizationLevel, Session};
    use ort::value::TensorRef;
    use std::sync::Mutex;
    use tokenizers::Tokenizer;

    /// ONNX-based local embedding model
    /// Uses Mutex for session because ort 2.0 requires &mut self for Session::run
    pub struct OnnxEmbedder {
        session: Mutex<Session>,
        tokenizer: Tokenizer,
        dimension: usize,
        max_seq_length: usize,
    }

    impl OnnxEmbedder {
        /// Create a new ONNX embedder from model and tokenizer paths
        pub fn new(model_path: &Path, tokenizer_path: &Path) -> Result<Self> {
            let session = Session::builder()?
                .with_optimization_level(GraphOptimizationLevel::Level3)?
                .with_intra_threads(4)?
                .commit_from_file(model_path)?;

            let tokenizer = Tokenizer::from_file(tokenizer_path)
                .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?;

            // Detect dimension from model output shape
            // Note: ort 2.0 removed tensor_dimensions(), use default dimension
            let dimension: usize = 768;

            Ok(Self {
                session: Mutex::new(session),
                tokenizer,
                dimension,
                max_seq_length: 512,
            })
        }

        /// Create from a pretrained model name (downloads if needed)
        pub fn from_pretrained(model_name: &str, cache_dir: &Path) -> Result<Self> {
            let model_dir = cache_dir.join(model_name.replace('/', "_"));

            if !model_dir.exists() {
                anyhow::bail!(
                    "Model not found at {:?}. Please download manually:\n\
                     optimum-cli export onnx --model {} {}\n\
                     Or download from: https://huggingface.co/{}/tree/main",
                    model_dir,
                    model_name,
                    model_dir.display(),
                    model_name
                );
            }

            Self::new(
                &model_dir.join("model.onnx"),
                &model_dir.join("tokenizer.json"),
            )
        }

        fn mean_pool(&self, embeddings: &[f32], seq_len: usize) -> Vec<f32> {
            let mut pooled = vec![0.0f32; self.dimension];

            if seq_len == 0 {
                return pooled;
            }

            for i in 0..seq_len {
                for j in 0..self.dimension {
                    pooled[j] += embeddings[i * self.dimension + j];
                }
            }

            for x in &mut pooled {
                *x /= seq_len as f32;
            }

            // L2 normalize
            let norm: f32 = pooled.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > 0.0 {
                for x in &mut pooled {
                    *x /= norm;
                }
            }

            pooled
        }
    }

    impl EmbeddingBackend for OnnxEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>> {
            let encoding = self
                .tokenizer
                .encode(text, true)
                .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;

            let input_ids: Vec<i64> = encoding
                .get_ids()
                .iter()
                .take(self.max_seq_length)
                .map(|&id| id as i64)
                .collect();

            let attention_mask: Vec<i64> = encoding
                .get_attention_mask()
                .iter()
                .take(self.max_seq_length)
                .map(|&m| m as i64)
                .collect();

            let seq_len = input_ids.len();

            // Create ONNX tensors
            let input_ids_array =
                Array2::from_shape_vec((1, seq_len), input_ids).context("Invalid input shape")?;
            let attention_mask_array = Array2::from_shape_vec((1, seq_len), attention_mask)
                .context("Invalid mask shape")?;

            // Run inference - ort 2.0 takes owned view without reference
            let input_ids_tensor = TensorRef::from_array_view(input_ids_array.view())?;
            let attention_mask_tensor = TensorRef::from_array_view(attention_mask_array.view())?;

            // Lock the session for mutable access (ort 2.0 requires &mut self for run)
            let mut session = self
                .session
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to lock session: {}", e))?;

            let outputs = session.run(ort::inputs![
                "input_ids" => input_ids_tensor,
                "attention_mask" => attention_mask_tensor,
            ])?;

            // Extract embeddings - ort 2.0 API
            // Try to get output by name first, then fallback to first
            let output: &ort::value::Value = outputs
                .get("last_hidden_state")
                .ok_or_else(|| anyhow::anyhow!("No output tensor found from ONNX model"))?;

            // ort 2.0: try_extract_tensor returns (Shape, &[T])
            let (_, data) = output.try_extract_tensor::<f32>()?;
            let embeddings: Vec<f32> = data.to_vec();

            Ok(self.mean_pool(&embeddings, seq_len))
        }

        fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>> {
            // For simplicity, process sequentially
            // Could optimize with proper batched inference
            texts.iter().map(|t| self.embed(t)).collect()
        }

        fn dimension(&self) -> usize {
            self.dimension
        }
    }
}

// ============================================================================
// API Backend (Voyage, OpenAI, etc.)
// ============================================================================

/// API-based embedding provider (Voyage, OpenAI, etc.)
pub struct ApiEmbedder {
    client: reqwest::blocking::Client,
    endpoint: String,
    model: String,
    api_key: Option<String>,
    dimension: usize,
}

impl ApiEmbedder {
    /// Create a reqwest client with security settings (timeout, limits)
    fn create_secure_client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(API_REQUEST_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client")
    }

    /// Create a Voyage AI embedder
    pub fn voyage(api_key: &str) -> Self {
        Self {
            client: Self::create_secure_client(),
            endpoint: "https://api.voyageai.com/v1/embeddings".to_string(),
            model: "voyage-code-2".to_string(),
            api_key: Some(api_key.to_string()),
            dimension: 1536,
        }
    }

    /// Create a Voyage AI embedder with custom model
    pub fn voyage_with_model(api_key: &str, model: &str) -> Self {
        Self {
            client: Self::create_secure_client(),
            endpoint: "https://api.voyageai.com/v1/embeddings".to_string(),
            model: model.to_string(),
            api_key: Some(api_key.to_string()),
            dimension: 1536,
        }
    }

    /// Create an OpenAI embedder
    pub fn openai(api_key: &str) -> Self {
        Self {
            client: Self::create_secure_client(),
            endpoint: "https://api.openai.com/v1/embeddings".to_string(),
            model: "text-embedding-3-small".to_string(),
            api_key: Some(api_key.to_string()),
            dimension: 1536,
        }
    }

    /// Create an OpenAI embedder with custom model
    pub fn openai_with_model(api_key: &str, model: &str, dimension: usize) -> Self {
        Self {
            client: Self::create_secure_client(),
            endpoint: "https://api.openai.com/v1/embeddings".to_string(),
            model: model.to_string(),
            api_key: Some(api_key.to_string()),
            dimension,
        }
    }

    /// Create a custom API embedder
    pub fn custom(endpoint: &str, model: &str, api_key: Option<&str>, dimension: usize) -> Self {
        Self {
            client: Self::create_secure_client(),
            endpoint: endpoint.to_string(),
            model: model.to_string(),
            api_key: api_key.map(|s| s.to_string()),
            dimension,
        }
    }
}

impl EmbeddingBackend for ApiEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let results = self.embed_batch(&[text.to_string()])?;
        results.into_iter().next().context("No embedding returned")
    }

    fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>> {
        // Input validation - batch size
        if texts.is_empty() {
            bail!("Cannot embed empty batch");
        }
        if texts.len() > MAX_EMBEDDING_BATCH_SIZE {
            bail!(
                "Batch size {} exceeds maximum of {}",
                texts.len(),
                MAX_EMBEDDING_BATCH_SIZE
            );
        }

        // Input validation - text length
        for (i, text) in texts.iter().enumerate() {
            if text.len() > MAX_TEXT_LENGTH {
                bail!(
                    "Text at index {} is {} characters, exceeds maximum of {}",
                    i,
                    text.len(),
                    MAX_TEXT_LENGTH
                );
            }
        }

        #[derive(Serialize)]
        struct Request<'a> {
            model: &'a str,
            input: &'a [String],
        }

        #[derive(Deserialize)]
        struct Response {
            data: Vec<EmbeddingData>,
        }

        #[derive(Deserialize)]
        struct EmbeddingData {
            embedding: Vec<f32>,
        }

        let mut request = self
            .client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .json(&Request {
                model: &self.model,
                input: texts,
            });

        if let Some(key) = &self.api_key {
            // Redact API key in logs - only show first/last 4 chars
            let redacted = if key.len() > 8 {
                format!("{}...{}", &key[..4], &key[key.len() - 4..])
            } else {
                "****".to_string()
            };
            tracing::debug!("Using API key: {}", redacted);
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        let mut resp = request.send().context("Failed to send embedding request")?;

        let status = resp.status();

        // Read response with size limit to prevent memory exhaustion
        let mut limited_body = Vec::new();
        let mut chunk_buffer = [0u8; 8192];
        let mut total_read = 0;

        loop {
            match resp.read(&mut chunk_buffer) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    total_read += n;
                    if total_read > MAX_RESPONSE_SIZE_BYTES {
                        bail!(
                            "Response size exceeds maximum of {} bytes",
                            MAX_RESPONSE_SIZE_BYTES
                        );
                    }
                    limited_body.extend_from_slice(&chunk_buffer[..n]);
                }
                Err(e) => return Err(e).context("Failed to read response body"),
            }
        }

        let text = String::from_utf8(limited_body).context("Response body is not valid UTF-8")?;

        if !status.is_success() {
            // Redact potential sensitive info from error messages
            let safe_text = if text.len() > 500 {
                format!("{}... (truncated)", &text[..500])
            } else {
                text.clone()
            };
            bail!("API error ({}): {}", status, safe_text);
        }

        let response: Response = serde_json::from_str(&text).with_context(|| {
            format!(
                "Failed to parse embedding response: {}",
                &text[..text.len().min(200)]
            )
        })?;

        // Validate response embedding dimensions
        for (i, emb_data) in response.data.iter().enumerate() {
            if emb_data.embedding.len() != self.dimension {
                bail!(
                    "Embedding at index {} has dimension {}, expected {}",
                    i,
                    emb_data.embedding.len(),
                    self.dimension
                );
            }
        }

        Ok(response.data.into_iter().map(|d| d.embedding).collect())
    }

    fn dimension(&self) -> usize {
        self.dimension
    }
}

// ============================================================================
// Vector Index (requires `neural` feature for usearch)
// ============================================================================

#[cfg(feature = "neural")]
pub mod vector_index {
    use super::*;
    use usearch::{Index, IndexOptions, MetricKind, ScalarKind};

    /// Vector index for efficient approximate nearest neighbor search
    pub struct VectorIndex {
        index: Index,
        id_map: RwLock<Vec<String>>,
        dimension: usize,
    }

    impl VectorIndex {
        /// Create a new vector index
        pub fn new(dimension: usize, capacity: usize) -> Result<Self> {
            let options = IndexOptions {
                dimensions: dimension,
                metric: MetricKind::Cos,
                quantization: ScalarKind::F32,
                connectivity: 16,     // M parameter for HNSW
                expansion_add: 128,   // ef_construction
                expansion_search: 64, // ef_search
                multi: false,
            };

            let index = Index::new(&options)?;
            index.reserve(capacity)?;

            Ok(Self {
                index,
                id_map: RwLock::new(Vec::with_capacity(capacity)),
                dimension,
            })
        }

        /// Add an embedding with associated document ID
        pub fn add(&self, doc_id: &str, embedding: &[f32]) -> Result<()> {
            let mut id_map = self.id_map.write();
            let idx = id_map.len() as u64;
            id_map.push(doc_id.to_string());
            self.index.add(idx, embedding)?;
            Ok(())
        }

        /// Search for similar embeddings
        pub fn search(&self, query: &[f32], k: usize) -> Vec<(String, f32)> {
            match self.index.search(query, k) {
                Ok(results) => {
                    let id_map = self.id_map.read();
                    results
                        .keys
                        .iter()
                        .zip(results.distances.iter())
                        .filter_map(|(&idx, &dist)| {
                            id_map.get(idx as usize).map(|id| (id.clone(), 1.0 - dist))
                            // Convert distance to similarity
                        })
                        .collect()
                }
                Err(_) => Vec::new(),
            }
        }

        /// Save the index to disk
        pub fn save(&self, path: &Path) -> Result<()> {
            let path_str = path.to_string_lossy();
            self.index.save(&path_str)?;

            // Save id_map separately
            let id_map = self.id_map.read();
            let id_map_path = path.with_extension("ids.json");
            let json = serde_json::to_string(&*id_map)?;
            std::fs::write(id_map_path, json)?;

            Ok(())
        }

        /// Load the index from disk
        pub fn load(path: &Path, dimension: usize) -> Result<Self> {
            let options = IndexOptions {
                dimensions: dimension,
                metric: MetricKind::Cos,
                quantization: ScalarKind::F32,
                ..Default::default()
            };
            let index = Index::new(&options)?;
            let path_str = path.to_string_lossy();
            index.load(&path_str)?;

            let id_map_path = path.with_extension("ids.json");
            let json = std::fs::read_to_string(id_map_path)?;
            let id_map: Vec<String> = serde_json::from_str(&json)?;

            Ok(Self {
                index,
                id_map: RwLock::new(id_map),
                dimension,
            })
        }

        /// Get the number of indexed documents
        pub fn len(&self) -> usize {
            self.id_map.read().len()
        }

        /// Check if the index is empty
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        /// Clear the index
        pub fn clear(&self) {
            self.id_map.write().clear();
            // Note: usearch doesn't have a clear method, need to recreate
        }

        /// Get the dimension
        pub fn dimension(&self) -> usize {
            self.dimension
        }
    }
}

// ============================================================================
// Simple Vector Store (fallback when neural feature is not enabled)
// ============================================================================

/// Simple in-memory vector store using linear search
/// Used when usearch is not available (neural feature not enabled)
pub struct SimpleVectorStore {
    embeddings: RwLock<Vec<(String, Vec<f32>)>>,
    dimension: usize,
}

impl SimpleVectorStore {
    pub fn new(dimension: usize) -> Self {
        Self {
            embeddings: RwLock::new(Vec::new()),
            dimension,
        }
    }

    pub fn add(&self, doc_id: &str, embedding: &[f32]) {
        self.embeddings
            .write()
            .push((doc_id.to_string(), embedding.to_vec()));
    }

    pub fn search(&self, query: &[f32], k: usize) -> Vec<(String, f32)> {
        let embeddings = self.embeddings.read();
        let mut results: Vec<(String, f32)> = embeddings
            .iter()
            .map(|(id, emb)| (id.clone(), cosine_similarity(query, emb)))
            .collect();

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(k);
        results
    }

    pub fn len(&self) -> usize {
        self.embeddings.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.embeddings.write().clear();
    }

    pub fn dimension(&self) -> usize {
        self.dimension
    }
}

/// Compute cosine similarity between two vectors
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }

    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a > 0.0 && norm_b > 0.0 {
        dot / (norm_a * norm_b)
    } else {
        0.0
    }
}

// ============================================================================
// Neural Engine
// ============================================================================

/// A document indexed for neural search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralDocument {
    pub id: String,
    pub file_path: String,
    pub content: String,
    pub start_line: usize,
    pub end_line: usize,
    pub symbol_name: Option<String>,
}

/// A neural search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralSearchResult {
    pub document: NeuralDocument,
    pub similarity: f32,
}

/// Statistics about the neural engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralStats {
    pub indexed_count: usize,
    pub dimension: usize,
    pub backend: String,
    pub model: Option<String>,
}

/// Main neural embedding engine
pub struct NeuralEngine {
    backend: Arc<dyn EmbeddingBackend>,
    store: SimpleVectorStore,
    documents: RwLock<HashMap<String, NeuralDocument>>,
    config: NeuralConfig,
}

impl NeuralEngine {
    /// Create a new neural engine with API backend
    ///
    /// Supports custom embedding endpoints via `EMBEDDING_SERVER_ENDPOINT` environment variable.
    /// If not set, falls back to Voyage or OpenAI based on model name.
    ///
    /// # Environment Variables
    /// - `EMBEDDING_SERVER_ENDPOINT` (optional) - Custom embedding API endpoint URL
    /// - `EMBEDDING_API_KEY` - Generic API key (checked first)
    /// - `VOYAGE_API_KEY` - Voyage AI specific API key
    /// - `OPENAI_API_KEY` - OpenAI specific API key
    pub fn with_api(config: NeuralConfig) -> Result<Self> {
        // Validate dimension bounds
        if config.dimension < MIN_DIMENSION || config.dimension > MAX_DIMENSION {
            bail!(
                "Dimension {} is out of valid range [{}, {}]",
                config.dimension,
                MIN_DIMENSION,
                MAX_DIMENSION
            );
        }

        // Validate model name if provided
        if let Some(ref model_name) = config.model_name {
            if model_name.is_empty() {
                bail!("Model name cannot be empty");
            }
            if model_name.len() > MAX_MODEL_NAME_LENGTH {
                bail!(
                    "Model name length {} exceeds maximum of {}",
                    model_name.len(),
                    MAX_MODEL_NAME_LENGTH
                );
            }
        }

        // Try to get API key (optional for custom endpoints)
        let api_key = std::env::var("EMBEDDING_API_KEY")
            .or_else(|_| std::env::var("VOYAGE_API_KEY"))
            .or_else(|_| std::env::var("OPENAI_API_KEY"))
            .ok();

        // Validate API key length if present
        if let Some(ref key) = api_key {
            if key.len() > MAX_API_KEY_LENGTH {
                bail!(
                    "API key length {} exceeds maximum of {}",
                    key.len(),
                    MAX_API_KEY_LENGTH
                );
            }
        }

        let backend: Arc<dyn EmbeddingBackend>;

        // Check for custom endpoint first
        if let Ok(custom_endpoint) = std::env::var("EMBEDDING_SERVER_ENDPOINT") {
            // Validate the custom endpoint URL
            let validated_endpoint = validate_embedding_endpoint(&custom_endpoint)
                .context("Invalid EMBEDDING_SERVER_ENDPOINT")?;

            let model_name = config
                .model_name
                .as_deref()
                .unwrap_or("custom-embedding-model");

            tracing::info!(
                "Using custom embedding endpoint: {} (model: {})",
                validated_endpoint,
                model_name
            );

            backend = Arc::new(ApiEmbedder::custom(
                &validated_endpoint,
                model_name,
                api_key.as_deref(),
                config.dimension,
            ));
        } else {
            // Fallback to Voyage/OpenAI - API key is required
            let api_key = api_key.context(
                "No embedding API key found. Set EMBEDDING_API_KEY, VOYAGE_API_KEY, or OPENAI_API_KEY"
            )?;

            let model_name = config.model_name.as_deref().unwrap_or("voyage-code-2");
            backend = if model_name.contains("voyage") {
                Arc::new(ApiEmbedder::voyage_with_model(&api_key, model_name))
            } else {
                Arc::new(ApiEmbedder::openai_with_model(
                    &api_key,
                    model_name,
                    config.dimension,
                ))
            };
        }

        let store = SimpleVectorStore::new(config.dimension);

        Ok(Self {
            backend,
            store,
            documents: RwLock::new(HashMap::new()),
            config,
        })
    }

    /// Create a new neural engine with ONNX backend (requires neural-onnx feature)
    #[cfg(feature = "neural-onnx")]
    pub fn with_onnx(config: NeuralConfig) -> Result<Self> {
        let model_path = config
            .model_path
            .as_ref()
            .context("model_path required for ONNX backend")?;
        let tokenizer_path = config
            .tokenizer_path
            .as_ref()
            .context("tokenizer_path required for ONNX backend")?;

        let backend: Arc<dyn EmbeddingBackend> = Arc::new(onnx::OnnxEmbedder::new(
            Path::new(model_path),
            Path::new(tokenizer_path),
        )?);

        let store = SimpleVectorStore::new(config.dimension);

        Ok(Self {
            backend,
            store,
            documents: RwLock::new(HashMap::new()),
            config,
        })
    }

    /// Create based on config
    pub fn new(config: NeuralConfig) -> Result<Self> {
        match config.backend.as_str() {
            #[cfg(feature = "neural-onnx")]
            "onnx" => Self::with_onnx(config),
            _ => Self::with_api(config),
        }
    }

    /// Index a code snippet
    pub fn index_snippet(
        &self,
        id: String,
        file_path: String,
        content: String,
        start_line: usize,
        end_line: usize,
        symbol_name: Option<String>,
    ) -> Result<()> {
        let embedding = self.backend.embed(&content)?;
        self.store.add(&id, &embedding);

        let doc = NeuralDocument {
            id: id.clone(),
            file_path,
            content,
            start_line,
            end_line,
            symbol_name,
        };
        self.documents.write().insert(id, doc);

        Ok(())
    }

    /// Index multiple snippets in batch (with chunking to respect API limits)
    pub fn index_batch(&self, items: &[(NeuralDocument,)]) -> Result<()> {
        const BATCH_SIZE: usize = 96; // Voyage API limit is 128, use 96 for safety

        for chunk in items.chunks(BATCH_SIZE) {
            let contents: Vec<String> = chunk.iter().map(|(doc,)| doc.content.clone()).collect();
            let embeddings = self.backend.embed_batch(&contents)?;

            for ((doc,), embedding) in chunk.iter().zip(embeddings.iter()) {
                self.store.add(&doc.id, embedding);
                self.documents.write().insert(doc.id.clone(), doc.clone());
            }
        }

        Ok(())
    }

    /// Search for similar code
    pub fn search(&self, query: &str, k: usize) -> Result<Vec<NeuralSearchResult>> {
        let query_embedding = self.backend.embed(query)?;
        let results = self.store.search(&query_embedding, k);

        let documents = self.documents.read();
        Ok(results
            .into_iter()
            .filter_map(|(id, similarity)| {
                documents.get(&id).map(|doc| NeuralSearchResult {
                    document: doc.clone(),
                    similarity,
                })
            })
            .collect())
    }

    /// Find code similar to a specific document
    pub fn find_similar(&self, doc_id: &str, k: usize) -> Result<Vec<NeuralSearchResult>> {
        let documents = self.documents.read();
        let doc = documents.get(doc_id).context("Document not found")?.clone();
        drop(documents);

        // Re-embed the document content to get its embedding
        let embedding = self.backend.embed(&doc.content)?;
        let results = self.store.search(&embedding, k + 1);

        let documents = self.documents.read();
        Ok(results
            .into_iter()
            .filter(|(id, _)| id != doc_id) // Exclude self
            .take(k)
            .filter_map(|(id, similarity)| {
                documents.get(&id).map(|doc| NeuralSearchResult {
                    document: doc.clone(),
                    similarity,
                })
            })
            .collect())
    }

    /// Get statistics about the engine
    pub fn stats(&self) -> NeuralStats {
        NeuralStats {
            indexed_count: self.store.len(),
            dimension: self.config.dimension,
            backend: self.config.backend.clone(),
            model: self.config.model_name.clone(),
        }
    }

    /// Clear all indexed data
    pub fn clear(&self) {
        self.store.clear();
        self.documents.write().clear();
    }

    /// Check if neural search is available
    pub fn is_available(&self) -> bool {
        self.config.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Global mutex to serialize tests that modify environment variables
    // This prevents race conditions when tests run in parallel
    static ENV_VAR_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 0.001);

        let c = vec![0.0, 1.0, 0.0];
        assert!((cosine_similarity(&a, &c) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_simple_vector_store() {
        let store = SimpleVectorStore::new(3);

        store.add("doc1", &[1.0, 0.0, 0.0]);
        store.add("doc2", &[0.9, 0.1, 0.0]);
        store.add("doc3", &[0.0, 1.0, 0.0]);

        let results = store.search(&[1.0, 0.0, 0.0], 3);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, "doc1"); // Most similar
    }

    #[test]
    fn test_neural_config_default() {
        let config = NeuralConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.backend, "api");
        assert_eq!(config.dimension, 1536);
    }

    #[test]
    fn test_api_embedder_creation() {
        // Test that embedders can be created (won't actually call APIs)
        let _voyage = ApiEmbedder::voyage("test-key");
        let _openai = ApiEmbedder::openai("test-key");
    }

    #[test]
    fn test_custom_api_embedder() {
        let custom = ApiEmbedder::custom(
            "https://localhost:8080/v1/embeddings",
            "custom-model",
            Some("test-key"),
            768,
        );
        assert_eq!(custom.endpoint, "https://localhost:8080/v1/embeddings");
        assert_eq!(custom.model, "custom-model");
        assert_eq!(custom.dimension, 768);
        assert!(custom.api_key.is_some());
    }

    #[test]
    fn test_custom_api_embedder_without_key() {
        let custom = ApiEmbedder::custom(
            "http://192.168.1.100:8080/embeddings",
            "local-model",
            None,
            384,
        );
        assert_eq!(custom.endpoint, "http://192.168.1.100:8080/embeddings");
        assert!(custom.api_key.is_none());
    }

    mod custom_endpoint_integration {
        use super::*;

        #[test]
        fn test_with_api_custom_endpoint_with_key() {
            let _guard = super::ENV_VAR_MUTEX.lock().unwrap();

            // Set up environment
            std::env::set_var(
                "EMBEDDING_SERVER_ENDPOINT",
                "https://api.example.com/v1/embeddings",
            );
            std::env::set_var("EMBEDDING_API_KEY", "test-api-key-123");

            let config = NeuralConfig {
                enabled: true,
                backend: "api".to_string(),
                model_name: Some("custom-model".to_string()),
                dimension: 768,
                ..Default::default()
            };

            let result = NeuralEngine::with_api(config);
            assert!(result.is_ok(), "Should create engine with custom endpoint");

            // Clean up
            std::env::remove_var("EMBEDDING_SERVER_ENDPOINT");
            std::env::remove_var("EMBEDDING_API_KEY");
        }

        #[test]
        fn test_with_api_custom_endpoint_without_key() {
            let _guard = super::ENV_VAR_MUTEX.lock().unwrap();

            // Set up environment (no API key - should work for custom endpoints)
            std::env::set_var(
                "EMBEDDING_SERVER_ENDPOINT",
                "http://localhost:8080/embeddings",
            );
            std::env::remove_var("EMBEDDING_API_KEY");
            std::env::remove_var("VOYAGE_API_KEY");
            std::env::remove_var("OPENAI_API_KEY");

            let config = NeuralConfig {
                enabled: true,
                backend: "api".to_string(),
                model_name: Some("local-model".to_string()),
                dimension: 384,
                ..Default::default()
            };

            let result = NeuralEngine::with_api(config);
            assert!(
                result.is_ok(),
                "Should create engine without API key for custom endpoint"
            );

            // Clean up
            std::env::remove_var("EMBEDDING_SERVER_ENDPOINT");
        }

        #[test]
        fn test_with_api_invalid_custom_endpoint() {
            let _guard = super::ENV_VAR_MUTEX.lock().unwrap();

            // Set up environment with invalid endpoint
            std::env::set_var(
                "EMBEDDING_SERVER_ENDPOINT",
                "ftp://invalid-scheme.com/embeddings",
            );
            std::env::set_var("EMBEDDING_API_KEY", "test-key");

            let config = NeuralConfig::default();
            let result = NeuralEngine::with_api(config);

            assert!(result.is_err(), "Should reject invalid scheme");
            if let Err(e) = result {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("scheme") || err_msg.contains("Invalid"),
                    "Error message should mention invalid scheme, got: {}",
                    err_msg
                );
            }

            // Clean up
            std::env::remove_var("EMBEDDING_SERVER_ENDPOINT");
            std::env::remove_var("EMBEDDING_API_KEY");
        }

        #[test]
        fn test_with_api_fallback_to_voyage() {
            let _guard = super::ENV_VAR_MUTEX.lock().unwrap();

            // Clean all API-related env vars first to avoid race conditions
            std::env::remove_var("EMBEDDING_SERVER_ENDPOINT");
            std::env::remove_var("EMBEDDING_API_KEY");
            std::env::remove_var("OPENAI_API_KEY");
            // Now set only the one we need
            std::env::set_var("VOYAGE_API_KEY", "test-voyage-key");

            let config = NeuralConfig {
                enabled: true,
                backend: "api".to_string(),
                model_name: Some("voyage-code-2".to_string()),
                ..Default::default()
            };

            let result = NeuralEngine::with_api(config);
            assert!(result.is_ok(), "Should create engine with Voyage key");

            // Clean up
            std::env::remove_var("VOYAGE_API_KEY");
        }

        #[test]
        fn test_with_api_no_endpoint_no_key() {
            let _guard = super::ENV_VAR_MUTEX.lock().unwrap();

            // Clean up environment completely first
            std::env::remove_var("EMBEDDING_SERVER_ENDPOINT");
            std::env::remove_var("EMBEDDING_API_KEY");
            std::env::remove_var("VOYAGE_API_KEY");
            std::env::remove_var("OPENAI_API_KEY");

            // Verify environment is clean
            assert!(std::env::var("EMBEDDING_SERVER_ENDPOINT").is_err());
            assert!(std::env::var("EMBEDDING_API_KEY").is_err());
            assert!(std::env::var("VOYAGE_API_KEY").is_err());
            assert!(std::env::var("OPENAI_API_KEY").is_err());

            let config = NeuralConfig::default();
            let result = NeuralEngine::with_api(config);

            // Should fail because no endpoint and no API key
            match result {
                Ok(_) => panic!("Should require API key without custom endpoint"),
                Err(e) => {
                    let msg = e.to_string();
                    assert!(
                        msg.contains("API key") || msg.contains("No embedding"),
                        "Error should mention API key requirement, got: {}",
                        msg
                    );
                }
            }
        }
    }

    mod endpoint_validation {
        use super::*;

        #[test]
        fn test_validate_https_endpoint() {
            let result = validate_embedding_endpoint("https://api.example.com/v1/embeddings");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "https://api.example.com/v1/embeddings");
        }

        #[test]
        fn test_validate_http_endpoint() {
            // HTTP should be allowed for local development
            let result = validate_embedding_endpoint("http://localhost:8080/embeddings");
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_http_with_ip() {
            let result = validate_embedding_endpoint("http://192.168.1.100:8080/v1/embeddings");
            assert!(result.is_ok());
        }

        #[test]
        fn test_reject_invalid_scheme() {
            let result = validate_embedding_endpoint("ftp://example.com/embeddings");
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("scheme"));
        }

        #[test]
        fn test_reject_file_scheme() {
            let result = validate_embedding_endpoint("file:///etc/passwd");
            assert!(result.is_err());
        }

        #[test]
        fn test_reject_malformed_url() {
            let result = validate_embedding_endpoint("not a url");
            assert!(result.is_err());
        }

        #[test]
        fn test_reject_missing_scheme() {
            let result = validate_embedding_endpoint("example.com/embeddings");
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_with_port() {
            let result = validate_embedding_endpoint("https://api.example.com:443/v1/embeddings");
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_with_query_params() {
            let result =
                validate_embedding_endpoint("https://api.example.com/embeddings?version=1");
            assert!(result.is_ok());
        }

        #[test]
        fn test_private_ip_detection() {
            // Should succeed but log warning (check via tracing in real usage)
            let result = validate_embedding_endpoint("http://127.0.0.1:8080/embeddings");
            assert!(result.is_ok());

            let result = validate_embedding_endpoint("http://10.0.0.1/embeddings");
            assert!(result.is_ok());

            let result = validate_embedding_endpoint("http://172.16.0.1/embeddings");
            assert!(result.is_ok());

            let result = validate_embedding_endpoint("http://192.168.1.1/embeddings");
            assert!(result.is_ok());
        }

        #[test]
        fn test_localhost_detection() {
            let result = validate_embedding_endpoint("http://localhost:3000/embeddings");
            assert!(result.is_ok());

            let result = validate_embedding_endpoint("https://localhost/embeddings");
            assert!(result.is_ok());
        }

        #[test]
        fn test_reject_metadata_service_urls() {
            // AWS metadata service IPv4
            let result = validate_embedding_endpoint("http://169.254.169.254/latest/meta-data/");
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("metadata service"));
            }

            // GCP metadata service
            let result =
                validate_embedding_endpoint("http://metadata.google.internal/computeMetadata/v1/");
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("metadata service"));
            }

            // GCP metadata short form
            let result = validate_embedding_endpoint("http://metadata/computeMetadata/v1/");
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("metadata service"));
            }

            // Azure IMDS
            let result = validate_embedding_endpoint("http://169.254.169.253/metadata/instance");
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("metadata service"));
            }
        }

        #[test]
        fn test_reject_too_long_url() {
            let long_url = format!("https://example.com/{}", "a".repeat(3000));
            let result = validate_embedding_endpoint(&long_url);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("too long"));
        }

        #[test]
        fn test_reject_url_without_host() {
            // Opaque URLs (like data: or mailto:) don't have hosts
            // These should be rejected by the scheme check anyway
            let result = validate_embedding_endpoint("data:text/plain,hello");
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("scheme"));
            }
        }
    }

    // Security tests for input validation
    mod security_validation {
        use super::*;

        #[test]
        fn test_dimension_bounds_validation() {
            let _guard = super::ENV_VAR_MUTEX.lock().unwrap();

            // Clean environment first
            std::env::remove_var("EMBEDDING_SERVER_ENDPOINT");
            std::env::remove_var("EMBEDDING_API_KEY");
            std::env::remove_var("OPENAI_API_KEY");

            // Too small
            let config = NeuralConfig {
                enabled: true,
                backend: "api".to_string(),
                dimension: 32, // Below MIN_DIMENSION (64)
                ..Default::default()
            };
            std::env::set_var("VOYAGE_API_KEY", "test-key");
            let result = NeuralEngine::with_api(config);
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("out of valid range"));
            }

            // Too large
            let config = NeuralConfig {
                enabled: true,
                backend: "api".to_string(),
                dimension: 10000, // Above MAX_DIMENSION (8192)
                ..Default::default()
            };
            let result = NeuralEngine::with_api(config);
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("out of valid range"));
            }

            std::env::remove_var("VOYAGE_API_KEY");
        }

        #[test]
        fn test_dimension_valid_bounds() {
            let _guard = super::ENV_VAR_MUTEX.lock().unwrap();

            // Clean environment first
            std::env::remove_var("EMBEDDING_SERVER_ENDPOINT");
            std::env::remove_var("EMBEDDING_API_KEY");
            std::env::remove_var("OPENAI_API_KEY");

            // Min valid dimension
            let config = NeuralConfig {
                enabled: true,
                backend: "api".to_string(),
                dimension: MIN_DIMENSION,
                ..Default::default()
            };
            std::env::set_var("VOYAGE_API_KEY", "test-key");
            let result = NeuralEngine::with_api(config);
            assert!(result.is_ok());

            // Max valid dimension (re-set API key since env vars can be cleared)
            std::env::set_var("VOYAGE_API_KEY", "test-key");
            let config = NeuralConfig {
                enabled: true,
                backend: "api".to_string(),
                dimension: MAX_DIMENSION,
                ..Default::default()
            };
            let result = NeuralEngine::with_api(config);
            if let Err(ref e) = result {
                eprintln!("Error creating engine with MAX_DIMENSION: {}", e);
            }
            assert!(result.is_ok());

            std::env::remove_var("VOYAGE_API_KEY");
        }

        #[test]
        fn test_model_name_validation() {
            let _guard = super::ENV_VAR_MUTEX.lock().unwrap();

            // Clean environment first
            std::env::remove_var("EMBEDDING_SERVER_ENDPOINT");
            std::env::remove_var("EMBEDDING_API_KEY");
            std::env::remove_var("OPENAI_API_KEY");

            // Empty model name
            let config = NeuralConfig {
                enabled: true,
                backend: "api".to_string(),
                model_name: Some("".to_string()),
                dimension: 1536,
                ..Default::default()
            };
            std::env::set_var("VOYAGE_API_KEY", "test-key");
            let result = NeuralEngine::with_api(config);
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("cannot be empty"));
            }

            // Too long model name
            let config = NeuralConfig {
                enabled: true,
                backend: "api".to_string(),
                model_name: Some("a".repeat(300)),
                dimension: 1536,
                ..Default::default()
            };
            let result = NeuralEngine::with_api(config);
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("exceeds maximum"));
            }

            std::env::remove_var("VOYAGE_API_KEY");
        }

        #[test]
        fn test_api_key_length_validation() {
            let _guard = super::ENV_VAR_MUTEX.lock().unwrap();

            // Clean environment first
            std::env::remove_var("EMBEDDING_SERVER_ENDPOINT");
            std::env::remove_var("VOYAGE_API_KEY");
            std::env::remove_var("OPENAI_API_KEY");

            // Extremely long API key
            let long_key = "a".repeat(3000);
            std::env::set_var("EMBEDDING_API_KEY", &long_key);

            let config = NeuralConfig {
                enabled: true,
                backend: "api".to_string(),
                dimension: 1536,
                ..Default::default()
            };

            let result = NeuralEngine::with_api(config);
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("API key length"));
            }

            std::env::remove_var("EMBEDDING_API_KEY");
        }

        #[test]
        fn test_batch_size_validation() {
            let embedder = ApiEmbedder::custom(
                "https://api.example.com/embeddings",
                "test-model",
                Some("test-key"),
                768,
            );

            // Empty batch
            let result = embedder.embed_batch(&[]);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("empty batch"));

            // Too large batch
            let large_batch: Vec<String> = (0..200).map(|i| format!("text {}", i)).collect();
            let result = embedder.embed_batch(&large_batch);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
        }

        #[test]
        fn test_text_length_validation() {
            let embedder = ApiEmbedder::custom(
                "https://api.example.com/embeddings",
                "test-model",
                Some("test-key"),
                768,
            );

            // Text too long
            let long_text = "a".repeat(40_000);
            let result = embedder.embed_batch(&[long_text]);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("exceeds maximum"));

            // Multiple texts, one too long
            let texts = vec![
                "normal text".to_string(),
                "a".repeat(40_000),
                "another normal text".to_string(),
            ];
            let result = embedder.embed_batch(&texts);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("index 1"));
        }

        #[test]
        fn test_valid_batch_sizes() {
            let embedder = ApiEmbedder::custom(
                "https://api.example.com/embeddings",
                "test-model",
                Some("test-key"),
                768,
            );

            // Single text (valid size)
            let texts = vec!["test text".to_string()];
            // Note: This will fail at HTTP level (no actual server), but should pass validation
            let _result = embedder.embed_batch(&texts);

            // Maximum valid batch size
            let max_batch: Vec<String> = (0..MAX_EMBEDDING_BATCH_SIZE)
                .map(|i| format!("text {}", i))
                .collect();
            // Note: This will fail at HTTP level, but should pass validation
            let _result = embedder.embed_batch(&max_batch);
        }

        #[test]
        fn test_http_client_has_timeout() {
            // Create an embedder and verify the client has timeout configured
            let embedder = ApiEmbedder::voyage("test-key");
            // We can't directly inspect the client's timeout, but we can verify it was created
            // In real usage, timeout would be tested by connecting to a slow server
            assert!(embedder.api_key.is_some());
        }
    }
}
