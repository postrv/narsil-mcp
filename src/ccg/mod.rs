//! Code Context Graph (CCG) generation module.
//!
//! This module implements multi-layer CCG generation as specified in
//! `docs/CODE_CONTEXT_GRAPH_SIZING_ARCH.md`. CCG provides a structured,
//! RDF-based representation of codebase knowledge optimized for AI context windows.
//!
//! # Layer Architecture
//!
//! CCG uses a progressive disclosure model with four layers:
//!
//! - **Layer 0 (Manifest):** ~1-2 KB JSON-LD - Repository identity, counts, summary
//! - **Layer 1 (Architecture):** ~10-50 KB JSON-LD - Module hierarchy, public API
//! - **Layer 2 (Symbol Index):** ~100-500 KB N-Quads gzipped - All symbols, call graph
//! - **Layer 3 (Full Detail):** ~1-20 MB N-Quads gzipped - Complete RDF dataset
//!
//! # Size Constraints
//!
//! - L0 + L1 combined MUST be < 50 KB (always fits in context)
//! - L2 optimized for symbol-level navigation
//! - L3 provides full detail for deep analysis
//!
//! # Access Tiers (Triple-Heart Model)
//!
//! CCG supports tiered access control based on the Triple-Heart Model:
//!
//! - **🔴 Public (Red Heart):** Anyone can access (foaf:Agent)
//! - **🟡 Authenticated (Yellow Heart):** Authenticated agents (acl:AuthenticatedAgent)
//! - **🔵 Private (Blue Heart):** Specific agents via WebACL
//!
//! # Example
//!
//! ```ignore
//! use narsil_mcp::ccg::{CcgGenerator, CcgOptions, Layer, AccessTier, AccessControl};
//!
//! let generator = CcgGenerator::new(&engine);
//! let manifest = generator.generate_layer(Layer::Manifest, "my-repo", &options)?;
//! assert!(manifest.size_bytes() < 2048);
//!
//! // Create access control for the CCG
//! let acl = AccessControl::default_triple_heart("my-repo");
//! let turtle = acl.to_turtle();
//! ```

pub mod access;
pub mod import;
mod layers;

pub use access::{AccessControl, AccessMetadata, AccessMode, AccessTier, AgentId, Authorization};
pub use layers::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum size for Layer 0 (Manifest) in bytes.
pub const L0_MAX_SIZE: usize = 2 * 1024; // 2 KB

/// Maximum size for Layer 1 (Architecture) in bytes.
pub const L1_MAX_SIZE: usize = 50 * 1024; // 50 KB

/// Maximum combined size for L0 + L1 in bytes.
pub const L0_L1_MAX_COMBINED: usize = 50 * 1024; // 50 KB

/// Target size for Layer 2 (Symbol Index) in bytes.
pub const L2_TARGET_SIZE: usize = 500 * 1024; // 500 KB

/// Maximum size for Layer 3 (Full Detail) in bytes.
pub const L3_MAX_SIZE: usize = 20 * 1024 * 1024; // 20 MB

/// CCG layer identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    /// Layer 0: Minimal manifest (~1-2 KB JSON-LD)
    Manifest,
    /// Layer 1: Architecture overview (~10-50 KB JSON-LD)
    Architecture,
    /// Layer 2: Symbol index (~100-500 KB N-Quads gzipped)
    SymbolIndex,
    /// Layer 3: Full detail (~1-20 MB N-Quads gzipped)
    FullDetail,
}

impl Layer {
    /// Returns the maximum recommended size in bytes for this layer.
    #[must_use]
    pub const fn max_size(&self) -> usize {
        match self {
            Self::Manifest => L0_MAX_SIZE,
            Self::Architecture => L1_MAX_SIZE,
            Self::SymbolIndex => L2_TARGET_SIZE,
            Self::FullDetail => L3_MAX_SIZE,
        }
    }

    /// Returns the layer number (0-3).
    #[must_use]
    pub const fn number(&self) -> u8 {
        match self {
            Self::Manifest => 0,
            Self::Architecture => 1,
            Self::SymbolIndex => 2,
            Self::FullDetail => 3,
        }
    }

    /// Returns the format for this layer (json-ld or nquads).
    #[must_use]
    pub const fn format(&self) -> LayerFormat {
        match self {
            Self::Manifest | Self::Architecture => LayerFormat::JsonLd,
            Self::SymbolIndex | Self::FullDetail => LayerFormat::NQuadsGzip,
        }
    }

    /// Returns true if this layer should be gzip compressed.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        matches!(self, Self::SymbolIndex | Self::FullDetail)
    }
}

/// Output format for CCG layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayerFormat {
    /// JSON-LD format (for L0, L1)
    JsonLd,
    /// N-Quads format with gzip compression (for L2, L3)
    NQuadsGzip,
}

/// Options for CCG generation.
#[derive(Debug, Clone)]
pub struct CcgOptions {
    /// Base URL for the CCG endpoints (for layer URIs)
    pub base_url: Option<String>,
    /// Git commit SHA (for versioning)
    pub commit: Option<String>,
    /// Include security findings in manifest
    pub include_security_summary: bool,
    /// Maximum docstring length to include in L2
    pub max_docstring_length: usize,
    /// Maximum source snippet length for L3
    pub max_snippet_length: usize,
    /// Access control configuration (Triple-Heart Model)
    pub access_control: Option<AccessControl>,
}

impl Default for CcgOptions {
    fn default() -> Self {
        Self {
            base_url: None,
            commit: None,
            include_security_summary: true,
            max_docstring_length: 200,
            max_snippet_length: 500,
            access_control: None,
        }
    }
}

impl CcgOptions {
    /// Sets the base URL for layer URIs.
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Sets the git commit SHA.
    #[must_use]
    pub fn with_commit(mut self, commit: impl Into<String>) -> Self {
        self.commit = Some(commit.into());
        self
    }

    /// Disables security summary in manifest.
    #[must_use]
    pub fn without_security_summary(mut self) -> Self {
        self.include_security_summary = false;
        self
    }

    /// Sets access control configuration for the CCG.
    ///
    /// When set, generated layers will include access metadata
    /// based on the Triple-Heart Model.
    #[must_use]
    pub fn with_access_control(mut self, access: AccessControl) -> Self {
        self.access_control = Some(access);
        self
    }

    /// Sets default Triple-Heart access control for the given repository.
    ///
    /// This creates the standard access pattern:
    /// - L0 (Manifest): Public access
    /// - L1 (Architecture): Authenticated access
    /// - L2 (Symbol Index): Private access
    /// - L3 (Full Detail): Private access
    #[must_use]
    pub fn with_default_access_control(mut self, repo: impl Into<String>) -> Self {
        self.access_control = Some(AccessControl::default_triple_heart(repo));
        self
    }
}

/// Generated CCG layer output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcgOutput {
    /// The layer this output represents
    pub layer: Layer,
    /// Content format
    pub format: LayerFormat,
    /// Raw content (JSON-LD string or base64-encoded gzipped N-Quads)
    pub content: String,
    /// Size in bytes (of raw content, before any encoding)
    pub size_bytes: usize,
    /// Whether the content is compressed
    pub compressed: bool,
    /// Repository name
    pub repo: String,
    /// Generation timestamp (ISO 8601)
    pub generated_at: String,
    /// Metadata about the layer contents
    pub metadata: HashMap<String, serde_json::Value>,
    /// Access control metadata (Triple-Heart Model)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<AccessMetadata>,
}

impl CcgOutput {
    /// Returns the size of the content in bytes.
    #[must_use]
    pub fn size_bytes(&self) -> usize {
        self.size_bytes
    }

    /// Returns true if this layer is within its size budget.
    #[must_use]
    pub fn is_within_budget(&self) -> bool {
        self.size_bytes <= self.layer.max_size()
    }
}

/// Bundle containing all CCG layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcgBundle {
    /// Repository name
    pub repo: String,
    /// All generated layers
    pub layers: HashMap<Layer, CcgOutput>,
    /// Total size in bytes
    pub total_size_bytes: usize,
    /// Generation timestamp
    pub generated_at: String,
    /// Access control configuration for this CCG
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_control: Option<AccessControl>,
}

impl CcgBundle {
    /// Returns true if L0 + L1 combined size is within budget.
    #[must_use]
    pub fn manifest_layers_within_budget(&self) -> bool {
        let l0_size = self
            .layers
            .get(&Layer::Manifest)
            .map_or(0, |l| l.size_bytes);
        let l1_size = self
            .layers
            .get(&Layer::Architecture)
            .map_or(0, |l| l.size_bytes);
        l0_size + l1_size <= L0_L1_MAX_COMBINED
    }

    /// Gets a specific layer from the bundle.
    #[must_use]
    pub fn get_layer(&self, layer: Layer) -> Option<&CcgOutput> {
        self.layers.get(&layer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_max_sizes() {
        assert_eq!(Layer::Manifest.max_size(), 2 * 1024);
        assert_eq!(Layer::Architecture.max_size(), 50 * 1024);
        assert_eq!(Layer::SymbolIndex.max_size(), 500 * 1024);
        assert_eq!(Layer::FullDetail.max_size(), 20 * 1024 * 1024);
    }

    #[test]
    fn test_layer_numbers() {
        assert_eq!(Layer::Manifest.number(), 0);
        assert_eq!(Layer::Architecture.number(), 1);
        assert_eq!(Layer::SymbolIndex.number(), 2);
        assert_eq!(Layer::FullDetail.number(), 3);
    }

    #[test]
    fn test_layer_formats() {
        assert_eq!(Layer::Manifest.format(), LayerFormat::JsonLd);
        assert_eq!(Layer::Architecture.format(), LayerFormat::JsonLd);
        assert_eq!(Layer::SymbolIndex.format(), LayerFormat::NQuadsGzip);
        assert_eq!(Layer::FullDetail.format(), LayerFormat::NQuadsGzip);
    }

    #[test]
    fn test_layer_compression() {
        assert!(!Layer::Manifest.is_compressed());
        assert!(!Layer::Architecture.is_compressed());
        assert!(Layer::SymbolIndex.is_compressed());
        assert!(Layer::FullDetail.is_compressed());
    }

    #[test]
    fn test_ccg_options_builder() {
        let options = CcgOptions::default()
            .with_base_url("https://example.com/ccg")
            .with_commit("abc123")
            .without_security_summary();

        assert_eq!(
            options.base_url,
            Some("https://example.com/ccg".to_string())
        );
        assert_eq!(options.commit, Some("abc123".to_string()));
        assert!(!options.include_security_summary);
    }

    #[test]
    fn test_ccg_output_within_budget() {
        let output = CcgOutput {
            layer: Layer::Manifest,
            format: LayerFormat::JsonLd,
            content: "{}".to_string(),
            size_bytes: 1024,
            compressed: false,
            repo: "test".to_string(),
            generated_at: "2024-01-01T00:00:00Z".to_string(),
            metadata: HashMap::new(),
            access: None,
        };

        assert!(output.is_within_budget());

        let over_budget = CcgOutput {
            layer: Layer::Manifest,
            size_bytes: 10_000, // Over 2KB limit
            ..output.clone()
        };

        assert!(!over_budget.is_within_budget());
    }

    #[test]
    fn test_ccg_bundle_manifest_budget() {
        let mut layers = HashMap::new();

        // L0 = 1KB, L1 = 10KB -> total 11KB < 50KB
        layers.insert(
            Layer::Manifest,
            CcgOutput {
                layer: Layer::Manifest,
                format: LayerFormat::JsonLd,
                content: "{}".to_string(),
                size_bytes: 1024,
                compressed: false,
                repo: "test".to_string(),
                generated_at: "2024-01-01T00:00:00Z".to_string(),
                metadata: HashMap::new(),
                access: None,
            },
        );
        layers.insert(
            Layer::Architecture,
            CcgOutput {
                layer: Layer::Architecture,
                format: LayerFormat::JsonLd,
                content: "{}".to_string(),
                size_bytes: 10 * 1024,
                compressed: false,
                repo: "test".to_string(),
                generated_at: "2024-01-01T00:00:00Z".to_string(),
                metadata: HashMap::new(),
                access: None,
            },
        );

        let bundle = CcgBundle {
            repo: "test".to_string(),
            layers,
            total_size_bytes: 11 * 1024,
            generated_at: "2024-01-01T00:00:00Z".to_string(),
            access_control: None,
        };

        assert!(bundle.manifest_layers_within_budget());
    }

    #[test]
    fn test_ccg_bundle_manifest_over_budget() {
        let mut layers = HashMap::new();

        // L0 = 30KB, L1 = 30KB -> total 60KB > 50KB
        layers.insert(
            Layer::Manifest,
            CcgOutput {
                layer: Layer::Manifest,
                format: LayerFormat::JsonLd,
                content: "{}".to_string(),
                size_bytes: 30 * 1024,
                compressed: false,
                repo: "test".to_string(),
                generated_at: "2024-01-01T00:00:00Z".to_string(),
                metadata: HashMap::new(),
                access: None,
            },
        );
        layers.insert(
            Layer::Architecture,
            CcgOutput {
                layer: Layer::Architecture,
                format: LayerFormat::JsonLd,
                content: "{}".to_string(),
                size_bytes: 30 * 1024,
                compressed: false,
                repo: "test".to_string(),
                generated_at: "2024-01-01T00:00:00Z".to_string(),
                metadata: HashMap::new(),
                access: None,
            },
        );

        let bundle = CcgBundle {
            repo: "test".to_string(),
            layers,
            total_size_bytes: 60 * 1024,
            generated_at: "2024-01-01T00:00:00Z".to_string(),
            access_control: None,
        };

        assert!(!bundle.manifest_layers_within_budget());
    }

    // Tests for re-exported access control types (verify public API works)

    #[test]
    fn test_access_mode_read() {
        // Verify AccessMode is available from public API
        let mode = AccessMode::Read;
        assert_eq!(mode.name(), "Read");
    }

    #[test]
    fn test_agent_id_creation() {
        // Verify AgentId is available from public API
        let agent = AgentId::new("https://example.com/#agent");
        assert_eq!(agent.uri(), "https://example.com/#agent");
    }

    #[test]
    fn test_authorization_creation() {
        // Verify Authorization is available from public API
        let auth = Authorization::new(
            "test-auth",
            "https://example.com/resource",
            AccessTier::Public,
        );
        assert_eq!(auth.id, "test-auth");
        assert_eq!(auth.tier, AccessTier::Public);
    }

    #[test]
    fn test_ccg_options_with_access_control() {
        let options = CcgOptions::default().with_default_access_control("test-repo");

        assert!(options.access_control.is_some());
        let acl = options.access_control.unwrap();
        assert_eq!(acl.repo, "test-repo");
        assert_eq!(acl.authorizations.len(), 4); // One per layer
    }
}
