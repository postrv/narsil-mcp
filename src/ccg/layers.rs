//! CCG layer generation implementations.
//!
//! This module provides the `CcgGenerator` which transforms code intelligence data
//! into CCG layers with size-aware content selection.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_ENGINE, Engine};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::io::Write;

use super::{
    AccessMetadata, AccessTier, CcgBundle, CcgOptions, CcgOutput, Layer, LayerFormat,
    L0_L1_MAX_COMBINED,
};

/// JSON-LD context for CCG documents.
pub const CCG_CONTEXT: &str = "https://narsilmcp.com/ccg/v1";

/// Narsil ontology namespace.
pub const NARSIL_NS: &str = "https://narsilmcp.com/ontology/v1#";

/// Layer 0 manifest structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// JSON-LD context
    #[serde(rename = "@context")]
    pub context: String,
    /// JSON-LD type
    #[serde(rename = "@type")]
    pub type_: String,
    /// Repository name
    pub name: String,
    /// Repository URL (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Git commit SHA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Symbol counts by type
    pub symbol_counts: SymbolCounts,
    /// Security summary (if enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_summary: Option<SecuritySummary>,
    /// Language breakdown
    pub languages: Vec<LanguageInfo>,
    /// Top-level entry points
    pub entry_points: Vec<EntryPoint>,
    /// URIs to fetch other layers
    pub layer_uris: LayerUris,
    /// Generation metadata
    pub generated: GenerationInfo,
}

/// Symbol counts by type for manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolCounts {
    pub functions: usize,
    pub classes: usize,
    pub structs: usize,
    pub traits: usize,
    pub enums: usize,
    pub modules: usize,
    pub constants: usize,
    pub total: usize,
}

/// Security summary for manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

/// Language information for manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageInfo {
    pub language: String,
    pub file_count: usize,
    pub percentage: f64,
}

/// Entry point information for manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    pub name: String,
    pub file: String,
    pub line: usize,
    #[serde(rename = "type")]
    pub entry_type: String,
}

/// URIs to fetch other layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerUris {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_index: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_detail: Option<String>,
}

/// Generation metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationInfo {
    pub timestamp: String,
    pub version: String,
    pub generator: String,
}

/// Layer 1 architecture structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Architecture {
    /// JSON-LD context
    #[serde(rename = "@context")]
    pub context: String,
    /// JSON-LD type
    #[serde(rename = "@type")]
    pub type_: String,
    /// Repository name
    pub name: String,
    /// Module hierarchy
    pub modules: Vec<ModuleInfo>,
    /// Public API surface (exported symbols)
    pub public_api: Vec<PublicSymbol>,
    /// Module-level dependencies
    pub dependencies: Vec<ModuleDependency>,
    /// Key abstractions (traits, interfaces)
    pub abstractions: Vec<AbstractionInfo>,
}

/// Module information for architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub path: String,
    pub name: String,
    pub children: Vec<String>,
    pub symbol_count: usize,
}

/// Public symbol for architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicSymbol {
    pub name: String,
    pub kind: String,
    pub file: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Module dependency for architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleDependency {
    pub from: String,
    pub to: String,
    pub import_count: usize,
}

/// Abstraction (trait/interface) for architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractionInfo {
    pub name: String,
    pub kind: String,
    pub file: String,
    pub implementors: usize,
}

/// Input data for CCG generation.
///
/// This struct collects all the data needed to generate CCG layers.
#[derive(Debug, Clone, Default)]
pub struct CcgInput {
    /// Repository name
    pub repo_name: String,
    /// Repository URL
    pub repo_url: Option<String>,
    /// All files in the repository
    pub files: Vec<FileInfo>,
    /// All symbols indexed
    pub symbols: Vec<SymbolInfo>,
    /// Call graph edges
    pub call_edges: Vec<CallEdgeInfo>,
    /// Import edges
    pub import_edges: Vec<ImportEdgeInfo>,
    /// Security findings
    pub security_findings: Vec<SecurityFindingInfo>,
}

/// File information for CCG input.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: String,
    pub language: String,
    pub size_bytes: usize,
}

/// Symbol information for CCG input.
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub kind: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub signature: Option<String>,
    pub doc_comment: Option<String>,
    pub is_public: bool,
    pub complexity: Option<u32>,
}

/// Call edge information for CCG input.
#[derive(Debug, Clone)]
pub struct CallEdgeInfo {
    pub caller: String,
    pub caller_file: String,
    pub callee: String,
    pub callee_file: String,
    pub line: usize,
}

/// Import edge information for CCG input.
#[derive(Debug, Clone)]
pub struct ImportEdgeInfo {
    pub source_file: String,
    pub target_module: String,
}

/// Security finding information for CCG input.
#[derive(Debug, Clone)]
pub struct SecurityFindingInfo {
    pub rule_id: String,
    pub severity: String,
    pub file: String,
    pub line: usize,
    pub message: String,
}

/// CCG generator that transforms code intelligence data into layers.
pub struct CcgGenerator;

impl CcgGenerator {
    /// Creates a new CCG generator.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Generates a specific layer from the input data.
    ///
    /// # Arguments
    ///
    /// * `layer` - The layer to generate
    /// * `input` - The input data
    /// * `options` - Generation options
    ///
    /// # Errors
    ///
    /// Returns an error if generation fails.
    pub fn generate_layer(
        &self,
        layer: Layer,
        input: &CcgInput,
        options: &CcgOptions,
    ) -> Result<CcgOutput> {
        match layer {
            Layer::Manifest => self.generate_manifest(input, options),
            Layer::Architecture => self.generate_architecture(input, options),
            Layer::SymbolIndex => self.generate_symbol_index(input, options),
            Layer::FullDetail => self.generate_full_detail(input, options),
        }
    }

    /// Generates all layers and returns a bundle.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data
    /// * `options` - Generation options
    ///
    /// # Errors
    ///
    /// Returns an error if L0+L1 combined size exceeds the budget.
    pub fn generate_bundle(&self, input: &CcgInput, options: &CcgOptions) -> Result<CcgBundle> {
        let l0 = self.generate_manifest(input, options)?;
        let l1 = self.generate_architecture(input, options)?;

        // Check L0+L1 combined size
        let combined_size = l0.size_bytes + l1.size_bytes;
        if combined_size > L0_L1_MAX_COMBINED {
            return Err(anyhow!(
                "L0+L1 combined size ({} bytes) exceeds budget ({} bytes)",
                combined_size,
                L0_L1_MAX_COMBINED
            ));
        }

        let l2 = self.generate_symbol_index(input, options)?;
        let l3 = self.generate_full_detail(input, options)?;

        let total_size = l0.size_bytes + l1.size_bytes + l2.size_bytes + l3.size_bytes;
        let timestamp = chrono::Utc::now().to_rfc3339();

        let mut layers = HashMap::new();
        layers.insert(Layer::Manifest, l0);
        layers.insert(Layer::Architecture, l1);
        layers.insert(Layer::SymbolIndex, l2);
        layers.insert(Layer::FullDetail, l3);

        Ok(CcgBundle {
            repo: input.repo_name.clone(),
            layers,
            total_size_bytes: total_size,
            generated_at: timestamp,
            access_control: options.access_control.clone(),
        })
    }

    /// Generates Layer 0 (Manifest).
    fn generate_manifest(&self, input: &CcgInput, options: &CcgOptions) -> Result<CcgOutput> {
        let symbol_counts = self.count_symbols(&input.symbols);
        let languages = self.aggregate_languages(&input.files);
        let entry_points = self.find_entry_points(&input.symbols);

        let security_summary = if options.include_security_summary {
            Some(self.aggregate_security(&input.security_findings))
        } else {
            None
        };

        let layer_uris = self.build_layer_uris(&input.repo_name, options);
        let timestamp = chrono::Utc::now().to_rfc3339();

        let manifest = Manifest {
            context: CCG_CONTEXT.to_string(),
            type_: "CodeContextGraph".to_string(),
            name: input.repo_name.clone(),
            url: input.repo_url.clone(),
            commit: options.commit.clone(),
            symbol_counts,
            security_summary,
            languages,
            entry_points,
            layer_uris,
            generated: GenerationInfo {
                timestamp: timestamp.clone(),
                version: "1.0.0".to_string(),
                generator: format!("narsil-mcp/{}", env!("CARGO_PKG_VERSION")),
            },
        };

        let content = serde_json::to_string_pretty(&manifest)?;
        let size_bytes = content.len();

        Ok(CcgOutput {
            layer: Layer::Manifest,
            format: LayerFormat::JsonLd,
            content,
            size_bytes,
            compressed: false,
            repo: input.repo_name.clone(),
            generated_at: timestamp,
            metadata: HashMap::new(),
            access: self.derive_access_metadata(Layer::Manifest, options),
        })
    }

    /// Generates Layer 1 (Architecture).
    fn generate_architecture(&self, input: &CcgInput, options: &CcgOptions) -> Result<CcgOutput> {
        let modules = self.build_module_hierarchy(input);
        let public_api = self.extract_public_api(&input.symbols, options);
        let dependencies = self.build_module_dependencies(&input.import_edges);
        let abstractions = self.extract_abstractions(&input.symbols);

        let timestamp = chrono::Utc::now().to_rfc3339();

        let architecture = Architecture {
            context: CCG_CONTEXT.to_string(),
            type_: "ArchitectureGraph".to_string(),
            name: input.repo_name.clone(),
            modules,
            public_api,
            dependencies,
            abstractions,
        };

        let content = serde_json::to_string_pretty(&architecture)?;
        let size_bytes = content.len();

        Ok(CcgOutput {
            layer: Layer::Architecture,
            format: LayerFormat::JsonLd,
            content,
            size_bytes,
            compressed: false,
            repo: input.repo_name.clone(),
            generated_at: timestamp,
            metadata: HashMap::new(),
            access: self.derive_access_metadata(Layer::Architecture, options),
        })
    }

    /// Generates Layer 2 (Symbol Index).
    fn generate_symbol_index(&self, input: &CcgInput, options: &CcgOptions) -> Result<CcgOutput> {
        let mut nquads = String::new();
        let timestamp = chrono::Utc::now().to_rfc3339();

        // Generate N-Quads for all symbols
        for symbol in &input.symbols {
            let subject = format!(
                "<https://narsilmcp.com/code/{}/{}::{}@L{}>",
                input.repo_name,
                symbol.file.replace('/', "%2F"),
                symbol.name,
                symbol.start_line
            );

            // Type triple
            nquads.push_str(&format!(
                "{} <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <{}{}> .\n",
                subject, NARSIL_NS, symbol.kind
            ));

            // Name triple
            nquads.push_str(&format!(
                "{} <{}name> \"{}\" .\n",
                subject, NARSIL_NS, symbol.name
            ));

            // File path triple
            nquads.push_str(&format!(
                "{} <{}filePath> \"{}\" .\n",
                subject, NARSIL_NS, symbol.file
            ));

            // Line numbers
            nquads.push_str(&format!(
                "{} <{}startLine> \"{}\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
                subject, NARSIL_NS, symbol.start_line
            ));
            nquads.push_str(&format!(
                "{} <{}endLine> \"{}\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
                subject, NARSIL_NS, symbol.end_line
            ));

            // Optional signature (truncated)
            if let Some(ref sig) = symbol.signature {
                nquads.push_str(&format!(
                    "{} <{}signature> \"{}\" .\n",
                    subject,
                    NARSIL_NS,
                    escape_nquads_string(sig)
                ));
            }

            // Optional docstring (truncated)
            if let Some(ref doc) = symbol.doc_comment {
                let truncated = truncate_string(doc, options.max_docstring_length);
                nquads.push_str(&format!(
                    "{} <{}docComment> \"{}\" .\n",
                    subject,
                    NARSIL_NS,
                    escape_nquads_string(&truncated)
                ));
            }

            // Complexity if available
            if let Some(complexity) = symbol.complexity {
                nquads.push_str(&format!(
                    "{} <{}complexity> \"{}\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
                    subject, NARSIL_NS, complexity
                ));
            }
        }

        // Add call graph edges
        for edge in &input.call_edges {
            let caller = format!(
                "<https://narsilmcp.com/code/{}/{}::{}>",
                input.repo_name,
                edge.caller_file.replace('/', "%2F"),
                edge.caller
            );
            let callee = format!(
                "<https://narsilmcp.com/code/{}/{}::{}>",
                input.repo_name,
                edge.callee_file.replace('/', "%2F"),
                edge.callee
            );
            nquads.push_str(&format!("{} <{}calls> {} .\n", caller, NARSIL_NS, callee));
        }

        // Compress with gzip
        let compressed = compress_gzip(nquads.as_bytes())?;
        let size_bytes = compressed.len();

        // Base64 encode for transport
        let content = BASE64_ENGINE.encode(&compressed);

        Ok(CcgOutput {
            layer: Layer::SymbolIndex,
            format: LayerFormat::NQuadsGzip,
            content,
            size_bytes,
            compressed: true,
            repo: input.repo_name.clone(),
            generated_at: timestamp,
            metadata: {
                let mut m = HashMap::new();
                m.insert("symbol_count".to_string(), json!(input.symbols.len()));
                m.insert("call_edge_count".to_string(), json!(input.call_edges.len()));
                m
            },
            access: self.derive_access_metadata(Layer::SymbolIndex, options),
        })
    }

    /// Generates Layer 3 (Full Detail).
    fn generate_full_detail(&self, input: &CcgInput, options: &CcgOptions) -> Result<CcgOutput> {
        let mut nquads = String::new();
        let timestamp = chrono::Utc::now().to_rfc3339();

        // Include everything from L2
        for symbol in &input.symbols {
            let subject = format!(
                "<https://narsilmcp.com/code/{}/{}::{}@L{}>",
                input.repo_name,
                symbol.file.replace('/', "%2F"),
                symbol.name,
                symbol.start_line
            );

            nquads.push_str(&format!(
                "{} <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <{}{}> .\n",
                subject, NARSIL_NS, symbol.kind
            ));
            nquads.push_str(&format!(
                "{} <{}name> \"{}\" .\n",
                subject, NARSIL_NS, symbol.name
            ));
            nquads.push_str(&format!(
                "{} <{}filePath> \"{}\" .\n",
                subject, NARSIL_NS, symbol.file
            ));
            nquads.push_str(&format!(
                "{} <{}startLine> \"{}\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
                subject, NARSIL_NS, symbol.start_line
            ));
            nquads.push_str(&format!(
                "{} <{}endLine> \"{}\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
                subject, NARSIL_NS, symbol.end_line
            ));

            if let Some(ref sig) = symbol.signature {
                nquads.push_str(&format!(
                    "{} <{}signature> \"{}\" .\n",
                    subject,
                    NARSIL_NS,
                    escape_nquads_string(sig)
                ));
            }

            // Full docstring (not truncated)
            if let Some(ref doc) = symbol.doc_comment {
                nquads.push_str(&format!(
                    "{} <{}docComment> \"{}\" .\n",
                    subject,
                    NARSIL_NS,
                    escape_nquads_string(doc)
                ));
            }

            if let Some(complexity) = symbol.complexity {
                nquads.push_str(&format!(
                    "{} <{}complexity> \"{}\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
                    subject, NARSIL_NS, complexity
                ));
            }

            // Is public flag
            nquads.push_str(&format!(
                "{} <{}isPublic> \"{}\"^^<http://www.w3.org/2001/XMLSchema#boolean> .\n",
                subject, NARSIL_NS, symbol.is_public
            ));
        }

        // Call edges
        for edge in &input.call_edges {
            let caller = format!(
                "<https://narsilmcp.com/code/{}/{}::{}>",
                input.repo_name,
                edge.caller_file.replace('/', "%2F"),
                edge.caller
            );
            let callee = format!(
                "<https://narsilmcp.com/code/{}/{}::{}>",
                input.repo_name,
                edge.callee_file.replace('/', "%2F"),
                edge.callee
            );
            nquads.push_str(&format!("{} <{}calls> {} .\n", caller, NARSIL_NS, callee));
        }

        // Import edges
        for edge in &input.import_edges {
            let source = format!(
                "<https://narsilmcp.com/code/{}/file/{}>",
                input.repo_name,
                edge.source_file.replace('/', "%2F")
            );
            let target = format!(
                "<https://narsilmcp.com/code/{}/module/{}>",
                input.repo_name,
                edge.target_module.replace('/', "%2F").replace(':', "%3A")
            );
            nquads.push_str(&format!("{} <{}imports> {} .\n", source, NARSIL_NS, target));
        }

        // Security findings
        for finding in &input.security_findings {
            let finding_id = format!(
                "<https://narsilmcp.com/code/{}/finding/{}@L{}>",
                input.repo_name,
                finding.file.replace('/', "%2F"),
                finding.line
            );

            nquads.push_str(&format!(
                "{} <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <{}SecurityFinding> .\n",
                finding_id, NARSIL_NS
            ));
            nquads.push_str(&format!(
                "{} <{}ruleId> \"{}\" .\n",
                finding_id, NARSIL_NS, finding.rule_id
            ));
            nquads.push_str(&format!(
                "{} <{}severity> \"{}\" .\n",
                finding_id, NARSIL_NS, finding.severity
            ));
            nquads.push_str(&format!(
                "{} <{}filePath> \"{}\" .\n",
                finding_id, NARSIL_NS, finding.file
            ));
            nquads.push_str(&format!(
                "{} <{}message> \"{}\" .\n",
                finding_id,
                NARSIL_NS,
                escape_nquads_string(&finding.message)
            ));
        }

        // Compress with gzip
        let compressed = compress_gzip(nquads.as_bytes())?;
        let size_bytes = compressed.len();
        let content = BASE64_ENGINE.encode(&compressed);

        Ok(CcgOutput {
            layer: Layer::FullDetail,
            format: LayerFormat::NQuadsGzip,
            content,
            size_bytes,
            compressed: true,
            repo: input.repo_name.clone(),
            generated_at: timestamp,
            metadata: {
                let mut m = HashMap::new();
                m.insert("symbol_count".to_string(), json!(input.symbols.len()));
                m.insert("call_edge_count".to_string(), json!(input.call_edges.len()));
                m.insert(
                    "import_edge_count".to_string(),
                    json!(input.import_edges.len()),
                );
                m.insert(
                    "finding_count".to_string(),
                    json!(input.security_findings.len()),
                );
                m
            },
            access: self.derive_access_metadata(Layer::FullDetail, options),
        })
    }

    // Helper methods

    /// Derives access metadata for a layer based on the options.
    ///
    /// Returns the appropriate access tier based on the Triple-Heart model:
    /// - L0 (Manifest): Public
    /// - L1 (Architecture): Authenticated
    /// - L2/L3 (Symbol Index/Full Detail): Private
    fn derive_access_metadata(&self, layer: Layer, options: &CcgOptions) -> Option<AccessMetadata> {
        options.access_control.as_ref().map(|_acl| {
            let tier = match layer {
                Layer::Manifest => AccessTier::Public,
                Layer::Architecture => AccessTier::Authenticated,
                Layer::SymbolIndex | Layer::FullDetail => AccessTier::Private,
            };
            AccessMetadata::new(tier)
        })
    }

    fn count_symbols(&self, symbols: &[SymbolInfo]) -> SymbolCounts {
        let mut counts = SymbolCounts::default();

        for symbol in symbols {
            match symbol.kind.as_str() {
                "Function" | "Method" => counts.functions += 1,
                "Class" => counts.classes += 1,
                "Struct" => counts.structs += 1,
                "Trait" | "Interface" => counts.traits += 1,
                "Enum" => counts.enums += 1,
                "Module" | "Namespace" | "Package" => counts.modules += 1,
                "Constant" => counts.constants += 1,
                _ => {}
            }
            counts.total += 1;
        }

        counts
    }

    fn aggregate_languages(&self, files: &[FileInfo]) -> Vec<LanguageInfo> {
        let mut lang_counts: HashMap<String, usize> = HashMap::new();

        for file in files {
            *lang_counts.entry(file.language.clone()).or_default() += 1;
        }

        let total = files.len() as f64;
        let mut languages: Vec<_> = lang_counts
            .into_iter()
            .map(|(language, file_count)| LanguageInfo {
                language,
                file_count,
                percentage: if total > 0.0 {
                    (file_count as f64 / total) * 100.0
                } else {
                    0.0
                },
            })
            .collect();

        languages.sort_by(|a, b| b.file_count.cmp(&a.file_count));
        languages
    }

    fn aggregate_security(&self, findings: &[SecurityFindingInfo]) -> SecuritySummary {
        let mut summary = SecuritySummary::default();

        for finding in findings {
            match finding.severity.to_lowercase().as_str() {
                "critical" => summary.critical += 1,
                "high" => summary.high += 1,
                "medium" => summary.medium += 1,
                "low" => summary.low += 1,
                "info" => summary.info += 1,
                _ => summary.info += 1,
            }
            summary.total += 1;
        }

        summary
    }

    fn find_entry_points(&self, symbols: &[SymbolInfo]) -> Vec<EntryPoint> {
        let entry_point_names = ["main", "Main", "run", "start", "init", "execute"];

        symbols
            .iter()
            .filter(|s| s.kind == "Function" && entry_point_names.contains(&s.name.as_str()))
            .take(5) // Limit to top 5 entry points
            .map(|s| EntryPoint {
                name: s.name.clone(),
                file: s.file.clone(),
                line: s.start_line,
                entry_type: "function".to_string(),
            })
            .collect()
    }

    fn build_layer_uris(&self, repo: &str, options: &CcgOptions) -> LayerUris {
        if let Some(ref base) = options.base_url {
            LayerUris {
                architecture: Some(format!("{}/{}/architecture", base, repo)),
                symbol_index: Some(format!("{}/{}/symbol-index", base, repo)),
                full_detail: Some(format!("{}/{}/full-detail", base, repo)),
            }
        } else {
            LayerUris {
                architecture: None,
                symbol_index: None,
                full_detail: None,
            }
        }
    }

    fn build_module_hierarchy(&self, input: &CcgInput) -> Vec<ModuleInfo> {
        let mut module_map: HashMap<String, (String, Vec<String>, usize)> = HashMap::new();

        for symbol in &input.symbols {
            // Extract module path from file path
            let module_path = symbol
                .file
                .rsplit_once('/')
                .map(|(dir, _)| dir)
                .unwrap_or(&symbol.file);

            let entry = module_map
                .entry(module_path.to_string())
                .or_insert_with(|| {
                    let name = module_path
                        .rsplit_once('/')
                        .map(|(_, n)| n)
                        .unwrap_or(module_path);
                    (name.to_string(), Vec::new(), 0)
                });

            entry.2 += 1;
        }

        module_map
            .into_iter()
            .map(|(path, (name, children, count))| ModuleInfo {
                path,
                name,
                children,
                symbol_count: count,
            })
            .collect()
    }

    fn extract_public_api(
        &self,
        symbols: &[SymbolInfo],
        _options: &CcgOptions,
    ) -> Vec<PublicSymbol> {
        symbols
            .iter()
            .filter(|s| s.is_public)
            .take(100) // Limit to keep L1 within budget
            .map(|s| PublicSymbol {
                name: s.name.clone(),
                kind: s.kind.clone(),
                file: s.file.clone(),
                line: s.start_line,
                signature: s.signature.clone(),
            })
            .collect()
    }

    fn build_module_dependencies(&self, edges: &[ImportEdgeInfo]) -> Vec<ModuleDependency> {
        let mut dep_map: HashMap<(String, String), usize> = HashMap::new();

        for edge in edges {
            let from_module = edge
                .source_file
                .rsplit_once('/')
                .map(|(dir, _)| dir)
                .unwrap_or(&edge.source_file);

            *dep_map
                .entry((from_module.to_string(), edge.target_module.clone()))
                .or_default() += 1;
        }

        dep_map
            .into_iter()
            .map(|((from, to), count)| ModuleDependency {
                from,
                to,
                import_count: count,
            })
            .collect()
    }

    fn extract_abstractions(&self, symbols: &[SymbolInfo]) -> Vec<AbstractionInfo> {
        symbols
            .iter()
            .filter(|s| s.kind == "Trait" || s.kind == "Interface")
            .take(20) // Limit to keep L1 within budget
            .map(|s| AbstractionInfo {
                name: s.name.clone(),
                kind: s.kind.clone(),
                file: s.file.clone(),
                implementors: 0, // Would need additional analysis to determine
            })
            .collect()
    }
}

impl Default for CcgGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Escapes a string for N-Quads format.
fn escape_nquads_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Truncates a string to a maximum length, adding ellipsis if truncated.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Compresses data with gzip.
fn compress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder
        .finish()
        .map_err(|e| anyhow!("Gzip compression failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_input() -> CcgInput {
        CcgInput {
            repo_name: "test-repo".to_string(),
            repo_url: Some("https://github.com/test/repo".to_string()),
            files: vec![
                FileInfo {
                    path: "src/main.rs".to_string(),
                    language: "rust".to_string(),
                    size_bytes: 1000,
                },
                FileInfo {
                    path: "src/lib.rs".to_string(),
                    language: "rust".to_string(),
                    size_bytes: 2000,
                },
                FileInfo {
                    path: "src/utils.py".to_string(),
                    language: "python".to_string(),
                    size_bytes: 500,
                },
            ],
            symbols: vec![
                SymbolInfo {
                    name: "main".to_string(),
                    kind: "Function".to_string(),
                    file: "src/main.rs".to_string(),
                    start_line: 1,
                    end_line: 10,
                    signature: Some("fn main() -> Result<()>".to_string()),
                    doc_comment: Some("Entry point".to_string()),
                    is_public: true,
                    complexity: Some(5),
                },
                SymbolInfo {
                    name: "helper".to_string(),
                    kind: "Function".to_string(),
                    file: "src/lib.rs".to_string(),
                    start_line: 5,
                    end_line: 15,
                    signature: Some("fn helper(x: i32) -> i32".to_string()),
                    doc_comment: None,
                    is_public: true,
                    complexity: Some(3),
                },
                SymbolInfo {
                    name: "MyTrait".to_string(),
                    kind: "Trait".to_string(),
                    file: "src/lib.rs".to_string(),
                    start_line: 20,
                    end_line: 30,
                    signature: None,
                    doc_comment: Some("A test trait".to_string()),
                    is_public: true,
                    complexity: None,
                },
            ],
            call_edges: vec![CallEdgeInfo {
                caller: "main".to_string(),
                caller_file: "src/main.rs".to_string(),
                callee: "helper".to_string(),
                callee_file: "src/lib.rs".to_string(),
                line: 5,
            }],
            import_edges: vec![ImportEdgeInfo {
                source_file: "src/main.rs".to_string(),
                target_module: "std::io".to_string(),
            }],
            security_findings: vec![SecurityFindingInfo {
                rule_id: "SQL-001".to_string(),
                severity: "HIGH".to_string(),
                file: "src/db.rs".to_string(),
                line: 42,
                message: "Potential SQL injection".to_string(),
            }],
        }
    }

    #[test]
    fn test_generate_manifest_creates_valid_json() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default();

        let output = generator
            .generate_layer(Layer::Manifest, &input, &options)
            .unwrap();

        assert_eq!(output.layer, Layer::Manifest);
        assert_eq!(output.format, LayerFormat::JsonLd);
        assert!(!output.compressed);

        // Verify JSON is valid
        let manifest: Manifest = serde_json::from_str(&output.content).unwrap();
        assert_eq!(manifest.name, "test-repo");
        assert_eq!(manifest.symbol_counts.functions, 2);
        assert_eq!(manifest.symbol_counts.traits, 1);
    }

    #[test]
    fn test_manifest_includes_security_summary() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default();

        let output = generator
            .generate_layer(Layer::Manifest, &input, &options)
            .unwrap();
        let manifest: Manifest = serde_json::from_str(&output.content).unwrap();

        assert!(manifest.security_summary.is_some());
        let summary = manifest.security_summary.unwrap();
        assert_eq!(summary.high, 1);
        assert_eq!(summary.total, 1);
    }

    #[test]
    fn test_manifest_excludes_security_when_disabled() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default().without_security_summary();

        let output = generator
            .generate_layer(Layer::Manifest, &input, &options)
            .unwrap();
        let manifest: Manifest = serde_json::from_str(&output.content).unwrap();

        assert!(manifest.security_summary.is_none());
    }

    #[test]
    fn test_manifest_includes_languages() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default();

        let output = generator
            .generate_layer(Layer::Manifest, &input, &options)
            .unwrap();
        let manifest: Manifest = serde_json::from_str(&output.content).unwrap();

        assert!(!manifest.languages.is_empty());
        // Rust should be first (2 files vs 1 Python)
        assert_eq!(manifest.languages[0].language, "rust");
        assert_eq!(manifest.languages[0].file_count, 2);
    }

    #[test]
    fn test_manifest_finds_entry_points() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default();

        let output = generator
            .generate_layer(Layer::Manifest, &input, &options)
            .unwrap();
        let manifest: Manifest = serde_json::from_str(&output.content).unwrap();

        assert!(!manifest.entry_points.is_empty());
        assert!(manifest.entry_points.iter().any(|e| e.name == "main"));
    }

    #[test]
    fn test_manifest_includes_layer_uris_when_base_url_provided() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default().with_base_url("https://example.com/ccg");

        let output = generator
            .generate_layer(Layer::Manifest, &input, &options)
            .unwrap();
        let manifest: Manifest = serde_json::from_str(&output.content).unwrap();

        assert!(manifest.layer_uris.architecture.is_some());
        assert!(manifest
            .layer_uris
            .architecture
            .unwrap()
            .contains("test-repo"));
    }

    #[test]
    fn test_generate_architecture_creates_valid_json() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default();

        let output = generator
            .generate_layer(Layer::Architecture, &input, &options)
            .unwrap();

        assert_eq!(output.layer, Layer::Architecture);
        assert_eq!(output.format, LayerFormat::JsonLd);

        let architecture: Architecture = serde_json::from_str(&output.content).unwrap();
        assert_eq!(architecture.name, "test-repo");
        assert!(!architecture.modules.is_empty());
    }

    #[test]
    fn test_architecture_extracts_public_api() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default();

        let output = generator
            .generate_layer(Layer::Architecture, &input, &options)
            .unwrap();
        let architecture: Architecture = serde_json::from_str(&output.content).unwrap();

        // All test symbols are public
        assert_eq!(architecture.public_api.len(), 3);
        assert!(architecture.public_api.iter().any(|s| s.name == "main"));
    }

    #[test]
    fn test_architecture_extracts_abstractions() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default();

        let output = generator
            .generate_layer(Layer::Architecture, &input, &options)
            .unwrap();
        let architecture: Architecture = serde_json::from_str(&output.content).unwrap();

        assert!(!architecture.abstractions.is_empty());
        assert!(architecture
            .abstractions
            .iter()
            .any(|a| a.name == "MyTrait"));
    }

    #[test]
    fn test_generate_symbol_index_compressed() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default();

        let output = generator
            .generate_layer(Layer::SymbolIndex, &input, &options)
            .unwrap();

        assert_eq!(output.layer, Layer::SymbolIndex);
        assert_eq!(output.format, LayerFormat::NQuadsGzip);
        assert!(output.compressed);
        assert!(output.size_bytes > 0);
    }

    #[test]
    fn test_generate_full_detail_includes_security() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default();

        let output = generator
            .generate_layer(Layer::FullDetail, &input, &options)
            .unwrap();

        assert_eq!(output.layer, Layer::FullDetail);
        assert!(output.compressed);

        // Verify metadata includes finding count
        assert_eq!(output.metadata.get("finding_count").unwrap(), &json!(1));
    }

    #[test]
    fn test_generate_bundle_succeeds() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default();

        let bundle = generator.generate_bundle(&input, &options).unwrap();

        assert_eq!(bundle.repo, "test-repo");
        assert_eq!(bundle.layers.len(), 4);
        assert!(bundle.manifest_layers_within_budget());
    }

    #[test]
    fn test_l0_l1_combined_size_check() {
        let generator = CcgGenerator::new();
        let input = create_test_input();
        let options = CcgOptions::default();

        let bundle = generator.generate_bundle(&input, &options).unwrap();

        let l0_size = bundle.get_layer(Layer::Manifest).unwrap().size_bytes;
        let l1_size = bundle.get_layer(Layer::Architecture).unwrap().size_bytes;

        assert!(l0_size + l1_size < super::super::L0_L1_MAX_COMBINED);
    }

    #[test]
    fn test_escape_nquads_string() {
        assert_eq!(escape_nquads_string("hello"), "hello");
        assert_eq!(escape_nquads_string("hello\"world"), "hello\\\"world");
        assert_eq!(escape_nquads_string("line1\nline2"), "line1\\nline2");
        assert_eq!(escape_nquads_string("path\\to\\file"), "path\\\\to\\\\file");
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("short", 10), "short");
        assert_eq!(truncate_string("this is a long string", 10), "this is...");
    }

    #[test]
    fn test_symbol_counts() {
        let generator = CcgGenerator::new();
        let symbols = vec![
            SymbolInfo {
                name: "f1".to_string(),
                kind: "Function".to_string(),
                file: "test.rs".to_string(),
                start_line: 1,
                end_line: 5,
                signature: None,
                doc_comment: None,
                is_public: true,
                complexity: None,
            },
            SymbolInfo {
                name: "f2".to_string(),
                kind: "Function".to_string(),
                file: "test.rs".to_string(),
                start_line: 10,
                end_line: 15,
                signature: None,
                doc_comment: None,
                is_public: true,
                complexity: None,
            },
            SymbolInfo {
                name: "S1".to_string(),
                kind: "Struct".to_string(),
                file: "test.rs".to_string(),
                start_line: 20,
                end_line: 25,
                signature: None,
                doc_comment: None,
                is_public: true,
                complexity: None,
            },
        ];

        let counts = generator.count_symbols(&symbols);
        assert_eq!(counts.functions, 2);
        assert_eq!(counts.structs, 1);
        assert_eq!(counts.total, 3);
    }
}
