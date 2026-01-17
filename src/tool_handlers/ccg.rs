//! Code Context Graph (CCG) tool handlers
//!
//! These handlers are only available when the `graph` feature is enabled.

use anyhow::Result;
use serde_json::Value;

#[cfg(feature = "graph")]
use super::ArgExtractor;
use super::ToolHandler;
use crate::index::CodeIntelEngine;

#[cfg(feature = "graph")]
use crate::ccg::{AccessControl, AccessMode, AccessTier, AgentId, Authorization};

/// Handler for get_ccg_manifest tool (Layer 0)
pub struct GetCcgManifestHandler;

#[async_trait::async_trait]
impl ToolHandler for GetCcgManifestHandler {
    fn name(&self) -> &'static str {
        "get_ccg_manifest"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let include_security = args.get_bool_or("include_security", true);
        let base_url = args.get_str("base_url");

        engine
            .get_ccg_manifest(repo, include_security, base_url)
            .await
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "CCG requires the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

/// Handler for export_ccg_manifest tool (Layer 0 to file)
pub struct ExportCcgManifestHandler;

#[async_trait::async_trait]
impl ToolHandler for ExportCcgManifestHandler {
    fn name(&self) -> &'static str {
        "export_ccg_manifest"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let include_security = args.get_bool_or("include_security", true);
        let base_url = args.get_str("base_url");
        let output_path = args.get_str("output");

        engine
            .export_ccg_manifest(repo, include_security, base_url, output_path)
            .await
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "CCG requires the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

/// Handler for export_ccg_architecture tool (Layer 1)
pub struct ExportCcgArchitectureHandler;

#[async_trait::async_trait]
impl ToolHandler for ExportCcgArchitectureHandler {
    fn name(&self) -> &'static str {
        "export_ccg_architecture"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let output_path = args.get_str("output");

        engine.export_ccg_architecture(repo, output_path).await
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "CCG requires the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

/// Handler for export_ccg_index tool (Layer 2)
pub struct ExportCcgIndexHandler;

#[async_trait::async_trait]
impl ToolHandler for ExportCcgIndexHandler {
    fn name(&self) -> &'static str {
        "export_ccg_index"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let output_path = args.get_str("output");

        engine.export_ccg_index(repo, output_path).await
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "CCG requires the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

/// Handler for export_ccg_full tool (Layer 3)
pub struct ExportCcgFullHandler;

#[async_trait::async_trait]
impl ToolHandler for ExportCcgFullHandler {
    fn name(&self) -> &'static str {
        "export_ccg_full"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let output_path = args.get_str("output");

        engine.export_ccg_full(repo, output_path).await
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "CCG requires the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

/// Handler for export_ccg tool (all layers bundled)
pub struct ExportCcgHandler;

#[async_trait::async_trait]
impl ToolHandler for ExportCcgHandler {
    fn name(&self) -> &'static str {
        "export_ccg"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let output_dir = args.get_str("output_dir");
        let base_url = args.get_str("base_url");
        let include_security = args.get_bool_or("include_security", true);

        engine
            .export_ccg(repo, output_dir, base_url, include_security)
            .await
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "CCG requires the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

/// Handler for query_ccg tool (query against L3 via SPARQL)
pub struct QueryCcgHandler;

#[async_trait::async_trait]
impl ToolHandler for QueryCcgHandler {
    fn name(&self) -> &'static str {
        "query_ccg"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let query = args.get_str("query").unwrap_or("");
        let timeout_ms = args.get_u64("timeout_ms");
        let limit = args.get_u64("limit").map(|v| v as usize);

        engine.query_ccg(repo, query, timeout_ms, limit).await
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "CCG requires the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

/// Handler for get_ccg_acl tool (generate WebACL document)
pub struct GetCcgAclHandler;

#[async_trait::async_trait]
impl ToolHandler for GetCcgAclHandler {
    fn name(&self) -> &'static str {
        "get_ccg_acl"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, _engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("unknown");
        let tier_str = args.get_str("tier").unwrap_or("triple-heart");
        let agent_uri = args.get_str("agent");

        // Determine access tier
        let acl = match tier_str {
            "public" => AccessControl::all_public(repo),
            _ => {
                let mut acl = AccessControl::default_triple_heart(repo);

                // Add specific agent if provided (for private tier access)
                if let Some(uri) = agent_uri {
                    let agent = AgentId::new(uri);
                    // Update authorizations to include the agent
                    for auth in &mut acl.authorizations {
                        if auth.tier == AccessTier::Private {
                            auth.agents.insert(agent.clone());
                        }
                    }
                }
                acl
            }
        };

        // Generate Turtle output
        Ok(acl.to_turtle())
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "CCG requires the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

/// Handler for get_ccg_access_info tool (get access tier information)
pub struct GetCcgAccessInfoHandler;

#[async_trait::async_trait]
impl ToolHandler for GetCcgAccessInfoHandler {
    fn name(&self) -> &'static str {
        "get_ccg_access_info"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, _engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let tier_str = args.get_str("tier").unwrap_or("public");

        let tier = match tier_str {
            "authenticated" => AccessTier::Authenticated,
            "private" => AccessTier::Private,
            _ => AccessTier::Public,
        };

        // Build access mode info
        let modes = [
            AccessMode::Read,
            AccessMode::Write,
            AccessMode::Append,
            AccessMode::Control,
        ];
        let mode_info: Vec<String> = modes
            .iter()
            .map(|m| format!("- {}: {}", m.name(), m.uri()))
            .collect();

        // Create authorization example
        let auth = Authorization::new(
            format!("{}-example", tier_str),
            format!("https://example.com/ccg/{}/resource", tier_str),
            tier,
        );

        let info = format!(
            "# CCG Access Tier: {} {}\n\n\
             **Color:** {} Heart\n\n\
             **Agent Class:** {}\n\n\
             **Accessible Layers:** {:?}\n\n\
             ## Access Modes\n\n{}\n\n\
             ## Example Authorization (Turtle)\n\n```turtle\n{}\n```",
            tier.emoji(),
            tier.name(),
            tier.heart_color(),
            tier.agent_class()
                .unwrap_or("Specific agents (via acl:agent)"),
            tier.accessible_layers()
                .iter()
                .map(|l| format!("L{}", l.number()))
                .collect::<Vec<_>>(),
            mode_info.join("\n"),
            auth.to_turtle()
        );

        Ok(info)
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "CCG requires the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

/// Handler for import_ccg tool (import CCG from URL or file)
pub struct ImportCcgHandler;

#[async_trait::async_trait]
impl ToolHandler for ImportCcgHandler {
    fn name(&self) -> &'static str {
        "import_ccg"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, _engine: &CodeIntelEngine, args: Value) -> Result<String> {
        use crate::ccg::import::{layer_from_filename, parse_registry_url, CcgImporter};

        let url = args.get_str("url");
        let path = args.get_str("path");
        let layer_str = args.get_str("layer");

        // Determine import source
        if url.is_none() && path.is_none() {
            return Err(anyhow::anyhow!(
                "Either 'url' or 'path' parameter is required"
            ));
        }

        let importer = CcgImporter::new();

        // Import from file path
        if let Some(file_path) = path {
            let layer = if let Some(l) = layer_str {
                match l {
                    "manifest" | "0" => crate::ccg::Layer::Manifest,
                    "architecture" | "1" => crate::ccg::Layer::Architecture,
                    "symbol_index" | "index" | "2" => crate::ccg::Layer::SymbolIndex,
                    "full_detail" | "full" | "3" => crate::ccg::Layer::FullDetail,
                    _ => return Err(anyhow::anyhow!("Invalid layer: {}", l)),
                }
            } else {
                // Try to determine from filename
                let filename = std::path::Path::new(file_path)
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("");
                layer_from_filename(filename).ok_or_else(|| {
                    anyhow::anyhow!("Could not determine layer from filename: {}", filename)
                })?
            };

            let imported = match layer {
                crate::ccg::Layer::Manifest => importer.load_manifest_from_file(file_path)?,
                crate::ccg::Layer::Architecture => {
                    importer.load_architecture_from_file(file_path)?
                }
                crate::ccg::Layer::SymbolIndex | crate::ccg::Layer::FullDetail => {
                    importer.load_nquads_from_file(file_path, layer)?
                }
            };

            return Ok(serde_json::json!({
                "status": "success",
                "layer": format!("{:?}", imported.layer),
                "source": imported.source,
                "size_bytes": imported.size_bytes,
                "was_compressed": imported.was_compressed,
                "preview": if imported.content.len() > 500 {
                    format!("{}...", &imported.content[..500])
                } else {
                    imported.content.clone()
                }
            })
            .to_string());
        }

        // Import from URL
        if let Some(registry_url) = url {
            // Determine which layer to fetch
            let layer = if let Some(l) = layer_str {
                match l {
                    "manifest" | "0" => crate::ccg::Layer::Manifest,
                    "architecture" | "1" => crate::ccg::Layer::Architecture,
                    "symbol_index" | "index" | "2" => crate::ccg::Layer::SymbolIndex,
                    "full_detail" | "full" | "3" => crate::ccg::Layer::FullDetail,
                    _ => return Err(anyhow::anyhow!("Invalid layer: {}", l)),
                }
            } else {
                // Try to determine from URL
                let (_, _, _, _, filename) = parse_registry_url(registry_url)?;
                layer_from_filename(&filename).ok_or_else(|| {
                    anyhow::anyhow!("Could not determine layer from URL: {}", registry_url)
                })?
            };

            let imported = importer.fetch_layer(registry_url, layer).await?;

            return Ok(serde_json::json!({
                "status": "success",
                "layer": format!("{:?}", imported.layer),
                "source": imported.source,
                "size_bytes": imported.size_bytes,
                "was_compressed": imported.was_compressed,
                "preview": if imported.content.len() > 500 {
                    format!("{}...", &imported.content[..500])
                } else {
                    imported.content.clone()
                }
            })
            .to_string());
        }

        Err(anyhow::anyhow!("No valid import source specified"))
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "CCG requires the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

/// Handler for import_ccg_from_registry tool (import all layers from registry)
pub struct ImportCcgFromRegistryHandler;

#[async_trait::async_trait]
impl ToolHandler for ImportCcgFromRegistryHandler {
    fn name(&self) -> &'static str {
        "import_ccg_from_registry"
    }

    #[cfg(feature = "graph")]
    async fn execute(&self, _engine: &CodeIntelEngine, args: Value) -> Result<String> {
        use crate::ccg::import::CcgImporter;

        let host = args.get_str("host").unwrap_or("github.com");
        let owner = args
            .get_str("owner")
            .ok_or_else(|| anyhow::anyhow!("'owner' parameter is required"))?;
        let repo = args
            .get_str("repo")
            .ok_or_else(|| anyhow::anyhow!("'repo' parameter is required"))?;
        let commit = args.get_str("commit").unwrap_or("latest");

        let importer = CcgImporter::new();
        let imported_layers = importer
            .fetch_from_registry(host, owner, repo, commit)
            .await?;

        let layer_summaries: Vec<_> = imported_layers
            .iter()
            .map(|l| {
                serde_json::json!({
                    "layer": format!("{:?}", l.layer),
                    "size_bytes": l.size_bytes,
                    "was_compressed": l.was_compressed
                })
            })
            .collect();

        Ok(serde_json::json!({
            "status": "success",
            "registry_url": format!(
                "https://codecontextgraph.com/ccg/{}/{}/{}@{}",
                host, owner, repo, commit
            ),
            "layers_imported": imported_layers.len(),
            "layers": layer_summaries
        })
        .to_string())
    }

    #[cfg(not(feature = "graph"))]
    async fn execute(&self, _engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        Err(anyhow::anyhow!(
            "CCG requires the 'graph' feature. Rebuild with --features graph"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_names() {
        assert_eq!(GetCcgManifestHandler.name(), "get_ccg_manifest");
        assert_eq!(ExportCcgManifestHandler.name(), "export_ccg_manifest");
        assert_eq!(
            ExportCcgArchitectureHandler.name(),
            "export_ccg_architecture"
        );
        assert_eq!(ExportCcgIndexHandler.name(), "export_ccg_index");
        assert_eq!(ExportCcgFullHandler.name(), "export_ccg_full");
        assert_eq!(ExportCcgHandler.name(), "export_ccg");
        assert_eq!(QueryCcgHandler.name(), "query_ccg");
        assert_eq!(GetCcgAclHandler.name(), "get_ccg_acl");
        assert_eq!(GetCcgAccessInfoHandler.name(), "get_ccg_access_info");
        assert_eq!(ImportCcgHandler.name(), "import_ccg");
        assert_eq!(
            ImportCcgFromRegistryHandler.name(),
            "import_ccg_from_registry"
        );
    }
}
