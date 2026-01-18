//! Graph visualization tool handler
//!
//! This module provides a unified JSON API for graph visualization,
//! wrapping existing call graph, import graph, and symbol data.
//! Returns data in a format optimized for frontend visualization libraries like Cytoscape.js.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use super::{ArgExtractor, ToolHandler};
use crate::callgraph::CallType;
use crate::index::CodeIntelEngine;

// ============================================================================
// JSON Schema Types (matching frontend TypeScript interfaces)
// ============================================================================

/// The complete graph structure for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeGraph {
    pub metadata: GraphMetadata,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clusters: Option<Vec<Cluster>>,
}

/// Metadata about the generated graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphMetadata {
    pub repo: String,
    pub view: String,
    pub generated_at: String,
    pub node_count: usize,
    pub edge_count: usize,
}

/// A node in the visualization graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub file_path: String,
    pub line: usize,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<NodeMetrics>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<NodeSecurity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
}

/// Complexity metrics for a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub loc: usize,
    pub cyclomatic: usize,
    pub cognitive: usize,
    pub call_count: usize,
    pub caller_count: usize,
}

/// Security information for a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSecurity {
    pub has_vulnerabilities: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    pub taint_source: bool,
    pub taint_sink: bool,
}

/// An edge in the visualization graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    #[serde(rename = "type")]
    pub edge_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_cycle: Option<bool>,
}

/// A cluster (group) of nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cluster {
    pub id: String,
    pub label: String,
    pub nodes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// Supported graph view types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewType {
    Call,
    Import,
    Symbol,
    Hybrid,
    Flow,
}

/// Options for building graphs, consolidating multiple parameters
#[derive(Debug, Clone)]
pub struct GraphBuildOptions<'a> {
    pub repo: &'a str,
    pub root: Option<&'a str>,
    pub depth: usize,
    pub direction: &'a str,
    pub include_metrics: bool,
    pub include_excerpts: bool,
    pub cluster_by: &'a str,
    pub min_complexity: Option<usize>,
    pub file_pattern: Option<&'a str>,
}

impl ViewType {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "call" => Some(ViewType::Call),
            "import" => Some(ViewType::Import),
            "symbol" => Some(ViewType::Symbol),
            "hybrid" => Some(ViewType::Hybrid),
            "flow" => Some(ViewType::Flow),
            _ => None,
        }
    }
}

// ============================================================================
// Tool Handler
// ============================================================================

/// Handler for the get_code_graph tool
pub struct GetCodeGraphHandler;

#[async_trait::async_trait]
impl ToolHandler for GetCodeGraphHandler {
    fn name(&self) -> &'static str {
        "get_code_graph"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let view_str = args.get_str("view").unwrap_or("call");
        let view = ViewType::from_str(view_str).ok_or_else(|| {
            anyhow!(
                "Invalid view type: {}. Expected: call, import, symbol, hybrid, or flow",
                view_str
            )
        })?;

        let repo = args.get_str("repo").unwrap_or("");
        let root = args.get_str("root");
        let depth = args.get_u64_or("depth", 3) as usize;
        let direction = args.get_str("direction").unwrap_or("both");
        let include_metrics = args.get_bool_or("include_metrics", true);
        let include_security = args.get_bool_or("include_security", false);
        let include_excerpts = args.get_bool_or("include_excerpts", false);
        let cluster_by = args.get_str("cluster_by").unwrap_or("none");

        // Extract filter options
        let min_complexity = args
            .get("filter")
            .and_then(|f| f.get("min_complexity"))
            .and_then(|v| v.as_u64())
            .map(|v| v as usize);

        let file_pattern = args
            .get("filter")
            .and_then(|f| f.get("file_pattern"))
            .and_then(|v| v.as_str());

        let options = GraphBuildOptions {
            repo,
            root,
            depth,
            direction,
            include_metrics,
            include_excerpts,
            cluster_by,
            min_complexity,
            file_pattern,
        };

        let graph = match view {
            ViewType::Call => self.build_call_graph(engine, &options).await?,
            ViewType::Import => {
                self.build_import_graph(engine, repo, root, depth, direction, cluster_by)
                    .await?
            }
            ViewType::Symbol => {
                self.build_symbol_graph(engine, repo, root, depth, cluster_by)
                    .await?
            }
            ViewType::Hybrid => self.build_hybrid_graph(engine, &options).await?,
            ViewType::Flow => {
                self.build_flow_graph(engine, repo, root, cluster_by)
                    .await?
            }
        };

        // Optionally overlay security information
        let graph = if include_security {
            self.add_security_overlay(engine, repo, graph).await?
        } else {
            graph
        };

        serde_json::to_string_pretty(&graph)
            .map_err(|e| anyhow!("Failed to serialize graph: {}", e))
    }
}

impl GetCodeGraphHandler {
    // ========================================================================
    // Call Graph Builder
    // ========================================================================

    async fn build_call_graph(
        &self,
        engine: &CodeIntelEngine,
        options: &GraphBuildOptions<'_>,
    ) -> Result<CodeGraph> {
        // Access call graph data through engine
        let call_graph_data = engine.get_call_graph_for_viz(options.repo)?;

        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut visited = HashSet::new();
        let mut edge_id = 0;

        // Determine starting points
        let starting_nodes: Vec<String> = if let Some(r) = options.root {
            if let Some(func_name) = call_graph_data.find_function(r) {
                vec![func_name]
            } else {
                // Return similar functions as suggestions
                let similar = call_graph_data.get_similar_functions(r, 5);
                if similar.is_empty() {
                    return Err(anyhow!("Function '{}' not found in call graph", r));
                } else {
                    return Err(anyhow!(
                        "Function '{}' not found. Did you mean: {}?",
                        r,
                        similar.join(", ")
                    ));
                }
            }
        } else {
            // Get all functions (entry points first if possible)
            call_graph_data.get_all_function_names()
        };

        // Limit starting nodes for manageable graph size
        let starting_nodes: Vec<String> = starting_nodes.into_iter().take(100).collect();

        // BFS traversal
        let mut queue: Vec<(String, usize)> = starting_nodes.into_iter().map(|n| (n, 0)).collect();

        while let Some((func_name, current_depth)) = queue.pop() {
            if visited.contains(&func_name) || current_depth > options.depth {
                continue;
            }
            visited.insert(func_name.clone());

            if let Some(node) = call_graph_data.get_node(&func_name) {
                // Apply complexity filter
                if let Some(min) = options.min_complexity {
                    if node.metrics.cyclomatic < min {
                        continue;
                    }
                }

                // Create graph node
                let graph_node = GraphNode {
                    id: func_name.clone(),
                    label: short_name(&func_name),
                    kind: "function".to_string(),
                    file_path: node.file_path.clone(),
                    line: node.line,
                    metrics: if options.include_metrics {
                        Some(NodeMetrics {
                            loc: node.metrics.loc,
                            cyclomatic: node.metrics.cyclomatic,
                            cognitive: node.metrics.cognitive,
                            call_count: node.calls.len(),
                            caller_count: node.called_by.len(),
                        })
                    } else {
                        None
                    },
                    security: None,
                    excerpt: if options.include_excerpts {
                        engine
                            .get_excerpt_for_viz(options.repo, &node.file_path, node.line, 5)
                            .await
                            .ok()
                    } else {
                        None
                    },
                };
                nodes.push(graph_node);

                // Add edges based on direction
                if matches!(options.direction, "both" | "callees") {
                    for call in &node.calls {
                        edges.push(GraphEdge {
                            id: format!("e{}", edge_id),
                            source: func_name.clone(),
                            target: call.target.clone(),
                            edge_type: "call".to_string(),
                            label: None,
                            call_type: Some(call_type_string(&call.call_type)),
                            weight: Some(1.0),
                            is_cycle: None,
                        });
                        edge_id += 1;

                        if current_depth < options.depth {
                            queue.push((call.target.clone(), current_depth + 1));
                        }
                    }
                }

                if matches!(options.direction, "both" | "callers") {
                    for caller in &node.called_by {
                        edges.push(GraphEdge {
                            id: format!("e{}", edge_id),
                            source: caller.target.clone(),
                            target: func_name.clone(),
                            edge_type: "call".to_string(),
                            label: None,
                            call_type: Some(call_type_string(&caller.call_type)),
                            weight: Some(1.0),
                            is_cycle: None,
                        });
                        edge_id += 1;

                        if current_depth < options.depth {
                            queue.push((caller.target.clone(), current_depth + 1));
                        }
                    }
                }
            }
        }

        // Deduplicate edges
        let mut seen_edges = HashSet::new();
        edges.retain(|e| seen_edges.insert((e.source.clone(), e.target.clone())));

        // Build clusters if requested
        let clusters = if options.cluster_by == "file" {
            Some(build_file_clusters(&nodes))
        } else {
            None
        };

        Ok(CodeGraph {
            metadata: GraphMetadata {
                repo: options.repo.to_string(),
                view: "call".to_string(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                node_count: nodes.len(),
                edge_count: edges.len(),
            },
            nodes,
            edges,
            clusters,
        })
    }

    // ========================================================================
    // Import Graph Builder
    // ========================================================================

    async fn build_import_graph(
        &self,
        engine: &CodeIntelEngine,
        repo: &str,
        _root: Option<&str>,
        _depth: usize,
        _direction: &str,
        cluster_by: &str,
    ) -> Result<CodeGraph> {
        // Get import graph data through engine
        let import_data = engine.get_import_graph_for_viz(repo).await?;

        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut visited = HashSet::new();
        let mut edge_id = 0;

        for (file, imports) in &import_data.files {
            let file_str = file.to_string();

            if !visited.contains(&file_str) {
                visited.insert(file_str.clone());
                nodes.push(GraphNode {
                    id: file_str.clone(),
                    label: file_name(&file_str),
                    kind: "file".to_string(),
                    file_path: file_str.clone(),
                    line: 1,
                    metrics: None,
                    security: None,
                    excerpt: None,
                });
            }

            for import in imports {
                let is_cycle = import_data.cycles.iter().any(|cycle| {
                    cycle
                        .windows(2)
                        .any(|w| w[0] == file_str && w[1] == *import)
                });

                edges.push(GraphEdge {
                    id: format!("e{}", edge_id),
                    source: file_str.clone(),
                    target: import.clone(),
                    edge_type: "import".to_string(),
                    label: None,
                    call_type: None,
                    weight: Some(1.0),
                    is_cycle: if is_cycle { Some(true) } else { None },
                });
                edge_id += 1;

                // Ensure target node exists
                if !visited.contains(import) {
                    visited.insert(import.clone());
                    nodes.push(GraphNode {
                        id: import.clone(),
                        label: file_name(import),
                        kind: "file".to_string(),
                        file_path: import.clone(),
                        line: 1,
                        metrics: None,
                        security: None,
                        excerpt: None,
                    });
                }
            }
        }

        // Build clusters if requested
        let clusters = if cluster_by == "file" {
            // For import graphs, cluster by directory instead of file
            Some(build_directory_clusters(&nodes))
        } else {
            None
        };

        Ok(CodeGraph {
            metadata: GraphMetadata {
                repo: repo.to_string(),
                view: "import".to_string(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                node_count: nodes.len(),
                edge_count: edges.len(),
            },
            nodes,
            edges,
            clusters,
        })
    }

    // ========================================================================
    // Symbol Reference Graph Builder
    // ========================================================================

    async fn build_symbol_graph(
        &self,
        engine: &CodeIntelEngine,
        repo: &str,
        root: Option<&str>,
        _depth: usize,
        cluster_by: &str,
    ) -> Result<CodeGraph> {
        let symbol_name =
            root.ok_or_else(|| anyhow!("Symbol graph requires 'root' parameter (symbol name)"))?;

        // Get symbol data through engine
        let symbol_data = engine.get_symbol_graph_for_viz(repo, symbol_name).await?;

        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        // Add the root symbol
        nodes.push(GraphNode {
            id: symbol_data.definition.id.clone(),
            label: symbol_name.to_string(),
            kind: symbol_data.definition.kind.clone(),
            file_path: symbol_data.definition.file_path.clone(),
            line: symbol_data.definition.line,
            metrics: None,
            security: None,
            excerpt: None,
        });

        // Add references as nodes and edges
        for (edge_id, reference) in symbol_data.references.iter().enumerate() {
            let ref_id = format!("{}:{}", reference.file_path, reference.line);
            nodes.push(GraphNode {
                id: ref_id.clone(),
                label: format!("ref@{}:{}", file_name(&reference.file_path), reference.line),
                kind: "reference".to_string(),
                file_path: reference.file_path.clone(),
                line: reference.line,
                metrics: None,
                security: None,
                excerpt: None,
            });

            edges.push(GraphEdge {
                id: format!("e{}", edge_id),
                source: ref_id,
                target: symbol_data.definition.id.clone(),
                edge_type: "reference".to_string(),
                label: None,
                call_type: None,
                weight: Some(1.0),
                is_cycle: None,
            });
        }

        // Build clusters if requested
        let clusters = if cluster_by == "file" {
            Some(build_file_clusters(&nodes))
        } else {
            None
        };

        Ok(CodeGraph {
            metadata: GraphMetadata {
                repo: repo.to_string(),
                view: "symbol".to_string(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                node_count: nodes.len(),
                edge_count: edges.len(),
            },
            nodes,
            edges,
            clusters,
        })
    }

    // ========================================================================
    // Hybrid Graph Builder (Calls + Imports)
    // ========================================================================

    async fn build_hybrid_graph(
        &self,
        engine: &CodeIntelEngine,
        options: &GraphBuildOptions<'_>,
    ) -> Result<CodeGraph> {
        // Build both graphs
        let call_graph = self.build_call_graph(engine, options).await?;

        let import_graph = self
            .build_import_graph(
                engine,
                options.repo,
                options.root,
                options.depth,
                options.direction,
                options.cluster_by,
            )
            .await?;

        // Merge nodes (dedup by id)
        let mut nodes_map: HashMap<String, GraphNode> = HashMap::new();
        for node in call_graph.nodes {
            nodes_map.insert(node.id.clone(), node);
        }
        for node in import_graph.nodes {
            nodes_map.entry(node.id.clone()).or_insert(node);
        }

        // Combine edges (renumber to avoid conflicts)
        let mut edges = call_graph.edges;
        let offset = edges.len();
        for (i, mut edge) in import_graph.edges.into_iter().enumerate() {
            edge.id = format!("e{}", offset + i);
            edges.push(edge);
        }

        // Merge clusters if present
        let clusters = match (call_graph.clusters, import_graph.clusters) {
            (Some(mut c1), Some(c2)) => {
                c1.extend(c2);
                Some(c1)
            }
            (Some(c), None) | (None, Some(c)) => Some(c),
            (None, None) => None,
        };

        Ok(CodeGraph {
            metadata: GraphMetadata {
                repo: options.repo.to_string(),
                view: "hybrid".to_string(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                node_count: nodes_map.len(),
                edge_count: edges.len(),
            },
            nodes: nodes_map.into_values().collect(),
            edges,
            clusters,
        })
    }

    // ========================================================================
    // Flow Graph Builder (CFG for single function)
    // ========================================================================

    async fn build_flow_graph(
        &self,
        engine: &CodeIntelEngine,
        repo: &str,
        root: Option<&str>,
        _cluster_by: &str,
    ) -> Result<CodeGraph> {
        let function =
            root.ok_or_else(|| anyhow!("Flow graph requires 'root' parameter (function name)"))?;

        // Get control flow graph through engine
        let cfg_data = engine.get_cfg_for_viz(repo, function).await?;

        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut edge_id = 0;

        // Convert CFG blocks to graph nodes
        for block in &cfg_data.blocks {
            nodes.push(GraphNode {
                id: block.id.clone(),
                label: block.label.clone(),
                kind: block.block_type.clone(),
                file_path: cfg_data.file_path.clone(),
                line: block.start_line,
                metrics: None,
                security: None,
                excerpt: Some(block.code.clone()),
            });
        }

        // Add CFG edges
        for edge in &cfg_data.edges {
            edges.push(GraphEdge {
                id: format!("e{}", edge_id),
                source: edge.from.clone(),
                target: edge.to.clone(),
                edge_type: edge.edge_type.clone(),
                label: edge.condition.clone(),
                call_type: None,
                weight: Some(1.0),
                is_cycle: edge.is_back_edge,
            });
            edge_id += 1;
        }

        Ok(CodeGraph {
            metadata: GraphMetadata {
                repo: repo.to_string(),
                view: "flow".to_string(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                node_count: nodes.len(),
                edge_count: edges.len(),
            },
            nodes,
            edges,
            clusters: None,
        })
    }

    // ========================================================================
    // Security Overlay
    // ========================================================================

    async fn add_security_overlay(
        &self,
        engine: &CodeIntelEngine,
        repo: &str,
        mut graph: CodeGraph,
    ) -> Result<CodeGraph> {
        // Extract unique file paths from graph nodes - only scan files that are in the graph
        let file_paths: Vec<String> = graph
            .nodes
            .iter()
            .map(|n| n.file_path.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // Get security summary from engine - only for files in the graph
        if let Ok(security_data) = engine.get_security_for_viz(repo, &file_paths).await {
            // Build a map with multiple key variants for each vulnerability
            // This handles absolute vs relative path mismatches
            let mut vuln_map: HashMap<String, (bool, Option<String>)> = HashMap::new();
            for vuln in &security_data.vulnerabilities {
                // Generate multiple keys for the same vulnerability
                for key in normalize_path_key(&vuln.file_path, vuln.line) {
                    vuln_map.insert(key, (true, Some(vuln.severity.clone())));
                }
                // Also map by function name if available
                if let Some(func) = &vuln.function {
                    vuln_map.insert(func.clone(), (true, Some(vuln.severity.clone())));
                }
            }

            // Build taint source/sink sets with normalized keys
            let mut taint_sources: HashSet<String> = HashSet::new();
            for source in &security_data.taint_sources {
                taint_sources.insert(source.clone());
                // Add filename-only variant
                if let Some(colon_idx) = source.rfind(':') {
                    let path = &source[..colon_idx];
                    let line = &source[colon_idx + 1..];
                    if let Some(fname) = std::path::Path::new(path).file_name() {
                        taint_sources.insert(format!("{}:{}", fname.to_string_lossy(), line));
                    }
                }
            }
            let mut taint_sinks: HashSet<String> = HashSet::new();
            for sink in &security_data.taint_sinks {
                taint_sinks.insert(sink.clone());
                // Add filename-only variant
                if let Some(colon_idx) = sink.rfind(':') {
                    let path = &sink[..colon_idx];
                    let line = &sink[colon_idx + 1..];
                    if let Some(fname) = std::path::Path::new(path).file_name() {
                        taint_sinks.insert(format!("{}:{}", fname.to_string_lossy(), line));
                    }
                }
            }

            // Update nodes with security info
            for node in &mut graph.nodes {
                // Try multiple key variants for matching
                let node_keys = normalize_path_key(&node.file_path, node.line);
                let has_vuln = node_keys
                    .iter()
                    .find_map(|key| vuln_map.get(key))
                    .or_else(|| vuln_map.get(&node.id));

                let is_taint_source = node_keys.iter().any(|key| taint_sources.contains(key))
                    || taint_sources.contains(&node.id);
                let is_taint_sink = node_keys.iter().any(|key| taint_sinks.contains(key))
                    || taint_sinks.contains(&node.id);

                if has_vuln.is_some() || is_taint_source || is_taint_sink {
                    node.security = Some(NodeSecurity {
                        has_vulnerabilities: has_vuln.map(|v| v.0).unwrap_or(false),
                        severity: has_vuln.and_then(|v| v.1.clone()),
                        taint_source: is_taint_source,
                        taint_sink: is_taint_sink,
                    });
                }
            }
        }

        Ok(graph)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract the short name from a fully qualified name
fn short_name(full_name: &str) -> String {
    full_name
        .split("::")
        .last()
        .unwrap_or(full_name)
        .to_string()
}

/// Extract the filename from a path
fn file_name(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

/// Normalize a file path for comparison - extract just the filename:line for matching
fn normalize_path_key(path: &str, line: usize) -> Vec<String> {
    let mut keys = Vec::new();

    // Full path key
    keys.push(format!("{}:{}", path, line));

    // Filename only key (for cross-path matching)
    if let Some(fname) = std::path::Path::new(path).file_name() {
        keys.push(format!("{}:{}", fname.to_string_lossy(), line));
    }

    // Try to extract relative path by finding common patterns like src/, lib/, etc.
    for prefix in &[
        "src/",
        "lib/",
        "test/",
        "tests/",
        "pkg/",
        "cmd/",
        "internal/",
        "app/",
    ] {
        if let Some(idx) = path.find(prefix) {
            keys.push(format!("{}:{}", &path[idx..], line));
        }
    }

    keys
}

/// Convert CallType to string
fn call_type_string(ct: &CallType) -> String {
    match ct {
        CallType::Direct => "direct",
        CallType::Method => "method",
        CallType::StaticMethod => "static",
        CallType::Closure => "closure",
        CallType::Async => "async",
        CallType::Spawn => "spawn",
        CallType::Unknown => "unknown",
    }
    .to_string()
}

/// Build file-based clusters from nodes
fn build_file_clusters(nodes: &[GraphNode]) -> Vec<Cluster> {
    let mut file_to_nodes: HashMap<String, Vec<String>> = HashMap::new();

    for node in nodes {
        file_to_nodes
            .entry(node.file_path.clone())
            .or_default()
            .push(node.id.clone());
    }

    file_to_nodes
        .into_iter()
        .map(|(file, node_ids)| Cluster {
            id: format!("cluster_{}", file.replace(['/', '\\', '.'], "_")),
            label: file_name(&file),
            nodes: node_ids,
            parent: None,
        })
        .collect()
}

/// Build directory-based clusters from nodes (useful for import graphs where nodes are files)
fn build_directory_clusters(nodes: &[GraphNode]) -> Vec<Cluster> {
    let mut dir_to_nodes: HashMap<String, Vec<String>> = HashMap::new();

    for node in nodes {
        let dir = std::path::Path::new(&node.file_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| ".".to_string());

        dir_to_nodes.entry(dir).or_default().push(node.id.clone());
    }

    dir_to_nodes
        .into_iter()
        .filter(|(_, nodes)| nodes.len() > 1) // Only cluster if more than 1 node
        .map(|(dir, node_ids)| {
            let label = if dir.is_empty() || dir == "." {
                "root".to_string()
            } else {
                dir.split(['/', '\\'])
                    .next_back()
                    .unwrap_or(&dir)
                    .to_string()
            };
            Cluster {
                id: format!("cluster_{}", dir.replace(['/', '\\', '.', ' '], "_")),
                label,
                nodes: node_ids,
                parent: None,
            }
        })
        .collect()
}

// ============================================================================
// Data Transfer Types (for engine -> handler communication)
// ============================================================================

/// Import graph data for visualization
#[derive(Debug, Clone)]
pub struct ImportGraphData {
    pub files: HashMap<String, Vec<String>>,
    pub cycles: Vec<Vec<String>>,
}

/// Symbol definition info
#[derive(Debug, Clone)]
pub struct SymbolDefinition {
    pub id: String,
    pub kind: String,
    pub file_path: String,
    pub line: usize,
}

/// Symbol reference info
#[derive(Debug, Clone)]
pub struct SymbolReference {
    pub file_path: String,
    pub line: usize,
}

/// Symbol graph data for visualization
#[derive(Debug, Clone)]
pub struct SymbolGraphData {
    pub definition: SymbolDefinition,
    pub references: Vec<SymbolReference>,
}

/// CFG block data
#[derive(Debug, Clone)]
pub struct CfgBlock {
    pub id: String,
    pub label: String,
    pub block_type: String,
    pub start_line: usize,
    pub code: String,
}

/// CFG edge data
#[derive(Debug, Clone)]
pub struct CfgEdge {
    pub from: String,
    pub to: String,
    pub edge_type: String,
    pub condition: Option<String>,
    pub is_back_edge: Option<bool>,
}

/// CFG data for visualization
#[derive(Debug, Clone)]
pub struct CfgData {
    pub file_path: String,
    pub blocks: Vec<CfgBlock>,
    pub edges: Vec<CfgEdge>,
}

/// Security data for visualization
#[derive(Debug, Clone)]
pub struct SecurityVizData {
    pub vulnerabilities: Vec<VulnInfo>,
    pub taint_sources: Vec<String>,
    pub taint_sinks: Vec<String>,
}

/// Vulnerability info
#[derive(Debug, Clone)]
pub struct VulnInfo {
    pub file_path: String,
    pub line: usize,
    pub severity: String,
    pub function: Option<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_name() {
        assert_eq!(short_name("module::submodule::function"), "function");
        assert_eq!(short_name("function"), "function");
        assert_eq!(short_name("Struct::method"), "method");
        assert_eq!(short_name(""), "");
    }

    #[test]
    fn test_file_name() {
        assert_eq!(file_name("src/lib.rs"), "lib.rs");
        assert_eq!(file_name("/path/to/file.py"), "file.py");
        assert_eq!(file_name("file.rs"), "file.rs");
    }

    #[test]
    fn test_call_type_string() {
        assert_eq!(call_type_string(&CallType::Direct), "direct");
        assert_eq!(call_type_string(&CallType::Method), "method");
        assert_eq!(call_type_string(&CallType::Async), "async");
    }

    #[test]
    fn test_view_type_from_str() {
        assert_eq!(ViewType::from_str("call"), Some(ViewType::Call));
        assert_eq!(ViewType::from_str("IMPORT"), Some(ViewType::Import));
        assert_eq!(ViewType::from_str("invalid"), None);
    }

    #[test]
    fn test_graph_serialization() {
        let graph = CodeGraph {
            metadata: GraphMetadata {
                repo: "test".to_string(),
                view: "call".to_string(),
                generated_at: "2024-12-23T00:00:00Z".to_string(),
                node_count: 1,
                edge_count: 0,
            },
            nodes: vec![GraphNode {
                id: "main".to_string(),
                label: "main".to_string(),
                kind: "function".to_string(),
                file_path: "src/main.rs".to_string(),
                line: 1,
                metrics: Some(NodeMetrics {
                    loc: 10,
                    cyclomatic: 1,
                    cognitive: 0,
                    call_count: 0,
                    caller_count: 0,
                }),
                security: None,
                excerpt: None,
            }],
            edges: vec![],
            clusters: None,
        };

        let json = serde_json::to_string(&graph).unwrap();
        assert!(json.contains("\"view\":\"call\""));
        assert!(json.contains("\"label\":\"main\""));
        assert!(json.contains("\"cyclomatic\":1"));
    }

    #[test]
    fn test_build_file_clusters() {
        let nodes = vec![
            GraphNode {
                id: "func1".to_string(),
                label: "func1".to_string(),
                kind: "function".to_string(),
                file_path: "src/lib.rs".to_string(),
                line: 10,
                metrics: None,
                security: None,
                excerpt: None,
            },
            GraphNode {
                id: "func2".to_string(),
                label: "func2".to_string(),
                kind: "function".to_string(),
                file_path: "src/lib.rs".to_string(),
                line: 20,
                metrics: None,
                security: None,
                excerpt: None,
            },
            GraphNode {
                id: "func3".to_string(),
                label: "func3".to_string(),
                kind: "function".to_string(),
                file_path: "src/main.rs".to_string(),
                line: 1,
                metrics: None,
                security: None,
                excerpt: None,
            },
        ];

        let clusters = build_file_clusters(&nodes);
        assert_eq!(clusters.len(), 2);

        // Find the lib.rs cluster
        let lib_cluster = clusters.iter().find(|c| c.label == "lib.rs").unwrap();
        assert_eq!(lib_cluster.nodes.len(), 2);
        assert!(lib_cluster.nodes.contains(&"func1".to_string()));
        assert!(lib_cluster.nodes.contains(&"func2".to_string()));
    }

    #[test]
    fn test_security_node_serialization() {
        let node = GraphNode {
            id: "vulnerable_func".to_string(),
            label: "vulnerable_func".to_string(),
            kind: "function".to_string(),
            file_path: "src/unsafe.rs".to_string(),
            line: 42,
            metrics: None,
            security: Some(NodeSecurity {
                has_vulnerabilities: true,
                severity: Some("high".to_string()),
                taint_source: false,
                taint_sink: true,
            }),
            excerpt: None,
        };

        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains("\"has_vulnerabilities\":true"));
        assert!(json.contains("\"severity\":\"high\""));
        assert!(json.contains("\"taint_sink\":true"));
    }
}
