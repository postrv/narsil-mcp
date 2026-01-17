/// Tool Metadata Registry
///
/// This module provides comprehensive metadata for all 75 MCP tools,
/// including categorization, performance indicators, required feature flags,
/// and JSON schemas.
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMetadata {
    /// Tool name (e.g., "list_repos")
    pub name: &'static str,

    /// Human-readable description
    pub description: &'static str,

    /// Category (Repository, Symbols, Search, etc.)
    pub category: ToolCategory,

    /// Tags for cross-category searching
    pub tags: HashSet<&'static str>,

    /// Stability level
    pub stability: StabilityLevel,

    /// Performance impact indicator
    pub performance: PerformanceImpact,

    /// Required CLI flags (empty if always available)
    pub required_flags: HashSet<FeatureFlag>,

    /// JSON schema for input parameters
    pub input_schema: serde_json::Value,

    /// Whether this tool requires API keys
    pub requires_api_key: bool,

    /// Aliases for discoverability
    pub aliases: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolCategory {
    Repository,
    Symbols,
    Search,
    CallGraph,
    Git,
    Lsp,
    Remote,
    Security,
    SupplyChain,
    Analysis,
    Graph,
}

impl std::fmt::Display for ToolCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolCategory::Repository => write!(f, "Repository"),
            ToolCategory::Symbols => write!(f, "Symbols"),
            ToolCategory::Search => write!(f, "Search"),
            ToolCategory::CallGraph => write!(f, "CallGraph"),
            ToolCategory::Git => write!(f, "Git"),
            ToolCategory::Lsp => write!(f, "LSP"),
            ToolCategory::Remote => write!(f, "Remote"),
            ToolCategory::Security => write!(f, "Security"),
            ToolCategory::SupplyChain => write!(f, "SupplyChain"),
            ToolCategory::Analysis => write!(f, "Analysis"),
            ToolCategory::Graph => write!(f, "Graph"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StabilityLevel {
    Stable,       // Production-ready
    Beta,         // Mostly stable, may have edge cases
    Experimental, // Under development, API may change
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PerformanceImpact {
    Low,    // <100ms typical
    Medium, // 100ms-1s typical
    High,   // >1s typical, may require API calls
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeatureFlag {
    Git,
    CallGraph,
    Lsp,
    Neural,
    Remote,
    Persist,
    Watch,
    Graph,
}

impl ToolMetadata {
    /// Check if this tool is available given current feature flags
    pub fn is_available(&self, enabled_flags: &HashSet<FeatureFlag>) -> bool {
        self.required_flags.is_subset(enabled_flags)
    }

    /// Check if this tool matches a search query
    pub fn matches_query(&self, query: &str) -> bool {
        let query_lower = query.to_lowercase();
        self.name.to_lowercase().contains(&query_lower)
            || self.description.to_lowercase().contains(&query_lower)
            || self
                .tags
                .iter()
                .any(|tag| tag.to_lowercase().contains(&query_lower))
            || self
                .aliases
                .iter()
                .any(|alias| alias.to_lowercase().contains(&query_lower))
    }
}

lazy_static! {
    /// Static registry of all tool metadata
    pub static ref TOOL_METADATA: HashMap<&'static str, ToolMetadata> = {
        let mut map = HashMap::new();

        // ===== Repository Tools (10) =====

        map.insert("list_repos", ToolMetadata {
            name: "list_repos",
            description: "List all indexed repositories with metadata (path, language breakdown, file count)",
            category: ToolCategory::Repository,
            tags: ["repository", "index", "metadata", "list"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({"type": "object", "properties": {}, "required": []}),
            requires_api_key: false,
            aliases: vec!["repos", "list_repositories"],
        });

        map.insert("get_project_structure", ToolMetadata {
            name: "get_project_structure",
            description: "Get the directory structure and key files of a repository. Returns a tree view with file types and sizes.",
            category: ToolCategory::Repository,
            tags: ["repository", "structure", "tree", "files"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository name or path"},
                    "max_depth": {"type": "integer", "description": "Maximum directory depth (default: 4)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["structure", "tree", "project_tree"],
        });

        map.insert("get_file", ToolMetadata {
            name: "get_file",
            description: "Get the contents of a specific file with optional line range",
            category: ToolCategory::Repository,
            tags: ["file", "read", "content"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File path relative to repository root"},
                    "start_line": {"type": "integer", "description": "Start line (1-indexed, optional)"},
                    "end_line": {"type": "integer", "description": "End line (inclusive, optional)"}
                },
                "required": ["repo", "path"]
            }),
            requires_api_key: false,
            aliases: vec!["read_file", "file_content"],
        });

        map.insert("get_excerpt", ToolMetadata {
            name: "get_excerpt",
            description: "Extract code excerpts around specific lines with intelligent context expansion. Automatically expands to function/class boundaries when enabled.",
            category: ToolCategory::Repository,
            tags: ["excerpt", "context", "lines", "code"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string"},
                    "lines": {"type": "array", "items": {"type": "integer"}, "description": "Line numbers to extract around (1-indexed)"},
                    "context_before": {"type": "integer", "description": "Lines of context before (default: 5)"},
                    "context_after": {"type": "integer", "description": "Lines of context after (default: 5)"},
                    "expand_to_scope": {"type": "boolean", "description": "Expand to function/class boundaries (default: true)"},
                    "max_lines": {"type": "integer", "description": "Maximum lines per excerpt (default: 50)"}
                },
                "required": ["repo", "path", "lines"]
            }),
            requires_api_key: false,
            aliases: vec!["excerpt", "code_excerpt"],
        });

        map.insert("discover_repos", ToolMetadata {
            name: "discover_repos",
            description: "Auto-discover repositories in a directory by detecting VCS roots and project markers",
            category: ToolCategory::Repository,
            tags: ["discover", "repository", "find", "vcs"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Base directory to search for repositories"},
                    "max_depth": {"type": "integer", "description": "Maximum directory depth to search (default: 3)"}
                },
                "required": ["path"]
            }),
            requires_api_key: false,
            aliases: vec!["find_repos", "discover_repositories"],
        });

        map.insert("validate_repo", ToolMetadata {
            name: "validate_repo",
            description: "Validate that a path is a valid repository and can be indexed",
            category: ToolCategory::Repository,
            tags: ["validate", "repository", "check"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to validate as a repository"}
                },
                "required": ["path"]
            }),
            requires_api_key: false,
            aliases: vec!["check_repo", "verify_repo"],
        });

        map.insert("reindex", ToolMetadata {
            name: "reindex",
            description: "Trigger re-indexing of a repository or all repositories",
            category: ToolCategory::Repository,
            tags: ["reindex", "index", "refresh"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository to reindex (optional, reindexes all if omitted)"}
                },
                "required": []
            }),
            requires_api_key: false,
            aliases: vec!["refresh", "rebuild_index"],
        });

        map.insert("get_index_status", ToolMetadata {
            name: "get_index_status",
            description: "Get status of the search index and enabled features. Shows which optional features are enabled (--git, --call-graph, --persist, --watch) and index statistics.",
            category: ToolCategory::Repository,
            tags: ["index", "status", "features", "stats"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository name (optional, shows all if omitted)"}
                },
                "required": []
            }),
            requires_api_key: false,
            aliases: vec!["status", "index_info"],
        });

        map.insert("get_incremental_status", ToolMetadata {
            name: "get_incremental_status",
            description: "Get status of incremental indexing including Merkle tree root hash, file counts, and change statistics.",
            category: ToolCategory::Repository,
            tags: ["incremental", "index", "merkle", "changes"].iter().copied().collect(),
            stability: StabilityLevel::Beta,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository name"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["incremental_status", "merkle_status"],
        });

        map.insert("get_metrics", ToolMetadata {
            name: "get_metrics",
            description: "Get performance metrics including tool execution times, indexing statistics, and server uptime",
            category: ToolCategory::Repository,
            tags: ["metrics", "performance", "stats", "timing"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "format": {"type": "string", "enum": ["markdown", "json"], "description": "Output format (default: markdown)"}
                },
                "required": []
            }),
            requires_api_key: false,
            aliases: vec!["performance", "stats"],
        });

        // ===== Symbol Tools (7) =====

        map.insert("find_symbols", ToolMetadata {
            name: "find_symbols",
            description: "Find data structures (structs, classes, enums, interfaces) and functions/methods in a repository. Supports filtering by type and name pattern.",
            category: ToolCategory::Symbols,
            tags: ["symbols", "find", "search", "structs", "functions"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "symbol_type": {"type": "string", "enum": ["struct", "class", "enum", "interface", "function", "method", "trait", "type", "all"], "description": "Type of symbol to find (default: all)"},
                    "pattern": {"type": "string", "description": "Glob or regex pattern to filter symbol names"},
                    "file_pattern": {"type": "string", "description": "Glob pattern to filter files (e.g., '*.rs', 'src/**/*.py')"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from results (default: false)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["symbols", "find_definitions"],
        });

        map.insert("get_symbol_definition", ToolMetadata {
            name: "get_symbol_definition",
            description: "Get the full definition of a symbol with surrounding context. Returns the source code with line numbers.",
            category: ToolCategory::Symbols,
            tags: ["symbol", "definition", "source", "context"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "symbol": {"type": "string", "description": "Fully qualified symbol name (e.g., 'MyStruct', 'module::function')"},
                    "context_lines": {"type": "integer", "description": "Number of context lines before/after (default: 5)"}
                },
                "required": ["repo", "symbol"]
            }),
            requires_api_key: false,
            aliases: vec!["definition", "symbol_def"],
        });

        map.insert("find_references", ToolMetadata {
            name: "find_references",
            description: "Find all references to a symbol across the codebase",
            category: ToolCategory::Symbols,
            tags: ["references", "usages", "symbol", "find"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "symbol": {"type": "string", "description": "Symbol name to find references for"},
                    "include_definition": {"type": "boolean", "description": "Include the definition location (default: true)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from results (default: false)"}
                },
                "required": ["repo", "symbol"]
            }),
            requires_api_key: false,
            aliases: vec!["references", "find_usages"],
        });

        map.insert("get_dependencies", ToolMetadata {
            name: "get_dependencies",
            description: "Analyze dependencies and imports for a file or module",
            category: ToolCategory::Symbols,
            tags: ["dependencies", "imports", "module", "analysis"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File or module path"},
                    "direction": {"type": "string", "enum": ["imports", "imported_by", "both"], "description": "Direction of dependency analysis (default: both)"}
                },
                "required": ["repo", "path"]
            }),
            requires_api_key: false,
            aliases: vec!["dependencies", "imports"],
        });

        map.insert("find_symbol_usages", ToolMetadata {
            name: "find_symbol_usages",
            description: "Find all usages of a symbol across files, including imports and re-exports. Cross-language aware for JS/TS projects.",
            category: ToolCategory::Symbols,
            tags: ["symbol", "usages", "imports", "exports"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "symbol": {"type": "string"},
                    "include_imports": {"type": "boolean", "description": "Include import statements (default: true)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from results (default: false)"}
                },
                "required": ["repo", "symbol"]
            }),
            requires_api_key: false,
            aliases: vec!["usages", "symbol_usages"],
        });

        map.insert("get_export_map", ToolMetadata {
            name: "get_export_map",
            description: "Get the export map for a file or module showing all exported symbols and their types.",
            category: ToolCategory::Symbols,
            tags: ["exports", "module", "symbols", "api"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File path to get exports for"}
                },
                "required": ["repo", "path"]
            }),
            requires_api_key: false,
            aliases: vec!["exports", "export_map"],
        });

        map.insert("workspace_symbol_search", ToolMetadata {
            name: "workspace_symbol_search",
            description: "Fuzzy search for symbols across the entire workspace. Uses trigram matching for typo-tolerant search.",
            category: ToolCategory::Symbols,
            tags: ["search", "symbols", "fuzzy", "workspace"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Symbol name or partial name to search for"},
                    "kind": {"type": "string", "enum": ["function", "class", "struct", "interface", "enum", "variable", "all"], "description": "Filter by symbol kind (default: all)"},
                    "limit": {"type": "integer", "description": "Maximum results to return (default: 20)"}
                },
                "required": ["query"]
            }),
            requires_api_key: false,
            aliases: vec!["search_symbols", "fuzzy_symbols"],
        });

        // ===== Search Tools (12) =====

        map.insert("search_code", ToolMetadata {
            name: "search_code",
            description: "Semantic and keyword search across code. Returns ranked excerpts with surrounding context.",
            category: ToolCategory::Search,
            tags: ["search", "code", "keyword", "semantic"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query - can be natural language or code pattern"},
                    "repo": {"type": "string", "description": "Repository name (optional, searches all if omitted)"},
                    "file_pattern": {"type": "string", "description": "Glob pattern to filter files"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default: 10)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from results (default: false)"}
                },
                "required": ["query"]
            }),
            requires_api_key: false,
            aliases: vec!["search", "code_search"],
        });

        map.insert("semantic_search", ToolMetadata {
            name: "semantic_search",
            description: "BM25-ranked semantic search with code-aware tokenization. Better than simple text search for natural language queries.",
            category: ToolCategory::Search,
            tags: ["search", "semantic", "bm25", "ranking"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "repo": {"type": "string", "description": "Repository name (optional, searches all if omitted)"},
                    "doc_type": {"type": "string", "enum": ["file", "function", "class", "struct", "method"], "description": "Filter by document type"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default: 10)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from results (default: false)"}
                },
                "required": ["query"]
            }),
            requires_api_key: false,
            aliases: vec!["bm25_search", "ranked_search"],
        });

        map.insert("hybrid_search", ToolMetadata {
            name: "hybrid_search",
            description: "Perform hybrid search combining BM25 keyword search with TF-IDF semantic similarity using Reciprocal Rank Fusion (RRF).",
            category: ToolCategory::Search,
            tags: ["search", "hybrid", "bm25", "tfidf", "rrf"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "repo": {"type": "string", "description": "Optional: limit to specific repository"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default: 10)"},
                    "mode": {"type": "string", "enum": ["hybrid", "bm25", "tfidf"], "description": "Search mode: hybrid (default), bm25 only, or tfidf only"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from results (default: false)"}
                },
                "required": ["query"]
            }),
            requires_api_key: false,
            aliases: vec!["combined_search", "rrf_search"],
        });

        map.insert("neural_search", ToolMetadata {
            name: "neural_search",
            description: "Search code using neural semantic embeddings. Finds semantically similar code even with different variable names. Requires --neural flag and EMBEDDING_API_KEY.",
            category: ToolCategory::Search,
            tags: ["search", "neural", "embeddings", "semantic", "ai"].iter().copied().collect(),
            stability: StabilityLevel::Beta,
            performance: PerformanceImpact::High,
            required_flags: [FeatureFlag::Neural].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Natural language or code query"},
                    "repo": {"type": "string", "description": "Optional: limit to specific repository"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default: 10)"}
                },
                "required": ["query"]
            }),
            requires_api_key: true,
            aliases: vec!["ai_search", "embedding_search"],
        });

        map.insert("search_chunks", ToolMetadata {
            name: "search_chunks",
            description: "Search over AST-aware code chunks with symbol context.",
            category: ToolCategory::Search,
            tags: ["search", "chunks", "ast", "semantic"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "repo": {"type": "string", "description": "Optional: limit to specific repository"},
                    "chunk_type": {"type": "string", "enum": ["function", "method", "class", "trait", "module", "all"], "description": "Filter by chunk type"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default: 10)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from results (default: false)"}
                },
                "required": ["query"]
            }),
            requires_api_key: false,
            aliases: vec!["chunk_search", "ast_search"],
        });

        map.insert("find_similar_code", ToolMetadata {
            name: "find_similar_code",
            description: "Find code similar to a given snippet using TF-IDF embeddings. Good for finding duplicate or related code patterns.",
            category: ToolCategory::Search,
            tags: ["similar", "duplicate", "clone", "tfidf"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Code snippet to find similar code for"},
                    "repo": {"type": "string", "description": "Repository to search in (optional, searches all if omitted)"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default: 10)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from results (default: false)"}
                },
                "required": ["query"]
            }),
            requires_api_key: false,
            aliases: vec!["similar_code", "find_duplicates"],
        });

        map.insert("find_similar_to_symbol", ToolMetadata {
            name: "find_similar_to_symbol",
            description: "Find code similar to a specific symbol (function, class, etc.). Useful for finding related implementations or potential duplicates.",
            category: ToolCategory::Search,
            tags: ["similar", "symbol", "clone", "duplicate"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "symbol": {"type": "string", "description": "Symbol name to find similar code for"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default: 10)"}
                },
                "required": ["repo", "symbol"]
            }),
            requires_api_key: false,
            aliases: vec!["similar_symbol", "find_related"],
        });

        map.insert("find_semantic_clones", ToolMetadata {
            name: "find_semantic_clones",
            description: "Find semantically similar code (Type-3/4 clones) using neural embeddings. Detects code that does the same thing with different implementation.",
            category: ToolCategory::Search,
            tags: ["clones", "semantic", "similar", "neural"].iter().copied().collect(),
            stability: StabilityLevel::Beta,
            performance: PerformanceImpact::High,
            required_flags: [FeatureFlag::Neural].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string"},
                    "function": {"type": "string", "description": "Function name to find clones of"},
                    "threshold": {"type": "number", "description": "Similarity threshold 0-1 (default: 0.8)"}
                },
                "required": ["repo", "path", "function"]
            }),
            requires_api_key: true,
            aliases: vec!["semantic_clones", "clone_detection"],
        });

        map.insert("get_embedding_stats", ToolMetadata {
            name: "get_embedding_stats",
            description: "Get statistics about the embedding index.",
            category: ToolCategory::Search,
            tags: ["stats", "embedding", "tfidf", "index"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({"type": "object", "properties": {}, "required": []}),
            requires_api_key: false,
            aliases: vec!["embedding_stats", "tfidf_stats"],
        });

        map.insert("get_neural_stats", ToolMetadata {
            name: "get_neural_stats",
            description: "Get statistics about the neural embedding index. Requires --neural flag.",
            category: ToolCategory::Search,
            tags: ["stats", "neural", "embedding", "index"].iter().copied().collect(),
            stability: StabilityLevel::Beta,
            performance: PerformanceImpact::Low,
            required_flags: [FeatureFlag::Neural].iter().copied().collect(),
            input_schema: json!({"type": "object", "properties": {}, "required": []}),
            requires_api_key: false,
            aliases: vec!["neural_stats", "ai_stats"],
        });

        map.insert("get_chunk_stats", ToolMetadata {
            name: "get_chunk_stats",
            description: "Get statistics about code chunks in a repository.",
            category: ToolCategory::Search,
            tags: ["stats", "chunks", "ast", "analysis"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["chunk_stats", "chunking_stats"],
        });

        map.insert("get_chunks", ToolMetadata {
            name: "get_chunks",
            description: "Get AST-aware code chunks for a file with symbol context.",
            category: ToolCategory::Search,
            tags: ["chunks", "ast", "code", "symbols"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File path"},
                    "include_imports": {"type": "boolean", "description": "Include import statements in context (default: true)"}
                },
                "required": ["repo", "path"]
            }),
            requires_api_key: false,
            aliases: vec!["chunks", "code_chunks"],
        });

        // ===== Call Graph Tools (6) =====

        map.insert("get_call_graph", ToolMetadata {
            name: "get_call_graph",
            description: "Get the call graph for a repository or specific function. Requires --call-graph flag.",
            category: ToolCategory::CallGraph,
            tags: ["callgraph", "dependencies", "analysis", "graph"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::CallGraph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "function": {"type": "string", "description": "Focus on specific function (optional)"},
                    "depth": {"type": "integer", "description": "Maximum depth to traverse (default: 3)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files (accepted, but filtering requires rebuild)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["callgraph", "call_tree"],
        });

        map.insert("get_callers", ToolMetadata {
            name: "get_callers",
            description: "Find functions that call a given function. Requires --call-graph flag.",
            category: ToolCategory::CallGraph,
            tags: ["callers", "callgraph", "references", "analysis"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::CallGraph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "function": {"type": "string", "description": "Function name to find callers of"},
                    "transitive": {"type": "boolean", "description": "Include transitive callers (default: false)"},
                    "max_depth": {"type": "integer", "description": "Maximum depth for transitive analysis (default: 5)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files (accepted, but filtering requires rebuild)"}
                },
                "required": ["repo", "function"]
            }),
            requires_api_key: false,
            aliases: vec!["callers", "who_calls"],
        });

        map.insert("get_callees", ToolMetadata {
            name: "get_callees",
            description: "Find functions called by a given function. Requires --call-graph flag.",
            category: ToolCategory::CallGraph,
            tags: ["callees", "callgraph", "dependencies", "analysis"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::CallGraph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "function": {"type": "string", "description": "Function name to find callees of"},
                    "transitive": {"type": "boolean", "description": "Include transitive callees (default: false)"},
                    "max_depth": {"type": "integer", "description": "Maximum depth for transitive analysis (default: 5)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files (accepted, but filtering requires rebuild)"}
                },
                "required": ["repo", "function"]
            }),
            requires_api_key: false,
            aliases: vec!["callees", "calls_to"],
        });

        map.insert("find_call_path", ToolMetadata {
            name: "find_call_path",
            description: "Find the call path between two functions. Requires --call-graph flag.",
            category: ToolCategory::CallGraph,
            tags: ["callpath", "callgraph", "trace", "analysis"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::CallGraph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "from": {"type": "string", "description": "Source function name"},
                    "to": {"type": "string", "description": "Target function name"}
                },
                "required": ["repo", "from", "to"]
            }),
            requires_api_key: false,
            aliases: vec!["call_path", "trace_calls"],
        });

        map.insert("get_complexity", ToolMetadata {
            name: "get_complexity",
            description: "Get complexity metrics (cyclomatic, cognitive) for a function. Requires --call-graph flag.",
            category: ToolCategory::CallGraph,
            tags: ["complexity", "metrics", "analysis", "quality"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: [FeatureFlag::CallGraph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "function": {"type": "string", "description": "Function name to analyze"}
                },
                "required": ["repo", "function"]
            }),
            requires_api_key: false,
            aliases: vec!["complexity", "cyclomatic"],
        });

        map.insert("get_function_hotspots", ToolMetadata {
            name: "get_function_hotspots",
            description: "Find highly connected functions (potential refactoring targets) based on call graph analysis. Requires --call-graph flag.",
            category: ToolCategory::CallGraph,
            tags: ["hotspots", "refactoring", "analysis", "complexity"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::CallGraph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "min_connections": {"type": "integer", "description": "Minimum total connections (incoming + outgoing) to be considered a hotspot (default: 5)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files (accepted, but filtering requires rebuild)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["hotspots", "function_hotspots"],
        });

        // ===== Git Tools (9) =====

        map.insert("get_blame", ToolMetadata {
            name: "get_blame",
            description: "Get git blame information for a file. Requires --git flag.",
            category: ToolCategory::Git,
            tags: ["git", "blame", "history", "author"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Git].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File path relative to repository"},
                    "start_line": {"type": "integer", "description": "Start line for blame range"},
                    "end_line": {"type": "integer", "description": "End line for blame range"}
                },
                "required": ["repo", "path"]
            }),
            requires_api_key: false,
            aliases: vec!["blame", "git_blame"],
        });

        map.insert("get_file_history", ToolMetadata {
            name: "get_file_history",
            description: "Get git commit history for a file. Requires --git flag.",
            category: ToolCategory::Git,
            tags: ["git", "history", "commits", "log"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Git].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File path relative to repository"},
                    "max_commits": {"type": "integer", "description": "Maximum commits to return (default: 20)"}
                },
                "required": ["repo", "path"]
            }),
            requires_api_key: false,
            aliases: vec!["file_history", "git_log"],
        });

        map.insert("get_recent_changes", ToolMetadata {
            name: "get_recent_changes",
            description: "Get recent commits across the repository. Requires --git flag.",
            category: ToolCategory::Git,
            tags: ["git", "commits", "recent", "history"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Git].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "days": {"type": "integer", "description": "Number of days to look back (default: 7)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["recent_commits", "recent_changes"],
        });

        map.insert("get_hotspots", ToolMetadata {
            name: "get_hotspots",
            description: "Find code hotspots - files with high churn and complexity. Requires --git flag.",
            category: ToolCategory::Git,
            tags: ["git", "hotspots", "churn", "complexity", "analysis"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Git].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "days": {"type": "integer", "description": "Number of days to analyze (default: 30)"},
                    "min_complexity": {"type": "integer", "description": "Minimum cyclomatic complexity to report"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["hotspots", "code_hotspots"],
        });

        map.insert("get_contributors", ToolMetadata {
            name: "get_contributors",
            description: "Get contributors to a file or repository. Requires --git flag.",
            category: ToolCategory::Git,
            tags: ["git", "contributors", "authors", "stats"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Git].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File path (optional, shows repo contributors if omitted)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["contributors", "authors"],
        });

        map.insert("get_commit_diff", ToolMetadata {
            name: "get_commit_diff",
            description: "Get the diff for a specific commit. Requires --git flag.",
            category: ToolCategory::Git,
            tags: ["git", "diff", "commit", "changes"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Git].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "commit": {"type": "string", "description": "Commit hash or reference (e.g., HEAD, branch name)"},
                    "path": {"type": "string", "description": "Optional file path to filter the diff"}
                },
                "required": ["repo", "commit"]
            }),
            requires_api_key: false,
            aliases: vec!["commit_diff", "diff"],
        });

        map.insert("get_symbol_history", ToolMetadata {
            name: "get_symbol_history",
            description: "Get commits that modified a specific symbol/function. Requires --git flag.",
            category: ToolCategory::Git,
            tags: ["git", "symbol", "history", "commits"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Git].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File path relative to repository"},
                    "symbol": {"type": "string", "description": "Symbol/function name to track"},
                    "max_commits": {"type": "integer", "description": "Maximum commits to return (default: 10)"}
                },
                "required": ["repo", "path", "symbol"]
            }),
            requires_api_key: false,
            aliases: vec!["symbol_history", "function_history"],
        });

        map.insert("get_branch_info", ToolMetadata {
            name: "get_branch_info",
            description: "Get current branch name and repository status. Requires --git flag.",
            category: ToolCategory::Git,
            tags: ["git", "branch", "status", "info"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: [FeatureFlag::Git].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["branch_info", "current_branch"],
        });

        map.insert("get_modified_files", ToolMetadata {
            name: "get_modified_files",
            description: "Get list of modified files in the working tree. Requires --git flag.",
            category: ToolCategory::Git,
            tags: ["git", "modified", "status", "changes"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: [FeatureFlag::Git].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["modified_files", "git_status"],
        });

        // ===== LSP Tools (3) =====

        map.insert("get_hover_info", ToolMetadata {
            name: "get_hover_info",
            description: "Get hover information (type info, documentation) for a symbol at a specific position. Enhanced with LSP when available.",
            category: ToolCategory::Lsp,
            tags: ["lsp", "hover", "type", "documentation"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(), // Enhanced with LSP but works without
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File path relative to repository root"},
                    "line": {"type": "integer", "description": "Line number (1-indexed)"},
                    "character": {"type": "integer", "description": "Character position (0-indexed)"}
                },
                "required": ["repo", "path", "line", "character"]
            }),
            requires_api_key: false,
            aliases: vec!["hover", "type_info"],
        });

        map.insert("get_type_info", ToolMetadata {
            name: "get_type_info",
            description: "Get precise type information for a symbol. Requires LSP to be enabled.",
            category: ToolCategory::Lsp,
            tags: ["lsp", "type", "type-inference", "analysis"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Lsp].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string"},
                    "line": {"type": "integer"},
                    "character": {"type": "integer"}
                },
                "required": ["repo", "path", "line", "character"]
            }),
            requires_api_key: false,
            aliases: vec!["type", "types"],
        });

        map.insert("go_to_definition", ToolMetadata {
            name: "go_to_definition",
            description: "Find the definition location of a symbol at a specific position. Enhanced with LSP when available.",
            category: ToolCategory::Lsp,
            tags: ["lsp", "definition", "navigation", "goto"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(), // Enhanced with LSP but works without
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string"},
                    "line": {"type": "integer"},
                    "character": {"type": "integer"}
                },
                "required": ["repo", "path", "line", "character"]
            }),
            requires_api_key: false,
            aliases: vec!["definition", "goto_def"],
        });

        // ===== Remote Tools (3) =====

        map.insert("add_remote_repo", ToolMetadata {
            name: "add_remote_repo",
            description: "Add a remote GitHub repository for indexing. Clones the repo to a temporary location.",
            category: ToolCategory::Remote,
            tags: ["remote", "github", "clone", "repository"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: [FeatureFlag::Remote].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "GitHub URL (e.g., github.com/owner/repo or https://github.com/owner/repo)"},
                    "sparse_paths": {"type": "array", "items": {"type": "string"}, "description": "Optional: only clone these paths for efficiency"}
                },
                "required": ["url"]
            }),
            requires_api_key: false,
            aliases: vec!["add_repo", "clone_repo"],
        });

        map.insert("list_remote_files", ToolMetadata {
            name: "list_remote_files",
            description: "List files in a remote GitHub repository via API (no clone needed). Rate limited without GITHUB_TOKEN.",
            category: ToolCategory::Remote,
            tags: ["remote", "github", "files", "list", "api"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Remote].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "GitHub URL"},
                    "path": {"type": "string", "description": "Optional subdirectory to list"}
                },
                "required": ["url"]
            }),
            requires_api_key: false,
            aliases: vec!["remote_files", "github_files"],
        });

        map.insert("get_remote_file", ToolMetadata {
            name: "get_remote_file",
            description: "Fetch a specific file from a remote GitHub repository via API (no clone needed).",
            category: ToolCategory::Remote,
            tags: ["remote", "github", "file", "fetch", "api"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Remote].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "GitHub URL"},
                    "path": {"type": "string", "description": "File path to fetch"}
                },
                "required": ["url", "path"]
            }),
            requires_api_key: false,
            aliases: vec!["remote_file", "fetch_file"],
        });

        // ===== Security Tools (9) =====

        map.insert("scan_security", ToolMetadata {
            name: "scan_security",
            description: "Scan repository for security issues using the security rules engine. Detects vulnerabilities, secrets, crypto issues, and more.",
            category: ToolCategory::Security,
            tags: ["security", "scan", "vulnerabilities", "owasp", "cwe"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "Optional specific file or directory path to scan"},
                    "ruleset": {"type": "string", "description": "Optional ruleset to use (owasp, cwe, crypto, secrets, or path to custom YAML)"},
                    "severity_threshold": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Minimum severity level to report (default: low)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from scanning (default: true)"},
                    "max_findings": {"type": "integer", "description": "Maximum number of findings to return"},
                    "offset": {"type": "integer", "description": "Skip this many findings before returning results"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["security", "scan", "vulnerabilities"],
        });

        map.insert("check_owasp_top10", ToolMetadata {
            name: "check_owasp_top10",
            description: "Scan specifically for OWASP Top 10 2021 vulnerabilities including injection, broken auth, XSS, SSRF, etc.",
            category: ToolCategory::Security,
            tags: ["security", "owasp", "vulnerabilities", "scan"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "Optional specific file or directory path to scan"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from scanning (default: true)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["owasp", "owasp_top10"],
        });

        map.insert("check_cwe_top25", ToolMetadata {
            name: "check_cwe_top25",
            description: "Scan for CWE Top 25 Most Dangerous Software Weaknesses including buffer overflows, injection, improper input validation.",
            category: ToolCategory::Security,
            tags: ["security", "cwe", "vulnerabilities", "scan"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "Optional specific file or directory path to scan"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from scanning (default: true)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["cwe", "cwe_top25"],
        });

        map.insert("find_injection_vulnerabilities", ToolMetadata {
            name: "find_injection_vulnerabilities",
            description: "Find injection vulnerabilities (SQL injection, XSS, command injection, path traversal) using taint analysis.",
            category: ToolCategory::Security,
            tags: ["security", "injection", "xss", "sql", "taint"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "Optional: specific file to analyze"},
                    "vulnerability_types": {"type": "array", "items": {"type": "string", "enum": ["sql", "xss", "command", "path", "all"]}, "description": "Types of vulnerabilities to find (default: all)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from scanning (default: true)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["injection", "find_injection"],
        });

        map.insert("trace_taint", ToolMetadata {
            name: "trace_taint",
            description: "Trace how tainted data flows from a source location through the code.",
            category: ToolCategory::Security,
            tags: ["security", "taint", "trace", "dataflow"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File path containing the source"},
                    "line": {"type": "integer", "description": "Line number of the taint source"}
                },
                "required": ["repo", "path", "line"]
            }),
            requires_api_key: false,
            aliases: vec!["taint", "taint_trace"],
        });

        map.insert("get_taint_sources", ToolMetadata {
            name: "get_taint_sources",
            description: "List all identified taint sources (user inputs, file reads, network data) in the codebase.",
            category: ToolCategory::Security,
            tags: ["security", "taint", "sources", "input"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "Optional: specific file to analyze"},
                    "source_types": {"type": "array", "items": {"type": "string", "enum": ["user_input", "file_read", "database", "environment", "network", "all"]}, "description": "Types of sources to find (default: all)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from scanning (default: true)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["taint_sources", "input_sources"],
        });

        map.insert("get_security_summary", ToolMetadata {
            name: "get_security_summary",
            description: "Get a comprehensive security summary for a repository including vulnerability counts and risk assessment.",
            category: ToolCategory::Security,
            tags: ["security", "summary", "risk", "assessment"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from scanning (default: true)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["security_summary", "security_report"],
        });

        map.insert("explain_vulnerability", ToolMetadata {
            name: "explain_vulnerability",
            description: "Get detailed explanation of a security vulnerability type including examples, references, and remediation guidance.",
            category: ToolCategory::Security,
            tags: ["security", "explain", "vulnerability", "help"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "Rule ID to explain (e.g., OWASP-A03-001, CWE-89-001)"},
                    "cwe": {"type": "string", "description": "CWE ID to explain (e.g., CWE-89, CWE-79)"}
                },
                "required": []
            }),
            requires_api_key: false,
            aliases: vec!["explain", "vulnerability_info"],
        });

        map.insert("suggest_fix", ToolMetadata {
            name: "suggest_fix",
            description: "Get suggested fixes for a specific security finding.",
            category: ToolCategory::Security,
            tags: ["security", "fix", "remediation", "suggestion"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File path containing the vulnerability"},
                    "line": {"type": "integer", "description": "Line number of the vulnerability"},
                    "rule_id": {"type": "string", "description": "Rule ID that detected the issue"}
                },
                "required": ["repo", "path", "line"]
            }),
            requires_api_key: false,
            aliases: vec!["fix", "remediation"],
        });

        // ===== Supply Chain Tools (4) =====

        map.insert("generate_sbom", ToolMetadata {
            name: "generate_sbom",
            description: "Generate a Software Bill of Materials (SBOM) for a project. Supports CycloneDX and SPDX formats. Parses Cargo.toml, package.json, requirements.txt, and go.mod.",
            category: ToolCategory::SupplyChain,
            tags: ["sbom", "dependencies", "supply-chain", "bom"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "format": {"type": "string", "enum": ["cyclonedx", "spdx", "json"], "description": "Output format (default: cyclonedx)"},
                    "compact": {"type": "boolean", "description": "Output minified JSON without whitespace (default: false)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["sbom", "bom", "dependencies_list"],
        });

        map.insert("check_dependencies", ToolMetadata {
            name: "check_dependencies",
            description: "Check project dependencies for known vulnerabilities using the OSV (Open Source Vulnerabilities) database. Returns CVE/GHSA IDs and recommended upgrades.",
            category: ToolCategory::SupplyChain,
            tags: ["dependencies", "vulnerabilities", "osv", "cve", "supply-chain"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "severity_threshold": {"type": "string", "enum": ["critical", "high", "medium", "low"], "description": "Minimum severity level to report (default: low)"},
                    "include_dev": {"type": "boolean", "description": "Include dev dependencies (default: true)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["check_deps", "dependency_scan"],
        });

        map.insert("check_licenses", ToolMetadata {
            name: "check_licenses",
            description: "Analyze dependency licenses for compliance issues. Detects copyleft licenses, unknown licenses, and license compatibility problems.",
            category: ToolCategory::SupplyChain,
            tags: ["licenses", "compliance", "legal", "supply-chain"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "project_license": {"type": "string", "description": "SPDX identifier for your project's license (e.g., MIT, Apache-2.0)"},
                    "fail_on_copyleft": {"type": "boolean", "description": "Treat copyleft licenses as issues (default: false)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["licenses", "license_check"],
        });

        map.insert("find_upgrade_path", ToolMetadata {
            name: "find_upgrade_path",
            description: "Find safe upgrade paths for vulnerable dependencies. Shows which versions fix known vulnerabilities and whether upgrades have breaking changes.",
            category: ToolCategory::SupplyChain,
            tags: ["upgrade", "dependencies", "vulnerabilities", "fix"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "dependency": {"type": "string", "description": "Optional: specific dependency to check (checks all vulnerable deps if omitted)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["upgrade_path", "upgrade"],
        });

        // ===== Analysis Tools (11) =====

        map.insert("get_control_flow", ToolMetadata {
            name: "get_control_flow",
            description: "Get the control flow graph (CFG) for a function, showing basic blocks, branches, and loops.",
            category: ToolCategory::Analysis,
            tags: ["cfg", "control-flow", "analysis", "graph"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File path containing the function"},
                    "function": {"type": "string", "description": "Function name to analyze"}
                },
                "required": ["repo", "path", "function"]
            }),
            requires_api_key: false,
            aliases: vec!["cfg", "control_flow"],
        });

        map.insert("find_dead_code", ToolMetadata {
            name: "find_dead_code",
            description: "Find unreachable code blocks in a function or file using control flow analysis.",
            category: ToolCategory::Analysis,
            tags: ["dead-code", "analysis", "cfg", "unreachable"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "File path to analyze"},
                    "function": {"type": "string", "description": "Optional: specific function to analyze"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from analysis (default: true)"}
                },
                "required": ["repo", "path"]
            }),
            requires_api_key: false,
            aliases: vec!["dead_code", "unreachable"],
        });

        map.insert("get_data_flow", ToolMetadata {
            name: "get_data_flow",
            description: "Get data flow analysis for a function, showing variable definitions and uses.",
            category: ToolCategory::Analysis,
            tags: ["dfg", "data-flow", "analysis", "variables"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string"},
                    "function": {"type": "string"}
                },
                "required": ["repo", "path", "function"]
            }),
            requires_api_key: false,
            aliases: vec!["dfg", "data_flow"],
        });

        map.insert("get_reaching_definitions", ToolMetadata {
            name: "get_reaching_definitions",
            description: "Get reaching definitions analysis - which variable assignments reach each point in the code.",
            category: ToolCategory::Analysis,
            tags: ["analysis", "data-flow", "definitions", "variables"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string"},
                    "function": {"type": "string"}
                },
                "required": ["repo", "path", "function"]
            }),
            requires_api_key: false,
            aliases: vec!["reaching_defs", "definitions"],
        });

        map.insert("find_uninitialized", ToolMetadata {
            name: "find_uninitialized",
            description: "Find variables that may be used before being initialized.",
            category: ToolCategory::Analysis,
            tags: ["analysis", "uninitialized", "variables", "bugs"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string"},
                    "function": {"type": "string", "description": "Optional: specific function to analyze"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from analysis (default: true)"}
                },
                "required": ["repo", "path"]
            }),
            requires_api_key: false,
            aliases: vec!["uninitialized", "uninitialized_vars"],
        });

        map.insert("find_dead_stores", ToolMetadata {
            name: "find_dead_stores",
            description: "Find variable assignments that are never read (dead stores).",
            category: ToolCategory::Analysis,
            tags: ["analysis", "dead-stores", "variables", "optimization"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string"},
                    "function": {"type": "string", "description": "Optional: specific function to analyze"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from analysis (default: true)"}
                },
                "required": ["repo", "path"]
            }),
            requires_api_key: false,
            aliases: vec!["dead_stores", "unused_assignments"],
        });

        map.insert("infer_types", ToolMetadata {
            name: "infer_types",
            description: "Infer types for variables in a Python/JavaScript/TypeScript function. Shows what types flow through the code without running external type checkers.",
            category: ToolCategory::Analysis,
            tags: ["analysis", "types", "inference", "python", "javascript"].iter().copied().collect(),
            stability: StabilityLevel::Beta,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string"},
                    "function": {"type": "string"}
                },
                "required": ["repo", "path", "function"]
            }),
            requires_api_key: false,
            aliases: vec!["type_inference", "infer"],
        });

        map.insert("check_type_errors", ToolMetadata {
            name: "check_type_errors",
            description: "Find potential type errors in Python/JavaScript/TypeScript code without running mypy/tsc. Detects type mismatches, undefined variables, etc.",
            category: ToolCategory::Analysis,
            tags: ["analysis", "types", "errors", "python", "javascript"].iter().copied().collect(),
            stability: StabilityLevel::Beta,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from analysis (default: true)"}
                },
                "required": ["repo", "path"]
            }),
            requires_api_key: false,
            aliases: vec!["type_errors", "type_check"],
        });

        map.insert("get_typed_taint_flow", ToolMetadata {
            name: "get_typed_taint_flow",
            description: "Enhanced taint analysis with type information. More precise than untyped taint tracking, combines data flow with type inference.",
            category: ToolCategory::Analysis,
            tags: ["analysis", "taint", "types", "security", "dataflow"].iter().copied().collect(),
            stability: StabilityLevel::Beta,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "path": {"type": "string"},
                    "source_line": {"type": "integer", "description": "Line number to trace from"}
                },
                "required": ["repo", "path", "source_line"]
            }),
            requires_api_key: false,
            aliases: vec!["typed_taint", "taint_flow"],
        });

        map.insert("get_import_graph", ToolMetadata {
            name: "get_import_graph",
            description: "Build and analyze the import/dependency graph for a codebase. Shows which files import which other files, helps identify circular dependencies.",
            category: ToolCategory::Analysis,
            tags: ["analysis", "imports", "dependencies", "graph", "circular"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "file": {"type": "string", "description": "Optional: focus on imports from/to a specific file"},
                    "direction": {"type": "string", "enum": ["imports", "importers", "both"], "description": "Direction to show (default: both)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["import_graph", "dependency_graph"],
        });

        map.insert("find_circular_imports", ToolMetadata {
            name: "find_circular_imports",
            description: "Detect circular import dependencies in the codebase. Returns all cycles with the files involved.",
            category: ToolCategory::Analysis,
            tags: ["analysis", "imports", "circular", "dependencies", "cycles"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files from analysis (default: true)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["circular_imports", "import_cycles"],
        });

        map.insert("find_unused_exports", ToolMetadata {
            name: "find_unused_exports",
            description: "Detect exported symbols never imported by other files in repo. Cross-file analysis using import graph. Configurable to exclude public API surface.",
            category: ToolCategory::Analysis,
            tags: ["analysis", "exports", "dead-code", "unused", "imports"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository name"},
                    "exclude_entry_points": {"type": "boolean", "description": "Exclude entry point files like lib.rs, main.rs, index.js (default: true)"},
                    "exclude_patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Glob patterns for files to exclude from analysis (public API surface)"
                    }
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["unused_exports", "dead_exports"],
        });

        // ===== Graph Tools (1) =====

        map.insert("get_code_graph", ToolMetadata {
            name: "get_code_graph",
            description: "Get graph visualization data (call graph, import graph, symbols). HTTP-only tool, not available via MCP.",
            category: ToolCategory::Graph,
            tags: ["graph", "visualization", "http", "callgraph", "imports"].iter().copied().collect(),
            stability: StabilityLevel::Experimental,
            performance: PerformanceImpact::High,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "view": {"type": "string", "enum": ["call", "import", "symbol", "hybrid", "control_flow"]},
                    "depth": {"type": "integer", "description": "Maximum depth (default: 3)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["graph", "visualization"],
        });

        // ===== SPARQL Tools (3) =====

        map.insert("sparql_query", ToolMetadata {
            name: "sparql_query",
            description: "Execute a SPARQL query against the RDF knowledge graph. Supports SELECT and ASK queries with timeout and result limits. Requires --graph flag.",
            category: ToolCategory::Graph,
            tags: ["sparql", "rdf", "query", "graph", "knowledge-graph"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "SPARQL query to execute"},
                    "timeout_ms": {"type": "integer", "description": "Query timeout in milliseconds (default: 30000, max: 300000)"},
                    "limit": {"type": "integer", "description": "Maximum number of results (default: 1000, max: 10000)"},
                    "offset": {"type": "integer", "description": "Offset for pagination (default: 0)"},
                    "format": {"type": "string", "enum": ["json", "markdown", "csv"], "description": "Output format (default: json)"}
                },
                "required": ["query"]
            }),
            requires_api_key: false,
            aliases: vec!["sparql", "rdf_query"],
        });

        map.insert("list_sparql_templates", ToolMetadata {
            name: "list_sparql_templates",
            description: "List available SPARQL query templates for common code intelligence patterns. Requires --graph flag.",
            category: ToolCategory::Graph,
            tags: ["sparql", "templates", "query", "graph"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({"type": "object", "properties": {}, "required": []}),
            requires_api_key: false,
            aliases: vec!["sparql_templates"],
        });

        map.insert("run_sparql_template", ToolMetadata {
            name: "run_sparql_template",
            description: "Execute a predefined SPARQL query template with parameters. Requires --graph flag.",
            category: ToolCategory::Graph,
            tags: ["sparql", "templates", "query", "graph"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "template": {"type": "string", "description": "Template name (e.g., find_functions, find_calls)"},
                    "params": {"type": "object", "description": "Template parameters as key-value pairs"},
                    "timeout_ms": {"type": "integer", "description": "Query timeout in milliseconds (default: 30000)"},
                    "limit": {"type": "integer", "description": "Maximum number of results (default: 1000)"},
                    "format": {"type": "string", "enum": ["json", "markdown", "csv"], "description": "Output format (default: json)"}
                },
                "required": ["template"]
            }),
            requires_api_key: false,
            aliases: vec!["run_template"],
        });

        // ===== CCG Tools (12) =====

        map.insert("get_ccg_manifest", ToolMetadata {
            name: "get_ccg_manifest",
            description: "Get CCG Layer 0 manifest (~1-2KB JSON-LD) with repository identity, symbol counts, languages, and security summary. Always fits in AI context window.",
            category: ToolCategory::Graph,
            tags: ["ccg", "manifest", "context", "json-ld", "layer0"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository name"},
                    "include_security": {"type": "boolean", "description": "Include security summary in manifest (default: true)"},
                    "base_url": {"type": "string", "description": "Base URL for layer URIs (optional)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["ccg_manifest", "manifest"],
        });

        map.insert("export_ccg_manifest", ToolMetadata {
            name: "export_ccg_manifest",
            description: "Export CCG Layer 0 manifest to a file. Returns content or writes to specified path.",
            category: ToolCategory::Graph,
            tags: ["ccg", "manifest", "export", "json-ld", "layer0"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository name"},
                    "include_security": {"type": "boolean", "description": "Include security summary (default: true)"},
                    "base_url": {"type": "string", "description": "Base URL for layer URIs"},
                    "output": {"type": "string", "description": "Output file path (optional)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["export_manifest"],
        });

        map.insert("export_ccg_architecture", ToolMetadata {
            name: "export_ccg_architecture",
            description: "Export CCG Layer 1 architecture (~10-50KB JSON-LD) with module hierarchy, public API, and dependencies.",
            category: ToolCategory::Graph,
            tags: ["ccg", "architecture", "export", "json-ld", "layer1", "modules"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository name"},
                    "output": {"type": "string", "description": "Output file path (optional)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["export_architecture", "ccg_architecture"],
        });

        map.insert("export_ccg_index", ToolMetadata {
            name: "export_ccg_index",
            description: "Export CCG Layer 2 symbol index (~100-500KB N-Quads gzipped) with all symbols and call graph edges.",
            category: ToolCategory::Graph,
            tags: ["ccg", "index", "export", "nquads", "layer2", "symbols"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository name"},
                    "output": {"type": "string", "description": "Output file path (optional)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["export_symbol_index", "ccg_index"],
        });

        map.insert("export_ccg_full", ToolMetadata {
            name: "export_ccg_full",
            description: "Export CCG Layer 3 full detail (~1-20MB N-Quads gzipped) with complete RDF dataset including imports and security findings.",
            category: ToolCategory::Graph,
            tags: ["ccg", "full", "export", "nquads", "layer3", "rdf"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository name"},
                    "output": {"type": "string", "description": "Output file path (optional)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["export_full_detail", "ccg_full"],
        });

        map.insert("export_ccg", ToolMetadata {
            name: "export_ccg",
            description: "Export all CCG layers as a bundle to a directory. Generates manifest.json, architecture.json, symbol-index.nq.gz.b64, and full-detail.nq.gz.b64.",
            category: ToolCategory::Graph,
            tags: ["ccg", "bundle", "export", "all-layers"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository name"},
                    "output_dir": {"type": "string", "description": "Output directory path (optional)"},
                    "base_url": {"type": "string", "description": "Base URL for layer URIs"},
                    "include_security": {"type": "boolean", "description": "Include security summary (default: true)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["ccg_bundle", "export_all_layers"],
        });

        map.insert("query_ccg", ToolMetadata {
            name: "query_ccg",
            description: "Query CCG Layer 3 using SPARQL. Enables rich semantic queries against the full code context graph.",
            category: ToolCategory::Graph,
            tags: ["ccg", "query", "sparql", "layer3", "semantic"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository name"},
                    "query": {"type": "string", "description": "SPARQL query to execute"},
                    "timeout_ms": {"type": "integer", "description": "Query timeout in milliseconds (default: 30000)"},
                    "limit": {"type": "integer", "description": "Maximum number of results (default: 1000)"}
                },
                "required": ["repo", "query"]
            }),
            requires_api_key: false,
            aliases: vec!["ccg_query", "query_context_graph"],
        });

        map.insert("get_ccg_acl", ToolMetadata {
            name: "get_ccg_acl",
            description: "Generate WebACL access control document for CCG layers. Supports Triple-Heart Model (public/authenticated/private tiers).",
            category: ToolCategory::Graph,
            tags: ["ccg", "acl", "access", "webacl", "security", "triple-heart"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository name"},
                    "tier": {"type": "string", "description": "Access tier: 'public' or 'triple-heart' (default)"},
                    "agent": {"type": "string", "description": "Specific agent URI to grant private access to (optional)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["ccg_acl", "ccg_access_control"],
        });

        map.insert("get_ccg_access_info", ToolMetadata {
            name: "get_ccg_access_info",
            description: "Get information about CCG access tiers and permissions. Explains the Triple-Heart Model and WebACL configuration.",
            category: ToolCategory::Graph,
            tags: ["ccg", "access", "info", "triple-heart", "help"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "tier": {"type": "string", "description": "Access tier to explain: 'public', 'authenticated', or 'private'"}
                },
                "required": []
            }),
            requires_api_key: false,
            aliases: vec!["ccg_access_info", "ccg_tier_info"],
        });

        map.insert("import_ccg", ToolMetadata {
            name: "import_ccg",
            description: "Import a CCG layer from URL or local file. Supports JSON-LD (L0/L1) and gzipped N-Quads (L2/L3) formats.",
            category: ToolCategory::Graph,
            tags: ["ccg", "import", "fetch", "load", "registry"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch CCG layer from (e.g., codecontextgraph.com registry)"},
                    "path": {"type": "string", "description": "Local file path to load CCG layer from"},
                    "layer": {"type": "string", "description": "Layer type: 'manifest', 'architecture', 'symbol_index', 'full_detail' (or 0-3)"}
                },
                "required": []
            }),
            requires_api_key: false,
            aliases: vec!["ccg_import", "load_ccg", "fetch_ccg"],
        });

        map.insert("import_ccg_from_registry", ToolMetadata {
            name: "import_ccg_from_registry",
            description: "Import all CCG layers from the codecontextgraph.com registry for a repository.",
            category: ToolCategory::Graph,
            tags: ["ccg", "import", "registry", "fetch", "all-layers"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: [FeatureFlag::Graph].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Git host (default: github.com)"},
                    "owner": {"type": "string", "description": "Repository owner"},
                    "repo": {"type": "string", "description": "Repository name"},
                    "commit": {"type": "string", "description": "Commit SHA or 'latest' (default: latest)"}
                },
                "required": ["owner", "repo"]
            }),
            requires_api_key: false,
            aliases: vec!["ccg_import_registry", "fetch_ccg_from_registry"],
        });

        map
    };
}

/// Get metadata for a tool
pub fn get_tool_metadata(name: &str) -> Option<&'static ToolMetadata> {
    TOOL_METADATA.get(name)
}

/// Get all tools in a category
pub fn get_tools_by_category(category: ToolCategory) -> Vec<&'static ToolMetadata> {
    TOOL_METADATA
        .values()
        .filter(|meta| meta.category == category)
        .collect()
}

/// Search tools by query string
pub fn search_tools(query: &str) -> Vec<&'static ToolMetadata> {
    TOOL_METADATA
        .values()
        .filter(|meta| meta.matches_query(query))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_metadata_exists() {
        assert!(!TOOL_METADATA.is_empty());
        assert!(TOOL_METADATA.contains_key("list_repos"));
    }

    #[test]
    fn test_is_available() {
        let list_repos = TOOL_METADATA.get("list_repos").unwrap();
        assert!(list_repos.is_available(&HashSet::new()));

        let get_blame = TOOL_METADATA.get("get_blame").unwrap();
        assert!(!get_blame.is_available(&HashSet::new()));

        let mut flags = HashSet::new();
        flags.insert(FeatureFlag::Git);
        assert!(get_blame.is_available(&flags));
    }

    #[test]
    fn test_matches_query() {
        let list_repos = TOOL_METADATA.get("list_repos").unwrap();
        assert!(list_repos.matches_query("list"));
        assert!(list_repos.matches_query("repository"));
        assert!(list_repos.matches_query("LIST")); // Case insensitive
    }
}
