/// Tool Metadata Registry
///
/// This module provides comprehensive metadata for all 91 MCP tools,
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
    Persist,
    Watch,
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
            description: "List indexed repositories (path, file/line counts). Pass detail=true for the per-language breakdown, or repo=<path> to scope to one.",
            category: ToolCategory::Repository,
            tags: ["repository", "index", "metadata", "list"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Low,
            required_flags: HashSet::new(),
            input_schema: json!({"type": "object", "properties": {
                "repo": {"type": "string", "description": "Show only this repository (path or '.'); omit to list all"},
                "detail": {"type": "boolean", "description": "Include the per-language file/line breakdown (default: false)"}
            }, "required": []}),
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
                    "repo": {"type": "string"},
                    "max_depth": {"type": "integer", "description": "Maximum directory depth (default: 4)"},
                    "max_entries_per_dir": {"type": "integer", "description": "Max entries listed per directory (default: 40; 0 = all)"},
                    "max_total_entries": {"type": "integer", "description": "Max entries in the whole tree (default: 600; 0 = all)"}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["structure", "tree", "project_tree"],
        });

        map.insert("get_file", ToolMetadata {
            name: "get_file",
            description: "File contents, optionally one contiguous start_line..end_line range. For context around scattered line numbers use get_excerpt.",
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
            description: "Context around a list of specific line numbers, expanded to function or class boundaries. Takes `lines`; a `start_line`/`end_line` range is read as one plain range, like get_file.",
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
                    "start_line": {"type": "integer", "description": "First line of a plain range, in place of `lines`"},
                    "end_line": {"type": "integer", "description": "Last line of a plain range, in place of `lines`"},
                    "context_before": {"type": "integer", "description": "Lines of context before (default: 5)"},
                    "context_after": {"type": "integer", "description": "Lines of context after (default: 5)"},
                    "expand_to_scope": {"type": "boolean", "description": "Expand to function/class boundaries (default: true)"},
                    "max_lines": {"type": "integer", "description": "Maximum lines per excerpt (default: 50)"}
                },
                "required": ["repo", "path"]
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
            description: "Check whether a path is a repository narsil can index, before adding it.",
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
            description: "Re-index one repository or all of them. The first move when a query returns nothing for code you know exists.",
            category: ToolCategory::Repository,
            tags: ["reindex", "index", "refresh"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::High,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository to reindex (optional, reindexes all if omitted). Absolute path, relative path, or `.`."}
                },
                "required": []
            }),
            requires_api_key: false,
            aliases: vec!["refresh", "rebuild_index"],
        });

        map.insert("forget_repo", ToolMetadata {
            name: "forget_repo",
            description: "Drop a repository from the index, freeing the memory and the on-disk store it held. The repository stops answering queries until `reindex` registers it again.",
            category: ToolCategory::Repository,
            tags: ["forget", "evict", "index", "memory"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository to drop. Absolute path, relative path, or `.`."}
                },
                "required": ["repo"]
            }),
            requires_api_key: false,
            aliases: vec!["drop_repo", "evict_repo"],
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
                    "repo": {"type": "string", "description": "Repository to query (optional, shows all if omitted). Absolute path, relative path, or `.`."}
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
                    "repo": {"type": "string"}
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

        // ===== Symbol Tools (6) =====

        map.insert("find_symbols", ToolMetadata {
            name: "find_symbols",
            description: "Find structs, classes, enums, interfaces, functions and methods by name pattern or kind. Exact and glob matching; for typo tolerance use workspace_symbol_search.",
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
                    "pattern": {"type": "string", "description": "Pattern to filter symbol names: use '*'/'?' wildcards for glob matching (e.g. 'fuse_*'), or a plain string for case-insensitive substring matching. Required unless symbol_type/file_pattern is given; pass '*' to list everything. Also accepted under the alias 'query'."},
                    "query": {"type": "string", "description": "Alias for 'pattern'."},
                    "file_pattern": {"type": "string", "description": "Glob pattern to filter files (e.g., '*.rs', 'src/**/*.py')"},
                    "exclude_tests": {"type": "boolean", "description": "Skip test files (default: false)"},
                    "limit": {"type": "integer", "description": "Maximum number of symbols to return (default: 100)"}
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
            description: "Every reference to a symbol, unioning LSP hits with text matches. To resolve imports and re-exports as well, use find_symbol_usages.",
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
                    "exclude_tests": {"type": "boolean", "description": "Skip test files (default: false)"},
                    "limit": {"type": "integer", "description": "Max references to list (default: 50; 0 = all)"},
                    "offset": {"type": "integer", "description": "Index of the first reference to list (default: 0)"}
                },
                "required": ["repo", "symbol"]
            }),
            requires_api_key: false,
            aliases: vec!["references", "find_usages"],
        });

        map.insert("get_dependencies", ToolMetadata {
            name: "get_dependencies",
            description: "Imports and module dependencies of one source file.",
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
            description: "Usages of a symbol including its imports and re-exports, cross-language aware for JS/TS. For plain reference sites, find_references.",
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
                    "exclude_tests": {"type": "boolean", "description": "Skip test files (default: false)"}
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

        // ===== Search Tools (3) =====

        map.insert("search_code", ToolMetadata {
            name: "search_code",
            description: "Keyword and phrase search across code — the default when you know the terms to look for. Returns ranked excerpts with context.",
            category: ToolCategory::Search,
            tags: ["search", "code", "keyword", "semantic"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query - can be natural language or code pattern"},
                    "repo": {"type": "string", "description": "Repository to search (optional, searches all if omitted). Absolute path, relative path, or `.`."},
                    "file_pattern": {"type": "string", "description": "Glob pattern to filter files"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default: 10)"},
                    "mode": {"type": "string", "enum": ["text", "regex"], "description": "text (default): case-insensitive terms. regex: Rust regex per line, case-sensitive unless the pattern says otherwise"},
                    "exclude_tests": {"type": "boolean", "description": "Skip test files (default: false)"}
                },
                "required": ["query"]
            }),
            requires_api_key: false,
            aliases: vec!["search", "code_search"],
        });

        map.insert("semantic_search", ToolMetadata {
            name: "semantic_search",
            description: "Ranked search for a natural-language description of code, using BM25 with code-aware tokenization. Lexical despite the name — no embeddings.",
            category: ToolCategory::Search,
            tags: ["search", "semantic", "bm25", "ranking"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "repo": {"type": "string", "description": "Repository to search (optional, searches all if omitted). Absolute path, relative path, or `.`."},
                    "doc_type": {"type": "string", "enum": ["file", "function", "class", "struct", "method"], "description": "Filter by document type"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default: 10)"},
                    "exclude_tests": {"type": "boolean", "description": "Skip test files (default: false)"}
                },
                "required": ["query"]
            }),
            requires_api_key: false,
            aliases: vec!["bm25_search", "ranked_search"],
        });

        map.insert("hybrid_search", ToolMetadata {
            name: "hybrid_search",
            description: "Fuses keyword ranking with TF-IDF similarity (Reciprocal Rank Fusion). Slowest of the three searches; reach for it when keywords alone miss.",
            category: ToolCategory::Search,
            tags: ["search", "hybrid", "bm25", "tfidf", "rrf"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: HashSet::new(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "repo": {"type": "string", "description": "Repository to limit to (optional, all repositories if omitted). Absolute path, relative path, or `.`."},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default: 10)"},
                    "mode": {"type": "string", "enum": ["hybrid", "bm25", "tfidf"], "description": "Search mode: hybrid (default), bm25 only, or tfidf only"},
                    "exclude_tests": {"type": "boolean", "description": "Skip test files (default: false)"}
                },
                "required": ["query"]
            }),
            requires_api_key: false,
            aliases: vec!["combined_search", "rrf_search"],
        });

        // ===== Call Graph Tools (6) =====

        map.insert("get_call_graph", ToolMetadata {
            name: "get_call_graph",
            description: "Callers, callees and complexity for one function in a single call, or the whole repository's graph. Requires --call-graph flag.",
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
                    "function": {"type": "string", "description": "Function name to find callers of (alias: symbol)"},
                    "transitive": {"type": "boolean", "description": "Include transitive callers (default: false)"},
                    "max_depth": {"type": "integer", "description": "Maximum depth for transitive analysis (default: 5)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files (accepted, but filtering requires rebuild)"},
                    "limit": {"type": "integer", "description": "Max callers to list (default: 50; 0 = all)"},
                    "offset": {"type": "integer", "description": "Index of the first caller to list (default: 0)"}
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
                    "function": {"type": "string", "description": "Function name to find callees of (alias: symbol)"},
                    "transitive": {"type": "boolean", "description": "Include transitive callees (default: false)"},
                    "max_depth": {"type": "integer", "description": "Maximum depth for transitive analysis (default: 5)"},
                    "exclude_tests": {"type": "boolean", "description": "Exclude test files (accepted, but filtering requires rebuild)"},
                    "limit": {"type": "integer", "description": "Max callees to list (default: 50; 0 = all)"},
                    "offset": {"type": "integer", "description": "Index of the first callee to list (default: 0)"}
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
                    "end_line": {"type": "integer", "description": "End line for blame range"},
                    "revision": {"type": "string", "description": "Commit to blame at, e.g. a hash or 'HEAD~1' (default: working tree)"}
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

        map.insert("get_commit_range", ToolMetadata {
            name: "get_commit_range",
            description: "List commits in base..branch and their merge-base, oldest first. Requires --git flag.",
            category: ToolCategory::Git,
            tags: ["git", "commits", "history", "branch"].iter().copied().collect(),
            stability: StabilityLevel::Stable,
            performance: PerformanceImpact::Medium,
            required_flags: [FeatureFlag::Git].iter().copied().collect(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "base": {"type": "string", "description": "Exclude commits reachable from this revision"},
                    "branch": {"type": "string", "description": "Branch or revision to list (default: HEAD)"},
                    "include_body": {"type": "boolean", "description": "Include commit bodies (default: false)"},
                    "limit": {"type": "integer", "minimum": 0, "description": "Maximum commits to return (default: 50; 0 = all)"},
                    "offset": {"type": "integer", "minimum": 0, "description": "Index of the first commit to list, oldest first (default: 0)"}
                },
                "required": ["repo", "base"]
            }),
            requires_api_key: false,
            aliases: vec![],
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
                    "path": {"type": "string", "description": "File path (optional, shows repo contributors if omitted)"},
                    "limit": {"type": "integer", "description": "Max contributors to list, ranked by commit count (default: 30; 0 = all)"},
                    "offset": {"type": "integer", "description": "Index of the first contributor to list (default: 0)"}
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
                    "path": {"type": "string", "description": "Optional file path to filter the diff"},
                    "max_bytes": {"type": "integer", "description": "Cap the response in bytes (default 48 KB, floor 4 KB). Lower it to fit two commits in one answer; files past the cap are listed, not cut mid-hunk"},
                    "context_lines": {"type": "integer", "description": "Diff context lines around each hunk (git -U, default 3). 0 or 1 shrinks a diff without dropping files"}
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
                    "path": {"type": "string", "description": "File path relative to repository (optional; defaults to the indexed files defining the symbol)"},
                    "symbol": {"type": "string", "description": "Symbol/function name to track"},
                    "max_commits": {"type": "integer", "description": "Maximum commits to return (default: 10)"}
                },
                "required": ["repo", "symbol"]
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
                    "repo": {"type": "string"},
                    "limit": {"type": "integer", "description": "Max rows to list in each of the modified-files and unpushed-commits sections (default: 20; 0 = all)"},
                    "offset": {"type": "integer", "description": "Index of the first row to list in each section (default: 0)"}
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

        // ===== Analysis Tools (3) =====

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

        // ===== Graph Tools (1) =====

        map.insert("get_code_graph", ToolMetadata {
            name: "get_code_graph",
            description: "Whole-repo graph data as raw JSON for the visualization frontend. Very large; over MCP prefer get_call_graph or get_import_graph.",
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
