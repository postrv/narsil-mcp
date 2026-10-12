//! Tool handlers for MCP protocol
//!
//! This module provides a trait-based architecture for handling MCP tool calls.
//! Each tool is implemented as a struct implementing the `ToolHandler` trait,
//! allowing for isolated testing and reduced complexity in the main MCP handler.

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

use crate::config::ExposeGroup;
use crate::index::{CodeIntelEngine, IndexBusy};

mod analysis;
mod callgraph;
mod git;
pub mod graph;
mod lsp;
mod repo;
mod search;
mod symbols;

/// Trait for implementing tool handlers
///
/// Each tool handler extracts its arguments from JSON and calls the appropriate
/// engine method, returning the result as a string.
#[async_trait::async_trait]
pub trait ToolHandler: Send + Sync {
    /// Returns the tool name as it appears in MCP protocol
    fn name(&self) -> &'static str;

    /// Execute the tool with the given arguments
    ///
    /// # Arguments
    /// * `engine` - The code intel engine to use for operations
    /// * `args` - JSON arguments from the tool call
    ///
    /// # Returns
    /// The tool result as a string, or an error
    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String>;
}

/// Registry for tool handlers
///
/// Provides efficient dispatch from tool name to handler implementation.
pub struct ToolRegistry {
    handlers: HashMap<&'static str, Box<dyn ToolHandler>>,
}

impl ToolRegistry {
    /// Create a new registry with all standard handlers
    pub fn new() -> Self {
        let mut registry = Self {
            handlers: HashMap::new(),
        };

        // Register repository handlers
        registry.register(Box::new(repo::ListReposHandler));
        registry.register(Box::new(repo::GetProjectStructureHandler));
        registry.register(Box::new(repo::GetFileHandler));
        registry.register(Box::new(repo::GetExcerptHandler));
        registry.register(Box::new(repo::DiscoverReposHandler));
        registry.register(Box::new(repo::ValidateRepoHandler));
        registry.register(Box::new(repo::ReindexHandler));
        registry.register(Box::new(repo::ForgetRepoHandler));
        registry.register(Box::new(repo::GetIndexStatusHandler));
        registry.register(Box::new(repo::GetIncrementalStatusHandler));
        registry.register(Box::new(repo::GetMetricsHandler));

        // Register symbol handlers
        registry.register(Box::new(symbols::FindSymbolsHandler));
        registry.register(Box::new(symbols::GetSymbolDefinitionHandler));
        registry.register(Box::new(symbols::FindReferencesHandler));
        registry.register(Box::new(symbols::GetDependenciesHandler));
        registry.register(Box::new(symbols::FindSymbolUsagesHandler));
        registry.register(Box::new(symbols::GetExportMapHandler));

        // Register search handlers
        registry.register(Box::new(search::SearchCodeHandler));
        registry.register(Box::new(search::SemanticSearchHandler));
        registry.register(Box::new(search::HybridSearchHandler));

        // Register call graph handlers
        registry.register(Box::new(callgraph::GetCallGraphHandler));
        registry.register(Box::new(callgraph::GetCallersHandler));
        registry.register(Box::new(callgraph::GetCalleesHandler));
        registry.register(Box::new(callgraph::FindCallPathHandler));
        registry.register(Box::new(callgraph::GetComplexityHandler));
        registry.register(Box::new(callgraph::GetFunctionHotspotsHandler));

        // Register git handlers
        registry.register(Box::new(git::GetBlameHandler));
        registry.register(Box::new(git::GetFileHistoryHandler));
        registry.register(Box::new(git::GetRecentChangesHandler));
        registry.register(Box::new(git::GetCommitRangeHandler));
        registry.register(Box::new(git::GetHotspotsHandler));
        registry.register(Box::new(git::GetContributorsHandler));
        registry.register(Box::new(git::GetCommitDiffHandler));
        registry.register(Box::new(git::GetSymbolHistoryHandler));
        registry.register(Box::new(git::GetBranchInfoHandler));
        registry.register(Box::new(git::GetModifiedFilesHandler));

        // Register LSP handlers
        registry.register(Box::new(lsp::GetHoverInfoHandler));
        registry.register(Box::new(lsp::GetTypeInfoHandler));
        registry.register(Box::new(lsp::GoToDefinitionHandler));

        // Register analysis handlers
        registry.register(Box::new(analysis::GetControlFlowHandler));
        registry.register(Box::new(analysis::GetDataFlowHandler));
        registry.register(Box::new(analysis::GetReachingDefinitionsHandler));

        // Register graph visualization handler
        registry.register(Box::new(graph::GetCodeGraphHandler));

        registry
    }

    /// Register a handler
    fn register(&mut self, handler: Box<dyn ToolHandler>) {
        self.handlers.insert(handler.name(), handler);
    }

    /// Dispatch a tool call to the appropriate handler
    ///
    /// # Arguments
    /// * `name` - The tool name
    /// * `engine` - The code intel engine
    /// * `args` - JSON arguments
    ///
    /// # Returns
    /// The tool result, or an error if the tool is unknown
    pub async fn dispatch(
        &self,
        name: &str,
        engine: &CodeIntelEngine,
        mut args: Value,
    ) -> Result<String> {
        normalize_arg_aliases(&mut args);
        reject_undeclared_args(name, &args)?;
        resolve_repo_from_path(engine, name, &mut args);
        // Index-backed tools must not answer from an index that is being
        // rebuilt: hold a read lease for the call, or refuse with EAGAIN.
        let _leases = query_leases(engine, name, &args).await?;
        self.handlers
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("Unknown tool: {}", name))?
            .execute(engine, args)
            .await
    }

    /// Check if a tool exists
    pub fn has_tool(&self, name: &str) -> bool {
        self.handlers.contains_key(name)
    }

    /// Get all registered tool names
    pub fn tool_names(&self) -> Vec<&'static str> {
        self.handlers.keys().copied().collect()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a tool answers from the in-memory index. Base tools address repos
/// and repair the index, git tools answer from git itself; everything else
/// reads the index and must not answer from one being rebuilt.
fn reads_index(tool: &str) -> bool {
    !matches!(
        ExposeGroup::of(tool),
        Some(ExposeGroup::Base) | Some(ExposeGroup::Git)
    )
}

/// Read leases to hold for the duration of an index-backed tool call. Empty for
/// tools that do not read the index, so a client can still ask what is going on
/// while a repo is being re-indexed.
async fn query_leases(
    engine: &CodeIntelEngine,
    tool: &str,
    args: &Value,
) -> Result<Vec<tokio::sync::OwnedRwLockReadGuard<()>>> {
    if !reads_index(tool) {
        return Ok(Vec::new());
    }
    let repos = match args.get_str("repo") {
        // An unresolvable repo is the handler's error to report, not ours.
        Some(repo) => match engine.resolve_repo(repo) {
            Ok(key) => vec![key],
            Err(_) => return Ok(Vec::new()),
        },
        // No repo named: the tool searches every indexed repo, so one repo
        // mid-update would make the answer silently partial.
        None => engine.all_repo_keys(),
    };
    let mut leases = Vec::with_capacity(repos.len());
    for repo in repos {
        match engine.try_query_lease(&repo).await {
            Some(lease) => leases.push(lease),
            // Returning drops the leases taken so far, so a refused query never
            // holds up the update it collided with.
            None => {
                let (indexed_repos, total_repos) = engine.indexing_progress();
                return Err(IndexBusy {
                    repo,
                    indexed_repos,
                    total_repos,
                    first_pass: false,
                }
                .into());
            }
        }
    }
    Ok(leases)
}

/// Helper trait for extracting arguments from JSON
pub trait ArgExtractor {
    fn get_str(&self, key: &str) -> Option<&str>;
    fn get_str_or(&self, key: &str, default: &str) -> String;
    fn get_u64(&self, key: &str) -> Option<u64>;
    fn get_u64_or(&self, key: &str, default: u64) -> u64;
    fn get_bool(&self, key: &str) -> Option<bool>;
    fn get_bool_or(&self, key: &str, default: bool) -> bool;
    fn get_array(&self, key: &str) -> Option<&Vec<Value>>;
}

impl ArgExtractor for Value {
    fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }

    fn get_str_or(&self, key: &str, default: &str) -> String {
        self.get_str(key).unwrap_or(default).to_string()
    }

    fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|v| v.as_u64())
    }

    fn get_u64_or(&self, key: &str, default: u64) -> u64 {
        self.get_u64(key).unwrap_or(default)
    }

    fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

    fn get_bool_or(&self, key: &str, default: bool) -> bool {
        self.get_bool(key).unwrap_or(default)
    }

    fn get_array(&self, key: &str) -> Option<&Vec<Value>> {
        self.get(key).and_then(|v| v.as_array())
    }
}

// (canonical, alias) pairs.
const ALIASES: &[(&str, &str)] = &[
    ("path", "file_path"),
    ("path", "file"),
    ("repo", "repo_path"),
    ("symbol", "symbol_name"),
    ("commit", "commit_hash"),
];

/// Map well-known argument-name aliases onto the canonical names used by the
/// handlers, in place. Clients reach for a plausible-but-wrong key
/// (`file_path` for `path`, `repo_path` for `repo`, `symbol_name` for
/// `symbol`); the schema and every handler read the canonical key, so an
/// unrecognised alias would leave the canonical key absent and silently
/// degrade downstream — an empty path (git blame -- ''), or an ignored `repo`
/// that falls through to an all-repos search. An explicit canonical key always
/// wins over its alias.
fn normalize_arg_aliases(args: &mut Value) {
    if let Some(obj) = args.as_object_mut() {
        for (canonical, alias) in ALIASES {
            if !obj.contains_key(*canonical) {
                if let Some(value) = obj.get(*alias).cloned() {
                    obj.insert((*canonical).to_string(), value);
                }
            }
        }
        // Every schema names its arguments in snake_case, but clients reach for
        // camelCase (`maxDepth`); unrecognised, the key is ignored and the tool
        // answers with the default as if nothing had been asked for.
        for (key, value) in obj.clone() {
            let snake = snake_case(&key);
            if snake != key && !obj.contains_key(&snake) {
                obj.insert(snake, value);
            }
        }
    }
}

/// Refuse an argument the tool's schema does not declare. A handler reads the
/// keys it knows and ignores the rest, so a mistaken one (`mode` on a tool
/// with no modes) leaves an answer that reads as if it had been honoured —
/// the whole query silently means something else. Aliases and camelCase are
/// accepted: normalize_arg_aliases has already put their canonical form in.
fn reject_undeclared_args(tool: &str, args: &Value) -> Result<()> {
    let Some(metadata) = crate::tool_metadata::get_tool_metadata(tool) else {
        return Ok(());
    };
    let Some(properties) = metadata.input_schema["properties"].as_object() else {
        return Ok(());
    };
    let Some(passed) = args.as_object() else {
        return Ok(());
    };

    let declared = |key: &str| {
        properties.contains_key(key)
            || properties.contains_key(&snake_case(key))
            || ALIASES
                .iter()
                .any(|(canonical, alias)| *alias == key && properties.contains_key(*canonical))
    };

    let undeclared: Vec<&str> = passed
        .keys()
        .map(String::as_str)
        .filter(|key| !declared(key))
        .collect();
    if undeclared.is_empty() {
        return Ok(());
    }

    let mut accepted: Vec<&str> = properties.keys().map(String::as_str).collect();
    accepted.sort_unstable();
    Err(anyhow::anyhow!(
        "{} does not take {}. It takes: {}.",
        tool,
        undeclared.join(", "),
        accepted.join(", ")
    ))
}

/// An absolute `path` already names the repository it lives in: take `repo`
/// from it and make the path repo-relative, so a path pasted from a search
/// result or an editor works without restating the repo. Silent when the path
/// is outside every indexed repo — the handler's own error is the better one.
///
/// Only for tools that take a `repo` at all; for the repo-discovery tools
/// (discover_repos, validate_repo) the path is the subject of the call, not a
/// file inside an indexed repo. The path is rewritten only where the schema
/// also declares `path`, which is what makes that argument repo-relative.
fn resolve_repo_from_path(engine: &CodeIntelEngine, tool: &str, args: &mut Value) {
    if args.get_str("repo").is_some_and(|repo| !repo.is_empty()) {
        return;
    }
    let Some(path) = args.get_str("path").map(str::to_string) else {
        return;
    };
    if !std::path::Path::new(&path).is_absolute() {
        return;
    }
    let Some(metadata) = crate::tool_metadata::get_tool_metadata(tool) else {
        return;
    };
    let properties = &metadata.input_schema["properties"];
    if properties["repo"].is_null() {
        return;
    }
    let Ok(repo) = engine.resolve_repo(&path) else {
        return;
    };
    let relative = std::path::Path::new(&path)
        .canonicalize()
        .ok()
        .and_then(|canonical| {
            canonical
                .strip_prefix(&repo)
                .ok()
                .map(|relative| relative.to_string_lossy().into_owned())
        });

    let takes_repo_relative_path = !properties["path"].is_null();
    if let Some(obj) = args.as_object_mut() {
        obj.insert("repo".to_string(), Value::String(repo));
        if let Some(relative) = relative {
            if takes_repo_relative_path {
                obj.insert("path".to_string(), Value::String(relative));
            }
        }
    }
}

/// `maxDepth` -> `max_depth`. Returns the input unchanged when there is nothing
/// to convert.
fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for ch in name.chars() {
        if ch.is_ascii_uppercase() {
            if !out.is_empty() {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Require a non-empty string argument, erroring with a message naming the
/// tool and argument. Without this, a missing or empty required argument
/// silently flows into the engine and produces a plausible-but-wrong result
/// (validate_path resolves "" to the repo root directory, `.contains("")`
/// matches every line, a lookup on "" just reads as "not found") instead of
/// a clear failure.
fn require_arg<'a>(args: &'a Value, key: &str, tool: &str) -> Result<&'a str> {
    match args.get_str(key) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(anyhow::anyhow!(
            "{tool} requires a non-empty '{key}' argument"
        )),
    }
}

/// The caller's window into a list-shaped result, from the `offset` and
/// `limit` arguments. `default_limit` differs per tool because the rows differ
/// in size; `limit=0` always means "no cap".
fn list_window(args: &Value, default_limit: u64) -> crate::response_budget::ListWindow {
    crate::response_budget::ListWindow::new(
        args.get_u64_or("offset", 0) as usize,
        args.get_u64_or("limit", default_limit) as usize,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A branch switch (or a reindex) makes the index unreadable for a while.
    /// An index-backed tool must say so rather than answer from it, while the
    /// tools that report what is going on keep working.
    #[tokio::test]
    async fn index_backed_tools_get_eagain_during_an_update() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();
        let registry = ToolRegistry::new();
        let args = serde_json::json!({ "repo": repo.to_str().unwrap() });

        let _update = engine.index_update_leases(&engine.all_repo_keys()).await;

        let refused = registry
            .dispatch("find_symbols", &engine, args.clone())
            .await
            .expect_err("find_symbols reads the index");
        assert!(refused.downcast_ref::<IndexBusy>().is_some());

        // A query naming no repo searches all of them, so it is refused too.
        let refused_all = registry
            .dispatch("search_code", &engine, serde_json::json!({ "query": "x" }))
            .await
            .expect_err("search_code reads every repo");
        assert!(refused_all.downcast_ref::<IndexBusy>().is_some());

        // get_index_status is how a caller finds out why: it must not be
        // refused by the very update it is asking about.
        let status = registry.dispatch("get_index_status", &engine, args).await;
        assert!(status.is_ok(), "{:?}", status.err());
    }

    /// A path pasted from a search result or an editor is absolute and already
    /// says which repo it belongs to; the caller should not have to restate it.
    #[tokio::test]
    async fn absolute_path_supplies_the_repo() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(repo.join("src/lib.rs"), "fn main() {}").unwrap();
        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();

        let mut args = serde_json::json!({ "path": repo.join("src/lib.rs").to_str().unwrap() });
        resolve_repo_from_path(&engine, "get_file", &mut args);
        assert_eq!(args.get_str("repo"), Some(repo.to_str().unwrap()));
        assert_eq!(args.get_str("path"), Some("src/lib.rs"));

        // get_project_structure has no `path` argument, so only the repo is
        // filled in — its `path` is not repo-relative to rewrite.
        let mut args = serde_json::json!({ "path": repo.join("src").to_str().unwrap() });
        resolve_repo_from_path(&engine, "get_project_structure", &mut args);
        assert_eq!(args.get_str("repo"), Some(repo.to_str().unwrap()));
    }

    /// validate_repo's path IS the subject of the call: rewriting it, or
    /// pinning the call to some other repo, would answer a different question.
    #[tokio::test]
    async fn repo_discovery_tools_keep_their_path() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        let engine = CodeIntelEngine::new(temp.path().join("index"), vec![repo.clone()])
            .await
            .unwrap();

        let inside = repo.join("src");
        let mut args = serde_json::json!({ "path": inside.to_str().unwrap() });
        resolve_repo_from_path(&engine, "validate_repo", &mut args);
        assert_eq!(args.get_str("repo"), None);
        assert_eq!(args.get_str("path"), inside.to_str());
    }

    #[test]
    fn non_index_tools_take_no_lease() {
        assert!(reads_index("find_symbols"));
        assert!(reads_index("get_callers"));
        assert!(!reads_index("get_index_status"));
        assert!(!reads_index("reindex"));
        assert!(!reads_index("get_blame"));
    }

    #[test]
    fn test_registry_creation() {
        let registry = ToolRegistry::new();
        assert!(registry.has_tool("list_repos"));
        assert!(registry.has_tool("find_symbols"));
        assert!(registry.has_tool("search_code"));
        assert!(!registry.has_tool("nonexistent_tool"));
    }

    #[test]
    fn test_tool_names() {
        let registry = ToolRegistry::new();
        let names = registry.tool_names();
        assert!(names.contains(&"list_repos"));
        assert!(names.contains(&"get_file"));
    }

    #[test]
    fn test_arg_extractor() {
        let args = serde_json::json!({
            "repo": "test",
            "count": 5,
            "enabled": true
        });

        assert_eq!(args.get_str("repo"), Some("test"));
        assert_eq!(args.get_str("missing"), None);
        assert_eq!(args.get_str_or("missing", "default"), "default");

        assert_eq!(args.get_u64("count"), Some(5));
        assert_eq!(args.get_u64_or("missing", 10), 10);

        assert_eq!(args.get_bool("enabled"), Some(true));
        assert!(!args.get_bool_or("missing", false));
    }

    /// An argument no tool declares changes nothing, so an answer computed
    /// without it looks like an answer that honoured it. It must be refused.
    #[test]
    fn an_undeclared_argument_is_refused() {
        let args = serde_json::json!({"query": "a|b", "depth": 3});
        let error = reject_undeclared_args("search_code", &args)
            .expect_err("search_code has no depth argument")
            .to_string();
        assert!(error.contains("does not take depth"), "{error}");
        assert!(error.contains("file_pattern"), "{error}");

        // Declared, aliased and camelCase forms all pass.
        let good = serde_json::json!({
            "query": "a|b",
            "mode": "regex",
            "repo_path": "/tmp/r",
            "maxResults": 5,
            "max_results": 5,
        });
        assert!(reject_undeclared_args("search_code", &good).is_ok());

        // A tool with no metadata is not second-guessed.
        assert!(reject_undeclared_args("no_such_tool", &args).is_ok());
    }

    #[test]
    fn test_file_path_aliases_to_path() {
        // Regression: a caller sending `file_path` must reach the handler as
        // `path`, not an empty string (git blame -- '' "no such path ''").
        let mut args = serde_json::json!({"repo": "r", "file_path": "src/x.rs"});
        normalize_arg_aliases(&mut args);
        assert_eq!(args.get_str("path"), Some("src/x.rs"));
    }

    #[test]
    fn test_explicit_path_wins_over_file_path() {
        let mut args = serde_json::json!({"path": "real", "file_path": "alias"});
        normalize_arg_aliases(&mut args);
        assert_eq!(args.get_str("path"), Some("real"));
    }

    #[test]
    fn test_no_path_alias_leaves_args_untouched() {
        let mut args = serde_json::json!({"repo": "r"});
        normalize_arg_aliases(&mut args);
        assert_eq!(args.get_str("path"), None);
    }

    #[test]
    fn test_repo_path_aliases_to_repo() {
        // Regression: `repo_path` is a common wrong guess; unaliased it leaves
        // `repo` absent, which for search_code falls through to an all-repos
        // search instead of scoping to the intended repo.
        let mut args = serde_json::json!({"repo_path": "/src/x", "query": "q"});
        normalize_arg_aliases(&mut args);
        assert_eq!(args.get_str("repo"), Some("/src/x"));
    }

    #[test]
    fn test_explicit_repo_wins_over_repo_path() {
        let mut args = serde_json::json!({"repo": "real", "repo_path": "alias"});
        normalize_arg_aliases(&mut args);
        assert_eq!(args.get_str("repo"), Some("real"));
    }

    #[test]
    fn test_symbol_name_aliases_to_symbol() {
        // Regression: `symbol_name` (the engine's own param name) is a natural
        // guess; unaliased it leaves `symbol` empty and require_arg rejects the
        // call with a misleading "non-empty 'symbol'" error.
        let mut args = serde_json::json!({"repo": "r", "symbol_name": "foo"});
        normalize_arg_aliases(&mut args);
        assert_eq!(args.get_str("symbol"), Some("foo"));
    }

    #[test]
    fn test_explicit_symbol_wins_over_symbol_name() {
        let mut args = serde_json::json!({"symbol": "real", "symbol_name": "alias"});
        normalize_arg_aliases(&mut args);
        assert_eq!(args.get_str("symbol"), Some("real"));
    }

    #[test]
    fn test_commit_hash_aliases_to_commit() {
        // Regression: unaliased, `commit_hash` left `commit` empty and
        // get_commit_diff ran `git show ''` — an "ambiguous argument ''" error
        // that reads as a broken hash rather than a wrong argument name.
        let mut args = serde_json::json!({"repo": "r", "commit_hash": "846d0f2552a1"});
        normalize_arg_aliases(&mut args);
        assert_eq!(args.get_str("commit"), Some("846d0f2552a1"));
    }

    #[test]
    fn test_explicit_commit_wins_over_commit_hash() {
        let mut args = serde_json::json!({"commit": "real", "commit_hash": "alias"});
        normalize_arg_aliases(&mut args);
        assert_eq!(args.get_str("commit"), Some("real"));
    }

    #[test]
    fn test_camel_case_reaches_the_snake_case_argument() {
        // Regression: get_project_structure(maxDepth=2) ignored the depth and
        // walked the default 4 levels, with nothing in the output saying so.
        let mut args = serde_json::json!({"repo": "r", "maxDepth": 2, "maxTotalEntries": 10});
        normalize_arg_aliases(&mut args);
        assert_eq!(args.get_u64("max_depth"), Some(2));
        assert_eq!(args.get_u64("max_total_entries"), Some(10));
    }

    #[test]
    fn test_explicit_snake_case_wins_over_camel_case() {
        let mut args = serde_json::json!({"max_depth": 1, "maxDepth": 9});
        normalize_arg_aliases(&mut args);
        assert_eq!(args.get_u64("max_depth"), Some(1));
    }
}
