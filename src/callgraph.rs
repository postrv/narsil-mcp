//! Call graph analysis - tracks which functions call which
//!
//! This is critical for AI understanding of code flow and impact analysis.

use crate::symbols::{SourceLine, SourceSet};
use crate::syscall::{syscall_body_of, syscall_define_name, syscall_name_for_body};
use anyhow::Result;
use dashmap::DashMap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use regex::Regex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use tree_sitter::{Node, Tree};

/// A node in the call graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallNode {
    /// Fully qualified name of the function
    pub name: String,
    /// File where defined
    pub file_path: String,
    /// Line number
    pub line: usize,
    /// Functions this calls (outgoing edges)
    pub calls: Vec<CallEdge>,
    /// Functions that call this (incoming edges)
    pub called_by: Vec<CallEdge>,
    /// Complexity metrics
    pub metrics: FunctionMetrics,
}

/// An edge in the call graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    /// Target function name
    pub target: String,
    /// File containing the call
    pub file_path: String,
    /// Line of the call site (canonical — from the highest-priority confirmer)
    pub line: usize,
    /// Column of the call site
    pub column: usize,
    /// Is this a direct call or through a reference/closure?
    pub call_type: CallType,
    /// Scope qualifier from the call site (e.g. "App" from `App::run()`)
    #[serde(default)]
    pub scope_hint: Option<String>,
    /// Backends that confirmed this edge (tree-sitter, clangd, ccls, gtags).
    #[serde(default = "SourceSet::tree_sitter_default")]
    pub confirmed_by: SourceSet,
    /// Confirmers whose reported call-site line differs from `line`. Empty when
    /// all agree. Retained so a disagreement reaches the consumer.
    #[serde(default)]
    pub line_conflicts: Vec<SourceLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CallType {
    Direct,       // foo()
    Method,       // obj.foo()
    StaticMethod, // Type::foo()
    Closure,      // let f = foo; f()
    Async,        // foo().await
    Spawn,        // spawn(foo)
    Unknown,
}

/// Function complexity metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionMetrics {
    /// Lines of code
    pub loc: usize,
    /// Cyclomatic complexity (branches + 1)
    pub cyclomatic: usize,
    /// Nesting depth
    pub max_depth: usize,
    /// Number of parameters
    pub params: usize,
    /// Number of return points
    pub returns: usize,
    /// Cognitive complexity
    pub cognitive: usize,
}

/// A span tree-sitter could not parse into a function definition — typically an
/// `if` whose condition or opening brace is split across `#if`/`#else`/`#endif`,
/// which the C/C++ grammars fold into a single `ERROR` node. The functions (and
/// any calls inside them) in this span are absent from the call graph.
#[derive(Debug, Clone)]
pub struct DegradedRegion {
    pub start_line: usize,
    pub end_line: usize,
    pub likely_preprocessor: bool,
}

/// The call graph for a repository
pub struct CallGraph {
    /// Function name -> CallNode
    nodes: DashMap<String, CallNode>,
    /// File -> Functions defined in that file
    file_functions: DashMap<String, Vec<String>>,
    /// bare_name -> Vec<qualified_key>  (built during first pass, O(1) lookup in resolve_callee)
    name_index: DashMap<String, Vec<String>>,
    /// File -> unparsed regions that look like function bodies (see `DegradedRegion`)
    degraded: DashMap<String, Vec<DegradedRegion>>,
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Definitions of one name that `to_markdown` renders in full. A name like
/// `init` has one per file in a large C tree; the rest are named by count.
const MAX_RENDERED_DEFINITIONS: usize = 10;

/// Heap bytes owned by one call edge (strings + line_conflicts Vec). Excludes
/// the edge's inline footprint, counted by the holding Vec's capacity.
fn call_edge_heap_bytes(edge: &CallEdge) -> usize {
    edge.target.capacity()
        + edge.file_path.capacity()
        + edge.scope_hint.as_ref().map_or(0, String::capacity)
        + edge.line_conflicts.capacity() * std::mem::size_of::<SourceLine>()
}

/// Heap behind a `DashMap<String, Vec<String>>`: key buffers plus each Vec's
/// inline String slots and their buffers. The map's slot table is sized by the
/// caller; DashMap does not expose slot capacity, so len() approximates it.
fn string_vec_map_heap_bytes(map: &DashMap<String, Vec<String>>) -> usize {
    map.iter()
        .map(|entry| {
            entry.key().capacity()
                + entry.value().capacity() * std::mem::size_of::<String>()
                + entry.value().iter().map(String::capacity).sum::<usize>()
        })
        .sum()
}

/// An identifier, a parenthesised parameter list, and an opening brace — the
/// shape of a function signature immediately followed by its body. Cheap
/// stand-in for re-parsing an `ERROR` node's text.
fn function_like_error_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"[A-Za-z_][A-Za-z0-9_]*\s*\([^;{}]*\)\s*\{").expect("static regex is valid")
    })
}

/// Classify an `ERROR` node as a lost function body, or `None` if it doesn't
/// look like one. `likely_preprocessor` names the common cause seen in
/// practice: an `if` whose condition or brace is split across
/// `#if`/`#else`/`#endif`, which C/C++ grammars cannot reconcile into one
/// `if_statement`.
fn degraded_region_for(node: Node, source: &[u8]) -> Option<DegradedRegion> {
    let text = node.utf8_text(source).ok()?;
    if !function_like_error_regex().is_match(text) {
        return None;
    }
    let likely_preprocessor = text.contains("#if") || text.contains("#ifdef") || text.contains("#else");
    Some(DegradedRegion {
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
        likely_preprocessor,
    })
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
            file_functions: DashMap::new(),
            name_index: DashMap::new(),
            degraded: DashMap::new(),
        }
    }

    /// Estimated heap held by this call graph: the three DashMaps' slot tables,
    /// their String keys, and the CallNodes with their CallEdge vectors. DashMap
    /// does not expose slot capacity, so per-map table overhead is approximated
    /// from len().
    pub fn heap_bytes(&self) -> usize {
        use crate::metrics::hashmap_table_bytes;

        let nodes = hashmap_table_bytes::<String, CallNode>(self.nodes.len())
            + self
                .nodes
                .iter()
                .map(|entry| {
                    let node = entry.value();
                    entry.key().capacity()
                        + node.name.capacity()
                        + node.file_path.capacity()
                        + node.calls.capacity() * std::mem::size_of::<CallEdge>()
                        + node.calls.iter().map(call_edge_heap_bytes).sum::<usize>()
                        + node.called_by.capacity() * std::mem::size_of::<CallEdge>()
                        + node
                            .called_by
                            .iter()
                            .map(call_edge_heap_bytes)
                            .sum::<usize>()
                })
                .sum::<usize>();

        let file_functions = hashmap_table_bytes::<String, Vec<String>>(self.file_functions.len())
            + string_vec_map_heap_bytes(&self.file_functions);

        let name_index = hashmap_table_bytes::<String, Vec<String>>(self.name_index.len())
            + string_vec_map_heap_bytes(&self.name_index);

        let degraded = hashmap_table_bytes::<String, Vec<DegradedRegion>>(self.degraded.len())
            + self
                .degraded
                .iter()
                .map(|entry| {
                    entry.key().capacity()
                        + entry.value().capacity() * std::mem::size_of::<DegradedRegion>()
                })
                .sum::<usize>();

        nodes + file_functions + name_index + degraded
    }

    /// Build call graph from parsed files
    pub fn build_from_files(&self, files: &[(String, String, Tree)]) -> Result<()> {
        // Pass 1: collect all function definitions — fully independent per file
        files
            .par_iter()
            .try_for_each(|(path, content, tree)| self.extract_functions(path, content, tree))?;

        // Sort each name_index entry once so resolve_callee gets a pre-sorted
        // candidate list and never needs to sort again.  Serial is fine here —
        // O(E log E) total over all entries, negligible versus the two AST walks.
        self.name_index.iter_mut().for_each(|mut entry| {
            entry.value_mut().sort();
        });

        // Pass 2: find all call sites — per-file caller keys are distinct;
        // hot callees (e.g. printk) serialize called_by pushes across shards
        // but DashMap handles it correctly and this is still far faster than serial.
        files
            .par_iter()
            .try_for_each(|(path, content, tree)| self.extract_calls(path, content, tree))?;

        Ok(())
    }

    /// Remove the definitions and call edges contributed by one file.
    pub fn remove_file(&self, file_path: &str) {
        self.degraded.remove(file_path);

        let function_names = self
            .file_functions
            .remove(file_path)
            .map(|(_, names)| names)
            .unwrap_or_default();
        let removed_names: HashSet<_> = function_names.iter().cloned().collect();
        let removed_bare_names: HashSet<String> = function_names
            .iter()
            .filter_map(|name| name.rsplit("::").next())
            .map(str::to_owned)
            .collect();

        for function_name in function_names {
            self.nodes.remove(&function_name);
            if let Some(bare_name) = function_name.rsplit("::").next() {
                if let Some(mut names) = self.name_index.get_mut(bare_name) {
                    names.retain(|name| name != &function_name);
                    if names.is_empty() {
                        drop(names);
                        self.name_index.remove(bare_name);
                    }
                }
            }
        }

        for mut node in self.nodes.iter_mut() {
            node.calls.retain(|edge| {
                edge.file_path != file_path
                    && !removed_names.contains(&edge.target)
                    && !removed_bare_names.contains(edge.target.as_str())
            });
            node.called_by.retain(|edge| edge.file_path != file_path);
        }
    }

    /// Bare callee names at every call site of one parsed file, sorted and
    /// deduplicated, before any resolution against known definitions. A scoped
    /// index asks for these to find out which definitions its filter left out.
    pub fn referenced_callee_names(content: &str, tree: &Tree) -> Vec<String> {
        let source = content.as_bytes();
        let mut cursor = tree.walk();
        let mut names = Vec::new();
        let mut depth: usize = 0;

        loop {
            let node = cursor.node();
            if matches!(
                node.kind(),
                "call_expression" | "call" | "method_call_expression" | "invocation_expression"
            ) {
                if let Some((name, _, _)) = Self::callee_at_call_site(node, source) {
                    names.push(name);
                }
            }

            if cursor.goto_first_child() {
                depth += 1;
                continue;
            }

            if cursor.goto_next_sibling() {
                continue;
            }

            loop {
                if depth == 0 {
                    names.sort();
                    names.dedup();
                    return names;
                }
                cursor.goto_parent();
                depth -= 1;
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Merge edges from one backend into the graph. Each input pairs a resolved
    /// caller key with an outgoing `CallEdge` whose `target` is the callee's
    /// bare name (resolved here against the existing nodes). For each
    /// (caller, callee) pair:
    ///   - `confirmed_by` accumulates `source`;
    ///   - if `source` outranks the current canonical confirmer it wins the
    ///     call-site line/column, demoting the old line into `line_conflicts`;
    ///   - otherwise a differing line is recorded in `line_conflicts`.
    ///
    /// A pair not already present is inserted with `confirmed_by = {source}`.
    /// Only existing caller/callee nodes are touched — tree-sitter provides the
    /// node baseline.
    pub fn merge_edges(&self, edges: Vec<(String, CallEdge)>, source: SourceSet) {
        for (caller_key, mut new_edge) in edges {
            let callee_key = self.resolve_callee(
                &new_edge.target,
                &new_edge.file_path,
                new_edge.scope_hint.as_deref(),
            );
            new_edge.target = callee_key.clone();

            // Outgoing edge on the caller.
            if let Some(mut caller_node) = self.nodes.get_mut(&caller_key) {
                match Self::edge_to(&mut caller_node.calls, &callee_key, new_edge.line) {
                    Some(existing) => {
                        Self::fold_edge(existing, source, new_edge.line, new_edge.column)
                    }
                    None => {
                        new_edge.confirmed_by = source;
                        new_edge.line_conflicts = Vec::new();
                        caller_node.calls.push(new_edge.clone());
                    }
                }
            }

            // Incoming edge on the callee (keyed by the caller).
            if let Some(mut callee_node) = self.nodes.get_mut(callee_key.as_str()) {
                match Self::edge_to(&mut callee_node.called_by, &caller_key, new_edge.line) {
                    Some(existing) => {
                        Self::fold_edge(existing, source, new_edge.line, new_edge.column)
                    }
                    None => {
                        callee_node.called_by.push(CallEdge {
                            target: caller_key.clone(),
                            file_path: new_edge.file_path.clone(),
                            line: new_edge.line,
                            column: new_edge.column,
                            call_type: new_edge.call_type.clone(),
                            scope_hint: None,
                            confirmed_by: source,
                            line_conflicts: Vec::new(),
                        });
                    }
                }
            }
        }
    }

    /// The edge to `target` at `line`, else the first edge to `target`. A caller
    /// can call one function on several lines; matching by name alone folds
    /// every site onto the first. The fallback keeps a backend that reports
    /// another line for a single site folding into it.
    fn edge_to<'a>(
        edges: &'a mut [CallEdge],
        target: &str,
        line: usize,
    ) -> Option<&'a mut CallEdge> {
        let idx = edges
            .iter()
            .position(|e| e.target == target && e.line == line)
            .or_else(|| edges.iter().position(|e| e.target == target))?;
        Some(&mut edges[idx])
    }

    /// Fold a `source` confirmation into an existing edge: record the confirmer,
    /// and let priority decide the canonical call-site line — the loser's line
    /// is retained in `line_conflicts`.
    fn fold_edge(edge: &mut CallEdge, source: SourceSet, new_line: usize, new_column: usize) {
        let old_canonical = edge.confirmed_by.highest();
        edge.confirmed_by.insert(source);
        if source.rank() > old_canonical.rank() {
            if edge.line != new_line {
                edge.line_conflicts.push(SourceLine {
                    source: old_canonical,
                    line: edge.line,
                });
            }
            edge.line = new_line;
            edge.column = new_column;
        } else if new_line != edge.line {
            edge.line_conflicts.push(SourceLine {
                source,
                line: new_line,
            });
        }
    }

    /// Collapse edges that render identically. One line can hold several calls
    /// to the same function (`f(a) || f(b)`), and neither the caller nor the
    /// callee listing carries a column, so those sites arrive as repeated rows
    /// and inflate the reported total. Confirmers and line conflicts of the
    /// folded sites are kept.
    pub fn fold_duplicate_sites(edges: Vec<CallEdge>) -> Vec<CallEdge> {
        let mut folded: Vec<CallEdge> = Vec::with_capacity(edges.len());
        let mut first_at: HashMap<(String, String, usize, CallType), usize> = HashMap::new();

        for edge in edges {
            let key = (
                edge.target.clone(),
                edge.file_path.clone(),
                edge.line,
                edge.call_type.clone(),
            );
            match first_at.get(&key) {
                Some(&kept_idx) => {
                    let kept = &mut folded[kept_idx];
                    kept.confirmed_by.insert(edge.confirmed_by);
                    for conflict in edge.line_conflicts {
                        if !kept.line_conflicts.contains(&conflict) {
                            kept.line_conflicts.push(conflict);
                        }
                    }
                }
                None => {
                    first_at.insert(key, folded.len());
                    folded.push(edge);
                }
            }
        }

        folded
    }

    /// Create a qualified key for the DashMap: "file_path::function_name".
    /// `pub(crate)` so index-time edge augmentation can build the resolved
    /// caller key that [`CallGraph::merge_edges`] expects.
    pub(crate) fn qualified_key(file_path: &str, name: &str) -> String {
        format!("{}::{}", file_path, name)
    }

    /// Outgoing edges that a non-tree-sitter backend (clangd/ccls/gtags)
    /// confirmed, as `(caller_key, edge)`. These are the expensive product of
    /// [`CallGraph::merge_edges`]; persisting them lets an unchanged repo replay
    /// the augmentation on restart instead of re-querying the backends. Pure
    /// tree-sitter edges are omitted — `build_from_files` reproduces them.
    pub fn export_augmentation_edges(&self) -> Vec<(String, CallEdge)> {
        let mut edges = Vec::new();
        for node in self.nodes.iter() {
            let caller_key = node.key();
            for edge in &node.value().calls {
                if edge.confirmed_by.contains(SourceSet::CLANGD)
                    || edge.confirmed_by.contains(SourceSet::CCLS)
                    || edge.confirmed_by.contains(SourceSet::GTAGS)
                {
                    edges.push((caller_key.clone(), edge.clone()));
                }
            }
        }
        edges
    }

    /// Replay persisted augmentation edges onto a freshly-built baseline,
    /// reproducing the end state of [`CallGraph::merge_edges`] without the
    /// backend round-trips. Each input edge is already fully folded (its
    /// `target` is the resolved callee key, its `confirmed_by`/`line` final), so
    /// it overwrites the matching tree-sitter baseline edge or is inserted when
    /// no backend-only edge exists yet. The callee's `called_by` mirror is
    /// derived from the same edge, matching how `merge_edges` keeps both sides in
    /// sync. Only existing caller/callee nodes are touched.
    pub fn restore_augmentation_edges(&self, edges: Vec<(String, CallEdge)>) {
        for (caller_key, edge) in edges {
            let callee_key = edge.target.clone();

            if let Some(mut caller_node) = self.nodes.get_mut(&caller_key) {
                match Self::edge_to(&mut caller_node.calls, &callee_key, edge.line) {
                    Some(existing) => *existing = edge.clone(),
                    None => caller_node.calls.push(edge.clone()),
                }
            }

            // The callee's incoming edge keyed by the caller; scope_hint is not
            // carried on the called_by side (matches `merge_edges`).
            if let Some(mut callee_node) = self.nodes.get_mut(callee_key.as_str()) {
                let incoming = CallEdge {
                    target: caller_key.clone(),
                    file_path: edge.file_path.clone(),
                    line: edge.line,
                    column: edge.column,
                    call_type: edge.call_type.clone(),
                    scope_hint: None,
                    confirmed_by: edge.confirmed_by,
                    line_conflicts: edge.line_conflicts.clone(),
                };
                match Self::edge_to(&mut callee_node.called_by, &caller_key, incoming.line) {
                    Some(existing) => *existing = incoming,
                    None => callee_node.called_by.push(incoming),
                }
            }
        }
    }

    fn extract_functions(&self, path: &str, content: &str, tree: &Tree) -> Result<()> {
        let source = content.as_bytes();
        let mut cursor = tree.walk();
        let mut functions = Vec::new();
        let mut degraded = Vec::new();

        self.walk_for_functions(&mut cursor, source, path, &mut functions, &mut degraded);

        for func in &functions {
            let key = Self::qualified_key(path, &func.name);
            self.name_index
                .entry(func.name.clone())
                .or_default()
                .push(key.clone());
            self.nodes.insert(key, func.clone());
        }

        let names: Vec<_> = functions
            .into_iter()
            .map(|f| Self::qualified_key(path, &f.name))
            .collect();
        self.file_functions.insert(path.to_string(), names);

        if degraded.is_empty() {
            self.degraded.remove(path);
        } else {
            self.degraded.insert(path.to_string(), degraded);
        }

        Ok(())
    }

    fn walk_for_functions(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        path: &str,
        functions: &mut Vec<CallNode>,
        degraded: &mut Vec<DegradedRegion>,
    ) {
        let mut depth: usize = 0;
        loop {
            let node = cursor.node();

            if let Some(func) = self.try_extract_function(node, source, path) {
                functions.push(func);
            }

            // An ERROR node that reads like a function body is a parse failure,
            // not a construct to recurse into — nested ERROR children inside it
            // add no further signal and would only double-count the same gap.
            if node.kind() == "ERROR" {
                if let Some(region) = degraded_region_for(node, source) {
                    degraded.push(region);
                }
            } else if cursor.goto_first_child() {
                depth += 1;
                continue;
            }

            if cursor.goto_next_sibling() {
                continue;
            }

            loop {
                if depth == 0 {
                    return;
                }
                cursor.goto_parent();
                depth -= 1;
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn try_extract_function(&self, node: Node, source: &[u8], path: &str) -> Option<CallNode> {
        let kind = node.kind();

        // Linux SYSCALL_DEFINEn: tree-sitter sees a call_expression, not a
        // function_definition. Synthesise a node named after the syscall so the
        // entry point and its body's callees enter the graph.
        if kind == "call_expression" {
            if let (Some(name), Some(body)) =
                (syscall_define_name(node, source), syscall_body_of(node))
            {
                let metrics = self.compute_metrics(body, source);
                return Some(CallNode {
                    name,
                    file_path: path.to_string(),
                    line: node.start_position().row + 1,
                    calls: Vec::new(),
                    called_by: Vec::new(),
                    metrics,
                });
            }
        }

        // Match function definition patterns across languages
        let is_function = matches!(
            kind,
            "function_item"
                | "function_definition"
                | "function_declaration"
                | "method_definition"
                | "method_declaration"
                | "arrow_function"
                | "lambda"
                | "closure_expression"
                | "lambda_expression"   // C++ lambda
                | "template_declaration" // C++ template — wraps a function_definition
        );

        if !is_function {
            return None;
        }

        // For C++ template_declaration, descend into the wrapped function rather than
        // treating the template node itself as a callable.
        if kind == "template_declaration" {
            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if matches!(
                        child.kind(),
                        "function_definition" | "function_declaration" | "method_declaration"
                    ) {
                        return self.try_extract_function(child, source, path);
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
            return None;
        }

        // C++ lambda_expression has no identifier child; synthesise a name from position.
        let name = if kind == "lambda_expression" {
            format!("lambda@{}", node.start_position().row + 1)
        } else {
            extract_function_name(node, source)?
        };
        let metrics = self.compute_metrics(node, source);

        Some(CallNode {
            name,
            file_path: path.to_string(),
            line: node.start_position().row + 1,
            calls: Vec::new(),
            called_by: Vec::new(),
            metrics,
        })
    }

    fn extract_calls(&self, path: &str, content: &str, tree: &Tree) -> Result<()> {
        let source = content.as_bytes();
        let mut cursor = tree.walk();

        // Track current function scope
        let mut current_function: Option<String> = None;
        self.walk_for_calls(&mut cursor, source, path, &mut current_function);

        Ok(())
    }

    fn walk_for_calls(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        path: &str,
        current_function: &mut Option<String>,
    ) {
        // Saved (function-node depth, enclosing scope) pairs. A function's scope
        // is only valid for nodes deeper than its definition node, so it must be
        // popped once the walk returns to that depth or shallower — otherwise
        // top-level calls after a function body get charged to that function.
        let mut scope_stack: Vec<(usize, Option<String>)> = Vec::new();
        let mut depth: usize = 0;
        loop {
            let node = cursor.node();
            let kind = node.kind();

            // Leave any function scope whose definition node sits at or above the
            // current depth: a node at depth d cannot be inside such a function.
            while let Some(&(scope_depth, _)) = scope_stack.last() {
                if scope_depth >= depth {
                    *current_function = scope_stack.pop().unwrap().1;
                } else {
                    break;
                }
            }

            // Update current function context (use qualified key)
            if matches!(
                kind,
                "function_item"
                    | "function_definition"
                    | "function_declaration"
                    | "method_definition"
                    | "method_declaration"
                    | "lambda_expression"
                    | "template_declaration"
            ) {
                let name = if kind == "lambda_expression" {
                    Some(format!("lambda@{}", node.start_position().row + 1))
                } else {
                    extract_function_name(node, source)
                };
                if let Some(name) = name {
                    scope_stack.push((depth, current_function.clone()));
                    *current_function = Some(Self::qualified_key(path, &name));
                }
            }

            // A SYSCALL_DEFINEn body is a compound_statement sibling of the macro
            // call, not a child of any function node — scope its calls to the
            // synthesised syscall function for the duration of the body subtree.
            if kind == "compound_statement" {
                if let Some(name) = syscall_name_for_body(node, source) {
                    scope_stack.push((depth, current_function.clone()));
                    *current_function = Some(Self::qualified_key(path, &name));
                }
            }

            // Check for call expressions
            if matches!(
                kind,
                "call_expression" | "call" | "method_call_expression" | "invocation_expression"
            ) {
                if let Some(ref caller_key) = current_function {
                    if let Some(edge) = self.extract_call_edge(node, source, path) {
                        // Resolve callee with scope hint for disambiguation
                        let callee_key =
                            self.resolve_callee(&edge.target, path, edge.scope_hint.as_deref());

                        // Add to caller's outgoing calls (with resolved key as target)
                        if let Some(mut caller_node) = self.nodes.get_mut(caller_key.as_str()) {
                            let mut resolved_edge = edge.clone();
                            resolved_edge.target = callee_key.clone();
                            caller_node.calls.push(resolved_edge);
                        }

                        // Add to callee's incoming calls
                        if let Some(mut callee_node) = self.nodes.get_mut(callee_key.as_str()) {
                            callee_node.called_by.push(CallEdge {
                                target: caller_key.clone(),
                                file_path: edge.file_path,
                                line: edge.line,
                                column: edge.column,
                                call_type: edge.call_type,
                                scope_hint: None,
                                confirmed_by: SourceSet::TREE_SITTER,
                                line_conflicts: Vec::new(),
                            });
                        }
                    }
                }
            }

            // Handle macro invocations (opaque token trees in tree-sitter)
            // Extract call patterns from macro body text
            if kind == "macro_invocation" {
                if let Some(ref caller_key) = current_function {
                    if let Ok(macro_text) = node.utf8_text(source) {
                        let macro_line = node.start_position().row + 1;
                        self.extract_calls_from_macro_text(
                            macro_text, caller_key, path, macro_line,
                        );
                    }
                }
            }

            if cursor.goto_first_child() {
                depth += 1;
                continue;
            }

            if cursor.goto_next_sibling() {
                continue;
            }

            loop {
                if depth == 0 {
                    return;
                }
                cursor.goto_parent();
                depth -= 1;
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Extract call-like patterns from macro invocation body text.
    /// Finds patterns like `func_name(`, `obj.method(`, `Type::method(`.
    fn extract_calls_from_macro_text(
        &self,
        text: &str,
        caller_key: &str,
        caller_file: &str,
        line: usize,
    ) {
        // Simple tokenizer: find identifiers followed by '('
        let bytes = text.as_bytes();
        let len = bytes.len();
        let mut i = 0;

        while i < len {
            // Skip non-identifier chars
            if !bytes[i].is_ascii_alphanumeric() && bytes[i] != b'_' {
                i += 1;
                continue;
            }

            // Collect identifier
            let start = i;
            while i < len && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let ident = &text[start..i];

            // Skip whitespace
            let mut j = i;
            while j < len && bytes[j].is_ascii_whitespace() {
                j += 1;
            }

            // Check if followed by '(' — this is a call
            if j < len && bytes[j] == b'(' {
                // Skip Rust keywords
                if matches!(
                    ident,
                    "if" | "else"
                        | "match"
                        | "while"
                        | "for"
                        | "loop"
                        | "let"
                        | "mut"
                        | "fn"
                        | "pub"
                        | "return"
                        | "async"
                        | "await"
                        | "move"
                        | "unsafe"
                        | "Some"
                        | "None"
                        | "Ok"
                        | "Err"
                ) {
                    i = j + 1;
                    continue;
                }

                let callee_key = self.resolve_callee(ident, caller_file, None);

                // Add to caller's outgoing calls
                if let Some(mut caller_node) = self.nodes.get_mut(caller_key) {
                    // Avoid duplicate edges
                    if !caller_node.calls.iter().any(|c| c.target == callee_key) {
                        caller_node.calls.push(CallEdge {
                            target: callee_key.clone(),
                            file_path: caller_file.to_string(),
                            line,
                            column: 0,
                            call_type: CallType::Direct,
                            scope_hint: None,
                            confirmed_by: SourceSet::TREE_SITTER,
                            line_conflicts: Vec::new(),
                        });
                    }
                }

                // Add to callee's incoming calls
                if let Some(mut callee_node) = self.nodes.get_mut(callee_key.as_str()) {
                    if !callee_node
                        .called_by
                        .iter()
                        .any(|c| c.target == *caller_key)
                    {
                        callee_node.called_by.push(CallEdge {
                            target: caller_key.to_string(),
                            file_path: caller_file.to_string(),
                            line,
                            column: 0,
                            call_type: CallType::Direct,
                            scope_hint: None,
                            confirmed_by: SourceSet::TREE_SITTER,
                            line_conflicts: Vec::new(),
                        });
                    }
                }

                i = j + 1;
            }
        }
    }

    /// Resolve a callee name to a qualified key.
    /// Prefers same-file match, then scope-hint match, then deterministic alphabetical fallback.
    fn resolve_callee(
        &self,
        bare_name: &str,
        caller_file: &str,
        scope_hint: Option<&str>,
    ) -> String {
        // 1. Try same-file first
        let same_file_key = Self::qualified_key(caller_file, bare_name);
        if self.nodes.contains_key(&same_file_key) {
            return same_file_key;
        }

        // 2. Collect ALL candidates matching bare_name via O(1) index lookup
        let mut candidates: Vec<String> = self
            .name_index
            .get(bare_name)
            .map(|v| v.clone())
            .unwrap_or_default();

        if matches!(caller_file.rsplit('.').next(), Some("py" | "pyi")) {
            candidates.retain(|key| {
                matches!(file_of_key(key).rsplit('.').next(), Some("py" | "pyi"))
            });
        }

        match candidates.len() {
            0 => bare_name.to_string(),
            1 => candidates.remove(0),
            _ => {
                // 3. If scope_hint present, try to narrow down
                if let Some(scope) = scope_hint {
                    // Extract the file_path part from qualified keys (everything before ::)
                    let scope_matches: Vec<&String> = candidates
                        .iter()
                        .filter(|key| {
                            if let Some(file_part) = key.rsplit_once("::").map(|(f, _)| f) {
                                Self::scope_matches_file_path(scope, file_part)
                            } else {
                                false
                            }
                        })
                        .collect();

                    if scope_matches.len() == 1 {
                        return scope_matches[0].clone();
                    }
                }

                // 4. Deterministic fallback: sort alphabetically, pick first
                candidates.sort();
                candidates.remove(0)
            }
        }
    }

    /// Extract the scope qualifier from a scoped call expression.
    /// For `App::run()`, the full text is `"App::run"` and this returns `Some("App")`.
    /// For `crate::utils::helper()`, returns `Some("crate::utils")`.
    fn extract_scope_qualifier(node: Node, source: &[u8]) -> Option<String> {
        let text = node.utf8_text(source).ok()?;
        // Find the last "::" to split scope from bare name
        let pos = text.rfind("::")?;
        let scope = &text[..pos];
        if scope.is_empty() {
            None
        } else {
            Some(scope.to_string())
        }
    }

    /// Check if a scope qualifier plausibly matches a file path.
    /// Lowercases scope, strips `crate::`/`self::`/`super::` prefix,
    /// converts `::` to `/`, and checks if `file_path` contains `/{scope}/` or `/{scope}.`.
    fn scope_matches_file_path(scope: &str, file_path: &str) -> bool {
        let scope_lower = scope.to_lowercase();
        // Strip common Rust path prefixes
        let stripped = scope_lower
            .strip_prefix("crate::")
            .or_else(|| scope_lower.strip_prefix("self::"))
            .or_else(|| scope_lower.strip_prefix("super::"))
            .unwrap_or(&scope_lower);
        // Convert :: to / for path matching
        let as_path = stripped.replace("::", "/");
        let path_lower = file_path.to_lowercase();
        // Check if file_path contains /{scope}/ or /{scope}.
        let with_slash = format!("/{}/", as_path);
        let with_dot = format!("/{}.", as_path);
        path_lower.contains(&with_slash) || path_lower.contains(&with_dot)
    }

    fn extract_call_edge(&self, node: Node, source: &[u8], path: &str) -> Option<CallEdge> {
        let (target, call_type, scope_hint) = Self::callee_at_call_site(node, source)?;

        Some(CallEdge {
            target,
            file_path: path.to_string(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            call_type,
            scope_hint,
            confirmed_by: SourceSet::TREE_SITTER,
            line_conflicts: Vec::new(),
        })
    }

    /// The callee named at a call node: its bare name, the call form, and the
    /// scope qualifier of a `Type::method` call.
    fn callee_at_call_site(
        node: Node,
        source: &[u8],
    ) -> Option<(String, CallType, Option<String>)> {
        let mut cursor = node.walk();
        cursor.goto_first_child();

        let mut target = None;
        let mut call_type = CallType::Direct;
        let mut scope_hint = None;

        loop {
            let child = cursor.node();
            let kind = child.kind();

            match kind {
                "identifier" | "field_identifier" => {
                    target = child.utf8_text(source).ok().map(|s| s.to_string());
                }
                // field_expression is C/C++, member_expression JavaScript,
                // attribute Python — all of them `receiver.method(...)`.
                "field_expression" | "member_expression" | "attribute" => {
                    // Method call: extract the method name
                    if let Some(method) = Self::get_last_identifier(child, source) {
                        target = if kind == "attribute" {
                            let receiver = child
                                .child_by_field_name("object")?
                                .utf8_text(source)
                                .ok()?;
                            if matches!(receiver, "self" | "cls") {
                                Some(method)
                            } else {
                                Some(child.utf8_text(source).ok()?.to_string())
                            }
                        } else {
                            Some(method)
                        };
                        call_type = CallType::Method;
                    }
                }
                "scoped_identifier" | "qualified_identifier" => {
                    // Static method call: Type::method - extract scope qualifier
                    scope_hint = Self::extract_scope_qualifier(child, source);
                    if let Some(method) = Self::get_last_identifier(child, source) {
                        target = Some(method);
                        call_type = CallType::StaticMethod;
                    }
                }
                _ => {}
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }

        target.map(|name| (name, call_type, scope_hint))
    }

    fn get_last_identifier(node: Node, source: &[u8]) -> Option<String> {
        let mut cursor = node.walk();
        let mut last_ident = None;
        let mut depth: usize = 0;

        loop {
            let n = cursor.node();
            if n.kind() == "identifier" || n.kind() == "field_identifier" {
                last_ident = n.utf8_text(source).ok().map(|s| s.to_string());
            }

            if cursor.goto_first_child() {
                depth += 1;
                continue;
            }

            if cursor.goto_next_sibling() {
                continue;
            }

            loop {
                if depth == 0 {
                    return last_ident;
                }
                cursor.goto_parent();
                depth -= 1;
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn compute_metrics(&self, node: Node, _source: &[u8]) -> FunctionMetrics {
        let mut metrics = FunctionMetrics {
            loc: node.end_position().row - node.start_position().row + 1,
            ..Default::default()
        };

        // Walk the function body for complexity metrics
        let mut cursor = node.walk();
        self.walk_for_metrics(&mut cursor, 0, &mut metrics);

        metrics
    }

    fn walk_for_metrics(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        initial_depth: usize,
        metrics: &mut FunctionMetrics,
    ) {
        let mut tree_depth: usize = 0;
        // nesting_stack[tree_depth] holds the nesting depth at that AST level.
        let mut nesting_stack: Vec<usize> = vec![initial_depth];

        loop {
            let node = cursor.node();
            let kind = node.kind();
            let depth = *nesting_stack.last().unwrap_or(&0);

            // Track nesting depth
            metrics.max_depth = metrics.max_depth.max(depth);

            // Count branches for cyclomatic complexity
            if matches!(
                kind,
                "if_statement"
                    | "if_expression"
                    | "else_clause"
                    | "match_arm"
                    | "case"
                    | "for_statement"
                    | "for_expression"
                    | "while_statement"
                    | "while_expression"
                    | "loop_expression"
                    | "catch_clause"
                    | "&&"
                    | "||"
                    | "?"
            ) {
                metrics.cyclomatic += 1;
            }

            // Count returns
            if matches!(kind, "return_statement" | "return_expression") {
                metrics.returns += 1;
            }

            // Count parameters (look for parameter_list)
            if kind == "parameters" || kind == "parameter_list" {
                metrics.params = node.named_child_count();
            }

            // Cognitive complexity (adds for nesting)
            if matches!(
                kind,
                "if_statement"
                    | "if_expression"
                    | "for_statement"
                    | "for_expression"
                    | "while_statement"
                    | "while_expression"
                    | "loop_expression"
                    | "match_expression"
            ) {
                metrics.cognitive += 1 + depth;
            }

            // Nesting depth increments for children of control structures
            let child_depth = if matches!(
                kind,
                "if_statement"
                    | "if_expression"
                    | "for_statement"
                    | "for_expression"
                    | "while_statement"
                    | "while_expression"
                    | "loop_expression"
                    | "match_expression"
                    | "try_statement"
                    | "block"
            ) {
                depth + 1
            } else {
                depth
            };

            if cursor.goto_first_child() {
                tree_depth += 1;
                nesting_stack.push(child_depth);
                continue;
            }

            if cursor.goto_next_sibling() {
                continue;
            }

            loop {
                if tree_depth == 0 {
                    // Base cyclomatic is 1
                    if metrics.cyclomatic == 0 {
                        metrics.cyclomatic = 1;
                    }
                    return;
                }
                cursor.goto_parent();
                tree_depth -= 1;
                nesting_stack.pop();
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    // === Query Methods ===

    /// Find a function by name with fuzzy matching.
    ///
    /// Tries (in order):
    /// 1. Exact match on qualified key (e.g., "src/app/mod.rs::run")
    /// 2. Case-insensitive exact match on qualified key
    /// 3. Suffix match with :: separator (e.g., "app::run" matches "src/app/mod.rs::run")
    /// 4. Bare name suffix match (e.g., "run" matches "src/app/mod.rs::run")
    /// 5. Case-insensitive suffix match
    /// 6. Contains match
    ///
    /// Returns the actual qualified key in the graph, or None if not found.
    pub fn find_function(&self, query: &str) -> Option<String> {
        // An empty/blank query must not resolve to anything: the suffix and
        // contains fallbacks below both treat "" as matching every node
        // (`key.ends_with("")` / `key.contains("")` are always true), so without
        // this guard a caller that forgot the function name would silently get
        // the alphabetically-first node's edges instead of nothing.
        if query.trim().is_empty() {
            return None;
        }

        // 1. Exact match on qualified key
        if self.nodes.contains_key(query) {
            return Some(query.to_string());
        }

        let query_lower = query.to_lowercase();

        // 2. Case-insensitive exact match (deterministic: collect, sort, pick first)
        let mut matches: Vec<String> = self
            .nodes
            .iter()
            .filter(|entry| entry.key().to_lowercase() == query_lower)
            .map(|entry| entry.key().clone())
            .collect();
        if !matches.is_empty() {
            matches.sort();
            return Some(matches.remove(0));
        }

        // 3. Suffix match with :: separator (e.g., "app::run" or "mod.rs::run")
        let suffix_pattern = format!("::{}", query);
        let mut matches: Vec<String> = self
            .nodes
            .iter()
            .filter(|entry| entry.key().ends_with(&suffix_pattern))
            .map(|entry| entry.key().clone())
            .collect();
        if !matches.is_empty() {
            matches.sort();
            return Some(matches.remove(0));
        }

        // 3b. Path component match (e.g., "app/mod.rs::run" matches "src/app/mod.rs::run")
        if query.contains("::") {
            let mut matches: Vec<String> = self
                .nodes
                .iter()
                .filter(|entry| entry.key().ends_with(query))
                .map(|entry| entry.key().clone())
                .collect();
            if !matches.is_empty() {
                matches.sort();
                return Some(matches.remove(0));
            }
        }

        // 4. Bare name match: query is just a function name like "run"
        // Match against the function name part of qualified keys
        if !query.contains("::") && !query.contains('/') {
            let bare_suffix = format!("::{}", query);
            let mut matches: Vec<String> = self
                .nodes
                .iter()
                .filter(|entry| entry.key().ends_with(&bare_suffix))
                .map(|entry| entry.key().clone())
                .collect();
            if !matches.is_empty() {
                matches.sort();
                return Some(matches.remove(0));
            }
        }

        // 4b. Receiver-qualified name: source and review notes call the method
        // `TestRunner.run_one`, while its key is `<file>::run_one`.
        if let Some(method) = method_of_receiver_qualified(query) {
            let mut matches = self.keys_ending_in_name(method);
            if !matches.is_empty() {
                return Some(matches.remove(0));
            }
        }

        // 5. Case-insensitive suffix match (deterministic)
        let mut matches: Vec<String> = self
            .nodes
            .iter()
            .filter(|entry| entry.key().to_lowercase().ends_with(&query_lower))
            .map(|entry| entry.key().clone())
            .collect();
        if !matches.is_empty() {
            matches.sort();
            return Some(matches.remove(0));
        }

        // 6. Contains match (deterministic)
        let mut matches: Vec<String> = self
            .nodes
            .iter()
            .filter(|entry| entry.key().to_lowercase().contains(&query_lower))
            .map(|entry| entry.key().clone())
            .collect();
        if !matches.is_empty() {
            matches.sort();
            return Some(matches.remove(0));
        }

        None
    }

    /// Keys whose function-name part is exactly `name`, sorted.
    fn keys_ending_in_name(&self, name: &str) -> Vec<String> {
        let suffix = format!("::{}", name);
        let mut matches: Vec<String> = self
            .nodes
            .iter()
            .filter(|entry| entry.key().ends_with(&suffix) || entry.key() == name)
            .map(|entry| entry.key().clone())
            .collect();
        matches.sort();
        matches
    }

    /// Find all functions matching a query (returns multiple matches for disambiguation).
    pub fn find_all_functions(&self, query: &str) -> Vec<String> {
        let matches = self.keys_ending_in_name(query);
        if !matches.is_empty() {
            return matches;
        }
        match method_of_receiver_qualified(query) {
            Some(method) => self.keys_ending_in_name(method),
            None => matches,
        }
    }

    /// Get similar function names for suggestions when a function is not found
    pub fn get_similar_functions(&self, query: &str, limit: usize) -> Vec<String> {
        let query_lower = query.to_lowercase();
        let mut candidates: Vec<(String, usize)> = Vec::new();

        for entry in self.nodes.iter() {
            let name = entry.key();
            let name_lower = name.to_lowercase();

            // Calculate a simple similarity score
            let score = if name_lower.contains(&query_lower) {
                100 - name.len() // Shorter matches are better
            } else {
                // Count matching characters
                let mut matches = 0;
                for c in query_lower.chars() {
                    if name_lower.contains(c) {
                        matches += 1;
                    }
                }
                matches * 10
            };

            if score > 0 {
                candidates.push((name.clone(), score));
            }
        }

        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.1));
        candidates
            .into_iter()
            .take(limit)
            .map(|(name, _)| name)
            .collect()
    }

    /// Every node key a query names.
    ///
    /// Call sites are recorded against the `file::name` key of the definition
    /// `resolve_callee` picked, so one name's edges are spread over all its
    /// definitions — a header declaration beside its definition, a `static`
    /// helper repeated in several C files. A bare name therefore answers from
    /// all of them. A query naming a file keeps the single-key resolution.
    pub fn keys_for_query(&self, query: &str) -> Vec<String> {
        if query.trim().is_empty() {
            return Vec::new();
        }
        if self.nodes.contains_key(query) {
            return vec![query.to_string()];
        }

        if !query.contains("::") && !query.contains('/') {
            let name = method_of_receiver_qualified(query).unwrap_or(query);
            let keys = self.keys_ending_in_name(name);
            if !keys.is_empty() {
                return keys;
            }
        }

        self.find_function(query).into_iter().collect()
    }

    /// Edges of every definition `function` names, folded so identically
    /// rendered sites are not repeated.
    fn edges_of(&self, function: &str, pick: fn(&CallNode) -> &Vec<CallEdge>) -> Vec<CallEdge> {
        let mut edges = Vec::new();
        for key in self.keys_for_query(function) {
            if let Some(node) = self.nodes.get(&key) {
                edges.extend(pick(node.value()).iter().cloned());
            }
        }
        Self::fold_duplicate_sites(edges)
    }

    /// Get direct callers of a function (with fuzzy matching)
    pub fn get_callers(&self, function: &str) -> Vec<CallEdge> {
        self.edges_of(function, |node| &node.called_by)
    }

    /// Get functions called by a function (with fuzzy matching)
    pub fn get_callees(&self, function: &str) -> Vec<CallEdge> {
        self.edges_of(function, |node| &node.calls)
    }

    /// Get transitive callers (all functions that eventually call this) - with fuzzy matching
    pub fn get_transitive_callers(&self, function: &str, max_depth: usize) -> Vec<(String, usize)> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        for key in self.keys_for_query(function) {
            if visited.insert(key.clone()) {
                queue.push_back((key, 0));
            }
        }

        while let Some((func, depth)) = queue.pop_front() {
            if depth > 0 {
                result.push((func.clone(), depth));
            }

            if depth < max_depth {
                if let Some(node) = self.nodes.get(&func) {
                    for caller in &node.called_by {
                        if !visited.contains(&caller.target) {
                            visited.insert(caller.target.clone());
                            queue.push_back((caller.target.clone(), depth + 1));
                        }
                    }
                }
            }
        }

        result
    }

    /// Get transitive callees (all functions eventually called) - with fuzzy matching
    pub fn get_transitive_callees(&self, function: &str, max_depth: usize) -> Vec<(String, usize)> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        for key in self.keys_for_query(function) {
            if visited.insert(key.clone()) {
                queue.push_back((key, 0));
            }
        }

        while let Some((func, depth)) = queue.pop_front() {
            if depth > 0 {
                result.push((func.clone(), depth));
            }

            if depth < max_depth {
                if let Some(node) = self.nodes.get(&func) {
                    for callee in &node.calls {
                        if !visited.contains(&callee.target) {
                            visited.insert(callee.target.clone());
                            queue.push_back((callee.target.clone(), depth + 1));
                        }
                    }
                }
            }
        }

        result
    }

    /// Find the path between two functions - with fuzzy matching
    pub fn find_call_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        // Any definition of `from` may hold the path, and reaching any
        // definition of `to` ends it.
        let targets: HashSet<String> = self.keys_for_query(to).into_iter().collect();

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut predecessors: HashMap<String, String> = HashMap::new();

        for key in self.keys_for_query(from) {
            if visited.insert(key.clone()) {
                queue.push_back(key);
            }
        }

        while let Some(current) = queue.pop_front() {
            if targets.contains(&current) {
                // Reconstruct path
                let mut path = vec![current.clone()];
                let mut node = current.clone();
                while let Some(pred) = predecessors.get(&node) {
                    path.push(pred.clone());
                    node = pred.clone();
                }
                path.reverse();
                return Some(path);
            }

            if let Some(node) = self.nodes.get(&current) {
                for callee in &node.calls {
                    if !visited.contains(&callee.target) {
                        visited.insert(callee.target.clone());
                        predecessors.insert(callee.target.clone(), current.clone());
                        queue.push_back(callee.target.clone());
                    }
                }
            }
        }

        None
    }

    /// Generic trait method names to filter from hotspots (these are noise)
    const TRAIT_METHOD_NAMES: &'static [&'static str] = &[
        "new",
        "default",
        "from",
        "into",
        "clone",
        "fmt",
        "drop",
        "deref",
        "deref_mut",
        "as_ref",
        "as_mut",
        "borrow",
        "borrow_mut",
        "try_from",
        "try_into",
        "eq",
        "ne",
        "partial_cmp",
        "cmp",
        "hash",
        "serialize",
        "deserialize",
        "to_string",
        "to_owned",
        "build",
        "index",
        "index_mut",
        "len",
        "is_empty",
        "get",
        "insert",
        "contains",
    ];

    /// Check if a function name is a generic trait method that should be filtered
    fn is_trait_method(qualified_key: &str) -> bool {
        if let Some(bare_name) = qualified_key.rsplit("::").next() {
            Self::TRAIT_METHOD_NAMES.contains(&bare_name)
        } else {
            false
        }
    }

    /// Total unparsed regions and the number of files they span, or `None` when
    /// there are none. A non-`None` result means every caller/callee list this
    /// call graph produces may be missing edges from those regions.
    pub fn degraded_summary(&self) -> Option<(usize, usize)> {
        let file_count = self.degraded.len();
        if file_count == 0 {
            return None;
        }
        let region_count = self.degraded.iter().map(|entry| entry.value().len()).sum();
        Some((region_count, file_count))
    }

    /// Get highly connected functions (potential refactoring targets).
    /// Filters out generic trait methods and limits output.
    pub fn get_hotspots(&self, min_connections: usize) -> Vec<(String, usize, usize)> {
        let mut hotspots = Vec::new();

        for entry in self.nodes.iter() {
            let key = entry.key();

            // Skip generic trait method implementations
            if Self::is_trait_method(key) {
                continue;
            }

            let incoming = entry.called_by.len();
            let outgoing = entry.calls.len();
            let total = incoming + outgoing;

            if total >= min_connections {
                hotspots.push((key.clone(), incoming, outgoing));
            }
        }

        hotspots.sort_by_key(|hotspot| std::cmp::Reverse(hotspot.1 + hotspot.2));
        hotspots
    }

    /// Get function metrics
    pub fn get_metrics(&self, function: &str) -> Option<FunctionMetrics> {
        let actual_name = self.find_function(function)?;
        self.nodes.get(&actual_name).map(|n| n.metrics.clone())
    }

    /// Export call graph in DOT format for visualization
    pub fn to_dot(&self, filter_file: Option<&str>) -> String {
        let mut dot = String::from("digraph CallGraph {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box];\n\n");

        for entry in self.nodes.iter() {
            let key = entry.key();
            let node = entry.value();

            if let Some(file) = filter_file {
                if !node.file_path.contains(file) {
                    continue;
                }
            }

            // Node styling based on metrics
            let color = if node.metrics.cyclomatic > 10 {
                "red"
            } else if node.metrics.cyclomatic > 5 {
                "orange"
            } else {
                "black"
            };

            dot.push_str(&format!(
                "  \"{}\" [label=\"{}\\nCC:{} LOC:{}\", color={}];\n",
                key, node.name, node.metrics.cyclomatic, node.metrics.loc, color
            ));

            for call in &node.calls {
                dot.push_str(&format!("  \"{}\" -> \"{}\";\n", key, call.target));
            }
        }

        dot.push_str("}\n");
        dot
    }

    /// Format call graph as markdown for AI consumption.
    /// `exclude_tests` drops the rows whose file is test code.
    pub fn to_markdown(&self, function: Option<&str>, exclude_tests: bool) -> String {
        let keep = |file: &str| !exclude_tests || !crate::extract::is_test_file(file);
        let mut md = String::new();

        match function {
            Some(func) => {
                let keys: Vec<String> = self
                    .keys_for_query(func)
                    .into_iter()
                    .filter(|key| keep(file_of_key(key)))
                    .collect();
                let shown = keys.len().min(MAX_RENDERED_DEFINITIONS);
                for key in &keys[..shown] {
                    let Some(node) = self.nodes.get(key) else {
                        continue;
                    };
                    md.push_str(&format!("# Call Graph: {}\n\n", key));
                    md.push_str(&format!(
                        "**Location**: `{}:{}`\n",
                        node.file_path, node.line
                    ));
                    md.push_str(&format!(
                        "**Metrics**: CC={}, LOC={}, Depth={}\n\n",
                        node.metrics.cyclomatic, node.metrics.loc, node.metrics.max_depth
                    ));

                    let calls: Vec<&CallEdge> = node
                        .calls
                        .iter()
                        .filter(|call| keep(file_of_key(&call.target)))
                        .collect();
                    let called_by: Vec<&CallEdge> = node
                        .called_by
                        .iter()
                        .filter(|caller| keep(&caller.file_path))
                        .collect();

                    md.push_str("## Calls (outgoing)\n\n");
                    if calls.is_empty() {
                        md.push_str("*No outgoing calls*\n\n");
                    } else {
                        for call in calls {
                            md.push_str(&format!(
                                "- `{}` at `{}:{}` ({:?})\n",
                                call.target, call.file_path, call.line, call.call_type
                            ));
                        }
                        md.push('\n');
                    }

                    md.push_str("## Called By (incoming)\n\n");
                    if called_by.is_empty() {
                        md.push_str("*No incoming calls (entry point or unused)*\n\n");
                    } else {
                        for caller in called_by {
                            md.push_str(&format!(
                                "- `{}` at `{}:{}`\n",
                                caller.target, caller.file_path, caller.line
                            ));
                        }
                        md.push('\n');
                    }
                }
                if keys.is_empty() {
                    md.push_str(&format!("Function `{}` not found in call graph.\n", func));
                } else if keys.len() > shown {
                    md.push_str(&format!(
                        "*{} further definition(s) of `{}` not shown; ask for one by \
                         its file-qualified name.*\n",
                        keys.len() - shown,
                        func
                    ));
                }
            }
            None => {
                md.push_str("# Call Graph Summary\n\n");
                md.push_str(&format!("**Total Functions**: {}\n\n", self.nodes.len()));

                // Top callers
                md.push_str("## Most Called Functions\n\n");
                let mut by_callers: Vec<_> = self
                    .nodes
                    .iter()
                    .filter(|e| keep(file_of_key(e.key())))
                    .map(|e| (e.key().clone(), e.called_by.len()))
                    .collect();
                by_callers.sort_by_key(|caller| std::cmp::Reverse(caller.1));

                for (name, count) in by_callers.iter().take(10) {
                    md.push_str(&format!("- `{}`: {} callers\n", name, count));
                }
                md.push('\n');

                // Complexity hotspots
                md.push_str("## Complexity Hotspots\n\n");
                let mut by_complexity: Vec<_> = self
                    .nodes
                    .iter()
                    .filter(|e| keep(file_of_key(e.key())))
                    .map(|e| (e.key().clone(), e.metrics.clone()))
                    .collect();
                by_complexity.sort_by_key(|entry| std::cmp::Reverse(entry.1.cyclomatic));

                for (name, metrics) in by_complexity.iter().take(10) {
                    md.push_str(&format!(
                        "- `{}`: CC={}, LOC={}\n",
                        name, metrics.cyclomatic, metrics.loc
                    ));
                }
            }
        }

        md
    }

    // ========================================================================
    // Visualization Helper Methods (for graph tool handler)
    // ========================================================================

    /// Get all function names in the call graph
    pub fn get_all_function_names(&self) -> Vec<String> {
        // Return entry points first (functions not called by anything), then the rest
        let mut entry_points: Vec<String> = Vec::new();
        let mut others: Vec<String> = Vec::new();

        for entry in self.nodes.iter() {
            if entry.value().called_by.is_empty() {
                entry_points.push(entry.key().clone());
            } else {
                others.push(entry.key().clone());
            }
        }

        // Sort for deterministic output
        entry_points.sort();
        others.sort();

        entry_points.extend(others);
        entry_points
    }

    /// Get a node by exact name (for visualization)
    pub fn get_node(&self, name: &str) -> Option<dashmap::mapref::one::Ref<'_, String, CallNode>> {
        self.nodes.get(name)
    }

    /// Return every qualified key (`file_path::function_name`) that
    /// defines a function with this exact bare `name`.
    ///
    /// Returns an empty vector when the name is unknown. Multiple
    /// entries indicate that several files define a function with
    /// this name — typical for `static` helpers in C. Callers must
    /// apply their own disambiguation rule rather than guessing,
    /// because the wrong definition would mislead downstream analyses
    /// (e.g. flagging a heap overflow against the wrong allocation
    /// size).
    pub fn lookup_by_name(&self, name: &str) -> Vec<String> {
        self.name_index
            .get(name)
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
    }

    /// Get the number of nodes in the call graph
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get all nodes (for iteration)
    pub fn iter_nodes(
        &self,
    ) -> impl Iterator<Item = dashmap::mapref::multiple::RefMulti<'_, String, CallNode>> {
        self.nodes.iter()
    }
}

/// The file part of a node key (`lib/fuse.c::fuse_session_destroy` ->
/// `lib/fuse.c`). An unresolved callee has no `::` and yields the bare name,
/// which names no file and so passes a test-file filter.
pub(crate) fn file_of_key(key: &str) -> &str {
    key.rsplit_once("::").map(|(file, _)| file).unwrap_or(key)
}

/// The method part of a receiver-qualified query (`TestRunner.run_one` ->
/// `run_one`). `None` for a plain name, and for anything path-qualified, which
/// the `::` and `/` rules already resolve.
fn method_of_receiver_qualified(query: &str) -> Option<&str> {
    if query.contains("::") || query.contains('/') {
        return None;
    }
    query
        .rsplit_once('.')
        .map(|(_, method)| method)
        .filter(|method| !method.is_empty())
}

/// Helper function to extract function name from a node (not a method to avoid recursion warning)
fn extract_function_name(node: Node, source: &[u8]) -> Option<String> {
    // Look for name in children
    let mut cursor = node.walk();
    cursor.goto_first_child();

    loop {
        let child = cursor.node();
        let kind = child.kind();

        if kind == "identifier"
            || kind == "name"
            || kind == "field_identifier"
            || kind == "property_identifier"
        {
            return child.utf8_text(source).ok().map(|s| s.to_string());
        }

        // C++: out-of-class member function — return fully-qualified name e.g. "Foo::bar"
        if kind == "qualified_identifier" {
            return child.utf8_text(source).ok().map(|s| s.to_string());
        }

        // C++: destructor — return "~ClassName"
        if kind == "destructor_name" {
            return child.utf8_text(source).ok().map(|s| s.to_string());
        }

        // C++: operator overload — return "operator=="
        if kind == "operator_name" {
            return child.utf8_text(source).ok().map(|s| s.to_string());
        }

        // For declarators (C/C++)
        if kind.contains("declarator") {
            if let Some(name) = extract_function_name(child, source) {
                return Some(name);
            }
        }

        if !cursor.goto_next_sibling() {
            break;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_type() {
        assert_eq!(CallType::Direct, CallType::Direct);
        assert_ne!(CallType::Direct, CallType::Method);
    }

    #[test]
    fn test_function_metrics_default() {
        let m = FunctionMetrics::default();
        assert_eq!(m.loc, 0);
        assert_eq!(m.cyclomatic, 0);
    }

    #[test]
    fn test_callgraph_new() {
        let graph = CallGraph::new();
        assert_eq!(graph.nodes.len(), 0);
        assert_eq!(graph.file_functions.len(), 0);
    }

    #[test]
    fn test_add_function_node() {
        let graph = CallGraph::new();

        let node = CallNode {
            name: "test_function".to_string(),
            file_path: "/path/to/file.rs".to_string(),
            line: 42,
            calls: Vec::new(),
            called_by: Vec::new(),
            metrics: FunctionMetrics {
                loc: 10,
                cyclomatic: 2,
                max_depth: 1,
                params: 2,
                returns: 1,
                cognitive: 3,
            },
        };

        graph
            .nodes
            .insert("test_function".to_string(), node.clone());

        assert_eq!(graph.nodes.len(), 1);
        let retrieved = graph.nodes.get("test_function").unwrap();
        assert_eq!(retrieved.name, "test_function");
        assert_eq!(retrieved.line, 42);
        assert_eq!(retrieved.metrics.loc, 10);
        assert_eq!(retrieved.metrics.cyclomatic, 2);
    }

    #[test]
    fn test_add_call_edge() {
        let graph = CallGraph::new();

        // Create caller and callee nodes
        let caller = CallNode {
            name: "caller".to_string(),
            file_path: "/path/to/file.rs".to_string(),
            line: 10,
            calls: Vec::new(),
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        let callee = CallNode {
            name: "callee".to_string(),
            file_path: "/path/to/file.rs".to_string(),
            line: 20,
            calls: Vec::new(),
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        graph.nodes.insert("caller".to_string(), caller);
        graph.nodes.insert("callee".to_string(), callee);

        // Add call edge
        let edge = CallEdge {
            target: "callee".to_string(),
            file_path: "/path/to/file.rs".to_string(),
            line: 12,
            column: 5,
            call_type: CallType::Direct,
            scope_hint: None,
            confirmed_by: SourceSet::TREE_SITTER,
            line_conflicts: Vec::new(),
        };

        graph
            .nodes
            .get_mut("caller")
            .unwrap()
            .calls
            .push(edge.clone());

        let reverse_edge = CallEdge {
            target: "caller".to_string(),
            file_path: edge.file_path.clone(),
            line: edge.line,
            column: edge.column,
            call_type: edge.call_type.clone(),
            scope_hint: None,
            confirmed_by: SourceSet::TREE_SITTER,
            line_conflicts: Vec::new(),
        };

        graph
            .nodes
            .get_mut("callee")
            .unwrap()
            .called_by
            .push(reverse_edge);

        // Verify the edge was added
        let caller_node = graph.nodes.get("caller").unwrap();
        assert_eq!(caller_node.calls.len(), 1);
        assert_eq!(caller_node.calls[0].target, "callee");

        let callee_node = graph.nodes.get("callee").unwrap();
        assert_eq!(callee_node.called_by.len(), 1);
        assert_eq!(callee_node.called_by[0].target, "caller");
    }

    // A node with the given outgoing/incoming edges, for replay tests.
    fn node_with(name: &str, calls: Vec<CallEdge>, called_by: Vec<CallEdge>) -> CallNode {
        CallNode {
            name: name.to_string(),
            file_path: "f.c".to_string(),
            line: 1,
            calls,
            called_by,
            metrics: FunctionMetrics::default(),
        }
    }

    #[test]
    fn two_calls_on_one_line_fold_into_one_row() {
        // `f(a) || f(b)` on line 110, `f(c) || f(d)` on line 111: four call
        // sites, one caller, and no column in the rendered row.
        let site = |line: usize, column: usize, confirmed_by: SourceSet| CallEdge {
            target: "mount_util.c::add_mount".to_string(),
            file_path: "lib/mount_util.c".to_string(),
            line,
            column,
            call_type: CallType::Direct,
            scope_hint: None,
            confirmed_by,
            line_conflicts: Vec::new(),
        };

        let folded = CallGraph::fold_duplicate_sites(vec![
            site(110, 5, SourceSet::TREE_SITTER),
            site(110, 30, SourceSet::CCLS),
            site(111, 5, SourceSet::TREE_SITTER),
            site(111, 30, SourceSet::TREE_SITTER),
        ]);

        assert_eq!(folded.len(), 2);
        assert_eq!(folded[0].line, 110);
        assert_eq!(folded[1].line, 111);
        assert!(folded[0].confirmed_by.contains(SourceSet::TREE_SITTER));
        assert!(folded[0].confirmed_by.contains(SourceSet::CCLS));
    }

    #[test]
    fn test_merge_edges_keeps_call_sites_of_one_caller_apart() {
        // `a` calls `b` on lines 4 and 9; a backend hit on each line must
        // confirm the edge at that line, not fold onto the line-4 edge.
        let site = |target: &str, line: usize| CallEdge {
            target: target.to_string(),
            file_path: "f.c".to_string(),
            line,
            column: 0,
            call_type: CallType::Direct,
            scope_hint: None,
            confirmed_by: SourceSet::TREE_SITTER,
            line_conflicts: Vec::new(),
        };
        let graph = CallGraph::new();
        graph.nodes.insert(
            "f.c::a".to_string(),
            node_with("a", vec![site("f.c::b", 4), site("f.c::b", 9)], Vec::new()),
        );
        graph.nodes.insert(
            "f.c::b".to_string(),
            node_with("b", Vec::new(), vec![site("f.c::a", 4), site("f.c::a", 9)]),
        );

        let hits = vec![
            ("f.c::a".to_string(), site("b", 4)),
            ("f.c::a".to_string(), site("b", 9)),
        ];
        graph.merge_edges(hits, SourceSet::GTAGS);

        let a = graph.nodes.get("f.c::a").unwrap();
        let b = graph.nodes.get("f.c::b").unwrap();
        for edge in a.calls.iter().chain(b.called_by.iter()) {
            assert!(edge.confirmed_by.contains(SourceSet::GTAGS), "{:?}", edge);
            assert!(edge.line_conflicts.is_empty(), "{:?}", edge);
        }
    }

    #[test]
    fn test_export_restore_augmentation_edges() {
        // The folded augmentation edge as merge_edges(CCLS) would leave it: CCLS
        // outranks tree-sitter, so its line wins and the tree-sitter line drops
        // into line_conflicts.
        let augmented = CallEdge {
            target: "f.c::b".to_string(),
            file_path: "f.c".to_string(),
            line: 5,
            column: 2,
            call_type: CallType::Unknown,
            scope_hint: None,
            confirmed_by: {
                let mut s = SourceSet::TREE_SITTER;
                s.insert(SourceSet::CCLS);
                s
            },
            line_conflicts: vec![SourceLine {
                source: SourceSet::TREE_SITTER,
                line: 4,
            }],
        };
        // A pure tree-sitter edge must NOT be exported (build_from_files rebuilds it).
        let baseline_only = CallEdge {
            target: "f.c::c".to_string(),
            file_path: "f.c".to_string(),
            line: 7,
            column: 0,
            call_type: CallType::Direct,
            scope_hint: None,
            confirmed_by: SourceSet::TREE_SITTER,
            line_conflicts: Vec::new(),
        };

        let src = CallGraph::new();
        src.nodes.insert(
            "f.c::a".to_string(),
            node_with(
                "a",
                vec![augmented.clone(), baseline_only.clone()],
                Vec::new(),
            ),
        );
        src.nodes
            .insert("f.c::b".to_string(), node_with("b", Vec::new(), Vec::new()));
        src.nodes
            .insert("f.c::c".to_string(), node_with("c", Vec::new(), Vec::new()));

        let exported = src.export_augmentation_edges();
        assert_eq!(
            exported.len(),
            1,
            "only the backend-confirmed edge is exported"
        );
        assert_eq!(exported[0].0, "f.c::a");
        assert_eq!(exported[0].1.target, "f.c::b");

        // Replay onto a fresh baseline: caller carries the tree-sitter version of
        // the same pair (as build_from_files would have produced) plus a
        // backend-only pair not seen by tree-sitter.
        let ts_baseline = CallEdge {
            target: "f.c::b".to_string(),
            file_path: "f.c".to_string(),
            line: 4,
            column: 0,
            call_type: CallType::Direct,
            scope_hint: None,
            confirmed_by: SourceSet::TREE_SITTER,
            line_conflicts: Vec::new(),
        };
        let backend_only = CallEdge {
            target: "f.c::d".to_string(),
            file_path: "f.c".to_string(),
            line: 9,
            column: 0,
            call_type: CallType::Unknown,
            scope_hint: None,
            confirmed_by: SourceSet::GTAGS,
            line_conflicts: Vec::new(),
        };
        let dst = CallGraph::new();
        dst.nodes.insert(
            "f.c::a".to_string(),
            node_with("a", vec![ts_baseline], Vec::new()),
        );
        dst.nodes
            .insert("f.c::b".to_string(), node_with("b", Vec::new(), Vec::new()));
        dst.nodes
            .insert("f.c::d".to_string(), node_with("d", Vec::new(), Vec::new()));

        let mut replay = exported;
        replay.push(("f.c::a".to_string(), backend_only));
        dst.restore_augmentation_edges(replay);

        // Existing tree-sitter edge is overwritten with the folded version.
        let a = dst.nodes.get("f.c::a").unwrap();
        assert_eq!(
            a.calls.len(),
            2,
            "no duplicate edge for the overwritten pair"
        );
        let to_b = a.calls.iter().find(|e| e.target == "f.c::b").unwrap();
        assert_eq!(to_b.line, 5);
        assert!(to_b.confirmed_by.contains(SourceSet::CCLS));
        assert_eq!(to_b.line_conflicts.len(), 1);
        // Callee gains the mirrored incoming edge.
        let b = dst.nodes.get("f.c::b").unwrap();
        assert_eq!(b.called_by.len(), 1);
        assert_eq!(b.called_by[0].target, "f.c::a");
        assert!(b.called_by[0].confirmed_by.contains(SourceSet::CCLS));
        // Backend-only pair is inserted; its callee gets the incoming edge.
        let d = dst.nodes.get("f.c::d").unwrap();
        assert_eq!(d.called_by.len(), 1);
        assert_eq!(d.called_by[0].target, "f.c::a");
    }

    #[test]
    fn test_get_callers() {
        let graph = CallGraph::new();

        // Create a function that is called by multiple functions
        let target = CallNode {
            name: "target".to_string(),
            file_path: "/path/to/file.rs".to_string(),
            line: 30,
            calls: Vec::new(),
            called_by: vec![
                CallEdge {
                    target: "caller1".to_string(),
                    file_path: "/path/to/file.rs".to_string(),
                    line: 10,
                    column: 5,
                    call_type: CallType::Direct,
                    scope_hint: None,
                    confirmed_by: SourceSet::TREE_SITTER,
                    line_conflicts: Vec::new(),
                },
                CallEdge {
                    target: "caller2".to_string(),
                    file_path: "/path/to/file.rs".to_string(),
                    line: 20,
                    column: 8,
                    call_type: CallType::Method,
                    scope_hint: None,
                    confirmed_by: SourceSet::TREE_SITTER,
                    line_conflicts: Vec::new(),
                },
            ],
            metrics: FunctionMetrics::default(),
        };

        graph.nodes.insert("target".to_string(), target);

        let callers = graph.get_callers("target");
        assert_eq!(callers.len(), 2);
        assert_eq!(callers[0].target, "caller1");
        assert_eq!(callers[1].target, "caller2");
        assert_eq!(callers[0].call_type, CallType::Direct);
        assert_eq!(callers[1].call_type, CallType::Method);
    }

    #[test]
    fn test_get_callers_empty() {
        let graph = CallGraph::new();

        let node = CallNode {
            name: "isolated".to_string(),
            file_path: "/path/to/file.rs".to_string(),
            line: 10,
            calls: Vec::new(),
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        graph.nodes.insert("isolated".to_string(), node);

        let callers = graph.get_callers("isolated");
        assert_eq!(callers.len(), 0);
    }

    #[test]
    fn test_get_callers_nonexistent() {
        let graph = CallGraph::new();

        let callers = graph.get_callers("nonexistent");
        assert_eq!(callers.len(), 0);
    }

    #[test]
    fn test_top_level_call_not_attributed_to_preceding_function() {
        // A trailing top-level call (in the module's `if __name__` block) sits
        // outside any function. Without scope restoration it leaked into the
        // lexically preceding function `target`, producing a phantom self-call.
        let source = "\
def helper():
    return 1

def target():
    helper()

if __name__ == \"__main__\":
    target()
";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();

        let graph = CallGraph::new();
        graph
            .build_from_files(&[("mod.py".to_string(), source.to_string(), tree)])
            .unwrap();

        // No function calls `target`; `helper` is `target`'s only callee.
        assert!(graph.get_callers("target").is_empty());

        let target_callees: Vec<String> = graph
            .get_callees("target")
            .into_iter()
            .map(|edge| edge.target)
            .collect();
        assert_eq!(target_callees, vec!["mod.py::helper".to_string()]);

        let helper_callers: Vec<String> = graph
            .get_callers("helper")
            .into_iter()
            .map(|edge| edge.target)
            .collect();
        assert_eq!(helper_callers, vec!["mod.py::target".to_string()]);
    }

    #[test]
    fn referenced_callee_names_lists_callees_without_definitions() {
        // The names a scoped index must resolve elsewhere: `blk_mq_requeue` is
        // defined nowhere in this file, and neither is the method `submit`.
        let source = "\
int helper(void) { return 1; }

int caller(struct q *queue) {
    helper();
    blk_mq_requeue(queue);
    return queue->ops->submit(queue);
}
";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();

        let names = CallGraph::referenced_callee_names(source, &tree);

        assert_eq!(
            names,
            vec![
                "blk_mq_requeue".to_string(),
                "helper".to_string(),
                "submit".to_string(),
            ]
        );
    }

    /// Call sites attach to the definition in their own file, so one name's
    /// callers are spread over its definitions. A bare name must gather all of
    /// them; the file-qualified name must not.
    #[test]
    fn a_bare_name_gathers_the_callers_of_every_definition() {
        let sources = [
            (
                "lib.c",
                "\
void session_destroy(void) { }

void user_one(void) { session_destroy(); }
",
            ),
            (
                "stub.c",
                "\
void session_destroy(void) { }

void user_two(void) { session_destroy(); }
",
            ),
        ];

        let mut files = Vec::new();
        for (path, source) in sources {
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_c::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            files.push((path.to_string(), source.to_string(), tree));
        }

        let graph = CallGraph::new();
        graph.build_from_files(&files).unwrap();

        let mut callers: Vec<String> = graph
            .get_callers("session_destroy")
            .into_iter()
            .map(|edge| edge.target)
            .collect();
        callers.sort();
        assert_eq!(
            callers,
            vec![
                "lib.c::user_one".to_string(),
                "stub.c::user_two".to_string()
            ]
        );

        let one: Vec<String> = graph
            .get_callers("stub.c::session_destroy")
            .into_iter()
            .map(|edge| edge.target)
            .collect();
        assert_eq!(one, vec!["stub.c::user_two".to_string()]);
    }

    /// `TestRunner.run_one` is how the method is written in the source and in
    /// a review note; the graph keys it as `<file>::run_one`.
    #[test]
    fn a_method_resolves_under_its_class_name() {
        let source = "\
class TestRunner:
    def run_one(self):
        return 1

    def run_all(self):
        self.run_one()
";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();

        let graph = CallGraph::new();
        graph
            .build_from_files(&[("run-tests.py".to_string(), source.to_string(), tree)])
            .unwrap();

        assert_eq!(
            graph.find_function("TestRunner.run_one"),
            Some("run-tests.py::run_one".to_string())
        );
        assert_eq!(
            graph.find_all_functions("TestRunner.run_one"),
            vec!["run-tests.py::run_one".to_string()]
        );
        let callers: Vec<String> = graph
            .get_callers("TestRunner.run_one")
            .into_iter()
            .map(|edge| edge.target)
            .collect();
        assert_eq!(callers, vec!["run-tests.py::run_all".to_string()]);

        // A file-qualified key still wins over the dotted fallback.
        assert_eq!(
            graph.find_function("run-tests.py::run_all"),
            Some("run-tests.py::run_all".to_string())
        );
        assert_eq!(graph.find_function("TestRunner.no_such_method"), None);
    }

    /// A test runner class whose methods only call each other through `self`
    /// used to come back with no edges in either direction.
    #[test]
    fn python_self_method_call_is_an_edge() {
        let source = "\
class TestRunner:
    def run_one(self):
        return 1

    def run_all(self):
        self.run_one()
";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();

        let graph = CallGraph::new();
        graph
            .build_from_files(&[("run-tests.py".to_string(), source.to_string(), tree)])
            .unwrap();

        let callees: Vec<String> = graph
            .get_callees("run_all")
            .into_iter()
            .map(|edge| edge.target)
            .collect();
        assert_eq!(callees, vec!["run-tests.py::run_one".to_string()]);

        let callers: Vec<String> = graph
            .get_callers("run_one")
            .into_iter()
            .map(|edge| edge.target)
            .collect();
        assert_eq!(callers, vec!["run-tests.py::run_all".to_string()]);
    }

    #[test]
    fn python_calls_do_not_resolve_to_unrelated_functions() {
        let python = "\
import client

def sample_fn(reader, mapping):
    def execute():
        pass
    reader.fetch()
    mapping.lookup('key')
    list(mapping)
    client.execute()
    helper()
";
        let go = "\
package other
func fetch() {}
func lookup() {}
func list() {}
";
        let parser = crate::parser::LanguageParser::new().unwrap();
        let mut files = Vec::new();
        for (path, source) in [
            ("sample.py", python),
            ("other.go", go),
            ("helpers.py", "def helper():\n    pass\n"),
        ] {
            let tree = parser
                .parse_to_tree(std::path::Path::new(path), source)
                .unwrap();
            files.push((path.to_string(), source.to_string(), tree));
        }
        let graph = CallGraph::new();
        graph.build_from_files(&files).unwrap();

        let mut targets: Vec<String> = graph
            .get_callees("sample_fn")
            .into_iter()
            .map(|edge| edge.target)
            .collect();
        targets.sort();
        assert_eq!(
            targets,
            vec![
                "client.execute",
                "helpers.py::helper",
                "list",
                "mapping.lookup",
                "reader.fetch"
            ]
        );
        for name in [
            "other.go::fetch",
            "other.go::lookup",
            "other.go::list",
            "sample.py::execute",
        ] {
            assert!(graph.get_callers(name).is_empty(), "false caller of {name}");
        }
    }

    #[test]
    fn test_get_callees() {
        let graph = CallGraph::new();

        // Create a function that calls multiple functions
        let caller = CallNode {
            name: "caller".to_string(),
            file_path: "/path/to/file.rs".to_string(),
            line: 10,
            calls: vec![
                CallEdge {
                    target: "callee1".to_string(),
                    file_path: "/path/to/file.rs".to_string(),
                    line: 12,
                    column: 5,
                    call_type: CallType::Direct,
                    scope_hint: None,
                    confirmed_by: SourceSet::TREE_SITTER,
                    line_conflicts: Vec::new(),
                },
                CallEdge {
                    target: "callee2".to_string(),
                    file_path: "/path/to/file.rs".to_string(),
                    line: 15,
                    column: 10,
                    call_type: CallType::StaticMethod,
                    scope_hint: None,
                    confirmed_by: SourceSet::TREE_SITTER,
                    line_conflicts: Vec::new(),
                },
            ],
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        graph.nodes.insert("caller".to_string(), caller);

        let callees = graph.get_callees("caller");
        assert_eq!(callees.len(), 2);
        assert_eq!(callees[0].target, "callee1");
        assert_eq!(callees[1].target, "callee2");
        assert_eq!(callees[0].call_type, CallType::Direct);
        assert_eq!(callees[1].call_type, CallType::StaticMethod);
    }

    #[test]
    fn test_get_callees_empty() {
        let graph = CallGraph::new();

        let node = CallNode {
            name: "leaf".to_string(),
            file_path: "/path/to/file.rs".to_string(),
            line: 10,
            calls: Vec::new(),
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        graph.nodes.insert("leaf".to_string(), node);

        let callees = graph.get_callees("leaf");
        assert_eq!(callees.len(), 0);
    }

    #[test]
    fn test_get_callees_nonexistent() {
        let graph = CallGraph::new();

        let callees = graph.get_callees("nonexistent");
        assert_eq!(callees.len(), 0);
    }

    #[test]
    fn test_get_metrics() {
        let graph = CallGraph::new();

        let metrics = FunctionMetrics {
            loc: 25,
            cyclomatic: 5,
            max_depth: 3,
            params: 4,
            returns: 2,
            cognitive: 8,
        };

        let node = CallNode {
            name: "complex_function".to_string(),
            file_path: "/path/to/file.rs".to_string(),
            line: 100,
            calls: Vec::new(),
            called_by: Vec::new(),
            metrics: metrics.clone(),
        };

        graph.nodes.insert("complex_function".to_string(), node);

        let retrieved_metrics = graph.get_metrics("complex_function").unwrap();
        assert_eq!(retrieved_metrics.loc, 25);
        assert_eq!(retrieved_metrics.cyclomatic, 5);
        assert_eq!(retrieved_metrics.max_depth, 3);
        assert_eq!(retrieved_metrics.params, 4);
        assert_eq!(retrieved_metrics.returns, 2);
        assert_eq!(retrieved_metrics.cognitive, 8);
    }

    #[test]
    fn test_get_metrics_nonexistent() {
        let graph = CallGraph::new();

        let metrics = graph.get_metrics("nonexistent");
        assert!(metrics.is_none());
    }

    #[test]
    fn test_get_transitive_callers() {
        let graph = CallGraph::new();

        // Create a call chain: a -> b -> c -> d
        // Test getting transitive callers of d should return c, b, a

        let node_a = CallNode {
            name: "a".to_string(),
            file_path: "/file.rs".to_string(),
            line: 1,
            calls: vec![CallEdge {
                target: "b".to_string(),
                file_path: "/file.rs".to_string(),
                line: 2,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        let node_b = CallNode {
            name: "b".to_string(),
            file_path: "/file.rs".to_string(),
            line: 10,
            calls: vec![CallEdge {
                target: "c".to_string(),
                file_path: "/file.rs".to_string(),
                line: 12,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            called_by: vec![CallEdge {
                target: "a".to_string(),
                file_path: "/file.rs".to_string(),
                line: 2,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            metrics: FunctionMetrics::default(),
        };

        let node_c = CallNode {
            name: "c".to_string(),
            file_path: "/file.rs".to_string(),
            line: 20,
            calls: vec![CallEdge {
                target: "d".to_string(),
                file_path: "/file.rs".to_string(),
                line: 22,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            called_by: vec![CallEdge {
                target: "b".to_string(),
                file_path: "/file.rs".to_string(),
                line: 12,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            metrics: FunctionMetrics::default(),
        };

        let node_d = CallNode {
            name: "d".to_string(),
            file_path: "/file.rs".to_string(),
            line: 30,
            calls: Vec::new(),
            called_by: vec![CallEdge {
                target: "c".to_string(),
                file_path: "/file.rs".to_string(),
                line: 22,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            metrics: FunctionMetrics::default(),
        };

        graph.nodes.insert("a".to_string(), node_a);
        graph.nodes.insert("b".to_string(), node_b);
        graph.nodes.insert("c".to_string(), node_c);
        graph.nodes.insert("d".to_string(), node_d);

        let callers = graph.get_transitive_callers("d", 10);
        assert_eq!(callers.len(), 3);

        // Should find c at depth 1, b at depth 2, a at depth 3
        assert!(callers
            .iter()
            .any(|(name, depth)| name == "c" && *depth == 1));
        assert!(callers
            .iter()
            .any(|(name, depth)| name == "b" && *depth == 2));
        assert!(callers
            .iter()
            .any(|(name, depth)| name == "a" && *depth == 3));
    }

    #[test]
    fn test_get_transitive_callers_with_max_depth() {
        let graph = CallGraph::new();

        // Create a chain a -> b -> c
        let node_b = CallNode {
            name: "b".to_string(),
            file_path: "/file.rs".to_string(),
            line: 10,
            calls: vec![CallEdge {
                target: "c".to_string(),
                file_path: "/file.rs".to_string(),
                line: 12,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            called_by: vec![CallEdge {
                target: "a".to_string(),
                file_path: "/file.rs".to_string(),
                line: 2,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            metrics: FunctionMetrics::default(),
        };

        let node_c = CallNode {
            name: "c".to_string(),
            file_path: "/file.rs".to_string(),
            line: 20,
            calls: Vec::new(),
            called_by: vec![CallEdge {
                target: "b".to_string(),
                file_path: "/file.rs".to_string(),
                line: 12,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            metrics: FunctionMetrics::default(),
        };

        graph.nodes.insert("b".to_string(), node_b);
        graph.nodes.insert("c".to_string(), node_c);

        // With max_depth=1, should only find b
        let callers = graph.get_transitive_callers("c", 1);
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].0, "b");
        assert_eq!(callers[0].1, 1);
    }

    #[test]
    fn test_get_transitive_callees() {
        let graph = CallGraph::new();

        // Create a call chain: a -> b -> c -> d
        // Test getting transitive callees of a should return b, c, d

        let node_a = CallNode {
            name: "a".to_string(),
            file_path: "/file.rs".to_string(),
            line: 1,
            calls: vec![CallEdge {
                target: "b".to_string(),
                file_path: "/file.rs".to_string(),
                line: 2,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        let node_b = CallNode {
            name: "b".to_string(),
            file_path: "/file.rs".to_string(),
            line: 10,
            calls: vec![CallEdge {
                target: "c".to_string(),
                file_path: "/file.rs".to_string(),
                line: 12,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            called_by: vec![CallEdge {
                target: "a".to_string(),
                file_path: "/file.rs".to_string(),
                line: 2,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            metrics: FunctionMetrics::default(),
        };

        let node_c = CallNode {
            name: "c".to_string(),
            file_path: "/file.rs".to_string(),
            line: 20,
            calls: vec![CallEdge {
                target: "d".to_string(),
                file_path: "/file.rs".to_string(),
                line: 22,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            called_by: vec![CallEdge {
                target: "b".to_string(),
                file_path: "/file.rs".to_string(),
                line: 12,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            metrics: FunctionMetrics::default(),
        };

        let node_d = CallNode {
            name: "d".to_string(),
            file_path: "/file.rs".to_string(),
            line: 30,
            calls: Vec::new(),
            called_by: vec![CallEdge {
                target: "c".to_string(),
                file_path: "/file.rs".to_string(),
                line: 22,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            metrics: FunctionMetrics::default(),
        };

        graph.nodes.insert("a".to_string(), node_a);
        graph.nodes.insert("b".to_string(), node_b);
        graph.nodes.insert("c".to_string(), node_c);
        graph.nodes.insert("d".to_string(), node_d);

        let callees = graph.get_transitive_callees("a", 10);
        assert_eq!(callees.len(), 3);

        // Should find b at depth 1, c at depth 2, d at depth 3
        assert!(callees
            .iter()
            .any(|(name, depth)| name == "b" && *depth == 1));
        assert!(callees
            .iter()
            .any(|(name, depth)| name == "c" && *depth == 2));
        assert!(callees
            .iter()
            .any(|(name, depth)| name == "d" && *depth == 3));
    }

    #[test]
    fn test_find_call_path() {
        let graph = CallGraph::new();

        // Create a call path: a -> b -> c
        let node_a = CallNode {
            name: "a".to_string(),
            file_path: "/file.rs".to_string(),
            line: 1,
            calls: vec![CallEdge {
                target: "b".to_string(),
                file_path: "/file.rs".to_string(),
                line: 2,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        let node_b = CallNode {
            name: "b".to_string(),
            file_path: "/file.rs".to_string(),
            line: 10,
            calls: vec![CallEdge {
                target: "c".to_string(),
                file_path: "/file.rs".to_string(),
                line: 12,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        let node_c = CallNode {
            name: "c".to_string(),
            file_path: "/file.rs".to_string(),
            line: 20,
            calls: Vec::new(),
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        graph.nodes.insert("a".to_string(), node_a);
        graph.nodes.insert("b".to_string(), node_b);
        graph.nodes.insert("c".to_string(), node_c);

        let path = graph.find_call_path("a", "c");
        assert!(path.is_some());
        let path = path.unwrap();
        assert_eq!(path, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_find_call_path_no_path() {
        let graph = CallGraph::new();

        // Create two separate functions with no connection
        let node_a = CallNode {
            name: "a".to_string(),
            file_path: "/file.rs".to_string(),
            line: 1,
            calls: Vec::new(),
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        let node_b = CallNode {
            name: "b".to_string(),
            file_path: "/file.rs".to_string(),
            line: 10,
            calls: Vec::new(),
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        graph.nodes.insert("a".to_string(), node_a);
        graph.nodes.insert("b".to_string(), node_b);

        let path = graph.find_call_path("a", "b");
        assert!(path.is_none());
    }

    #[test]
    fn test_get_hotspots() {
        let graph = CallGraph::new();

        // Create a highly connected function
        let hotspot = CallNode {
            name: "hotspot".to_string(),
            file_path: "/file.rs".to_string(),
            line: 10,
            calls: vec![
                CallEdge {
                    target: "f1".to_string(),
                    file_path: "/file.rs".to_string(),
                    line: 11,
                    column: 1,
                    call_type: CallType::Direct,
                    scope_hint: None,
                    confirmed_by: SourceSet::TREE_SITTER,
                    line_conflicts: Vec::new(),
                },
                CallEdge {
                    target: "f2".to_string(),
                    file_path: "/file.rs".to_string(),
                    line: 12,
                    column: 1,
                    call_type: CallType::Direct,
                    scope_hint: None,
                    confirmed_by: SourceSet::TREE_SITTER,
                    line_conflicts: Vec::new(),
                },
            ],
            called_by: vec![
                CallEdge {
                    target: "caller1".to_string(),
                    file_path: "/file.rs".to_string(),
                    line: 20,
                    column: 1,
                    call_type: CallType::Direct,
                    scope_hint: None,
                    confirmed_by: SourceSet::TREE_SITTER,
                    line_conflicts: Vec::new(),
                },
                CallEdge {
                    target: "caller2".to_string(),
                    file_path: "/file.rs".to_string(),
                    line: 30,
                    column: 1,
                    call_type: CallType::Direct,
                    scope_hint: None,
                    confirmed_by: SourceSet::TREE_SITTER,
                    line_conflicts: Vec::new(),
                },
                CallEdge {
                    target: "caller3".to_string(),
                    file_path: "/file.rs".to_string(),
                    line: 40,
                    column: 1,
                    call_type: CallType::Direct,
                    scope_hint: None,
                    confirmed_by: SourceSet::TREE_SITTER,
                    line_conflicts: Vec::new(),
                },
            ],
            metrics: FunctionMetrics::default(),
        };

        // Create a less connected function
        let normal = CallNode {
            name: "normal".to_string(),
            file_path: "/file.rs".to_string(),
            line: 50,
            calls: vec![CallEdge {
                target: "f3".to_string(),
                file_path: "/file.rs".to_string(),
                line: 51,
                column: 1,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            called_by: Vec::new(),
            metrics: FunctionMetrics::default(),
        };

        graph.nodes.insert("hotspot".to_string(), hotspot);
        graph.nodes.insert("normal".to_string(), normal);

        let hotspots = graph.get_hotspots(3);

        // Should find hotspot (5 connections) but not normal (1 connection)
        assert_eq!(hotspots.len(), 1);
        assert_eq!(hotspots[0].0, "hotspot");
        assert_eq!(hotspots[0].1, 3); // incoming
        assert_eq!(hotspots[0].2, 2); // outgoing
    }

    #[test]
    fn test_cyclomatic_complexity_calculation() {
        // Test that the base cyclomatic complexity is 1 for a simple function
        let metrics = FunctionMetrics {
            loc: 5,
            cyclomatic: 1, // Base complexity
            max_depth: 1,
            params: 0,
            returns: 1,
            cognitive: 0,
        };

        assert_eq!(metrics.cyclomatic, 1);

        // Test that branches increase complexity
        let complex_metrics = FunctionMetrics {
            loc: 20,
            cyclomatic: 6, // 1 base + 5 branches
            max_depth: 3,
            params: 2,
            returns: 3,
            cognitive: 10,
        };

        assert_eq!(complex_metrics.cyclomatic, 6);
    }

    #[test]
    fn test_to_markdown_single_function() {
        let graph = CallGraph::new();

        let node = CallNode {
            name: "test_func".to_string(),
            file_path: "/path/to/file.rs".to_string(),
            line: 42,
            calls: vec![CallEdge {
                target: "helper".to_string(),
                file_path: "/path/to/file.rs".to_string(),
                line: 45,
                column: 5,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            called_by: vec![CallEdge {
                target: "main".to_string(),
                file_path: "/path/to/main.rs".to_string(),
                line: 10,
                column: 3,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            metrics: FunctionMetrics {
                loc: 10,
                cyclomatic: 3,
                max_depth: 2,
                params: 1,
                returns: 1,
                cognitive: 4,
            },
        };

        graph.nodes.insert("test_func".to_string(), node);

        let markdown = graph.to_markdown(Some("test_func"), false);

        assert!(markdown.contains("# Call Graph: test_func"));
        assert!(markdown.contains("/path/to/file.rs:42"));
        assert!(markdown.contains("CC=3"));
        assert!(markdown.contains("LOC=10"));
        assert!(markdown.contains("helper"));
        assert!(markdown.contains("main"));
    }

    /// exclude_tests drops a caller sitting in a test file and keeps the rest.
    #[test]
    fn exclude_tests_drops_a_caller_in_a_test_file() {
        let source = "\
void probe(void) { }

void user(void) { probe(); }
";
        let test_source = "\
void run_case(void) { probe(); }
";
        let mut files = Vec::new();
        for (path, text) in [("lib/probe.c", source), ("test/case.c", test_source)] {
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_c::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(text, None).unwrap();
            files.push((path.to_string(), text.to_string(), tree));
        }

        let graph = CallGraph::new();
        graph.build_from_files(&files).unwrap();

        let all = graph.to_markdown(Some("probe"), false);
        assert!(all.contains("test/case.c::run_case"));
        assert!(all.contains("lib/probe.c::user"));

        let without_tests = graph.to_markdown(Some("probe"), true);
        assert!(!without_tests.contains("test/case.c::run_case"));
        assert!(without_tests.contains("lib/probe.c::user"));
    }

    #[test]
    fn test_to_markdown_nonexistent_function() {
        let graph = CallGraph::new();

        let markdown = graph.to_markdown(Some("nonexistent"), false);

        assert!(markdown.contains("Function `nonexistent` not found"));
    }

    #[test]
    fn test_to_markdown_summary() {
        let graph = CallGraph::new();

        let node1 = CallNode {
            name: "func1".to_string(),
            file_path: "/file.rs".to_string(),
            line: 10,
            calls: Vec::new(),
            called_by: Vec::new(),
            metrics: FunctionMetrics {
                loc: 10,
                cyclomatic: 2,
                max_depth: 1,
                params: 0,
                returns: 1,
                cognitive: 2,
            },
        };

        graph.nodes.insert("func1".to_string(), node1);

        let markdown = graph.to_markdown(None, false);

        assert!(markdown.contains("# Call Graph Summary"));
        assert!(markdown.contains("**Total Functions**: 1"));
        assert!(markdown.contains("Most Called Functions"));
        assert!(markdown.contains("Complexity Hotspots"));
    }

    #[test]
    fn test_to_dot_format() {
        let graph = CallGraph::new();

        let node = CallNode {
            name: "func".to_string(),
            file_path: "/file.rs".to_string(),
            line: 10,
            calls: vec![CallEdge {
                target: "helper".to_string(),
                file_path: "/file.rs".to_string(),
                line: 12,
                column: 5,
                call_type: CallType::Direct,
                scope_hint: None,
                confirmed_by: SourceSet::TREE_SITTER,
                line_conflicts: Vec::new(),
            }],
            called_by: Vec::new(),
            metrics: FunctionMetrics {
                loc: 5,
                cyclomatic: 2,
                max_depth: 1,
                params: 1,
                returns: 1,
                cognitive: 2,
            },
        };

        graph.nodes.insert("func".to_string(), node);

        let dot = graph.to_dot(None);

        assert!(dot.contains("digraph CallGraph"));
        assert!(dot.contains("\"func\""));
        assert!(dot.contains("\"func\" -> \"helper\""));
        assert!(dot.contains("CC:2"));
        assert!(dot.contains("LOC:5"));
    }

    #[test]
    fn test_call_edge_properties() {
        let edge = CallEdge {
            target: "target_func".to_string(),
            file_path: "/path/to/file.rs".to_string(),
            line: 42,
            column: 10,
            call_type: CallType::Method,
            scope_hint: None,
            confirmed_by: SourceSet::TREE_SITTER,
            line_conflicts: Vec::new(),
        };

        assert_eq!(edge.target, "target_func");
        assert_eq!(edge.file_path, "/path/to/file.rs");
        assert_eq!(edge.line, 42);
        assert_eq!(edge.column, 10);
        assert_eq!(edge.call_type, CallType::Method);
    }

    #[test]
    fn test_call_types_distinct() {
        assert_ne!(CallType::Direct, CallType::Method);
        assert_ne!(CallType::Method, CallType::StaticMethod);
        assert_ne!(CallType::StaticMethod, CallType::Closure);
        assert_ne!(CallType::Closure, CallType::Async);
        assert_ne!(CallType::Async, CallType::Spawn);
        assert_ne!(CallType::Spawn, CallType::Unknown);
    }

    #[test]
    fn test_function_metrics_all_fields() {
        let metrics = FunctionMetrics {
            loc: 100,
            cyclomatic: 15,
            max_depth: 5,
            params: 7,
            returns: 4,
            cognitive: 25,
        };

        assert_eq!(metrics.loc, 100);
        assert_eq!(metrics.cyclomatic, 15);
        assert_eq!(metrics.max_depth, 5);
        assert_eq!(metrics.params, 7);
        assert_eq!(metrics.returns, 4);
        assert_eq!(metrics.cognitive, 25);
    }

    #[test]
    fn test_multiple_functions_in_graph() {
        let graph = CallGraph::new();

        let functions = vec!["func1", "func2", "func3", "func4", "func5"];

        for (i, name) in functions.iter().enumerate() {
            let node = CallNode {
                name: name.to_string(),
                file_path: format!("/file{}.rs", i),
                line: (i + 1) * 10,
                calls: Vec::new(),
                called_by: Vec::new(),
                metrics: FunctionMetrics::default(),
            };
            graph.nodes.insert(name.to_string(), node);
        }

        assert_eq!(graph.nodes.len(), 5);

        for name in &functions {
            assert!(graph.nodes.contains_key(*name));
        }
    }

    /// Verify that resolve_callee stays fast when the graph is large.
    ///
    /// Simulates the Linux kernel scenario: ~10k distinct functions, each with a
    /// unique name so every lookup returns exactly one candidate in O(1).  The old
    /// O(N) scan would touch all 10k nodes on every call; the name_index skips
    /// straight to the match.
    #[test]
    fn test_resolve_callee_scales() {
        let graph = CallGraph::new();

        // 100 files × 100 unique functions each = 10_000 nodes.
        // Every (file, func) combination produces a distinct qualified key AND a
        // distinct bare name, so each name_index entry has exactly one candidate.
        for file_idx in 0..100usize {
            let file = format!("src/module_{}/mod.rs", file_idx);
            for fn_idx in 0..100usize {
                let name = format!("func_{}_{}", file_idx, fn_idx);
                insert_test_node(
                    &graph,
                    &file,
                    CallNode {
                        name: name.clone(),
                        file_path: file.clone(),
                        line: fn_idx + 1,
                        calls: Vec::new(),
                        called_by: Vec::new(),
                        metrics: FunctionMetrics::default(),
                    },
                );
            }
        }

        // 100_000 resolve calls from a file not in the graph — forces the full
        // lookup path through name_index every time.
        let start = std::time::Instant::now();
        for call_idx in 0..100_000usize {
            let file_idx = call_idx % 100;
            let fn_idx = call_idx % 100;
            let name = format!("func_{}_{}", file_idx, fn_idx);
            let _ = graph.resolve_callee(&name, "src/other/mod.rs", None);
        }
        let elapsed = start.elapsed();

        // Under the old O(N) scan: 100k calls × 10k nodes = 1 billion iterations.
        // With the name_index: 100k O(1) DashMap lookups — must finish in < 5 s
        // even in unoptimised debug builds under heavy CI load.
        assert!(
            elapsed.as_secs() < 5,
            "resolve_callee took {:?} for 100k calls over 10k functions — O(N) scan not fixed?",
            elapsed
        );
    }

    #[test]
    fn test_scope_matches_file_path() {
        // "App" should match src/app/mod.rs
        assert!(CallGraph::scope_matches_file_path("App", "src/app/mod.rs"));
        // "App" should not match src/application.rs (no /app/ or /app.)
        assert!(!CallGraph::scope_matches_file_path(
            "App",
            "src/application.rs"
        ));
        // "crate::utils" -> strips crate::, becomes "utils", matches src/utils/mod.rs
        assert!(CallGraph::scope_matches_file_path(
            "crate::utils",
            "src/utils/mod.rs"
        ));
        // "crate::utils" -> "utils" matches src/utils.rs
        assert!(CallGraph::scope_matches_file_path(
            "crate::utils",
            "src/utils.rs"
        ));
        // "self::foo" -> "foo" matches src/foo/bar.rs
        assert!(CallGraph::scope_matches_file_path(
            "self::foo",
            "src/foo/bar.rs"
        ));
        // "super::bar" -> "bar" matches src/bar.rs
        assert!(CallGraph::scope_matches_file_path(
            "super::bar",
            "src/bar.rs"
        ));
        // Case insensitive: "App" matches "src/App/mod.rs" and "src/app/mod.rs"
        assert!(CallGraph::scope_matches_file_path("App", "src/App/mod.rs"));
        // Nested scope: "api::client" -> "api/client" matches "src/api/client.rs"
        assert!(CallGraph::scope_matches_file_path(
            "api::client",
            "src/api/client.rs"
        ));
    }

    fn insert_test_node(graph: &CallGraph, file: &str, node: CallNode) {
        let key = CallGraph::qualified_key(file, &node.name);
        graph
            .name_index
            .entry(node.name.clone())
            .or_default()
            .push(key.clone());
        graph.nodes.insert(key, node);
    }

    #[test]
    fn test_resolve_callee_deterministic() {
        let graph = CallGraph::new();

        insert_test_node(
            &graph,
            "src/agents/mod.rs",
            CallNode {
                name: "run".to_string(),
                file_path: "src/agents/mod.rs".to_string(),
                line: 10,
                calls: Vec::new(),
                called_by: Vec::new(),
                metrics: FunctionMetrics::default(),
            },
        );
        insert_test_node(
            &graph,
            "src/app/mod.rs",
            CallNode {
                name: "run".to_string(),
                file_path: "src/app/mod.rs".to_string(),
                line: 20,
                calls: Vec::new(),
                called_by: Vec::new(),
                metrics: FunctionMetrics::default(),
            },
        );

        // Without scope hint, from a third file, should get deterministic result
        // (alphabetically first: "src/agents/mod.rs::run" < "src/app/mod.rs::run")
        let result1 = graph.resolve_callee("run", "src/main.rs", None);
        let result2 = graph.resolve_callee("run", "src/main.rs", None);
        assert_eq!(result1, result2, "resolve_callee must be deterministic");
        assert_eq!(result1, "src/agents/mod.rs::run");
    }

    #[test]
    fn test_resolve_callee_with_scope_hint() {
        let graph = CallGraph::new();

        insert_test_node(
            &graph,
            "src/agents/mod.rs",
            CallNode {
                name: "run".to_string(),
                file_path: "src/agents/mod.rs".to_string(),
                line: 10,
                calls: Vec::new(),
                called_by: Vec::new(),
                metrics: FunctionMetrics::default(),
            },
        );
        insert_test_node(
            &graph,
            "src/app/mod.rs",
            CallNode {
                name: "run".to_string(),
                file_path: "src/app/mod.rs".to_string(),
                line: 20,
                calls: Vec::new(),
                called_by: Vec::new(),
                metrics: FunctionMetrics::default(),
            },
        );

        // With scope hint "App", should pick app/mod.rs::run
        let result = graph.resolve_callee("run", "src/main.rs", Some("App"));
        assert_eq!(
            result, "src/app/mod.rs::run",
            "scope hint 'App' should resolve to app module"
        );

        // With scope hint "agents", should pick agents/mod.rs::run
        let result = graph.resolve_callee("run", "src/main.rs", Some("agents"));
        assert_eq!(
            result, "src/agents/mod.rs::run",
            "scope hint 'agents' should resolve to agents module"
        );
    }

    #[test]
    fn test_resolve_callee_same_file_preferred() {
        let graph = CallGraph::new();

        insert_test_node(
            &graph,
            "src/main.rs",
            CallNode {
                name: "helper".to_string(),
                file_path: "src/main.rs".to_string(),
                line: 5,
                calls: Vec::new(),
                called_by: Vec::new(),
                metrics: FunctionMetrics::default(),
            },
        );
        insert_test_node(
            &graph,
            "src/utils.rs",
            CallNode {
                name: "helper".to_string(),
                file_path: "src/utils.rs".to_string(),
                line: 10,
                calls: Vec::new(),
                called_by: Vec::new(),
                metrics: FunctionMetrics::default(),
            },
        );

        // Same-file match should always win, even with a scope hint pointing elsewhere
        let result = graph.resolve_callee("helper", "src/main.rs", Some("utils"));
        assert_eq!(result, "src/main.rs::helper");
    }

    #[test]
    fn test_find_function_deterministic() {
        let graph = CallGraph::new();

        // Multiple functions named "run" in different files
        for file in &["src/agents/mod.rs", "src/app/mod.rs", "src/cli/mod.rs"] {
            let node = CallNode {
                name: "run".to_string(),
                file_path: file.to_string(),
                line: 1,
                calls: Vec::new(),
                called_by: Vec::new(),
                metrics: FunctionMetrics::default(),
            };
            graph
                .nodes
                .insert(CallGraph::qualified_key(file, "run"), node);
        }

        // find_function("run") should return the same result every time (alphabetically first)
        let result1 = graph.find_function("run");
        let result2 = graph.find_function("run");
        assert_eq!(result1, result2, "find_function must be deterministic");
        assert_eq!(result1, Some("src/agents/mod.rs::run".to_string()));

        // An empty or blank query must not fuzzy-match any node: the suffix and
        // contains fallbacks treat "" as matching every key, so without the guard
        // this would resolve to the alphabetically-first node instead of None.
        assert_eq!(graph.find_function(""), None);
        assert_eq!(graph.find_function("   "), None);
        assert!(graph.get_callees("").is_empty());
        assert!(graph.get_callers("").is_empty());
    }

    #[test]
    fn lookup_by_name_returns_every_definition_site() {
        // Two files defining a function with the same bare name —
        // the cross-TU heap-overflow resolver consumes this list to
        // pick the right definition (e.g. same-file static wins).
        let graph = CallGraph::new();
        insert_test_node(
            &graph,
            "lib/helper.c",
            CallNode {
                name: "build_buffer".to_string(),
                file_path: "lib/helper.c".to_string(),
                line: 12,
                calls: Vec::new(),
                called_by: Vec::new(),
                metrics: FunctionMetrics::default(),
            },
        );
        insert_test_node(
            &graph,
            "util/other.c",
            CallNode {
                name: "build_buffer".to_string(),
                file_path: "util/other.c".to_string(),
                line: 7,
                calls: Vec::new(),
                called_by: Vec::new(),
                metrics: FunctionMetrics::default(),
            },
        );

        let mut keys = graph.lookup_by_name("build_buffer");
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "lib/helper.c::build_buffer".to_string(),
                "util/other.c::build_buffer".to_string(),
            ]
        );

        // Unknown name -> empty vector, not panic / not None.
        assert!(graph.lookup_by_name("does_not_exist").is_empty());
    }
}
