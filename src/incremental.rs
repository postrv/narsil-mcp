//! Incremental Indexing with Merkle Trees
//!
//! Phase 6 feature: Efficient change detection using Merkle trees to minimize
//! re-indexing work. Also includes cross-language symbol resolution for imports.

#![allow(dead_code)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::symbols::{Symbol, SymbolKind};

/// A node in the Merkle tree representing either a file or directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MerkleNode {
    /// A file with its content hash and metadata
    File {
        path: PathBuf,
        hash: String,
        size: u64,
        modified: u64,
        symbols: Vec<Symbol>,
    },
    /// A directory with children hashes combined
    Directory {
        path: PathBuf,
        hash: String,
        children: BTreeMap<String, MerkleNode>,
        total_files: usize,
        total_size: u64,
    },
}

impl MerkleNode {
    /// Get the hash of this node
    pub fn hash(&self) -> &str {
        match self {
            MerkleNode::File { hash, .. } => hash,
            MerkleNode::Directory { hash, .. } => hash,
        }
    }

    /// Get the path of this node
    pub fn path(&self) -> &Path {
        match self {
            MerkleNode::File { path, .. } => path,
            MerkleNode::Directory { path, .. } => path,
        }
    }

    /// Check if this is a file node
    pub fn is_file(&self) -> bool {
        matches!(self, MerkleNode::File { .. })
    }

    /// Get total file count
    pub fn file_count(&self) -> usize {
        match self {
            MerkleNode::File { .. } => 1,
            MerkleNode::Directory { total_files, .. } => *total_files,
        }
    }

    /// Get total size
    pub fn total_size(&self) -> u64 {
        match self {
            MerkleNode::File { size, .. } => *size,
            MerkleNode::Directory { total_size, .. } => *total_size,
        }
    }
}

/// A Merkle tree representing the state of a codebase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub root: MerkleNode,
    pub version: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

impl MerkleTree {
    const CURRENT_VERSION: u32 = 1;

    /// Build a Merkle tree from a directory
    pub fn build<F>(root_path: &Path, mut parse_fn: F) -> Result<Self>
    where
        F: FnMut(&Path) -> Result<Vec<Symbol>>,
    {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();

        let root = Self::build_node(root_path, &mut parse_fn)?;

        Ok(Self {
            root,
            version: Self::CURRENT_VERSION,
            created_at: now,
            updated_at: now,
        })
    }

    /// Build a node recursively
    fn build_node<F>(path: &Path, parse_fn: &mut F) -> Result<MerkleNode>
    where
        F: FnMut(&Path) -> Result<Vec<Symbol>>,
    {
        if path.is_file() {
            Self::build_file_node(path, parse_fn)
        } else if path.is_dir() {
            Self::build_dir_node(path, parse_fn)
        } else {
            Err(anyhow::anyhow!("Invalid path: {:?}", path))
        }
    }

    /// Build a file node
    fn build_file_node<F>(path: &Path, parse_fn: &mut F) -> Result<MerkleNode>
    where
        F: FnMut(&Path) -> Result<Vec<Symbol>>,
    {
        let metadata = std::fs::metadata(path)?;
        let content = std::fs::read(path)?;

        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = format!("{:x}", hasher.finalize());

        let modified = metadata
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();

        // Parse symbols if it's a source file
        let symbols = if is_source_file(path) {
            parse_fn(path).unwrap_or_default()
        } else {
            Vec::new()
        };

        Ok(MerkleNode::File {
            path: path.to_path_buf(),
            hash,
            size: metadata.len(),
            modified,
            symbols,
        })
    }

    /// Build a directory node
    fn build_dir_node<F>(path: &Path, parse_fn: &mut F) -> Result<MerkleNode>
    where
        F: FnMut(&Path) -> Result<Vec<Symbol>>,
    {
        let mut children = BTreeMap::new();
        let mut total_files = 0;
        let mut total_size = 0;

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip hidden files and common ignore patterns
            if should_ignore(&name) {
                continue;
            }

            if let Ok(child) = Self::build_node(&entry_path, parse_fn) {
                total_files += child.file_count();
                total_size += child.total_size();
                children.insert(name, child);
            }
        }

        // Compute directory hash from children hashes
        let mut hasher = Sha256::new();
        for (name, child) in &children {
            hasher.update(name.as_bytes());
            hasher.update(child.hash().as_bytes());
        }
        let hash = format!("{:x}", hasher.finalize());

        Ok(MerkleNode::Directory {
            path: path.to_path_buf(),
            hash,
            children,
            total_files,
            total_size,
        })
    }

    /// Compare two Merkle trees and find changed files
    pub fn diff(&self, other: &MerkleTree) -> ChangeSet {
        let mut changes = ChangeSet::new();
        Self::diff_nodes(&self.root, &other.root, &mut changes);
        changes
    }

    /// Compare two nodes recursively
    fn diff_nodes(old: &MerkleNode, new: &MerkleNode, changes: &mut ChangeSet) {
        match (old, new) {
            // Both are files - only new_path is needed since we track modified files by their current path
            (
                MerkleNode::File { hash: old_hash, .. },
                MerkleNode::File {
                    path: new_path,
                    hash: new_hash,
                    ..
                },
            ) => {
                if old_hash != new_hash {
                    changes.modified.push(new_path.clone());
                }
            }
            // Both are directories
            (
                MerkleNode::Directory {
                    children: old_children,
                    ..
                },
                MerkleNode::Directory {
                    children: new_children,
                    ..
                },
            ) => {
                // Find deleted entries
                for (name, old_child) in old_children {
                    if !new_children.contains_key(name) {
                        Self::collect_files(old_child, &mut changes.deleted);
                    }
                }

                // Find added and modified entries
                for (name, new_child) in new_children {
                    if let Some(old_child) = old_children.get(name) {
                        // Check if hashes differ (optimization: skip subtree if same)
                        if old_child.hash() != new_child.hash() {
                            Self::diff_nodes(old_child, new_child, changes);
                        }
                    } else {
                        // New entry
                        Self::collect_files(new_child, &mut changes.added);
                    }
                }
            }
            // Type changed (file -> dir or dir -> file)
            _ => {
                Self::collect_files(old, &mut changes.deleted);
                Self::collect_files(new, &mut changes.added);
            }
        }
    }

    /// Collect all file paths from a node
    fn collect_files(node: &MerkleNode, files: &mut Vec<PathBuf>) {
        match node {
            MerkleNode::File { path, .. } => {
                if is_source_file(path) {
                    files.push(path.clone());
                }
            }
            MerkleNode::Directory { children, .. } => {
                for child in children.values() {
                    Self::collect_files(child, files);
                }
            }
        }
    }

    /// Get all symbols from the tree
    pub fn all_symbols(&self) -> Vec<&Symbol> {
        let mut symbols = Vec::new();
        Self::collect_symbols(&self.root, &mut symbols);
        symbols
    }

    fn collect_symbols<'a>(node: &'a MerkleNode, symbols: &mut Vec<&'a Symbol>) {
        match node {
            MerkleNode::File {
                symbols: file_syms, ..
            } => {
                symbols.extend(file_syms.iter());
            }
            MerkleNode::Directory { children, .. } => {
                for child in children.values() {
                    Self::collect_symbols(child, symbols);
                }
            }
        }
    }

    /// Get symbols for a specific file
    pub fn file_symbols(&self, path: &Path) -> Option<&[Symbol]> {
        self.find_file(path).map(|node| {
            if let MerkleNode::File { symbols, .. } = node {
                symbols.as_slice()
            } else {
                &[]
            }
        })
    }

    /// Find a file node by path
    fn find_file(&self, target: &Path) -> Option<&MerkleNode> {
        Self::find_file_in_node(&self.root, target)
    }

    fn find_file_in_node<'a>(node: &'a MerkleNode, target: &Path) -> Option<&'a MerkleNode> {
        match node {
            MerkleNode::File { path, .. } if path == target => Some(node),
            MerkleNode::Directory { children, path, .. } => {
                if target.starts_with(path) {
                    for child in children.values() {
                        if let Some(found) = Self::find_file_in_node(child, target) {
                            return Some(found);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Save tree to disk
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = bincode::serialize(self).context("Failed to serialize Merkle tree")?;

        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, &data).context("Failed to write temp file")?;
        std::fs::rename(&temp_path, path).context("Failed to rename file")?;

        Ok(())
    }

    /// Load tree from disk
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).context("Failed to read Merkle tree")?;
        let tree: Self = bincode::deserialize(&data).context("Failed to deserialize")?;

        if tree.version != Self::CURRENT_VERSION {
            return Err(anyhow::anyhow!("Version mismatch"));
        }

        Ok(tree)
    }
}

/// Set of changes detected between two states
#[derive(Debug, Default)]
pub struct ChangeSet {
    pub added: Vec<PathBuf>,
    pub modified: Vec<PathBuf>,
    pub deleted: Vec<PathBuf>,
}

impl ChangeSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.deleted.is_empty()
    }

    pub fn total_changes(&self) -> usize {
        self.added.len() + self.modified.len() + self.deleted.len()
    }
}

// =============================================================================
// Cross-Language Symbol Resolution
// =============================================================================

/// An import statement parsed from source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    /// The file containing this import
    pub source_file: PathBuf,
    /// The import path/module (e.g., "./utils", "lodash", "crate::parser")
    pub import_path: String,
    /// Imported symbols (empty for "import *" or default imports)
    pub imported_symbols: Vec<ImportedSymbol>,
    /// Type of import
    pub import_type: ImportType,
    /// Line number
    pub line: usize,
}

/// An imported symbol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedSymbol {
    pub name: String,
    pub alias: Option<String>,
    pub is_default: bool,
}

/// Types of imports
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportType {
    /// ES6 import: import { x } from 'y'
    EsModule,
    /// CommonJS require: const x = require('y')
    CommonJs,
    /// Python import: from x import y
    Python,
    /// Rust use: use crate::x::y
    Rust,
    /// Go import: import "package"
    Go,
    /// Java import: import x.y.z
    Java,
    /// C/C++ include: #include "x.h"
    CppInclude,
}

/// Cross-language symbol resolution
#[derive(Debug)]
pub struct SymbolResolver {
    /// Map of file path -> exported symbols
    exports: HashMap<PathBuf, Vec<ExportedSymbol>>,
    /// Map of file path -> imports
    imports: HashMap<PathBuf, Vec<Import>>,
    /// Map of symbol name -> defining files
    symbol_index: HashMap<String, Vec<PathBuf>>,
    /// Language-specific resolution rules
    resolution_rules: Vec<ResolutionRule>,
}

/// An exported symbol from a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedSymbol {
    pub name: String,
    pub symbol: Symbol,
    pub is_default: bool,
    pub is_public: bool,
}

/// Rule for resolving imports to files
#[derive(Debug, Clone)]
pub struct ResolutionRule {
    /// Import type this rule applies to
    pub import_type: ImportType,
    /// File extensions to try
    pub extensions: Vec<String>,
    /// Module directories to search
    pub module_dirs: Vec<String>,
    /// Index files to check (e.g., "index.js", "mod.rs")
    pub index_files: Vec<String>,
}

impl Default for SymbolResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolResolver {
    pub fn new() -> Self {
        Self {
            exports: HashMap::new(),
            imports: HashMap::new(),
            symbol_index: HashMap::new(),
            resolution_rules: Self::default_rules(),
        }
    }

    /// Default resolution rules for common languages
    fn default_rules() -> Vec<ResolutionRule> {
        vec![
            // JavaScript/TypeScript
            ResolutionRule {
                import_type: ImportType::EsModule,
                extensions: vec![
                    ".ts".to_string(),
                    ".tsx".to_string(),
                    ".js".to_string(),
                    ".jsx".to_string(),
                ],
                module_dirs: vec!["node_modules".to_string()],
                index_files: vec!["index.ts".to_string(), "index.js".to_string()],
            },
            // CommonJS
            ResolutionRule {
                import_type: ImportType::CommonJs,
                extensions: vec![".js".to_string(), ".cjs".to_string()],
                module_dirs: vec!["node_modules".to_string()],
                index_files: vec!["index.js".to_string()],
            },
            // Python
            ResolutionRule {
                import_type: ImportType::Python,
                extensions: vec![".py".to_string()],
                module_dirs: vec!["site-packages".to_string(), "lib".to_string()],
                index_files: vec!["__init__.py".to_string()],
            },
            // Rust
            ResolutionRule {
                import_type: ImportType::Rust,
                extensions: vec![".rs".to_string()],
                module_dirs: vec!["src".to_string()],
                index_files: vec!["mod.rs".to_string(), "lib.rs".to_string()],
            },
            // Go
            ResolutionRule {
                import_type: ImportType::Go,
                extensions: vec![".go".to_string()],
                module_dirs: vec!["pkg".to_string(), "vendor".to_string()],
                index_files: vec![],
            },
            // C/C++
            ResolutionRule {
                import_type: ImportType::CppInclude,
                extensions: vec![".h".to_string(), ".hpp".to_string(), ".hh".to_string()],
                module_dirs: vec!["include".to_string()],
                index_files: vec![],
            },
        ]
    }

    /// Index symbols from a file for cross-referencing
    pub fn index_file(&mut self, path: &Path, symbols: &[Symbol], exports: Vec<ExportedSymbol>) {
        // Index exports
        self.exports.insert(path.to_path_buf(), exports.clone());

        // Track exported symbol names to avoid duplicates
        let mut indexed_names: HashSet<String> = HashSet::new();

        // Index exported symbol names for external visibility
        for export in &exports {
            indexed_names.insert(export.name.clone());
            self.symbol_index
                .entry(export.name.clone())
                .or_default()
                .push(path.to_path_buf());
        }

        // Also index all internal symbols for comprehensive lookup
        // (useful for find-references, go-to-definition across files)
        for symbol in symbols {
            // Use qualified_name if available, otherwise just name
            let sym_name = symbol.qualified_name.as_ref().unwrap_or(&symbol.name);
            // Skip if already indexed via exports to avoid duplicates
            if indexed_names.contains(sym_name) {
                continue;
            }
            indexed_names.insert(sym_name.clone());
            self.symbol_index
                .entry(sym_name.clone())
                .or_default()
                .push(path.to_path_buf());
        }
    }

    /// Register imports from a file
    pub fn register_imports(&mut self, path: &Path, imports: Vec<Import>) {
        self.imports.insert(path.to_path_buf(), imports);
    }

    /// Resolve an import path to a file
    pub fn resolve_import(
        &self,
        import: &Import,
        base_dir: &Path,
        project_root: &Path,
    ) -> Option<PathBuf> {
        let rules = self
            .resolution_rules
            .iter()
            .find(|r| r.import_type == import.import_type)?;

        // Handle relative imports
        if import.import_path.starts_with('.') {
            return self.resolve_relative_import(import, base_dir, rules);
        }

        // Handle absolute/package imports
        self.resolve_package_import(import, project_root, rules)
    }

    /// Resolve a relative import (./foo, ../bar)
    fn resolve_relative_import(
        &self,
        import: &Import,
        base_dir: &Path,
        rules: &ResolutionRule,
    ) -> Option<PathBuf> {
        let target = base_dir.join(&import.import_path);

        // Try with each extension
        for ext in &rules.extensions {
            let with_ext = target.with_extension(ext.trim_start_matches('.'));
            if with_ext.exists() {
                return Some(with_ext);
            }
        }

        // Try as directory with index file
        if target.is_dir() {
            for index in &rules.index_files {
                let index_path = target.join(index);
                if index_path.exists() {
                    return Some(index_path);
                }
            }
        }

        None
    }

    /// Resolve a package/module import
    fn resolve_package_import(
        &self,
        import: &Import,
        project_root: &Path,
        rules: &ResolutionRule,
    ) -> Option<PathBuf> {
        for module_dir in &rules.module_dirs {
            let search_path = project_root.join(module_dir).join(&import.import_path);

            // Try with extensions
            for ext in &rules.extensions {
                let with_ext = search_path.with_extension(ext.trim_start_matches('.'));
                if with_ext.exists() {
                    return Some(with_ext);
                }
            }

            // Try as directory with index
            if search_path.is_dir() {
                for index in &rules.index_files {
                    let index_path = search_path.join(index);
                    if index_path.exists() {
                        return Some(index_path);
                    }
                }
            }
        }

        None
    }

    /// Find where a symbol is defined
    pub fn find_symbol_definition(&self, name: &str) -> Vec<&PathBuf> {
        self.symbol_index
            .get(name)
            .map(|paths| paths.iter().collect())
            .unwrap_or_default()
    }

    /// Get all files that import from a given file
    pub fn find_importers(&self, target_file: &Path) -> Vec<&PathBuf> {
        self.imports
            .iter()
            .filter_map(|(file, imports)| {
                let has_import = imports.iter().any(|i| {
                    // Check if any import resolves to target_file
                    if let Some(parent) = file.parent() {
                        if let Some(resolved) = self.resolve_import(i, parent, parent) {
                            return resolved == target_file;
                        }
                    }
                    false
                });
                if has_import {
                    Some(file)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find all symbols imported from a file
    pub fn get_imported_symbols(
        &self,
        from_file: &Path,
        target_file: &Path,
    ) -> Vec<&ImportedSymbol> {
        self.imports
            .get(from_file)
            .map(|imports| {
                imports
                    .iter()
                    .filter_map(|i| {
                        if let Some(parent) = from_file.parent() {
                            if let Some(resolved) = self.resolve_import(i, parent, parent) {
                                if resolved == target_file {
                                    return Some(i.imported_symbols.iter().collect::<Vec<_>>());
                                }
                            }
                        }
                        None
                    })
                    .flatten()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get reference to all exports
    ///
    /// Returns a reference to the map of file paths to their exported symbols.
    #[must_use]
    pub fn get_exports(&self) -> &HashMap<PathBuf, Vec<ExportedSymbol>> {
        &self.exports
    }

    /// Get reference to all imports
    ///
    /// Returns a reference to the map of file paths to their imports.
    #[must_use]
    pub fn get_imports(&self) -> &HashMap<PathBuf, Vec<Import>> {
        &self.imports
    }

    /// Build import graph for the codebase
    pub fn build_import_graph(&self, project_root: &Path) -> ImportGraph {
        let mut graph = ImportGraph::new();

        // Only process code files, not scripts or configs
        const CODE_EXTENSIONS: &[&str] = &[
            ".rs", ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".c", ".cpp", ".h",
            ".hpp", ".cs", ".rb", ".php", ".swift", ".scala",
        ];

        let is_code_file = |path: &Path| -> bool {
            let path_str = path.to_string_lossy();
            CODE_EXTENSIONS.iter().any(|ext| path_str.ends_with(ext))
        };

        for (file, imports) in &self.imports {
            // Skip non-code files
            if !is_code_file(file) {
                continue;
            }

            for import in imports {
                if let Some(parent) = file.parent() {
                    if let Some(resolved) = self.resolve_import(import, parent, project_root) {
                        // Skip if resolved to non-code file
                        if !is_code_file(&resolved) {
                            continue;
                        }
                        // Avoid duplicate edges
                        if !graph.has_edge(file, &resolved) {
                            graph.add_edge(file.clone(), resolved, import.import_path.clone());
                        }
                    }
                }
            }
        }

        graph
    }
}

/// Import dependency graph
#[derive(Debug, Default)]
pub struct ImportGraph {
    /// Edges: source file -> (target file, import path)
    edges: HashMap<PathBuf, Vec<(PathBuf, String)>>,
    /// Reverse edges: target file -> source files
    reverse_edges: HashMap<PathBuf, Vec<PathBuf>>,
}

impl ImportGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_edge(&mut self, from: PathBuf, to: PathBuf, import_path: String) {
        self.edges
            .entry(from.clone())
            .or_default()
            .push((to.clone(), import_path));
        self.reverse_edges.entry(to).or_default().push(from);
    }

    /// Check if an edge already exists
    pub fn has_edge(&self, from: &Path, to: &Path) -> bool {
        self.edges
            .get(from)
            .map(|deps| deps.iter().any(|(target, _)| target == to))
            .unwrap_or(false)
    }

    /// Get files that a file depends on
    pub fn dependencies(&self, file: &Path) -> Vec<&PathBuf> {
        self.edges
            .get(file)
            .map(|deps| deps.iter().map(|(p, _)| p).collect())
            .unwrap_or_default()
    }

    /// Get files that depend on a file
    pub fn dependents(&self, file: &Path) -> Vec<&PathBuf> {
        self.reverse_edges
            .get(file)
            .map(|deps| deps.iter().collect())
            .unwrap_or_default()
    }

    /// Find circular dependencies
    pub fn find_cycles(&self) -> Vec<Vec<PathBuf>> {
        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let mut path = Vec::new();

        for start in self.edges.keys() {
            if !visited.contains(start) {
                self.dfs_find_cycles(start, &mut visited, &mut rec_stack, &mut path, &mut cycles);
            }
        }

        cycles
    }

    fn dfs_find_cycles(
        &self,
        node: &Path,
        visited: &mut HashSet<PathBuf>,
        rec_stack: &mut HashSet<PathBuf>,
        path: &mut Vec<PathBuf>,
        cycles: &mut Vec<Vec<PathBuf>>,
    ) {
        visited.insert(node.to_path_buf());
        rec_stack.insert(node.to_path_buf());
        path.push(node.to_path_buf());

        if let Some(deps) = self.edges.get(node) {
            for (dep, _) in deps {
                if !visited.contains(dep) {
                    self.dfs_find_cycles(dep, visited, rec_stack, path, cycles);
                } else if rec_stack.contains(dep) {
                    // Found cycle - extract it from path
                    if let Some(pos) = path.iter().position(|p| p == dep) {
                        cycles.push(path[pos..].to_vec());
                    }
                }
            }
        }

        path.pop();
        rec_stack.remove(node);
    }

    /// Calculate depth of a file in import hierarchy
    pub fn depth(&self, file: &Path) -> usize {
        let mut visited = HashSet::new();
        self.calc_depth(file, &mut visited)
    }

    fn calc_depth(&self, file: &Path, visited: &mut HashSet<PathBuf>) -> usize {
        if visited.contains(file) {
            return 0; // Cycle detected
        }
        visited.insert(file.to_path_buf());

        let max_child_depth = self
            .edges
            .get(file)
            .map(|deps| {
                deps.iter()
                    .map(|(d, _)| self.calc_depth(d, visited))
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);

        max_child_depth + 1
    }

    /// Get all files in topological order (dependencies first)
    pub fn topological_sort(&self) -> Result<Vec<PathBuf>> {
        let mut in_degree: HashMap<&PathBuf, usize> = HashMap::new();
        let mut all_nodes: HashSet<&PathBuf> = HashSet::new();

        // Collect all nodes and compute in-degrees
        for (from, deps) in &self.edges {
            all_nodes.insert(from);
            in_degree.entry(from).or_insert(0);
            for (to, _) in deps {
                all_nodes.insert(to);
                *in_degree.entry(to).or_insert(0) += 1;
            }
        }

        // Start with nodes that have no dependencies
        let mut queue: Vec<&PathBuf> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&node, _)| node)
            .collect();

        let mut result = Vec::new();

        while let Some(node) = queue.pop() {
            result.push(node.clone());

            if let Some(deps) = self.edges.get(node) {
                for (dep, _) in deps {
                    if let Some(deg) = in_degree.get_mut(dep) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(dep);
                        }
                    }
                }
            }
        }

        if result.len() != all_nodes.len() {
            return Err(anyhow::anyhow!("Circular dependency detected"));
        }

        Ok(result)
    }
}

// =============================================================================
// Workspace Symbol Search
// =============================================================================

/// Workspace-wide symbol search with fuzzy matching
#[derive(Debug)]
pub struct WorkspaceSymbolIndex {
    /// All symbols indexed by normalized name
    symbols: HashMap<String, Vec<IndexedSymbol>>,
    /// Trigram index for fuzzy search
    trigram_index: HashMap<String, HashSet<String>>,
}

#[derive(Debug, Clone)]
pub struct IndexedSymbol {
    pub symbol: Symbol,
    pub file_path: PathBuf,
    pub score_boost: f32,
}

impl Default for WorkspaceSymbolIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkspaceSymbolIndex {
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
            trigram_index: HashMap::new(),
        }
    }

    /// Add a symbol to the index
    pub fn add_symbol(&mut self, symbol: Symbol, file_path: PathBuf) {
        let name = symbol.name.clone();
        let normalized = name.to_lowercase();

        // Calculate score boost based on visibility and type
        let score_boost = match symbol.kind {
            SymbolKind::Function | SymbolKind::Method => 1.2,
            SymbolKind::Struct | SymbolKind::Class => 1.3,
            SymbolKind::Interface | SymbolKind::Trait => 1.25,
            SymbolKind::Enum => 1.1,
            _ => 1.0,
        };

        let indexed = IndexedSymbol {
            symbol,
            file_path,
            score_boost,
        };

        // Add to main index
        self.symbols
            .entry(normalized.clone())
            .or_default()
            .push(indexed);

        // Add to trigram index
        for trigram in Self::trigrams(&normalized) {
            self.trigram_index
                .entry(trigram)
                .or_default()
                .insert(normalized.clone());
        }
    }

    /// Generate trigrams from a string
    fn trigrams(s: &str) -> Vec<String> {
        let chars: Vec<char> = s.chars().collect();
        if chars.len() < 3 {
            return vec![s.to_string()];
        }

        chars.windows(3).map(|w| w.iter().collect()).collect()
    }

    /// Fuzzy search for symbols
    pub fn search(&self, query: &str, limit: usize) -> Vec<SymbolSearchResult> {
        let normalized_query = query.to_lowercase();
        let query_trigrams: HashSet<String> =
            Self::trigrams(&normalized_query).into_iter().collect();

        // Find candidate symbols using trigram index
        let mut candidates: HashMap<String, usize> = HashMap::new();

        for trigram in &query_trigrams {
            if let Some(names) = self.trigram_index.get(trigram) {
                for name in names {
                    *candidates.entry(name.clone()).or_insert(0) += 1;
                }
            }
        }

        // Also include exact prefix matches
        for name in self.symbols.keys() {
            if name.starts_with(&normalized_query) || normalized_query.starts_with(name) {
                candidates
                    .entry(name.clone())
                    .or_insert(query_trigrams.len());
            }
        }

        // Score candidates
        let mut results: Vec<SymbolSearchResult> = candidates
            .iter()
            .filter_map(|(name, &trigram_matches)| {
                let symbols = self.symbols.get(name)?;

                // Calculate fuzzy score
                let trigram_score = if query_trigrams.is_empty() {
                    0.0
                } else {
                    trigram_matches as f32 / query_trigrams.len() as f32
                };

                // Bonus for prefix match
                let prefix_bonus = if name.starts_with(&normalized_query) {
                    0.3
                } else {
                    0.0
                };

                // Bonus for exact match
                let exact_bonus = if name == &normalized_query { 0.5 } else { 0.0 };

                let base_score = trigram_score + prefix_bonus + exact_bonus;

                Some(symbols.iter().map(move |indexed| SymbolSearchResult {
                    symbol: indexed.symbol.clone(),
                    file_path: indexed.file_path.clone(),
                    score: base_score * indexed.score_boost,
                }))
            })
            .flatten()
            .collect();

        // Sort by score descending
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        results.truncate(limit);
        results
    }

    /// Search with exact match
    pub fn find_exact(&self, name: &str) -> Vec<&IndexedSymbol> {
        self.symbols
            .get(&name.to_lowercase())
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get all symbols of a specific kind
    pub fn symbols_by_kind(&self, kind: SymbolKind) -> Vec<&IndexedSymbol> {
        self.symbols
            .values()
            .flatten()
            .filter(|s| s.symbol.kind == kind)
            .collect()
    }

    /// Clear the index
    pub fn clear(&mut self) {
        self.symbols.clear();
        self.trigram_index.clear();
    }
}

/// Result from workspace symbol search
#[derive(Debug, Clone)]
pub struct SymbolSearchResult {
    pub symbol: Symbol,
    pub file_path: PathBuf,
    pub score: f32,
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if a file is a source file
fn is_source_file(path: &Path) -> bool {
    let extensions = [
        "rs", "py", "js", "jsx", "ts", "tsx", "go", "java", "c", "h", "cpp", "hpp", "cc", "cxx",
        "hxx", "cs", "swift", "v", "vh", "sv", "svh",
    ];

    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| extensions.contains(&e))
        .unwrap_or(false)
}

/// Check if a file/directory should be ignored
fn should_ignore(name: &str) -> bool {
    // Hidden files/directories
    if name.starts_with('.') {
        return true;
    }

    // Common ignore patterns
    let ignore_patterns = [
        "node_modules",
        "target",
        "build",
        "dist",
        "__pycache__",
        ".git",
        ".svn",
        "vendor",
        "venv",
        ".venv",
        "env",
    ];

    ignore_patterns.contains(&name)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_merkle_node_hash() {
        let node = MerkleNode::File {
            path: PathBuf::from("test.rs"),
            hash: "abc123".to_string(),
            size: 100,
            modified: 0,
            symbols: vec![],
        };
        assert_eq!(node.hash(), "abc123");
    }

    #[test]
    fn test_merkle_tree_build() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("test.rs"), "fn main() {}").unwrap();

        let tree = MerkleTree::build(dir.path(), |_| Ok(vec![])).unwrap();

        assert!(matches!(tree.root, MerkleNode::Directory { .. }));
        assert!(tree.root.file_count() >= 1);
    }

    #[test]
    fn test_change_detection() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("test.rs"), "fn main() {}").unwrap();

        let tree1 = MerkleTree::build(dir.path(), |_| Ok(vec![])).unwrap();

        // Modify file
        std::fs::write(dir.path().join("test.rs"), "fn main() { println!(); }").unwrap();

        let tree2 = MerkleTree::build(dir.path(), |_| Ok(vec![])).unwrap();

        let changes = tree1.diff(&tree2);
        assert!(!changes.modified.is_empty() || !changes.is_empty());
    }

    #[test]
    fn test_change_set() {
        let mut changes = ChangeSet::new();
        assert!(changes.is_empty());

        changes.added.push(PathBuf::from("new.rs"));
        assert!(!changes.is_empty());
        assert_eq!(changes.total_changes(), 1);
    }

    #[test]
    fn test_symbol_resolver_new() {
        let resolver = SymbolResolver::new();
        assert!(!resolver.resolution_rules.is_empty());
    }

    #[test]
    fn test_import_type() {
        assert_eq!(ImportType::EsModule, ImportType::EsModule);
        assert_ne!(ImportType::EsModule, ImportType::CommonJs);
    }

    #[test]
    fn test_import_graph() {
        let mut graph = ImportGraph::new();

        graph.add_edge(
            PathBuf::from("a.ts"),
            PathBuf::from("b.ts"),
            "./b".to_string(),
        );

        graph.add_edge(
            PathBuf::from("b.ts"),
            PathBuf::from("c.ts"),
            "./c".to_string(),
        );

        let deps = graph.dependencies(Path::new("a.ts"));
        assert_eq!(deps.len(), 1);

        let dependents = graph.dependents(Path::new("b.ts"));
        assert_eq!(dependents.len(), 1);
    }

    #[test]
    fn test_import_graph_cycles() {
        let mut graph = ImportGraph::new();

        graph.add_edge(
            PathBuf::from("a.ts"),
            PathBuf::from("b.ts"),
            "./b".to_string(),
        );

        graph.add_edge(
            PathBuf::from("b.ts"),
            PathBuf::from("a.ts"),
            "./a".to_string(),
        );

        let cycles = graph.find_cycles();
        assert!(!cycles.is_empty());
    }

    #[test]
    fn test_import_graph_depth() {
        let mut graph = ImportGraph::new();

        graph.add_edge(
            PathBuf::from("a.ts"),
            PathBuf::from("b.ts"),
            "./b".to_string(),
        );

        graph.add_edge(
            PathBuf::from("b.ts"),
            PathBuf::from("c.ts"),
            "./c".to_string(),
        );

        assert_eq!(graph.depth(Path::new("a.ts")), 3);
        assert_eq!(graph.depth(Path::new("c.ts")), 1);
    }

    #[test]
    fn test_workspace_symbol_index() {
        let mut index = WorkspaceSymbolIndex::new();

        let symbol = Symbol {
            name: "MyFunction".to_string(),
            kind: SymbolKind::Function,
            file_path: "test.rs".to_string(),
            start_line: 1,
            end_line: 5,
            signature: None,
            qualified_name: None,
            doc_comment: None,
        };

        index.add_symbol(symbol.clone(), PathBuf::from("test.rs"));

        // Exact search
        let results = index.find_exact("myfunction");
        assert_eq!(results.len(), 1);

        // Fuzzy search
        let fuzzy = index.search("myfunc", 10);
        assert!(!fuzzy.is_empty());
    }

    #[test]
    fn test_trigram_generation() {
        let trigrams = WorkspaceSymbolIndex::trigrams("hello");
        assert_eq!(trigrams.len(), 3);
        assert!(trigrams.contains(&"hel".to_string()));
        assert!(trigrams.contains(&"ell".to_string()));
        assert!(trigrams.contains(&"llo".to_string()));
    }

    #[test]
    fn test_fuzzy_search_ranking() {
        let mut index = WorkspaceSymbolIndex::new();

        // Add symbols with similar names
        for name in ["getUserById", "getUser", "getUserName", "setUser"] {
            let symbol = Symbol {
                name: name.to_string(),
                kind: SymbolKind::Function,
                file_path: "test.rs".to_string(),
                start_line: 1,
                end_line: 5,
                signature: None,
                qualified_name: None,
                doc_comment: None,
            };
            index.add_symbol(symbol, PathBuf::from("test.rs"));
        }

        let results = index.search("getUser", 10);

        // Exact match should be first
        assert!(!results.is_empty());
        assert!(results[0].symbol.name.to_lowercase().contains("getuser"));
    }

    #[test]
    fn test_symbols_by_kind() {
        let mut index = WorkspaceSymbolIndex::new();

        let func = Symbol {
            name: "myFunc".to_string(),
            kind: SymbolKind::Function,
            file_path: "test.rs".to_string(),
            start_line: 1,
            end_line: 5,
            signature: None,
            qualified_name: None,
            doc_comment: None,
        };

        let class = Symbol {
            name: "MyClass".to_string(),
            kind: SymbolKind::Class,
            file_path: "test.rs".to_string(),
            start_line: 10,
            end_line: 20,
            signature: None,
            qualified_name: None,
            doc_comment: None,
        };

        index.add_symbol(func, PathBuf::from("test.rs"));
        index.add_symbol(class, PathBuf::from("test.rs"));

        let functions = index.symbols_by_kind(SymbolKind::Function);
        assert_eq!(functions.len(), 1);

        let classes = index.symbols_by_kind(SymbolKind::Class);
        assert_eq!(classes.len(), 1);
    }

    #[test]
    fn test_is_source_file() {
        assert!(is_source_file(Path::new("test.rs")));
        assert!(is_source_file(Path::new("src/main.py")));
        assert!(is_source_file(Path::new("lib/utils.ts")));
        assert!(!is_source_file(Path::new("README.md")));
        assert!(!is_source_file(Path::new("data.json")));
    }

    #[test]
    fn test_should_ignore() {
        assert!(should_ignore(".git"));
        assert!(should_ignore("node_modules"));
        assert!(should_ignore("target"));
        assert!(should_ignore("__pycache__"));
        assert!(!should_ignore("src"));
        assert!(!should_ignore("lib"));
    }

    #[test]
    fn test_exported_symbol() {
        let symbol = Symbol {
            name: "test".to_string(),
            kind: SymbolKind::Function,
            file_path: "test.rs".to_string(),
            start_line: 1,
            end_line: 5,
            signature: None,
            qualified_name: None,
            doc_comment: None,
        };

        let exported = ExportedSymbol {
            name: "test".to_string(),
            symbol,
            is_default: false,
            is_public: true,
        };

        assert_eq!(exported.name, "test");
        assert!(exported.is_public);
        assert!(!exported.is_default);
    }

    #[test]
    fn test_import_struct() {
        let import = Import {
            source_file: PathBuf::from("test.ts"),
            import_path: "./utils".to_string(),
            imported_symbols: vec![ImportedSymbol {
                name: "helper".to_string(),
                alias: None,
                is_default: false,
            }],
            import_type: ImportType::EsModule,
            line: 1,
        };

        assert_eq!(import.import_path, "./utils");
        assert_eq!(import.imported_symbols.len(), 1);
    }

    #[test]
    fn test_resolution_rules() {
        let resolver = SymbolResolver::new();

        // Check ES module rules exist
        let es_rule = resolver
            .resolution_rules
            .iter()
            .find(|r| r.import_type == ImportType::EsModule);
        assert!(es_rule.is_some());

        let es_rule = es_rule.unwrap();
        assert!(es_rule.extensions.contains(&".ts".to_string()));
        assert!(es_rule.extensions.contains(&".js".to_string()));
    }

    #[test]
    fn test_find_symbol_definition() {
        let mut resolver = SymbolResolver::new();

        let symbol = Symbol {
            name: "TestFunc".to_string(),
            kind: SymbolKind::Function,
            file_path: "test.rs".to_string(),
            start_line: 1,
            end_line: 5,
            signature: None,
            qualified_name: None,
            doc_comment: None,
        };

        let exported = ExportedSymbol {
            name: "TestFunc".to_string(),
            symbol: symbol.clone(),
            is_default: false,
            is_public: true,
        };

        resolver.index_file(Path::new("test.rs"), &[symbol], vec![exported]);

        let defs = resolver.find_symbol_definition("TestFunc");
        assert_eq!(defs.len(), 1);
    }

    #[test]
    fn test_topological_sort_simple() {
        let mut graph = ImportGraph::new();

        // a -> b -> c (no cycles)
        graph.add_edge(
            PathBuf::from("a.ts"),
            PathBuf::from("b.ts"),
            "./b".to_string(),
        );

        graph.add_edge(
            PathBuf::from("b.ts"),
            PathBuf::from("c.ts"),
            "./c".to_string(),
        );

        let sorted = graph.topological_sort();
        assert!(sorted.is_ok());
    }

    #[test]
    fn test_topological_sort_cycle() {
        let mut graph = ImportGraph::new();

        // a -> b -> a (cycle)
        graph.add_edge(
            PathBuf::from("a.ts"),
            PathBuf::from("b.ts"),
            "./b".to_string(),
        );

        graph.add_edge(
            PathBuf::from("b.ts"),
            PathBuf::from("a.ts"),
            "./a".to_string(),
        );

        let sorted = graph.topological_sort();
        assert!(sorted.is_err());
    }
}
