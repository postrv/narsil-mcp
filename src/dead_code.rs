//! Dead code analysis module.
//!
//! This module provides comprehensive dead code detection across multiple languages,
//! consolidating unreachable code, dead stores, and unused imports analysis.
//!
//! # Features
//! - Unreachable code detection via CFG analysis
//! - Dead store detection via DFG analysis
//! - Unused import detection via import graph analysis
//!
//! # Supported Languages
//! - Rust, Python, JavaScript/TypeScript, Go, Java, C#, Kotlin
//!
//! # Examples
//! ```ignore
//! use narsil_mcp::dead_code::{analyze_dead_code, DeadCodeReport};
//!
//! let report = analyze_dead_code(tree, source, "file.rs")?;
//! println!("{}", report.to_markdown());
//! ```

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tree_sitter::Tree;

use crate::cfg;
use crate::dfg;
use crate::incremental::{ExportedSymbol, Import, SymbolResolver};

/// A comprehensive dead code analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeReport {
    /// File path being analyzed
    pub file_path: String,
    /// Unreachable code blocks per function
    pub unreachable_blocks: Vec<UnreachableBlock>,
    /// Dead stores (assignments never read)
    pub dead_stores: Vec<DeadStore>,
    /// Unused imports in the file
    pub unused_imports: Vec<UnusedImport>,
}

/// An unreachable code block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnreachableBlock {
    /// Function containing the block
    pub function_name: String,
    /// Block identifier
    pub block_id: usize,
    /// Block label
    pub label: String,
    /// Starting line
    pub start_line: usize,
    /// Ending line
    pub end_line: usize,
}

/// A dead store (variable assigned but never read)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadStore {
    /// Function containing the dead store
    pub function_name: String,
    /// Variable name
    pub variable: String,
    /// Line where the assignment occurs
    pub line: usize,
    /// The assignment text
    pub text: String,
}

/// An unused import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnusedImport {
    /// The import path/module
    pub import_path: String,
    /// Specific symbols imported (if any)
    pub symbols: Vec<String>,
    /// Line where import is declared
    pub line: usize,
    /// Language-specific import type
    pub import_type: ImportType,
}

/// Types of imports across languages
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportType {
    /// Rust: use statement
    RustUse,
    /// Python: import or from...import
    PythonImport,
    /// JavaScript/TypeScript: import statement
    JsImport,
    /// Go: import statement
    GoImport,
    /// Java: import statement
    JavaImport,
    /// C#: using statement
    CSharpUsing,
    /// Kotlin: import statement
    KotlinImport,
    /// C/C++: #include directive
    CppInclude,
}

/// An exported symbol that is never imported by other files in the repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnusedExport {
    /// File containing the unused export
    pub file_path: String,
    /// Name of the exported symbol
    pub symbol_name: String,
    /// Kind of symbol (function, struct, class, etc.)
    pub symbol_kind: String,
    /// Line number where the export is defined
    pub line: usize,
    /// Whether this is a public API (exported from entry point)
    pub is_public_api: bool,
    /// The export signature if available
    pub signature: Option<String>,
}

/// Configuration for unused export detection
#[derive(Debug, Clone, Default)]
pub struct UnusedExportConfig {
    /// Exclude entry point files (lib.rs, main.rs, index.js, __init__.py, etc.)
    pub exclude_entry_points: bool,
    /// Glob patterns for files to exclude (public API surface)
    pub exclude_patterns: Vec<String>,
    /// Include re-exports (symbols imported and then exported)
    pub include_reexports: bool,
}

impl UnusedExportConfig {
    /// Create a new config with sensible defaults
    #[must_use]
    pub fn new() -> Self {
        Self {
            exclude_entry_points: true,
            exclude_patterns: Vec::new(),
            include_reexports: false,
        }
    }

    /// Check if a file should be excluded based on config
    #[must_use]
    pub fn should_exclude_file(&self, file_path: &str) -> bool {
        if self.exclude_entry_points {
            // Common entry point patterns
            let entry_points = [
                "lib.rs",
                "main.rs",
                "mod.rs",
                "index.js",
                "index.ts",
                "index.jsx",
                "index.tsx",
                "__init__.py",
                "setup.py",
                "main.go",
                "main.py",
                "main.java",
                "Program.cs",
                "Main.kt",
            ];

            for entry in &entry_points {
                if file_path.ends_with(entry) {
                    return true;
                }
            }
        }

        // Check exclude patterns (simple glob matching)
        for pattern in &self.exclude_patterns {
            if Self::matches_pattern(file_path, pattern) {
                return true;
            }
        }

        false
    }

    /// Simple glob pattern matching
    fn matches_pattern(path: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            // Handle wildcard patterns
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                let (prefix, suffix) = (parts[0], parts[1]);
                return path.starts_with(prefix) && path.ends_with(suffix);
            }
        }
        path.contains(pattern)
    }
}

impl UnusedExport {
    /// Create a new unused export finding
    #[must_use]
    pub fn new(
        file_path: &str,
        symbol_name: &str,
        symbol_kind: &str,
        line: usize,
        signature: Option<String>,
    ) -> Self {
        Self {
            file_path: file_path.to_string(),
            symbol_name: symbol_name.to_string(),
            symbol_kind: symbol_kind.to_string(),
            line,
            is_public_api: false,
            signature,
        }
    }
}

/// Report of unused exports across a repository
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnusedExportReport {
    /// All unused exports found
    pub unused_exports: Vec<UnusedExport>,
    /// Total exports analyzed
    pub total_exports: usize,
    /// Files analyzed
    pub files_analyzed: usize,
    /// Files excluded (entry points, patterns)
    pub files_excluded: usize,
}

impl UnusedExportReport {
    /// Create a new empty report
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if there are any findings
    #[must_use]
    pub fn has_findings(&self) -> bool {
        !self.unused_exports.is_empty()
    }

    /// Get count of unused exports
    #[must_use]
    pub fn count(&self) -> usize {
        self.unused_exports.len()
    }

    /// Format the report as markdown
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# Unused Export Analysis\n\n");

        md.push_str("## Summary\n\n");
        md.push_str(&format!("- **Files Analyzed**: {}\n", self.files_analyzed));
        md.push_str(&format!("- **Files Excluded**: {}\n", self.files_excluded));
        md.push_str(&format!("- **Total Exports**: {}\n", self.total_exports));
        md.push_str(&format!(
            "- **Unused Exports**: {}\n\n",
            self.unused_exports.len()
        ));

        if self.unused_exports.is_empty() {
            md.push_str("✅ No unused exports detected.\n");
        } else {
            md.push_str("## ⚠️ Unused Exports\n\n");
            md.push_str("| File | Symbol | Kind | Line |\n");
            md.push_str("|------|--------|------|------|\n");

            for export in &self.unused_exports {
                md.push_str(&format!(
                    "| `{}` | `{}` | {} | {} |\n",
                    export.file_path, export.symbol_name, export.symbol_kind, export.line
                ));
            }
        }

        md
    }
}

impl DeadCodeReport {
    /// Create a new empty report
    #[must_use]
    pub fn new(file_path: &str) -> Self {
        Self {
            file_path: file_path.to_string(),
            unreachable_blocks: Vec::new(),
            dead_stores: Vec::new(),
            unused_imports: Vec::new(),
        }
    }

    /// Check if the report has any findings
    #[must_use]
    pub fn has_findings(&self) -> bool {
        !self.unreachable_blocks.is_empty()
            || !self.dead_stores.is_empty()
            || !self.unused_imports.is_empty()
    }

    /// Get total count of all dead code findings
    #[must_use]
    pub fn total_findings(&self) -> usize {
        self.unreachable_blocks.len() + self.dead_stores.len() + self.unused_imports.len()
    }

    /// Format the report as markdown
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("# Dead Code Analysis: `{}`\n\n", self.file_path));

        // Summary
        md.push_str("## Summary\n\n");
        md.push_str(&format!(
            "- **Unreachable Blocks**: {}\n",
            self.unreachable_blocks.len()
        ));
        md.push_str(&format!("- **Dead Stores**: {}\n", self.dead_stores.len()));
        md.push_str(&format!(
            "- **Unused Imports**: {}\n\n",
            self.unused_imports.len()
        ));

        // Unreachable blocks
        if !self.unreachable_blocks.is_empty() {
            md.push_str("## ⚠️ Unreachable Code Blocks\n\n");
            for block in &self.unreachable_blocks {
                md.push_str(&format!(
                    "- `{}` block `{}` (lines {}-{})\n",
                    block.function_name, block.label, block.start_line, block.end_line
                ));
            }
            md.push('\n');
        }

        // Dead stores
        if !self.dead_stores.is_empty() {
            md.push_str("## ⚠️ Dead Stores\n\n");
            md.push_str("*Variables assigned but never read:*\n\n");
            for store in &self.dead_stores {
                md.push_str(&format!(
                    "- `{}::{}` line {}: `{}`\n",
                    store.function_name,
                    store.variable,
                    store.line,
                    truncate_text(&store.text, 60)
                ));
            }
            md.push('\n');
        }

        // Unused imports
        if !self.unused_imports.is_empty() {
            md.push_str("## ⚠️ Unused Imports\n\n");
            for import in &self.unused_imports {
                if import.symbols.is_empty() {
                    md.push_str(&format!(
                        "- Line {}: `{}` ({:?})\n",
                        import.line, import.import_path, import.import_type
                    ));
                } else {
                    md.push_str(&format!(
                        "- Line {}: `{}` - unused symbols: {}\n",
                        import.line,
                        import.import_path,
                        import.symbols.join(", ")
                    ));
                }
            }
            md.push('\n');
        }

        if !self.has_findings() {
            md.push_str("✅ No dead code detected.\n");
        }

        md
    }
}

/// Truncate text to a maximum length
fn truncate_text(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        format!("{}...", &text[..max_len])
    }
}

/// Find exported symbols that are never imported by other files in the repository
///
/// This performs cross-file analysis using the import graph to identify exports
/// that may be dead code at the repository level.
///
/// # Arguments
/// * `resolver` - Symbol resolver containing exports and imports data
/// * `repo_root` - Root path of the repository
/// * `config` - Configuration for the analysis
///
/// # Returns
/// A report of unused exports
///
/// # Examples
/// ```ignore
/// use narsil_mcp::dead_code::{find_unused_exports, UnusedExportConfig};
/// use narsil_mcp::incremental::SymbolResolver;
///
/// let resolver = SymbolResolver::new();
/// // ... populate resolver with file data ...
/// let config = UnusedExportConfig::new();
/// let report = find_unused_exports(&resolver, Path::new("/repo"), &config);
/// println!("{}", report.to_markdown());
/// ```
#[must_use]
pub fn find_unused_exports(
    exports: &HashMap<PathBuf, Vec<ExportedSymbol>>,
    imports: &HashMap<PathBuf, Vec<Import>>,
    repo_root: &Path,
    config: &UnusedExportConfig,
) -> UnusedExportReport {
    let mut report = UnusedExportReport::new();

    // Build set of all imported symbol names across the repository
    let mut imported_symbols: HashSet<String> = HashSet::new();
    for file_imports in imports.values() {
        for import in file_imports {
            for sym in &import.imported_symbols {
                // Use alias if present, otherwise use name
                let name = sym.alias.as_ref().unwrap_or(&sym.name);
                imported_symbols.insert(name.clone());
                // Also add the original name for matching
                imported_symbols.insert(sym.name.clone());
            }
            // For wildcard/default imports, we can't easily determine what's used
            // so we'll be conservative and skip analysis for those
        }
    }

    // Analyze each file's exports
    for (file_path, file_exports) in exports {
        // Convert path to relative for display
        let relative_path = file_path
            .strip_prefix(repo_root)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        // Check if file should be excluded
        if config.should_exclude_file(&relative_path) {
            report.files_excluded += 1;
            continue;
        }

        report.files_analyzed += 1;

        for export in file_exports {
            report.total_exports += 1;

            // Check if this export is ever imported by another file
            let is_used = imported_symbols.contains(&export.name);

            if !is_used && export.is_public {
                // This public export is never imported - potential unused export
                report.unused_exports.push(UnusedExport {
                    file_path: relative_path.clone(),
                    symbol_name: export.name.clone(),
                    symbol_kind: format!("{:?}", export.symbol.kind),
                    line: export.symbol.start_line,
                    is_public_api: false,
                    signature: export.symbol.signature.clone(),
                });
            }
        }
    }

    report
}

/// Find unused exports with direct access to SymbolResolver
///
/// # Arguments
/// * `resolver` - The symbol resolver with exports/imports data
/// * `repo_root` - Root path of the repository
/// * `config` - Configuration for analysis
///
/// # Returns
/// Report of unused exports
#[must_use]
pub fn find_unused_exports_from_resolver(
    resolver: &SymbolResolver,
    repo_root: &Path,
    config: &UnusedExportConfig,
) -> UnusedExportReport {
    find_unused_exports(
        resolver.get_exports(),
        resolver.get_imports(),
        repo_root,
        config,
    )
}

/// Analyze a file for all types of dead code
///
/// # Arguments
/// * `tree` - Parsed syntax tree
/// * `source` - Source code content
/// * `file_path` - Path to the file
///
/// # Returns
/// A comprehensive dead code report
///
/// # Errors
/// Returns an error if CFG or DFG analysis fails
pub fn analyze_dead_code(tree: &Tree, source: &str, file_path: &str) -> Result<DeadCodeReport> {
    let mut report = DeadCodeReport::new(file_path);

    // 1. Analyze CFGs for unreachable blocks
    let cfgs = cfg::analyze_function(tree, source, file_path)?;
    for cfg in &cfgs {
        for &block_id in &cfg.unreachable_blocks {
            if let Some(block) = cfg.blocks.get(&block_id) {
                report.unreachable_blocks.push(UnreachableBlock {
                    function_name: cfg.function_name.clone(),
                    block_id,
                    label: block.label.clone(),
                    start_line: block.start_line,
                    end_line: block.end_line,
                });
            }
        }
    }

    // 2. Analyze DFG for dead stores
    let dfg_analyses = dfg::analyze_file(tree, source, file_path)?;
    for analysis in &dfg_analyses {
        for dead_store in &analysis.dead_stores {
            // Find the definition text
            let text = analysis
                .definitions
                .iter()
                .find(|d| d.id == *dead_store)
                .map(|d| d.expression.clone())
                .unwrap_or_default();

            report.dead_stores.push(DeadStore {
                function_name: analysis.function_name.clone(),
                variable: dead_store.variable.clone(),
                line: dead_store.line,
                text,
            });
        }
    }

    // 3. Analyze unused imports
    let unused_imports = detect_unused_imports(tree, source, file_path)?;
    report.unused_imports = unused_imports;

    Ok(report)
}

/// Detect unused imports in a file
///
/// # Arguments
/// * `tree` - Parsed syntax tree
/// * `source` - Source code content
/// * `file_path` - Path to the file
///
/// # Returns
/// List of unused imports
///
/// # Errors
/// Returns an error if parsing fails
pub fn detect_unused_imports(
    tree: &Tree,
    source: &str,
    file_path: &str,
) -> Result<Vec<UnusedImport>> {
    let mut unused = Vec::new();

    // Determine language from file extension
    let extension = std::path::Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    match extension {
        "rs" => unused = detect_rust_unused_imports(tree, source)?,
        "py" | "pyi" => unused = detect_python_unused_imports(tree, source)?,
        "js" | "jsx" | "mjs" | "ts" | "tsx" => unused = detect_js_unused_imports(tree, source)?,
        "go" => unused = detect_go_unused_imports(tree, source)?,
        "java" => unused = detect_java_unused_imports(tree, source)?,
        "cs" => unused = detect_csharp_unused_imports(tree, source)?,
        "kt" | "kts" => unused = detect_kotlin_unused_imports(tree, source)?,
        _ => {} // Unsupported language
    }

    Ok(unused)
}

/// Detect unused Rust imports (use statements)
fn detect_rust_unused_imports(tree: &Tree, source: &str) -> Result<Vec<UnusedImport>> {
    let mut imports = Vec::new();
    let mut used_symbols: HashSet<String> = HashSet::new();

    // First pass: collect all identifiers used in the code (excluding import statements)
    collect_used_identifiers(tree.root_node(), source, &mut used_symbols, true);

    // Second pass: find all use statements and check if imported symbols are used
    find_rust_imports(tree.root_node(), source, &mut imports, &used_symbols);

    Ok(imports)
}

/// Collect all identifiers used in the code
fn collect_used_identifiers(
    node: tree_sitter::Node,
    source: &str,
    used: &mut HashSet<String>,
    skip_use_statements: bool,
) {
    // Skip use statements when collecting used identifiers
    if skip_use_statements && node.kind() == "use_declaration" {
        return;
    }

    // Collect identifiers (but not from use paths)
    if node.kind() == "identifier" || node.kind() == "type_identifier" {
        // Skip if this is part of a use path
        let mut parent = node.parent();
        let mut is_use_path = false;
        while let Some(p) = parent {
            if p.kind() == "use_declaration" || p.kind() == "scoped_use_list" {
                is_use_path = true;
                break;
            }
            parent = p.parent();
        }

        if !is_use_path {
            if let Ok(text) = node.utf8_text(source.as_bytes()) {
                used.insert(text.to_string());
            }
        }
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_used_identifiers(child, source, used, skip_use_statements);
    }
}

/// Find Rust import statements and check if they're used
fn find_rust_imports(
    node: tree_sitter::Node,
    source: &str,
    imports: &mut Vec<UnusedImport>,
    used_symbols: &HashSet<String>,
) {
    if node.kind() == "use_declaration" {
        let line = node.start_position().row + 1;
        let mut imported_symbols: Vec<String> = Vec::new();
        let mut import_path = String::new();

        // Extract the use path and imported names
        extract_rust_use_symbols(node, source, &mut imported_symbols, &mut import_path);

        // Check which symbols are unused
        let unused_symbols: Vec<String> = imported_symbols
            .into_iter()
            .filter(|s| !used_symbols.contains(s))
            .collect();

        if !unused_symbols.is_empty() {
            imports.push(UnusedImport {
                import_path,
                symbols: unused_symbols,
                line,
                import_type: ImportType::RustUse,
            });
        }
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_rust_imports(child, source, imports, used_symbols);
    }
}

/// Extract symbols from a Rust use statement
fn extract_rust_use_symbols(
    node: tree_sitter::Node,
    source: &str,
    symbols: &mut Vec<String>,
    path: &mut String,
) {
    match node.kind() {
        "use_declaration" => {
            // Get the full text for path
            if let Ok(text) = node.utf8_text(source.as_bytes()) {
                *path = text
                    .trim_start_matches("use ")
                    .trim_end_matches(';')
                    .to_string();
            }
            // Process children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                extract_rust_use_symbols(child, source, symbols, path);
            }
        }
        "identifier" | "type_identifier" => {
            // Check if this is a leaf identifier (actual import name, not path segment)
            if let Ok(text) = node.utf8_text(source.as_bytes()) {
                // Only add if it's not a path component
                let parent = node.parent();
                if let Some(p) = parent {
                    if p.kind() == "use_as_clause"
                        || p.kind() == "use_list"
                        || p.kind() == "use_declaration"
                    {
                        symbols.push(text.to_string());
                    }
                    // For simple use like `use foo::Bar;`, the last identifier is the imported symbol
                    if p.kind() == "scoped_identifier" {
                        // Check if this is the last child
                        if node.next_sibling().is_none() {
                            symbols.push(text.to_string());
                        }
                    }
                }
            }
        }
        "use_list" | "scoped_use_list" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                extract_rust_use_symbols(child, source, symbols, path);
            }
        }
        "use_as_clause" => {
            // For `use foo as bar`, we want to track 'bar'
            if let Some(alias) = node.child_by_field_name("alias") {
                if let Ok(text) = alias.utf8_text(source.as_bytes()) {
                    symbols.push(text.to_string());
                }
            }
            // Also need to recurse for the original name
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() != "identifier" || child.field_name_for_child(0).is_some() {
                    extract_rust_use_symbols(child, source, symbols, path);
                }
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                extract_rust_use_symbols(child, source, symbols, path);
            }
        }
    }
}

/// Detect unused Python imports
fn detect_python_unused_imports(tree: &Tree, source: &str) -> Result<Vec<UnusedImport>> {
    let mut imports = Vec::new();
    let mut used_symbols: HashSet<String> = HashSet::new();

    // Collect used identifiers
    collect_python_used_identifiers(tree.root_node(), source, &mut used_symbols);

    // Find imports and check if used
    find_python_imports(tree.root_node(), source, &mut imports, &used_symbols);

    Ok(imports)
}

/// Collect identifiers used in Python code
fn collect_python_used_identifiers(
    node: tree_sitter::Node,
    source: &str,
    used: &mut HashSet<String>,
) {
    // Skip import statements
    if node.kind() == "import_statement" || node.kind() == "import_from_statement" {
        return;
    }

    if node.kind() == "identifier" {
        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            used.insert(text.to_string());
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_python_used_identifiers(child, source, used);
    }
}

/// Find Python imports
fn find_python_imports(
    node: tree_sitter::Node,
    source: &str,
    imports: &mut Vec<UnusedImport>,
    used_symbols: &HashSet<String>,
) {
    match node.kind() {
        "import_statement" => {
            // import foo, bar
            let line = node.start_position().row + 1;
            let mut imported: Vec<String> = Vec::new();

            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "dotted_name" {
                    if let Ok(text) = child.utf8_text(source.as_bytes()) {
                        // For `import foo.bar`, the usable name is `foo`
                        let first_part = text.split('.').next().unwrap_or(text);
                        imported.push(first_part.to_string());
                    }
                } else if child.kind() == "aliased_import" {
                    // import foo as bar - check for alias
                    if let Some(alias) = child.child_by_field_name("alias") {
                        if let Ok(text) = alias.utf8_text(source.as_bytes()) {
                            imported.push(text.to_string());
                        }
                    }
                }
            }

            let unused: Vec<String> = imported
                .into_iter()
                .filter(|s| !used_symbols.contains(s))
                .collect();

            if !unused.is_empty() {
                if let Ok(path) = node.utf8_text(source.as_bytes()) {
                    imports.push(UnusedImport {
                        import_path: path.to_string(),
                        symbols: unused,
                        line,
                        import_type: ImportType::PythonImport,
                    });
                }
            }
        }
        "import_from_statement" => {
            // from foo import bar, baz
            let line = node.start_position().row + 1;
            let mut imported: Vec<String> = Vec::new();
            let mut module_name = String::new();

            // Extract module name and imported symbols recursively
            collect_python_from_import_symbols(node, source, &mut module_name, &mut imported);

            let unused: Vec<String> = imported
                .into_iter()
                .filter(|s| !used_symbols.contains(s))
                .collect();

            if !unused.is_empty() {
                imports.push(UnusedImport {
                    import_path: format!("from {} import ...", module_name),
                    symbols: unused,
                    line,
                    import_type: ImportType::PythonImport,
                });
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                find_python_imports(child, source, imports, used_symbols);
            }
        }
    }
}

/// Recursively collect symbols from a Python from...import statement
fn collect_python_from_import_symbols(
    node: tree_sitter::Node,
    source: &str,
    module_name: &mut String,
    imported: &mut Vec<String>,
) {
    // For import_from_statement:
    // Tree structure: import_from_statement -> from, dotted_name (module), import, dotted_name/identifier (symbols)
    // The first dotted_name after "from" is the module, subsequent dotted_name/identifiers are imports

    if node.kind() == "import_from_statement" {
        let mut found_import_keyword = false;
        let mut cursor = node.walk();

        for child in node.children(&mut cursor) {
            match child.kind() {
                "from" => {
                    // Skip the "from" keyword
                }
                "import" => {
                    // After seeing "import", everything following is an imported symbol
                    found_import_keyword = true;
                }
                "dotted_name" | "relative_import" => {
                    if !found_import_keyword {
                        // Before "import" keyword - this is the module name
                        if module_name.is_empty() {
                            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                                *module_name = text.to_string();
                            }
                        }
                    } else {
                        // After "import" keyword - these are imported symbols
                        // For "from pathlib import Path", Path is in a dotted_name
                        if let Ok(text) = child.utf8_text(source.as_bytes()) {
                            // Get the last part (for dotted imports like foo.bar, we want bar)
                            let symbol = text.split('.').next_back().unwrap_or(text);
                            imported.push(symbol.to_string());
                        }
                    }
                }
                "identifier" => {
                    if found_import_keyword {
                        if let Ok(text) = child.utf8_text(source.as_bytes()) {
                            imported.push(text.to_string());
                        }
                    }
                }
                "aliased_import" => {
                    // from foo import bar as baz
                    if let Some(alias) = child.child_by_field_name("alias") {
                        if let Ok(text) = alias.utf8_text(source.as_bytes()) {
                            imported.push(text.to_string());
                        }
                    } else {
                        // No alias, get the name
                        let mut inner_cursor = child.walk();
                        for inner_child in child.children(&mut inner_cursor) {
                            if inner_child.kind() == "identifier"
                                || inner_child.kind() == "dotted_name"
                            {
                                if let Ok(text) = inner_child.utf8_text(source.as_bytes()) {
                                    let symbol = text.split('.').next_back().unwrap_or(text);
                                    imported.push(symbol.to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
                "wildcard_import" => {
                    // from foo import * - skip these
                }
                _ => {
                    // For other nodes like parenthesized lists, recurse
                    collect_python_from_import_list(child, source, imported);
                }
            }
        }
    }
}

/// Helper to collect imported symbols from nested structures (parenthesized imports, etc.)
fn collect_python_from_import_list(
    node: tree_sitter::Node,
    source: &str,
    imported: &mut Vec<String>,
) {
    match node.kind() {
        "identifier" => {
            if let Ok(text) = node.utf8_text(source.as_bytes()) {
                imported.push(text.to_string());
            }
        }
        "dotted_name" => {
            if let Ok(text) = node.utf8_text(source.as_bytes()) {
                let symbol = text.split('.').next_back().unwrap_or(text);
                imported.push(symbol.to_string());
            }
        }
        "aliased_import" => {
            if let Some(alias) = node.child_by_field_name("alias") {
                if let Ok(text) = alias.utf8_text(source.as_bytes()) {
                    imported.push(text.to_string());
                }
            } else {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "identifier" || child.kind() == "dotted_name" {
                        if let Ok(text) = child.utf8_text(source.as_bytes()) {
                            let symbol = text.split('.').next_back().unwrap_or(text);
                            imported.push(symbol.to_string());
                            break;
                        }
                    }
                }
            }
        }
        _ => {
            // Recurse into children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_python_from_import_list(child, source, imported);
            }
        }
    }
}

/// Detect unused JavaScript/TypeScript imports
fn detect_js_unused_imports(tree: &Tree, source: &str) -> Result<Vec<UnusedImport>> {
    let mut imports = Vec::new();
    let mut used_symbols: HashSet<String> = HashSet::new();

    // Collect used identifiers
    collect_js_used_identifiers(tree.root_node(), source, &mut used_symbols);

    // Find imports
    find_js_imports(tree.root_node(), source, &mut imports, &used_symbols);

    Ok(imports)
}

/// Collect identifiers used in JS/TS code
fn collect_js_used_identifiers(node: tree_sitter::Node, source: &str, used: &mut HashSet<String>) {
    // Skip import statements
    if node.kind() == "import_statement" {
        return;
    }

    if node.kind() == "identifier" {
        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            used.insert(text.to_string());
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_js_used_identifiers(child, source, used);
    }
}

/// Find JS/TS imports
fn find_js_imports(
    node: tree_sitter::Node,
    source: &str,
    imports: &mut Vec<UnusedImport>,
    used_symbols: &HashSet<String>,
) {
    if node.kind() == "import_statement" {
        let line = node.start_position().row + 1;
        let mut imported: Vec<String> = Vec::new();
        let mut import_path = String::new();

        // Get the source string
        if let Some(source_node) = node.child_by_field_name("source") {
            if let Ok(text) = source_node.utf8_text(source.as_bytes()) {
                import_path = text.trim_matches(|c| c == '\'' || c == '"').to_string();
            }
        }

        // Collect imported names
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            collect_js_import_specifiers(child, source, &mut imported);
        }

        let unused: Vec<String> = imported
            .into_iter()
            .filter(|s| !used_symbols.contains(s))
            .collect();

        if !unused.is_empty() {
            imports.push(UnusedImport {
                import_path,
                symbols: unused,
                line,
                import_type: ImportType::JsImport,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_js_imports(child, source, imports, used_symbols);
    }
}

/// Collect JS import specifiers
fn collect_js_import_specifiers(node: tree_sitter::Node, source: &str, imported: &mut Vec<String>) {
    match node.kind() {
        "import_specifier" => {
            // For `import { foo as bar }` or `import { foo }`
            if let Some(alias) = node.child_by_field_name("alias") {
                if let Ok(text) = alias.utf8_text(source.as_bytes()) {
                    imported.push(text.to_string());
                }
            } else if let Some(name) = node.child_by_field_name("name") {
                if let Ok(text) = name.utf8_text(source.as_bytes()) {
                    imported.push(text.to_string());
                }
            }
        }
        "identifier" => {
            // Default import
            let parent = node.parent();
            if let Some(p) = parent {
                if p.kind() == "import_clause" {
                    if let Ok(text) = node.utf8_text(source.as_bytes()) {
                        imported.push(text.to_string());
                    }
                }
            }
        }
        "namespace_import" => {
            // import * as foo
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "identifier" {
                    if let Ok(text) = child.utf8_text(source.as_bytes()) {
                        imported.push(text.to_string());
                    }
                }
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_js_import_specifiers(child, source, imported);
            }
        }
    }
}

/// Detect unused Go imports
fn detect_go_unused_imports(tree: &Tree, source: &str) -> Result<Vec<UnusedImport>> {
    let mut imports = Vec::new();
    let mut used_symbols: HashSet<String> = HashSet::new();

    // Collect used package references
    collect_go_used_identifiers(tree.root_node(), source, &mut used_symbols);

    // Find imports
    find_go_imports(tree.root_node(), source, &mut imports, &used_symbols);

    Ok(imports)
}

/// Collect identifiers used in Go code
fn collect_go_used_identifiers(node: tree_sitter::Node, source: &str, used: &mut HashSet<String>) {
    // Skip import declarations
    if node.kind() == "import_declaration" || node.kind() == "import_spec" {
        return;
    }

    // In Go, we care about qualified identifiers like `fmt.Println`
    if node.kind() == "selector_expression" {
        if let Some(operand) = node.child_by_field_name("operand") {
            if operand.kind() == "identifier" {
                if let Ok(text) = operand.utf8_text(source.as_bytes()) {
                    used.insert(text.to_string());
                }
            }
        }
    } else if node.kind() == "identifier" {
        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            used.insert(text.to_string());
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_go_used_identifiers(child, source, used);
    }
}

/// Find Go imports
fn find_go_imports(
    node: tree_sitter::Node,
    source: &str,
    imports: &mut Vec<UnusedImport>,
    used_symbols: &HashSet<String>,
) {
    if node.kind() == "import_spec" {
        let line = node.start_position().row + 1;

        // Get the package path
        if let Some(path_node) = node.child_by_field_name("path") {
            if let Ok(path) = path_node.utf8_text(source.as_bytes()) {
                let path = path.trim_matches('"');

                // Get the alias or derive package name from path
                let package_name = if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                        if name == "_" {
                            // Blank import, skip
                            return;
                        }
                        name.to_string()
                    } else {
                        // Use last part of path
                        path.split('/').next_back().unwrap_or(path).to_string()
                    }
                } else {
                    // Use last part of path
                    path.split('/').next_back().unwrap_or(path).to_string()
                };

                if !used_symbols.contains(&package_name) {
                    imports.push(UnusedImport {
                        import_path: path.to_string(),
                        symbols: vec![package_name],
                        line,
                        import_type: ImportType::GoImport,
                    });
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_go_imports(child, source, imports, used_symbols);
    }
}

/// Detect unused Java imports
fn detect_java_unused_imports(tree: &Tree, source: &str) -> Result<Vec<UnusedImport>> {
    let mut imports = Vec::new();
    let mut used_symbols: HashSet<String> = HashSet::new();

    // Collect used type names
    collect_java_used_identifiers(tree.root_node(), source, &mut used_symbols);

    // Find imports
    find_java_imports(tree.root_node(), source, &mut imports, &used_symbols);

    Ok(imports)
}

/// Collect identifiers used in Java code
fn collect_java_used_identifiers(
    node: tree_sitter::Node,
    source: &str,
    used: &mut HashSet<String>,
) {
    // Skip import declarations
    if node.kind() == "import_declaration" {
        return;
    }

    if node.kind() == "identifier" || node.kind() == "type_identifier" {
        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            used.insert(text.to_string());
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_java_used_identifiers(child, source, used);
    }
}

/// Find Java imports
fn find_java_imports(
    node: tree_sitter::Node,
    source: &str,
    imports: &mut Vec<UnusedImport>,
    used_symbols: &HashSet<String>,
) {
    if node.kind() == "import_declaration" {
        let line = node.start_position().row + 1;

        // Check if it's a static import or wildcard
        let _is_static = node
            .children(&mut node.walk())
            .any(|c| c.kind() == "static");

        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            let text = text.trim();
            // Skip wildcard imports
            if text.contains(".*") {
                return;
            }

            // Extract the class name (last part of the import)
            let import_path = text
                .trim_start_matches("import ")
                .trim_start_matches("static ")
                .trim_end_matches(';')
                .trim();

            let class_name = import_path
                .split('.')
                .next_back()
                .unwrap_or(import_path)
                .to_string();

            if !used_symbols.contains(&class_name) {
                imports.push(UnusedImport {
                    import_path: import_path.to_string(),
                    symbols: vec![class_name],
                    line,
                    import_type: ImportType::JavaImport,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_java_imports(child, source, imports, used_symbols);
    }
}

/// Detect unused C# usings
fn detect_csharp_unused_imports(tree: &Tree, source: &str) -> Result<Vec<UnusedImport>> {
    let mut imports = Vec::new();
    let mut used_symbols: HashSet<String> = HashSet::new();

    // Collect used type names
    collect_csharp_used_identifiers(tree.root_node(), source, &mut used_symbols);

    // Find usings
    find_csharp_usings(tree.root_node(), source, &mut imports, &used_symbols);

    Ok(imports)
}

/// Collect identifiers used in C# code
fn collect_csharp_used_identifiers(
    node: tree_sitter::Node,
    source: &str,
    used: &mut HashSet<String>,
) {
    // Skip using directives
    if node.kind() == "using_directive" {
        return;
    }

    if node.kind() == "identifier" {
        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            used.insert(text.to_string());
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_csharp_used_identifiers(child, source, used);
    }
}

/// Find C# using directives
fn find_csharp_usings(
    node: tree_sitter::Node,
    source: &str,
    imports: &mut Vec<UnusedImport>,
    _used_symbols: &HashSet<String>,
) {
    if node.kind() == "using_directive" {
        let line = node.start_position().row + 1;

        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            let text = text.trim();

            // Extract namespace
            let ns = text
                .trim_start_matches("using ")
                .trim_end_matches(';')
                .trim();

            // C# using directives import entire namespaces, harder to detect unused
            // For now, we just record them - proper detection requires type resolution
            // This is a simplified version that may have false positives
            imports.push(UnusedImport {
                import_path: ns.to_string(),
                symbols: Vec::new(),
                line,
                import_type: ImportType::CSharpUsing,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_csharp_usings(child, source, imports, _used_symbols);
    }
}

/// Detect unused Kotlin imports
fn detect_kotlin_unused_imports(tree: &Tree, source: &str) -> Result<Vec<UnusedImport>> {
    let mut imports = Vec::new();
    let mut used_symbols: HashSet<String> = HashSet::new();

    // Collect used identifiers
    collect_kotlin_used_identifiers(tree.root_node(), source, &mut used_symbols);

    // Find imports
    find_kotlin_imports(tree.root_node(), source, &mut imports, &used_symbols);

    Ok(imports)
}

/// Collect identifiers used in Kotlin code
fn collect_kotlin_used_identifiers(
    node: tree_sitter::Node,
    source: &str,
    used: &mut HashSet<String>,
) {
    // Skip import statements
    if node.kind() == "import_header" || node.kind() == "import_list" {
        return;
    }

    if node.kind() == "simple_identifier" {
        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            used.insert(text.to_string());
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_kotlin_used_identifiers(child, source, used);
    }
}

/// Find Kotlin imports
fn find_kotlin_imports(
    node: tree_sitter::Node,
    source: &str,
    imports: &mut Vec<UnusedImport>,
    used_symbols: &HashSet<String>,
) {
    if node.kind() == "import_header" {
        let line = node.start_position().row + 1;

        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            let text = text.trim();

            // Skip wildcard imports
            if text.contains(".*") {
                return;
            }

            let import_path = text.trim_start_matches("import ").trim();

            // Get the last part (class/function name)
            let name = import_path
                .split('.')
                .next_back()
                .unwrap_or(import_path)
                .to_string();

            if !used_symbols.contains(&name) {
                imports.push(UnusedImport {
                    import_path: import_path.to_string(),
                    symbols: vec![name],
                    line,
                    import_type: ImportType::KotlinImport,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_kotlin_imports(child, source, imports, used_symbols);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==== DeadCodeReport Tests ====

    #[test]
    fn test_dead_code_report_new() {
        let report = DeadCodeReport::new("test.rs");
        assert_eq!(report.file_path, "test.rs");
        assert!(report.unreachable_blocks.is_empty());
        assert!(report.dead_stores.is_empty());
        assert!(report.unused_imports.is_empty());
    }

    #[test]
    fn test_dead_code_report_has_findings_empty() {
        let report = DeadCodeReport::new("test.rs");
        assert!(!report.has_findings());
    }

    #[test]
    fn test_dead_code_report_has_findings_with_unreachable() {
        let mut report = DeadCodeReport::new("test.rs");
        report.unreachable_blocks.push(UnreachableBlock {
            function_name: "test".to_string(),
            block_id: 0,
            label: "block".to_string(),
            start_line: 1,
            end_line: 2,
        });
        assert!(report.has_findings());
    }

    #[test]
    fn test_dead_code_report_has_findings_with_dead_stores() {
        let mut report = DeadCodeReport::new("test.rs");
        report.dead_stores.push(DeadStore {
            function_name: "test".to_string(),
            variable: "x".to_string(),
            line: 1,
            text: "let x = 5".to_string(),
        });
        assert!(report.has_findings());
    }

    #[test]
    fn test_dead_code_report_has_findings_with_unused_imports() {
        let mut report = DeadCodeReport::new("test.rs");
        report.unused_imports.push(UnusedImport {
            import_path: "std::fs".to_string(),
            symbols: vec!["File".to_string()],
            line: 1,
            import_type: ImportType::RustUse,
        });
        assert!(report.has_findings());
    }

    #[test]
    fn test_dead_code_report_total_findings() {
        let mut report = DeadCodeReport::new("test.rs");
        report.unreachable_blocks.push(UnreachableBlock {
            function_name: "test".to_string(),
            block_id: 0,
            label: "block".to_string(),
            start_line: 1,
            end_line: 2,
        });
        report.dead_stores.push(DeadStore {
            function_name: "test".to_string(),
            variable: "x".to_string(),
            line: 1,
            text: "let x = 5".to_string(),
        });
        report.unused_imports.push(UnusedImport {
            import_path: "std::fs".to_string(),
            symbols: vec!["File".to_string()],
            line: 1,
            import_type: ImportType::RustUse,
        });
        assert_eq!(report.total_findings(), 3);
    }

    #[test]
    fn test_dead_code_report_to_markdown_empty() {
        let report = DeadCodeReport::new("test.rs");
        let md = report.to_markdown();
        assert!(md.contains("Dead Code Analysis"));
        assert!(md.contains("test.rs"));
        assert!(md.contains("No dead code detected"));
    }

    #[test]
    fn test_dead_code_report_to_markdown_with_findings() {
        let mut report = DeadCodeReport::new("test.rs");
        report.dead_stores.push(DeadStore {
            function_name: "foo".to_string(),
            variable: "unused_var".to_string(),
            line: 10,
            text: "let unused_var = 5".to_string(),
        });
        let md = report.to_markdown();
        assert!(md.contains("Dead Stores"));
        assert!(md.contains("unused_var"));
        assert!(md.contains("line 10"));
    }

    #[test]
    fn test_truncate_text_short() {
        assert_eq!(truncate_text("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_text_long() {
        assert_eq!(truncate_text("hello world", 5), "hello...");
    }

    // ==== Rust Unused Import Tests ====

    #[test]
    fn test_rust_unused_import_detection() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();

        let source = r#"
use std::fs::File;
use std::io::Read;

fn main() {
    let x = 5;
}
"#;

        let tree = parser.parse(source, None).unwrap();
        let unused = detect_rust_unused_imports(&tree, source).unwrap();

        // Both File and Read should be detected as unused
        assert!(
            unused
                .iter()
                .any(|u| u.symbols.contains(&"File".to_string())),
            "Should detect 'File' as unused"
        );
        assert!(
            unused
                .iter()
                .any(|u| u.symbols.contains(&"Read".to_string())),
            "Should detect 'Read' as unused"
        );
    }

    #[test]
    fn test_rust_used_import_not_reported() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();

        let source = r#"
use std::fs::File;

fn main() {
    let _f = File::open("test.txt");
}
"#;

        let tree = parser.parse(source, None).unwrap();
        let unused = detect_rust_unused_imports(&tree, source).unwrap();

        // File is used, should not be in unused list
        assert!(
            !unused
                .iter()
                .any(|u| u.symbols.contains(&"File".to_string())),
            "Should NOT report 'File' as unused when it's used"
        );
    }

    // ==== Python Unused Import Tests ====

    #[test]
    fn test_python_unused_import_detection() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();

        let source = r#"
import os
import sys
from pathlib import Path

def main():
    print(os.getcwd())
"#;

        let tree = parser.parse(source, None).unwrap();
        let unused = detect_python_unused_imports(&tree, source).unwrap();

        // sys and Path should be unused, os is used
        assert!(
            unused
                .iter()
                .any(|u| u.symbols.contains(&"sys".to_string())),
            "Should detect 'sys' as unused"
        );
        assert!(
            unused
                .iter()
                .any(|u| u.symbols.contains(&"Path".to_string())),
            "Should detect 'Path' as unused"
        );
        assert!(
            !unused.iter().any(|u| u.symbols.contains(&"os".to_string())),
            "Should NOT report 'os' as unused"
        );
    }

    // ==== JavaScript/TypeScript Unused Import Tests ====

    #[test]
    fn test_js_unused_import_detection() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();

        let source = r#"
import { useState, useEffect } from 'react';
import axios from 'axios';

function App() {
    const [count, setCount] = useState(0);
    return count;
}
"#;

        let tree = parser.parse(source, None).unwrap();
        let unused = detect_js_unused_imports(&tree, source).unwrap();

        // useEffect and axios should be unused
        assert!(
            unused
                .iter()
                .any(|u| u.symbols.contains(&"useEffect".to_string())),
            "Should detect 'useEffect' as unused"
        );
        assert!(
            unused
                .iter()
                .any(|u| u.symbols.contains(&"axios".to_string())),
            "Should detect 'axios' as unused"
        );
    }

    // ==== Go Unused Import Tests ====

    #[test]
    fn test_go_unused_import_detection() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .unwrap();

        let source = r#"
package main

import (
    "fmt"
    "os"
)

func main() {
    fmt.Println("hello")
}
"#;

        let tree = parser.parse(source, None).unwrap();
        let unused = detect_go_unused_imports(&tree, source).unwrap();

        // os should be unused
        assert!(
            unused.iter().any(|u| u.symbols.contains(&"os".to_string())),
            "Should detect 'os' as unused. Found: {:?}",
            unused
        );
        // fmt is used
        assert!(
            !unused
                .iter()
                .any(|u| u.symbols.contains(&"fmt".to_string())),
            "Should NOT report 'fmt' as unused"
        );
    }

    // ==== Java Unused Import Tests ====

    #[test]
    fn test_java_unused_import_detection() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();

        let source = r#"
import java.util.List;
import java.util.ArrayList;
import java.io.File;

public class Test {
    public void example() {
        List<String> items = new ArrayList<>();
    }
}
"#;

        let tree = parser.parse(source, None).unwrap();
        let unused = detect_java_unused_imports(&tree, source).unwrap();

        // File should be unused
        assert!(
            unused
                .iter()
                .any(|u| u.symbols.contains(&"File".to_string())),
            "Should detect 'File' as unused. Found: {:?}",
            unused
        );
    }

    // ==== Integration Tests ====

    #[test]
    fn test_analyze_dead_code_rust() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();

        let source = r#"
use std::fs::File;

fn example() {
    let unused = 5;
    let x = 10;
    return x;
}
"#;

        let tree = parser.parse(source, None).unwrap();
        let report = analyze_dead_code(&tree, source, "test.rs").unwrap();

        // Should have dead store for 'unused'
        assert!(
            report.dead_stores.iter().any(|d| d.variable == "unused"),
            "Should detect 'unused' as dead store"
        );

        // Should have unused import for 'File'
        assert!(
            report
                .unused_imports
                .iter()
                .any(|u| u.symbols.contains(&"File".to_string())),
            "Should detect 'File' as unused import"
        );
    }

    #[test]
    fn test_analyze_dead_code_python() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();

        let source = r#"
import os
import unused_module

def example():
    unused = 5
    x = 10
    return x
"#;

        let tree = parser.parse(source, None).unwrap();
        let report = analyze_dead_code(&tree, source, "test.py").unwrap();

        // Should detect dead store
        assert!(
            report.dead_stores.iter().any(|d| d.variable == "unused"),
            "Should detect 'unused' as dead store"
        );

        // Should detect unused import
        assert!(
            report
                .unused_imports
                .iter()
                .any(|u| u.symbols.contains(&"unused_module".to_string())),
            "Should detect 'unused_module' as unused import"
        );
    }

    #[test]
    fn test_analyze_dead_code_go() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .unwrap();

        let source = r#"
package main

import (
    "fmt"
    "unused"
)

func example() int {
    unused := 5
    x := 10
    fmt.Println(x)
    return x
}
"#;

        let tree = parser.parse(source, None).unwrap();
        let report = analyze_dead_code(&tree, source, "test.go").unwrap();

        // Should have findings
        assert!(report.has_findings(), "Should have some findings");
    }

    #[test]
    fn test_import_type_equality() {
        assert_eq!(ImportType::RustUse, ImportType::RustUse);
        assert_ne!(ImportType::RustUse, ImportType::PythonImport);
        assert_ne!(ImportType::GoImport, ImportType::JavaImport);
    }

    // ==== Unused Export Detection Tests ====

    use crate::incremental::{ExportedSymbol, Import, ImportType as IncImportType, ImportedSymbol};
    use crate::symbols::{Symbol, SymbolKind as SymKind};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn make_test_symbol(name: &str, kind: SymKind, line: usize) -> Symbol {
        Symbol {
            name: name.to_string(),
            kind,
            file_path: "test.rs".to_string(),
            start_line: line,
            end_line: line + 5,
            signature: Some(format!("pub fn {}()", name)),
            qualified_name: Some(name.to_string()),
            doc_comment: None,
        }
    }

    fn make_exported_symbol(
        name: &str,
        kind: SymKind,
        line: usize,
        is_public: bool,
    ) -> ExportedSymbol {
        ExportedSymbol {
            name: name.to_string(),
            symbol: make_test_symbol(name, kind, line),
            is_default: false,
            is_public,
        }
    }

    fn make_import(source_file: &str, import_path: &str, symbols: Vec<&str>) -> Import {
        Import {
            source_file: PathBuf::from(source_file),
            import_path: import_path.to_string(),
            imported_symbols: symbols
                .into_iter()
                .map(|s| ImportedSymbol {
                    name: s.to_string(),
                    alias: None,
                    is_default: false,
                })
                .collect(),
            import_type: IncImportType::Rust,
            line: 1,
        }
    }

    #[test]
    fn test_unused_export_config_new() {
        let config = UnusedExportConfig::new();
        assert!(config.exclude_entry_points);
        assert!(config.exclude_patterns.is_empty());
        assert!(!config.include_reexports);
    }

    #[test]
    fn test_unused_export_config_excludes_entry_points() {
        let config = UnusedExportConfig::new();

        // Common Rust entry points
        assert!(config.should_exclude_file("src/lib.rs"));
        assert!(config.should_exclude_file("src/main.rs"));
        assert!(config.should_exclude_file("src/module/mod.rs"));

        // Common JS entry points
        assert!(config.should_exclude_file("src/index.js"));
        assert!(config.should_exclude_file("src/index.ts"));
        assert!(config.should_exclude_file("components/index.tsx"));

        // Python entry points
        assert!(config.should_exclude_file("package/__init__.py"));
        assert!(config.should_exclude_file("main.py"));

        // Other language entry points
        assert!(config.should_exclude_file("cmd/main.go"));
        assert!(config.should_exclude_file("src/Program.cs"));
        assert!(config.should_exclude_file("src/Main.kt"));

        // Non-entry point files should not be excluded
        assert!(!config.should_exclude_file("src/utils.rs"));
        assert!(!config.should_exclude_file("src/helper.js"));
        assert!(!config.should_exclude_file("src/models.py"));
    }

    #[test]
    fn test_unused_export_config_exclude_patterns() {
        let config = UnusedExportConfig {
            exclude_entry_points: false,
            exclude_patterns: vec!["api/*".to_string(), "public/".to_string()],
            include_reexports: false,
        };

        assert!(config.should_exclude_file("api/routes.rs"));
        assert!(config.should_exclude_file("public/types.ts"));
        assert!(!config.should_exclude_file("internal/utils.rs"));
    }

    #[test]
    fn test_unused_export_config_disabled_entry_points() {
        let config = UnusedExportConfig {
            exclude_entry_points: false,
            exclude_patterns: Vec::new(),
            include_reexports: false,
        };

        // Entry points should NOT be excluded when disabled
        assert!(!config.should_exclude_file("src/lib.rs"));
        assert!(!config.should_exclude_file("index.js"));
    }

    #[test]
    fn test_unused_export_new() {
        let export = UnusedExport::new(
            "src/utils.rs",
            "helper_fn",
            "Function",
            10,
            Some("pub fn helper_fn()".to_string()),
        );

        assert_eq!(export.file_path, "src/utils.rs");
        assert_eq!(export.symbol_name, "helper_fn");
        assert_eq!(export.symbol_kind, "Function");
        assert_eq!(export.line, 10);
        assert!(!export.is_public_api);
        assert_eq!(export.signature, Some("pub fn helper_fn()".to_string()));
    }

    #[test]
    fn test_unused_export_report_new() {
        let report = UnusedExportReport::new();
        assert!(report.unused_exports.is_empty());
        assert_eq!(report.total_exports, 0);
        assert_eq!(report.files_analyzed, 0);
        assert_eq!(report.files_excluded, 0);
    }

    #[test]
    fn test_unused_export_report_has_findings() {
        let mut report = UnusedExportReport::new();
        assert!(!report.has_findings());

        report.unused_exports.push(UnusedExport::new(
            "test.rs",
            "unused_fn",
            "Function",
            1,
            None,
        ));
        assert!(report.has_findings());
    }

    #[test]
    fn test_unused_export_report_count() {
        let mut report = UnusedExportReport::new();
        assert_eq!(report.count(), 0);

        report
            .unused_exports
            .push(UnusedExport::new("a.rs", "fn1", "Function", 1, None));
        report
            .unused_exports
            .push(UnusedExport::new("b.rs", "fn2", "Function", 2, None));
        assert_eq!(report.count(), 2);
    }

    #[test]
    fn test_unused_export_report_to_markdown_empty() {
        let report = UnusedExportReport::new();
        let md = report.to_markdown();

        assert!(md.contains("Unused Export Analysis"));
        assert!(md.contains("No unused exports detected"));
        assert!(md.contains("Total Exports**: 0"));
    }

    #[test]
    fn test_unused_export_report_to_markdown_with_findings() {
        let mut report = UnusedExportReport::new();
        report.files_analyzed = 5;
        report.files_excluded = 2;
        report.total_exports = 10;
        report.unused_exports.push(UnusedExport::new(
            "src/utils.rs",
            "dead_function",
            "Function",
            42,
            None,
        ));

        let md = report.to_markdown();
        assert!(md.contains("Files Analyzed**: 5"));
        assert!(md.contains("Files Excluded**: 2"));
        assert!(md.contains("Total Exports**: 10"));
        assert!(md.contains("Unused Exports**: 1"));
        assert!(md.contains("dead_function"));
        assert!(md.contains("utils.rs"));
        assert!(md.contains("42"));
    }

    #[test]
    fn test_find_unused_exports_empty() {
        let exports: HashMap<PathBuf, Vec<ExportedSymbol>> = HashMap::new();
        let imports: HashMap<PathBuf, Vec<Import>> = HashMap::new();
        let config = UnusedExportConfig::new();

        let report = find_unused_exports(&exports, &imports, Path::new("/repo"), &config);

        assert!(!report.has_findings());
        assert_eq!(report.files_analyzed, 0);
        assert_eq!(report.total_exports, 0);
    }

    #[test]
    fn test_find_unused_exports_all_used() {
        // Setup: file_a exports "foo", file_b imports "foo"
        let mut exports: HashMap<PathBuf, Vec<ExportedSymbol>> = HashMap::new();
        exports.insert(
            PathBuf::from("/repo/src/utils.rs"),
            vec![make_exported_symbol("foo", SymKind::Function, 10, true)],
        );

        let mut imports: HashMap<PathBuf, Vec<Import>> = HashMap::new();
        imports.insert(
            PathBuf::from("/repo/src/main.rs"),
            vec![make_import("src/main.rs", "crate::utils", vec!["foo"])],
        );

        let config = UnusedExportConfig {
            exclude_entry_points: false,
            exclude_patterns: Vec::new(),
            include_reexports: false,
        };

        let report = find_unused_exports(&exports, &imports, Path::new("/repo"), &config);

        // "foo" is imported, so no unused exports
        assert!(!report.has_findings());
        assert_eq!(report.total_exports, 1);
    }

    #[test]
    fn test_find_unused_exports_detects_unused() {
        // Setup: file_a exports "foo" and "bar", file_b only imports "foo"
        let mut exports: HashMap<PathBuf, Vec<ExportedSymbol>> = HashMap::new();
        exports.insert(
            PathBuf::from("/repo/src/utils.rs"),
            vec![
                make_exported_symbol("foo", SymKind::Function, 10, true),
                make_exported_symbol("bar", SymKind::Function, 20, true),
            ],
        );

        let mut imports: HashMap<PathBuf, Vec<Import>> = HashMap::new();
        imports.insert(
            PathBuf::from("/repo/src/other.rs"),
            vec![make_import("src/other.rs", "crate::utils", vec!["foo"])],
        );

        let config = UnusedExportConfig {
            exclude_entry_points: false,
            exclude_patterns: Vec::new(),
            include_reexports: false,
        };

        let report = find_unused_exports(&exports, &imports, Path::new("/repo"), &config);

        // "bar" is not imported, should be detected as unused
        assert!(report.has_findings());
        assert_eq!(report.count(), 1);
        assert!(report.unused_exports.iter().any(|e| e.symbol_name == "bar"));
        assert!(!report.unused_exports.iter().any(|e| e.symbol_name == "foo"));
    }

    #[test]
    fn test_find_unused_exports_excludes_entry_points() {
        // Setup: lib.rs exports "foo" which is never imported
        let mut exports: HashMap<PathBuf, Vec<ExportedSymbol>> = HashMap::new();
        exports.insert(
            PathBuf::from("/repo/src/lib.rs"),
            vec![make_exported_symbol("foo", SymKind::Function, 10, true)],
        );

        let imports: HashMap<PathBuf, Vec<Import>> = HashMap::new();

        let config = UnusedExportConfig::new(); // exclude_entry_points = true

        let report = find_unused_exports(&exports, &imports, Path::new("/repo"), &config);

        // lib.rs is excluded, so no unused exports should be reported
        assert!(!report.has_findings());
        assert_eq!(report.files_excluded, 1);
        assert_eq!(report.files_analyzed, 0);
    }

    #[test]
    fn test_find_unused_exports_private_not_reported() {
        // Setup: file exports private symbol (is_public = false)
        let mut exports: HashMap<PathBuf, Vec<ExportedSymbol>> = HashMap::new();
        exports.insert(
            PathBuf::from("/repo/src/utils.rs"),
            vec![make_exported_symbol(
                "private_fn",
                SymKind::Function,
                10,
                false,
            )],
        );

        let imports: HashMap<PathBuf, Vec<Import>> = HashMap::new();

        let config = UnusedExportConfig {
            exclude_entry_points: false,
            exclude_patterns: Vec::new(),
            include_reexports: false,
        };

        let report = find_unused_exports(&exports, &imports, Path::new("/repo"), &config);

        // Private symbols should not be reported as unused exports
        assert!(!report.has_findings());
    }

    #[test]
    fn test_find_unused_exports_with_aliases() {
        // Setup: file_a exports "foo", file_b imports "foo as bar"
        let mut exports: HashMap<PathBuf, Vec<ExportedSymbol>> = HashMap::new();
        exports.insert(
            PathBuf::from("/repo/src/utils.rs"),
            vec![make_exported_symbol("foo", SymKind::Function, 10, true)],
        );

        let mut imports: HashMap<PathBuf, Vec<Import>> = HashMap::new();
        imports.insert(
            PathBuf::from("/repo/src/other.rs"),
            vec![Import {
                source_file: PathBuf::from("src/other.rs"),
                import_path: "crate::utils".to_string(),
                imported_symbols: vec![ImportedSymbol {
                    name: "foo".to_string(),
                    alias: Some("bar".to_string()),
                    is_default: false,
                }],
                import_type: IncImportType::Rust,
                line: 1,
            }],
        );

        let config = UnusedExportConfig {
            exclude_entry_points: false,
            exclude_patterns: Vec::new(),
            include_reexports: false,
        };

        let report = find_unused_exports(&exports, &imports, Path::new("/repo"), &config);

        // "foo" is imported (even though aliased as "bar"), so not unused
        assert!(!report.has_findings());
    }

    #[test]
    fn test_find_unused_exports_multiple_files() {
        // Setup: Multiple files with multiple exports
        let mut exports: HashMap<PathBuf, Vec<ExportedSymbol>> = HashMap::new();
        exports.insert(
            PathBuf::from("/repo/src/a.rs"),
            vec![
                make_exported_symbol("used_from_a", SymKind::Function, 1, true),
                make_exported_symbol("unused_from_a", SymKind::Function, 10, true),
            ],
        );
        exports.insert(
            PathBuf::from("/repo/src/b.rs"),
            vec![
                make_exported_symbol("used_from_b", SymKind::Struct, 1, true),
                make_exported_symbol("also_unused", SymKind::Struct, 10, true),
            ],
        );

        let mut imports: HashMap<PathBuf, Vec<Import>> = HashMap::new();
        imports.insert(
            PathBuf::from("/repo/src/c.rs"),
            vec![
                make_import("src/c.rs", "crate::a", vec!["used_from_a"]),
                make_import("src/c.rs", "crate::b", vec!["used_from_b"]),
            ],
        );

        let config = UnusedExportConfig {
            exclude_entry_points: false,
            exclude_patterns: Vec::new(),
            include_reexports: false,
        };

        let report = find_unused_exports(&exports, &imports, Path::new("/repo"), &config);

        assert!(report.has_findings());
        assert_eq!(report.count(), 2);
        assert_eq!(report.files_analyzed, 2);
        assert_eq!(report.total_exports, 4);

        let unused_names: Vec<_> = report
            .unused_exports
            .iter()
            .map(|e| e.symbol_name.as_str())
            .collect();
        assert!(unused_names.contains(&"unused_from_a"));
        assert!(unused_names.contains(&"also_unused"));
        assert!(!unused_names.contains(&"used_from_a"));
        assert!(!unused_names.contains(&"used_from_b"));
    }

    #[test]
    fn test_find_unused_exports_with_exclude_patterns() {
        // Setup: exports in api/ directory should be excluded
        let mut exports: HashMap<PathBuf, Vec<ExportedSymbol>> = HashMap::new();
        exports.insert(
            PathBuf::from("/repo/src/api/routes.rs"),
            vec![make_exported_symbol("api_fn", SymKind::Function, 1, true)],
        );
        exports.insert(
            PathBuf::from("/repo/src/internal/utils.rs"),
            vec![make_exported_symbol(
                "internal_fn",
                SymKind::Function,
                1,
                true,
            )],
        );

        let imports: HashMap<PathBuf, Vec<Import>> = HashMap::new();

        let config = UnusedExportConfig {
            exclude_entry_points: false,
            exclude_patterns: vec!["api/".to_string()],
            include_reexports: false,
        };

        let report = find_unused_exports(&exports, &imports, Path::new("/repo"), &config);

        // api/ is excluded, only internal_fn should be reported
        assert!(report.has_findings());
        assert_eq!(report.count(), 1);
        assert_eq!(report.files_excluded, 1);
        assert!(report
            .unused_exports
            .iter()
            .any(|e| e.symbol_name == "internal_fn"));
    }
}
