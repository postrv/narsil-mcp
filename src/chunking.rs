//! AST-aware code chunking for improved semantic search.
//!
//! Provides intelligent code chunking that respects AST boundaries,
//! keeping functions, classes, and logical units together.

use crate::parser::{LanguageParser, ParsedFile};
use crate::symbols::SymbolKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tree_sitter::{Node, Tree};

/// A chunk of code with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeChunk {
    /// Unique identifier for this chunk
    pub id: String,
    /// The actual code content
    pub content: String,
    /// Path to the source file
    pub file_path: String,
    /// Starting line number (1-indexed)
    pub start_line: usize,
    /// Ending line number (1-indexed, inclusive)
    pub end_line: usize,
    /// Language of the code
    pub language: String,
    /// Symbol context (function/class this belongs to)
    pub symbol_context: Option<SymbolContext>,
    /// Type of chunk
    pub chunk_type: ChunkType,
    /// Associated documentation/comments
    pub doc_comment: Option<String>,
    /// Import statements at file level (for context)
    pub imports: Vec<String>,
}

/// Context about the symbol a chunk belongs to
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolContext {
    /// Symbol name
    pub name: String,
    /// Kind of symbol
    pub kind: SymbolKind,
    /// Function/method signature if applicable
    pub signature: Option<String>,
    /// Parent symbol (e.g., class for a method)
    pub parent: Option<Box<SymbolContext>>,
}

/// Type of code chunk
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChunkType {
    /// Complete function definition
    Function,
    /// Method within a class/impl
    Method,
    /// Class or struct definition (may be split if large)
    Class,
    /// Module or namespace
    Module,
    /// Import/use statements
    Import,
    /// Trait or interface definition
    Trait,
    /// Enum definition
    Enum,
    /// Type alias or typedef
    TypeAlias,
    /// Top-level code that doesn't fit other categories
    TopLevel,
    /// Large code block split for size limits
    SplitBlock,
}

impl std::fmt::Display for ChunkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChunkType::Function => write!(f, "function"),
            ChunkType::Method => write!(f, "method"),
            ChunkType::Class => write!(f, "class"),
            ChunkType::Module => write!(f, "module"),
            ChunkType::Import => write!(f, "import"),
            ChunkType::Trait => write!(f, "trait"),
            ChunkType::Enum => write!(f, "enum"),
            ChunkType::TypeAlias => write!(f, "type_alias"),
            ChunkType::TopLevel => write!(f, "top_level"),
            ChunkType::SplitBlock => write!(f, "split_block"),
        }
    }
}

/// Configuration for the chunker
#[derive(Debug, Clone)]
pub struct ChunkerConfig {
    /// Maximum lines per chunk
    pub max_chunk_lines: usize,
    /// Minimum lines per chunk (to avoid tiny chunks)
    pub min_chunk_lines: usize,
    /// Number of overlap lines between chunks
    pub overlap_lines: usize,
    /// Include surrounding context (imports, class definition)
    pub include_context: bool,
    /// Maximum context lines to include
    pub max_context_lines: usize,
}

impl Default for ChunkerConfig {
    fn default() -> Self {
        Self {
            max_chunk_lines: 100,
            min_chunk_lines: 5,
            overlap_lines: 5,
            include_context: true,
            max_context_lines: 20,
        }
    }
}

/// Parameters for creating a top-level code chunk
struct ToplevelChunkParams<'a> {
    content: &'a str,
    file_path: &'a str,
    lang: &'a str,
    start: usize,
    end: usize,
    imports: &'a [String],
    chunk_id: usize,
}

/// Boundary information for a symbol in the AST
#[derive(Debug, Clone)]
struct SymbolBoundary {
    name: String,
    kind: SymbolKind,
    chunk_type: ChunkType,
    start_line: usize,
    end_line: usize,
    doc_start: Option<usize>,
    signature: Option<String>,
    parent_name: Option<String>,
}

/// AST-aware code chunker
pub struct AstChunker {
    config: ChunkerConfig,
    parser: LanguageParser,
}

impl AstChunker {
    /// Create a new chunker with default configuration
    pub fn new() -> Self {
        Self {
            config: ChunkerConfig::default(),
            parser: LanguageParser::new().expect("Failed to create language parser"),
        }
    }

    /// Create a new chunker with custom configuration
    pub fn with_config(config: ChunkerConfig) -> Self {
        Self {
            config,
            parser: LanguageParser::new().expect("Failed to create language parser"),
        }
    }

    /// Chunk a file respecting AST boundaries
    pub fn chunk_file(&self, content: &str, file_path: &str) -> Vec<CodeChunk> {
        let lang = self.detect_language(file_path);
        let path = std::path::Path::new(file_path);

        // Try to parse and chunk based on AST
        match self.parser.parse_file(path, content) {
            Ok(parsed) => self.chunk_parsed_file(&parsed, content, file_path, &lang),
            Err(_) => {
                // Fall back to line-based chunking
                self.chunk_by_lines(content, file_path, &lang)
            }
        }
    }

    /// Chunk a file that has already been parsed
    fn chunk_parsed_file(
        &self,
        parsed: &ParsedFile,
        content: &str,
        file_path: &str,
        lang: &str,
    ) -> Vec<CodeChunk> {
        let lines: Vec<&str> = content.lines().collect();
        let tree = match &parsed.tree {
            Some(t) => t,
            None => return self.chunk_by_lines(content, file_path, lang),
        };

        // Extract symbol boundaries from AST
        let boundaries = self.extract_boundaries(tree, content, lang);

        // Extract imports for context
        let imports = self.extract_imports(tree, content, lang);

        // Create chunks from boundaries
        let mut chunks = Vec::new();
        let mut chunk_id = 0;

        // Track which lines have been chunked
        let mut covered_lines: Vec<bool> = vec![false; lines.len() + 1];

        // First, create chunks for each symbol
        for boundary in &boundaries {
            let start = boundary.doc_start.unwrap_or(boundary.start_line);
            let end = boundary.end_line;

            // Skip if already covered by a parent chunk
            if covered_lines.get(start).copied().unwrap_or(false) {
                continue;
            }

            // Mark lines as covered
            for line in start..=end.min(covered_lines.len() - 1) {
                covered_lines[line] = true;
            }

            // Check if chunk is too large
            let chunk_lines = end.saturating_sub(start) + 1;
            if chunk_lines > self.config.max_chunk_lines {
                // Split large chunks
                let split_chunks = self.split_large_chunk(
                    content,
                    file_path,
                    lang,
                    boundary,
                    &imports,
                    &mut chunk_id,
                );
                chunks.extend(split_chunks);
            } else {
                let chunk = self.create_chunk_from_boundary(
                    content, file_path, lang, boundary, &imports, chunk_id,
                );
                chunks.push(chunk);
                chunk_id += 1;
            }
        }

        // Create chunks for remaining uncovered lines (top-level code)
        let mut uncovered_start: Option<usize> = None;
        for (i, &covered) in covered_lines.iter().enumerate().skip(1) {
            if !covered && i <= lines.len() {
                if uncovered_start.is_none() {
                    uncovered_start = Some(i);
                }
            } else if let Some(start) = uncovered_start {
                let end = i - 1;
                if end >= start + self.config.min_chunk_lines {
                    chunks.push(self.create_toplevel_chunk(ToplevelChunkParams {
                        content,
                        file_path,
                        lang,
                        start,
                        end,
                        imports: &imports,
                        chunk_id,
                    }));
                    chunk_id += 1;
                }
                uncovered_start = None;
            }
        }

        // Handle remaining uncovered lines at end
        if let Some(start) = uncovered_start {
            let end = lines.len();
            if end >= start + self.config.min_chunk_lines {
                chunks.push(self.create_toplevel_chunk(ToplevelChunkParams {
                    content,
                    file_path,
                    lang,
                    start,
                    end,
                    imports: &imports,
                    chunk_id,
                }));
            }
        }

        // Sort chunks by start line
        chunks.sort_by_key(|c| c.start_line);

        // Merge adjacent small chunks if needed
        self.merge_small_chunks(chunks)
    }

    /// Extract symbol boundaries from AST
    fn extract_boundaries(&self, tree: &Tree, content: &str, lang: &str) -> Vec<SymbolBoundary> {
        let mut boundaries = Vec::new();
        let root = tree.root_node();

        self.visit_node_for_boundaries(&root, content, lang, None, &mut boundaries);

        // Sort by start line
        boundaries.sort_by_key(|b| b.start_line);

        boundaries
    }

    /// Recursively visit nodes to find symbol boundaries
    fn visit_node_for_boundaries(
        &self,
        node: &Node,
        content: &str,
        lang: &str,
        parent_name: Option<&str>,
        boundaries: &mut Vec<SymbolBoundary>,
    ) {
        let kind = node.kind();
        let start_line = node.start_position().row + 1;
        let end_line = node.end_position().row + 1;

        // Check if this is a symbol we care about
        if let Some((chunk_type, symbol_kind)) = self.classify_node(kind, lang) {
            let name = self.extract_node_name(node, content, kind, lang);
            let signature = self.extract_signature(node, content, kind, lang);
            let doc_start = self.find_doc_comment_start(node, content, start_line);

            if let Some(name) = name {
                boundaries.push(SymbolBoundary {
                    name: name.clone(),
                    kind: symbol_kind,
                    chunk_type,
                    start_line,
                    end_line,
                    doc_start,
                    signature,
                    parent_name: parent_name.map(String::from),
                });

                // For classes/impls, visit children with this as parent
                if matches!(chunk_type, ChunkType::Class | ChunkType::Trait) {
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        self.visit_node_for_boundaries(
                            &child,
                            content,
                            lang,
                            Some(&name),
                            boundaries,
                        );
                    }
                    return;
                }
            }
        }

        // Visit children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.visit_node_for_boundaries(&child, content, lang, parent_name, boundaries);
        }
    }

    /// Classify a node kind into chunk type and symbol kind
    fn classify_node(&self, kind: &str, lang: &str) -> Option<(ChunkType, SymbolKind)> {
        match lang {
            "rust" => match kind {
                "function_item" => Some((ChunkType::Function, SymbolKind::Function)),
                "impl_item" | "struct_item" => Some((ChunkType::Class, SymbolKind::Struct)),
                "trait_item" => Some((ChunkType::Trait, SymbolKind::Trait)),
                "enum_item" => Some((ChunkType::Enum, SymbolKind::Enum)),
                "type_item" => Some((ChunkType::TypeAlias, SymbolKind::TypeAlias)),
                "mod_item" => Some((ChunkType::Module, SymbolKind::Module)),
                _ => None,
            },
            "python" => match kind {
                "function_definition" => Some((ChunkType::Function, SymbolKind::Function)),
                "class_definition" => Some((ChunkType::Class, SymbolKind::Class)),
                _ => None,
            },
            "javascript" | "typescript" | "tsx" => match kind {
                "function_declaration" | "arrow_function" | "function" => {
                    Some((ChunkType::Function, SymbolKind::Function))
                }
                "method_definition" => Some((ChunkType::Method, SymbolKind::Method)),
                "class_declaration" | "class" => Some((ChunkType::Class, SymbolKind::Class)),
                "interface_declaration" => Some((ChunkType::Trait, SymbolKind::Interface)),
                "type_alias_declaration" => Some((ChunkType::TypeAlias, SymbolKind::TypeAlias)),
                _ => None,
            },
            "go" => match kind {
                "function_declaration" => Some((ChunkType::Function, SymbolKind::Function)),
                "method_declaration" => Some((ChunkType::Method, SymbolKind::Method)),
                "type_declaration" => Some((ChunkType::Class, SymbolKind::Struct)),
                "interface_type" => Some((ChunkType::Trait, SymbolKind::Interface)),
                _ => None,
            },
            "java" | "c_sharp" => match kind {
                "method_declaration" => Some((ChunkType::Method, SymbolKind::Method)),
                "class_declaration" => Some((ChunkType::Class, SymbolKind::Class)),
                "interface_declaration" => Some((ChunkType::Trait, SymbolKind::Interface)),
                "enum_declaration" => Some((ChunkType::Enum, SymbolKind::Enum)),
                _ => None,
            },
            "c" | "cpp" => match kind {
                "function_definition" => Some((ChunkType::Function, SymbolKind::Function)),
                "struct_specifier" | "class_specifier" => {
                    Some((ChunkType::Class, SymbolKind::Struct))
                }
                "enum_specifier" => Some((ChunkType::Enum, SymbolKind::Enum)),
                _ => None,
            },
            _ => None,
        }
    }

    /// Extract the name of a node
    fn extract_node_name(
        &self,
        node: &Node,
        content: &str,
        kind: &str,
        _lang: &str,
    ) -> Option<String> {
        let mut cursor = node.walk();

        // Look for identifier children
        for child in node.children(&mut cursor) {
            let child_kind = child.kind();
            if child_kind == "identifier" || child_kind == "name" || child_kind == "type_identifier"
            {
                return Some(self.node_text(&child, content));
            }

            // For Rust impl blocks, look for the type
            if kind == "impl_item" && child_kind == "type_identifier" {
                return Some(format!("impl {}", self.node_text(&child, content)));
            }
        }

        // Try first named child
        if let Some(first) = node.named_child(0) {
            let child_kind = first.kind();
            if child_kind == "identifier" || child_kind == "name" {
                return Some(self.node_text(&first, content));
            }
        }

        None
    }

    /// Extract function/method signature
    fn extract_signature(
        &self,
        node: &Node,
        content: &str,
        kind: &str,
        lang: &str,
    ) -> Option<String> {
        // Only extract signatures for functions/methods
        if !matches!(
            kind,
            "function_item"
                | "function_declaration"
                | "function_definition"
                | "method_definition"
                | "method_declaration"
                | "function"
                | "arrow_function"
        ) {
            return None;
        }

        // Get the first line or until opening brace
        let start_byte = node.start_byte();
        let end_byte = node.end_byte().min(start_byte + 500); // Limit signature length
        let text = content.get(start_byte..end_byte)?;

        // Find the end of signature (before body)
        let sig_end = match lang {
            "rust" => text.find('{'),
            "python" => text.find(':'),
            "go" => text.find('{'),
            _ => text.find('{'),
        };

        sig_end.map(|pos| text.get(..pos).unwrap_or(text).trim().to_string())
    }

    /// Find the start of doc comments before a symbol
    fn find_doc_comment_start(
        &self,
        node: &Node,
        _content: &str,
        symbol_start: usize,
    ) -> Option<usize> {
        // Look at preceding siblings for comments
        let mut prev = node.prev_sibling();
        let mut doc_start = None;

        while let Some(sibling) = prev {
            let kind = sibling.kind();
            if kind.contains("comment") || kind == "attribute_item" || kind == "decorator" {
                let line = sibling.start_position().row + 1;
                // Only include if immediately preceding
                if doc_start.is_none() || doc_start == Some(line + 1) {
                    doc_start = Some(line);
                }
            } else if kind != "newline" && !kind.contains("whitespace") {
                break;
            }
            prev = sibling.prev_sibling();
        }

        // Also check if the comment is on the same line or immediately before
        if let Some(start) = doc_start {
            // Make sure it's actually close to the symbol
            if symbol_start.saturating_sub(start) <= 20 {
                return Some(start);
            }
        }

        None
    }

    /// Extract import statements
    fn extract_imports(&self, tree: &Tree, content: &str, lang: &str) -> Vec<String> {
        let mut imports = Vec::new();
        let root = tree.root_node();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            let kind = child.kind();
            let is_import = match lang {
                "rust" => kind == "use_declaration",
                "python" => kind == "import_statement" || kind == "import_from_statement",
                "javascript" | "typescript" | "tsx" => kind == "import_statement",
                "go" => kind == "import_declaration",
                "java" => kind == "import_declaration",
                _ => false,
            };

            if is_import {
                imports.push(self.node_text(&child, content));
            }
        }

        imports
    }

    /// Get text content of a node
    fn node_text(&self, node: &Node, content: &str) -> String {
        content
            .get(node.start_byte()..node.end_byte())
            .unwrap_or("")
            .to_string()
    }

    /// Create a chunk from a symbol boundary
    fn create_chunk_from_boundary(
        &self,
        content: &str,
        file_path: &str,
        lang: &str,
        boundary: &SymbolBoundary,
        imports: &[String],
        chunk_id: usize,
    ) -> CodeChunk {
        let start = boundary.doc_start.unwrap_or(boundary.start_line);
        let end = boundary.end_line;

        let lines: Vec<&str> = content.lines().collect();
        let chunk_content = lines
            .get(start.saturating_sub(1)..end.min(lines.len()))
            .map(|ls| ls.join("\n"))
            .unwrap_or_default();

        // Extract doc comment
        let doc_comment = boundary.doc_start.and_then(|doc_start| {
            if doc_start < boundary.start_line {
                lines
                    .get(doc_start.saturating_sub(1)..boundary.start_line.saturating_sub(1))
                    .map(|ls| ls.join("\n"))
            } else {
                None
            }
        });

        let symbol_context = Some(SymbolContext {
            name: boundary.name.clone(),
            kind: boundary.kind.clone(),
            signature: boundary.signature.clone(),
            parent: boundary.parent_name.as_ref().map(|p| {
                Box::new(SymbolContext {
                    name: p.clone(),
                    kind: SymbolKind::Class, // Assume parent is class-like
                    signature: None,
                    parent: None,
                })
            }),
        });

        CodeChunk {
            id: format!("{}:{}:{}", file_path, chunk_id, boundary.name),
            content: chunk_content,
            file_path: file_path.to_string(),
            start_line: start,
            end_line: end,
            language: lang.to_string(),
            symbol_context,
            chunk_type: boundary.chunk_type,
            doc_comment,
            imports: if self.config.include_context {
                imports.to_vec()
            } else {
                Vec::new()
            },
        }
    }

    /// Split a large chunk into smaller pieces
    fn split_large_chunk(
        &self,
        content: &str,
        file_path: &str,
        lang: &str,
        boundary: &SymbolBoundary,
        imports: &[String],
        chunk_id: &mut usize,
    ) -> Vec<CodeChunk> {
        let lines: Vec<&str> = content.lines().collect();
        let start = boundary.doc_start.unwrap_or(boundary.start_line);
        let end = boundary.end_line;
        let mut chunks = Vec::new();

        let mut current_start = start;
        while current_start <= end {
            let current_end = (current_start + self.config.max_chunk_lines - 1).min(end);

            let chunk_content = lines
                .get(current_start.saturating_sub(1)..current_end.min(lines.len()))
                .map(|ls| ls.join("\n"))
                .unwrap_or_default();

            let is_first = current_start == start;
            let symbol_context = Some(SymbolContext {
                name: if is_first {
                    boundary.name.clone()
                } else {
                    format!("{} (continued)", boundary.name)
                },
                kind: boundary.kind.clone(),
                signature: if is_first {
                    boundary.signature.clone()
                } else {
                    None
                },
                parent: boundary.parent_name.as_ref().map(|p| {
                    Box::new(SymbolContext {
                        name: p.clone(),
                        kind: SymbolKind::Class,
                        signature: None,
                        parent: None,
                    })
                }),
            });

            chunks.push(CodeChunk {
                id: format!(
                    "{}:{}:{}:{}",
                    file_path,
                    *chunk_id,
                    boundary.name,
                    chunks.len()
                ),
                content: chunk_content,
                file_path: file_path.to_string(),
                start_line: current_start,
                end_line: current_end,
                language: lang.to_string(),
                symbol_context,
                chunk_type: if is_first {
                    boundary.chunk_type
                } else {
                    ChunkType::SplitBlock
                },
                doc_comment: if is_first && current_start > boundary.start_line {
                    lines
                        .get(start.saturating_sub(1)..boundary.start_line.saturating_sub(1))
                        .map(|ls| ls.join("\n"))
                } else {
                    None
                },
                imports: if self.config.include_context && is_first {
                    imports.to_vec()
                } else {
                    Vec::new()
                },
            });

            *chunk_id += 1;

            // Move to next chunk with overlap
            current_start = current_end + 1 - self.config.overlap_lines;
            if current_start <= current_end {
                current_start = current_end + 1;
            }
        }

        chunks
    }

    /// Create a chunk for top-level code
    fn create_toplevel_chunk(&self, params: ToplevelChunkParams<'_>) -> CodeChunk {
        let lines: Vec<&str> = params.content.lines().collect();
        let chunk_content = lines
            .get(params.start.saturating_sub(1)..params.end.min(lines.len()))
            .map(|ls| ls.join("\n"))
            .unwrap_or_default();

        CodeChunk {
            id: format!("{}:{}:toplevel", params.file_path, params.chunk_id),
            content: chunk_content,
            file_path: params.file_path.to_string(),
            start_line: params.start,
            end_line: params.end,
            language: params.lang.to_string(),
            symbol_context: None,
            chunk_type: ChunkType::TopLevel,
            doc_comment: None,
            imports: if self.config.include_context {
                params.imports.to_vec()
            } else {
                Vec::new()
            },
        }
    }

    /// Fall back to simple line-based chunking
    fn chunk_by_lines(&self, content: &str, file_path: &str, lang: &str) -> Vec<CodeChunk> {
        let lines: Vec<&str> = content.lines().collect();
        let mut chunks = Vec::new();
        let mut chunk_id = 0;
        let mut start = 1;

        while start <= lines.len() {
            let end = (start + self.config.max_chunk_lines - 1).min(lines.len());
            let chunk_content = lines
                .get(start.saturating_sub(1)..end)
                .map(|ls| ls.join("\n"))
                .unwrap_or_default();

            chunks.push(CodeChunk {
                id: format!("{}:{}:lines", file_path, chunk_id),
                content: chunk_content,
                file_path: file_path.to_string(),
                start_line: start,
                end_line: end,
                language: lang.to_string(),
                symbol_context: None,
                chunk_type: ChunkType::TopLevel,
                doc_comment: None,
                imports: Vec::new(),
            });

            chunk_id += 1;
            start = end + 1 - self.config.overlap_lines;
            if start <= end {
                start = end + 1;
            }
        }

        chunks
    }

    /// Merge adjacent small chunks
    fn merge_small_chunks(&self, chunks: Vec<CodeChunk>) -> Vec<CodeChunk> {
        if chunks.is_empty() {
            return chunks;
        }

        let mut merged = Vec::new();
        let mut current: Option<CodeChunk> = None;

        for chunk in chunks {
            let chunk_lines = chunk.end_line.saturating_sub(chunk.start_line) + 1;

            if let Some(mut curr) = current.take() {
                let curr_lines = curr.end_line.saturating_sub(curr.start_line) + 1;
                let combined_lines = curr_lines + chunk_lines;

                // Merge if both are small and same type or adjacent
                if combined_lines <= self.config.max_chunk_lines
                    && (curr_lines < self.config.min_chunk_lines
                        || chunk_lines < self.config.min_chunk_lines)
                    && chunk.start_line <= curr.end_line + 2
                {
                    // Merge chunks
                    curr.content = format!("{}\n{}", curr.content, chunk.content);
                    curr.end_line = chunk.end_line;
                    if curr.symbol_context.is_none() {
                        curr.symbol_context = chunk.symbol_context;
                    }
                    current = Some(curr);
                } else {
                    merged.push(curr);
                    current = Some(chunk);
                }
            } else {
                current = Some(chunk);
            }
        }

        if let Some(curr) = current {
            merged.push(curr);
        }

        merged
    }

    /// Detect language from file path
    fn detect_language(&self, file_path: &str) -> String {
        let ext = file_path.rsplit('.').next().unwrap_or("");
        match ext {
            "rs" => "rust",
            "py" => "python",
            "js" => "javascript",
            "ts" => "typescript",
            "tsx" => "tsx",
            "jsx" => "javascript",
            "go" => "go",
            "java" => "java",
            "cs" => "c_sharp",
            "c" | "h" => "c",
            "cpp" | "cc" | "cxx" | "hpp" | "hxx" => "cpp",
            _ => "unknown",
        }
        .to_string()
    }
}

impl Default for AstChunker {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about chunking
#[derive(Debug, Default)]
pub struct ChunkingStats {
    pub total_chunks: usize,
    pub by_type: HashMap<ChunkType, usize>,
    pub avg_chunk_lines: f64,
    pub max_chunk_lines: usize,
    pub min_chunk_lines: usize,
}

impl ChunkingStats {
    pub fn from_chunks(chunks: &[CodeChunk]) -> Self {
        if chunks.is_empty() {
            return Self::default();
        }

        let mut by_type: HashMap<ChunkType, usize> = HashMap::new();
        let mut total_lines = 0;
        let mut max_lines = 0;
        let mut min_lines = usize::MAX;

        for chunk in chunks {
            let lines = chunk.end_line.saturating_sub(chunk.start_line) + 1;
            *by_type.entry(chunk.chunk_type).or_default() += 1;
            total_lines += lines;
            max_lines = max_lines.max(lines);
            min_lines = min_lines.min(lines);
        }

        Self {
            total_chunks: chunks.len(),
            by_type,
            avg_chunk_lines: total_lines as f64 / chunks.len() as f64,
            max_chunk_lines: max_lines,
            min_chunk_lines: if min_lines == usize::MAX {
                0
            } else {
                min_lines
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_simple_rust_functions() {
        let code = r#"
fn foo() {
    println!("foo");
}

fn bar() {
    println!("bar");
}
"#;
        let chunker = AstChunker::new();
        let chunks = chunker.chunk_file(code, "test.rs");

        // Should have at least 1 chunk
        assert!(!chunks.is_empty(), "Should produce at least one chunk");

        // All the code should be covered by chunks
        let all_content: String = chunks.iter().map(|c| c.content.clone()).collect();
        assert!(all_content.contains("fn foo"), "Should have foo function");
        assert!(all_content.contains("fn bar"), "Should have bar function");
    }

    #[test]
    fn test_chunk_with_doc_comment() {
        let code = r#"
/// This is a doc comment
/// for the function
fn documented() {
    println!("documented");
}
"#;
        let chunker = AstChunker::new();
        let chunks = chunker.chunk_file(code, "test.rs");

        assert!(!chunks.is_empty());
        let fn_chunk = chunks
            .iter()
            .find(|c| c.content.contains("fn documented"))
            .unwrap();

        // Doc comment should be included
        assert!(fn_chunk.content.contains("/// This is a doc comment"));
    }

    #[test]
    fn test_chunk_type_classification() {
        let code = r#"
fn my_function() {}

struct MyStruct {
    field: i32,
}

trait MyTrait {
    fn method(&self);
}

enum MyEnum {
    A,
    B,
}
"#;
        let chunker = AstChunker::new();
        let chunks = chunker.chunk_file(code, "test.rs");

        // Should have at least one chunk
        assert!(!chunks.is_empty(), "Should produce chunks");

        // All content should be covered
        let all_content: String = chunks.iter().map(|c| c.content.clone()).collect();
        assert!(
            all_content.contains("fn my_function"),
            "Should have function"
        );
        assert!(
            all_content.contains("struct MyStruct"),
            "Should have struct"
        );
        assert!(all_content.contains("trait MyTrait"), "Should have trait");
        assert!(all_content.contains("enum MyEnum"), "Should have enum");
    }

    #[test]
    fn test_chunk_python_code() {
        let code = r#"
def hello():
    print("hello")

class MyClass:
    def __init__(self):
        pass

    def method(self):
        pass
"#;
        let chunker = AstChunker::new();
        let chunks = chunker.chunk_file(code, "test.py");

        assert!(!chunks.is_empty(), "Should produce chunks");

        // All content should be covered
        let all_content: String = chunks.iter().map(|c| c.content.clone()).collect();
        assert!(
            all_content.contains("def hello"),
            "Should have hello function"
        );
        assert!(all_content.contains("class MyClass"), "Should have class");
    }

    #[test]
    fn test_chunk_javascript_code() {
        let code = r#"
function greet() {
    console.log("hello");
}

class User {
    constructor(name) {
        this.name = name;
    }

    getName() {
        return this.name;
    }
}
"#;
        let chunker = AstChunker::new();
        let chunks = chunker.chunk_file(code, "test.js");

        assert!(!chunks.is_empty());
    }

    #[test]
    fn test_large_function_splitting() {
        // Create a function with many lines
        let mut code = String::from("fn large_function() {\n");
        for i in 0..150 {
            code.push_str(&format!("    let x{} = {};\n", i, i));
        }
        code.push_str("}\n");

        let config = ChunkerConfig {
            max_chunk_lines: 50,
            ..Default::default()
        };
        let chunker = AstChunker::with_config(config);
        let chunks = chunker.chunk_file(&code, "test.rs");

        // Should be split into multiple chunks
        assert!(chunks.len() > 1, "Large function should be split");

        // First chunk should have the function type
        let first = &chunks[0];
        assert_eq!(first.chunk_type, ChunkType::Function);

        // Subsequent chunks should be SplitBlock
        if chunks.len() > 1 {
            assert!(chunks[1..]
                .iter()
                .any(|c| c.chunk_type == ChunkType::SplitBlock));
        }
    }

    #[test]
    fn test_imports_extraction() {
        let code = r#"
use std::collections::HashMap;
use std::io::Read;

fn main() {
    let map = HashMap::new();
}
"#;
        let chunker = AstChunker::new();
        let chunks = chunker.chunk_file(code, "test.rs");

        // Function chunk should include imports in context
        let fn_chunk = chunks
            .iter()
            .find(|c| c.content.contains("fn main"))
            .unwrap();
        assert!(!fn_chunk.imports.is_empty(), "Should have imports");
    }

    #[test]
    fn test_symbol_context() {
        let code = r#"
fn my_func(x: i32) -> i32 {
    x + 1
}
"#;
        let chunker = AstChunker::new();
        let chunks = chunker.chunk_file(code, "test.rs");

        let fn_chunk = chunks
            .iter()
            .find(|c| c.content.contains("fn my_func"))
            .unwrap();

        assert!(fn_chunk.symbol_context.is_some());
        let ctx = fn_chunk.symbol_context.as_ref().unwrap();
        assert_eq!(ctx.name, "my_func");
        assert_eq!(ctx.kind, SymbolKind::Function);
    }

    #[test]
    fn test_line_based_fallback() {
        // Content that might not parse well
        let code = "some random text\nthat is not code\nbut needs chunking\n".repeat(50);

        let chunker = AstChunker::new();
        let chunks = chunker.chunk_file(&code, "test.txt");

        // Should still produce chunks via fallback
        assert!(!chunks.is_empty());
    }

    #[test]
    fn test_chunking_stats() {
        let code = r#"
fn a() { println!("a"); }
fn b() { println!("b"); }
fn c() { println!("c"); }
"#;
        let chunker = AstChunker::new();
        let chunks = chunker.chunk_file(code, "test.rs");
        let stats = ChunkingStats::from_chunks(&chunks);

        assert!(stats.total_chunks > 0);
        assert!(stats.avg_chunk_lines > 0.0);
    }

    #[test]
    fn test_merge_small_chunks() {
        let config = ChunkerConfig {
            max_chunk_lines: 100,
            min_chunk_lines: 10,
            ..Default::default()
        };
        let chunker = AstChunker::with_config(config);

        // Very short functions
        let code = r#"
fn a() {}
fn b() {}
fn c() {}
fn d() {}
"#;
        let chunks = chunker.chunk_file(code, "test.rs");

        // Small adjacent chunks might be merged
        // At minimum, we should have at least one chunk
        assert!(!chunks.is_empty());
    }

    #[test]
    fn test_chunk_type_display() {
        assert_eq!(format!("{}", ChunkType::Function), "function");
        assert_eq!(format!("{}", ChunkType::Class), "class");
        assert_eq!(format!("{}", ChunkType::Method), "method");
        assert_eq!(format!("{}", ChunkType::Module), "module");
    }

    #[test]
    fn test_detect_language() {
        let chunker = AstChunker::new();

        assert_eq!(chunker.detect_language("test.rs"), "rust");
        assert_eq!(chunker.detect_language("test.py"), "python");
        assert_eq!(chunker.detect_language("test.js"), "javascript");
        assert_eq!(chunker.detect_language("test.ts"), "typescript");
        assert_eq!(chunker.detect_language("test.tsx"), "tsx");
        assert_eq!(chunker.detect_language("test.go"), "go");
        assert_eq!(chunker.detect_language("test.java"), "java");
        assert_eq!(chunker.detect_language("test.cs"), "c_sharp");
        assert_eq!(chunker.detect_language("test.c"), "c");
        assert_eq!(chunker.detect_language("test.cpp"), "cpp");
        assert_eq!(chunker.detect_language("test.unknown"), "unknown");
    }

    #[test]
    fn test_node_text_multibyte_safety() {
        // Content with multi-byte UTF-8 characters (emoji, CJK, accented)
        let code =
            "fn héllo_wörld() {\n    let msg = \"你好世界 🌍\";\n    println!(\"{}\", msg);\n}\n";
        let chunker = AstChunker::new();
        let chunks = chunker.chunk_file(code, "test.rs");

        // Should not panic and should produce valid chunks
        assert!(
            !chunks.is_empty(),
            "Should produce chunks for multibyte content"
        );
        for chunk in &chunks {
            // Every chunk content must be valid UTF-8 (guaranteed by String type, but verify non-empty)
            assert!(!chunk.content.is_empty() || chunk.start_line == chunk.end_line);
        }
    }

    #[test]
    fn test_extract_signature_truncation_safety() {
        // Create a function with a very long name containing multi-byte chars
        // such that the 500-byte truncation lands mid-character
        let long_name: String = "á".repeat(260); // 260 * 2 bytes = 520 bytes, exceeds 500-byte limit
        let code = format!("fn {}() {{\n    println!(\"test\");\n}}\n", long_name);
        let chunker = AstChunker::new();
        let chunks = chunker.chunk_file(&code, "test.rs");

        // Should not panic
        assert!(
            !chunks.is_empty(),
            "Should produce chunks despite long multibyte name"
        );
    }

    #[test]
    fn test_chunk_file_with_mixed_encodings() {
        // File mixing ASCII, Latin-1 extended, CJK, and emoji across function boundaries
        let code = r#"
fn ascii_func() {
    let x = "hello world";
}

fn café_résumé() {
    let y = "naïve über";
}

fn 数据处理() {
    let z = "日本語テスト";
}

fn emoji_func() {
    let w = "🚀🔥💯";
}
"#;
        let chunker = AstChunker::new();
        let chunks = chunker.chunk_file(code, "test.rs");

        assert!(
            !chunks.is_empty(),
            "Should produce chunks for mixed encoding content"
        );

        // Verify all chunks are valid UTF-8 strings (they are String, so this is guaranteed)
        let all_content: String = chunks.iter().map(|c| c.content.clone()).collect();
        assert!(
            all_content.contains("ascii_func"),
            "Should contain ASCII function"
        );
        assert!(
            all_content.contains("emoji_func"),
            "Should contain emoji function"
        );
    }

    #[test]
    fn test_chunk_multiple_files_no_panic() {
        let chunker = AstChunker::new();

        // Simulate chunking multiple files in sequence, including ones with multibyte content
        let files = vec![
            ("file1.rs", "fn normal() { let x = 1; }\n"),
            ("file2.rs", "fn émoji() { let x = \"🎉\"; }\n"),
            ("file3.py", "def hello():\n    print('世界')\n"),
            ("file4.js", "function greet() { return '挨拶'; }\n"),
            ("file5.rs", "fn café() { let ñ = \"über\"; }\n"),
        ];

        let mut total_chunks = 0;
        for (path, content) in &files {
            let chunks = chunker.chunk_file(content, path);
            total_chunks += chunks.len();
        }

        assert!(
            total_chunks > 0,
            "Should produce chunks across multiple files"
        );
    }
}
