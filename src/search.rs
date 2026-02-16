//! Semantic code search with BM25 ranking and code-aware tokenization
//!
//! Provides intelligent code search that understands programming patterns.

// Allow dead code for planned search improvements
#![allow(dead_code)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Validate regex pattern to prevent ReDoS attacks
fn validate_regex_pattern(pattern: &str) -> Result<regex::Regex, String> {
    // Reject overly long patterns
    if pattern.len() > 1000 {
        return Err("Pattern too long (max 1000 chars)".to_string());
    }

    // Count potentially dangerous constructs
    let nested_quantifiers =
        pattern.matches('+').count() + pattern.matches('*').count() + pattern.matches('?').count();

    if nested_quantifiers > 20 {
        return Err("Pattern has too many quantifiers".to_string());
    }

    regex::Regex::new(pattern).map_err(|e| e.to_string())
}

/// A searchable document (file or symbol)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchDocument {
    pub id: String,
    pub file_path: String,
    pub content: String,
    pub doc_type: DocType,
    pub start_line: usize,
    pub end_line: usize,
    /// Pre-computed tokens
    pub tokens: Vec<String>,
    /// Token frequencies
    pub term_freq: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DocType {
    File,
    Function,
    Class,
    Struct,
    Method,
    Other,
}

/// A search result with relevance scoring
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub document: SearchDocument,
    pub score: f64,
    pub matched_terms: Vec<String>,
    pub snippet: String,
}

/// BM25 parameters
#[derive(Debug, Clone)]
pub struct BM25Params {
    /// Term frequency saturation (default: 1.2)
    pub k1: f64,
    /// Document length normalization (default: 0.75)
    pub b: f64,
}

impl Default for BM25Params {
    fn default() -> Self {
        Self { k1: 1.2, b: 0.75 }
    }
}

/// Code-aware search index using BM25
pub struct SearchIndex {
    /// All documents
    documents: Vec<SearchDocument>,
    /// Inverted index: term -> document indices
    inverted_index: HashMap<String, Vec<usize>>,
    /// Document frequency per term
    doc_freq: HashMap<String, usize>,
    /// Average document length
    avg_doc_len: f64,
    /// BM25 parameters
    params: BM25Params,
    /// Code-specific synonyms
    synonyms: HashMap<String, Vec<String>>,
}

impl Default for SearchIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchIndex {
    pub fn new() -> Self {
        Self {
            documents: Vec::new(),
            inverted_index: HashMap::new(),
            doc_freq: HashMap::new(),
            avg_doc_len: 0.0,
            params: BM25Params::default(),
            synonyms: Self::build_code_synonyms(),
        }
    }

    /// Build code-specific synonym mappings
    fn build_code_synonyms() -> HashMap<String, Vec<String>> {
        let mut synonyms = HashMap::new();

        // Common programming synonyms
        let synonym_groups = vec![
            vec![
                "func",
                "function",
                "fn",
                "def",
                "method",
                "proc",
                "procedure",
            ],
            vec!["struct", "structure", "class", "type", "record"],
            vec!["err", "error", "exception", "failure", "fault"],
            vec!["ok", "success", "result"],
            vec!["str", "string", "text"],
            vec!["int", "integer", "number", "num"],
            vec!["bool", "boolean", "flag"],
            vec!["arr", "array", "list", "vec", "vector", "slice"],
            vec!["dict", "dictionary", "map", "hashmap", "hash"],
            vec!["cfg", "config", "configuration", "settings", "options"],
            vec!["msg", "message", "payload"],
            vec!["req", "request"],
            vec!["res", "resp", "response"],
            vec!["db", "database", "store", "storage"],
            vec!["auth", "authentication", "authorize"],
            vec!["impl", "implement", "implementation"],
            vec!["init", "initialize", "setup", "create", "new"],
            vec!["del", "delete", "remove", "drop"],
            vec!["get", "fetch", "retrieve", "read", "load"],
            vec!["set", "update", "write", "save", "store"],
            vec!["async", "asynchronous", "concurrent"],
            vec!["sync", "synchronous", "blocking"],
        ];

        for group in synonym_groups {
            for term in &group {
                let others: Vec<String> = group
                    .iter()
                    .filter(|&t| t != term)
                    .map(|s| s.to_string())
                    .collect();
                synonyms.insert(term.to_string(), others);
            }
        }

        synonyms
    }

    /// Add a document to the index
    pub fn add_document(&mut self, doc: SearchDocument) {
        let doc_idx = self.documents.len();

        // Update inverted index
        for token in &doc.tokens {
            self.inverted_index
                .entry(token.clone())
                .or_default()
                .push(doc_idx);
        }

        // Update document frequencies
        let unique_tokens: HashSet<_> = doc.tokens.iter().collect();
        for token in unique_tokens {
            *self.doc_freq.entry(token.clone()).or_default() += 1;
        }

        self.documents.push(doc);

        // Recalculate average document length
        let total_len: usize = self.documents.iter().map(|d| d.tokens.len()).sum();
        self.avg_doc_len = total_len as f64 / self.documents.len() as f64;
    }

    /// Index content from a file
    pub fn index_file(&mut self, file_path: &str, content: &str) {
        let tokens = tokenize_code(content);
        let term_freq = count_terms(&tokens);

        self.add_document(SearchDocument {
            id: file_path.to_string(),
            file_path: file_path.to_string(),
            content: content.to_string(),
            doc_type: DocType::File,
            start_line: 1,
            end_line: content.lines().count(),
            tokens,
            term_freq,
        });
    }

    /// Index a symbol (function, class, etc.)
    pub fn index_symbol(
        &mut self,
        file_path: &str,
        name: &str,
        content: &str,
        doc_type: DocType,
        start_line: usize,
        end_line: usize,
    ) {
        let tokens = tokenize_code(content);
        let term_freq = count_terms(&tokens);

        self.add_document(SearchDocument {
            id: format!("{}::{}", file_path, name),
            file_path: file_path.to_string(),
            content: content.to_string(),
            doc_type,
            start_line,
            end_line,
            tokens,
            term_freq,
        });
    }

    /// Search the index with BM25 ranking
    pub fn search(&self, query: &str, max_results: usize) -> Vec<SearchResult> {
        // Validate query pattern to prevent ReDoS attacks
        if let Err(e) = validate_regex_pattern(query) {
            eprintln!("Invalid search pattern: {}", e);
            return Vec::new();
        }

        let query_tokens = tokenize_code(query);

        // Expand query with synonyms
        let expanded_tokens = self.expand_query(&query_tokens);

        let mut scores: HashMap<usize, (f64, Vec<String>)> = HashMap::new();

        for token in &expanded_tokens {
            if let Some(doc_indices) = self.inverted_index.get(token) {
                let idf = self.compute_idf(token);

                for &doc_idx in doc_indices {
                    let doc = &self.documents[doc_idx];
                    let tf = doc.term_freq.get(token).copied().unwrap_or(0) as f64;
                    let doc_len = doc.tokens.len() as f64;

                    let bm25_score = self.bm25_score(tf, doc_len, idf);

                    let entry = scores.entry(doc_idx).or_insert((0.0, Vec::new()));
                    entry.0 += bm25_score;
                    if !entry.1.contains(token) {
                        entry.1.push(token.clone());
                    }
                }
            }
        }

        // Boost exact name matches
        for (doc_idx, (score, _)) in &mut scores {
            let doc = &self.documents[*doc_idx];
            if doc.id.to_lowercase().contains(&query.to_lowercase()) {
                *score *= 2.0;
            }
        }

        // Sort by score and take top results
        let mut results: Vec<_> = scores.into_iter().collect();
        results.sort_by(|a, b| {
            b.1 .0
                .partial_cmp(&a.1 .0)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(max_results);

        results
            .into_iter()
            .map(|(doc_idx, (score, matched_terms))| {
                let doc = self.documents[doc_idx].clone();
                let snippet = self.generate_snippet(&doc, &matched_terms);

                SearchResult {
                    document: doc,
                    score,
                    matched_terms,
                    snippet,
                }
            })
            .collect()
    }

    /// Compute IDF (Inverse Document Frequency)
    fn compute_idf(&self, term: &str) -> f64 {
        let n = self.documents.len() as f64;
        let df = self.doc_freq.get(term).copied().unwrap_or(0) as f64;

        if df == 0.0 {
            0.0
        } else {
            ((n - df + 0.5) / (df + 0.5) + 1.0).ln()
        }
    }

    /// Compute BM25 score for a term in a document
    fn bm25_score(&self, tf: f64, doc_len: f64, idf: f64) -> f64 {
        let k1 = self.params.k1;
        let b = self.params.b;
        let avg_dl = self.avg_doc_len;

        let numerator = tf * (k1 + 1.0);
        let denominator = tf + k1 * (1.0 - b + b * doc_len / avg_dl);

        idf * numerator / denominator
    }

    /// Expand query terms with synonyms
    fn expand_query(&self, tokens: &[String]) -> Vec<String> {
        let mut expanded = tokens.to_vec();

        for token in tokens {
            if let Some(synonyms) = self.synonyms.get(token) {
                expanded.extend(synonyms.clone());
            }
        }

        expanded
    }

    /// Generate a snippet highlighting matched terms
    fn generate_snippet(&self, doc: &SearchDocument, matched_terms: &[String]) -> String {
        let lines: Vec<&str> = doc.content.lines().collect();
        let mut best_line_idx = 0;
        let mut best_score = 0;

        // Find the line with the most matches
        for (idx, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();
            let score: usize = matched_terms
                .iter()
                .filter(|term| line_lower.contains(&term.to_lowercase()))
                .count();

            if score > best_score {
                best_score = score;
                best_line_idx = idx;
            }
        }

        // Extract context around the best line
        let start = best_line_idx.saturating_sub(2);
        let end = (best_line_idx + 3).min(lines.len());

        lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, line)| format!("{:4} | {}", start + i + 1, line))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get statistics about the index
    pub fn stats(&self) -> IndexStats {
        let doc_types: HashMap<DocType, usize> =
            self.documents.iter().fold(HashMap::new(), |mut acc, doc| {
                *acc.entry(doc.doc_type.clone()).or_default() += 1;
                acc
            });

        IndexStats {
            total_documents: self.documents.len(),
            total_terms: self.inverted_index.len(),
            avg_doc_length: self.avg_doc_len,
            doc_types,
        }
    }

    /// Clear the index
    pub fn clear(&mut self) {
        self.documents.clear();
        self.inverted_index.clear();
        self.doc_freq.clear();
        self.avg_doc_len = 0.0;
    }
}

/// Index statistics
#[derive(Debug, Clone)]
pub struct IndexStats {
    pub total_documents: usize,
    pub total_terms: usize,
    pub avg_doc_length: f64,
    pub doc_types: HashMap<DocType, usize>,
}

/// Code-aware tokenization
pub fn tokenize_code(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            current.push(ch);
        } else if !current.is_empty() {
            // Split camelCase and snake_case
            tokens.extend(split_identifier(&current));
            current.clear();
        }
    }

    if !current.is_empty() {
        tokens.extend(split_identifier(&current));
    }

    // Lowercase and filter short tokens
    tokens
        .into_iter()
        .map(|t| t.to_lowercase())
        .filter(|t| t.len() >= 2)
        .filter(|t| !is_stop_word(t))
        .collect()
}

/// Split identifiers by camelCase, PascalCase, and snake_case
fn split_identifier(ident: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();

    let chars: Vec<char> = ident.chars().collect();

    for i in 0..chars.len() {
        let ch = chars[i];
        let prev_lower = i > 0 && chars[i - 1].is_lowercase();
        let next_lower = i + 1 < chars.len() && chars[i + 1].is_lowercase();

        // Split on underscore
        if ch == '_' {
            if !current.is_empty() {
                parts.push(current.clone());
                current.clear();
            }
            continue;
        }

        // Split on camelCase boundary
        if ch.is_uppercase()
            && (prev_lower || (i + 1 < chars.len() && next_lower))
            && !current.is_empty()
        {
            parts.push(current.clone());
            current.clear();
        }

        current.push(ch);
    }

    if !current.is_empty() {
        parts.push(current);
    }

    // Also include the full identifier
    parts.push(ident.to_string());

    parts
}

/// Count term frequencies
fn count_terms(tokens: &[String]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for token in tokens {
        *counts.entry(token.clone()).or_default() += 1;
    }
    counts
}

/// Check if a token is a common stop word in code
fn is_stop_word(token: &str) -> bool {
    const STOP_WORDS: &[&str] = &[
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "to", "of", "in", "for", "on",
        "with", "at", "by", "from", "if", "then", "else", "do", "while", "this", "that", "it",
        "let", "var", "const", "mut", "pub", "fn", "def", "class", "return", "true", "false",
        "null", "none", "nil", "self",
    ];
    STOP_WORDS.contains(&token)
}

/// Thread-safe search index wrapper
pub struct ConcurrentSearchIndex {
    /// The inner search index (public for direct access when needed)
    pub inner: RwLock<SearchIndex>,
}

impl Default for ConcurrentSearchIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl ConcurrentSearchIndex {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(SearchIndex::new()),
        }
    }

    /// Add a single document to the search index.
    /// Used by WASM interface for incremental indexing.
    pub fn add_document(&self, doc: SearchDocument) {
        self.inner.write().add_document(doc);
    }

    pub fn index_file(&self, file_path: &str, content: &str) {
        self.inner.write().index_file(file_path, content);
    }

    pub fn search(&self, query: &str, max_results: usize) -> Vec<SearchResult> {
        self.inner.read().search(query, max_results)
    }

    pub fn stats(&self) -> IndexStats {
        self.inner.read().stats()
    }

    pub fn clear(&self) {
        self.inner.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_camel_case() {
        let tokens = tokenize_code("getUserById");
        assert!(tokens.contains(&"get".to_string()));
        assert!(tokens.contains(&"user".to_string()));
        // "by" is filtered out as a stop word
        assert!(tokens.contains(&"id".to_string()));
        assert!(tokens.contains(&"getuserbyid".to_string())); // Full identifier is included
    }

    #[test]
    fn test_tokenize_snake_case() {
        let tokens = tokenize_code("get_user_by_id");
        assert!(tokens.contains(&"get".to_string()));
        assert!(tokens.contains(&"user".to_string()));
    }

    #[test]
    fn test_search_index() {
        let mut index = SearchIndex::new();

        index.index_file(
            "user.rs",
            r#"
            pub fn get_user_by_id(id: u32) -> User {
                // Fetch user from database
            }
        "#,
        );

        index.index_file(
            "order.rs",
            r#"
            pub fn create_order(user: &User) -> Order {
                // Create new order
            }
        "#,
        );

        let results = index.search("user", 10);
        assert!(!results.is_empty());
        assert!(results[0].score > 0.0);
    }

    #[test]
    fn test_split_identifier() {
        let parts = split_identifier("getUserByID");
        assert!(parts.contains(&"get".to_string()));
        assert!(parts.contains(&"User".to_string()));
        assert!(parts.contains(&"By".to_string()));
        assert!(parts.contains(&"ID".to_string()));
    }

    #[test]
    fn test_synonym_expansion() {
        let index = SearchIndex::new();
        let tokens = vec!["func".to_string()];
        let expanded = index.expand_query(&tokens);

        assert!(expanded.contains(&"function".to_string()) || expanded.contains(&"fn".to_string()));
    }

    // Security tests for regex DoS prevention
    #[test]
    fn test_validate_regex_pattern_valid() {
        let result = validate_regex_pattern("simple_pattern");
        assert!(result.is_ok());

        let result = validate_regex_pattern(r"fn\s+\w+");
        assert!(result.is_ok());
    }

    #[test]
    fn test_regex_dos_prevention_pattern_too_long() {
        // Prevent ReDoS by rejecting patterns >1000 chars
        let long_pattern = "a".repeat(1001);
        let result = validate_regex_pattern(&long_pattern);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Pattern too long (max 1000 chars)");
    }

    #[test]
    fn test_regex_dos_prevention_too_many_quantifiers() {
        // Prevent ReDoS by rejecting patterns with >20 quantifiers
        let dangerous_pattern = "a+b*c+d*e+f*g+h*i+j*k+l*m+n*o+p*q+r*s+t*u+v*w+x*y+z*";
        let result = validate_regex_pattern(dangerous_pattern);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Pattern has too many quantifiers");
    }

    #[test]
    fn test_validate_regex_pattern_invalid_syntax() {
        let invalid_pattern = "[invalid(";
        let result = validate_regex_pattern(invalid_pattern);
        assert!(result.is_err());
    }

    #[test]
    fn test_sort_handles_nan_scores() {
        let mut index = SearchIndex::new();

        index.index_file("a.rs", "fn hello() { }");
        index.index_file("b.rs", "fn world() { }");

        // Search should not panic even if scores could theoretically be NaN
        let results = index.search("hello", 10);
        assert!(!results.is_empty());

        // Directly test the sort with NaN values
        let mut scores: Vec<(usize, (f64, Vec<String>))> = vec![
            (0, (1.0, vec!["a".to_string()])),
            (1, (f64::NAN, vec!["b".to_string()])),
            (2, (0.5, vec!["c".to_string()])),
        ];
        // This should not panic with our fix
        scores.sort_by(|a, b| {
            b.1 .0
                .partial_cmp(&a.1 .0)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
}
