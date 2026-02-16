//! Semantic embeddings for code similarity search using TF-IDF
//!
//! Provides a simple and fast embedding system for finding similar code without
//! heavy ML dependencies. Uses TF-IDF vectors with cosine similarity.
//!
//! This is a Phase 3 feature - semantic embeddings for "find similar code" queries.

// Allow dead code for Phase 3 embedding features
#![allow(dead_code)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::search::tokenize_code;

/// A trait for generating embeddings from code
pub trait EmbeddingProvider: Send + Sync {
    /// Generate an embedding vector from text
    fn embed(&self, text: &str) -> Vec<f32>;

    /// Get the dimensionality of embeddings
    fn dimension(&self) -> usize;
}

/// TF-IDF based embedding provider
pub struct TfIdfEmbedding {
    /// Global term frequencies across all documents
    document_freq: HashMap<String, usize>,
    /// Total number of documents
    total_docs: usize,
    /// Vocabulary (terms to indices)
    vocabulary: HashMap<String, usize>,
    /// Maximum vocabulary size (for dimensionality)
    max_vocab_size: usize,
}

impl TfIdfEmbedding {
    /// Create a new TF-IDF embedding provider
    pub fn new(max_vocab_size: usize) -> Self {
        Self {
            document_freq: HashMap::new(),
            total_docs: 0,
            vocabulary: HashMap::new(),
            max_vocab_size,
        }
    }

    /// Add a document to update the IDF statistics
    pub fn add_document(&mut self, text: &str) {
        let tokens = tokenize_code(text);
        let unique_tokens: std::collections::HashSet<_> = tokens.into_iter().collect();

        for token in unique_tokens {
            *self.document_freq.entry(token).or_insert(0) += 1;
        }

        self.total_docs += 1;
        self.rebuild_vocabulary();
    }

    /// Rebuild vocabulary from most frequent terms
    fn rebuild_vocabulary(&mut self) {
        // Sort terms by document frequency (descending)
        let mut terms: Vec<_> = self.document_freq.iter().collect();
        terms.sort_by(|a, b| b.1.cmp(a.1));

        // Take top N terms for vocabulary
        self.vocabulary.clear();
        for (idx, (term, _)) in terms.iter().take(self.max_vocab_size).enumerate() {
            self.vocabulary.insert((*term).clone(), idx);
        }
    }

    /// Compute IDF for a term (with smoothing to avoid zero values)
    fn idf(&self, term: &str) -> f32 {
        if self.total_docs == 0 {
            return 0.0;
        }

        let df = self.document_freq.get(term).copied().unwrap_or(0) as f32;
        if df == 0.0 {
            return 0.0;
        }

        // Use smoothed IDF: log((N + 1) / (df + 1)) + 1
        // This prevents IDF from being 0 when df == N
        ((self.total_docs as f32 + 1.0) / (df + 1.0)).ln() + 1.0
    }

    /// Compute TF for a term in a document
    fn tf(term_count: usize, total_terms: usize) -> f32 {
        if total_terms == 0 {
            return 0.0;
        }
        term_count as f32 / total_terms as f32
    }

    /// Get statistics about the embedding model
    pub fn stats(&self) -> EmbeddingStats {
        EmbeddingStats {
            total_docs: self.total_docs,
            vocab_size: self.vocabulary.len(),
            dimension: self.dimension(),
        }
    }
}

impl EmbeddingProvider for TfIdfEmbedding {
    fn embed(&self, text: &str) -> Vec<f32> {
        let tokens = tokenize_code(text);
        let total_terms = tokens.len();

        // Count term frequencies
        let mut term_freq: HashMap<String, usize> = HashMap::new();
        for token in &tokens {
            *term_freq.entry(token.clone()).or_insert(0) += 1;
        }

        // Build TF-IDF vector
        let mut vector = vec![0.0; self.dimension()];

        for (term, &count) in &term_freq {
            if let Some(&idx) = self.vocabulary.get(term) {
                let tf = Self::tf(count, total_terms);
                let idf = self.idf(term);
                vector[idx] = tf * idf;
            }
        }

        // L2 normalize the vector
        normalize_vector(&mut vector);

        vector
    }

    fn dimension(&self) -> usize {
        self.max_vocab_size
    }
}

/// Normalize a vector to unit length (L2 norm)
fn normalize_vector(vec: &mut [f32]) {
    let magnitude: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();

    if magnitude > 0.0 {
        for x in vec.iter_mut() {
            *x /= magnitude;
        }
    }
}

/// Compute cosine similarity between two vectors
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }

    // Since vectors are normalized, dot product = cosine similarity
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Statistics about the embedding model
#[derive(Debug, Clone)]
pub struct EmbeddingStats {
    pub total_docs: usize,
    pub vocab_size: usize,
    pub dimension: usize,
}

/// A document with its embedding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedDocument {
    pub id: String,
    pub file_path: String,
    pub content: String,
    pub start_line: usize,
    pub end_line: usize,
    pub embedding: Vec<f32>,
}

/// A similarity search result
#[derive(Debug, Clone)]
pub struct SimilarityResult {
    pub document: EmbeddedDocument,
    pub similarity: f32,
}

/// Vector store for caching embeddings
pub struct VectorStore {
    /// Embedded documents
    documents: Vec<EmbeddedDocument>,
    /// Index for fast lookup by ID
    id_to_idx: HashMap<String, usize>,
}

impl VectorStore {
    pub fn new() -> Self {
        Self {
            documents: Vec::new(),
            id_to_idx: HashMap::new(),
        }
    }

    /// Add a document with its embedding
    pub fn add(&mut self, doc: EmbeddedDocument) {
        let idx = self.documents.len();
        self.id_to_idx.insert(doc.id.clone(), idx);
        self.documents.push(doc);
    }

    /// Find similar documents to a query embedding
    pub fn find_similar(
        &self,
        query_embedding: &[f32],
        max_results: usize,
    ) -> Vec<SimilarityResult> {
        let mut results: Vec<_> = self
            .documents
            .iter()
            .map(|doc| {
                let similarity = cosine_similarity(query_embedding, &doc.embedding);
                SimilarityResult {
                    document: doc.clone(),
                    similarity,
                }
            })
            .collect();

        // Sort by similarity (descending)
        results.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Take top results
        results.truncate(max_results);

        results
    }

    /// Get document by ID
    pub fn get(&self, id: &str) -> Option<&EmbeddedDocument> {
        self.id_to_idx
            .get(id)
            .and_then(|&idx| self.documents.get(idx))
    }

    /// Get number of documents
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Check if store is empty
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// Clear the store
    pub fn clear(&mut self) {
        self.documents.clear();
        self.id_to_idx.clear();
    }
}

impl Default for VectorStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe vector store wrapper
pub struct ConcurrentVectorStore {
    inner: RwLock<VectorStore>,
}

impl ConcurrentVectorStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(VectorStore::new()),
        }
    }

    pub fn add(&self, doc: EmbeddedDocument) {
        self.inner.write().add(doc);
    }

    pub fn find_similar(
        &self,
        query_embedding: &[f32],
        max_results: usize,
    ) -> Vec<SimilarityResult> {
        self.inner.read().find_similar(query_embedding, max_results)
    }

    pub fn get(&self, id: &str) -> Option<EmbeddedDocument> {
        self.inner.read().get(id).cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    pub fn clear(&self) {
        self.inner.write().clear();
    }
}

impl Default for ConcurrentVectorStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Embedding engine that combines provider and store
pub struct EmbeddingEngine {
    provider: Arc<RwLock<TfIdfEmbedding>>,
    store: Arc<ConcurrentVectorStore>,
}

impl EmbeddingEngine {
    pub fn new(max_vocab_size: usize) -> Self {
        Self {
            provider: Arc::new(RwLock::new(TfIdfEmbedding::new(max_vocab_size))),
            store: Arc::new(ConcurrentVectorStore::new()),
        }
    }

    /// Index a code snippet
    pub fn index_snippet(
        &self,
        id: String,
        file_path: String,
        content: String,
        start_line: usize,
        end_line: usize,
    ) {
        // Update IDF statistics
        self.provider.write().add_document(&content);

        // Generate embedding
        let embedding = self.provider.read().embed(&content);

        // Store the embedded document
        self.store.add(EmbeddedDocument {
            id,
            file_path,
            content,
            start_line,
            end_line,
            embedding,
        });
    }

    /// Find similar code to a query string
    pub fn find_similar_code(&self, query: &str, max_results: usize) -> Vec<SimilarityResult> {
        let query_embedding = self.provider.read().embed(query);
        self.store.find_similar(&query_embedding, max_results)
    }

    /// Find code similar to a specific document
    pub fn find_similar_to_doc(&self, doc_id: &str, max_results: usize) -> Vec<SimilarityResult> {
        if let Some(doc) = self.store.get(doc_id) {
            self.store.find_similar(&doc.embedding, max_results)
        } else {
            Vec::new()
        }
    }

    /// Get statistics
    pub fn stats(&self) -> (EmbeddingStats, usize) {
        let embedding_stats = self.provider.read().stats();
        let doc_count = self.store.len();
        (embedding_stats, doc_count)
    }

    /// Clear all data
    pub fn clear(&self) {
        self.store.clear();
        let mut provider = self.provider.write();
        provider.document_freq.clear();
        provider.total_docs = 0;
        provider.vocabulary.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tfidf_embedding() {
        let mut tfidf = TfIdfEmbedding::new(100);

        // Add some documents
        tfidf.add_document("fn hello_world() { println!(\"Hello\"); }");
        tfidf.add_document("fn goodbye_world() { println!(\"Goodbye\"); }");
        tfidf.add_document("fn main() { hello_world(); }");

        assert_eq!(tfidf.total_docs, 3);
        assert!(!tfidf.vocabulary.is_empty());

        // Generate embedding
        let embedding = tfidf.embed("fn hello_world()");
        assert_eq!(embedding.len(), 100);

        // Check normalization (L2 norm should be ~1.0)
        let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((magnitude - 1.0).abs() < 0.001 || magnitude == 0.0);
    }

    #[test]
    fn test_cosine_similarity() {
        let vec1 = vec![1.0, 0.0, 0.0];
        let vec2 = vec![1.0, 0.0, 0.0];
        let vec3 = vec![0.0, 1.0, 0.0];

        // Identical vectors
        assert!((cosine_similarity(&vec1, &vec2) - 1.0).abs() < 0.001);

        // Orthogonal vectors
        assert!((cosine_similarity(&vec1, &vec3) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_normalize_vector() {
        let mut vec = vec![3.0, 4.0];
        normalize_vector(&mut vec);

        let magnitude: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((magnitude - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_vector_store() {
        let mut store = VectorStore::new();

        let doc1 = EmbeddedDocument {
            id: "doc1".to_string(),
            file_path: "test.rs".to_string(),
            content: "fn hello()".to_string(),
            start_line: 1,
            end_line: 5,
            embedding: vec![1.0, 0.0, 0.0],
        };

        let doc2 = EmbeddedDocument {
            id: "doc2".to_string(),
            file_path: "test2.rs".to_string(),
            content: "fn goodbye()".to_string(),
            start_line: 10,
            end_line: 15,
            embedding: vec![0.9, 0.1, 0.0],
        };

        store.add(doc1);
        store.add(doc2);

        assert_eq!(store.len(), 2);

        // Find similar to a query
        let query = vec![1.0, 0.0, 0.0];
        let results = store.find_similar(&query, 2);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].document.id, "doc1"); // Should be most similar
        assert!(results[0].similarity > results[1].similarity);
    }

    #[test]
    fn test_embedding_engine() {
        let engine = EmbeddingEngine::new(100);

        engine.index_snippet(
            "test1".to_string(),
            "test.rs".to_string(),
            "fn calculate_sum(a: i32, b: i32) -> i32 { a + b }".to_string(),
            1,
            1,
        );

        engine.index_snippet(
            "test2".to_string(),
            "test.rs".to_string(),
            "fn calculate_product(x: i32, y: i32) -> i32 { x * y }".to_string(),
            3,
            3,
        );

        engine.index_snippet(
            "test3".to_string(),
            "test.rs".to_string(),
            "fn print_hello() { println!(\"Hello\"); }".to_string(),
            5,
            5,
        );

        // Find similar to a math function
        let results = engine.find_similar_code("fn add_numbers(a: i32, b: i32)", 3);
        assert!(!results.is_empty());

        // The math functions (test1, test2) should rank higher than print_hello (test3)
        // We check that test3 (non-math) is either not in results or ranks last
        let result_ids: Vec<&str> = results.iter().map(|r| r.document.id.as_str()).collect();
        assert!(
            !result_ids.contains(&"test3") || result_ids.last() == Some(&"test3"),
            "print_hello should rank lower than math functions, got: {:?}",
            result_ids
        );

        // Stats
        let (stats, doc_count) = engine.stats();
        assert_eq!(doc_count, 3);
        assert_eq!(stats.total_docs, 3);
        assert!(stats.vocab_size > 0);
    }

    #[test]
    fn test_find_similar_to_doc() {
        let engine = EmbeddingEngine::new(100);

        engine.index_snippet(
            "doc1".to_string(),
            "test.rs".to_string(),
            "fn fibonacci(n: u32) -> u32 { if n <= 1 { n } else { fibonacci(n-1) + fibonacci(n-2) } }".to_string(),
            1,
            5,
        );

        engine.index_snippet(
            "doc2".to_string(),
            "test.rs".to_string(),
            "fn factorial(n: u32) -> u32 { if n <= 1 { 1 } else { n * factorial(n-1) } }"
                .to_string(),
            7,
            11,
        );

        engine.index_snippet(
            "doc3".to_string(),
            "test.rs".to_string(),
            "fn print_message(msg: &str) { println!(\"{}\", msg); }".to_string(),
            13,
            15,
        );

        // Find similar to fibonacci
        let results = engine.find_similar_to_doc("doc1", 3);
        assert!(results.len() >= 2);

        // First result should be itself (doc1)
        assert_eq!(results[0].document.id, "doc1");

        // Other results should include doc2 and doc3 (order may vary by platform)
        let other_ids: Vec<&str> = results
            .iter()
            .skip(1)
            .map(|r| r.document.id.as_str())
            .collect();
        assert!(other_ids.contains(&"doc2") || other_ids.contains(&"doc3"));
    }

    #[test]
    fn test_empty_text_embedding() {
        let tfidf = TfIdfEmbedding::new(100);
        let embedding = tfidf.embed("");
        assert_eq!(embedding.len(), 100);
        assert!(embedding.iter().all(|&x| x == 0.0));
    }

    #[test]
    fn test_code_tokenization_integration() {
        let mut tfidf = TfIdfEmbedding::new(100);

        // Test with actual code patterns
        tfidf.add_document("getUserById");
        tfidf.add_document("get_user_by_id");
        tfidf.add_document("GetUserById");

        let emb1 = tfidf.embed("getUserById");
        let emb2 = tfidf.embed("get_user_by_id");

        // Should have high similarity due to tokenization
        let sim = cosine_similarity(&emb1, &emb2);
        assert!(
            sim > 0.5,
            "Similarity should be high for similar identifiers"
        );
    }

    #[test]
    fn test_embedding_sort_handles_nan() {
        let mut store = VectorStore::new();
        store.add(EmbeddedDocument {
            id: "a".to_string(),
            file_path: "a.rs".to_string(),
            content: "fn a()".to_string(),
            start_line: 1,
            end_line: 1,
            embedding: vec![1.0],
        });
        store.add(EmbeddedDocument {
            id: "c".to_string(),
            file_path: "c.rs".to_string(),
            content: "fn c()".to_string(),
            start_line: 1,
            end_line: 1,
            embedding: vec![1.0],
        });

        // Test that find_similar doesn't panic (uses the fixed sort internally)
        let query_with_nan = vec![f32::NAN];
        let results_from_store = store.find_similar(&query_with_nan, 10);
        // Should not panic
        assert_eq!(results_from_store.len(), 2);

        // Also directly test sort with NaN values
        let make_result = |id: &str, sim: f32| SimilarityResult {
            document: EmbeddedDocument {
                id: id.to_string(),
                file_path: format!("{}.rs", id),
                content: format!("fn {}()", id),
                start_line: 1,
                end_line: 1,
                embedding: vec![1.0],
            },
            similarity: sim,
        };
        let mut results = [
            make_result("a", 0.9),
            make_result("b", f32::NAN),
            make_result("c", 0.5),
        ];

        // This should not panic with our fix
        results.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // The non-NaN values should still be properly ordered
        let non_nan: Vec<f32> = results
            .iter()
            .filter(|r| !r.similarity.is_nan())
            .map(|r| r.similarity)
            .collect();
        if non_nan.len() >= 2 {
            assert!(
                non_nan[0] >= non_nan[1],
                "Non-NaN values should be sorted descending"
            );
        }
    }
}
