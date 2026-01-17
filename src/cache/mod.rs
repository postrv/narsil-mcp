//! Analysis cache infrastructure for expensive operations
//!
//! Provides intelligent caching for security scans, call graphs, and other
//! computationally expensive operations. Features:
//! - Hash-based invalidation (file content hash + mtime)
//! - TTL-based expiration (configurable, default 30 minutes)
//! - Bounded cache size with LRU eviction
//!
//! # Examples
//!
//! ```rust,ignore
//! use narsil_mcp::cache::AnalysisCache;
//! use std::time::Duration;
//!
//! let cache = AnalysisCache::new(1000, Duration::from_secs(1800));
//! cache.insert("key", "value".to_string());
//! assert_eq!(cache.get("key"), Some("value".to_string()));
//! ```

mod invalidation;

pub use invalidation::FileHashTracker;

use dashmap::DashMap;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Statistics for cache operations
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
    /// Number of items evicted due to LRU
    pub evictions: u64,
    /// Number of items expired due to TTL
    pub expirations: u64,
    /// Current number of items in cache
    pub size: usize,
    /// Maximum cache capacity
    pub capacity: usize,
}

impl CacheStats {
    /// Calculate the cache hit rate as a percentage
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// A cached entry with metadata
#[derive(Debug, Clone)]
struct CacheEntry<V> {
    /// The cached value
    value: V,
    /// When this entry was created
    created_at: Instant,
    /// Content hash for invalidation
    content_hash: Option<String>,
}

impl<V> CacheEntry<V> {
    fn new(value: V, content_hash: Option<String>) -> Self {
        Self {
            value,
            created_at: Instant::now(),
            content_hash,
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }
}

/// Thread-safe analysis cache with TTL expiration and LRU eviction
///
/// # Type Parameters
///
/// * `K` - Key type, must be hashable and comparable
/// * `V` - Value type, must be cloneable
pub struct AnalysisCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// The underlying concurrent map
    store: DashMap<K, CacheEntry<V>>,
    /// LRU tracking (most recent at back)
    lru_order: Mutex<VecDeque<K>>,
    /// Maximum number of entries
    capacity: usize,
    /// Time-to-live for entries
    ttl: Duration,
    /// Statistics
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    expirations: AtomicU64,
}

impl<K, V> AnalysisCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create a new cache with specified capacity and TTL
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of entries before LRU eviction
    /// * `ttl` - Time-to-live for entries
    ///
    /// # Panics
    ///
    /// Panics if capacity is 0
    #[must_use]
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        assert!(capacity > 0, "Cache capacity must be greater than 0");
        Self {
            store: DashMap::with_capacity(capacity),
            lru_order: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            ttl,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            expirations: AtomicU64::new(0),
        }
    }

    /// Create a cache with default settings (1000 entries, 30 min TTL)
    #[must_use]
    pub fn default_settings() -> Self {
        Self::new(1000, Duration::from_secs(1800))
    }

    /// Insert a value into the cache
    ///
    /// If the cache is at capacity, the least recently used entry is evicted.
    /// If the key already exists, the value is updated and the key is moved
    /// to the end of the LRU queue.
    pub fn insert(&self, key: K, value: V) {
        self.insert_with_hash(key, value, None);
    }

    /// Insert a value with an associated content hash for invalidation
    ///
    /// The content hash can later be used to invalidate the entry if the
    /// underlying content has changed.
    pub fn insert_with_hash(&self, key: K, value: V, content_hash: Option<String>) {
        // Check if we need to evict before inserting
        if !self.store.contains_key(&key) && self.store.len() >= self.capacity {
            self.evict_lru();
        }

        // Update LRU order
        {
            let mut lru = self.lru_order.lock();
            // Remove old position if exists
            lru.retain(|k| k != &key);
            // Add to back (most recently used)
            lru.push_back(key.clone());
        }

        // Insert the entry
        self.store.insert(key, CacheEntry::new(value, content_hash));
    }

    /// Get a value from the cache
    ///
    /// Returns `None` if the key is not found or the entry has expired.
    /// Updates the LRU order on successful retrieval.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<V> {
        if let Some(entry) = self.store.get(key) {
            // Check if expired
            if entry.is_expired(self.ttl) {
                drop(entry); // Release the lock before removing
                self.remove(key);
                self.expirations.fetch_add(1, Ordering::Relaxed);
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            // Update LRU order
            {
                let mut lru = self.lru_order.lock();
                lru.retain(|k| k != key);
                lru.push_back(key.clone());
            }

            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.value.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Get a value if the content hash matches
    ///
    /// Returns `None` if the key is not found, expired, or the hash doesn't match.
    /// This is useful for invalidation based on content changes.
    #[must_use]
    pub fn get_if_hash_matches(&self, key: &K, expected_hash: &str) -> Option<V> {
        if let Some(entry) = self.store.get(key) {
            // Check if expired
            if entry.is_expired(self.ttl) {
                drop(entry);
                self.remove(key);
                self.expirations.fetch_add(1, Ordering::Relaxed);
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            // Check hash
            if let Some(ref stored_hash) = entry.content_hash {
                if stored_hash != expected_hash {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }

            // Update LRU order
            {
                let mut lru = self.lru_order.lock();
                lru.retain(|k| k != key);
                lru.push_back(key.clone());
            }

            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.value.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Remove an entry from the cache
    pub fn remove(&self, key: &K) -> Option<V> {
        let removed = self.store.remove(key);

        if removed.is_some() {
            let mut lru = self.lru_order.lock();
            lru.retain(|k| k != key);
        }

        removed.map(|(_, entry)| entry.value)
    }

    /// Invalidate entries matching a predicate
    ///
    /// This is useful for bulk invalidation, e.g., when a file changes
    /// and all related cache entries should be cleared.
    pub fn invalidate_where<F>(&self, predicate: F)
    where
        F: Fn(&K) -> bool,
    {
        let keys_to_remove: Vec<K> = self
            .store
            .iter()
            .filter(|entry| predicate(entry.key()))
            .map(|entry| entry.key().clone())
            .collect();

        for key in keys_to_remove {
            self.remove(&key);
        }
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        self.store.clear();
        self.lru_order.lock().clear();
    }

    /// Get the current number of entries in the cache
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Check if the cache is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Get cache statistics
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            expirations: self.expirations.load(Ordering::Relaxed),
            size: self.store.len(),
            capacity: self.capacity,
        }
    }

    /// Reset statistics counters
    pub fn reset_stats(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
        self.expirations.store(0, Ordering::Relaxed);
    }

    /// Evict the least recently used entry
    fn evict_lru(&self) {
        let key_to_remove = {
            let mut lru = self.lru_order.lock();
            lru.pop_front()
        };

        if let Some(key) = key_to_remove {
            self.store.remove(&key);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Prune expired entries
    ///
    /// This can be called periodically to clean up expired entries
    /// without waiting for them to be accessed.
    pub fn prune_expired(&self) {
        let expired_keys: Vec<K> = self
            .store
            .iter()
            .filter(|entry| entry.value().is_expired(self.ttl))
            .map(|entry| entry.key().clone())
            .collect();

        for key in expired_keys {
            self.store.remove(&key);
            {
                let mut lru = self.lru_order.lock();
                lru.retain(|k| k != &key);
            }
            self.expirations.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Compute a SHA-256 hash of content
#[must_use]
pub fn compute_hash(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

/// A cache key for analysis results
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AnalysisCacheKey {
    /// Repository name
    pub repo: String,
    /// Analysis type (e.g., "security_summary", "call_graph")
    pub analysis_type: String,
    /// Optional additional discriminator (e.g., file path, function name)
    pub discriminator: Option<String>,
}

impl AnalysisCacheKey {
    /// Create a new cache key
    #[must_use]
    pub fn new(repo: impl Into<String>, analysis_type: impl Into<String>) -> Self {
        Self {
            repo: repo.into(),
            analysis_type: analysis_type.into(),
            discriminator: None,
        }
    }

    /// Create a cache key with a discriminator
    #[must_use]
    pub fn with_discriminator(
        repo: impl Into<String>,
        analysis_type: impl Into<String>,
        discriminator: impl Into<String>,
    ) -> Self {
        Self {
            repo: repo.into(),
            analysis_type: analysis_type.into(),
            discriminator: Some(discriminator.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_cache_hit_miss() {
        let cache: AnalysisCache<String, String> = AnalysisCache::new(100, Duration::from_secs(60));

        // Miss on empty cache
        assert!(cache.get(&"key1".to_string()).is_none());

        // Insert and hit
        cache.insert("key1".to_string(), "value1".to_string());
        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));

        // Verify stats
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_cache_update() {
        let cache: AnalysisCache<String, String> = AnalysisCache::new(100, Duration::from_secs(60));

        cache.insert("key1".to_string(), "value1".to_string());
        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));

        // Update existing key
        cache.insert("key1".to_string(), "value2".to_string());
        assert_eq!(cache.get(&"key1".to_string()), Some("value2".to_string()));

        // Size should still be 1
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_removal() {
        let cache: AnalysisCache<String, String> = AnalysisCache::new(100, Duration::from_secs(60));

        cache.insert("key1".to_string(), "value1".to_string());
        assert_eq!(cache.len(), 1);

        let removed = cache.remove(&"key1".to_string());
        assert_eq!(removed, Some("value1".to_string()));
        assert_eq!(cache.len(), 0);
        assert!(cache.get(&"key1".to_string()).is_none());
    }

    #[test]
    fn test_ttl_expiration() {
        let cache: AnalysisCache<String, String> =
            AnalysisCache::new(100, Duration::from_millis(50));

        cache.insert("key1".to_string(), "value1".to_string());
        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));

        // Wait for TTL to expire
        thread::sleep(Duration::from_millis(60));

        // Should return None and count as expired
        assert!(cache.get(&"key1".to_string()).is_none());

        let stats = cache.stats();
        assert_eq!(stats.expirations, 1);
    }

    #[test]
    fn test_lru_eviction() {
        let cache: AnalysisCache<String, String> = AnalysisCache::new(3, Duration::from_secs(60));

        // Fill cache
        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());
        cache.insert("key3".to_string(), "value3".to_string());

        assert_eq!(cache.len(), 3);

        // Access key1 to make it recently used
        let _ = cache.get(&"key1".to_string());

        // Insert new key, should evict key2 (least recently used)
        cache.insert("key4".to_string(), "value4".to_string());

        assert_eq!(cache.len(), 3);
        assert!(cache.get(&"key2".to_string()).is_none()); // Evicted
        assert!(cache.get(&"key1".to_string()).is_some()); // Still present
        assert!(cache.get(&"key3".to_string()).is_some()); // Still present
        assert!(cache.get(&"key4".to_string()).is_some()); // Newly added

        let stats = cache.stats();
        assert_eq!(stats.evictions, 1);
    }

    #[test]
    fn test_hash_based_invalidation() {
        let cache: AnalysisCache<String, String> = AnalysisCache::new(100, Duration::from_secs(60));

        let hash1 = compute_hash(b"content1");
        let hash2 = compute_hash(b"content2");

        cache.insert_with_hash(
            "key1".to_string(),
            "value1".to_string(),
            Some(hash1.clone()),
        );

        // Same hash should return value
        assert_eq!(
            cache.get_if_hash_matches(&"key1".to_string(), &hash1),
            Some("value1".to_string())
        );

        // Different hash should return None (content changed)
        assert!(cache
            .get_if_hash_matches(&"key1".to_string(), &hash2)
            .is_none());
    }

    #[test]
    fn test_invalidate_where() {
        let cache: AnalysisCache<String, String> = AnalysisCache::new(100, Duration::from_secs(60));

        cache.insert("repo1:file1".to_string(), "value1".to_string());
        cache.insert("repo1:file2".to_string(), "value2".to_string());
        cache.insert("repo2:file1".to_string(), "value3".to_string());

        assert_eq!(cache.len(), 3);

        // Invalidate all entries for repo1
        cache.invalidate_where(|k| k.starts_with("repo1:"));

        assert_eq!(cache.len(), 1);
        assert!(cache.get(&"repo1:file1".to_string()).is_none());
        assert!(cache.get(&"repo1:file2".to_string()).is_none());
        assert!(cache.get(&"repo2:file1".to_string()).is_some());
    }

    #[test]
    fn test_clear() {
        let cache: AnalysisCache<String, String> = AnalysisCache::new(100, Duration::from_secs(60));

        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_prune_expired() {
        let cache: AnalysisCache<String, String> =
            AnalysisCache::new(100, Duration::from_millis(50));

        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());

        thread::sleep(Duration::from_millis(60));

        // Add a fresh entry
        cache.insert("key3".to_string(), "value3".to_string());

        assert_eq!(cache.len(), 3);

        cache.prune_expired();

        // Only key3 should remain
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&"key3".to_string()).is_some());
    }

    #[test]
    fn test_cache_stats_hit_rate() {
        let cache: AnalysisCache<String, String> = AnalysisCache::new(100, Duration::from_secs(60));

        // 3 misses (key doesn't exist)
        let _ = cache.get(&"key1".to_string());
        let _ = cache.get(&"key2".to_string());
        let _ = cache.get(&"key3".to_string());

        cache.insert("key1".to_string(), "value1".to_string());

        // 1 hit
        let _ = cache.get(&"key1".to_string());

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 3);
        assert!((stats.hit_rate() - 25.0).abs() < 0.01);
    }

    #[test]
    fn test_cache_key_creation() {
        let key1 = AnalysisCacheKey::new("narsil-mcp", "security_summary");
        assert_eq!(key1.repo, "narsil-mcp");
        assert_eq!(key1.analysis_type, "security_summary");
        assert!(key1.discriminator.is_none());

        let key2 =
            AnalysisCacheKey::with_discriminator("narsil-mcp", "call_graph", "main::process");
        assert_eq!(key2.discriminator, Some("main::process".to_string()));

        // Keys should be hashable
        let cache: AnalysisCache<AnalysisCacheKey, String> =
            AnalysisCache::new(100, Duration::from_secs(60));
        cache.insert(key1.clone(), "result1".to_string());
        assert_eq!(cache.get(&key1), Some("result1".to_string()));
    }

    #[test]
    fn test_compute_hash() {
        let hash1 = compute_hash(b"hello world");
        let hash2 = compute_hash(b"hello world");
        let hash3 = compute_hash(b"hello world!");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64); // SHA-256 produces 64 hex chars
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;

        let cache = Arc::new(AnalysisCache::<String, String>::new(
            1000,
            Duration::from_secs(60),
        ));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let cache = Arc::clone(&cache);
                thread::spawn(move || {
                    for j in 0..100 {
                        let key = format!("thread{}:key{}", i, j);
                        let value = format!("value{}", j);
                        cache.insert(key.clone(), value.clone());
                        let _ = cache.get(&key);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have many entries (some may be evicted if capacity exceeded)
        assert!(!cache.is_empty());
    }

    #[test]
    #[should_panic(expected = "capacity must be greater than 0")]
    fn test_zero_capacity_panics() {
        let _cache: AnalysisCache<String, String> = AnalysisCache::new(0, Duration::from_secs(60));
    }

    #[test]
    fn test_default_settings() {
        let cache: AnalysisCache<String, String> = AnalysisCache::default_settings();
        assert_eq!(cache.capacity, 1000);
    }
}
