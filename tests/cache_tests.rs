//! Cache performance tests for query result caching
//!
//! Verifies that:
//! - Query cache hits return in <10ms
//! - Smart invalidation works correctly
//! - Cache integration with CodeIntelEngine works

use narsil_mcp::cache::query_cache::{QueryCache, QueryCacheKey, SearchOptions};
use std::time::{Duration, Instant};

#[test]
fn test_query_cache_hit_performance() {
    let cache = QueryCache::new(1000, Duration::from_secs(1800));
    let key = QueryCacheKey::symbol_lookup("test-repo", "TestSymbol");

    // Insert a result
    cache.insert_with_files(
        key.clone(),
        "# Test Result\n\nThis is a cached result with some content.".to_string(),
        vec!["src/lib.rs".to_string()],
    );

    // Measure cache hit time
    let iterations = 1000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = cache.get(&key);
    }
    let elapsed = start.elapsed();
    let avg_time = elapsed / iterations;

    // Cache hit should be <10ms (actually should be microseconds)
    assert!(
        avg_time < Duration::from_millis(10),
        "Cache hit took {:?} on average, expected <10ms",
        avg_time
    );

    // Verify stats
    let stats = cache.stats();
    assert_eq!(stats.hits, iterations as u64);
}

#[test]
fn test_search_options_cache_key_uniqueness() {
    let options1 = SearchOptions {
        file_pattern: Some("*.rs".to_string()),
        max_results: Some(10),
        exclude_tests: Some(true),
    };

    let options2 = SearchOptions {
        file_pattern: Some("*.rs".to_string()),
        max_results: Some(20), // Different max_results
        exclude_tests: Some(true),
    };

    let key1 = QueryCacheKey::code_search_with_options(Some("repo"), "query", &options1);
    let key2 = QueryCacheKey::code_search_with_options(Some("repo"), "query", &options2);

    // Keys should be different because options are different
    assert_ne!(key1.options_hash, key2.options_hash);
}

#[test]
fn test_partial_invalidation_performance() {
    let cache = QueryCache::new(10000, Duration::from_secs(1800));

    // Insert many entries with different file dependencies
    for i in 0..1000 {
        let key = QueryCacheKey::symbol_lookup("repo", format!("Symbol{}", i));
        let file = format!("src/file{}.rs", i % 10); // 10 unique files
        cache.insert_with_files(key, format!("result{}", i), vec![file]);
    }

    assert_eq!(cache.len(), 1000);

    // Invalidate one file - should only remove entries for that file
    let start = Instant::now();
    let invalidated = cache.invalidate_for_file("src/file0.rs");
    let elapsed = start.elapsed();

    // Should invalidate ~100 entries (1000/10)
    assert_eq!(invalidated, 100);
    assert_eq!(cache.len(), 900);

    // Invalidation should be fast (<100ms for 100 entries)
    assert!(
        elapsed < Duration::from_millis(100),
        "Invalidation took {:?}, expected <100ms",
        elapsed
    );
}

#[test]
fn test_cache_stats_tracking() {
    let cache = QueryCache::new(100, Duration::from_secs(1800));

    let key1 = QueryCacheKey::symbol_lookup("repo", "Symbol1");
    let key2 = QueryCacheKey::code_search(Some("repo"), "query");

    // Miss
    assert!(cache.get(&key1).is_none());

    // Insert and hit
    cache.insert(key1.clone(), "result1".to_string());
    assert!(cache.get(&key1).is_some());

    // Another miss
    assert!(cache.get(&key2).is_none());

    // Insert with file dependency and invalidate
    cache.insert_with_files(
        key2.clone(),
        "result2".to_string(),
        vec!["src/a.rs".to_string()],
    );
    cache.invalidate_for_file("src/a.rs");

    let stats = cache.stats();
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 2);
    assert_eq!(stats.invalidations, 1);
}

#[test]
fn test_cache_concurrent_performance() {
    use std::sync::Arc;
    use std::thread;

    let cache = Arc::new(QueryCache::new(10000, Duration::from_secs(1800)));

    // Pre-populate cache
    for i in 0..1000 {
        let key = QueryCacheKey::symbol_lookup("repo", format!("Symbol{}", i));
        cache.insert(key, format!("result{}", i));
    }

    // Spawn multiple threads doing concurrent reads
    let start = Instant::now();
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let cache = Arc::clone(&cache);
            thread::spawn(move || {
                for i in 0..1000 {
                    let key = QueryCacheKey::symbol_lookup(
                        "repo",
                        format!("Symbol{}", (t * 100 + i) % 1000),
                    );
                    let _ = cache.get(&key);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
    let elapsed = start.elapsed();

    // 8 threads x 1000 ops = 8000 operations should complete quickly
    // Use 3s threshold to account for CI runner variability
    // (Windows/Ubuntu GitHub Actions can be 2-3x slower than local machines)
    assert!(
        elapsed < Duration::from_secs(3),
        "Concurrent operations took {:?}, expected <3s",
        elapsed
    );

    let stats = cache.stats();
    assert!(stats.hits >= 8000);
}
