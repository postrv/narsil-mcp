use narsil_xref::streaming::{
    ProgressToken, Streamable, StreamableSearchResults, StreamableSymbols, StreamingConfig,
    StreamingResponse,
};

#[test]
fn test_progress_token_creation() {
    let token = ProgressToken::new("test_operation", 100);
    assert!(token.token.starts_with("test_operation_"));
    assert_eq!(token.total, 100);
    assert_eq!(token.current, 0);
    assert_eq!(token.percentage(), 0);
    assert!(!token.is_complete());
}

#[test]
fn test_progress_token_progress() {
    let mut token = ProgressToken::new("test", 200);

    token.current = 50;
    assert_eq!(token.percentage(), 25);
    assert!(!token.is_complete());

    token.current = 100;
    assert_eq!(token.percentage(), 50);
    assert!(!token.is_complete());

    token.current = 200;
    assert_eq!(token.percentage(), 100);
    assert!(token.is_complete());
}

#[test]
fn test_streaming_config_default() {
    let config = StreamingConfig::default();
    assert_eq!(config.default_chunk_size, 50);
    assert_eq!(config.auto_stream_threshold, 100);
    assert!(config.enabled);
}

#[test]
fn test_streamable_symbols() {
    let symbols = StreamableSymbols {
        symbols: (0..150).map(|i| format!("symbol_{}", i)).collect(),
    };

    assert_eq!(symbols.total_items(), 150);

    let chunks = symbols.split_into_chunks(50);
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0].len(), 50);
    assert_eq!(chunks[1].len(), 50);
    assert_eq!(chunks[2].len(), 50);
}

#[test]
fn test_streamable_symbols_uneven_chunks() {
    let symbols = StreamableSymbols {
        symbols: (0..155).map(|i| format!("symbol_{}", i)).collect(),
    };

    let chunks = symbols.split_into_chunks(50);
    assert_eq!(chunks.len(), 4);
    assert_eq!(chunks[0].len(), 50);
    assert_eq!(chunks[1].len(), 50);
    assert_eq!(chunks[2].len(), 50);
    assert_eq!(chunks[3].len(), 5);
}

#[test]
fn test_streamable_search_results() {
    let results = StreamableSearchResults {
        results: (0..25).map(|i| format!("result_{}", i)).collect(),
    };

    assert_eq!(results.total_items(), 25);

    let chunks = results.split_into_chunks(10);
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0].len(), 10);
    assert_eq!(chunks[1].len(), 10);
    assert_eq!(chunks[2].len(), 5);
}

#[test]
fn test_streaming_response_should_stream() {
    let config = StreamingConfig {
        default_chunk_size: 50,
        auto_stream_threshold: 100,
        enabled: true,
    };

    let response = StreamingResponse::new(config);

    // Should not stream small results
    assert!(!response.should_stream(50));
    assert!(!response.should_stream(100));

    // Should stream large results
    assert!(response.should_stream(101));
    assert!(response.should_stream(1000));
}

#[test]
fn test_streaming_response_disabled() {
    let config = StreamingConfig {
        default_chunk_size: 50,
        auto_stream_threshold: 100,
        enabled: false,
    };

    let response = StreamingResponse::new(config);

    // Should not stream even for large results when disabled
    assert!(!response.should_stream(1000));
}

#[test]
fn test_format_chunk_symbols() {
    let symbols = StreamableSymbols {
        symbols: vec!["sym1".to_string(), "sym2".to_string(), "sym3".to_string()],
    };

    let chunks = symbols.split_into_chunks(2);
    let formatted = symbols.format_chunk(&chunks[0], 0, 2);

    assert!(formatted.contains("Chunk 1"));
    assert!(formatted.contains("sym1"));
    assert!(formatted.contains("sym2"));
}

#[test]
fn test_format_chunk_search_results() {
    let results = StreamableSearchResults {
        results: vec!["result1".to_string(), "result2".to_string()],
    };

    let chunks = results.split_into_chunks(1);
    let formatted = results.format_chunk(&chunks[0], 0, 2);

    assert!(formatted.contains("Results chunk 1"));
    assert!(formatted.contains("result1"));
}
