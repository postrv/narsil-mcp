// Library exports for integration tests
#![recursion_limit = "256"]

/// Program name; also names the config, cache, state and runtime directories.
pub const APP_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Make tree-sitter's C code allocate from mimalloc. musl's malloc serializes
/// all threads on one lock.
///
/// # Safety
/// No tree-sitter object may exist yet: mi_free on a block from musl's malloc
/// corrupts the heap.
#[cfg(target_env = "musl")]
pub unsafe fn route_tree_sitter_allocations_to_mimalloc() {
    use std::ffi::c_void;
    extern "C" {
        fn mi_malloc(size: usize) -> *mut c_void;
        fn mi_calloc(count: usize, size: usize) -> *mut c_void;
        fn mi_realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
        fn mi_free(ptr: *mut c_void);
    }
    tree_sitter::set_allocator(
        Some(mi_malloc),
        Some(mi_calloc),
        Some(mi_realloc),
        Some(mi_free),
    );
}

// Core modules (always available)
pub mod cache;
pub mod callgraph;
pub mod cfg;
pub mod chunking;
pub mod config;
pub mod dfg;
pub mod embeddings;
pub mod extract;
pub mod hybrid_search;
pub mod incremental;
pub mod metrics;
pub mod parser;
pub mod pid_status;
pub mod repo;
pub mod response_budget;
pub mod search;
pub mod stats_cli;
pub mod symbols;
pub mod syscall;
pub mod tool_metadata;
pub mod validation;

// Native-only modules (require tokio, lsp, etc.)
#[cfg(feature = "native")]
pub mod git;
#[cfg(feature = "native")]
pub mod gtags;
#[cfg(feature = "native")]
pub mod http_server;
#[cfg(feature = "native")]
pub mod index;
#[cfg(feature = "native")]
pub mod lsp;
#[cfg(feature = "native")]
pub mod mcp;
#[cfg(feature = "native")]
pub mod persist;
#[cfg(feature = "native")]
pub mod sse_discovery;
#[cfg(feature = "native")]
pub mod stdio_proxy;
#[cfg(feature = "native")]
pub mod streaming;
#[cfg(feature = "native")]
pub mod tool_handlers;
