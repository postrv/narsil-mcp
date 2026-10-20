//! Own process: tree-sitter's allocator may change only before its first allocation.
#![cfg(target_env = "musl")]

use std::ffi::c_void;

extern "C" {
    static ts_current_malloc: unsafe extern "C" fn(size: usize) -> *mut c_void;
    static ts_current_free: unsafe extern "C" fn(ptr: *mut c_void);
    fn mi_is_in_heap_region(ptr: *const c_void) -> bool;
}

#[test]
fn tree_sitter_allocates_from_mimalloc() {
    // SAFETY: this process has created no tree-sitter object.
    let from_mimalloc = unsafe {
        narsil_xref::route_tree_sitter_allocations_to_mimalloc();
        let block = ts_current_malloc(64);
        let in_heap = mi_is_in_heap_region(block);
        ts_current_free(block);
        in_heap
    };
    assert!(from_mimalloc);
}
