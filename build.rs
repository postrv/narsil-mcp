//! Build-time checks for narsil-mcp.
//!
//! When the `frontend` feature is enabled but `frontend/dist/index.html`
//! is missing, the embedded UI will be empty and every web request will
//! return 404. The `rust_embed` derive in `src/http_server.rs` uses
//! `allow_missing = true` so the build still succeeds, but we print a
//! `cargo:warning` here so the user is told to run the frontend build.
//!
//! See issue #18b.

use std::path::Path;

fn main() {
    // Re-run only when the markers we care about change.
    println!("cargo:rerun-if-changed=frontend/dist/index.html");
    println!("cargo:rerun-if-changed=frontend/package.json");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_FRONTEND");

    if std::env::var_os("CARGO_FEATURE_FRONTEND").is_none() {
        return;
    }

    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo");
    let dist_index = Path::new(&manifest_dir)
        .join("frontend")
        .join("dist")
        .join("index.html");

    if !dist_index.exists() {
        println!(
            "cargo:warning=narsil-mcp: --features frontend was enabled, but \
             frontend/dist/index.html is missing. The embedded web UI will \
             return 404 for every request. To populate it, run: \
             `cd frontend && npm ci && npm run build`."
        );
    }
}
