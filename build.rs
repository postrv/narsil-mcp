//! Build-time checks for narsil-xref.
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
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_FRONTEND");
    emit_build_id();

    if std::env::var_os("CARGO_FEATURE_FRONTEND").is_none() {
        return;
    }

    println!("cargo:rerun-if-changed=frontend/dist/index.html");
    println!("cargo:rerun-if-changed=frontend/package.json");

    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo");
    let dist_index = Path::new(&manifest_dir)
        .join("frontend")
        .join("dist")
        .join("index.html");

    if !dist_index.exists() {
        println!(
            "cargo:warning=narsil-xref: --features frontend was enabled, but \
             frontend/dist/index.html is missing. The embedded web UI will \
             return 404 for every request. To populate it, run: \
             `cd frontend && npm ci && npm run build`."
        );
    }
}

/// Set `NARSIL_BUILD_ID` to the git commit (`-dirty` for unrefreshed edits)
/// and the UTC build time, so a running binary can be matched to its build.
fn emit_build_id() {
    let commit = command_output("git", &["describe", "--always", "--dirty", "--abbrev=12"])
        .unwrap_or_else(|| "unknown".to_string());
    let built = command_output("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=NARSIL_BUILD_ID={commit}, built {built}");

    // Without these cargo reruns this script only when build.rs itself
    // changes, and keeps printing the id of an older build. `src` covers
    // the -dirty state, the git paths cover a new commit or stg refresh.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    for git_path in ["HEAD", "index", "packed-refs"] {
        watch_git_path(git_path);
    }
    if let Some(branch_ref) = command_output("git", &["symbolic-ref", "-q", "HEAD"]) {
        watch_git_path(&branch_ref);
    }
}

/// Trimmed stdout of `program`, or None if it fails or prints nothing.
fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Rerun when `path` inside the git dir changes. Skips a missing path:
/// cargo treats one as changed on every build.
fn watch_git_path(path: &str) {
    if let Some(resolved) = command_output("git", &["rev-parse", "--git-path", path]) {
        if Path::new(&resolved).exists() {
            println!("cargo:rerun-if-changed={resolved}");
        }
    }
}
