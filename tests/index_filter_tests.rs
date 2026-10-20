//! `--index-filter` scoping: what a filtered index still has to cover.
//!
//! A scoped index only names directories, so a definition or header that
//! in-scope code calls or includes directly falls outside it and reads as
//! "not indexed" — the failure these tests pin down.

use narsil_xref::index::{CodeIntelEngine, EngineOptions};
use narsil_xref::persist::{ChangeType, FileChange};
use std::path::Path;

/// `src/` is the scoped-in directory; the callee and the header it includes
/// both live outside it.
fn write_scoped_repo(root: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(root.join("src"))?;
    std::fs::create_dir_all(root.join("lib"))?;
    std::fs::create_dir_all(root.join("inc"))?;

    std::fs::write(
        root.join("src/caller.c"),
        "#include \"inc/api.h\"\n\
         \n\
         int caller_fn(void)\n\
         {\n\
         \tint total = out_of_scope_helper();\n\
         \treturn total + api_inline_helper();\n\
         }\n",
    )?;
    std::fs::write(
        root.join("lib/helper.c"),
        "int out_of_scope_helper(void)\n{\n\treturn 7;\n}\n",
    )?;
    std::fs::write(
        root.join("inc/api.h"),
        "static inline int api_inline_helper(void)\n{\n\treturn 3;\n}\n",
    )?;
    Ok(())
}

/// The same shape in Rust, where neither pull-in rule that predates the
/// definition map applies: there is no `#include` to resolve and gtags does not
/// index Rust.
fn write_scoped_rust_repo(root: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(root.join("src"))?;
    std::fs::create_dir_all(root.join("lib"))?;

    std::fs::write(
        root.join("src/caller.rs"),
        "pub fn caller_fn() -> i32 {\n    out_of_scope_helper() + 1\n}\n",
    )?;
    std::fs::write(
        root.join("lib/helper.rs"),
        "pub fn out_of_scope_helper() -> i32 {\n    7\n}\n",
    )?;
    std::fs::write(
        root.join("lib/unrelated.rs"),
        "pub fn nobody_calls_this() -> i32 {\n    1\n}\n",
    )?;
    Ok(())
}

/// Give the fixture a real git HEAD.
///
/// Without one, `fingerprint_matches` bails out on its "no HEAD and no
/// compile_commands" guard and every index is treated as a full rebuild — which
/// hides whether a repo loaded from cache picks up symbols for files the
/// pull-in has only just named.
fn git_init_and_commit(root: &Path) {
    let run = |args: &[&str]| {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("git should be runnable");
        assert!(status.success(), "git {:?} failed", args);
    };
    run(&["init", "-q"]);
    run(&["add", "-A"]);
    run(&[
        "-c",
        "user.email=test@example.com",
        "-c",
        "user.name=narsil test",
        "commit",
        "-q",
        "-m",
        "fixture",
    ]);
}

async fn scoped_engine(repo: &Path, index_dir: &Path) -> CodeIntelEngine {
    let options = EngineOptions {
        call_graph_enabled: true,
        index_filter: vec!["src".to_string()],
        gtags_enabled: true,
        gtags_generate: true,
        // The definition map lives in the persisted store, so the callee
        // pull-in only has a non-gtags source when persistence is on.
        persist_enabled: true,
        ..Default::default()
    };
    let engine =
        CodeIntelEngine::with_options(index_dir.to_path_buf(), vec![repo.to_path_buf()], options)
            .await
            .expect("engine");

    // with_options returns before the index exists; the server builds it on a
    // background task.
    engine
        .complete_initialization()
        .await
        .expect("initialization");
    engine
}

async fn symbols_matching(engine: &CodeIntelEngine, repo: &Path, pattern: &str) -> String {
    engine
        .find_symbols(repo.to_str().unwrap(), None, Some(pattern), None, None, 50)
        .await
        .expect("find_symbols")
}

/// A header the scoped file includes, and the definition of a function it
/// calls, are both indexed even though neither is under `src/`.
#[tokio::test]
async fn referenced_files_outside_the_filter_are_indexed() {
    let repo = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_scoped_repo(repo.path()).unwrap();
    let engine = scoped_engine(repo.path(), index_dir.path()).await;

    // The filter itself still applies: the scoped file is indexed.
    let scoped = symbols_matching(&engine, repo.path(), "caller_fn").await;
    assert!(scoped.contains("src/caller.c"), "{}", scoped);

    let header = symbols_matching(&engine, repo.path(), "api_inline_helper").await;
    assert!(header.contains("inc/api.h"), "{}", header);

    // The callee half needs the whole-repo gtags database to say where the
    // definition lives; without the binary there is nothing to ask.
    if narsil_xref::gtags::gtags_binary_present() {
        let callee = symbols_matching(&engine, repo.path(), "out_of_scope_helper").await;
        assert!(callee.contains("lib/helper.c"), "{}", callee);
    }
}

/// A pulled-in file is indexed like any other: an edit to it reaches the index
/// through the watch path, without an explicit reindex.
#[tokio::test]
async fn edits_to_a_pulled_in_file_are_picked_up() {
    let repo = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_scoped_repo(repo.path()).unwrap();
    let engine = scoped_engine(repo.path(), index_dir.path()).await;

    let header = repo.path().join("inc/api.h");
    std::fs::write(
        &header,
        "static inline int api_inline_helper(void)\n{\n\treturn 3;\n}\n\
         \n\
         static inline int api_added_later(void)\n{\n\treturn 4;\n}\n",
    )
    .unwrap();

    let updated = engine
        .process_file_changes(&[FileChange {
            path: header,
            change_type: ChangeType::Modified,
        }])
        .await
        .expect("process_file_changes");
    assert_eq!(updated, 1);

    let added = symbols_matching(&engine, repo.path(), "api_added_later").await;
    assert!(added.contains("inc/api.h"), "{}", added);
}

/// The definition map is what makes the callee pull-in work where gtags cannot
/// reach. It is built behind the index, so the first index cannot use it; a
/// second index pass, once the map has committed, pulls the definition in.
#[tokio::test]
async fn rust_callee_definitions_are_pulled_in_once_the_map_is_built() {
    let repo = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_scoped_rust_repo(repo.path()).unwrap();
    git_init_and_commit(repo.path());
    let engine = scoped_engine(repo.path(), index_dir.path()).await;

    // The filter applies as usual: the scoped file is indexed.
    let scoped = symbols_matching(&engine, repo.path(), "caller_fn").await;
    assert!(scoped.contains("src/caller.rs"), "{}", scoped);

    // Wait for the background build's effect rather than for a duration: each
    // pass re-runs the pull-in, which succeeds on the first one that sees a
    // committed map.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut callee = String::new();
    while std::time::Instant::now() < deadline {
        engine
            .reindex(Some(repo.path().to_str().unwrap()))
            .await
            .expect("reindex");
        callee = symbols_matching(&engine, repo.path(), "out_of_scope_helper").await;
        if callee.contains("lib/helper.rs") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        callee.contains("lib/helper.rs"),
        "callee definition should be pulled in via the definition map: {}",
        callee
    );

    // One hop from in-scope code, not a blanket exemption: an out-of-scope file
    // nothing references stays out even with the whole repo in the map.
    let unrelated = symbols_matching(&engine, repo.path(), "nobody_calls_this").await;
    assert!(!unrelated.contains("lib/unrelated.rs"), "{}", unrelated);
}

/// The catch-up pass is what makes the first index of a repo benefit from its
/// own definition map: without it the map lands after the pull-in has run, and
/// nothing is pulled in until something else triggers a reindex.
#[tokio::test]
async fn the_first_index_pulls_in_definitions_after_the_catch_up_pass() {
    let repo = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_scoped_rust_repo(repo.path()).unwrap();
    // With a real fingerprint the catch-up index loads from cache, which is the
    // path that used to leave newly pulled-in files without symbols.
    git_init_and_commit(repo.path());
    let engine = scoped_engine(repo.path(), index_dir.path()).await;

    engine.catch_up_on_definition_maps().await;

    let callee = symbols_matching(&engine, repo.path(), "out_of_scope_helper").await;
    assert!(
        callee.contains("lib/helper.rs"),
        "the catch-up pass should pull the callee's definition in: {}",
        callee
    );
}

/// A file outside the filter that nothing in scope references stays out — the
/// pull-in is one hop from in-scope code, not a blanket exemption.
#[tokio::test]
async fn unreferenced_files_outside_the_filter_stay_out() {
    let repo = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_scoped_repo(repo.path()).unwrap();
    std::fs::write(
        repo.path().join("lib/unrelated.c"),
        "int nobody_calls_this(void)\n{\n\treturn 1;\n}\n",
    )
    .unwrap();
    let engine = scoped_engine(repo.path(), index_dir.path()).await;

    let unrelated = symbols_matching(&engine, repo.path(), "nobody_calls_this").await;
    assert!(!unrelated.contains("lib/unrelated.c"), "{}", unrelated);
}
