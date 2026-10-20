//! `reindex` is the documented first move when a query returns nothing for
//! code that exists — including for a repository the server was never started
//! with, which it has to register before it can index.
//!
//! `forget_repo` is its counterpart: it unregisters a repository and drops
//! everything the engine held for it.

use narsil_xref::index::{CodeIntelEngine, EngineOptions};
use narsil_xref::response_budget::ListWindow;
use std::path::Path;

fn write_repo(root: &Path, function: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(root.join(".git"))?;
    std::fs::create_dir_all(root.join("src"))?;
    std::fs::write(
        root.join("src/lib.rs"),
        format!("pub fn {}() -> u32 {{ 1 }}\n", function),
    )
}

async fn engine_for_all(repos: &[&Path], index_dir: &Path) -> CodeIntelEngine {
    let engine = CodeIntelEngine::with_options(
        index_dir.to_path_buf(),
        repos.iter().map(|repo| repo.to_path_buf()).collect(),
        EngineOptions::default(),
    )
    .await
    .expect("engine");
    engine
        .complete_initialization()
        .await
        .expect("initialization");
    engine
}

async fn engine_for(repo: &Path, index_dir: &Path) -> CodeIntelEngine {
    engine_for_all(&[repo], index_dir).await
}

/// A repository absent at startup is registered and indexed, not rejected.
#[tokio::test]
async fn reindex_registers_a_repo_the_server_never_saw() {
    let started_with = tempfile::TempDir::new().unwrap();
    let unseen = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_repo(started_with.path(), "known_fn").unwrap();
    write_repo(unseen.path(), "unseen_fn").unwrap();

    let engine = engine_for(started_with.path(), index_dir.path()).await;
    let unseen_arg = unseen.path().to_str().unwrap();

    // Before registration the repo is unknown, and says so.
    let before = engine
        .find_symbols(unseen_arg, None, Some("unseen_fn"), None, None, 10)
        .await;
    assert!(before.is_err(), "{:?}", before.map(|out| out.len()));

    let registered = engine.reindex(Some(unseen_arg)).await.expect("reindex");
    assert!(registered.contains("Registered"), "{}", registered);

    let after = engine
        .find_symbols(unseen_arg, None, Some("unseen_fn"), None, None, 10)
        .await
        .expect("find_symbols after registration");
    assert!(after.contains("unseen_fn"), "{}", after);

    // The repo the server started with is still answerable.
    let known = engine
        .find_symbols(
            started_with.path().to_str().unwrap(),
            None,
            Some("known_fn"),
            None,
            None,
            10,
        )
        .await
        .expect("find_symbols on the original repo");
    assert!(known.contains("known_fn"), "{}", known);
}

/// Forgetting a repo undoes its registration: it stops answering, and reindex
/// on the same path brings it back.
#[tokio::test]
async fn forget_repo_drops_a_repo_that_reindex_can_bring_back() {
    let repo = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_repo(repo.path(), "known_fn").unwrap();

    let engine = engine_for(repo.path(), index_dir.path()).await;
    let repo_arg = repo.path().to_str().unwrap();
    let found = engine
        .find_symbols(repo_arg, None, Some("known_fn"), None, None, 10)
        .await
        .expect("find_symbols before forgetting");
    assert!(found.contains("known_fn"), "{}", found);

    let forgotten = engine.forget_repo(repo_arg).await.expect("forget_repo");
    assert!(forgotten.contains("Forgot"), "{}", forgotten);

    let after = engine
        .find_symbols(repo_arg, None, Some("known_fn"), None, None, 10)
        .await;
    assert!(after.is_err(), "{:?}", after.map(|out| out.len()));

    engine
        .reindex(Some(repo_arg))
        .await
        .expect("reindex after forget_repo");
    let again = engine
        .find_symbols(repo_arg, None, Some("known_fn"), None, None, 10)
        .await
        .expect("find_symbols after reindex");
    assert!(again.contains("known_fn"), "{}", again);
}

/// Dropping one repo must leave every other repo the engine serves intact --
/// the search index and the file cache are shared across all of them.
#[tokio::test]
async fn forget_repo_leaves_the_other_repo_answering() {
    let kept = tempfile::TempDir::new().unwrap();
    let dropped = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_repo(kept.path(), "kept_fn").unwrap();
    write_repo(dropped.path(), "dropped_fn").unwrap();

    let engine = engine_for_all(&[kept.path(), dropped.path()], index_dir.path()).await;
    engine
        .forget_repo(dropped.path().to_str().unwrap())
        .await
        .expect("forget_repo");

    let still_there = engine
        .find_symbols(
            kept.path().to_str().unwrap(),
            None,
            Some("kept_fn"),
            None,
            None,
            10,
        )
        .await
        .expect("the repo that was kept must still answer");
    assert!(still_there.contains("kept_fn"), "{}", still_there);
}

/// A path that is not a repository leaves the original "not found" error in
/// place rather than being adopted.
#[tokio::test]
async fn reindex_rejects_a_path_that_is_not_a_repo() {
    let started_with = tempfile::TempDir::new().unwrap();
    let bare_dir = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_repo(started_with.path(), "known_fn").unwrap();
    std::fs::write(bare_dir.path().join("notes.txt"), "no vcs, no markers\n").unwrap();

    let engine = engine_for(started_with.path(), index_dir.path()).await;

    let error = engine
        .reindex(Some(bare_dir.path().to_str().unwrap()))
        .await
        .expect_err("a directory with no repository markers must not register");
    assert!(error.to_string().contains("not found"), "{}", error);
}

/// A branch switch removes files. find_references scans the cached contents of
/// every indexed file, so a file the new branch does not have must be gone from
/// that cache once the repo is reindexed.
#[tokio::test]
async fn reindex_forgets_a_file_the_branch_switch_removed() {
    let repo = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_repo(repo.path(), "kept_fn").unwrap();
    let only_on_old_branch = repo.path().join("src/gone.rs");
    std::fs::write(
        &only_on_old_branch,
        "pub fn kill_suidgid() -> u32 { kept_fn() }\n",
    )
    .unwrap();

    let engine = engine_for(repo.path(), index_dir.path()).await;
    let repo_arg = repo.path().to_str().unwrap();

    let before = engine
        .find_references(repo_arg, "kill_suidgid", true, None, ListWindow::new(0, 50))
        .await
        .expect("find_references");
    assert!(before.contains("src/gone.rs"), "{}", before);

    std::fs::remove_file(&only_on_old_branch).unwrap();
    engine.reindex(Some(repo_arg)).await.expect("reindex");

    let after = engine
        .find_references(repo_arg, "kill_suidgid", true, None, ListWindow::new(0, 50))
        .await
        .expect("find_references after reindex");
    assert!(!after.contains("src/gone.rs"), "{}", after);

    // The file the branch still has is answerable, so the prune was not a
    // wholesale cache wipe.
    let kept = engine
        .find_references(repo_arg, "kept_fn", true, None, ListWindow::new(0, 50))
        .await
        .expect("find_references for the surviving file");
    assert!(kept.contains("src/lib.rs"), "{}", kept);
}

/// Registration mutates engine-wide state that every query reads, so a query
/// running against another repo at the same time must still be answered.
#[tokio::test]
async fn a_query_is_answered_while_a_repo_registers() {
    let started_with = tempfile::TempDir::new().unwrap();
    let unseen = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_repo(started_with.path(), "known_fn").unwrap();
    write_repo(unseen.path(), "unseen_fn").unwrap();

    let engine = std::sync::Arc::new(engine_for(started_with.path(), index_dir.path()).await);

    let registering = {
        let engine = engine.clone();
        let unseen_arg = unseen.path().to_str().unwrap().to_string();
        tokio::spawn(async move { engine.reindex(Some(&unseen_arg)).await })
    };
    let querying = {
        let engine = engine.clone();
        let known_arg = started_with.path().to_str().unwrap().to_string();
        tokio::spawn(async move {
            engine
                .find_symbols(&known_arg, None, Some("known_fn"), None, None, 10)
                .await
        })
    };

    let registered = registering.await.unwrap().expect("reindex");
    assert!(registered.contains("Registered"), "{}", registered);
    let queried = querying.await.unwrap().expect("find_symbols");
    assert!(queried.contains("known_fn"), "{}", queried);
}
