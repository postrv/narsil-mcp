//! Persisted and refreshed indexes must agree with the current repository bytes.

use anyhow::Result;
use narsil_mcp::index::{CodeIntelEngine, EngineOptions};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

async fn engine(repo: &Path, cache: &Path) -> Result<CodeIntelEngine> {
    let engine = CodeIntelEngine::with_options(
        cache.to_path_buf(),
        vec![repo.to_path_buf()],
        EngineOptions {
            persist_enabled: true,
            call_graph_enabled: true,
            ..Default::default()
        },
    )
    .await?;
    engine.complete_initialization().await?;
    Ok(engine)
}

fn repo_name(repo: &TempDir) -> &str {
    repo.path().file_name().unwrap().to_str().unwrap()
}

#[tokio::test]
async fn persisted_restart_restores_search_and_callers() -> Result<()> {
    let repo = TempDir::new()?;
    let cache = TempDir::new()?;
    fs::write(
        repo.path().join("lib.rs"),
        "pub fn index_marker() {}\npub fn caller() { index_marker(); }\n",
    )?;
    drop(engine(repo.path(), cache.path()).await?);
    assert!(fs::read_dir(cache.path())?.any(|entry| {
        entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|ext| ext == "idx")
    }));

    let restarted = engine(repo.path(), cache.path()).await?;
    let search = restarted
        .search_code(Some(repo_name(&repo)), "index_marker", None, 10, None)
        .await?;
    assert!(search.contains("pub fn index_marker"), "{search}");
    let callers = restarted
        .get_callers(repo_name(&repo), "index_marker", false, 2, None)
        .await?;
    assert!(callers.contains("caller"), "{callers}");
    let status = restarted.get_index_status(None).await?;
    assert!(status.contains("**Total Documents**: 1\n"), "{status}");
    Ok(())
}

#[tokio::test]
async fn reindex_replaces_documents_and_removes_deleted_file_context() -> Result<()> {
    let repo = TempDir::new()?;
    let cache = TempDir::new()?;
    fs::write(repo.path().join("keep.rs"), "pub fn retained_marker() {}\n")?;
    fs::write(
        repo.path().join("remove.rs"),
        "pub fn removed_marker() {}\n",
    )?;
    let indexed = engine(repo.path(), cache.path()).await?;
    indexed.reindex(Some(repo_name(&repo))).await?;
    let status = indexed.get_index_status(None).await?;
    assert!(status.contains("**Total Documents**: 2\n"), "{status}");

    fs::remove_file(repo.path().join("remove.rs"))?;
    indexed.reindex(Some(repo_name(&repo))).await?;
    let search = indexed
        .search_code(Some(repo_name(&repo)), "removed_marker", None, 10, None)
        .await?;
    assert!(!search.contains("pub fn removed_marker"), "{search}");
    let status = indexed.get_index_status(None).await?;
    assert!(status.contains("**Total Documents**: 1\n"), "{status}");
    Ok(())
}

#[tokio::test]
async fn persisted_restart_removes_deleted_symbols() -> Result<()> {
    let repo = TempDir::new()?;
    let cache = TempDir::new()?;
    fs::write(repo.path().join("keep.rs"), "pub fn retained_marker() {}\n")?;
    fs::write(
        repo.path().join("remove.rs"),
        "pub fn removed_marker() {}\n",
    )?;
    drop(engine(repo.path(), cache.path()).await?);
    fs::remove_file(repo.path().join("remove.rs"))?;
    let restarted = engine(repo.path(), cache.path()).await?;
    let symbols = restarted
        .find_symbols(repo_name(&repo), None, None, None, None)
        .await?;
    assert!(symbols.contains("retained_marker"), "{symbols}");
    assert!(!symbols.contains("removed_marker"), "{symbols}");
    Ok(())
}

#[tokio::test]
async fn persisted_restart_checks_same_size_and_mtime_content() -> Result<()> {
    let repo = TempDir::new()?;
    let cache = TempDir::new()?;
    let source = repo.path().join("lib.rs");
    fs::write(&source, "pub fn old_name() {}\n")?;
    let original_modified = fs::metadata(&source)?.modified()?;
    drop(engine(repo.path(), cache.path()).await?);
    fs::write(&source, "pub fn new_name() {}\n")?;
    fs::File::options()
        .write(true)
        .open(&source)?
        .set_times(fs::FileTimes::new().set_modified(original_modified))?;
    let restarted = engine(repo.path(), cache.path()).await?;
    let symbols = restarted
        .find_symbols(repo_name(&repo), None, None, None, None)
        .await?;
    assert!(symbols.contains("new_name"), "{symbols}");
    assert!(!symbols.contains("old_name"), "{symbols}");
    Ok(())
}

#[tokio::test]
async fn refreshing_one_repository_preserves_other_repository_results() -> Result<()> {
    let first = TempDir::new()?;
    let second = TempDir::new()?;
    let cache = TempDir::new()?;
    fs::write(first.path().join("first.rs"), "pub fn first_marker() {}\n")?;
    fs::write(second.path().join("second.rs"), "pub fn old_marker() {}\n")?;
    let paths = vec![first.path().to_path_buf(), second.path().to_path_buf()];
    let options = EngineOptions {
        persist_enabled: true,
        ..Default::default()
    };
    let initial =
        CodeIntelEngine::with_options(cache.path().to_path_buf(), paths.clone(), options.clone())
            .await?;
    initial.complete_initialization().await?;
    drop(initial);
    fs::write(second.path().join("second.rs"), "pub fn new_marker() {}\n")?;
    let restarted =
        CodeIntelEngine::with_options(cache.path().to_path_buf(), paths, options).await?;
    restarted.complete_initialization().await?;
    restarted.reindex(Some(repo_name(&first))).await?;
    let first_symbols = restarted
        .find_symbols(repo_name(&first), None, None, None, None)
        .await?;
    let second_symbols = restarted
        .find_symbols(repo_name(&second), None, None, None, None)
        .await?;
    assert!(first_symbols.contains("first_marker"), "{first_symbols}");
    assert!(second_symbols.contains("new_marker"), "{second_symbols}");
    assert!(!second_symbols.contains("old_marker"), "{second_symbols}");
    let status = restarted.get_index_status(None).await?;
    assert!(status.contains("**Total Documents**: 2\n"), "{status}");
    Ok(())
}
