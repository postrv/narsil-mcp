//! Indexing must not ingest package-manager stores.
use narsil_mcp::index::CodeIntelEngine;
use std::fs;
use tempfile::tempdir;

#[tokio::test]
async fn index_skips_pnpm_and_node_modules() {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("src")).unwrap();
    fs::create_dir_all(
        repo.path()
            .join("node_modules/.pnpm/lodash@1.0.0/node_modules/lodash"),
    )
    .unwrap();
    fs::create_dir_all(repo.path().join("node_modules/lodash")).unwrap();
    fs::write(
        repo.path().join("src/main.ts"),
        "export function hello() { return 1; }\n",
    )
    .unwrap();
    fs::write(
        repo.path()
            .join("node_modules/.pnpm/lodash@1.0.0/node_modules/lodash/index.js"),
        "export const ignored = true;\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("node_modules/lodash/index.js"),
        "export const alsoIgnored = true;\n",
    )
    .unwrap();

    let index_dir = tempdir().unwrap();
    let engine = CodeIntelEngine::new(
        index_dir.path().to_path_buf(),
        vec![repo.path().to_path_buf()],
    )
    .await
    .expect("engine");
    engine
        .complete_initialization()
        .await
        .expect("initialization");

    let repo_name = repo
        .path()
        .file_name()
        .and_then(|n| n.to_str())
        .expect("repo name");
    let symbols = engine
        .find_symbols(repo_name, None, None, None, None)
        .await
        .expect("symbols");

    assert!(
        symbols.contains("hello"),
        "first-party symbol should be indexed: {symbols}"
    );
    assert!(
        !symbols.contains("ignored") && !symbols.contains("alsoIgnored"),
        "pnpm/node_modules symbols must not be indexed: {symbols}"
    );
}

#[tokio::test]
async fn compile_commands_skips_out_of_scope_c_files() {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("fs")).unwrap();
    fs::create_dir_all(repo.path().join("drivers")).unwrap();
    fs::write(
        repo.path().join("fs/namei.c"),
        "int namei_lookup(void) { return 0; }\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("drivers/unused.c"),
        "int unused_driver(void) { return 1; }\n",
    )
    .unwrap();
    let db = serde_json::json!([{
        "directory": repo.path(),
        "file": "fs/namei.c",
        "command": "gcc -Iinclude -c fs/namei.c",
    }]);
    fs::write(
        repo.path().join("compile_commands.json"),
        serde_json::to_vec(&db).unwrap(),
    )
    .unwrap();

    let engine = CodeIntelEngine::new(
        tempdir().unwrap().path().to_path_buf(),
        vec![repo.path().to_path_buf()],
    )
    .await
    .expect("engine");
    engine.complete_initialization().await.expect("init");

    let repo_name = repo.path().file_name().and_then(|n| n.to_str()).unwrap();
    let symbols = engine
        .find_symbols(repo_name, None, None, None, None)
        .await
        .expect("symbols");
    assert!(
        symbols.contains("namei_lookup"),
        "in-scope C file should be indexed: {symbols}"
    );
    assert!(
        !symbols.contains("unused_driver"),
        "C files outside compile_commands.json must be skipped: {symbols}"
    );

    let status = engine.get_index_status(Some(repo_name)).await.unwrap();
    assert!(
        status.contains("compile_commands.json"),
        "status should report compile_commands scoping: {status}"
    );
}

#[tokio::test]
async fn maven_multimodule_java_is_indexed() {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("module-a/src/main/java/com/example")).unwrap();
    fs::create_dir_all(repo.path().join("module-b/src/main/java/com/example")).unwrap();
    fs::create_dir_all(repo.path().join("module-a/target/classes")).unwrap();
    fs::write(repo.path().join("pom.xml"), "<project></project>\n").unwrap();
    fs::write(
        repo.path()
            .join("module-a/src/main/java/com/example/Alpha.java"),
        "package com.example; public class Alpha { public void ping() {} }\n",
    )
    .unwrap();
    fs::write(
        repo.path()
            .join("module-b/src/main/java/com/example/Beta.java"),
        "package com.example; public class Beta { public void pong() {} }\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("module-a/target/classes/Generated.java"),
        "public class Generated { public void skip() {} }\n",
    )
    .unwrap();

    let engine = CodeIntelEngine::new(
        tempdir().unwrap().path().to_path_buf(),
        vec![repo.path().to_path_buf()],
    )
    .await
    .expect("engine");
    engine.complete_initialization().await.expect("init");

    let repo_name = repo.path().file_name().and_then(|n| n.to_str()).unwrap();
    let symbols = engine
        .find_symbols(repo_name, None, None, None, None)
        .await
        .expect("symbols");
    assert!(
        symbols.contains("Alpha"),
        "module-a should be indexed: {symbols}"
    );
    assert!(
        symbols.contains("Beta"),
        "module-b should be indexed: {symbols}"
    );
    assert!(
        !symbols.contains("Generated") && !symbols.contains("skip"),
        "Maven target/ must not be indexed: {symbols}"
    );
}

#[tokio::test]
async fn eagain_clears_after_initialization() {
    let repo = tempdir().unwrap();
    fs::write(repo.path().join("lib.rs"), "pub fn ready() {}\n").unwrap();
    let engine = CodeIntelEngine::new(
        tempdir().unwrap().path().to_path_buf(),
        vec![repo.path().to_path_buf()],
    )
    .await
    .expect("engine");
    let message = engine
        .indexing_progress_message()
        .expect("should report EAGAIN before init");
    assert!(message.contains("EAGAIN"), "{message}");
    engine.complete_initialization().await.expect("init");
    assert!(engine.indexing_progress_message().is_none());
}
