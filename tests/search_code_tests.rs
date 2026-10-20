//! Behavioural tests for search_code: cross-repo hits are labelled with their
//! owning repo, and multi-word queries match non-adjacent terms.

use anyhow::Result;
use narsil_xref::index::{CodeIntelEngine, EngineOptions};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct TestRepo {
    dir: TempDir,
}

impl TestRepo {
    fn new() -> Result<Self> {
        Ok(Self {
            dir: TempDir::new()?,
        })
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn add_file(&self, name: &str, content: &str) -> Result<()> {
        let path = self.dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// Returns the engine and the index TempDir; the caller must keep the TempDir
/// alive (the engine reads/writes under it for the test's duration).
async fn engine_for(repo_paths: Vec<PathBuf>) -> Result<(CodeIntelEngine, TempDir)> {
    let index_dir = TempDir::new()?;
    let engine = CodeIntelEngine::with_options(
        index_dir.path().to_path_buf(),
        repo_paths,
        EngineOptions::default(),
    )
    .await?;
    engine.complete_initialization().await?;
    Ok((engine, index_dir))
}

/// The reported case: an alternation of macro names. Text mode reads it as one
/// literal and finds nothing; regex mode must find every branch.
#[tokio::test]
async fn regex_mode_matches_an_alternation_text_mode_cannot() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_file(
        "src/include/nio_uring.h",
        "#define QUEUE_DEPTH_DEF 64\n#define QUEUE_DEPTH_MAX 256\n",
    )?;
    repo.add_file(
        "src/nio_uring.c",
        "int depth = QUEUE_DEPTH_DEF;\nint entries = URING_ENTRIES_MAX;\n",
    )?;
    let repo_path = repo.path().canonicalize()?;
    let (engine, _index) = engine_for(vec![repo_path.clone()]).await?;
    let repo_arg = repo_path.to_string_lossy().to_string();
    let alternation = "QUEUE_DEPTH_DEF|QUEUE_DEPTH_MAX|URING_ENTRIES_MAX";

    let text = engine
        .search_code(Some(&repo_arg), alternation, None, 60, None, None)
        .await?;
    assert!(
        text.contains("Found 0 results"),
        "text mode reads the alternation as a literal:\n{text}"
    );

    let regex = engine
        .search_code(Some(&repo_arg), alternation, None, 60, None, Some("regex"))
        .await?;
    assert!(
        regex.contains("nio_uring.h") && regex.contains("nio_uring.c"),
        "regex mode must find every branch:\n{regex}"
    );

    let broken = engine
        .search_code(
            Some(&repo_arg),
            "QUEUE_DEPTH_(",
            None,
            60,
            None,
            Some("regex"),
        )
        .await;
    assert!(
        broken.is_err(),
        "an unparsable pattern must be reported, not silently match nothing"
    );

    let unknown_mode = engine
        .search_code(Some(&repo_arg), "depth", None, 60, None, Some("glob"))
        .await;
    assert!(unknown_mode.is_err(), "an unknown mode must be refused");
    Ok(())
}

/// A multi-word query whose terms sit on different lines must still find the
/// file (via the file-level fallback), not return zero results.
#[tokio::test]
async fn test_search_code_multi_token_non_adjacent() -> Result<()> {
    let repo = TestRepo::new()?;
    // "struct" and "tool_config" are 2 lines apart — never on one line.
    repo.add_file(
        "src/config.c",
        "const volatile struct {\n    unsigned int collect_syscalls;\n} tool_config = {};\n",
    )?;
    let repo_path = repo.path().canonicalize()?;
    let (engine, _index) = engine_for(vec![repo_path.clone()]).await?;

    let out = engine
        .search_code(
            Some(&repo_path.to_string_lossy()),
            "struct tool_config",
            None,
            10,
            None,
            None,
        )
        .await?;

    assert!(
        out.contains("config.c"),
        "non-adjacent multi-word query must find the file:\n{out}"
    );
    assert!(
        out.contains("across multiple lines"),
        "fallback note must explain the cross-line match:\n{out}"
    );
    Ok(())
}

/// The busybox shape: an applet opens with a `//config:` help block naming
/// every term, and implements them far below. The hit must land on the code.
#[tokio::test]
async fn test_search_code_fallback_prefers_code_over_comments() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_file(
        "util-linux/mount.c",
        "//config:config MOUNT\n\
         //config:\tOptions: bind, move, remount are supported by this applet.\n\
         //config:\tSee the manual for cmdopts handling of long options.\n\
         \n\
         int mount_main(int argc, char **argv)\n\
         {\n\
         \tfor (i = 1; argv[i]; i++) {\n\
         \t\tcmdopts = append_mount_options(cmdopts, argv[i]);\n\
         \t}\n\
         }\n",
    )?;
    let repo_path = repo.path().canonicalize()?;
    let (engine, _index) = engine_for(vec![repo_path.clone()]).await?;

    let out = engine
        .search_code(
            Some(&repo_path.to_string_lossy()),
            "append_mount_options cmdopts argv",
            None,
            10,
            None,
            None,
        )
        .await?;

    assert!(out.contains("mount.c"), "file must be found:\n{out}");
    assert!(
        out.contains("append_mount_options"),
        "the excerpt must show the code implementing the terms:\n{out}"
    );
    assert!(
        !out.contains("//config:config MOUNT"),
        "the help block must not be the anchor:\n{out}"
    );
    Ok(())
}

/// An exact-phrase hit on a single line must still win over the fallback and
/// must not trigger the fallback note.
#[tokio::test]
async fn test_search_code_phrase_on_one_line_no_fallback() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_file(
        "src/a.c",
        "int struct_tool_config_marker;\nstruct tool_config x;\n",
    )?;
    let repo_path = repo.path().canonicalize()?;
    let (engine, _index) = engine_for(vec![repo_path.clone()]).await?;

    let out = engine
        .search_code(
            Some(&repo_path.to_string_lossy()),
            "struct tool_config",
            None,
            10,
            None,
            None,
        )
        .await?;

    assert!(out.contains("a.c"), "phrase hit must be found:\n{out}");
    assert!(
        !out.contains("across multiple lines"),
        "a single-line hit must not use the fallback:\n{out}"
    );
    Ok(())
}

/// When the search spans more than one repo, every hit names its owning repo.
#[tokio::test]
async fn test_search_code_labels_repo_across_repos() -> Result<()> {
    let repo_a = TestRepo::new()?;
    repo_a.add_file("src/a.c", "int widget_a;\n")?;
    let repo_b = TestRepo::new()?;
    repo_b.add_file("src/b.c", "int widget_b;\n")?;
    let path_a = repo_a.path().canonicalize()?;
    let path_b = repo_b.path().canonicalize()?;
    let (engine, _index) = engine_for(vec![path_a.clone(), path_b.clone()]).await?;

    // repo=None searches all indexed repos.
    let out = engine
        .search_code(None, "widget", None, 10, None, None)
        .await?;

    assert!(
        out.contains("**Repo**:"),
        "cross-repo hits must be labelled with their repo:\n{out}"
    );
    assert!(
        out.contains(&path_a.to_string_lossy().to_string())
            && out.contains(&path_b.to_string_lossy().to_string()),
        "both repo roots must appear:\n{out}"
    );
    Ok(())
}

/// A single-repo search needs no repo label — it would be noise.
#[tokio::test]
async fn test_search_code_no_repo_label_single_repo() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_file("src/a.c", "int widget_a;\n")?;
    let repo_path = repo.path().canonicalize()?;
    let (engine, _index) = engine_for(vec![repo_path.clone()]).await?;

    let out = engine
        .search_code(
            Some(&repo_path.to_string_lossy()),
            "widget",
            None,
            10,
            None,
            None,
        )
        .await?;

    assert!(out.contains("widget"), "hit must be found:\n{out}");
    assert!(
        !out.contains("**Repo**:"),
        "single-repo search must not label the repo:\n{out}"
    );
    Ok(())
}
