//! Repository management utilities
//!
//! Handles repository discovery, validation, and configuration.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Configuration for a repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoConfig {
    /// Repository name
    pub name: String,

    /// Path to repository root
    pub path: PathBuf,

    /// Patterns to exclude from indexing
    pub exclude_patterns: Vec<String>,

    /// Patterns to include (if empty, include all)
    pub include_patterns: Vec<String>,

    /// Maximum file size to index (bytes)
    pub max_file_size: u64,

    /// Whether to follow symlinks
    pub follow_symlinks: bool,
}

impl Default for RepoConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            path: PathBuf::new(),
            exclude_patterns: vec![
                "**/node_modules/**".to_string(),
                "**/target/**".to_string(),
                "**/.git/**".to_string(),
                "**/vendor/**".to_string(),
                "**/__pycache__/**".to_string(),
                "**/dist/**".to_string(),
                "**/build/**".to_string(),
                "**/*.min.js".to_string(),
                "**/*.min.css".to_string(),
                "**/package-lock.json".to_string(),
                "**/yarn.lock".to_string(),
                "**/Cargo.lock".to_string(),
            ],
            include_patterns: vec![],
            max_file_size: 1024 * 1024, // 1MB
            follow_symlinks: false,
        }
    }
}

/// Discover repositories in a directory
pub fn discover_repos(base_path: &Path, max_depth: usize) -> Result<Vec<PathBuf>> {
    let mut repos = Vec::new();
    discover_repos_recursive(base_path, 0, max_depth, &mut repos)?;
    Ok(repos)
}

fn discover_repos_recursive(
    path: &Path,
    depth: usize,
    max_depth: usize,
    repos: &mut Vec<PathBuf>,
) -> Result<()> {
    if depth > max_depth {
        return Ok(());
    }

    // Check if this directory is a repository
    if is_repository(path) {
        repos.push(path.to_path_buf());
        return Ok(()); // Don't recurse into repos
    }

    // Recurse into subdirectories
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();

            if entry_path.is_dir() {
                let name = entry_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");

                // Skip hidden directories
                if !name.starts_with('.') {
                    discover_repos_recursive(&entry_path, depth + 1, max_depth, repos)?;
                }
            }
        }
    }

    Ok(())
}

/// Check if a directory is a repository root
pub fn is_repository(path: &Path) -> bool {
    // Check for common VCS directories
    if path.join(".git").exists() {
        return true;
    }

    // Check for common project files
    let project_markers = [
        "Cargo.toml",     // Rust
        "package.json",   // Node.js
        "pyproject.toml", // Python
        "setup.py",       // Python
        "go.mod",         // Go
        "pom.xml",        // Java/Maven
        "build.gradle",   // Java/Gradle
        "CMakeLists.txt", // C/C++
        "Makefile",       // Generic
        ".project",       // Eclipse
        "*.sln",          // .NET
    ];

    for marker in &project_markers {
        if marker.contains('*') {
            // Glob pattern
            if let Ok(entries) = glob::glob(&path.join(marker).to_string_lossy()) {
                if entries.filter_map(|e| e.ok()).count() > 0 {
                    return true;
                }
            }
        } else if path.join(marker).exists() {
            return true;
        }
    }

    false
}

/// Get the repository name from a path
pub fn repo_name_from_path(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string()
}

/// The main checkout's root `path` is a linked worktree of, or `None` when
/// `path` is not a linked worktree (a plain checkout, not a git repo at
/// all, or a `git` too old for `--path-format`).
///
/// A plain checkout's `git-common-dir` is its own `.git`; a linked
/// worktree's points at the main checkout's `.git` instead, which is what
/// distinguishes the two here.
pub fn worktree_main_repo(path: &Path) -> Option<PathBuf> {
    let canonical_path = path.canonicalize().ok()?;
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .current_dir(&canonical_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let common_dir = String::from_utf8(output.stdout).ok()?;
    let root = PathBuf::from(common_dir.trim()).parent()?.canonicalize().ok()?;
    if root == canonical_path {
        None
    } else {
        Some(root)
    }
}

/// `worktree_main_repo`, run once per path; per-query settings lookups call
/// this and would otherwise spawn `git` each time.
pub fn worktree_main_repo_cached(path: &Path) -> Option<PathBuf> {
    static ANSWERS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, Option<PathBuf>>>,
    > = std::sync::OnceLock::new();
    let answers = ANSWERS.get_or_init(Default::default);
    if let Some(answer) = answers.lock().unwrap().get(path) {
        return answer.clone();
    }
    let answer = worktree_main_repo(path);
    answers
        .lock()
        .unwrap()
        .insert(path.to_path_buf(), answer.clone());
    answer
}

/// Validate a repository path
pub fn validate_repo_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(anyhow!("Path does not exist: {:?}", path));
    }

    if !path.is_dir() {
        return Err(anyhow!("Path is not a directory: {:?}", path));
    }

    // Check if readable
    std::fs::read_dir(path).map_err(|e| anyhow!("Cannot read directory {:?}: {}", path, e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_is_repository_git() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        assert!(is_repository(dir.path()));
    }

    #[test]
    fn test_is_repository_cargo() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();
        assert!(is_repository(dir.path()));
    }

    #[test]
    fn test_is_not_repository() {
        let dir = tempdir().unwrap();
        assert!(!is_repository(dir.path()));
    }

    fn run_git(dir: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .unwrap();
        assert!(status.success(), "git {:?} failed in {:?}", args, dir);
    }

    #[test]
    fn worktree_main_repo_is_none_for_a_plain_checkout() {
        let dir = tempdir().unwrap();
        run_git(dir.path(), &["init", "-q"]);
        run_git(dir.path(), &["commit", "--allow-empty", "-q", "-m", "init"]);
        assert!(worktree_main_repo(dir.path()).is_none());
    }

    #[test]
    fn worktree_main_repo_finds_the_main_checkout_of_a_linked_worktree() {
        let main = tempdir().unwrap();
        run_git(main.path(), &["init", "-q"]);
        run_git(main.path(), &["commit", "--allow-empty", "-q", "-m", "init"]);

        let worktree_parent = tempdir().unwrap();
        let worktree_path = worktree_parent.path().join("wt");
        run_git(
            main.path(),
            &[
                "worktree",
                "add",
                "-q",
                worktree_path.to_str().unwrap(),
                "-b",
                "wt-branch",
            ],
        );

        let resolved = worktree_main_repo(&worktree_path).unwrap();
        assert_eq!(resolved, main.path().canonicalize().unwrap());
    }
}
