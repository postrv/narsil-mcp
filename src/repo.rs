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
}
