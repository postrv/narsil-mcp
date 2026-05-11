//! Remote repository support via GitHub API
//!
//! This module provides functionality to:
//! - Clone/fetch remote GitHub repositories
//! - List files without cloning
//! - Fetch specific files via GitHub API
//! - Search code on GitHub
//! - Manage temporary clones
//! - Handle rate limiting and authentication
//!
//! This is a Phase 3 feature - remote repository support.

use anyhow::{anyhow, Context, Result};
use octocrab::Octocrab;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use tracing::{info, warn};

use crate::validation;

/// Represents a remote GitHub repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteRepo {
    /// Owner/organization name
    pub owner: String,
    /// Repository name
    pub repo: String,
    /// Optional branch (defaults to main/master)
    pub branch: Option<String>,
    /// Full URL
    pub url: String,
}

impl RemoteRepo {
    /// Parse a GitHub URL into RemoteRepo
    /// Supports formats:
    /// - `github.com/owner/repo`
    /// - `https://github.com/owner/repo`
    /// - `https://github.com/owner/repo/tree/branch`
    pub fn from_url(url: &str) -> Result<Self> {
        let url = url.trim();

        // Remove protocol if present
        let url = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        // Remove github.com prefix
        let url = url.strip_prefix("github.com/").unwrap_or(url);

        // Split by slashes
        let parts: Vec<&str> = url.split('/').collect();

        if parts.len() < 2 {
            return Err(anyhow!(
                "Invalid GitHub URL format. Expected: github.com/owner/repo"
            ));
        }

        let owner = parts[0].to_string();
        let repo = parts[1].to_string();

        // Validate owner and repo names to prevent command injection
        validation::validate_github_component(&owner)
            .map_err(|e| anyhow!("Invalid GitHub owner '{}': {}", owner, e))?;
        validation::validate_github_component(&repo)
            .map_err(|e| anyhow!("Invalid GitHub repo '{}': {}", repo, e))?;

        // Check for branch specification (tree/branch or refs/heads/branch)
        let branch = if parts.len() >= 4 && parts[2] == "tree" {
            let branch_name = parts[3].to_string();
            // Validate branch name to prevent command injection in git operations
            validation::validate_git_ref(&branch_name)
                .map_err(|e| anyhow!("Invalid branch name '{}': {}", branch_name, e))?;
            Some(branch_name)
        } else {
            None
        };

        Ok(Self {
            owner: owner.clone(),
            repo: repo.clone(),
            branch,
            url: format!("https://github.com/{}/{}", owner, repo),
        })
    }

    /// Get the repository identifier (owner/repo)
    pub fn identifier(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }

    /// Get the full clone URL
    pub fn clone_url(&self) -> String {
        format!("{}.git", self.url)
    }
}

/// Manager for remote repositories
pub struct RemoteRepoManager {
    /// GitHub API client
    octocrab: Arc<Octocrab>,
    /// Temporary directory for clones
    temp_dir: TempDir,
    /// Map of repo identifier to local path
    cloned_repos: HashMap<String, PathBuf>,
}

impl RemoteRepoManager {
    /// Create a new RemoteRepoManager
    /// Looks for GITHUB_TOKEN environment variable for authentication
    pub fn new() -> Result<Self> {
        let octocrab = if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            info!("Using GITHUB_TOKEN for authentication");
            Octocrab::builder()
                .personal_token(token)
                .build()
                .context("Failed to create GitHub client with token")?
        } else {
            warn!("No GITHUB_TOKEN found - using unauthenticated access (lower rate limits)");
            Octocrab::builder()
                .build()
                .context("Failed to create GitHub client")?
        };

        let temp_dir =
            TempDir::new().context("Failed to create temporary directory for remote repos")?;

        info!("Remote repository temp directory: {:?}", temp_dir.path());

        Ok(Self {
            octocrab: Arc::new(octocrab),
            temp_dir,
            cloned_repos: HashMap::new(),
        })
    }

    /// List files in a remote repository without cloning
    /// Returns a list of file paths
    /// Note: This only lists the immediate contents of the specified path
    pub async fn list_files(&self, remote: &RemoteRepo, path: Option<&str>) -> Result<Vec<String>> {
        let path = path.unwrap_or("");

        info!(
            "Listing files in {}/{} at path '{}'",
            remote.owner, remote.repo, path
        );

        let contents = self
            .octocrab
            .repos(&remote.owner, &remote.repo)
            .get_content()
            .path(path)
            .r#ref(remote.branch.as_deref().unwrap_or(""))
            .send()
            .await
            .context("Failed to fetch repository contents")?;

        let mut files = Vec::new();

        // The result is ContentItems which contains a Vec of Content
        // For now, only list immediate contents (non-recursive to avoid API rate limits)
        for item in contents.items {
            if item.r#type == "file" {
                files.push(item.path);
            }
        }

        Ok(files)
    }

    /// Fetch a specific file from a remote repository
    pub async fn get_file(&self, remote: &RemoteRepo, path: &str) -> Result<String> {
        info!(
            "Fetching file {} from {}/{}",
            path, remote.owner, remote.repo
        );

        let contents = self
            .octocrab
            .repos(&remote.owner, &remote.repo)
            .get_content()
            .path(path)
            .r#ref(remote.branch.as_deref().unwrap_or(""))
            .send()
            .await
            .context(format!("Failed to fetch file: {}", path))?;

        // The result is ContentItems with a single file
        if let Some(item) = contents.items.first() {
            if let Some(content) = &item.content {
                use base64::Engine;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(content.replace('\n', ""))
                    .context("Failed to decode base64 content")?;
                String::from_utf8(decoded).context("File content is not valid UTF-8")
            } else {
                Err(anyhow!("File content not available for: {}", path))
            }
        } else {
            Err(anyhow!("File not found: {}", path))
        }
    }

    /// Search code in a remote repository via GitHub API
    pub async fn search_code(
        &self,
        remote: &RemoteRepo,
        query: &str,
        max_results: usize,
    ) -> Result<Vec<SearchResult>> {
        info!(
            "Searching code in {}/{} for: {}",
            remote.owner, remote.repo, query
        );

        // Construct search query with repo scope
        let search_query = format!("{} repo:{}/{}", query, remote.owner, remote.repo);

        let results = self
            .octocrab
            .search()
            .code(&search_query)
            .send()
            .await
            .context("GitHub code search failed")?;

        let mut search_results = Vec::new();

        for item in results.items.iter().take(max_results) {
            search_results.push(SearchResult {
                file_path: item.path.clone(),
                repository: format!("{}/{}", remote.owner, remote.repo),
                url: item.html_url.to_string(),
                score: 0.0, // GitHub doesn't provide scores in this format
            });
        }

        Ok(search_results)
    }

    /// Clone a remote repository to a temporary location
    /// Returns the path to the cloned repository
    pub async fn clone_repo(&mut self, remote: &RemoteRepo) -> Result<PathBuf> {
        let identifier = remote.identifier();

        // Check if already cloned
        if let Some(path) = self.cloned_repos.get(&identifier) {
            if path.exists() {
                info!("Repository {} already cloned at {:?}", identifier, path);
                return Ok(path.clone());
            }
        }

        // Create subdirectory in temp for this repo
        let repo_dir = self.temp_dir.path().join(&remote.repo);
        std::fs::create_dir_all(&repo_dir).context("Failed to create repository directory")?;

        info!("Cloning {} to {:?}", identifier, repo_dir);

        // Use git command to clone (shallow clone for speed)
        let mut cmd = tokio::process::Command::new("git");
        cmd.arg("clone")
            .arg("--depth=1") // Shallow clone
            .arg("--single-branch");

        if let Some(ref branch) = remote.branch {
            cmd.arg("--branch").arg(branch);
        }

        cmd.arg(remote.clone_url())
            .arg(&repo_dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());

        let output = cmd
            .spawn()
            .context("Failed to spawn git clone process")?
            .wait_with_output()
            .await
            .context("Failed to wait for git clone")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Git clone failed: {}", stderr));
        }

        info!("Successfully cloned {} to {:?}", identifier, repo_dir);

        // Store in map
        self.cloned_repos.insert(identifier, repo_dir.clone());

        Ok(repo_dir)
    }

    /// Perform a sparse checkout of specific directories
    /// This is more efficient than cloning the entire repo
    pub async fn sparse_checkout(
        &mut self,
        remote: &RemoteRepo,
        paths: &[&str],
    ) -> Result<PathBuf> {
        let identifier = remote.identifier();
        let repo_dir = self.temp_dir.path().join(&remote.repo);

        std::fs::create_dir_all(&repo_dir).context("Failed to create repository directory")?;

        info!(
            "Sparse checkout of {} to {:?} (paths: {:?})",
            identifier, repo_dir, paths
        );

        // Initialize repo
        let init_status = tokio::process::Command::new("git")
            .arg("init")
            .current_dir(&repo_dir)
            .status()
            .await
            .context("Failed to git init")?;

        if !init_status.success() {
            return Err(anyhow!("Git init failed"));
        }

        // Enable sparse checkout
        tokio::process::Command::new("git")
            .args(["config", "core.sparseCheckout", "true"])
            .current_dir(&repo_dir)
            .status()
            .await
            .context("Failed to enable sparse checkout")?;

        // Write sparse-checkout patterns
        let sparse_file = repo_dir.join(".git/info/sparse-checkout");
        std::fs::write(&sparse_file, paths.join("\n"))
            .context("Failed to write sparse-checkout file")?;

        // Add remote
        tokio::process::Command::new("git")
            .args(["remote", "add", "origin", &remote.clone_url()])
            .current_dir(&repo_dir)
            .status()
            .await
            .context("Failed to add remote")?;

        // Pull with depth 1
        let mut pull_cmd = tokio::process::Command::new("git");
        pull_cmd
            .args(["pull", "--depth=1", "origin"])
            .current_dir(&repo_dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());

        if let Some(ref branch) = remote.branch {
            pull_cmd.arg(branch);
        } else {
            pull_cmd.arg("main");
        }

        let output = pull_cmd
            .spawn()
            .context("Failed to spawn git pull")?
            .wait_with_output()
            .await
            .context("Failed to wait for git pull")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Try master branch if main failed
            if remote.branch.is_none() && stderr.contains("main") {
                let master_status = tokio::process::Command::new("git")
                    .args(["pull", "--depth=1", "origin", "master"])
                    .current_dir(&repo_dir)
                    .status()
                    .await?;

                if !master_status.success() {
                    return Err(anyhow!("Git pull failed for both main and master branches"));
                }
            } else {
                return Err(anyhow!("Git pull failed: {}", stderr));
            }
        }

        info!(
            "Successfully sparse-checked out {} to {:?}",
            identifier, repo_dir
        );

        self.cloned_repos.insert(identifier, repo_dir.clone());

        Ok(repo_dir)
    }

    /// Get statistics about cloned repositories
    pub fn get_stats(&self) -> RemoteStats {
        let total_size: u64 = self
            .cloned_repos
            .values()
            .filter_map(|path| dir_size(path).ok())
            .sum();

        RemoteStats {
            cloned_count: self.cloned_repos.len(),
            total_size_bytes: total_size,
            temp_dir: self.temp_dir.path().to_path_buf(),
        }
    }

    /// Clean up all cloned repositories
    pub fn cleanup(&mut self) {
        info!(
            "Cleaning up {} cloned repositories",
            self.cloned_repos.len()
        );
        self.cloned_repos.clear();
        // TempDir will be cleaned up on drop
    }
}

/// Search result from GitHub code search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub file_path: String,
    pub repository: String,
    pub url: String,
    pub score: f32,
}

/// Statistics about remote repository usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteStats {
    pub cloned_count: usize,
    pub total_size_bytes: u64,
    pub temp_dir: PathBuf,
}

/// Calculate the size of a directory recursively
fn dir_size(path: &Path) -> Result<u64> {
    let mut total = 0;

    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;

            if metadata.is_dir() {
                total += dir_size(&entry.path())?;
            } else {
                total += metadata.len();
            }
        }
    } else {
        total = path.metadata()?.len();
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_url_simple() {
        let remote = RemoteRepo::from_url("github.com/rust-lang/rust").unwrap();
        assert_eq!(remote.owner, "rust-lang");
        assert_eq!(remote.repo, "rust");
        assert_eq!(remote.branch, None);
    }

    #[test]
    fn test_parse_github_url_https() {
        let remote = RemoteRepo::from_url("https://github.com/microsoft/vscode").unwrap();
        assert_eq!(remote.owner, "microsoft");
        assert_eq!(remote.repo, "vscode");
    }

    #[test]
    fn test_parse_github_url_with_branch() {
        let remote = RemoteRepo::from_url("https://github.com/torvalds/linux/tree/master").unwrap();
        assert_eq!(remote.owner, "torvalds");
        assert_eq!(remote.repo, "linux");
        assert_eq!(remote.branch, Some("master".to_string()));
    }

    #[test]
    fn test_parse_invalid_url() {
        assert!(RemoteRepo::from_url("not-a-url").is_err());
        assert!(RemoteRepo::from_url("github.com/").is_err());
    }

    #[test]
    fn test_remote_identifier() {
        let remote = RemoteRepo::from_url("github.com/owner/repo").unwrap();
        assert_eq!(remote.identifier(), "owner/repo");
    }

    #[test]
    fn test_clone_url() {
        let remote = RemoteRepo::from_url("github.com/owner/repo").unwrap();
        assert_eq!(remote.clone_url(), "https://github.com/owner/repo.git");
    }

    #[test]
    fn test_rejects_malicious_branch() {
        assert!(RemoteRepo::from_url("github.com/owner/repo/tree/;whoami").is_err());
        assert!(RemoteRepo::from_url("github.com/owner/repo/tree/--exec=evil").is_err());
        assert!(RemoteRepo::from_url("github.com/owner/repo/tree/`id`").is_err());
        assert!(RemoteRepo::from_url("github.com/owner/repo/tree/$(cat /etc/passwd)").is_err());
    }

    #[test]
    fn test_rejects_malicious_owner_repo() {
        assert!(RemoteRepo::from_url("github.com/;whoami/repo").is_err());
        assert!(RemoteRepo::from_url("github.com/owner/;whoami").is_err());
        assert!(RemoteRepo::from_url("github.com/../../etc").is_err());
    }

    #[test]
    fn test_accepts_valid_branches() {
        let remote = RemoteRepo::from_url("github.com/owner/repo/tree/feature-branch").unwrap();
        assert_eq!(remote.branch, Some("feature-branch".to_string()));
    }

    #[test]
    fn test_accepts_valid_owner_repo_names() {
        let remote = RemoteRepo::from_url("github.com/my-org/my-project.v2").unwrap();
        assert_eq!(remote.owner, "my-org");
        assert_eq!(remote.repo, "my-project.v2");
    }
}
