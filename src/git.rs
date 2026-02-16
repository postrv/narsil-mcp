//! Git integration for code intelligence
//!
//! Provides blame information, recent changes, and historical context.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// Git blame information for a line
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameInfo {
    pub commit: String,
    pub author: String,
    pub author_email: String,
    pub timestamp: i64,
    pub summary: String,
    pub line_number: usize,
}

/// A commit affecting a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCommit {
    pub hash: String,
    pub short_hash: String,
    pub author: String,
    pub author_email: String,
    pub timestamp: i64,
    pub subject: String,
    pub body: String,
    pub files_changed: usize,
    pub insertions: usize,
    pub deletions: usize,
}

/// Change frequency data for a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeFrequency {
    pub file_path: String,
    pub total_commits: usize,
    pub total_lines_changed: usize,
    pub unique_authors: usize,
    pub last_modified: i64,
    pub churn_score: f32, // Higher = more volatile
}

/// Git repository interface
pub struct GitRepo {
    root: std::path::PathBuf,
}

impl GitRepo {
    /// Validate input to prevent git argument injection
    fn validate_input(input: &str, name: &str) -> Result<()> {
        if input.starts_with('-') {
            return Err(anyhow!("Invalid {}: cannot start with '-'", name));
        }
        if input.contains('\0') {
            return Err(anyhow!("Invalid {}: cannot contain null bytes", name));
        }
        Ok(())
    }

    pub fn new(path: &Path) -> Result<Self> {
        // Find git root
        let output = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .current_dir(path)
            .output()
            .context("Failed to run git")?;

        if !output.status.success() {
            return Err(anyhow!("Not a git repository: {:?}", path));
        }

        let root = String::from_utf8_lossy(&output.stdout).trim().to_string();

        Ok(Self {
            root: std::path::PathBuf::from(root),
        })
    }

    /// Get blame information for a file
    pub fn blame(&self, file_path: &str) -> Result<Vec<BlameInfo>> {
        Self::validate_input(file_path, "file_path")?;

        let output = Command::new("git")
            .args(["blame", "--line-porcelain", file_path])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git blame")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git blame failed: {}", err));
        }

        self.parse_blame_porcelain(&String::from_utf8_lossy(&output.stdout))
    }

    fn parse_blame_porcelain(&self, output: &str) -> Result<Vec<BlameInfo>> {
        let mut results = Vec::new();
        let mut current = BlameInfo {
            commit: String::new(),
            author: String::new(),
            author_email: String::new(),
            timestamp: 0,
            summary: String::new(),
            line_number: 0,
        };
        let mut line_num = 0;

        for line in output.lines() {
            // Commit hash lines start with 40 hex characters followed by space and line numbers
            // Format: "370b2e005d0eb2922ede57d85ddac0a9fab67e07 1 1 5"
            if line.len() >= 40 && line[..40].chars().all(|c| c.is_ascii_hexdigit()) {
                // This is a commit hash line
                if !current.commit.is_empty() {
                    results.push(current.clone());
                }
                current.commit = line[..40].to_string();
                // Extract line number from the format "hash orig_line final_line [count]"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    // final_line is the third part (index 2)
                    line_num = parts[2].parse().unwrap_or(line_num + 1);
                } else {
                    line_num += 1;
                }
                current.line_number = line_num;
            } else if let Some(author) = line.strip_prefix("author ") {
                current.author = author.to_string();
            } else if let Some(email) = line.strip_prefix("author-mail ") {
                current.author_email = email.trim_matches(|c| c == '<' || c == '>').to_string();
            } else if let Some(time) = line.strip_prefix("author-time ") {
                current.timestamp = time.parse().unwrap_or(0);
            } else if let Some(summary) = line.strip_prefix("summary ") {
                current.summary = summary.to_string();
            }
        }

        // Don't forget the last entry
        if !current.commit.is_empty() {
            results.push(current);
        }

        Ok(results)
    }

    /// Get blame for a specific line range
    pub fn blame_range(&self, file_path: &str, start: usize, end: usize) -> Result<Vec<BlameInfo>> {
        Self::validate_input(file_path, "file_path")?;

        let output = Command::new("git")
            .args([
                "blame",
                "--line-porcelain",
                &format!("-L{},{}", start, end),
                file_path,
            ])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git blame")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git blame failed: {}", err));
        }

        self.parse_blame_porcelain(&String::from_utf8_lossy(&output.stdout))
    }

    /// Get recent commits affecting a file
    pub fn file_history(&self, file_path: &str, max_commits: usize) -> Result<Vec<FileCommit>> {
        Self::validate_input(file_path, "file_path")?;

        let output = Command::new("git")
            .args([
                "log",
                "--format=%H|%h|%an|%ae|%at|%s",
                "--numstat",
                &format!("-{}", max_commits),
                "--",
                file_path,
            ])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git log")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git log failed: {}", err));
        }

        self.parse_log_output(&String::from_utf8_lossy(&output.stdout))
    }

    fn parse_log_output(&self, output: &str) -> Result<Vec<FileCommit>> {
        let mut commits = Vec::new();
        let mut current: Option<FileCommit> = None;

        for line in output.lines() {
            if line.contains('|') && line.len() > 40 {
                // New commit line
                if let Some(commit) = current.take() {
                    commits.push(commit);
                }

                let parts: Vec<&str> = line.splitn(6, '|').collect();
                if parts.len() >= 6 {
                    current = Some(FileCommit {
                        hash: parts[0].to_string(),
                        short_hash: parts[1].to_string(),
                        author: parts[2].to_string(),
                        author_email: parts[3].to_string(),
                        timestamp: parts[4].parse().unwrap_or(0),
                        subject: parts[5].to_string(),
                        body: String::new(),
                        files_changed: 0,
                        insertions: 0,
                        deletions: 0,
                    });
                }
            } else if !line.is_empty() && current.is_some() {
                // Numstat line: additions deletions filename
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Some(ref mut commit) = current {
                        commit.files_changed += 1;
                        commit.insertions += parts[0].parse().unwrap_or(0);
                        commit.deletions += parts[1].parse().unwrap_or(0);
                    }
                }
            }
        }

        if let Some(commit) = current {
            commits.push(commit);
        }

        Ok(commits)
    }

    /// Get recent changes across entire repository
    pub fn recent_changes(&self, days: u32) -> Result<Vec<FileCommit>> {
        let output = Command::new("git")
            .args([
                "log",
                "--format=%H|%h|%an|%ae|%at|%s",
                "--numstat",
                &format!("--since={} days ago", days),
            ])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git log")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git log failed: {}", err));
        }

        self.parse_log_output(&String::from_utf8_lossy(&output.stdout))
    }

    /// Calculate change frequency metrics for files
    pub fn change_frequency(&self, days: u32) -> Result<Vec<ChangeFrequency>> {
        let output = Command::new("git")
            .args([
                "log",
                "--format=%H %ae",
                "--name-only",
                &format!("--since={} days ago", days),
            ])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git log")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git log failed: {}", err));
        }

        let mut file_stats: HashMap<String, (usize, std::collections::HashSet<String>, i64)> =
            HashMap::new();
        let mut current_author = String::new();

        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.len() > 40 && line.contains(' ') {
                // Commit line: hash email
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    current_author = parts[1].to_string();
                }
            } else if !line.is_empty() && !current_author.is_empty() {
                // File name
                let entry = file_stats
                    .entry(line.to_string())
                    .or_insert_with(|| (0, std::collections::HashSet::new(), 0));
                entry.0 += 1;
                entry.1.insert(current_author.clone());
            }
        }

        let max_commits = file_stats.values().map(|(c, _, _)| *c).max().unwrap_or(1) as f32;

        let mut results: Vec<ChangeFrequency> = file_stats
            .into_iter()
            .map(|(path, (commits, authors, _))| {
                ChangeFrequency {
                    file_path: path,
                    total_commits: commits,
                    total_lines_changed: 0, // Would need separate calculation
                    unique_authors: authors.len(),
                    last_modified: 0, // Would need separate lookup
                    churn_score: (commits as f32 / max_commits) * (authors.len() as f32).sqrt(),
                }
            })
            .collect();

        results.sort_by(|a, b| {
            b.churn_score
                .partial_cmp(&a.churn_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(results)
    }

    /// Get contributors to a file
    pub fn file_contributors(&self, file_path: &str) -> Result<Vec<(String, usize)>> {
        Self::validate_input(file_path, "file_path")?;

        let output = Command::new("git")
            .args(["shortlog", "-sne", "HEAD", "--", file_path])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git shortlog")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git shortlog failed: {}", err));
        }

        let mut contributors = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let parts: Vec<&str> = line.trim().splitn(2, '\t').collect();
            if parts.len() == 2 {
                let count: usize = parts[0].trim().parse().unwrap_or(0);
                let name = parts[1].to_string();
                contributors.push((name, count));
            }
        }

        Ok(contributors)
    }

    /// Get all contributors to the repository (repo-level aggregation)
    pub fn repo_contributors(&self) -> Result<Vec<(String, usize)>> {
        let output = Command::new("git")
            .args(["shortlog", "-sne", "HEAD"])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git shortlog")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git shortlog failed: {}", err));
        }

        let mut contributors = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let parts: Vec<&str> = line.trim().splitn(2, '\t').collect();
            if parts.len() == 2 {
                let count: usize = parts[0].trim().parse().unwrap_or(0);
                let name = parts[1].to_string();
                contributors.push((name, count));
            }
        }

        // Sort by commit count descending
        contributors.sort_by(|a, b| b.1.cmp(&a.1));

        Ok(contributors)
    }

    /// Get the diff for a specific commit
    pub fn commit_diff(&self, commit: &str, file_path: Option<&str>) -> Result<String> {
        Self::validate_input(commit, "commit")?;
        if let Some(path) = file_path {
            Self::validate_input(path, "file_path")?;
        }

        let mut args = vec!["show", "--format=", "--patch", commit];

        if let Some(path) = file_path {
            args.push("--");
            args.push(path);
        }

        let output = Command::new("git")
            .args(&args)
            .current_dir(&self.root)
            .output()
            .context("Failed to run git show")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git show failed: {}", err));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Find commits that modified a specific function/symbol
    pub fn symbol_history(
        &self,
        file_path: &str,
        function_name: &str,
        max_commits: usize,
    ) -> Result<Vec<FileCommit>> {
        Self::validate_input(file_path, "file_path")?;
        Self::validate_input(function_name, "function_name")?;

        let output = Command::new("git")
            .args([
                "log",
                "--format=%H|%h|%an|%ae|%at|%s",
                &format!("-{}", max_commits),
                &format!("-S{}", function_name),
                "--",
                file_path,
            ])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git log")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git log -S failed: {}", err));
        }

        self.parse_log_output(&String::from_utf8_lossy(&output.stdout))
    }

    /// Get current branch name
    pub fn current_branch(&self) -> Result<String> {
        let output = Command::new("git")
            .args(["branch", "--show-current"])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git branch")?;

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get list of modified files (working tree)
    pub fn modified_files(&self) -> Result<Vec<String>> {
        let output = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git status")?;

        let files: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                if line.len() > 3 {
                    Some(line[3..].to_string())
                } else {
                    None
                }
            })
            .collect();

        Ok(files)
    }

    /// Check if git is available on the system
    pub fn check_git_available() -> Result<()> {
        let output = Command::new("git")
            .arg("--version")
            .output()
            .context("Failed to execute git command")?;

        if !output.status.success() {
            return Err(anyhow!("Git is not available or not functioning properly"));
        }

        Ok(())
    }

    /// Format blame info as markdown
    pub fn blame_markdown(&self, blame: &[BlameInfo]) -> String {
        let mut md = String::new();
        md.push_str("| Line | Author | Date | Commit | Summary |\n");
        md.push_str("|------|--------|------|--------|---------|");

        for info in blame {
            let date = chrono_lite_format(info.timestamp);
            md.push_str(&format!(
                "\n| {} | {} | {} | `{}` | {} |",
                info.line_number,
                info.author,
                date,
                &info.commit[..7],
                truncate(&info.summary, 40)
            ));
        }

        md
    }

    /// Format file history as markdown
    pub fn history_markdown(&self, commits: &[FileCommit]) -> String {
        let mut md = String::new();
        md.push_str("# File History\n\n");

        for commit in commits {
            let date = chrono_lite_format(commit.timestamp);
            md.push_str(&format!("## `{}` - {}\n", commit.short_hash, date));
            md.push_str(&format!(
                "**Author**: {} <{}>\n\n",
                commit.author, commit.author_email
            ));
            md.push_str(&format!("{}\n\n", commit.subject));
            md.push_str(&format!(
                "Changes: +{} -{} across {} file(s)\n\n---\n\n",
                commit.insertions, commit.deletions, commit.files_changed
            ));
        }

        md
    }
}

fn chrono_lite_format(timestamp: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};

    let dt = UNIX_EPOCH + Duration::from_secs(timestamp as u64);
    let now = std::time::SystemTime::now();

    let age = now.duration_since(dt).unwrap_or_default();
    let days = age.as_secs() / 86400;

    if days == 0 {
        "today".to_string()
    } else if days == 1 {
        "yesterday".to_string()
    } else if days < 7 {
        format!("{} days ago", days)
    } else if days < 30 {
        format!("{} weeks ago", days / 7)
    } else if days < 365 {
        format!("{} months ago", days / 30)
    } else {
        format!("{} years ago", days / 365)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrono_lite() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        assert_eq!(chrono_lite_format(now), "today");
        assert_eq!(chrono_lite_format(now - 86400), "yesterday");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world this is long", 10), "hello w...");
    }

    #[test]
    fn test_git_argument_injection_blocked_file_path() {
        // Test that file_path starting with '-' is rejected
        let result = GitRepo::validate_input("-flag", "file_path");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot start with '-'"));

        let result = GitRepo::validate_input("--flag", "file_path");
        assert!(result.is_err());

        // Valid paths should work
        let result = GitRepo::validate_input("src/main.rs", "file_path");
        assert!(result.is_ok());

        let result = GitRepo::validate_input("./src/main.rs", "file_path");
        assert!(result.is_ok());
    }

    #[test]
    fn test_git_argument_injection_blocked_function_name() {
        // Test that function_name starting with '-' is rejected
        let result = GitRepo::validate_input("-S", "function_name");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot start with '-'"));

        let result = GitRepo::validate_input("--pickaxe-all", "function_name");
        assert!(result.is_err());

        // Valid function names should work
        let result = GitRepo::validate_input("my_function", "function_name");
        assert!(result.is_ok());

        let result = GitRepo::validate_input("MyStruct", "function_name");
        assert!(result.is_ok());
    }

    #[test]
    fn test_git_argument_injection_blocked_commit() {
        // Test that commit hash starting with '-' is rejected
        let result = GitRepo::validate_input("-p", "commit");
        assert!(result.is_err());

        // Valid commit hashes should work
        let result = GitRepo::validate_input("abc123", "commit");
        assert!(result.is_ok());

        let result = GitRepo::validate_input("1234567890abcdef", "commit");
        assert!(result.is_ok());
    }

    #[test]
    fn test_git_null_byte_injection_blocked() {
        // Test that null bytes are rejected
        let result = GitRepo::validate_input("file\0path", "file_path");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot contain null bytes"));

        let result = GitRepo::validate_input("function\0name", "function_name");
        assert!(result.is_err());
    }
}
