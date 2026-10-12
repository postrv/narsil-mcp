//! Git integration for code intelligence
//!
//! Provides blame information, recent changes, and historical context.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// Commits a `--since=<days> days ago` log walk reads before stopping, for
/// any caller-supplied `days`. Without it `days=3650` on a repo with a long
/// history buffers the entire multi-year `git log` output (numstat or
/// name-only) into memory via `Command::output()` before any render-side
/// cap applies -- large enough to end the MCP connection. 500 commits is
/// far past what a "recent changes" or "hotspots" query needs; both
/// render-side caps already stop at 20.
const MAX_LOG_COMMITS: &str = "500";

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

#[derive(Debug)]
pub struct CommitRange {
    pub merge_base: String,
    pub total: usize,
    pub commits: Vec<FileCommit>,
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

/// Tracking state of the current branch relative to its upstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamInfo {
    pub upstream: String,
    pub ahead: usize,
    pub behind: usize,
    /// Subjects of the ahead (unpushed) commits, newest first.
    pub unpushed: Vec<String>,
}

/// Git repository interface
pub struct GitRepo {
    root: std::path::PathBuf,
}

impl GitRepo {
    /// Validate input to prevent git argument injection and shell metacharacter attacks.
    ///
    /// Blocks:
    /// - Strings starting with `-` (git argument injection)
    /// - Null bytes
    /// - Shell metacharacters (`;|&`$()><{}!'"`)
    /// - Newlines and carriage returns
    fn validate_input(input: &str, name: &str) -> Result<()> {
        if input.starts_with('-') {
            return Err(anyhow!("Invalid {}: cannot start with '-'", name));
        }
        // Check for null bytes, shell metacharacters, and control characters
        const FORBIDDEN: &[char] = &[
            ';', '|', '&', '`', '$', '(', ')', '>', '<', '{', '}', '!', '\n', '\r', '\0', '\'', '"',
        ];
        for ch in input.chars() {
            if FORBIDDEN.contains(&ch) {
                return Err(anyhow!(
                    "Invalid {}: contains forbidden character {:?}",
                    name,
                    ch
                ));
            }
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

    /// The directory a git command for `file_path` must run in, and the path
    /// to name there. A submodule's files live in the submodule's own work
    /// tree: the superproject's HEAD holds the gitlink, not them, so a command
    /// run at the superproject root reports the path as absent.
    fn work_tree_for(&self, file_path: &str) -> (std::path::PathBuf, String) {
        let components: Vec<&str> = file_path.split('/').collect();
        let mut prefix = std::path::PathBuf::new();
        let mut submodule: Option<(std::path::PathBuf, usize)> = None;

        for (index, component) in components.iter().enumerate().take(components.len() - 1) {
            prefix.push(component);
            let candidate = self.root.join(&prefix);
            if candidate.join(".git").exists() {
                submodule = Some((candidate, index + 1));
            }
        }

        match submodule {
            Some((dir, crossed)) => (dir, components[crossed..].join("/")),
            None => (self.root.clone(), file_path.to_string()),
        }
    }

    /// Get blame information for a file
    pub fn blame(&self, file_path: &str) -> Result<Vec<BlameInfo>> {
        Self::validate_input(file_path, "file_path")?;
        let (work_tree, file_path) = self.work_tree_for(file_path);

        let output = Command::new("git")
            .args(["blame", "--line-porcelain", &file_path])
            .current_dir(&work_tree)
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
        let (work_tree, file_path) = self.work_tree_for(file_path);

        let output = Command::new("git")
            .args([
                "blame",
                "--line-porcelain",
                &format!("-L{},{}", start, end),
                &file_path,
            ])
            .current_dir(&work_tree)
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
        let (work_tree, file_path) = self.work_tree_for(file_path);

        let output = Command::new("git")
            .args([
                "log",
                "--format=%H|%h|%an|%ae|%at|%s",
                "--numstat",
                &format!("-{}", max_commits),
                "--",
                &file_path,
            ])
            .current_dir(&work_tree)
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
                &format!("--max-count={}", MAX_LOG_COMMITS),
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

    fn git_output(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("git")
            .args(args)
            .current_dir(&self.root)
            .output()
            .context("Failed to run git")?;
        if !output.status.success() {
            return Err(anyhow!(
                "git {} failed: {}",
                args[0],
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    pub fn commit_range(
        &self,
        base: &str,
        branch: &str,
        include_body: bool,
        window: crate::response_budget::ListWindow,
    ) -> Result<CommitRange> {
        Self::validate_input(base, "base")?;
        Self::validate_input(branch, "branch")?;
        let base = self.git_output(&[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{base}^{{commit}}"),
        ])?;
        let branch = self.git_output(&[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{branch}^{{commit}}"),
        ])?;
        let base = base.trim();
        let branch = branch.trim();
        let merge_base = self.git_output(&["merge-base", base, branch])?;
        let range = format!("{base}..{branch}");
        let total: usize = self
            .git_output(&["rev-list", "--count", &range, "--"])?
            .trim()
            .parse()
            .context("Invalid git commit count")?;
        let offset = window.offset.min(total);
        let remaining = total - offset;
        let count = if window.limit == 0 {
            remaining
        } else {
            remaining.min(window.limit)
        };
        let mut result = CommitRange {
            merge_base: merge_base.trim().to_string(),
            total,
            commits: Vec::new(),
        };
        if count == 0 {
            return Ok(result);
        }

        // Git applies skip and max-count before reversing the commit order.
        let skip = total - offset - count;
        let format = if include_body {
            "--format=%H%x00%h%x00%an%x00%ae%x00%at%x00%s%x00%b"
        } else {
            "--format=%H%x00%h%x00%an%x00%ae%x00%at%x00%s%x00"
        };
        let output = self.git_output(&[
            "log",
            "--topo-order",
            "--reverse",
            "-z",
            format,
            &format!("--skip={skip}"),
            &format!("--max-count={count}"),
            &range,
            "--",
        ])?;
        let fields: Vec<&str> = output.split_terminator('\0').collect();
        let mut records = fields.chunks_exact(7);
        for record in &mut records {
            result.commits.push(FileCommit {
                hash: record[0].to_string(),
                short_hash: record[1].to_string(),
                author: record[2].to_string(),
                author_email: record[3].to_string(),
                timestamp: record[4].parse().context("Invalid git commit timestamp")?,
                subject: record[5].to_string(),
                body: record[6].trim_end().to_string(),
                files_changed: 0,
                insertions: 0,
                deletions: 0,
            });
        }
        if !records.remainder().is_empty() {
            return Err(anyhow!("Incomplete git commit record"));
        }
        Ok(result)
    }

    /// Calculate change frequency metrics for files
    pub fn change_frequency(&self, days: u32) -> Result<Vec<ChangeFrequency>> {
        let output = Command::new("git")
            .args([
                "log",
                "--format=%H %ae",
                "--name-only",
                &format!("--since={} days ago", days),
                &format!("--max-count={}", MAX_LOG_COMMITS),
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
        let (work_tree, file_path) = self.work_tree_for(file_path);

        let output = Command::new("git")
            .args(["shortlog", "-sne", "HEAD", "--", &file_path])
            .current_dir(&work_tree)
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
        contributors.sort_by_key(|contributor| std::cmp::Reverse(contributor.1));

        Ok(contributors)
    }

    /// Get the diff for a specific commit
    pub fn commit_diff(
        &self,
        commit: &str,
        file_path: Option<&str>,
        context_lines: Option<usize>,
    ) -> Result<String> {
        Self::validate_input(commit, "commit")?;
        if let Some(path) = file_path {
            Self::validate_input(path, "file_path")?;
        }

        let unified = context_lines.map(|lines| format!("-U{}", lines));

        // The message carries why the change was made, which no other tool
        // returns; the diff alone sends the caller to `git show` for it.
        let show = |rev: &str| {
            let mut args = vec![
                "show",
                "--format=commit %H%nAuthor: %an <%ae>%nDate:   %ad%n%n%B",
                "--patch",
            ];
            if let Some(flag) = &unified {
                args.push(flag.as_str());
            }
            args.push(rev);
            if let Some(path) = file_path {
                args.push("--");
                args.push(path);
            }
            Command::new("git")
                .args(&args)
                .current_dir(&self.root)
                .output()
                .context("Failed to run git show")
        };

        let mut output = show(commit)?;
        if !output.status.success() {
            // A name `git show` cannot resolve may still be an StGit patch:
            // those live under refs/patches/<branch>/ and are not part of the
            // revision namespace git searches.
            if let Some(patch_ref) = self.stgit_patch_ref(commit) {
                output = show(&patch_ref)?;
            }
        }

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git show failed: {}", err));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// The ref StGit keeps for patch `name` on the current branch, if it exists.
    fn stgit_patch_ref(&self, name: &str) -> Option<String> {
        let branch = self.current_branch().ok()?;
        if branch.is_empty() {
            return None;
        }
        let patch_ref = format!("refs/patches/{}/{}", branch, name);
        let output = Command::new("git")
            .args(["rev-parse", "--verify", "--quiet", &patch_ref])
            .current_dir(&self.root)
            .output()
            .ok()?;
        output.status.success().then_some(patch_ref)
    }

    /// Find commits that modified a specific function/symbol, in the given
    /// files. An empty `file_paths` searches the whole tree.
    pub fn symbol_history(
        &self,
        file_paths: &[String],
        function_name: &str,
        max_commits: usize,
    ) -> Result<Vec<FileCommit>> {
        for file_path in file_paths {
            Self::validate_input(file_path, "file_path")?;
        }
        Self::validate_input(function_name, "function_name")?;

        let mut args = vec![
            "log".to_string(),
            "--format=%H|%h|%an|%ae|%at|%s".to_string(),
            // parse_log_output sums these into the per-commit change counts.
            "--numstat".to_string(),
            format!("-{}", max_commits),
            format!("-S{}", function_name),
            "--".to_string(),
        ];
        args.extend(file_paths.iter().cloned());

        let output = Command::new("git")
            .args(&args)
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

    /// Get list of modified files (working tree). An unmerged path carries its
    /// `git status --porcelain` code, since its content is a conflict rather
    /// than a version of the file.
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
                    // An unmerged path has no one content to read; a caller
                    // told only that the file changed cannot know that.
                    let status = &line[..2];
                    let path = &line[3..];
                    Some(if is_unmerged_status(status) {
                        format!("{} (unmerged, {})", path, status)
                    } else {
                        path.to_string()
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(files)
    }

    /// Repo-relative paths that differ between `base` and the current working
    /// tree, including uncommitted edits and untracked files. Empty when `base`
    /// is not a commit this repo has (e.g. a rebased or deleted branch).
    pub fn changed_files_since(&self, base: &str) -> Result<Vec<String>> {
        Self::validate_input(base, "commit")?;

        // No second revision: git compares `base` against the working tree, so
        // committed and uncommitted changes come out of one command.
        let diff_out = Command::new("git")
            .args(["diff", "--name-only", base, "--"])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git diff")?;

        let mut files: Vec<String> = if diff_out.status.success() {
            String::from_utf8_lossy(&diff_out.stdout)
                .lines()
                .map(|line| line.to_string())
                .collect()
        } else {
            // An unknown base is not an error here — the caller loses the
            // widening, which is the state it was in before the base existed.
            Vec::new()
        };

        // Untracked files are invisible to git diff.
        let untracked_out = Command::new("git")
            .args(["ls-files", "--others", "--exclude-standard"])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git ls-files")?;

        if untracked_out.status.success() {
            files.extend(
                String::from_utf8_lossy(&untracked_out.stdout)
                    .lines()
                    .map(|line| line.to_string()),
            );
        }

        Ok(files)
    }

    /// Number of commits between `base` and HEAD, for reporting how far behind
    /// a build artefact is. `None` when `base` is unknown to this repo.
    pub fn commits_since(&self, base: &str) -> Option<usize> {
        Self::validate_input(base, "commit").ok()?;

        let output = Command::new("git")
            .args(["rev-list", "--count", &format!("{}..HEAD", base)])
            .current_dir(&self.root)
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        String::from_utf8_lossy(&output.stdout).trim().parse().ok()
    }

    /// Tracking state of the current branch versus its upstream. Returns
    /// `Ok(None)` when there is no upstream (detached HEAD or no tracking
    /// branch) — that is a normal state, not an error. All args are fixed
    /// literals, so no validate_input is needed.
    pub fn upstream_info(&self) -> Result<Option<UpstreamInfo>> {
        // Upstream ref name, e.g. "origin/main"; non-zero exit => no upstream.
        let name_out = Command::new("git")
            .args([
                "rev-parse",
                "--abbrev-ref",
                "--symbolic-full-name",
                "@{upstream}",
            ])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git rev-parse")?;
        if !name_out.status.success() {
            return Ok(None);
        }
        let upstream = String::from_utf8_lossy(&name_out.stdout).trim().to_string();
        if upstream.is_empty() {
            return Ok(None);
        }

        // "<behind>\t<ahead>": commits on upstream not HEAD, then HEAD not upstream.
        let counts_out = Command::new("git")
            .args(["rev-list", "--left-right", "--count", "@{upstream}...HEAD"])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git rev-list")?;
        let (mut behind, mut ahead) = (0usize, 0usize);
        if counts_out.status.success() {
            let text = String::from_utf8_lossy(&counts_out.stdout);
            let mut parts = text.split_whitespace();
            behind = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            ahead = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        }

        // Subjects of the unpushed (ahead) commits, newest first.
        let mut unpushed = Vec::new();
        if ahead > 0 {
            let log_out = Command::new("git")
                .args(["log", "--format=%h %s", "@{upstream}..HEAD"])
                .current_dir(&self.root)
                .output()
                .context("Failed to run git log")?;
            if log_out.status.success() {
                unpushed = String::from_utf8_lossy(&log_out.stdout)
                    .lines()
                    .map(|line| line.to_string())
                    .collect();
            }
        }

        Ok(Some(UpstreamInfo {
            upstream,
            ahead,
            behind,
            unpushed,
        }))
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
        format!(
            "{}...",
            crate::response_budget::truncate_on_char_boundary(s, max.saturating_sub(3))
        )
    }
}

/// The `git status --porcelain` two-letter codes for an unresolved merge:
/// either side unmerged (`U`), both added, or both deleted.
fn is_unmerged_status(status: &str) -> bool {
    matches!(status, "DD" | "AA") || status.contains('U')
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn unmerged_status_codes_are_recognised() {
        for unmerged in ["UU", "AA", "DD", "AU", "UA", "DU", "UD"] {
            assert!(is_unmerged_status(unmerged), "{unmerged}");
        }
        for resolved in [" M", "M ", "??", "A ", "R ", "MM"] {
            assert!(!is_unmerged_status(resolved), "{resolved}");
        }
    }

    /// Run a git command in `dir`, asserting success. gpg signing is disabled
    /// and identity is set via env so the test does not depend on global config.
    fn run_git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .arg("-c")
            .arg("commit.gpgsign=false")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e")
            .output()
            .expect("run git");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[tokio::test]
    async fn commit_range_paginates_oldest_first_and_keeps_bodies() {
        use crate::response_budget::ListWindow;

        let directory = TempDir::new().unwrap();
        let path = directory.path();
        run_git(path, &["init", "-q", "-b", "base"]);
        run_git(path, &["commit", "-q", "--allow-empty", "-m", "root"]);
        run_git(path, &["tag", "fork"]);
        run_git(path, &["checkout", "-q", "-b", "topic"]);
        run_git(
            path,
            &[
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "first | subject",
                "-m",
                "First line\nSecond | line",
            ],
        );
        for subject in ["second", "third"] {
            run_git(path, &["commit", "-q", "--allow-empty", "-m", subject]);
        }
        run_git(path, &["checkout", "-q", "base"]);
        run_git(
            path,
            &["commit", "-q", "--allow-empty", "-m", "base advanced"],
        );
        let git = GitRepo::new(path).unwrap();
        let first = git
            .commit_range("base", "topic", true, ListWindow::new(0, 2))
            .unwrap();
        assert_eq!(first.total, 3);
        assert_eq!(
            first.merge_base,
            std::fs::read_to_string(path.join(".git/refs/tags/fork"))
                .unwrap()
                .trim()
        );
        assert_eq!(first.commits.len(), 2);
        assert_eq!(first.commits[0].subject, "first | subject");
        assert_eq!(first.commits[0].body, "First line\nSecond | line");
        assert_eq!(first.commits[1].subject, "second");

        let last = git
            .commit_range("base", "topic", false, ListWindow::new(2, 2))
            .unwrap();
        assert_eq!(last.total, 3);
        assert_eq!(last.commits.len(), 1);
        assert_eq!(last.commits[0].subject, "third");
        let all = git
            .commit_range("base", "topic", false, ListWindow::new(0, 0))
            .unwrap();
        assert_eq!(all.commits.len(), 3);
        assert!(all.commits.iter().all(|commit| commit.body.is_empty()));
        assert_eq!(all.commits[0].hash, first.commits[0].hash);
        assert_eq!(all.commits[2].hash, last.commits[0].hash);
        assert!(git
            .commit_range("base", "topic", false, ListWindow::new(99, 2))
            .unwrap()
            .commits
            .is_empty());
        let empty = git
            .commit_range("topic", "topic", false, ListWindow::new(0, 2))
            .unwrap();
        assert_eq!(empty.total, 0);
        assert!(empty.commits.is_empty());
        for base in ["missing", "--all"] {
            assert!(git
                .commit_range(base, "topic", false, ListWindow::new(0, 2))
                .is_err());
        }
        assert!(git
            .commit_range("base", "missing", false, ListWindow::new(0, 2))
            .is_err());

        let index = TempDir::new().unwrap();
        let engine = crate::index::CodeIntelEngine::with_options(
            index.path().to_path_buf(),
            vec![path.to_path_buf()],
            crate::index::EngineOptions {
                git_enabled: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        engine.complete_initialization().await.unwrap();
        let output = engine
            .get_commit_range(
                path.to_str().unwrap(),
                "base",
                "topic",
                true,
                ListWindow::new(0, 2),
            )
            .await
            .unwrap();
        assert!(
            output.contains(&format!("Merge base: `{}`", first.merge_base)),
            "{output}"
        );
        assert!(output.contains("First line\n  Second | line"), "{output}");
        assert!(output.contains("get_commit_range(offset=2)"), "{output}");
        assert!(!output.contains(&last.commits[0].hash), "{output}");

        run_git(path, &["checkout", "-q", "-b", "side", "fork"]);
        run_git(path, &["commit", "-q", "--allow-empty", "-m", "side"]);
        run_git(path, &["checkout", "-q", "topic"]);
        run_git(path, &["merge", "-q", "--no-ff", "-m", "merge side", "side"]);
        let merged = git
            .commit_range("base", "topic", false, ListWindow::new(0, 0))
            .unwrap();
        assert_eq!(merged.total, 5);
        for (offset, expected) in merged.commits.iter().enumerate() {
            let page = git
                .commit_range("base", "topic", false, ListWindow::new(offset, 1))
                .unwrap();
            assert_eq!(page.commits[0].hash, expected.hash);
        }
    }

    /// A submodule's file is absent from the superproject's HEAD, so blame and
    /// history for it have to run in the submodule's own work tree.
    #[test]
    fn blame_and_history_of_a_submodule_file() {
        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("sub_origin");
        std::fs::create_dir(&sub).unwrap();
        run_git(&sub, &["init", "-q"]);
        std::fs::write(sub.join("Makefile.am"), "SUBDIRS = src\n").unwrap();
        run_git(&sub, &["add", "Makefile.am"]);
        run_git(&sub, &["commit", "-q", "-m", "add the submodule makefile"]);

        let super_project = dir.path().join("super");
        std::fs::create_dir(&super_project).unwrap();
        run_git(&super_project, &["init", "-q"]);
        std::fs::write(super_project.join("README"), "top\n").unwrap();
        run_git(&super_project, &["add", "README"]);
        run_git(&super_project, &["commit", "-q", "-m", "top"]);
        run_git(
            &super_project,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "--quiet",
                "add",
                sub.to_str().unwrap(),
                "core",
            ],
        );
        run_git(&super_project, &["commit", "-q", "-m", "add the submodule"]);

        let repo = GitRepo::new(&super_project).unwrap();

        let blame = repo
            .blame("core/Makefile.am")
            .expect("blame of a file under a gitlink");
        assert_eq!(blame.len(), 1);
        assert_eq!(blame[0].summary, "add the submodule makefile");

        let history = repo
            .file_history("core/Makefile.am", 5)
            .expect("history of a file under a gitlink");
        assert_eq!(history.len(), 1);

        // A path that crosses no gitlink still answers from the repo root.
        assert_eq!(repo.blame("README").unwrap().len(), 1);
    }

    #[test]
    fn test_upstream_info_none_without_tracking_branch() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        run_git(p, &["init", "-q"]);
        std::fs::write(p.join("a.txt"), "x").unwrap();
        run_git(p, &["add", "a.txt"]);
        run_git(p, &["commit", "-q", "-m", "a"]);

        let repo = GitRepo::new(p).unwrap();
        assert!(
            repo.upstream_info().unwrap().is_none(),
            "a branch with no upstream must report None, not an error"
        );
    }

    #[test]
    fn test_upstream_info_reports_ahead() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        run_git(p, &["init", "-q"]);
        std::fs::write(p.join("a.txt"), "1").unwrap();
        run_git(p, &["add", "a.txt"]);
        run_git(p, &["commit", "-q", "-m", "base"]);
        // Use a local branch as the current branch's upstream.
        run_git(p, &["branch", "up"]);
        run_git(p, &["branch", "--set-upstream-to=up"]);
        // One commit past the upstream: ahead by 1, behind by 0.
        std::fs::write(p.join("a.txt"), "2").unwrap();
        run_git(p, &["commit", "-qa", "-m", "ahead commit"]);

        let repo = GitRepo::new(p).unwrap();
        let info = repo.upstream_info().unwrap().expect("has upstream");
        assert_eq!(info.upstream, "up");
        assert_eq!(info.ahead, 1);
        assert_eq!(info.behind, 0);
        assert_eq!(info.unpushed.len(), 1);
        assert!(
            info.unpushed[0].contains("ahead commit"),
            "unpushed subject missing: {:?}",
            info.unpushed
        );
    }

/// One more commit than [`MAX_LOG_COMMITS`] allows, so a caller-visible
    /// count strictly under the created total proves the cap took effect
    /// rather than every commit simply falling outside `--since`.
    #[test]
    fn recent_changes_and_change_frequency_cap_at_max_log_commits() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        run_git(p, &["init", "-q"]);
        std::fs::write(p.join("a.txt"), "0").unwrap();
        run_git(p, &["add", "a.txt"]);
        run_git(p, &["commit", "-q", "-m", "step"]);
        let max_commits: usize = MAX_LOG_COMMITS.parse().unwrap();
        for step in 1..(max_commits + 1) {
            std::fs::write(p.join("a.txt"), step.to_string()).unwrap();
            run_git(p, &["commit", "-qa", "-m", "step"]);
        }

        let repo = GitRepo::new(p).unwrap();
        let changes = repo.recent_changes(3650).unwrap();
        assert_eq!(
            changes.len(),
            max_commits,
            "git log --max-count must cap recent_changes at {max_commits}"
        );

        let frequency = repo.change_frequency(3650).unwrap();
        let a_txt = frequency
            .iter()
            .find(|f| f.file_path == "a.txt")
            .expect("a.txt should appear in change_frequency");
        assert_eq!(
            a_txt.total_commits, max_commits,
            "git log --max-count must cap change_frequency's commit count at {max_commits}"
        );
    }

    #[test]
    fn changed_files_since_reports_committed_and_untracked() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        run_git(p, &["init", "-q"]);
        std::fs::write(p.join("base.c"), "int base;").unwrap();
        run_git(p, &["add", "base.c"]);
        run_git(p, &["commit", "-q", "-m", "base"]);

        let repo = GitRepo::new(p).unwrap();
        let base = {
            let out = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(p)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert!(repo.changed_files_since(&base).unwrap().is_empty());

        // Committed after the base, edited but not committed, never added.
        std::fs::write(p.join("added.c"), "int added;").unwrap();
        run_git(p, &["add", "added.c"]);
        run_git(p, &["commit", "-q", "-m", "add"]);
        std::fs::write(p.join("base.c"), "int base_edited;").unwrap();
        std::fs::write(p.join("untracked.c"), "int untracked;").unwrap();

        let changed = repo.changed_files_since(&base).unwrap();
        for expected in ["added.c", "base.c", "untracked.c"] {
            assert!(
                changed.iter().any(|f| f == expected),
                "{} missing from {:?}",
                expected,
                changed
            );
        }
        assert_eq!(repo.commits_since(&base), Some(1));
    }

    /// A base commit that no longer exists (rebase, deleted branch) must not
    /// propagate an error to the caller.
    #[test]
    fn changed_files_since_unknown_base_is_empty() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        run_git(p, &["init", "-q"]);
        std::fs::write(p.join("a.c"), "int a;").unwrap();
        run_git(p, &["add", "a.c"]);
        run_git(p, &["commit", "-q", "-m", "a"]);

        let repo = GitRepo::new(p).unwrap();
        let missing = "0123456789abcdef0123456789abcdef01234567";
        assert!(repo.changed_files_since(missing).unwrap().is_empty());
        assert_eq!(repo.commits_since(missing), None);
    }

    /// StGit names its patches in `stg series`, and those names are what a
    /// caller passes on; git resolves them only via refs/patches/<branch>/.
    #[test]
    fn commit_diff_resolves_an_stgit_patch_name() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        run_git(p, &["init", "-q", "-b", "work"]);
        std::fs::write(p.join("a.c"), "int a;").unwrap();
        run_git(p, &["add", "a.c"]);
        run_git(p, &["commit", "-q", "-m", "base"]);
        std::fs::write(p.join("a.c"), "int a_patched;").unwrap();
        run_git(p, &["commit", "-qa", "-m", "the patch"]);
        run_git(p, &["update-ref", "refs/patches/work/my-patch", "HEAD"]);

        let repo = GitRepo::new(p).unwrap();
        let diff = repo.commit_diff("my-patch", None, None).unwrap();
        assert!(diff.contains("a_patched"), "diff was: {}", diff);
    }

    /// Regression: the diff came back with `--format=`, so the message that
    /// says why the commit was made never reached the caller.
    #[test]
    fn commit_diff_carries_the_commit_message() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        run_git(p, &["init", "-q"]);
        std::fs::write(p.join("a.c"), "int a;").unwrap();
        run_git(p, &["add", "a.c"]);
        run_git(p, &["commit", "-q", "-m", "base"]);
        std::fs::write(p.join("a.c"), "int a_patched;").unwrap();
        run_git(
            p,
            &[
                "commit",
                "-qa",
                "-m",
                "pause the widget\n\nThe reason this is safe lives in the body.",
            ],
        );

        let repo = GitRepo::new(p).unwrap();
        let diff = repo.commit_diff("HEAD", None, None).unwrap();
        assert!(diff.contains("pause the widget"), "{diff}");
        assert!(diff.contains("The reason this is safe"), "{diff}");
        assert!(diff.contains("a_patched"), "{diff}");
    }

    /// One changed line in a long file: the unchanged neighbours around the
    /// hunk are what a caller comparing two commits pays for and can drop.
    #[test]
    fn commit_diff_context_lines_narrow_the_hunk() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        run_git(p, &["init", "-q"]);
        let lines: String = (0..40).map(|line| format!("int v{};\n", line)).collect();
        std::fs::write(p.join("a.c"), &lines).unwrap();
        run_git(p, &["add", "a.c"]);
        run_git(p, &["commit", "-q", "-m", "base"]);
        std::fs::write(p.join("a.c"), lines.replace("int v20;", "int v20_edited;")).unwrap();
        run_git(p, &["commit", "-qa", "-m", "edit one line"]);

        let repo = GitRepo::new(p).unwrap();
        let wide = repo.commit_diff("HEAD", None, None).unwrap();
        let tight = repo.commit_diff("HEAD", None, Some(0)).unwrap();
        assert!(tight.contains("+int v20_edited;"), "{tight}");
        assert!(!tight.contains(" int v17;"), "context not dropped: {tight}");
        assert!(wide.contains(" int v17;"), "{wide}");
    }

    /// A genuinely unknown name must still fail, and say so as git does.
    #[test]
    fn commit_diff_reports_an_unknown_revision() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        run_git(p, &["init", "-q"]);
        std::fs::write(p.join("a.c"), "int a;").unwrap();
        run_git(p, &["add", "a.c"]);
        run_git(p, &["commit", "-q", "-m", "base"]);

        let repo = GitRepo::new(p).unwrap();
        assert!(repo.commit_diff("no-such-patch", None, None).is_err());
    }

    /// Without a file the caller gets `git log -S` over the files passed in;
    /// an empty pathspec would make git refuse the command outright.
    #[test]
    fn symbol_history_searches_every_named_file() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        run_git(p, &["init", "-q"]);
        std::fs::write(p.join("a.c"), "void shared(void) {}").unwrap();
        std::fs::write(p.join("b.c"), "int untouched;").unwrap();
        run_git(p, &["add", "a.c", "b.c"]);
        run_git(p, &["commit", "-q", "-m", "add shared"]);

        let repo = GitRepo::new(p).unwrap();
        let paths = vec!["a.c".to_string(), "b.c".to_string()];
        let history = repo.symbol_history(&paths, "shared", 10).unwrap();
        assert_eq!(history.len(), 1, "history was: {:?}", history);
        assert_eq!(history[0].subject, "add shared");
        // Regression: every commit came back as "+0 -0 across 0 file(s)".
        assert!(history[0].files_changed > 0, "{:?}", history[0]);
        assert!(history[0].insertions > 0, "{:?}", history[0]);
    }

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

    /// Commit subjects and author names are routinely non-ASCII; cutting at a
    /// fixed byte offset used to panic when the offset split a character.
    #[test]
    fn test_truncate_multibyte_summary() {
        // 'ü' is 2 bytes and straddles the cut at byte 7.
        assert_eq!(truncate("fix: übergrößes buffer", 10), "fix: ü...");
        assert_eq!(truncate("🦀🦀🦀 rewrite in rust", 10), "🦀...");
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
            .contains("forbidden character"));

        let result = GitRepo::validate_input("function\0name", "function_name");
        assert!(result.is_err());
    }

    #[test]
    fn test_git_shell_metacharacter_injection_blocked() {
        assert!(GitRepo::validate_input(";whoami", "ref").is_err());
        assert!(GitRepo::validate_input("branch|cat", "ref").is_err());
        assert!(GitRepo::validate_input("branch&bg", "ref").is_err());
        assert!(GitRepo::validate_input("`id`", "ref").is_err());
        assert!(GitRepo::validate_input("$(whoami)", "ref").is_err());
        assert!(GitRepo::validate_input("branch>file", "ref").is_err());
    }

    #[test]
    fn test_git_argument_injection_variants() {
        assert!(GitRepo::validate_input("--upload-pack=evil", "ref").is_err());
        assert!(GitRepo::validate_input("-c", "ref").is_err());
    }

    #[test]
    fn test_git_valid_commit_hashes_pass() {
        assert!(GitRepo::validate_input("abc123def456", "commit").is_ok());
        assert!(
            GitRepo::validate_input("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "commit").is_ok()
        );
    }

    #[test]
    fn test_git_valid_file_paths_pass() {
        assert!(GitRepo::validate_input("src/main.rs", "file_path").is_ok());
        assert!(GitRepo::validate_input("tests/integration/test.rs", "file_path").is_ok());
    }
}
