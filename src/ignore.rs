//! Unified ignore policy for indexing, watch mode, merkle walks, and trees.
//!
//! Vendor and package-manager stores must never be treated as first-party
//! source. This module is the single matcher used by every ingestion path.

use glob::Pattern;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::FileType;
use std::path::{Path, PathBuf};

/// Directory / store names that are never first-party source.
pub const DENIED_DIR_NAMES: &[&str] = &[
    "node_modules",
    ".pnpm",
    ".pnpm-store",
    ".yarn",
    ".next",
    ".nuxt",
    ".turbo",
    ".svelte-kit",
    ".output",
    ".parcel-cache",
    "target",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    "site-packages",
    "Pods",
    ".gradle",
    "coverage",
    ".git",
    ".svn",
    ".hg",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".idea",
    ".cache",
    "bower_components",
];

const DENIED_FILE_SUFFIXES: &[&str] = &[
    ".min.js",
    ".min.css",
    ".min.mjs",
    ".min.cjs",
    ".bundle.js",
    ".bundle.css",
    ".chunk.js",
    ".chunk.css",
];

const NARSILIGNORE_FILENAME: &str = ".narsilignore";

/// Caps that keep large repos from exhausting memory or CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexLimits {
    /// Skip files larger than this many bytes (default 1 MiB).
    pub max_file_size: u64,
    /// Index at most this many files per repository after ignore.
    pub max_index_files: usize,
    /// Bound the in-memory file-content cache.
    pub max_cached_files: usize,
    /// Drop a watch batch larger than this (package-install storms).
    pub watch_burst_limit: usize,
}

impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            max_file_size: 1024 * 1024,
            max_index_files: 50_000,
            max_cached_files: 50_000,
            watch_burst_limit: 250,
        }
    }
}

impl IndexLimits {
    /// Load limits from `NARSIL_*` environment variables, falling back to defaults.
    ///
    /// # Examples
    ///
    /// ```
    /// use narsil_mcp::ignore::IndexLimits;
    /// let limits = IndexLimits::from_env();
    /// assert!(limits.max_file_size > 0);
    /// ```
    #[must_use]
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            max_file_size: env_u64("NARSIL_MAX_FILE_SIZE", defaults.max_file_size),
            max_index_files: env_usize("NARSIL_MAX_INDEX_FILES", defaults.max_index_files),
            max_cached_files: env_usize("NARSIL_MAX_CACHED_FILES", defaults.max_cached_files),
            watch_burst_limit: env_usize("NARSIL_WATCH_BURST_LIMIT", defaults.watch_burst_limit),
        }
    }
}

/// Matcher used for a single repository root.
#[derive(Debug, Clone)]
pub struct IgnoreService {
    root: PathBuf,
    extra_dir_names: HashSet<String>,
    extra_globs: Vec<Pattern>,
}

impl IgnoreService {
    /// Build a matcher for `root`, loading `.narsilignore` when present.
    ///
    /// # Examples
    ///
    /// ```
    /// use narsil_mcp::ignore::IgnoreService;
    /// let ignore = IgnoreService::for_repo(std::path::Path::new("."));
    /// assert!(ignore.is_ignored(std::path::Path::new("./node_modules/lodash/index.js")));
    /// ```
    #[must_use]
    pub fn for_repo(root: &Path) -> Self {
        let mut service = Self {
            root: root.to_path_buf(),
            extra_dir_names: HashSet::new(),
            extra_globs: Vec::new(),
        };
        service.merge_pattern_file(&root.join(NARSILIGNORE_FILENAME));
        service
    }

    /// Add extra gitignore-style patterns (from `RepoConfig.exclude_patterns`).
    pub fn with_extra_patterns(mut self, patterns: &[String]) -> Self {
        for pattern in patterns {
            self.add_pattern_line(pattern);
        }
        self
    }

    /// True when any path component is a denied vendor / store name.
    #[must_use]
    pub fn is_denied_dir_name(&self, name: &str) -> bool {
        is_denied_dir_name(name) || self.extra_dir_names.contains(name)
    }

    /// True when `path` should not be indexed, watched, or walked as source.
    #[must_use]
    pub fn is_ignored(&self, path: &Path) -> bool {
        if is_symlink(path) {
            return true;
        }
        if path.components().any(|component| {
            component
                .as_os_str()
                .to_str()
                .is_some_and(|name| self.is_denied_dir_name(name))
        }) {
            return true;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if is_denied_generated_file(name) {
                return true;
            }
        }
        self.matches_extra_globs(path)
    }

    /// True when a watch event for `path` should be dropped.
    #[must_use]
    pub fn should_skip_watch(&self, path: &Path) -> bool {
        self.is_ignored(path)
    }

    /// True when a walker should not descend into this directory entry.
    #[must_use]
    pub fn should_descend(&self, file_name: &OsStr, file_type: Option<FileType>) -> bool {
        if file_type.is_some_and(|ft| ft.is_symlink()) {
            return false;
        }
        match file_name.to_str() {
            Some(name) => !self.is_denied_dir_name(name),
            None => true,
        }
    }

    /// True when a file is small enough and not ignored.
    #[must_use]
    pub fn should_index_file(&self, path: &Path, max_file_size: u64) -> bool {
        if self.is_ignored(path) {
            return false;
        }
        match std::fs::metadata(path) {
            Ok(meta) => meta.is_file() && meta.len() <= max_file_size,
            Err(_) => false,
        }
    }

    fn merge_pattern_file(&mut self, path: &Path) {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return;
        };
        for line in contents.lines() {
            self.add_pattern_line(line);
        }
    }

    fn add_pattern_line(&mut self, line: &str) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return;
        }
        let pattern = trimmed.trim_start_matches('/').trim_end_matches('/');
        if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            if let Ok(glob) = Pattern::new(pattern) {
                self.extra_globs.push(glob);
            }
            if let Ok(glob) = Pattern::new(&format!("**/{}", pattern)) {
                self.extra_globs.push(glob);
            }
            return;
        }
        if let Some(name) = Path::new(pattern).file_name().and_then(|n| n.to_str()) {
            self.extra_dir_names.insert(name.to_string());
        }
        if let Ok(glob) = Pattern::new(&format!("**/{}", pattern)) {
            self.extra_globs.push(glob);
        }
        if let Ok(glob) = Pattern::new(&format!("**/{}/**", pattern)) {
            self.extra_globs.push(glob);
        }
    }

    fn matches_extra_globs(&self, path: &Path) -> bool {
        if self.extra_globs.is_empty() {
            return false;
        }
        let relative = path.strip_prefix(&self.root).unwrap_or(path);
        let rel = relative.to_string_lossy();
        self.extra_globs.iter().any(|glob| glob.matches(&rel))
    }
}

/// True when `name` is a well-known vendor or generated directory.
#[must_use]
pub fn is_denied_dir_name(name: &str) -> bool {
    DENIED_DIR_NAMES.contains(&name)
}

/// True when any path component is a denied directory name.
#[must_use]
pub fn path_has_denied_component(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(is_denied_dir_name)
    })
}

/// True when the path is a symlink (do not follow package-manager links).
#[must_use]
pub fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
}

/// True when the filename looks like generated / minified frontend output.
#[must_use]
pub fn is_denied_generated_file(name: &str) -> bool {
    DENIED_FILE_SUFFIXES
        .iter()
        .any(|suffix| name.ends_with(suffix))
        || name.contains(".bundle.")
        || name.contains(".chunk.")
        || name.contains(".min.")
}

/// Apply the watch-mode circuit breaker. Returns the kept changes and whether
/// the batch was dropped as a burst.
#[must_use]
pub fn apply_watch_burst_limit<T>(changes: Vec<T>, limit: usize) -> (Vec<T>, bool) {
    if changes.len() > limit {
        (Vec::new(), true)
    } else {
        (changes, false)
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn denies_node_modules_and_pnpm_store() {
        let ignore = IgnoreService::for_repo(Path::new("/repo"));
        assert!(ignore.is_ignored(Path::new("/repo/node_modules/lodash/index.js")));
        assert!(ignore.is_ignored(Path::new("/repo/node_modules/.pnpm/lodash@1.0.0/index.js")));
        assert!(ignore.is_ignored(Path::new("/repo/.pnpm-store/v3/file")));
        assert!(ignore.is_ignored(Path::new("/repo/packages/app/node_modules/react/index.js")));
    }

    #[test]
    fn denies_other_vendor_trees() {
        let ignore = IgnoreService::for_repo(Path::new("/repo"));
        assert!(ignore.is_ignored(Path::new("/repo/target/debug/narsil-mcp")));
        assert!(ignore.is_ignored(Path::new("/repo/.venv/lib/python3.12/site.py")));
        assert!(ignore.is_ignored(Path::new("/repo/frontend/.next/cache/x")));
        assert!(ignore.is_ignored(Path::new("/repo/coverage/lcov.info")));
        assert!(!ignore.is_ignored(Path::new("/repo/src/index.rs")));
        assert!(!ignore.is_ignored(Path::new("/repo/crates/core/src/lib.rs")));
    }

    #[test]
    fn denies_minified_bundles() {
        let ignore = IgnoreService::for_repo(Path::new("/repo"));
        assert!(ignore.is_ignored(Path::new("/repo/static/app.min.js")));
        assert!(ignore.is_ignored(Path::new("/repo/static/app.min.css")));
        assert!(ignore.is_ignored(Path::new("/repo/static/main.bundle.js")));
        assert!(ignore.is_ignored(Path::new("/repo/static/vendor.chunk.js")));
        assert!(!ignore.is_ignored(Path::new("/repo/src/app.js")));
    }

    #[test]
    fn does_not_treat_env_as_vendor() {
        let ignore = IgnoreService::for_repo(Path::new("/repo"));
        assert!(!ignore.is_ignored(Path::new("/repo/env/config.rs")));
    }

    #[test]
    fn narsilignore_adds_custom_names() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(".narsilignore"), "generated\n*.snap\n").unwrap();
        let ignore = IgnoreService::for_repo(dir.path());
        assert!(ignore.is_ignored(&dir.path().join("generated/out.rs")));
        assert!(ignore.is_ignored(&dir.path().join("src/foo.snap")));
        assert!(!ignore.is_ignored(&dir.path().join("src/main.rs")));
    }

    #[test]
    fn extra_patterns_from_repo_config() {
        let ignore = IgnoreService::for_repo(Path::new("/repo"))
            .with_extra_patterns(&["**/fixtures/**".to_string(), "tmp".to_string()]);
        assert!(ignore.is_ignored(Path::new("/repo/tests/fixtures/evil.js")));
        assert!(ignore.is_ignored(Path::new("/repo/tmp/cache.bin")));
    }

    #[test]
    fn should_descend_blocks_denied_and_symlinks() {
        let ignore = IgnoreService::for_repo(Path::new("/repo"));
        assert!(!ignore.should_descend(OsStr::new("node_modules"), None));
        assert!(ignore.should_descend(OsStr::new("src"), None));
    }

    #[test]
    fn skips_symlinks() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("real");
        let link = dir.path().join("link");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("foo.rs"), "fn main() {}").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let ignore = IgnoreService::for_repo(dir.path());
            assert!(ignore.is_ignored(&link));
        }
    }

    #[test]
    fn should_index_file_respects_size() {
        let dir = tempdir().unwrap();
        let small = dir.path().join("small.rs");
        let large = dir.path().join("large.rs");
        fs::write(&small, "fn main() {}").unwrap();
        fs::write(&large, "x".repeat(64)).unwrap();
        let ignore = IgnoreService::for_repo(dir.path());
        assert!(ignore.should_index_file(&small, 1024));
        assert!(!ignore.should_index_file(&large, 16));
    }

    #[test]
    fn watch_burst_drops_oversized_batches() {
        let (kept, dropped) = apply_watch_burst_limit(vec![1, 2, 3, 4], 3);
        assert!(dropped);
        assert!(kept.is_empty());
        let (kept, dropped) = apply_watch_burst_limit(vec![1, 2], 3);
        assert!(!dropped);
        assert_eq!(kept, vec![1, 2]);
    }

    #[test]
    fn default_limits_are_positive() {
        let limits = IndexLimits::default();
        assert_eq!(limits.max_file_size, 1024 * 1024);
        assert_eq!(limits.max_index_files, 50_000);
        assert_eq!(limits.watch_burst_limit, 250);
    }
}
