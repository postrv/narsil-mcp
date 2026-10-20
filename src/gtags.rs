use directories::ProjectDirs;
use std::fs::File;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Whether GNU Global's `global(1)` CLI is installed on `$PATH`.
///
/// Used to auto-enable gtags as a C/C++ reference backend only when it can
/// actually answer queries.
pub fn gtags_available() -> bool {
    crate::validation::binary_on_path("global")
}

/// Whether the `gtags(1)` database builder is installed on `$PATH`.
///
/// GNU Global ships two binaries: `global` answers queries, `gtags` builds the
/// database. Gates `--gtags-generate`: a database can only be auto-built when
/// this binary is present.
pub fn gtags_binary_present() -> bool {
    crate::validation::binary_on_path("gtags")
}

/// Base path (no extension) for the exclusive write lock guarding
/// `repo_path`'s GTAGS database. Lives in narsil's cache dir, not the repo
/// tree, keyed by the same canonical-path hash the per-repo stats file
/// already uses (`metrics::index_path_hash`) so it never collides across
/// repos and is stable across runs.
fn gtags_lock_base_path(repo_path: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(repo_path).unwrap_or_else(|_| repo_path.to_path_buf());
    let hash = crate::metrics::index_path_hash(&canonical);
    let dir = match ProjectDirs::from("", "", crate::APP_NAME) {
        Some(dirs) => dirs.cache_dir().join("gtags-locks"),
        None => Path::new("/tmp").join(crate::APP_NAME).join("gtags-locks"),
    };
    dir.join(hash)
}

/// Directory holding `repo_path`'s GTAGS/GRTAGS/GPATH, out of the repo tree.
/// Sibling of the lock directory, same per-repo hash. Keeping gtags's own
/// output out of the repo tree avoids polluting `git status`, and — per the
/// 2026-08-18 investigation — sidesteps a segfault GNU Global's in-place
/// incremental update hit against an existing in-tree database that the
/// same content did not reproduce once the database lived elsewhere.
fn gtags_db_dir(repo_path: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(repo_path).unwrap_or_else(|_| repo_path.to_path_buf());
    let hash = crate::metrics::index_path_hash(&canonical);
    let dir = match ProjectDirs::from("", "", crate::APP_NAME) {
        Some(dirs) => dirs.cache_dir().join("gtags-db"),
        None => Path::new("/tmp").join(crate::APP_NAME).join("gtags-db"),
    };
    dir.join(hash)
}

/// Path to `repo_path`'s GTAGS file, wherever its database currently lives.
/// The one place callers should ask "does a database exist" or "how old is
/// it" — never `repo_path.join("GTAGS")` directly, since the database no
/// longer lives in the repo tree.
pub fn gtags_file_path(repo_path: &Path) -> PathBuf {
    gtags_db_dir(repo_path).join("GTAGS")
}

/// Acquire the exclusive write lock for `repo_path`'s GTAGS database,
/// blocking off the async runtime (`spawn_blocking`) until any other
/// writer — in this process or another — releases it. `gtags`/`global -u`
/// write GTAGS/GRTAGS/GPATH in place and are not safe against a concurrent
/// writer; the caller holds the returned guard across the subprocess call.
/// Dropping it releases the lock, which also happens automatically if the
/// holder crashes (the kernel releases an flock on fd close).
///
/// Returns `None` if the lock could not be acquired — e.g. the cache
/// directory is not writable — in which case the caller proceeds without
/// it rather than failing gtags entirely.
async fn acquire_gtags_lock(repo_path: &Path) -> Option<File> {
    let lock_path = gtags_lock_base_path(repo_path);
    match tokio::task::spawn_blocking(move || crate::metrics::acquire_exclusive_lock(&lock_path))
        .await
    {
        Ok(Ok(file)) => Some(file),
        Ok(Err(e)) => {
            warn!("gtags: could not acquire write lock: {}", e);
            None
        }
        Err(e) => {
            warn!("gtags: lock task panicked: {}", e);
            None
        }
    }
}

/// Symbol names per batched `global -x` alternation pattern. Bounded so the
/// pattern stays well inside the argument-length limit.
const DEFINITION_BATCH_NAMES: usize = 256;

/// Wrapper around the GNU Global `global(1)` CLI for C/C++ reference queries.
///
/// gtags --lsp is not available in common distros, so we drive global(1)
/// as a subprocess and parse its output.
pub struct GtagsManager {
    /// Roots are stored for potential future filtering; queries use the
    /// per-call repo_path argument.
    #[allow(dead_code)]
    repo_roots: Vec<PathBuf>,
}

impl GtagsManager {
    pub fn new(repo_roots: Vec<PathBuf>) -> Self {
        Self { repo_roots }
    }

    /// Run `global -rx SYMBOL` from `repo_path` and return parsed references.
    ///
    /// `global -rx` output format (space-separated, symbol col is fixed-width):
    ///   SYMBOL    LINE  FILE    SOURCE_TEXT
    ///
    /// Returns an empty vec when global is not installed, the GTAGS database
    /// is missing, or the symbol has no references.
    pub async fn find_references(
        &self,
        symbol: &str,
        repo_path: &Path,
    ) -> Vec<(String, usize, String)> {
        let output = tokio::process::Command::new("global")
            .args(["-rx", symbol])
            .current_dir(repo_path)
            .env("GTAGSROOT", repo_path)
            .env("GTAGSDBPATH", gtags_db_dir(repo_path))
            .output()
            .await;

        match output {
            Err(e) => {
                debug!("gtags: global command unavailable: {}", e);
                vec![]
            }
            Ok(out) => Self::parse_output(&out.stdout, repo_path),
        }
    }

    /// Run `global -x -f FILE` from `repo_path` and return (name, line) pairs
    /// for every symbol defined in `file`.
    ///
    /// `-f` lists the definitions in one file; `-x` selects the extended,
    /// space-separated format also produced by `-rx`:
    ///   NAME  LINE  FILE  SOURCE_TEXT
    ///
    /// Returns an empty vec when global is missing, the GTAGS database is
    /// absent, or the file defines no symbols.
    pub async fn list_file_symbols(&self, file: &Path, repo_path: &Path) -> Vec<(String, usize)> {
        // global resolves -f paths against the GTAGS root, so pass the path
        // relative to repo_path; an absolute index path would not match.
        let rel = file.strip_prefix(repo_path).unwrap_or(file);
        let output = tokio::process::Command::new("global")
            .args(["-x", "-f"])
            .arg(rel)
            .current_dir(repo_path)
            .env("GTAGSROOT", repo_path)
            .env("GTAGSDBPATH", gtags_db_dir(repo_path))
            .output()
            .await;

        match output {
            Err(e) => {
                debug!("gtags: global -f unavailable: {}", e);
                vec![]
            }
            Ok(out) => Self::parse_file_symbols(&out.stdout),
        }
    }

    /// Ensure a GTAGS database exists for `repo_path`, building one with the
    /// `gtags` binary when absent. Returns true if a database exists afterwards.
    ///
    /// Writes into `gtags_db_dir(repo_path)`, out of the repo tree — a side
    /// effect, so callers gate this behind an opt-in. No-op returning the
    /// current state when the `gtags` binary is missing.
    pub async fn ensure_database(&self, repo_path: &Path) -> bool {
        if gtags_file_path(repo_path).exists() {
            return true;
        }
        if !gtags_binary_present() {
            return false;
        }
        let _lock = acquire_gtags_lock(repo_path).await;
        self.build_fresh(repo_path).await
    }

    /// Build a fresh GTAGS database for `repo_path` from scratch (no `-i`),
    /// discarding whatever is already at `gtags_db_dir`. Callers hold the
    /// write lock across this call; it does not acquire it itself.
    async fn build_fresh(&self, repo_path: &Path) -> bool {
        let db_dir = gtags_db_dir(repo_path);
        // A from-scratch build overwrites everything anyway, so a failed
        // cleanup here only wastes disk, not correctness.
        let _ = std::fs::remove_dir_all(&db_dir);
        if let Err(e) = std::fs::create_dir_all(&db_dir) {
            warn!("gtags: could not create db dir {:?}: {}", db_dir, e);
            return false;
        }
        info!("gtags: building GTAGS database in {:?}", db_dir);
        // `gtags` (the builder) does not consult GTAGSDBPATH — that is a
        // `global`/query-side variable — so the output directory has to be
        // its positional dbpath argument instead.
        match tokio::process::Command::new("gtags")
            .current_dir(repo_path)
            .arg(&db_dir)
            .output()
            .await
        {
            Err(e) => {
                warn!("gtags: failed to run gtags in {:?}: {}", repo_path, e);
                false
            }
            Ok(out) => {
                if !out.status.success() {
                    warn!(
                        "gtags: build failed in {:?}: {}",
                        repo_path,
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
                gtags_file_path(repo_path).exists()
            }
        }
    }

    /// Refresh an existing GTAGS database incrementally (`global -u`), out of
    /// the repo tree, so callers gate it behind opt-in. Falls back to a full
    /// rebuild (`build_fresh`) when the incremental update fails: GNU Global
    /// has no way to recover a database its own incremental path can't
    /// update, so retrying the same `global -u` would just fail again the
    /// same way — a full rebuild is the one thing that reliably produces a
    /// working database. Returns true on success (incremental or rebuilt);
    /// no-op returning false when the `gtags` toolchain is missing.
    pub async fn update_database(&self, repo_path: &Path) -> bool {
        if !gtags_binary_present() {
            return false;
        }
        let _lock = acquire_gtags_lock(repo_path).await;
        let db_dir = gtags_db_dir(repo_path);
        info!(
            "gtags: refreshing GTAGS database in {:?} (global -u)",
            db_dir
        );
        let updated = match tokio::process::Command::new("global")
            .arg("-u")
            .current_dir(repo_path)
            .env("GTAGSROOT", repo_path)
            .env("GTAGSDBPATH", &db_dir)
            .output()
            .await
        {
            Err(e) => {
                warn!("gtags: failed to run global -u in {:?}: {}", repo_path, e);
                false
            }
            Ok(out) => {
                if !out.status.success() {
                    warn!(
                        "gtags: global -u failed in {:?}: {}",
                        repo_path,
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
                out.status.success()
            }
        };
        if updated {
            return true;
        }
        warn!(
            "gtags: incremental update failed for {:?}; rebuilding from scratch",
            repo_path
        );
        self.build_fresh(repo_path).await
    }

    /// Run `global -x SYMBOL` from `repo_path` and return parsed definitions.
    ///
    /// Without `-r`, `global -x` reports definition sites (the tag), in the same
    /// space-separated format as `-rx`:
    ///   NAME  LINE  FILE  SOURCE_TEXT
    ///
    /// Returns an empty vec when global is missing, the GTAGS database is absent,
    /// or the symbol is not defined.
    pub async fn find_definitions(
        &self,
        symbol: &str,
        repo_path: &Path,
    ) -> Vec<(String, usize, String)> {
        let output = tokio::process::Command::new("global")
            .args(["-x", symbol])
            .current_dir(repo_path)
            .env("GTAGSROOT", repo_path)
            .env("GTAGSDBPATH", gtags_db_dir(repo_path))
            .output()
            .await;

        match output {
            Err(e) => {
                debug!("gtags: global -x unavailable: {}", e);
                vec![]
            }
            Ok(out) => Self::parse_output(&out.stdout, repo_path),
        }
    }

    /// Files defining any of `names`, repo-relative, sorted and deduplicated.
    ///
    /// One `global` run per batch of names — an alternation pattern resolves a
    /// scoped index's thousands of unmatched callees in a handful of
    /// subprocesses instead of one each. Names that are not plain identifiers
    /// cannot be tags and would be read as regex syntax, so they are dropped.
    pub async fn find_definition_files(&self, names: &[String], repo_path: &Path) -> Vec<String> {
        let identifiers: Vec<&str> = names
            .iter()
            .map(String::as_str)
            .filter(|name| {
                !name.is_empty()
                    && name
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            })
            .collect();

        let mut files = Vec::new();
        for batch in identifiers.chunks(DEFINITION_BATCH_NAMES) {
            let pattern = format!("^({})$", batch.join("|"));
            let output = tokio::process::Command::new("global")
                .arg("-x")
                .arg(&pattern)
                .current_dir(repo_path)
                .env("GTAGSROOT", repo_path)
                .env("GTAGSDBPATH", gtags_db_dir(repo_path))
                .output()
                .await;

            match output {
                Err(e) => {
                    debug!("gtags: global -x unavailable: {}", e);
                    break;
                }
                Ok(out) => files.extend(
                    Self::parse_output(&out.stdout, repo_path)
                        .into_iter()
                        .map(|(file, _, _)| file),
                ),
            }
        }

        files.sort();
        files.dedup();
        files
    }

    /// Parse `global -x -f` output into (name, line) pairs. Lines that lack a
    /// numeric line column are skipped.
    fn parse_file_symbols(stdout: &[u8]) -> Vec<(String, usize)> {
        let text = String::from_utf8_lossy(stdout);
        let mut symbols = Vec::new();

        for raw_line in text.lines() {
            let mut tokens = raw_line.split_whitespace();
            let name = match tokens.next() {
                Some(t) => t,
                None => continue,
            };
            let line_str = match tokens.next() {
                Some(t) => t,
                None => continue,
            };
            // Remaining tokens (file path, source text) are not needed here.
            if let Ok(line_num) = line_str.parse::<usize>() {
                symbols.push((name.to_string(), line_num));
            }
        }

        symbols
    }

    fn parse_output(stdout: &[u8], repo_path: &Path) -> Vec<(String, usize, String)> {
        let text = String::from_utf8_lossy(stdout);
        let mut refs = Vec::new();

        for raw_line in text.lines() {
            // Tokenize: symbol, line_number, file_path, context...
            let mut tokens = raw_line.split_whitespace();
            let _symbol = match tokens.next() {
                Some(t) => t,
                None => continue,
            };
            let line_str = match tokens.next() {
                Some(t) => t,
                None => continue,
            };
            let file_str = match tokens.next() {
                Some(t) => t,
                None => continue,
            };
            let context: Vec<&str> = tokens.collect();
            let context = context.join(" ");

            let line_num: usize = match line_str.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };

            // Make path relative to repo_root
            let rel = if file_str.starts_with('/') {
                let full = Path::new(file_str);
                full.strip_prefix(repo_path)
                    .unwrap_or(full)
                    .to_string_lossy()
                    .to_string()
            } else {
                file_str.to_string()
            };

            refs.push((rel, line_num, context));
        }

        refs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn test_parse_output_absolute_path() {
        let repo = PathBuf::from("/repo");
        let stdout = b"my_func          15 /repo/src/foo.c    my_func(arg);\n";
        let refs = GtagsManager::parse_output(stdout, &repo);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, "src/foo.c");
        assert_eq!(refs[0].1, 15);
        assert_eq!(refs[0].2, "my_func(arg);");
    }

    #[test]
    fn test_parse_output_relative_path() {
        let repo = PathBuf::from("/repo");
        let stdout = b"my_func          42 src/bar.c    my_func();\n";
        let refs = GtagsManager::parse_output(stdout, &repo);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, "src/bar.c");
        assert_eq!(refs[0].1, 42);
    }

    #[test]
    fn test_parse_output_empty() {
        let repo = PathBuf::from("/repo");
        let refs = GtagsManager::parse_output(b"", &repo);
        assert!(refs.is_empty());
    }

    #[test]
    fn test_parse_output_malformed_line_skipped() {
        let repo = PathBuf::from("/repo");
        // Only one token — should be silently skipped
        let stdout = b"only_symbol\n";
        let refs = GtagsManager::parse_output(stdout, &repo);
        assert!(refs.is_empty());
    }

    #[test]
    fn test_parse_file_symbols_extracts_name_and_line() {
        let stdout =
            b"my_func          15 src/foo.c    int my_func(int arg)\nMACRO   3 src/foo.c  #define MACRO 1\n";
        let syms = GtagsManager::parse_file_symbols(stdout);
        assert_eq!(
            syms,
            vec![("my_func".to_string(), 15), ("MACRO".to_string(), 3)]
        );
    }

    #[test]
    fn test_parse_file_symbols_skips_non_numeric_line() {
        // A line whose second column is not a number must be dropped, not panic.
        let stdout = b"weird   notaline   src/foo.c   text\n";
        let syms = GtagsManager::parse_file_symbols(stdout);
        assert!(syms.is_empty());
    }

    #[test]
    fn gtags_db_dir_is_repo_scoped_stable_and_out_of_tree() {
        let repo_a = TempDir::new().unwrap();
        let repo_b = TempDir::new().unwrap();

        let first = gtags_db_dir(repo_a.path());
        let second = gtags_db_dir(repo_a.path());
        assert_eq!(first, second, "same repo must hash to the same db dir");

        let other = gtags_db_dir(repo_b.path());
        assert_ne!(first, other, "different repos must not share a db dir");

        assert!(
            !first.starts_with(repo_a.path()),
            "the db dir must not live inside the repo tree"
        );
        assert_eq!(gtags_file_path(repo_a.path()), first.join("GTAGS"));
    }

    #[test]
    fn gtags_lock_base_path_is_repo_scoped_and_stable() {
        let repo_a = TempDir::new().unwrap();
        let repo_b = TempDir::new().unwrap();

        let first = gtags_lock_base_path(repo_a.path());
        let second = gtags_lock_base_path(repo_a.path());
        assert_eq!(first, second, "same repo must hash to the same lock path");

        let other = gtags_lock_base_path(repo_b.path());
        assert_ne!(first, other, "different repos must not share a lock path");
    }

    #[tokio::test]
    async fn acquire_gtags_lock_serializes_concurrent_writers() {
        let repo = TempDir::new().unwrap();
        let repo_path = repo.path().to_path_buf();

        let first = acquire_gtags_lock(&repo_path)
            .await
            .expect("first acquisition must succeed uncontended");

        let contender_path = repo_path.clone();
        let mut contender = tokio::spawn(async move { acquire_gtags_lock(&contender_path).await });

        // The second acquisition must not complete while the first lock is
        // still held — proves mutual exclusion, not just that the call
        // returns something.
        let still_blocked = tokio::time::timeout(Duration::from_millis(200), &mut contender).await;
        assert!(
            still_blocked.is_err(),
            "second writer must block while the first holds the lock"
        );

        drop(first);

        let second = tokio::time::timeout(Duration::from_secs(5), contender)
            .await
            .expect("second acquisition must complete once the first lock is released")
            .expect("task must not panic");
        assert!(
            second.is_some(),
            "second acquisition must eventually succeed"
        );
    }
}
