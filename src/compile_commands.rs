//! Compilation database (`compile_commands.json`) scoping for C/C++.
//!
//! When a repo contains a compilation database (Linux kernel, CMake, Bear,
//! compiledb), only in-scope translation units and their include trees should
//! be indexed. Walking every `arch/` and unused driver is what pins tens of
//! GiB on a kernel checkout (GitHub issue #27).

use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// File name looked up at the repository root (and common build dirs).
pub const COMPILE_COMMANDS_FILENAME: &str = "compile_commands.json";

const C_IMPL_EXTENSIONS: &[&str] = &["c", "cc", "cpp", "cxx"];
const C_HEADER_EXTENSIONS: &[&str] = &["h", "hh", "hpp", "hxx"];

/// A scoped allowlist derived from a compilation database.
#[derive(Debug, Clone, Default)]
pub struct CompileCommandsScope {
    /// Translation units listed in the database (canonical paths).
    pub translation_units: HashSet<PathBuf>,
    /// Include directories extracted from `-I` / `-isystem`.
    pub include_dirs: HashSet<PathBuf>,
    /// Directories that contain an allowlisted translation unit.
    pub tu_dirs: HashSet<PathBuf>,
}

impl CompileCommandsScope {
    /// Load from `root/compile_commands.json` or `root/build/compile_commands.json`.
    ///
    /// Returns `None` when no database is present or `NARSIL_COMPILE_COMMANDS=0`.
    ///
    /// # Examples
    ///
    /// ```
    /// use narsil_mcp::compile_commands::CompileCommandsScope;
    /// assert!(CompileCommandsScope::discover(std::path::Path::new(".")).is_none()
    ///     || CompileCommandsScope::discover(std::path::Path::new(".")).is_some());
    /// ```
    #[must_use]
    pub fn discover(root: &Path) -> Option<Self> {
        if compile_commands_disabled() {
            return None;
        }
        for candidate in candidate_paths(root) {
            if candidate.is_file() {
                return Self::load(&candidate).ok();
            }
        }
        None
    }

    /// Parse a compilation database file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or is not valid JSON.
    pub fn load(path: &Path) -> Result<Self, CompileCommandsError> {
        let data = std::fs::read_to_string(path).map_err(CompileCommandsError::Io)?;
        Self::parse(&data, path.parent().unwrap_or(path))
    }

    /// Parse compilation database JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if `json` is not a compilation database array.
    pub fn parse(json: &str, fallback_dir: &Path) -> Result<Self, CompileCommandsError> {
        let entries: Vec<CompileCommandEntry> =
            serde_json::from_str(json).map_err(CompileCommandsError::Json)?;
        let mut scope = Self::default();

        for entry in entries {
            let directory = resolve_dir(&entry.directory, fallback_dir);
            let Some(file) = entry.file.as_deref() else {
                continue;
            };
            let tu = resolve_file(&directory, file);
            if let Some(parent) = tu.parent() {
                scope.tu_dirs.insert(parent.to_path_buf());
            }
            scope.translation_units.insert(tu);

            if let Some(command) = entry.command.as_deref() {
                for include in include_dirs_from_command(command, &directory) {
                    scope.include_dirs.insert(include);
                }
            }
            if let Some(arguments) = entry.arguments.as_ref() {
                for include in include_dirs_from_args(arguments, &directory) {
                    scope.include_dirs.insert(include);
                }
            }
        }

        Ok(scope)
    }

    /// True when `path` is a C/C++ file that this database does not cover.
    #[must_use]
    pub fn should_skip_c_file(&self, path: &Path) -> bool {
        if !is_c_family(path) {
            return false;
        }
        if self.translation_units.iter().any(|tu| tu == path) {
            return false;
        }
        // Also match by file name suffix when canonicalization differs.
        if let Some(name) = path.file_name() {
            if self
                .translation_units
                .iter()
                .any(|tu| tu.file_name() == Some(name) && path_ends_with(path, tu))
            {
                return false;
            }
        }
        if is_c_header(path) {
            return !self.header_is_in_scope(path);
        }
        true
    }

    fn header_is_in_scope(&self, path: &Path) -> bool {
        if let Some(parent) = path.parent() {
            if self.tu_dirs.contains(parent) {
                return true;
            }
        }
        self.include_dirs
            .iter()
            .any(|dir| path.starts_with(dir) || path_is_under(path, dir))
    }
}

/// Error loading a compilation database.
#[derive(Debug)]
pub enum CompileCommandsError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for CompileCommandsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "failed to read compile_commands.json: {err}"),
            Self::Json(err) => write!(f, "invalid compile_commands.json: {err}"),
        }
    }
}

impl std::error::Error for CompileCommandsError {}

#[derive(Debug, Deserialize)]
struct CompileCommandEntry {
    #[serde(default)]
    directory: Option<String>,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    arguments: Option<Vec<String>>,
}

fn compile_commands_disabled() -> bool {
    matches!(
        std::env::var("NARSIL_COMPILE_COMMANDS").ok().as_deref(),
        Some("0") | Some("false") | Some("off")
    )
}

fn candidate_paths(root: &Path) -> Vec<PathBuf> {
    vec![
        root.join(COMPILE_COMMANDS_FILENAME),
        root.join("build").join(COMPILE_COMMANDS_FILENAME),
        root.join("builddir").join(COMPILE_COMMANDS_FILENAME),
        root.join("out").join(COMPILE_COMMANDS_FILENAME),
    ]
}

fn resolve_dir(directory: &Option<String>, fallback: &Path) -> PathBuf {
    match directory.as_deref() {
        Some(dir) => {
            let path = PathBuf::from(dir);
            if path.is_absolute() {
                path
            } else {
                fallback.join(path)
            }
        }
        None => fallback.to_path_buf(),
    }
}

fn resolve_file(directory: &Path, file: &str) -> PathBuf {
    let path = PathBuf::from(file);
    if path.is_absolute() {
        path
    } else {
        directory.join(path)
    }
}

/// True when the path is C or C++ source or header.
#[must_use]
pub fn is_c_family(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => {
            let ext = ext.to_ascii_lowercase();
            C_IMPL_EXTENSIONS.contains(&ext.as_str()) || C_HEADER_EXTENSIONS.contains(&ext.as_str())
        }
        None => false,
    }
}

fn is_c_header(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| C_HEADER_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

fn path_ends_with(path: &Path, suffix: &Path) -> bool {
    let path_comps: Vec<_> = path.components().collect();
    let suffix_comps: Vec<_> = suffix.components().collect();
    if suffix_comps.len() > path_comps.len() {
        return false;
    }
    path_comps
        .iter()
        .rev()
        .zip(suffix_comps.iter().rev())
        .all(|(a, b)| a == b)
}

fn path_is_under(path: &Path, dir: &Path) -> bool {
    path.starts_with(dir)
}

fn include_dirs_from_command(command: &str, directory: &Path) -> Vec<PathBuf> {
    include_dirs_from_args(&split_command(command), directory)
}

fn include_dirs_from_args(args: &[String], directory: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let value = if let Some(rest) = arg.strip_prefix("-I") {
            if rest.is_empty() {
                i += 1;
                args.get(i).map(String::as_str)
            } else {
                Some(rest)
            }
        } else if arg == "-isystem" || arg == "-iquote" || arg == "-idirafter" {
            i += 1;
            args.get(i).map(String::as_str)
        } else {
            None
        };
        if let Some(dir) = value {
            let path = PathBuf::from(dir);
            dirs.push(if path.is_absolute() {
                path
            } else {
                directory.join(path)
            });
        }
        i += 1;
    }
    dirs
}

fn split_command(command: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in command.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn parses_file_and_include_dirs() {
        let json = r#"[
            {
                "directory": "/linux",
                "command": "gcc -I/linux/include -Iarch/x86/include -c fs/namei.c",
                "file": "fs/namei.c"
            }
        ]"#;
        let scope = CompileCommandsScope::parse(json, Path::new("/linux")).unwrap();
        assert!(scope
            .translation_units
            .contains(&PathBuf::from("/linux/fs/namei.c")));
        assert!(scope
            .include_dirs
            .contains(&PathBuf::from("/linux/include")));
        assert!(scope
            .include_dirs
            .contains(&PathBuf::from("/linux/arch/x86/include")));
        assert!(scope.should_skip_c_file(Path::new("/linux/drivers/unused.c")));
        assert!(!scope.should_skip_c_file(Path::new("/linux/fs/namei.c")));
        assert!(!scope.should_skip_c_file(Path::new("/linux/include/linux/fs.h")));
        assert!(!scope.should_skip_c_file(Path::new("/linux/fs/namei.h")));
        assert!(!scope.should_skip_c_file(Path::new("/linux/src/main.rs")));
    }

    #[test]
    fn arguments_form_is_accepted() {
        let json = r#"[
            {
                "directory": "/proj",
                "arguments": ["clang", "-isystem", "/proj/include", "-c", "src/a.c"],
                "file": "src/a.c"
            }
        ]"#;
        let scope = CompileCommandsScope::parse(json, Path::new("/proj")).unwrap();
        assert!(!scope.should_skip_c_file(Path::new("/proj/src/a.c")));
        assert!(!scope.should_skip_c_file(Path::new("/proj/include/a.h")));
        assert!(scope.should_skip_c_file(Path::new("/proj/src/b.c")));
    }

    #[test]
    fn discover_reads_repo_root_file() {
        let dir = tempdir().unwrap();
        let db = serde_json::json!([{
            "directory": dir.path(),
            "file": "main.c",
            "command": "gcc -c main.c",
        }]);
        fs::write(
            dir.path().join("compile_commands.json"),
            serde_json::to_vec(&db).unwrap(),
        )
        .unwrap();
        fs::write(dir.path().join("main.c"), "int main() { return 0; }").unwrap();
        let scope = CompileCommandsScope::discover(dir.path()).expect("database");
        assert!(!scope.should_skip_c_file(&dir.path().join("main.c")));
        assert!(scope.should_skip_c_file(&dir.path().join("other.c")));
    }

    #[test]
    fn discover_reads_build_subdir() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("build")).unwrap();
        let db = serde_json::json!([{
            "directory": dir.path(),
            "file": "src/app.c",
            "command": "gcc -c src/app.c",
        }]);
        fs::write(
            dir.path().join("build/compile_commands.json"),
            serde_json::to_vec(&db).unwrap(),
        )
        .unwrap();
        let scope = CompileCommandsScope::discover(dir.path()).expect("build db");
        assert!(!scope.should_skip_c_file(&dir.path().join("src/app.c")));
    }

    #[test]
    fn is_c_family_detects_extensions() {
        assert!(is_c_family(Path::new("foo.c")));
        assert!(is_c_family(Path::new("foo.H")));
        assert!(is_c_family(Path::new("foo.cpp")));
        assert!(!is_c_family(Path::new("foo.rs")));
    }
}
