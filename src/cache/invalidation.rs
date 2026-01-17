//! File hash tracking for cache invalidation
//!
//! Tracks file content hashes and modification times to detect changes
//! and trigger cache invalidation.
//!
//! Note: This module provides infrastructure for sophisticated file-level
//! cache invalidation. The current implementation uses a simpler approach
//! via `compute_repo_hash` in index.rs. This module will be wired in when
//! more granular invalidation is needed.

#![allow(dead_code)]

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Metadata for tracking file changes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    /// SHA-256 hash of file content
    pub content_hash: String,
    /// Last modification time
    pub mtime: SystemTime,
    /// File size in bytes
    pub size: u64,
}

impl FileMetadata {
    /// Create metadata by reading from the filesystem
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or metadata cannot be obtained.
    pub fn from_path(path: &Path) -> std::io::Result<Self> {
        let content = fs::read(path)?;
        let metadata = fs::metadata(path)?;

        Ok(Self {
            content_hash: compute_file_hash(&content),
            mtime: metadata.modified()?,
            size: metadata.len(),
        })
    }

    /// Create metadata from content and mtime (for cached content)
    #[must_use]
    pub fn from_content(content: &[u8], mtime: SystemTime, size: u64) -> Self {
        Self {
            content_hash: compute_file_hash(content),
            mtime,
            size,
        }
    }
}

/// Compute SHA-256 hash of content
fn compute_file_hash(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

/// Tracks file hashes for cache invalidation
///
/// This struct maintains a mapping of file paths to their content hashes
/// and modification times. It can detect when files have changed and
/// provide the list of changed files for cache invalidation.
pub struct FileHashTracker {
    /// Map of file path to metadata
    files: DashMap<PathBuf, FileMetadata>,
}

impl Default for FileHashTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FileHashTracker {
    /// Create a new file hash tracker
    #[must_use]
    pub fn new() -> Self {
        Self {
            files: DashMap::new(),
        }
    }

    /// Track a file by its path
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn track(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let path = path.as_ref().to_path_buf();
        let metadata = FileMetadata::from_path(&path)?;
        self.files.insert(path, metadata);
        Ok(())
    }

    /// Track a file with pre-computed metadata
    pub fn track_with_metadata(&self, path: impl AsRef<Path>, metadata: FileMetadata) {
        self.files.insert(path.as_ref().to_path_buf(), metadata);
    }

    /// Track a file from cached content (avoids re-reading from disk)
    pub fn track_from_content(
        &self,
        path: impl AsRef<Path>,
        content: &[u8],
        mtime: SystemTime,
        size: u64,
    ) {
        let metadata = FileMetadata::from_content(content, mtime, size);
        self.files.insert(path.as_ref().to_path_buf(), metadata);
    }

    /// Check if a file has changed since it was tracked
    ///
    /// Returns `true` if:
    /// - The file is not being tracked
    /// - The file's mtime has changed
    /// - The file's content hash has changed
    ///
    /// # Errors
    ///
    /// Returns an error if the file metadata cannot be read.
    pub fn has_changed(&self, path: impl AsRef<Path>) -> std::io::Result<bool> {
        let path = path.as_ref();

        match self.files.get(path) {
            None => Ok(true), // Not tracked = considered changed
            Some(stored) => {
                let current_metadata = fs::metadata(path)?;
                let current_mtime = current_metadata.modified()?;

                // Quick check: if mtime is the same, assume content is the same
                if current_mtime == stored.mtime && current_metadata.len() == stored.size {
                    return Ok(false);
                }

                // Mtime or size changed, need to check content hash
                let current_content = fs::read(path)?;
                let current_hash = compute_file_hash(&current_content);

                Ok(current_hash != stored.content_hash)
            }
        }
    }

    /// Check if a file has changed based on content comparison only
    ///
    /// This bypasses the mtime check and always compares content hashes.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn has_content_changed(&self, path: impl AsRef<Path>) -> std::io::Result<bool> {
        let path = path.as_ref();

        match self.files.get(path) {
            None => Ok(true),
            Some(stored) => {
                let current_content = fs::read(path)?;
                let current_hash = compute_file_hash(&current_content);
                Ok(current_hash != stored.content_hash)
            }
        }
    }

    /// Get all files that have changed since they were tracked
    ///
    /// Skips files that no longer exist or cannot be read.
    #[must_use]
    pub fn get_changed_files(&self) -> Vec<PathBuf> {
        self.files
            .iter()
            .filter_map(|entry| {
                let path = entry.key();
                match self.has_changed(path) {
                    Ok(true) => Some(path.clone()),
                    _ => None,
                }
            })
            .collect()
    }

    /// Update tracking for a file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn refresh(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        self.track(path)
    }

    /// Stop tracking a file
    pub fn untrack(&self, path: impl AsRef<Path>) {
        self.files.remove(path.as_ref());
    }

    /// Clear all tracked files
    pub fn clear(&self) {
        self.files.clear();
    }

    /// Get the number of tracked files
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Check if no files are being tracked
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Get the stored hash for a file
    #[must_use]
    pub fn get_hash(&self, path: impl AsRef<Path>) -> Option<String> {
        self.files
            .get(path.as_ref())
            .map(|entry| entry.content_hash.clone())
    }

    /// Check if a path is being tracked
    #[must_use]
    pub fn is_tracked(&self, path: impl AsRef<Path>) -> bool {
        self.files.contains_key(path.as_ref())
    }

    /// Get all tracked paths
    #[must_use]
    pub fn tracked_paths(&self) -> Vec<PathBuf> {
        self.files.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Get paths that match a predicate
    #[must_use]
    pub fn paths_where<F>(&self, predicate: F) -> Vec<PathBuf>
    where
        F: Fn(&Path) -> bool,
    {
        self.files
            .iter()
            .filter(|entry| predicate(entry.key()))
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get all tracked paths for a repository
    #[must_use]
    pub fn paths_for_repo(&self, repo_path: &Path) -> Vec<PathBuf> {
        self.paths_where(|p| p.starts_with(repo_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_file_metadata_from_path() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(temp_dir.path(), "test.txt", "hello world");

        let metadata = FileMetadata::from_path(&file_path).unwrap();

        assert_eq!(metadata.size, 11);
        assert!(!metadata.content_hash.is_empty());
        assert_eq!(metadata.content_hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_track_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(temp_dir.path(), "test.txt", "content");

        let tracker = FileHashTracker::new();
        tracker.track(&file_path).unwrap();

        assert!(tracker.is_tracked(&file_path));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn test_has_changed_unchanged_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(temp_dir.path(), "test.txt", "content");

        let tracker = FileHashTracker::new();
        tracker.track(&file_path).unwrap();

        assert!(!tracker.has_changed(&file_path).unwrap());
    }

    #[test]
    fn test_has_changed_modified_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(temp_dir.path(), "test.txt", "original");

        let tracker = FileHashTracker::new();
        tracker.track(&file_path).unwrap();

        // Modify the file
        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"modified").unwrap();

        assert!(tracker.has_changed(&file_path).unwrap());
    }

    #[test]
    fn test_has_changed_untracked_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(temp_dir.path(), "test.txt", "content");

        let tracker = FileHashTracker::new();

        // Untracked files are considered changed
        assert!(tracker.has_changed(&file_path).unwrap());
    }

    #[test]
    fn test_get_changed_files() {
        let temp_dir = TempDir::new().unwrap();
        let file1 = create_test_file(temp_dir.path(), "file1.txt", "content1");
        let file2 = create_test_file(temp_dir.path(), "file2.txt", "content2");

        let tracker = FileHashTracker::new();
        tracker.track(&file1).unwrap();
        tracker.track(&file2).unwrap();

        // No changes yet
        assert!(tracker.get_changed_files().is_empty());

        // Modify file1
        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut file = File::create(&file1).unwrap();
        file.write_all(b"modified").unwrap();

        let changed = tracker.get_changed_files();
        assert_eq!(changed.len(), 1);
        assert!(changed.contains(&file1));
    }

    #[test]
    fn test_refresh() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(temp_dir.path(), "test.txt", "original");

        let tracker = FileHashTracker::new();
        tracker.track(&file_path).unwrap();

        // Modify file
        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"modified").unwrap();

        assert!(tracker.has_changed(&file_path).unwrap());

        // Refresh tracking
        tracker.refresh(&file_path).unwrap();

        assert!(!tracker.has_changed(&file_path).unwrap());
    }

    #[test]
    fn test_untrack() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(temp_dir.path(), "test.txt", "content");

        let tracker = FileHashTracker::new();
        tracker.track(&file_path).unwrap();

        assert!(tracker.is_tracked(&file_path));

        tracker.untrack(&file_path);

        assert!(!tracker.is_tracked(&file_path));
    }

    #[test]
    fn test_get_hash() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(temp_dir.path(), "test.txt", "content");

        let tracker = FileHashTracker::new();
        tracker.track(&file_path).unwrap();

        let hash = tracker.get_hash(&file_path);
        assert!(hash.is_some());
        assert_eq!(hash.unwrap().len(), 64);
    }

    #[test]
    fn test_paths_for_repo() {
        let temp_dir = TempDir::new().unwrap();
        let repo1 = temp_dir.path().join("repo1");
        let repo2 = temp_dir.path().join("repo2");
        std::fs::create_dir_all(&repo1).unwrap();
        std::fs::create_dir_all(&repo2).unwrap();

        let file1 = create_test_file(&repo1, "file1.txt", "content1");
        let file2 = create_test_file(&repo1, "file2.txt", "content2");
        let file3 = create_test_file(&repo2, "file3.txt", "content3");

        let tracker = FileHashTracker::new();
        tracker.track(&file1).unwrap();
        tracker.track(&file2).unwrap();
        tracker.track(&file3).unwrap();

        let repo1_files = tracker.paths_for_repo(&repo1);
        assert_eq!(repo1_files.len(), 2);
        assert!(repo1_files.contains(&file1));
        assert!(repo1_files.contains(&file2));

        let repo2_files = tracker.paths_for_repo(&repo2);
        assert_eq!(repo2_files.len(), 1);
        assert!(repo2_files.contains(&file3));
    }

    #[test]
    fn test_clear() {
        let temp_dir = TempDir::new().unwrap();
        let file1 = create_test_file(temp_dir.path(), "file1.txt", "content1");
        let file2 = create_test_file(temp_dir.path(), "file2.txt", "content2");

        let tracker = FileHashTracker::new();
        tracker.track(&file1).unwrap();
        tracker.track(&file2).unwrap();

        assert_eq!(tracker.len(), 2);

        tracker.clear();

        assert!(tracker.is_empty());
    }

    #[test]
    fn test_track_from_content() {
        let tracker = FileHashTracker::new();
        let path = PathBuf::from("/virtual/path.txt");
        let content = b"test content";

        tracker.track_from_content(&path, content, SystemTime::now(), content.len() as u64);

        assert!(tracker.is_tracked(&path));
        let hash = tracker.get_hash(&path).unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_default() {
        let tracker = FileHashTracker::default();
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_tracked_paths() {
        let temp_dir = TempDir::new().unwrap();
        let file1 = create_test_file(temp_dir.path(), "file1.txt", "content1");
        let file2 = create_test_file(temp_dir.path(), "file2.txt", "content2");

        let tracker = FileHashTracker::new();
        tracker.track(&file1).unwrap();
        tracker.track(&file2).unwrap();

        let paths = tracker.tracked_paths();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&file1));
        assert!(paths.contains(&file2));
    }
}
