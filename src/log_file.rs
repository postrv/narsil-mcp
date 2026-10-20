//! The `--log-file` writer for tracing; rotates the file at startup and above a size limit.

use parking_lot::Mutex;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub struct LogFile {
    path: PathBuf,
    max_size: usize,
    keep: usize,
    current: Mutex<CurrentFile>,
}

struct CurrentFile {
    file: File,
    written: usize,
}

impl LogFile {
    /// Open `path` for append; a non-empty file from an earlier run is rotated first.
    pub fn open(path: &Path, max_size: usize, keep: usize) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let earlier_run_logged = std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0);
        if earlier_run_logged {
            if let Err(e) = rotate(path, keep) {
                // The logger does not exist yet.
                eprintln!(
                    "narsil-xref: cannot rotate {}: {}; appending to it",
                    path.display(),
                    e
                );
            }
        }
        let file = open_for_append(path)?;
        // Not 0 when the rotation above failed.
        let written = file.metadata()?.len() as usize;
        Ok(Self {
            path: path.to_path_buf(),
            max_size,
            keep,
            current: Mutex::new(CurrentFile { file, written }),
        })
    }
}

fn open_for_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// `path` with `.<generation>` appended: dev.log -> dev.log.1.
fn rotated_path(path: &Path, generation: usize) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(format!(".{}", generation));
    PathBuf::from(name)
}

/// Shift path.1 .. path.(keep - 1) up by one, then rename `path` to path.1.
/// Renaming onto path.<keep> replaces the oldest file.
fn rotate(path: &Path, keep: usize) -> io::Result<()> {
    if keep == 0 {
        return std::fs::remove_file(path);
    }
    for generation in (1..keep).rev() {
        match std::fs::rename(
            rotated_path(path, generation),
            rotated_path(path, generation + 1),
        ) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    std::fs::rename(path, rotated_path(path, 1))
}

impl Write for &LogFile {
    /// tracing writes one whole event per call, so a line never spans two files.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut current = self.current.lock();
        let crosses_limit = current.written > 0 && current.written + buf.len() > self.max_size;
        if crosses_limit {
            match rotate(&self.path, self.keep).and_then(|()| open_for_append(&self.path)) {
                Ok(file) => current.file = file,
                // Logging here would recurse into this writer.
                Err(e) => eprintln!(
                    "narsil-xref: cannot rotate {}: {}; still writing the old file",
                    self.path.display(),
                    e
                ),
            }
            // Also after a failure: retry after another max_size, not on every line.
            current.written = 0;
        }
        let count = current.file.write(buf)?;
        current.written += count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.current.lock().file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    fn write_event(log: &LogFile, event: &str) {
        let mut writer = log;
        writer.write_all(event.as_bytes()).unwrap();
    }

    #[test]
    fn open_rotates_a_non_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.log");
        std::fs::write(&path, "earlier run\n").unwrap();

        let log = LogFile::open(&path, 1 << 20, 5).unwrap();
        write_event(&log, "this run\n");

        assert_eq!(read(&rotated_path(&path, 1)), "earlier run\n");
        assert_eq!(read(&path), "this run\n");
    }

    #[test]
    fn open_keeps_an_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.log");
        std::fs::write(&path, "").unwrap();

        LogFile::open(&path, 1 << 20, 5).unwrap();

        assert!(!rotated_path(&path, 1).exists());
    }

    #[test]
    fn keep_two_keeps_two_old_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.log");
        let log = LogFile::open(&path, 10, 2).unwrap();

        // 8 bytes each: every event after the first crosses the 10 byte limit.
        for event in ["event-1\n", "event-2\n", "event-3\n", "event-4\n"] {
            write_event(&log, event);
        }

        assert_eq!(read(&path), "event-4\n");
        assert_eq!(read(&rotated_path(&path, 1)), "event-3\n");
        assert_eq!(read(&rotated_path(&path, 2)), "event-2\n");
        assert!(!rotated_path(&path, 3).exists());
    }

    #[test]
    fn a_write_crossing_the_limit_goes_whole_into_the_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.log");
        let log = LogFile::open(&path, 10, 5).unwrap();

        write_event(&log, "12345678\n");
        write_event(&log, "abcdef\n");

        assert_eq!(read(&rotated_path(&path, 1)), "12345678\n");
        assert_eq!(read(&path), "abcdef\n");
    }

    #[test]
    fn keep_zero_deletes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.log");
        std::fs::write(&path, "earlier run\n").unwrap();

        LogFile::open(&path, 1 << 20, 0).unwrap();

        assert_eq!(read(&path), "");
        assert!(!rotated_path(&path, 1).exists());
    }
}
