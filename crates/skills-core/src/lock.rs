use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use fs2::FileExt;

use crate::{CoreError, Result};

const LOCK_FILENAME: &str = ".skillsissue.lock";

/// Process-wide advisory lock used to serialize repository CSV transactions.
///
/// The lock is released automatically on drop. All cooperating writers must use
/// the same workspace root for the advisory guarantee to hold.
#[derive(Debug)]
pub struct WorkspaceLock {
    file: File,
    path: PathBuf,
}

impl WorkspaceLock {
    /// Wait until an exclusive workspace lock can be acquired.
    pub fn acquire(workspace_root: impl AsRef<Path>) -> Result<Self> {
        let (file, path) = open_lock_file(workspace_root.as_ref())?;
        file.lock_exclusive()
            .map_err(|error| CoreError::io(&path, error))?;
        Ok(Self { file, path })
    }

    /// Attempt to acquire the lock without waiting.
    pub fn try_acquire(workspace_root: impl AsRef<Path>) -> Result<Option<Self>> {
        let (file, path) = open_lock_file(workspace_root.as_ref())?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Some(Self { file, path })),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(CoreError::io(path, error)),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for WorkspaceLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn open_lock_file(workspace_root: &Path) -> Result<(File, PathBuf)> {
    fs::create_dir_all(workspace_root).map_err(|error| CoreError::io(workspace_root, error))?;
    let path = workspace_root.join(LOCK_FILENAME);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|error| CoreError::io(&path, error))?;
    Ok((file, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_excludes_another_file_description_and_releases_on_drop() {
        let directory = tempfile::tempdir().unwrap();
        let first = WorkspaceLock::try_acquire(directory.path())
            .unwrap()
            .expect("first lock");
        assert!(
            WorkspaceLock::try_acquire(directory.path())
                .unwrap()
                .is_none()
        );
        assert_eq!(first.path(), directory.path().join(LOCK_FILENAME));
        drop(first);
        assert!(
            WorkspaceLock::try_acquire(directory.path())
                .unwrap()
                .is_some()
        );
    }
}
