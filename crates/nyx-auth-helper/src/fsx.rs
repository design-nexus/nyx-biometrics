//! Careful file handling for a root process writing into `/etc`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum FsError {
    #[error("{0} is a symbolic link")]
    Symlink(String),
    #[error("{0} isn't a regular file")]
    NotRegular(String),
    #[error("{0} isn't a directory")]
    NotDirectory(String),
    #[error("{0} is owned by someone else or writable by others")]
    Unsafe(String),
    #[error("{0} is too large")]
    TooLarge(String),
    #[error("{path}: {source}")]
    Io { path: String, source: io::Error },
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> FsError + '_ {
    move |source| FsError::Io { path: path.display().to_string(), source }
}

/// Owned by us, not writable by group or others.
fn check_owner(path: &Path, meta: &fs::Metadata) -> Result<(), FsError> {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid || meta.mode() & 0o022 != 0 {
        return Err(FsError::Unsafe(path.display().to_string()));
    }
    Ok(())
}

/// Create `dir` (mode 0755) if it's missing, refusing a link or a loosely owned directory.
pub fn ensure_dir(dir: &Path) -> Result<(), FsError> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => Err(FsError::Symlink(dir.display().to_string())),
        Ok(m) if !m.is_dir() => Err(FsError::NotDirectory(dir.display().to_string())),
        Ok(m) => check_owner(dir, &m),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).map_err(io_err(dir))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).map_err(io_err(dir))
        }
        Err(e) => Err(io_err(dir)(e)),
    }
}

/// Read a small file we own, or `None` when it doesn't exist.
pub fn read_owned(path: &Path, max: u64) -> Result<Option<String>, FsError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(path)(e)),
    };
    if meta.file_type().is_symlink() {
        return Err(FsError::Symlink(path.display().to_string()));
    }
    if !meta.is_file() {
        return Err(FsError::NotRegular(path.display().to_string()));
    }
    check_owner(path, &meta)?;
    if meta.len() > max {
        return Err(FsError::TooLarge(path.display().to_string()));
    }
    fs::read_to_string(path).map(Some).map_err(io_err(path))
}

/// Read a small file someone else wrote (Omarchy's authfile), refusing links.
pub fn read_foreign(path: &Path, max: u64) -> Result<Option<String>, FsError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(FsError::Symlink(path.display().to_string())),
        Ok(m) if !m.is_file() => Err(FsError::NotRegular(path.display().to_string())),
        Ok(m) if m.len() > max => Err(FsError::TooLarge(path.display().to_string())),
        Ok(_) => fs::read_to_string(path).map(Some).map_err(io_err(path)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(path)(e)),
    }
}

/// Replace `path` atomically: a new file beside it, synced, renamed over it, directory synced.
pub fn write_atomic(path: &Path, contents: &str, mode: u32) -> Result<(), FsError> {
    let dir = path.parent().ok_or_else(|| FsError::NotDirectory(path.display().to_string()))?;
    ensure_dir(dir)?;
    if let Ok(m) = fs::symlink_metadata(path) {
        if m.file_type().is_symlink() {
            return Err(FsError::Symlink(path.display().to_string()));
        }
        if !m.is_file() {
            return Err(FsError::NotRegular(path.display().to_string()));
        }
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{name}.nyx-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)
        .map_err(io_err(&tmp))?;
    let result = (|| {
        file.write_all(contents.as_bytes())?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(io_err(path))
}

/// Remove a file we own; missing is fine.
pub fn remove_owned(path: &Path) -> Result<(), FsError> {
    match read_owned(path, u64::MAX) {
        Ok(Some(_)) => fs::remove_file(path).map_err(io_err(path)),
        Ok(None) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("etc/nyx-biometrics/u2f_keys");
        write_atomic(&path, "one\n", 0o644).unwrap();
        write_atomic(&path, "two\n", 0o644).unwrap();
        assert_eq!(read_owned(&path, 1024).unwrap().as_deref(), Some("two\n"));
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap()).unwrap().collect();
        assert_eq!(leftovers.len(), 1);
    }

    #[test]
    fn refuses_links_and_loose_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, "x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(read_owned(&link, 10), Err(FsError::Symlink(_))));
        assert!(matches!(write_atomic(&link, "y", 0o644), Err(FsError::Symlink(_))));
        assert_eq!(fs::read_to_string(&target).unwrap(), "x");

        let loose = dir.path().join("loose");
        fs::write(&loose, "x").unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(read_owned(&loose, 10), Err(FsError::Unsafe(_))));

        let linked_dir = dir.path().join("linked-dir");
        std::os::unix::fs::symlink(dir.path(), &linked_dir).unwrap();
        assert!(matches!(write_atomic(&linked_dir.join("f"), "y", 0o644), Err(FsError::Symlink(_))));

        assert!(matches!(read_owned(&target, 0), Err(FsError::TooLarge(_))));
        assert_eq!(read_owned(&dir.path().join("missing"), 10).unwrap(), None);
    }
}
