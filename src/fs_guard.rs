//! Pin directory names while elevated filesystem work uses paths beneath them.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};

/// Without FILE_SHARE_DELETE, these directories cannot be renamed or replaced until
/// the handles close. Open each component without following links, from the root down.
pub fn pin_directory(path: &Path) -> io::Result<Vec<File>> {
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "an absolute directory without parent traversal is required"));
    }
    let mut pinned = Vec::new();
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        pinned.push(open_directory(ancestor)?);
    }
    Ok(pinned)
}

pub fn open_directory(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "linked directories are not cleanup targets"));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_ancestors_cannot_be_replaced() {
        let base = std::env::temp_dir().join(format!("vantix-pin-{}", std::process::id()));
        let child = base.join("parent").join("child");
        std::fs::create_dir_all(&child).unwrap();
        let handles = pin_directory(&child).unwrap();
        assert!(std::fs::rename(base.join("parent"), base.join("moved")).is_err());
        assert!(std::fs::rename(&child, base.join("other")).is_err());
        drop(handles);
        std::fs::rename(base.join("parent"), base.join("moved")).unwrap();
        std::fs::remove_dir_all(base).unwrap();
        assert!(pin_directory(Path::new("relative")).is_err());
    }
}
