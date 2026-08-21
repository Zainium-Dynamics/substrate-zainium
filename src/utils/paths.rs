use crate::error::{Result, ZexError};
use std::path::{Component, Path, PathBuf};

// Normalize a path for archive storage.
pub fn normalize_archive_path(raw: &str) -> Result<String> {
    let p = Path::new(raw);
    let mut parts = Vec::new();

    for component in p.components() {
        match component {
            Component::Normal(s) => {
                parts.push(s.to_string_lossy().to_string());
            }
            Component::ParentDir => {
                return Err(ZexError::Other(format!(
                    "path traversal rejected: '{}'",
                    raw
                )));
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {
                // skip leading '.', '/', drive prefixes
            }
        }
    }

    if parts.is_empty() {
        return Err(ZexError::Other(format!("empty/invalid path: '{}'", raw)));
    }

    Ok(parts.join("/"))
}

// Check if top-level directory matches usr.
pub fn references_usr_merge(normalized_path: &str) -> bool {
    normalized_path == "usr"
        || normalized_path.starts_with("usr/")
}

// Safe join for extraction root.

pub fn safe_join(root: &Path, archive_path: &str) -> Result<PathBuf> {
    let normalized = normalize_archive_path(archive_path)?;
    Ok(root.join(normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_usr_paths() {
        assert!(references_usr_merge("usr/bin/foo"));
        assert!(references_usr_merge("usr"));
        assert!(!references_usr_merge("bin/foo"));
        assert!(!references_usr_merge("usrlocal/foo")); // not a real /usr path
    }

    #[test]
    fn rejects_traversal() {
        assert!(normalize_archive_path("../../etc/passwd").is_err());
    }

    #[test]
    fn normalizes_leading_slash_and_dot() {
        assert_eq!(normalize_archive_path("/usr/bin/foo").unwrap(), "usr/bin/foo");
        assert_eq!(normalize_archive_path("./bin/foo").unwrap(), "bin/foo");
    }
}
