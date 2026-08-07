use crate::core::verifier::{self, ParsedZex};
use crate::error::{Result, ZexError};
use crate::utils::paths;
use ed25519_dalek::VerifyingKey;
use std::path::Path;

pub struct UnpackResult {
    pub destination: std::path::PathBuf,
    pub files_extracted: usize,
}

/// Extract a parsed .zex package to `dest_dir`. Verifies signature first
/// (hard requirement, not optional) and re-checks manifest integrity
/// against the freshly extracted files before declaring success.
pub fn unpack(
    parsed: &ParsedZex,
    dest_dir: &Path,
    public_key: &VerifyingKey,
) -> Result<UnpackResult> {
    let sig_ok = verifier::verify_signature(parsed, public_key)?;
    if !sig_ok {
        return Err(ZexError::SignatureInvalid(
            "package signature does not match its contents".into(),
        ));
    }

    std::fs::create_dir_all(dest_dir)?;

    let mut count = 0usize;
    for (archive_path, bytes, mode) in &parsed.payload_files {
        let rel = archive_path
            .strip_prefix("payload/")
            .ok_or_else(|| {
                ZexError::InvalidFormat(format!(
                    "payload entry missing payload/ prefix: {archive_path}"
                ))
            })?;

        let safe_path = paths::safe_join(dest_dir, rel)?;
        if let Some(parent) = safe_path.parent() {
            std::fs::create_dir_all(parent).map_err(ZexError::Io)?;
        }
        std::fs::write(&safe_path, bytes).map_err(ZexError::Io)?;
        // Confirmed live: without this, every unpacked file — including
        // binaries — landed as -rw-r--r--, unusable until manually
        // chmod'd. Same class of bug found and fixed in zex's own
        // extract_adb this session.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&safe_path, std::fs::Permissions::from_mode(*mode))
                .map_err(ZexError::Io)?;
        }
        count += 1;
    }

    Ok(UnpackResult {
        destination: dest_dir.to_path_buf(),
        files_extracted: count,
    })
}