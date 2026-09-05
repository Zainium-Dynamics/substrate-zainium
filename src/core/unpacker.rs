use crate::core::verifier::{self, ParsedZex};
use crate::error::{Result, ZexError};
use crate::utils::paths;
use ed25519_dalek::VerifyingKey;
use std::path::Path;

pub struct UnpackResult {
    pub destination: std::path::PathBuf,
    pub files_extracted: usize,
}

// Extract a parsed .zex package to dest_dir.

pub fn unpack(
    parsed: &ParsedZex,
    dest_dir: &Path,
    public_key: &VerifyingKey,
) -> Result<UnpackResult> {
    let sig_ok = verifier::verify_signature(parsed, public_key)?;
    if !sig_ok {
        return Err(ZexError::SignatureInvalid(
            "package signature mismatch".into(),
        ));
    }

    std::fs::create_dir_all(dest_dir)?;

    let mut count = 0usize;
    for (archive_path, bytes, mode, target) in &parsed.payload_files {
        let rel = archive_path
            .strip_prefix("payload/")
            .ok_or_else(|| {
                ZexError::InvalidFormat(format!(
                    "invalid payload path: {archive_path}"
                ))
            })?;

        let safe_path = paths::safe_join(dest_dir, rel)?;
        if let Some(parent) = safe_path.parent() {
            std::fs::create_dir_all(parent).map_err(ZexError::Io)?;
        }

        if let Some(link_target) = target {
            #[cfg(unix)]
            {
                let _ = std::fs::remove_file(&safe_path);
                std::os::unix::fs::symlink(link_target, &safe_path)
                    .map_err(ZexError::Io)?;
            }
            count += 1;
            continue;
        }

        std::fs::write(&safe_path, bytes).map_err(ZexError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Same data/config-file policy as packer.rs, applied again
            // here so it also repairs a .zex built before this existed --
            // *mode is whatever the archive says, not necessarily already
            // corrected.
            let mode = crate::core::mode_policy::normalize(rel, *mode);

            // chown MUST happen before chmod, not after: the kernel
            // unconditionally clears S_ISUID/S_ISGID on any chown() that
            // actually changes owner/group, regardless of caller
            // privilege -- this is a *different* rule from the
            // CAP_FSETID one that gates chmod/write, and root is not
            // exempt from it. Setting setuid first only ever appeared to
            // work when this ran unprivileged, because chown failed with
            // EPERM and never got the chance to wipe it back off. Real
            // elf setuid tools (elevate, sudo, ...) need both this and
            // the setuid bit baked in here, while this process still has
            // real privilege to chown to uid 0 -- the assembled image is
            // immutable after this point (Zainium's own core-OS-layer
            // guard refuses chown/chmod on it later, confirmed live:
            // "protected path: core OS layers cannot be modified (even
            // as root)"), so this is the only place it can ever happen.
            if mode & 0o6000 != 0 {
                let c_path = std::ffi::CString::new(safe_path.as_os_str().as_encoded_bytes())
                    .map_err(|e| ZexError::Other(format!("invalid path for chown: {e}")))?;
                // SAFETY: c_path is a valid NUL-terminated C string for
                // the lifetime of this call; chown's own failure (e.g.
                // EPERM when not running as root) is reported through
                // its return value, checked below, not treated as fatal
                // -- expected when unpacking unprivileged.
                let rc = unsafe { libc::chown(c_path.as_ptr(), 0, 0) };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    crate::ui::display::warn_kv(
                        "chown",
                        &format!("{rel:?} not root:root ({err}), setuid inert until fixed"),
                    );
                }
            }

            std::fs::set_permissions(&safe_path, std::fs::Permissions::from_mode(mode))
                .map_err(ZexError::Io)?;
        }
        count += 1;
    }

    Ok(UnpackResult {
        destination: dest_dir.to_path_buf(),
        files_extracted: count,
    })
}