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
            std::fs::set_permissions(&safe_path, std::fs::Permissions::from_mode(*mode))
                .map_err(ZexError::Io)?;

            // setuid/setgid (04000/02000) is meaningless -- actively
            // refused at runtime by Zainium's own immutable-core guard,
            // confirmed live ("protected path: core OS layers cannot be
            // modified (even as root)") -- unless the file is *also*
            // root:root-owned. Real elf setuid tools (elevate, sudo, ...)
            // need this baked in at unpack time, here, while this
            // process still has real privilege to chown to uid 0 -- the
            // assembled image is immutable after this point, so this is
            // the only place it can ever happen. Silently skipped (not
            // an error) when unpack runs unprivileged, e.g. local/dev
            // testing -- real image assembly runs as root.
            if *mode & 0o6000 != 0 {
                let c_path = std::ffi::CString::new(safe_path.as_os_str().as_encoded_bytes())
                    .map_err(|e| ZexError::Other(format!("invalid path for chown: {e}")))?;
                // SAFETY: c_path is a valid NUL-terminated C string for
                // the lifetime of this call; chown's own failure (e.g.
                // EPERM when not running as root) is reported through
                // its return value, which is checked below, not treated
                // as fatal -- it's expected when unpacking unprivileged.
                let rc = unsafe { libc::chown(c_path.as_ptr(), 0, 0) };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    eprintln!(
                        "warning: could not chown {} to root:root ({err}) -- setuid/setgid bit is inert until this is fixed (run unpack as root, or apply chown at final image assembly)",
                        safe_path.display()
                    );
                }
            }
        }
        count += 1;
    }

    Ok(UnpackResult {
        destination: dest_dir.to_path_buf(),
        files_extracted: count,
    })
}