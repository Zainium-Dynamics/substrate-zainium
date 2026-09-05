// Shared pack/unpack mode-normalization policy.
//
// substrate's packer is mode-preserving by design: whatever permission bits
// a file actually has on the build machine at pack time get recorded
// verbatim and re-applied verbatim at unpack time. That's correct -- even
// necessary -- for real executables (elevate, login, ...) that genuinely
// need +x/setuid. It's wrong for data/config files: a stray build-tool
// quirk, a `chmod -R 755`, or just how `git checkout` left a file can hand
// a .service/.toml/.conf an executable bit it was never supposed to have,
// and the packer would carry that bit through the whole pipeline with no
// warning -- this is why the same bug kept resurfacing across unrelated
// packages (systemd, dbus, greetd) as manual `chmod 644` calls in each
// recipe's own package().
//
// Fix: force known data/config extensions to 0o644 unconditionally,
// regardless of what the source file's mode says -- unless the file lives
// under a real executable directory (bin/, sbin/, libexec/), where the
// extension check doesn't apply at all. Applied identically on both sides
// (pack in packer.rs, unpack in unpacker.rs) so it also repairs any
// already-built .zex carrying a bad mode from before this existed.

const DATA_EXTENSIONS: &[&str] = &[
    "service", "socket", "target", "timer", "mount", "path",
    "toml", "conf", "md", "txt", "json", "yaml", "yml",
];

const EXEC_DIRS: &[&str] = &["bin", "sbin", "libexec"];

fn in_exec_dir(rel: &str) -> bool {
    rel.split('/').any(|c| EXEC_DIRS.contains(&c))
}

fn is_forced_data_file(rel: &str) -> bool {
    match rel.rsplit_once('.') {
        Some((_, ext)) => DATA_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
        None => false,
    }
}

/// Apply the data/config-file mode policy to one payload-relative path.
/// `mode` is the permission bits (already masked to 0o7777) as read from
/// disk (pack) or stored in the archive (unpack).
pub fn normalize(rel: &str, mode: u32) -> u32 {
    if is_forced_data_file(rel) && !in_exec_dir(rel) {
        0o644
    } else {
        mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forces_config_files_to_0644() {
        assert_eq!(normalize("payload/etc/dbus-1/system.conf", 0o755), 0o644);
        assert_eq!(normalize("payload/lib/systemd/system/dbus.service", 0o755), 0o644);
        assert_eq!(normalize("payload/etc/greetd/config.toml", 0o750), 0o644);
    }

    #[test]
    fn leaves_real_executables_alone() {
        assert_eq!(normalize("payload/bin/elevate", 0o4755), 0o4755);
        assert_eq!(normalize("payload/sbin/vielev", 0o755), 0o755);
        assert_eq!(normalize("payload/lib/libexec/helper.conf", 0o755), 0o755);
    }

    #[test]
    fn leaves_non_data_files_alone() {
        assert_eq!(normalize("payload/lib/libpam.so.0", 0o755), 0o755);
        assert_eq!(normalize("payload/lib/security/pam_unix.so", 0o755), 0o755);
    }
}
