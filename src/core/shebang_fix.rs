// Shebang interpreter path rewriting.
//
// The kernel resolves a script's #! line literally, with no fallback --
// unlike an ELF's PT_INTERP (patched by elfpatch.rs), there's no dynamic
// linker doing path resolution here. Zainium has no /bin, /usr/bin, etc.
// at all (everything lives under /overlayer/...), so any shipped script
// with a shebang like #!/bin/sh or #!/usr/bin/env perl fails to exec at
// all on a real system with ENOENT -- silently, since nothing at build
// or scan time actually executes the script. root_guard's layout scanner
// only rejects `/usr` references in file content; it doesn't touch `/bin`
// and doesn't rewrite anything, so this class of bug slips straight past
// it and only surfaces the first time someone actually runs the script.
//
// Same reasoning as the ELF interpreter: /overlayer/syshub is the one
// runtime-visible merged path every binary or script needs to find its
// interpreter at, regardless of which physical layer (syshub or
// zexlib/union) the package itself installs to.

use std::io::{Read, Write};
use std::path::Path;

use crate::error::Result;

pub const SYSHUB_BIN_TARGET: &str = "/overlayer/syshub/bin";

fn is_elf(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F']
}

// Rewrite one file's shebang line in place if it needs it. Returns
// whether a rewrite happened (for reporting).
fn fix_one(path: &Path) -> Result<bool> {
    let bytes = std::fs::read(path)?;
    if !bytes.starts_with(b"#!") {
        return Ok(false);
    }

    let nl = bytes.iter().position(|&b| b == b'\n').unwrap_or(bytes.len());
    let first_line = match std::str::from_utf8(&bytes[..nl]) {
        Ok(s) => s,
        Err(_) => return Ok(false), // not a text shebang we can parse
    };

    let rest_of_line = &first_line[2..]; // strip "#!"
    let trimmed = rest_of_line.trim_start();
    let leading_ws_len = rest_of_line.len() - trimmed.len();

    let (interp, tail) = match trimmed.find(char::is_whitespace) {
        Some(i) => (&trimmed[..i], &trimmed[i..]),
        None => (trimmed, ""),
    };

    if !interp.starts_with('/') || interp.starts_with("/overlayer/") {
        return Ok(false); // relative, or already Zainium-correct
    }

    let basename = interp.rsplit('/').next().unwrap_or(interp);
    if basename.is_empty() {
        return Ok(false);
    }

    let new_line = format!(
        "#!{}{}{}{}",
        &rest_of_line[..leading_ws_len],
        SYSHUB_BIN_TARGET,
        format_args!("/{basename}"),
        tail
    );

    let mut new_bytes = Vec::with_capacity(bytes.len());
    new_bytes.extend_from_slice(new_line.as_bytes());
    new_bytes.extend_from_slice(&bytes[nl..]);

    let mut f = std::fs::File::create(path)?;
    f.write_all(&new_bytes)?;
    Ok(true)
}

// Walk payload_dir, rewriting any non-ELF file whose shebang points at a
// non-Zainium absolute path. Returns the number of files rewritten.
pub fn patch_payload_dir(payload_dir: &Path) -> Result<usize> {
    let mut fixed = 0usize;

    for entry in walkdir::WalkDir::new(payload_dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if is_elf(path) {
            continue;
        }
        if fix_one(path)? {
            fixed += 1;
        }
    }

    Ok(fixed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "substrate-shebang-test-{tag}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> &Path { &self.0 }
    }
    impl Drop for TempDir {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    fn write_exec(dir: &Path, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[test]
    fn rewrites_bin_sh() {
        let dir = TempDir::new("bin-sh");
        let f = write_exec(dir.path(), "script.sh", "#!/bin/sh\necho hi\n");
        assert!(fix_one(&f).unwrap());
        let out = std::fs::read_to_string(&f).unwrap();
        assert_eq!(out, "#!/overlayer/syshub/bin/sh\necho hi\n");
    }

    #[test]
    fn rewrites_usr_bin_env_with_arg() {
        let dir = TempDir::new("env-perl");
        let f = write_exec(dir.path(), "script.pl", "#!/usr/bin/env perl\nprint 1;\n");
        assert!(fix_one(&f).unwrap());
        let out = std::fs::read_to_string(&f).unwrap();
        assert_eq!(out, "#!/overlayer/syshub/bin/env perl\nprint 1;\n");
    }

    #[test]
    fn leaves_already_correct_alone() {
        let dir = TempDir::new("already-ok");
        let f = write_exec(dir.path(), "script.sh", "#!/overlayer/syshub/bin/sh\necho hi\n");
        assert!(!fix_one(&f).unwrap());
    }

    #[test]
    fn leaves_non_shebang_alone() {
        let dir = TempDir::new("plain-text");
        let f = write_exec(dir.path(), "plain.txt", "just text\n");
        assert!(!fix_one(&f).unwrap());
    }
}
