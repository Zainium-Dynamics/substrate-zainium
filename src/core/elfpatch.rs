// ELF dynamic linker and RPATH patching.


use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use oxipatch::elf::ElfFile;

use crate::error::{Result, ZexError};

const ZEX_INTERP: &str = "/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1";

pub const SYSHUB_LIB_TARGET: &str = "/overlayer/syshub/lib";

pub const USERLAND_LIB_TARGET: &str = "/overlayer/zexlib/union/lib";

fn is_elf(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F']
}

fn is_replaceable_lib_entry(entry: &str) -> bool {
    entry == "/usr/lib" || entry == "/lib" || entry == "/usr/lib64" || entry == "/lib64"
        || entry.starts_with("/usr/lib/") || entry.starts_with("/lib/")
        || entry.starts_with("/usr/lib64/") || entry.starts_with("/lib64/")
        || entry.starts_with("$ORIGIN")
        || entry == SYSHUB_LIB_TARGET || entry.starts_with(&format!("{SYSHUB_LIB_TARGET}/"))
        || entry == USERLAND_LIB_TARGET || entry.starts_with(&format!("{USERLAND_LIB_TARGET}/"))
}

fn resolve_install_dest(payload_rel: &Path, install_map: &HashMap<String, String>) -> Option<PathBuf> {
    let mut components = payload_rel.components();
    let top = components.next()?.as_os_str().to_str()?;
    let dest_root = install_map.get(top)?;
    let rest: PathBuf = components.collect();
    Some(Path::new(dest_root).join(rest))
}

fn origin_relative(from_dir: &Path, to_dir: &Path) -> String {
    let from_comps: Vec<_> = from_dir.components().collect();
    let to_comps: Vec<_> = to_dir.components().collect();

    let common = from_comps
        .iter()
        .zip(to_comps.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let ups = from_comps.len() - common;
    let downs: PathBuf = to_comps[common..].iter().collect();

    let mut rpath = String::from("$ORIGIN");
    for _ in 0..ups {
        rpath.push_str("/..");
    }
    let downs_str = downs.to_string_lossy();
    if !downs_str.is_empty() {
        rpath.push('/');
        rpath.push_str(&downs_str);
    }
    rpath
}

fn rebuild_rpath(existing: &str, lib_rpath: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for entry in existing.split(':').filter(|e| !e.is_empty()) {
        let mapped = if is_replaceable_lib_entry(entry) { lib_rpath } else { entry };
        if !out.iter().any(|e| e == mapped) {
            out.push(mapped.to_string());
        }
    }
    if !out.iter().any(|e| e == lib_rpath) {
        out.push(lib_rpath.to_string());
    }
    out.join(":")
}

fn patch_one(path: &Path, lib_rpath: &str) -> std::result::Result<(), oxipatch::Error> {
    let mut f = ElfFile::open(path)?;

    let has_interp = f.interpreter()?.is_some();
    let has_needed = !f.needed_libs()?.is_empty();

    if !has_interp && !has_needed {
        return Ok(());
    }

    if has_interp {
        f.set_interpreter(ZEX_INTERP)?;
    }

    let existing = f.rpath()?.unwrap_or_default();
    let new_rpath = rebuild_rpath(&existing, lib_rpath);
    f.set_rpath(&new_rpath, true)?;

    f.commit()?;
    f.write_in_place()?;
    Ok(())
}

// Patch ELF binaries under payload_dir with proper interpreter and $ORIGIN-relative RPATH.

pub fn patch_payload_dir(
    payload_dir: &Path,
    install_map: &HashMap<String, String>,
    lib_target: &str,
) -> Result<()> {
    let lib_target_path = Path::new(lib_target);

    for entry in walkdir::WalkDir::new(payload_dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if !is_elf(path) {
            continue;
        }

        let payload_rel = path.strip_prefix(payload_dir).unwrap_or(path);
        let lib_rpath = match resolve_install_dest(payload_rel, install_map) {
            Some(dest) => {
                let from_dir = dest.parent().unwrap_or(&dest).to_path_buf();
                origin_relative(&from_dir, lib_target_path)
            }
            None => lib_target.to_string(),
        };

        patch_one(path, &lib_rpath).map_err(|e| {
            ZexError::Other(format!(
                "failed to patch ELF interpreter/RPATH for '{}': {e}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

