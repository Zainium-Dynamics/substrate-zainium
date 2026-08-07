//! elfpatch.rs — Rewrites ELF `PT_INTERP`/`RPATH` on payload binaries
//! before packing, so a `.zex` never ships a binary carrying a leaked
//! build-machine interpreter/library path.
//!
//! Ported from `zex`'s own `src/cmd/install/elfpatch.rs` (same crate, same
//! technique, same hard-won correctness constraints — see that file's doc
//! comments for the full reasoning, including the static-PIE corruption
//! case this module also guards against). The difference in scope: zex's
//! copy patches *installed* T2/T3/T4 (Alpine/Void/Chimera) packages at
//! install time; this one patches a T1 `.zex` package's own payload at
//! *pack* time, since a Tier-1 package should never need this fixed up
//! later — it should already be correct the moment it's built.
//!
//! RPATH is written `$ORIGIN`-relative, not as a fixed absolute path.
//! Confirmed live this needed fixing: an earlier version used one
//! constant absolute RPATH for every file regardless of where that file
//! ends up installed, which is wrong the moment a package has files at
//! different depths (a `bin/foo` executable and a
//! `lib/gcc/x86_64.../16/cc1plus` binary need a *different* number of
//! `..` hops to reach the same `lib/` directory). `$ORIGIN`-relative also
//! means the package keeps working if the install root ever moves.
//!
//! Must run before the payload is hashed (`packer.rs` Step 5/6) — patching
//! after hashing would mean the embedded blake3 no longer matches what a
//! later re-verify computes from the (by-then-patched) bytes on disk.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use oxipatch::elf::ElfFile;

use crate::error::{Result, ZexError};

/// Canonical musl dynamic linker for Zainium OS — same target zex's own
/// install-time elfpatch.rs uses, confirmed against a real syshub-
/// toolchain-built binary.
const ZEX_INTERP: &str = "/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1";

/// Where a syshub (core OS) package's own shared libraries live —
/// confirmed against a real syshub-toolchain-built binary
/// (`readelf -d .../syshub/bin/curl` → `RPATH: [/overlayer/syshub/lib]`).
pub const SYSHUB_LIB_TARGET: &str = "/overlayer/syshub/lib";

/// Where zex-installed userland packages' shared libraries live.
pub const USERLAND_LIB_TARGET: &str = "/overlayer/zexlib/union/lib";

fn is_elf(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F']
}

/// True for anything a fresh patch should replace: real host FHS lib
/// dirs, *and* anything left over from a previous elfpatch run on this
/// same file (a stale absolute Zainium path, or a stale `$ORIGIN`-
/// relative one — the exact depth may be wrong if the file's install
/// destination ever changes). Confirmed live this second half was
/// missing: re-running `pack` against an already-patched payload
/// directory (e.g. a second local test run without resetting the source
/// tree) appended a second RPATH entry instead of replacing the first,
/// because the old absolute `/overlayer/zexlib/union/lib` value didn't
/// match any of the plain-FHS patterns below and was kept as "some other,
/// unrelated entry."
fn is_replaceable_lib_entry(entry: &str) -> bool {
    entry == "/usr/lib" || entry == "/lib" || entry == "/usr/lib64" || entry == "/lib64"
        || entry.starts_with("/usr/lib/") || entry.starts_with("/lib/")
        || entry.starts_with("/usr/lib64/") || entry.starts_with("/lib64/")
        || entry.starts_with("$ORIGIN")
        || entry == SYSHUB_LIB_TARGET || entry.starts_with(&format!("{SYSHUB_LIB_TARGET}/"))
        || entry == USERLAND_LIB_TARGET || entry.starts_with(&format!("{USERLAND_LIB_TARGET}/"))
}

/// Resolve a payload-relative path (e.g. `bin/xz` or
/// `lib/gcc/x86_64-zainium-linux-musl/16/cc1plus`) to its final absolute
/// installed destination, using the manifest's `[install]` map (payload
/// top-level subdir name -> absolute destination). Returns `None` if the
/// file's top-level subdir isn't in the map at all (shouldn't happen for
/// anything the real installer would ever place — such a file wouldn't
/// get installed either).
fn resolve_install_dest(payload_rel: &Path, install_map: &HashMap<String, String>) -> Option<PathBuf> {
    let mut components = payload_rel.components();
    let top = components.next()?.as_os_str().to_str()?;
    let dest_root = install_map.get(top)?;
    let rest: PathBuf = components.collect();
    Some(Path::new(dest_root).join(rest))
}

/// Compute a `$ORIGIN`-relative RPATH string from `from_dir` (an absolute
/// directory — the file's own installed parent dir) up/down to `to_dir`
/// (an absolute directory — where the library actually lives). E.g.
/// `from_dir=/overlayer/syshub/bin, to_dir=/overlayer/syshub/lib` ->
/// `"$ORIGIN/../lib"`; `from_dir=/overlayer/syshub/lib,
/// to_dir=/overlayer/syshub/lib` -> `"$ORIGIN"`.
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

/// Rewrite RPATH/RUNPATH entries that point at FHS lib dirs to
/// `lib_rpath` (a per-file `$ORIGIN`-relative value, not a fixed
/// constant), keep everything else, dedup preserving order, and
/// guarantee `lib_rpath` is present even if the binary shipped no
/// RPATH at all.
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

    // A file with neither an interpreter nor any DT_NEEDED entries is
    // fully self-contained (a static-PIE executable) — no dynamic linker
    // ever runs for it, so RPATH is genuinely unused. Skip patching
    // entirely: confirmed elsewhere that growing the .dynamic section to
    // add an RPATH entry can corrupt a static-PIE binary's self-relocation
    // table even when the interpreter step is correctly skipped.
    if !has_interp && !has_needed {
        return Ok(());
    }

    if has_interp {
        f.set_interpreter(ZEX_INTERP)?;
    }

    let existing = f.rpath()?.unwrap_or_default();
    let new_rpath = rebuild_rpath(&existing, lib_rpath);
    // force_rpath = true → legacy DT_RPATH, matching this OS's own
    // toolchain-built binaries.
    f.set_rpath(&new_rpath, true)?;

    f.commit()?;
    f.write_in_place()?;
    Ok(())
}

/// Walk `payload_dir` and patch every regular ELF file's interpreter and
/// RPATH in place, on disk, before the caller reads/hashes the payload.
/// Any failure is a hard error — a Tier-1 package with an unpatched
/// interpreter is a broken package, not a best-effort concern.
///
/// `install_map` is the manifest's `[install]` table (payload subdir ->
/// absolute destination) and `lib_target` must be [`SYSHUB_LIB_TARGET`]
/// or [`USERLAND_LIB_TARGET`] depending on `manifest.install._syshub` —
/// both are needed to compute each file's own `$ORIGIN`-relative RPATH
/// correctly (its distance to `lib_target` depends on exactly where under
/// `payload/` it lives, per `resolve_install_dest`/`origin_relative`
/// above). Confirmed live that skipping this per-file computation is a
/// real bug: a fixed absolute RPATH is at least *tolerant* of location
/// (works regardless of nesting depth), but using the *wrong absolute
/// target* (userland path on a syshub package, e.g. `xz`) silently
/// produces a package whose binaries can't find their own libraries.
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
            // Not under any mapped install subdir — the real installer
            // wouldn't place this file anywhere either. Fall back to the
            // fixed absolute target rather than hard-erroring the whole
            // pack over what's likely an unrelated/auxiliary file.
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
