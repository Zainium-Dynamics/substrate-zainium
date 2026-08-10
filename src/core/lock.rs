//! Generates the `.zex.locked` companion artifact: the real, un-obfuscated
//! source tree a package was built from, plus its audit summary.
//!
//! ## Workflow
//!
//! 1. `substrate pack` always emits `<name>.zex` **and** `<name>.zex.locked`.
//! 2. Anyone reviewing the package (e.g. via the merge request that adds
//!    its recipe) extracts it (`substrate unpack <file>.zex.locked -o
//!    <dir>`) and reads `REVIEW.md` inside the tree.
//!
//! `.zex.locked` is never shipped to end users — installers only ever
//! handle the compiled `.zex` binary. There is no approval state embedded
//! in it — review happens wherever the recipe/source lives (e.g. a GitLab
//! merge request), not inside this file.
//!
//! ## What's inside (extracted layout)
//!
//! ```text
//! manifest.toml   ← the same *signed* manifest shipped in the .zex
//!                    (blake3 / ed25519_sig / ed25519_pubkey filled in —
//!                    not the pre-signing template that sits in source_dir)
//! REVIEW.md       ← human review checklist + audit summary
//! header.toml     ← [package.<name>] = LedgerHeader fields only (what
//!                    zex-server merges into zex_ledger-x86_64.toml on
//!                    approval) — no schema / reviews / security_report
//! security.toml   ← the full SecurityReport, split out of header.toml
//! receipt.toml    ← install receipt (same content as the .zex's sidecar)
//! source/         ← present only when `substrate pack --source <path>`
//!                    was given; the real upstream tree that was compiled,
//!                    with source_dir itself pruned out if nested inside it
//! ```
//!
//! `payload/` (the compiled binaries already shipped in the `.zex`) is
//! deliberately **not** included — a reviewer looks at what something was
//! built *from*, not a second copy of the build output.
//!
//! The outer `ZEXL` byte layout (magic || u64 header len || JSON
//! `LockedManifest` || zexc-compressed tar of the above) is unchanged —
//! `zex-server`'s `locked.rs::LockedManifest` mirrors that JSON header
//! field-for-field and never opens the compressed tar, so none of the
//! `header.toml`/`security.toml`/`source/` reshaping above is visible to
//! it; only the extracted-tree layout changed.

use crate::core::manifest::ZexTomlManifest;
use crate::core::report::SecurityReport;
use crate::error::Result;
use crate::utils::compressor;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Write};
use std::path::Path;

/// Filename of the human review checklist embedded at the root of the
/// locked source tarball (extracted next to `manifest.toml` / `payload/`).
pub const REVIEW_MD_NAME: &str = "REVIEW.md";

/// The ledger-ready `[packages.<name>]` block — same shape `zex-server`
/// merges into `zex_ledger.toml`/`syshub.toml`, deliberately carrying no
/// crypto fields (verification lives only in the `.zex`'s own
/// manifest.toml — see `manifest.rs::PackageMeta`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerHeader {
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub license: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub maintainer: String,
    /// The `.zex` filename this header describes (not a path — matches
    /// the `file = "name-version.zex"` convention in the ledger samples).
    pub file: String,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub libc_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_syshub: Option<String>,
}

impl LedgerHeader {
    fn from_manifest(manifest: &ZexTomlManifest, file: String, size_bytes: u64) -> Self {
        let p = &manifest.package;
        LedgerHeader {
            version: p.version.clone(),
            description: p.description.clone(),
            license: p.license.clone(),
            maintainer: p.maintainer.clone(),
            file,
            size_bytes,
            depends: p.depends.clone(),
            provides: p.provides.clone(),
            build_type: p.build_type.clone(),
            libc_target: p.libc_target.clone(),
            edition: p.edition.clone(),
            tags: p.tags.clone(),
            requires_syshub: p.requires_syshub.clone(),
        }
    }
}

/// Shape of `header.toml`, embedded inside `.zex.locked`'s tar —
/// `[package.<name>]` = the same fields that get merged into the ledger
/// on publish, keyed by package name so the table drops straight into a
/// ledger file structurally. Deliberately just this — no schema /
/// security_report (those stay in the JSON ZEXL prefix only; see
/// `security.toml` for the audit report instead).
#[derive(Debug, Serialize)]
struct HeaderTomlDoc {
    package: std::collections::BTreeMap<String, LedgerHeader>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedManifest {
    pub schema: String,
    pub package_name: String,
    pub package_version: String,
    /// The full security report (layout, content, manifest integrity,
    /// permission audit, rust/C audit, secrets) embedded so a reviewer
    /// can read it from the locked header without unpacking.
    pub security_report: SecurityReport,
    /// What gets merged into the ledger once this package is published —
    /// see [`LedgerHeader`].
    pub ledger_header: LedgerHeader,
}

impl LockedManifest {
    pub fn new(
        manifest: &ZexTomlManifest,
        report: &SecurityReport,
        zex_file: String,
        zex_size_bytes: u64,
    ) -> Self {
        LockedManifest {
            schema: "zainium-locked-source-v4".to_string(),
            package_name: manifest.package.name.clone(),
            package_version: manifest.package.version.clone(),
            security_report: report.clone(),
            ledger_header: LedgerHeader::from_manifest(manifest, zex_file, zex_size_bytes),
        }
    }

    /// Human-facing audit summary embedded as `REVIEW.md` inside the
    /// locked tarball — no approval state, this is read-only reference
    /// material for whoever's reviewing the package's source (e.g. the
    /// merge request that added its recipe).
    pub fn to_review_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!(
            "# Package Review — {} {}\n\n",
            self.package_name, self.package_version
        ));
        md.push_str(&format!("Schema: `{}`\n\n", self.schema));

        md.push_str("## How to review\n\n");
        md.push_str("1. Extract this `.zex.locked` (`substrate unpack <file.zex.locked> -o ./review-tree`).\n");
        md.push_str("2. Read this `REVIEW.md` plus the source tree (`source/`, if present).\n");
        md.push_str("3. Leave feedback wherever this package's source actually lives (e.g. the merge request that added it).\n\n");

        md.push_str("## Ledger header (what gets published)\n\n");
        let h = &self.ledger_header;
        md.push_str(&format!("- `file`: `{}` ({} bytes)\n", h.file, h.size_bytes));
        if !h.description.is_empty() {
            md.push_str(&format!("- `description`: {}\n", h.description));
        }
        if !h.license.is_empty() {
            md.push_str(&format!("- `license`: {}\n", h.license));
        }
        if !h.maintainer.is_empty() {
            md.push_str(&format!("- `maintainer`: {}\n", h.maintainer));
        }
        if !h.depends.is_empty() {
            md.push_str(&format!("- `depends`: {}\n", h.depends.join(", ")));
        }
        if !h.provides.is_empty() {
            md.push_str(&format!("- `provides`: {}\n", h.provides.join(", ")));
        }
        if let Some(bt) = &h.build_type {
            md.push_str(&format!("- `build_type`: {bt}\n"));
        }
        if let Some(lc) = &h.libc_target {
            md.push_str(&format!("- `libc_target`: {lc}\n"));
        }
        if let Some(rs) = &h.requires_syshub {
            md.push_str(&format!("- `requires_syshub`: {rs}\n"));
        }
        md.push_str(
            "\n_No cryptographic fields here — verification lives only in the .zex itself._\n\n",
        );

        md.push_str("## Automated audit summary (read-only, generated by substrate)\n\n");
        md.push_str(&format!(
            "- Layout policy: `{:?}`\n",
            self.security_report.layout_check.result
        ));
        md.push_str(&format!(
            "- Manifest integrity: `{:?}`\n",
            self.security_report.manifest_integrity.result
        ));
        let setuid = &self.security_report.permission_audit.setuid_files;
        md.push_str(&format!(
            "- setuid/setgid files: {}\n",
            if setuid.is_empty() {
                "none".to_string()
            } else {
                setuid.join(", ")
            }
        ));
        let ra = &self.security_report.rust_audit;
        if ra.applicable {
            md.push_str(&format!("- Rust build kind: `{:?}`\n", ra.build_kind));
            if let Some(n) = ra.unsafe_block_count {
                md.push_str(&format!("- Unsafe expressions: {n}\n"));
            }
            for t in &ra.tools {
                md.push_str(&format!(
                    "- {}: `{:?}` — {}\n",
                    t.tool, t.outcome, t.summary
                ));
            }
        }
        let ca = &self.security_report.c_audit;
        if ca.applicable {
            for t in &ca.tools {
                md.push_str(&format!(
                    "- {}: `{:?}` — {}\n",
                    t.tool, t.outcome, t.summary
                ));
            }
        }
        let sc = &self.security_report.secrets_scan;
        md.push_str(&format!(
            "- Secrets scan: `{:?}` ({} text file(s))\n",
            sc.outcome, sc.files_scanned
        ));
        md.push('\n');

        md.push_str("## Reviewer checklist\n\n");
        md.push_str("- [ ] Source matches the automated audit summary above — no edits since scan.\n");
        md.push_str("- [ ] No undisclosed network calls, telemetry, or credential exfiltration in source.\n");
        md.push_str("- [ ] `unsafe` blocks (if any) are isolated to a reviewed module and are necessary.\n");
        md.push_str("- [ ] Build/install scripts do not escalate privileges beyond what the package declares.\n");
        md.push_str("- [ ] License and provenance of bundled/vendored code is clear.\n");
        md.push_str("- [ ] Install map (`manifest.toml` `[install]`) lands files only under `/overlayer/`.\n");
        md
    }
}

/// File magic for the locked-source container. Distinct from `ZEX1` so
/// tooling never confuses an end-user binary with a maintainer-only
/// review artifact.
pub const LOCKED_MAGIC: &[u8; 4] = b"ZEXL";

/// Builds the `.zex.locked` file next to `output_zex_path`:
/// `ZEXL` magic || u64 LE manifest_len || JSON(LockedManifest) ||
/// zexc-compressed tar of the signed manifest.toml + real source (minus
/// payload/, plus `extra_source` under `source/` if given) + REVIEW.md +
/// header.toml + security.toml + receipt.toml. See the module doc above
/// for the full extracted layout.
///
/// No external sidecars are written — everything a reviewer needs lives
/// inside this one archive so a website download is one file.
pub fn write_locked(
    source_dir: &Path,
    manifest: &ZexTomlManifest,
    report: &SecurityReport,
    output_zex_path: &Path,
    zex_size_bytes: u64,
    receipt_toml: &[u8],
    signed_manifest_toml: &str,
    extra_source: Option<&Path>,
) -> Result<std::path::PathBuf> {
    let zex_file = output_zex_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let locked_manifest = LockedManifest::new(manifest, report, zex_file, zex_size_bytes);
    let review_md = locked_manifest.to_review_markdown();

    // header.toml: `[package.<name>]` = just the ledger-ready fields, keyed
    // by package name so it drops straight into a ledger file structurally.
    // Deliberately NOT the full LockedManifest (no schema / security_report
    // here) — those stay in the JSON ZEXL prefix only; this file is for a
    // human reviewer who already extracted the tree.
    let mut header_doc = std::collections::BTreeMap::new();
    header_doc.insert(manifest.package.name.clone(), locked_manifest.ledger_header.clone());
    let header_toml = toml::to_string_pretty(&HeaderTomlDoc { package: header_doc }).map_err(|e| {
        crate::error::ZexError::Other(format!("locked header.toml serialize error: {e}"))
    })?;

    // security.toml: the full security report, split out of header.toml so
    // the ledger-shaped file stays small and the audit detail lives on its
    // own.
    let security_toml = toml::to_string_pretty(report).map_err(|e| {
        crate::error::ZexError::Other(format!("locked security.toml serialize error: {e}"))
    })?;

    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);

        // Pack the real source tree, excluding `payload/` — that's a copy
        // of the compiled binaries already shipped in the .zex; `.locked`
        // is for reviewing what was *compiled from*, not a second copy of
        // what came out.
        let payload_dir = source_dir.join("payload");
        for entry in walkdir::WalkDir::new(source_dir)
            .min_depth(1)
            .into_iter()
            .filter_entry(|e| e.path() != payload_dir)
        {
            let entry = entry.map_err(|e| {
                crate::error::ZexError::Other(format!("walking source_dir for .locked: {e}"))
            })?;
            let rel = entry.path().strip_prefix(source_dir).unwrap();
            if entry.file_type().is_dir() {
                builder.append_dir(rel, entry.path()).map_err(crate::error::ZexError::Io)?;
            } else if entry.file_type().is_file() {
                let mut f = std::fs::File::open(entry.path()).map_err(crate::error::ZexError::Io)?;
                builder.append_file(rel, &mut f).map_err(crate::error::ZexError::Io)?;
            }
        }

        // If the package was compiled from a source tree outside
        // `source_dir` (e.g. `source_dir` is a build/output subdir of a
        // much larger upstream checkout), embed that tree too, under
        // `source/`. `source_dir` itself is pruned out of this walk (via
        // canonicalized comparison, since `extra_source`/`source_dir` may
        // be given in different relative/absolute forms) so payload/ is
        // never double-embedded through this second pass.
        if let Some(extra) = extra_source {
            let source_dir_canon = source_dir
                .canonicalize()
                .unwrap_or_else(|_| source_dir.to_path_buf());
            for entry in walkdir::WalkDir::new(extra).min_depth(1).into_iter().filter_entry(|e| {
                e.path()
                    .canonicalize()
                    .map(|p| p != source_dir_canon)
                    .unwrap_or(true)
            }) {
                let entry = entry.map_err(|e| {
                    crate::error::ZexError::Other(format!("walking --source for .locked: {e}"))
                })?;
                let rel = entry.path().strip_prefix(extra).unwrap();
                let archive_path = Path::new("source").join(rel);
                if entry.file_type().is_dir() {
                    builder
                        .append_dir(&archive_path, entry.path())
                        .map_err(crate::error::ZexError::Io)?;
                } else if entry.file_type().is_file() {
                    let mut f = std::fs::File::open(entry.path()).map_err(crate::error::ZexError::Io)?;
                    builder
                        .append_file(&archive_path, &mut f)
                        .map_err(crate::error::ZexError::Io)?;
                }
            }
        }

        // Inject REVIEW.md, header.toml, security.toml, receipt.toml at
        // tarball root so extract always yields them alongside
        // manifest.toml / whatever real source was found above.
        //
        // manifest.toml is appended *again* here, deliberately overriding
        // the stale on-disk copy the walk above just pulled in from
        // `source_dir` — that copy predates signing (blake3 / ed25519_sig /
        // ed25519_pubkey still blank). Our own extractor
        // (`extract_locked_bytes`) processes entries in tar order and
        // overwrites on each `unpack_in`, so this later entry wins and a
        // reviewer sees the same signed manifest the .zex was built with.
        append_tar_bytes(&mut builder, "manifest.toml", signed_manifest_toml.as_bytes())?;
        append_tar_bytes(&mut builder, REVIEW_MD_NAME, review_md.as_bytes())?;
        append_tar_bytes(&mut builder, "header.toml", header_toml.as_bytes())?;
        append_tar_bytes(&mut builder, "security.toml", security_toml.as_bytes())?;
        append_tar_bytes(&mut builder, "receipt.toml", receipt_toml)?;

        builder.finish().map_err(crate::error::ZexError::Io)?;
    }
    let compressed = compressor::compress(&tar_buf, compressor::DEFAULT_LEVEL)?;
    let manifest_json = serde_json::to_vec(&locked_manifest)?;

    let locked_path = locked_path_for(output_zex_path);
    let mut out = std::fs::File::create(&locked_path)?;
    out.write_all(LOCKED_MAGIC)?;
    out.write_all(&(manifest_json.len() as u64).to_le_bytes())?;
    out.write_all(&manifest_json)?;
    out.write_all(&compressed)?;
    out.flush()?;

    Ok(locked_path)
}

fn append_tar_bytes<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    data: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    builder
        .append_data(&mut header, path, data)
        .map_err(crate::error::ZexError::Io)
}

/// `vim-9.1.1366.zex` -> `vim-9.1.1366.zex.locked`
pub fn locked_path_for(output_zex_path: &Path) -> std::path::PathBuf {
    let mut s = output_zex_path.as_os_str().to_os_string();
    s.push(".locked");
    std::path::PathBuf::from(s)
}

/// True when `buf` starts with the locked-source magic.
pub fn is_locked_bytes(buf: &[u8]) -> bool {
    buf.len() >= 4 && &buf[0..4] == LOCKED_MAGIC
}

/// Reads back a `.zex.locked` file's manifest header (without
/// decompressing the embedded source tree).
pub fn read_locked_manifest(path: &Path) -> Result<LockedManifest> {
    let buf = std::fs::read(path)?;
    read_locked_manifest_from_bytes(&buf)
}

pub fn read_locked_manifest_from_bytes(buf: &[u8]) -> Result<LockedManifest> {
    if buf.len() < 12 || &buf[0..4] != LOCKED_MAGIC {
        return Err(crate::error::ZexError::InvalidFormat(
            "not a valid .zex.locked file (bad magic)".into(),
        ));
    }
    let manifest_len = u64::from_le_bytes(buf[4..12].try_into().unwrap()) as usize;
    if 12 + manifest_len > buf.len() {
        return Err(crate::error::ZexError::InvalidFormat(
            "locked manifest length exceeds file size".into(),
        ));
    }
    let manifest_json = &buf[12..12 + manifest_len];
    Ok(serde_json::from_slice(manifest_json)?)
}

/// Extract the source tree (including embedded `REVIEW.md`) from a
/// `.zex.locked` file into `dest_dir`.
pub fn extract_locked(path: &Path, dest_dir: &Path) -> Result<usize> {
    let buf = std::fs::read(path)?;
    extract_locked_bytes(&buf, dest_dir)
}

pub fn extract_locked_bytes(buf: &[u8], dest_dir: &Path) -> Result<usize> {
    if buf.len() < 12 || &buf[0..4] != LOCKED_MAGIC {
        return Err(crate::error::ZexError::InvalidFormat(
            "not a valid .zex.locked file (bad magic)".into(),
        ));
    }
    let manifest_len = u64::from_le_bytes(buf[4..12].try_into().unwrap()) as usize;
    let blob_start = 12 + manifest_len;
    if blob_start > buf.len() {
        return Err(crate::error::ZexError::InvalidFormat(
            "locked blob offset past end of file".into(),
        ));
    }
    let tar_bytes = compressor::decompress(&buf[blob_start..])?;

    std::fs::create_dir_all(dest_dir)?;
    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let mut count = 0usize;
    for entry in archive.entries().map_err(crate::error::ZexError::Io)? {
        let mut entry = entry.map_err(crate::error::ZexError::Io)?;
        // path() already rejects absolute / `..` escapes for GNU tar when
        // unpacking via unpack_in — use that.
        entry
            .unpack_in(dest_dir)
            .map_err(crate::error::ZexError::Io)?;
        count += 1;
    }
    Ok(count)
}
