// Package archive packer implementation for .zex packages.


use crate::core::manifest::ZexTomlManifest;
use crate::core::report::SecurityReport;
use crate::core::scanner;
use crate::error::Result;
use crate::security::root_guard;
use crate::security::secrets_scan;
use crate::security::signer::Signer128;
use crate::utils::compressor;
use std::{io::Write, path::Path};


pub struct PackOptions {
    pub version:         String,
    pub description:     String,
    pub features:        Vec<String>,
    pub requires_syshub: Option<String>,
    pub builder:         String,
    pub zstd_level:      i32,
    pub install_root:    String,
}

pub struct PackResult {
    pub output_path:       std::path::PathBuf,
    pub compressed_size:   u64,
    pub uncompressed_size: u64,
    pub report:            SecurityReport,
}

// Pack source_dir into a canonical .zex package at output_path.

pub fn pack(
    source_dir: &Path,
    output_path: &Path,
    opts: &PackOptions,
    signer: &Signer128,
) -> Result<PackResult> {
    let payload_dir = source_dir.join("payload");

    if !payload_dir.is_dir() {
        return Err(crate::error::ZexError::LayoutViolation(
            "source directory must contain a payload/ subdirectory".into(),
        ));
    }

    let manifest_src = source_dir.join("manifest.toml");
    let mut manifest: ZexTomlManifest = if manifest_src.exists() {
        let raw = std::fs::read_to_string(&manifest_src)?;
        toml::from_str(&raw).map_err(|e| {
            crate::error::ZexError::Other(format!("manifest.toml parse error: {e}"))
        })?
    } else {
        ZexTomlManifest::generate(source_dir, opts)?
    };

    if !opts.version.is_empty() {
        manifest.package.version = opts.version.clone();
    }
    if !opts.description.is_empty() {
        manifest.package.description = opts.description.clone();
    }
    manifest.package.requires_syshub = Some(
        opts.requires_syshub
            .clone()
            .unwrap_or_else(|| chrono::Utc::now().format("%Y").to_string()),
    );

    if !manifest.package.native {
        let lib_target = if manifest.install._syshub {
            crate::core::elfpatch::SYSHUB_LIB_TARGET
        } else {
            crate::core::elfpatch::USERLAND_LIB_TARGET
        };
        // shebang_fix must run before enforce_layout_policy below --
        // otherwise a #!/usr/bin/env script gets blocked by the /usr
        // scan before it ever gets the chance to be rewritten.
        crate::core::shebang_fix::patch_payload_dir(&payload_dir)?;
        crate::core::elfpatch::patch_payload_dir(&payload_dir, &manifest.install.paths, lib_target)?;
    }

    let (layout_result, content_result) = root_guard::enforce_layout_policy(source_dir)?;

    let secrets = secrets_scan::scan_secrets(source_dir);
    if secrets.is_blocked() {
        return Err(crate::error::ZexError::Other(
            "secrets scan blocked packaging: hardcoded credentials found".into(),
        ));
    }

    let mut payload_files: Vec<(String, Vec<u8>, Option<String>)> = Vec::new();
    let mut uncompressed = 0u64;

    for entry in walkdir::WalkDir::new(&payload_dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let ft = entry.file_type();
        let rel = entry.path()
            .strip_prefix(source_dir)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .to_string();
        if ft.is_symlink() {
            let target = std::fs::read_link(entry.path())?
                .to_string_lossy()
                .to_string();
            payload_files.push((rel, Vec::new(), Some(target)));
            continue;
        }
        if !ft.is_file() { continue; }
        let bytes = std::fs::read(entry.path())?;
        uncompressed += bytes.len() as u64;
        payload_files.push((rel, bytes, None));
    }

    payload_files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut payload_hasher = blake3::Hasher::new();
    for (path, bytes, target) in &payload_files {
        payload_hasher.update(path.as_bytes());
        match target {
            Some(t) => payload_hasher.update(t.as_bytes()),
            None => payload_hasher.update(bytes),
        };
    }
    let payload_blake3 = payload_hasher.finalize().to_hex().to_string();

    let sig_block = signer.sign(payload_blake3.as_bytes(), &opts.builder)?;
    manifest.package.blake3         = Some(payload_blake3.clone());
    manifest.package.ed25519_sig    = sig_block.ed25519_signature.clone();
    manifest.package.ed25519_pubkey = Some(signer.verifying_key_hex());

    let manifest_toml = toml::to_string_pretty(&manifest).map_err(|e| {
        crate::error::ZexError::Other(format!("manifest serialize error: {e}"))
    })?;

    let mut sig_hasher = blake3::Hasher::new();
    sig_hasher.update(manifest_toml.as_bytes());
    sig_hasher.update(payload_blake3.as_bytes());
    let sig_b3 = sig_hasher.finalize().to_hex().to_string();

    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);

        append_bytes(&mut builder, "manifest.toml", manifest_toml.as_bytes(), 0o644)?;
        append_bytes(&mut builder, "signature.b3", sig_b3.as_bytes(), 0o644)?;

        for (rel_path, bytes, target) in &payload_files {
            match target {
                Some(t) => append_symlink(&mut builder, rel_path, t)?,
                None => append_bytes(&mut builder, rel_path, bytes, 0o755)?,
            }
        }

        builder.finish()?;
    }

    let compressed = compressor::compress(&tar_buf, opts.zstd_level)?;
    let compressed_size = compressed.len() as u64;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output_path, &compressed)?;

    let permission_audit = scanner::audit_permissions(&payload_dir)?;
    let manifest_integrity = scanner::ManifestIntegrityResult {
        result: scanner::CheckOutcome::Passed,
        description: "Payload hashed via Blake3 at pack time".into(),
        mismatches: Vec::new(),
    };
    let report = SecurityReport::new(
        layout_result,
        content_result,
        manifest_integrity,
        permission_audit,
        secrets,
    );


    Ok(PackResult {
        output_path:       output_path.to_path_buf(),
        compressed_size,
        uncompressed_size: uncompressed,
        report,
    })
}

fn append_bytes<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    data: &[u8],
    mode: u32,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(mode);
    header.set_mtime(0);
    header.set_cksum();
    builder.append_data(&mut header, path, data)
        .map_err(crate::error::ZexError::Io)
}

fn append_symlink<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    target: &str,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_mtime(0);
    builder.append_link(&mut header, path, target)
        .map_err(crate::error::ZexError::Io)
}

// Derive package name from output path stem.

pub fn manifest_name_from_path(output_path: &Path) -> String {
    output_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("package")
        .split('_').next()
        .unwrap_or("package")
        .to_string()
}

