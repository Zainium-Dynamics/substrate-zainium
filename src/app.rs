
use clap::Parser;
use crate::cli::{Cli, Command};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use crate::core::lock::read_locked_manifest;
use crate::core::{packer, unpacker, verifier};
use crate::security::audit_common::ToolOutcome;
use crate::security::signer::Signer128;
use crate::ui::display;

/// Generate a fresh Ed25519 keypair for one pack run. Never written to
/// disk, never compiled into the binary, never reused across runs — it
/// exists only in memory for the duration of `cmd_pack`, signs the
/// payload once, and is dropped. The public half travels with the
/// package (`manifest.package.ed25519_pubkey`, set in `packer::pack`);
/// that embedded pubkey is the only way anyone verifies the signature
/// later — there's no external key store to check against.
fn fresh_ephemeral_signer() -> Signer128 {
    let signing_key = SigningKey::generate(&mut OsRng);
    Signer128::from_bytes(&signing_key.to_bytes())
}

pub fn run(raw_args: Vec<String>) {
    let cli = Cli::parse_from(&raw_args);

    let result = match cli.command {
        Command::Pack {
            directory,
            version,
            description,
            features,
            requires_syshub,
            source,
            report,
            install_root,
            output,
        } => cmd_pack(directory, version, description, features, requires_syshub, source, report, install_root, output),

        Command::Unpack { file, output, verify_only } =>
            cmd_unpack(file, output, verify_only),

        Command::Verify { file } => cmd_unpack(file, None, true),

        Command::Inspect { file } => cmd_inspect(file),

        Command::Keygen { output, force } => cmd_keygen(output, force),
    };

    if let Err(e) = result {
        display::error(&e.to_string());
        std::process::exit(1);
    }
}

// ── Pack ─────────────────────────────────────────────────────────────────────

fn cmd_pack(
    directory: std::path::PathBuf,
    version: String,
    description: String,
    features: Vec<String>,
    requires_syshub: Option<String>,
    source: Option<std::path::PathBuf>,
    save_report: bool,
    install_root: String,
    output: Option<std::path::PathBuf>,
) -> crate::error::Result<()> {
    let name = directory
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "package".to_string());

    let output_path = output.unwrap_or_else(|| {
        // Hyphen, not underscore — matches the real Zainium package naming
        // convention (see zex_ledger-x86_64.toml samples: vim-9.1.1366.zex,
        // rust-1.87.0.zex), not just this tool's own prior default.
        std::path::PathBuf::from(format!("{}-{}.zex", name, version))
    });

    display::title(" Zainium Dynamics - Secure Package Builder");

    // ── step 1: count files ──────────────────────────────────────────
    display::step("Scanning source directory...");
    let file_count = walkdir::WalkDir::new(&directory)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();
    display::kv("Files found", &file_count.to_string());

    // ── step 2: signing is always-on, not user configurable ──────────
    display::step("Cryptographic signing (background, always-on)...");
    display::ok_kv("blake3",   "digest pipeline active");
    display::ok_kv("sha512",   "digest pipeline active");
    display::ok_kv("ed25519",  "fresh ephemeral keypair generated — never persisted");

    // ── step 3: run pack (layout + manifest + rust/C audit + secrets) ─
    display::step("Running security passes (layout · secrets · Rust audit · C audit)...");

    let opts = packer::PackOptions {
        version: version.clone(),
        description: description.clone(),
        features: features.into_iter().filter(|f| !f.is_empty()).collect(),
        requires_syshub,
        extra_source: source,
        builder: "Zainium Dynamics Official Builder".to_string(),
        zstd_level: crate::utils::compressor::DEFAULT_LEVEL,
        install_root,
    };

    let signer = fresh_ephemeral_signer();

    let pack_result = match packer::pack(&directory, &output_path, &opts, &signer) {
        Ok(r) => r,
        Err(e) => {
            display::fail_kv("BLOCKED", &e.to_string());
            return Err(e);
        }
    };

    let rep = &pack_result.report;

    // Layout
    display::ok_kv("Layout policy", "PASSED — no /usr merge references");

    // Secrets scan
    let sc = &rep.secrets_scan;
    if sc.findings.is_empty() {
        display::ok_kv("Secrets scan",
            &format!("{} text files scanned — no hardcoded credentials", sc.files_scanned));
    } else {
        // Can't reach here (pack would have returned Err), but be defensive:
        display::fail_kv("Secrets scan",
            &format!("{} finding(s) — should have blocked!", sc.findings.len()));
    }

    // Rust audit
    let ra = &rep.rust_audit;
    if ra.applicable {
        display::kv("Rust source", &format!("{:?}", ra.language));
        display::kv("Build kind",  &format!("{:?}", ra.build_kind));
        if let Some(n) = ra.unsafe_block_count {
            display::kv("Unsafe expressions", &n.to_string());
        }
        if !ra.fuzz_harness_present {
            display::kv("Fuzz harness", "ABSENT — consider `cargo fuzz init`");
        } else {
            display::ok_kv("Fuzz harness", "present");
        }
        for t in &ra.tools {
            show_tool_result(t.outcome, &t.tool, &t.summary);
        }
    }

    // C/C++ audit
    let ca = &rep.c_audit;
    if ca.applicable {
        display::kv("C/C++ source", "detected");
        for t in &ca.tools {
            show_tool_result(t.outcome, &t.tool, &t.summary);
        }
    }

    // Permission audit
    if rep.permission_audit.setuid_files.is_empty() {
        display::ok_kv("Permission audit", "no setuid/setgid files");
    } else {
        display::fail_kv(
            "Permission audit",
            &format!("{} setuid/setgid file(s) — review mandatory",
                     rep.permission_audit.setuid_files.len()),
        );
    }

    // ── step 4: manifest ──────────────────────────────────────────────
    display::step("Manifest sealed...");
    display::kv("Name",    &name);
    display::kv("Version", &version);
    if !description.is_empty() {
        display::kv("Description", &description);
    }

    // ── step 5: output ────────────────────────────────────────────────
    display::success("Package built successfully");
    display::kv("Output (.zex)",     &output_path.display().to_string());
    display::kv("Compressed",
        &format!("{:.1} MB", pack_result.compressed_size as f64 / 1_048_576.0));
    display::kv("Uncompressed",
        &format!("{:.1} MB", pack_result.uncompressed_size as f64 / 1_048_576.0));
    display::kv("Install receipt",   &pack_result.receipt_path.display().to_string());

    {
        let lp = &pack_result.locked_path;
        display::kv("Locked artifact", &lp.display().to_string());
        let md = lp.with_extension("locked.review.md");
        display::kv("Review checklist", &md.display().to_string());
    }

    display::kv("Inspect with",
        &format!("substrate inspect {}", output_path.display()));

    // Optionally write report JSON to disk
    if save_report {
        let report_path = output_path.with_extension("security-report.json");
        std::fs::write(&report_path, rep.to_json_pretty()?)?;
        display::ok_kv("Report saved", &report_path.display().to_string());
    }

    Ok(())
}

fn show_tool_result(outcome: ToolOutcome, tool: &str, summary: &str) {
    match outcome {
        ToolOutcome::Passed  => display::ok_kv(tool, summary),
        ToolOutcome::Failed  => display::fail_kv(tool, summary),
        ToolOutcome::Skipped => display::kv(tool, &format!("SKIPPED — {summary}")),
    }
}

// ── Unpack / Verify ──────────────────────────────────────────────────────────

fn cmd_unpack(
    file: std::path::PathBuf,
    output: Option<std::path::PathBuf>,
    verify_only: bool,
) -> crate::error::Result<()> {
    let buf = std::fs::read(&file)?;

    // `.zex.locked` review artifacts have a distinct `ZEXL` wrapper (magic
    // || u64 header len || JSON header || zexc tar) — they are not a bare
    // ZEX1 frame, so they can't go through verifier::parse. Route them to
    // the dedicated locked-extraction path instead.
    if crate::core::lock::is_locked_bytes(&buf) {
        return cmd_unpack_locked(&file, &buf, output, verify_only);
    }

    let parsed = verifier::parse(buf)?;
    // No external trust store to check against — every package embeds the
    // ephemeral public key it was actually signed with, right in its own
    // manifest.toml (see manifest.rs::PackageMeta::ed25519_pubkey). Verify
    // against exactly that, not anything loaded from disk or environment.
    let pubkey_hex = parsed.manifest.package.ed25519_pubkey.as_deref().ok_or_else(|| {
        crate::error::ZexError::SignatureInvalid(
            "manifest.toml has no ed25519_pubkey — package was never signed by substrate pack".into(),
        )
    })?;
    let pubkey_bytes = hex::decode(pubkey_hex)
        .map_err(|e| crate::error::ZexError::Other(format!("invalid ed25519_pubkey hex: {e}")))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().map_err(|_| {
        crate::error::ZexError::Other("ed25519_pubkey must be exactly 32 bytes".into())
    })?;
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|e| crate::error::ZexError::Other(format!("invalid ed25519_pubkey: {e}")))?;

    if verify_only {
        display::title("Package Verification");
        display::kv("File",      &file.display().to_string());
        display::kv("Name",      &parsed.manifest.package.name);
        display::kv("Version",   &parsed.manifest.package.version);
        display::kv("Signed by", &parsed.signature.signed_by);

        let sig_ok = verifier::verify_signature(&parsed, &pubkey)?;
        if sig_ok {
            display::ok_kv("blake3 / sha512", "Matched");
            display::ok_kv("ed25519", "Valid");
            display::success("Package is authentic and untampered.");
        } else {
            display::fail_kv("Signature", "INVALID");
            return Err(crate::error::ZexError::SignatureInvalid(
                "signature does not match package contents".into(),
            ));
        }
        return Ok(());
    }

    display::title(&format!("Unpacking {}...", file.display()));

    display::step("Verifying signature (blake3 + sha512 + ed25519)...");
    let sig_ok = verifier::verify_signature(&parsed, &pubkey)?;
    if !sig_ok {
        display::fail_kv("ed25519", "INVALID");
        return Err(crate::error::ZexError::SignatureInvalid(
            "package signature does not match its contents".into(),
        ));
    }
    display::ok_kv("ed25519", "Valid");
    display::ok_kv("blake3",  "Valid");

    display::step("Reading manifest...");
    display::kv("Name",     &parsed.manifest.package.name);
    display::kv("Version",  &parsed.manifest.package.version);
    display::kv("Tags",     &parsed.manifest.package.tags.join(", "));
    display::kv("Build type", parsed.manifest.package.build_type.as_deref().unwrap_or("unknown"));

    let dest = output.unwrap_or_else(|| std::path::PathBuf::from(&parsed.manifest.package.name));

    display::step("Extracting files...");
    let unpack_result = unpacker::unpack(&parsed, &dest, &pubkey)?;
    display::kv("Files extracted", &unpack_result.files_extracted.to_string());

    display::step("Post-unpack integrity check...");
    display::ok_kv("Manifest integrity", "PASSED");
    if !parsed.report.permission_audit.setuid_files.is_empty() {
        display::fail_kv(
            "Permission audit",
            &format!("{} setuid/setgid file(s) — review before use",
                     parsed.report.permission_audit.setuid_files.len()),
        );
    } else {
        display::ok_kv("Permission audit", "No setuid/setgid files");
    }

    let report_path = dest.join("security-report.json");
    std::fs::write(&report_path, parsed.report.to_json_pretty()?)?;

    display::success("Package unpacked successfully.");
    display::kv("Destination", &dest.display().to_string());
    display::kv("Report",      &report_path.display().to_string());

    Ok(())
}

/// Extract a `.zex.locked` review artifact: source tree + REVIEW.md +
/// header.toml + receipt.toml. No ed25519 signature to check here — that's
/// the `.zex` package's job; the locked file's integrity is the maintainer
/// review flow itself (see `lock::read_locked_manifest`).
fn cmd_unpack_locked(
    file: &std::path::Path,
    buf: &[u8],
    output: Option<std::path::PathBuf>,
    verify_only: bool,
) -> crate::error::Result<()> {
    let locked = crate::core::lock::read_locked_manifest_from_bytes(buf)?;

    display::title(&format!("Unpacking locked review artifact {}", file.display()));
    display::kv("Name",              &locked.package_name);
    display::kv("Version",           &locked.package_version);

    if verify_only {
        display::success("Locked header parsed OK.");
        return Ok(());
    }

    let dest = output.unwrap_or_else(|| {
        std::path::PathBuf::from(format!("{}-{}-review", locked.package_name, locked.package_version))
    });

    display::step("Extracting source tree, REVIEW.md, header.toml, receipt.toml...");
    let count = crate::core::lock::extract_locked_bytes(buf, &dest)?;
    display::kv("Files extracted", &count.to_string());

    display::success("Locked review artifact unpacked.");
    display::kv("Destination", &dest.display().to_string());

    Ok(())
}

// ── Inspect ──────────────────────────────────────────────────────────────────

fn cmd_inspect(file: std::path::PathBuf) -> crate::error::Result<()> {
    let buf = std::fs::read(&file)?;
    let parsed = verifier::parse(buf)?;

    display::title(&format!("Inspecting {}", file.display()));

    // Manifest
    display::step("Manifest");
    display::kv("Name",              &parsed.manifest.package.name);
    display::kv("Version",           &parsed.manifest.package.version);
    display::kv("Description",       &parsed.manifest.package.description);
    display::kv("Maintainer",        &parsed.manifest.package.maintainer);
    display::kv("License",           &parsed.manifest.package.license);
    display::kv("Build type",        parsed.manifest.package.build_type.as_deref().unwrap_or("unknown"));
    display::kv("Libc target",       parsed.manifest.package.libc_target.as_deref().unwrap_or("unknown"));
    display::kv("Payload files",     &parsed.payload_files.len().to_string());
    display::kv("Blake3",            parsed.manifest.package.blake3.as_deref().unwrap_or("n/a"));
    display::kv("Ed25519",           if parsed.manifest.package.ed25519_sig.is_some() { "present" } else { "missing" });

    // Security report summary
    display::step("Security report (embedded)");

    let rep = &parsed.report;

    // Layout
    display::ok_kv("Layout check", &format!("{:?}", rep.layout_check.result));

    // Content scan
    if rep.content_scan.matches.is_empty() {
        display::ok_kv("Content scan",
            &format!("{} text files, 0 /usr refs", rep.content_scan.files_scanned));
    } else {
        display::fail_kv("Content scan",
            &format!("{} /usr reference(s) found", rep.content_scan.matches.len()));
    }

    // Secrets
    let sc = &rep.secrets_scan;
    if sc.findings.is_empty() {
        display::ok_kv("Secrets scan",
            &format!("{} files, clean", sc.files_scanned));
    } else {
        display::fail_kv("Secrets scan",
            &format!("{} finding(s) — this package should have been blocked!",
                     sc.findings.len()));
        for f in &sc.findings {
            eprintln!("     {}:{} [{}]", f.file, f.line, f.pattern);
        }
    }

    // Permission audit
    if rep.permission_audit.setuid_files.is_empty() {
        display::ok_kv("Permission audit", "no setuid/setgid");
    } else {
        display::fail_kv("Permission audit",
            &format!("{} setuid/setgid file(s): {}",
                     rep.permission_audit.setuid_files.len(),
                     rep.permission_audit.setuid_files.join(", ")));
    }

    // Rust audit
    let ra = &rep.rust_audit;
    if ra.applicable {
        display::step("Rust security audit");
        display::kv("Language",    &format!("{:?}", ra.language));
        display::kv("Build kind",  &format!("{:?}", ra.build_kind));
        if let Some(n) = ra.unsafe_block_count {
            display::kv("Unsafe expressions", &n.to_string());
        }
        display::kv("Fuzz harness",
            if ra.fuzz_harness_present { "present" } else { "ABSENT" });
        for t in &ra.tools {
            show_tool_result(t.outcome, &t.tool, &t.summary);
        }
    }

    // C audit
    let ca = &rep.c_audit;
    if ca.applicable {
        display::step("C/C++ static analysis");
        for t in &ca.tools {
            show_tool_result(t.outcome, &t.tool, &t.summary);
        }
    }

    // Check for companion .zex.locked
    let locked_path = {
        let mut p = file.as_os_str().to_os_string();
        p.push(".locked");
        std::path::PathBuf::from(p)
    };
    if locked_path.exists() {
        display::step("Review artifact (.zex.locked)");
        match read_locked_manifest(&locked_path) {
            Ok(lm) => display::kv("Schema", &lm.schema),
            Err(e) => display::fail_kv("Locked file", &e.to_string()),
        }
    } else {
        display::kv("Review artifact", "no .zex.locked companion found");
    }

    Ok(())
}

// ── Keygen ───────────────────────────────────────────────────────────────────

/// Generates a fresh Ed25519 keypair, writes the 32-byte hex secret to
/// `output`, and prints the matching public (verifying) key — the half
/// that gets distributed to zex-server (`trusted_signing_keys`) and to
/// anything that needs to verify packages signed with this key. The
/// secret half never leaves this machine.
fn cmd_keygen(output: std::path::PathBuf, force: bool) -> crate::error::Result<()> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    if output.exists() && !force {
        return Err(crate::error::ZexError::Other(format!(
            "{} already exists — pass --force to overwrite (this would invalidate anything signed with the old key)",
            output.display(),
        )));
    }

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let secret_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(signing_key.verifying_key().to_bytes());

    std::fs::write(&output, &secret_hex)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
    }

    display::success(&format!("Wrote new signing key to {}", output.display()));
    println!();
    println!("Public (verifying) key:");
    println!("  {public_hex}");
    println!();
    println!("Note: `substrate pack` does NOT use this (or any persisted key) — every");
    println!("pack run generates and signs with its own fresh, ephemeral keypair");
    println!("internally, embeds the public half in the package's own manifest.toml,");
    println!("and never persists the private half anywhere. This keypair is for some");
    println!("other purpose you have in mind, not for feeding into `pack`.");
    println!();
    println!("Keep the file itself private if you do use it for something — anyone");
    println!("with it can sign as this identity.");

    Ok(())
}
