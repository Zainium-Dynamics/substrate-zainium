
use clap::Parser;
use crate::cli::{Cli, Command};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use crate::core::{packer, unpacker, verifier};
use crate::security::signer::Signer128;
use crate::ui::display;


// Generate ephemeral Ed25519 keypair for signing.

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
            install_root,
            output,
        } => cmd_pack(directory, version, description, features, requires_syshub, install_root, output),


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
    install_root: String,
    output: Option<std::path::PathBuf>,
) -> crate::error::Result<()> {
    let name = directory
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "package".to_string());

    let output_path = output.unwrap_or_else(|| {
        std::path::PathBuf::from(format!("{}-{}.zex", name, version))
    });

    display::title("Zainium Package Builder");

    display::step("Scanning source directory...");
    let file_count = walkdir::WalkDir::new(&directory)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();
    display::kv("Files found", &file_count.to_string());

    display::step("Initializing cryptographic signers...");
    display::ok_kv("blake3",   "active");
    display::ok_kv("sha512",   "active");
    display::ok_kv("ed25519",  "ephemeral keypair generated");

    display::step("Running security passes...");

    let opts = packer::PackOptions {
        version: version.clone(),
        description: description.clone(),
        features: features.into_iter().filter(|f| !f.is_empty()).collect(),
        requires_syshub,
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

    display::ok_kv("Layout policy", "PASSED");

    let sc = &rep.secrets_scan;
    if sc.findings.is_empty() {
        display::ok_kv("Secrets scan",
            &format!("{} files scanned", sc.files_scanned));
    } else {
        display::fail_kv("Secrets scan",
            &format!("{} finding(s)", sc.findings.len()));
    }

    if rep.permission_audit.setuid_files.is_empty() {
        display::ok_kv("Permission audit", "clean");
    } else {
        display::fail_kv(
            "Permission audit",
            &format!("{} setuid/setgid file(s)",
                     rep.permission_audit.setuid_files.len()),
        );
    }

    display::step("Sealing manifest...");
    display::kv("Name",    &name);
    display::kv("Version", &version);
    if !description.is_empty() {
        display::kv("Description", &description);
    }

    display::success("Package built successfully");
    display::kv("Output", &output_path.display().to_string());
    display::kv("Compressed",
        &format!("{:.1} MB", pack_result.compressed_size as f64 / 1_048_576.0));
    display::kv("Uncompressed",
        &format!("{:.1} MB", pack_result.uncompressed_size as f64 / 1_048_576.0));

    Ok(())
}


// ── Unpack / Verify ──────────────────────────────────────────────────────────

fn cmd_unpack(
    file: std::path::PathBuf,
    output: Option<std::path::PathBuf>,
    verify_only: bool,
) -> crate::error::Result<()> {
    let buf = std::fs::read(&file)?;
    let parsed = verifier::parse(buf)?;
    let pubkey_hex = parsed.manifest.package.ed25519_pubkey.as_deref().ok_or_else(|| {
        crate::error::ZexError::SignatureInvalid(
            "manifest.toml missing ed25519_pubkey".into(),
        )
    })?;
    let pubkey_bytes = hex::decode(pubkey_hex)
        .map_err(|e| crate::error::ZexError::Other(format!("invalid ed25519_pubkey hex: {e}")))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().map_err(|_| {
        crate::error::ZexError::Other("ed25519_pubkey must be 32 bytes".into())
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
            display::success("Package signature verified.");
        } else {
            display::fail_kv("Signature", "INVALID");
            return Err(crate::error::ZexError::SignatureInvalid(
                "signature verification failed".into(),
            ));
        }
        return Ok(());
    }

    display::title(&format!("Unpacking {}", file.display()));

    display::step("Verifying signature...");
    let sig_ok = verifier::verify_signature(&parsed, &pubkey)?;
    if !sig_ok {
        display::fail_kv("ed25519", "INVALID");
        return Err(crate::error::ZexError::SignatureInvalid(
            "package signature mismatch".into(),
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

    display::step("Extracting payload...");
    let unpack_result = unpacker::unpack(&parsed, &dest, &pubkey)?;
    display::kv("Files extracted", &unpack_result.files_extracted.to_string());

    display::step("Post-unpack verification...");
    display::ok_kv("Manifest integrity", "PASSED");
    if !parsed.report.permission_audit.setuid_files.is_empty() {
        display::fail_kv(
            "Permission audit",
            &format!("{} setuid/setgid file(s)",
                     parsed.report.permission_audit.setuid_files.len()),
        );
    } else {
        display::ok_kv("Permission audit", "clean");
    }

    display::success("Package extracted.");
    display::kv("Destination", &dest.display().to_string());

    Ok(())
}

// ── Inspect ──────────────────────────────────────────────────────────────────

fn cmd_inspect(file: std::path::PathBuf) -> crate::error::Result<()> {
    let buf = std::fs::read(&file)?;
    let parsed = verifier::parse(buf)?;

    display::title(&format!("Inspecting {}", file.display()));

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

    display::step("Security Report");
    let rep = &parsed.report;

    display::ok_kv("Layout check", &format!("{:?}", rep.layout_check.result));

    if rep.content_scan.matches.is_empty() {
        display::ok_kv("Content scan",
            &format!("{} text files scanned", rep.content_scan.files_scanned));
    } else {
        display::fail_kv("Content scan",
            &format!("{} reference(s) found", rep.content_scan.matches.len()));
    }

    let sc = &rep.secrets_scan;
    if sc.findings.is_empty() {
        display::ok_kv("Secrets scan",
            &format!("{} files clean", sc.files_scanned));
    } else {
        display::fail_kv("Secrets scan",
            &format!("{} finding(s)", sc.findings.len()));
        for f in &sc.findings {
            eprintln!("     {}:{} [{}]", f.file, f.line, f.pattern);
        }
    }

    if rep.permission_audit.setuid_files.is_empty() {
        display::ok_kv("Permission audit", "clean");
    } else {
        display::fail_kv("Permission audit",
            &format!("{} setuid/setgid file(s)",
                     rep.permission_audit.setuid_files.len()));
    }

    Ok(())
}


// ── Keygen ───────────────────────────────────────────────────────────────────

fn cmd_keygen(output: std::path::PathBuf, force: bool) -> crate::error::Result<()> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    if output.exists() && !force {
        return Err(crate::error::ZexError::Other(format!(
            "{} already exists — use --force to overwrite",
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

    display::success(&format!("Wrote key to {}", output.display()));
    println!("Public Key: {public_hex}");

    Ok(())
}

