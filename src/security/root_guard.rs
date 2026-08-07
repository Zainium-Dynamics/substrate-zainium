//! Enforces Zainium OS's filesystem layout policy at pack time.
//!
//! Zainium OS does not use the /usr merge. Any package whose archive
//! contains a `usr/` path, or whose text content references a `/usr/`
//! style path, does not represent a valid Zainium root and is rejected
//! before compression or signing happens.

use crate::error::{Result, ZexError};
use crate::utils::paths::{normalize_archive_path, references_usr_merge};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level directories considered valid on a Zainium root.
pub const ALLOWED_TOP_LEVEL: &[&str] = &[
    "bin", "sbin", "lib", "etc", "share", "var", "opt", "boot", "root", "home",
];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LayoutCheckResult {
    pub policy: String,
    pub result: CheckOutcome,
    pub rejected_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContentScanResult {
    pub description: String,
    pub files_scanned: usize,
    pub matches: Vec<ContentMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMatch {
    pub path: String,
    pub line: usize,
    pub excerpt: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CheckOutcome {
    #[default]
    Passed,
    Failed,
}

/// File extensions / known filenames treated as text and therefore
/// eligible for content scanning. Binaries are intentionally excluded —
/// string-matching inside compiled binaries is unreliable and produces
/// false positives, so we rely on the path-structure check for them.
const TEXT_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "conf", "cfg", "ini", "toml", "yaml", "yml", "json",
    "py", "pl", "rb", "service", "rules", "desktop", "txt", "md", "env",
];

const TEXT_FILENAMES_NO_EXT: &[&str] = &["Makefile", "makefile", "Dockerfile"];

fn is_text_candidate(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if TEXT_FILENAMES_NO_EXT.contains(&name) {
            return true;
        }
    }
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        return TEXT_EXTENSIONS.contains(&ext.to_lowercase().as_str());
    }
    false
}

/// Check a single archive-relative path against the layout policy.
/// Returns Err with a human-readable rejection message if it violates
/// the no-/usr-merge rule, or if its top-level directory is unrecognized.
pub fn check_path(raw_path: &str) -> Result<String> {
    let normalized = normalize_archive_path(raw_path)?;

    if references_usr_merge(&normalized) {
        return Err(ZexError::LayoutViolation(format!(
            "path '{}' found. Zainium OS does not use the /usr merge — \
             this package does not represent a valid Zainium root layout.",
            normalized
        )));
    }

    Ok(normalized)
}

/// Walk a source directory and validate every entry's path against the
/// layout policy. Returns Ok(()) only if every path passes. On the first
/// violation, returns an error describing exactly which path failed.
pub fn check_directory_layout(root: &Path) -> Result<LayoutCheckResult> {
    let mut rejected = Vec::new();

    for entry in walkdir::WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .to_string();

        if rel.is_empty() {
            continue;
        }

        if let Err(ZexError::LayoutViolation(msg)) = check_path(&rel) {
            rejected.push(format!("{} ({})", rel, msg));
        }
    }

    if rejected.is_empty() {
        Ok(LayoutCheckResult {
            policy: "zainium-no-usr-merge-v1".to_string(),
            result: CheckOutcome::Passed,
            rejected_paths: rejected,
        })
    } else {
        Err(ZexError::LayoutViolation(rejected.join("; ")))
    }
}

/// Scan text-like files under `root` for literal `/usr/` or `usr/` path
/// references in their content. This catches scripts/configs that
/// hardcode /usr paths even if the package's own directory tree is
/// laid out correctly.
pub fn scan_content_for_usr_refs(root: &Path) -> Result<ContentScanResult> {
    let mut files_scanned = 0usize;
    let mut matches = Vec::new();

    for entry in walkdir::WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        if !is_text_candidate(entry.path()) {
            continue;
        }

        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue, // not valid UTF-8 text, skip (treated as binary)
        };
        files_scanned += 1;

        for (idx, line) in content.lines().enumerate() {
            if line.contains("/usr/") || line.trim_start().starts_with("usr/") {
                let rel = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap_or(entry.path())
                    .to_string_lossy()
                    .to_string();
                matches.push(ContentMatch {
                    path: rel,
                    line: idx + 1,
                    excerpt: line.trim().chars().take(120).collect(),
                });
            }
        }
    }

    let result = ContentScanResult {
        description:
            "Text files scanned for literal '/usr' path references".to_string(),
        files_scanned,
        matches,
    };

    if !result.matches.is_empty() {
        let details: Vec<String> = result
            .matches
            .iter()
            .map(|m| format!("{}:{} -> {}", m.path, m.line, m.excerpt))
            .collect();
        return Err(ZexError::LayoutViolation(format!(
            "/usr reference(s) found in file content: {}",
            details.join("; ")
        )));
    }

    Ok(result)
}

/// Full layout policy enforcement: structure + content. Call this before
/// any compression/signing step. Returns the passing reports on success,
/// or an error describing the violation on failure (pack must abort).
///
/// `root` is the *package source dir* (containing `manifest.toml` +
/// `payload/`), not the payload itself — but `check_directory_layout`
/// must walk `root/payload`, not `root`, or the check is blind to the
/// only place a `/usr` merge violation can actually occur. Confirmed
/// live: a `payload/usr/bin/badfile` packed clean, reported "PASSED — no
/// /usr merge references," because `references_usr_merge` only matches a
/// path that *starts with* `"usr/"`, and every real entry's path here was
/// `source_dir`-relative (`"payload/usr/bin/badfile"`, which doesn't
/// start with `"usr/"` — it starts with `"payload/"`) rather than
/// `payload/`-relative (`"usr/bin/badfile"`, which does). Content
/// scanning stays on the full `root` — that's about text hardcoding
/// `/usr/` paths anywhere (hook scripts, docs), not directory structure,
/// so it isn't affected by the same bug.
pub fn enforce_layout_policy(
    root: &Path,
) -> Result<(LayoutCheckResult, ContentScanResult)> {
    let payload_dir = root.join("payload");
    let layout = check_directory_layout(&payload_dir)?;
    let content = scan_content_for_usr_refs(root)?;
    Ok((layout, content))
}
