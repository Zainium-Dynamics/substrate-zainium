// Layout policy enforcement.


use crate::error::{Result, ZexError};
use crate::utils::paths::{normalize_archive_path, references_usr_merge};
use serde::{Deserialize, Serialize};
use std::path::Path;

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

// Minimum run length to count as a "string" when scanning binary content --
// matches the default `strings -n 4` threshold, short enough to still catch
// "/usr/" (5 chars) on its own.
const MIN_BINARY_STRING_LEN: usize = 4;

// Pull printable-ASCII runs out of raw bytes, `strings`-style, for files
// that aren't valid UTF-8 text (ELF binaries, shared libraries, ...) --
// compiled-in fallback paths (XDG defaults, hardcoded exec() targets, etc.)
// live in there as plain string constants and are otherwise invisible to
// this scanner.
fn extract_printable_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::new();

    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' {
            current.push(b);
        } else {
            if current.len() >= MIN_BINARY_STRING_LEN {
                out.push(String::from_utf8_lossy(&current).into_owned());
            }
            current.clear();
        }
    }
    if current.len() >= MIN_BINARY_STRING_LEN {
        out.push(String::from_utf8_lossy(&current).into_owned());
    }
    out
}

pub fn check_path(raw_path: &str) -> Result<String> {
    let normalized = normalize_archive_path(raw_path)?;

    if references_usr_merge(&normalized) {
        return Err(ZexError::LayoutViolation(format!(
            "path '{}' found: Zainium OS layout policy rejects /usr merge paths.",
            normalized
        )));
    }

    Ok(normalized)
}

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

pub fn scan_content_for_usr_refs(root: &Path) -> Result<ContentScanResult> {
    let mut files_scanned = 0usize;
    let mut matches = Vec::new();

    for entry in walkdir::WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        let Ok(bytes) = std::fs::read(path) else { continue };
        files_scanned += 1;

        // Valid UTF-8 (scripts, configs, anything text -- no extension
        // allowlist, so an extensionless launcher script like
        // `start-cosmic` gets the same scrutiny as a `.sh` file) gets
        // scanned line-by-line for a real excerpt + line number.
        if let Ok(content) = std::str::from_utf8(&bytes) {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("/usr/") || line.trim_start().starts_with("usr/") {
                    matches.push(ContentMatch {
                        path: rel.clone(),
                        line: idx + 1,
                        excerpt: line.trim().chars().take(120).collect(),
                    });
                }
            }
            continue;
        }

        // Not valid UTF-8 -- likely an ELF binary or shared library.
        // Pull out printable-ASCII string constants and check those
        // instead (a compiled-in fallback path is just as real a leak
        // as one sitting in a shell script).
        for s in extract_printable_strings(&bytes) {
            if s.contains("/usr/") {
                matches.push(ContentMatch {
                    path: rel.clone(),
                    line: 0,
                    excerpt: format!("(binary string) {}", s.chars().take(120).collect::<String>()),
                });
            }
        }
    }

    let result = ContentScanResult {
        description: "Files scanned (text + binary strings) for /usr path references".to_string(),
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

// Enforce layout policy across package directory structure and file contents.

pub fn enforce_layout_policy(
    root: &Path,
) -> Result<(LayoutCheckResult, ContentScanResult)> {
    let payload_dir = root.join("payload");
    let layout = check_directory_layout(&payload_dir)?;
    let content = scan_content_for_usr_refs(root)?;
    Ok((layout, content))
}

