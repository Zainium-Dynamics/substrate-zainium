//! Shared types used across all language-specific audit modules.
//! Single source of truth — no duplication across rust_audit/c_audit/etc.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// True if `entry_path` (walked from a package's source dir root) falls
/// under `payload/` — the packaged build *output*, never source code for
/// security-audit purposes. Confirmed live: packing a real staged GCC
/// build blocked with a false-positive clang-tidy failure because the
/// audit walked into `payload/include/c++/...` (GCC's own shipped
/// standard-library headers) and tried to lint them as if they were the
/// packager's own source. Every source-review scanner (secrets, Rust
/// audit, C audit) should skip anything under `payload/`; layout-policy
/// scanning (`root_guard.rs`) is a different concern — payload content
/// *is* what it's checking — and doesn't use this.
pub fn is_under_payload(root: &Path, entry_path: &Path) -> bool {
    entry_path
        .strip_prefix(root)
        .map(|rel| rel.starts_with("payload"))
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolOutcome {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditToolResult {
    pub tool: String,
    pub command: String,
    pub outcome: ToolOutcome,
    pub summary: String,
    /// Truncated raw output, kept short enough to embed in report without
    /// bloating the .zex. Full output belongs in build logs.
    pub output_excerpt: String,
}

impl AuditToolResult {
    pub fn skipped(tool: impl Into<String>, command: impl Into<String>, reason: impl Into<String>) -> Self {
        AuditToolResult {
            tool: tool.into(),
            command: command.into(),
            outcome: ToolOutcome::Skipped,
            summary: reason.into(),
            output_excerpt: String::new(),
        }
    }
}

pub const OUTPUT_EXCERPT_LIMIT: usize = 4000;

pub fn truncate_output(s: &str) -> String {
    if s.len() <= OUTPUT_EXCERPT_LIMIT {
        s.to_string()
    } else {
        format!(
            "{}\n... [truncated, {} bytes total — see build logs for full output]",
            &s[..OUTPUT_EXCERPT_LIMIT],
            s.len()
        )
    }
}

/// Implemented by every per-language audit report (`RustAuditReport`,
/// `CAuditReport`, ...) so `packer.rs` can gate packing on "did any
/// applicable language audit fail" without a hardcoded `if` per language.
/// Previously C-audit failures were computed but never checked here — only
/// Rust's `has_failures()` was ever called, an asymmetry with no
/// justification. Adding a third language's audit now means implementing
/// this trait and adding it to the list `packer.rs` iterates, not writing
/// a new hardcoded blocking check.
pub trait LanguageAudit {
    fn language_name(&self) -> &'static str;
    fn has_failures(&self) -> bool;
    fn tools(&self) -> &[AuditToolResult];

    /// Formatted detail of every failed tool, for the packing-abort error
    /// message — generic over any implementer, so a new language doesn't
    /// need its own copy of this formatting.
    fn failure_detail(&self) -> String {
        self.tools()
            .iter()
            .filter(|t| t.outcome == ToolOutcome::Failed)
            .map(|t| format!("{}: {}", t.tool, t.summary))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Abort packing if any applicable language audit failed. Add a new
/// language by implementing [`LanguageAudit`] for its report type and
/// including it in the slice passed here — nothing else to change.
pub fn enforce_language_audits(audits: &[&dyn LanguageAudit]) -> Result<(), String> {
    for audit in audits {
        if audit.has_failures() {
            return Err(format!(
                "{} security audit failed — package NOT built: {}",
                audit.language_name(),
                audit.failure_detail()
            ));
        }
    }
    Ok(())
}

pub fn tool_on_path(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
