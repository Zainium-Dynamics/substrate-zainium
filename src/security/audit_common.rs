// Shared audit primitives and report structures.


use serde::{Deserialize, Serialize};
use std::path::Path;

// Check if entry_path relative to root is inside payload/.

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
            "{}\n... [truncated, {} bytes total]",
            &s[..OUTPUT_EXCERPT_LIMIT],
            s.len()
        )
    }
}

pub trait LanguageAudit {
    fn language_name(&self) -> &'static str;
    fn has_failures(&self) -> bool;
    fn tools(&self) -> &[AuditToolResult];

    fn failure_detail(&self) -> String {
        self.tools()
            .iter()
            .filter(|t| t.outcome == ToolOutcome::Failed)
            .map(|t| format!("{}: {}", t.tool, t.summary))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

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

