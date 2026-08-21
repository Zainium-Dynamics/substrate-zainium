use crate::core::scanner::{ManifestIntegrityResult, PermissionAuditResult};
use crate::security::root_guard::{ContentScanResult, LayoutCheckResult};
use crate::security::secrets_scan::SecretsScanReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityReport {
    pub schema: String,
    pub layout_check: LayoutCheckResult,
    pub content_scan: ContentScanResult,
    pub manifest_integrity: ManifestIntegrityResult,
    pub permission_audit: PermissionAuditResult,
    pub secrets_scan: SecretsScanReport,
}

impl SecurityReport {
    pub fn new(
        layout_check: LayoutCheckResult,
        content_scan: ContentScanResult,
        manifest_integrity: ManifestIntegrityResult,
        permission_audit: PermissionAuditResult,
        secrets_scan: SecretsScanReport,
    ) -> Self {
        SecurityReport {
            schema: "zainium-security-report-v2".to_string(),
            layout_check,
            content_scan,
            manifest_integrity,
            permission_audit,
            secrets_scan,
        }
    }

    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

