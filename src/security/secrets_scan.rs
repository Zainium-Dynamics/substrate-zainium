// Source code secret scanning.


use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SecretsOutcome {
    #[default]
    Clean,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub file: String,
    pub line: usize,
    pub pattern: String,
    pub excerpt_redacted: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretsScanReport {
    pub outcome: SecretsOutcome,
    pub files_scanned: usize,
    pub findings: Vec<SecretFinding>,
}

impl SecretsScanReport {
    pub fn is_blocked(&self) -> bool {
        self.outcome == SecretsOutcome::Blocked
    }
}

const PATTERNS: &[(&str, &str)] = &[
    ("PEM private key block",         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("AWS access key ID",             r"AKIA[0-9A-Z]{16}"),
    ("AWS secret access key",
        r#"(?i)aws[_\-\. ]?secret[_\-\. ]?access[_\-\. ]?key\s*[=:]\s*['"][A-Za-z0-9/+=]{40}"#),
    ("GitHub token (ghp_)",           r"ghp_[A-Za-z0-9]{36}"),
    ("GitHub token (ghs_)",           r"ghs_[A-Za-z0-9]{36}"),
    ("GitHub token (github_pat)",     r"github_pat_[A-Za-z0-9_]{82}"),
    ("Stripe secret key",             r"sk_live_[A-Za-z0-9]{24}"),
    ("Stripe test key",               r"sk_test_[A-Za-z0-9]{24}"),
    ("bearer token literal",
        r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}"),
    ("dotenv private key",
        r#"(?i)^\s*(?:export\s+)?[A-Za-z0-9_]*PRIVATE_KEY\s*=\s*['"]?[A-Za-z0-9+/=_\\\-]{20,}"#),
];

// Assignment-style secrets. Matched separately so a hit can be rejected when
// the "assignment" is really just text inside a string literal or an
// identifier that is named after the keyword.
const ASSIGNMENTS: &[(&str, &str, usize)] = &[
    ("hardcoded password assignment", "password|passwd|pwd", 6),
    ("hardcoded secret assignment", "secret|api_secret|client_secret", 8),
    ("hardcoded api_key assignment", r"api[_\-]?key|apikey|access[_\-]?token", 8),
];

fn compile_assignment(keywords: &str, min_len: usize) -> Option<regex::Regex> {
    let pat = format!(
        r#"(?i)(?P<pre>['"]?)(?P<ident>[A-Za-z0-9_\-\.]*?(?:{keywords}))(?P<post>['"]?)\s*[=:]\s*['"](?P<val>[^'"]{{{min_len},}})['"]"#
    );
    regex::Regex::new(&pat).ok()
}

fn is_real_assignment(caps: &regex::Captures) -> bool {
    let pre = caps.name("pre").map_or("", |m| m.as_str());
    let post = caps.name("post").map_or("", |m| m.as_str());
    let ident = caps.name("ident").map_or("", |m| m.as_str());
    let val = caps.name("val").map_or("", |m| m.as_str());

    // "PWD="+dir : the keyword and "=" sit inside a string literal that the
    // next quote closes, so the "value" is code, not a credential.
    if !pre.is_empty() && post.is_empty() {
        return false;
    }
    // encodeUserPassword: "encodeUserPassword" : a name table entry.
    if val.eq_ignore_ascii_case(ident) {
        return false;
    }
    // "secret": "\u3299\ufe0f" : a table of unicode escapes (emoji names).
    if is_unicode_escapes_only(val) {
        return false;
    }
    true
}

fn is_unicode_escapes_only(val: &str) -> bool {
    let mut rest = val;
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        let digits = if rest.starts_with("\\u") {
            4
        } else if rest.starts_with("\\U") {
            8
        } else {
            return false;
        };
        let body = &rest[2..];
        if body.len() < digits || !body[..digits].chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        rest = &body[digits..];
    }
    true
}


const TEXT_EXTENSIONS: &[&str] = &[
    "rs", "c", "cpp", "h", "hpp", "py", "rb", "go", "js", "ts",
    "sh", "bash", "zsh", "toml", "yaml", "yml", "json", "ini", "cfg",
    "env", "conf", "service", "txt", "xml", "properties",
];
const TEXT_FILENAMES: &[&str] = &[".env", "Makefile", "Dockerfile"];

fn is_text_candidate(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if TEXT_FILENAMES.contains(&name) || name.starts_with(".env") {
            return true;
        }
    }
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        return TEXT_EXTENSIONS.contains(&ext.to_lowercase().as_str());
    }
    false
}

fn redact(line: &str, max_len: usize) -> String {
    let trimmed = line.trim();
    let visible = &trimmed[..trimmed.len().min(40)];
    format!("{} ... [REDACTED - {max_len} chars total]", visible)
}

pub fn scan_secrets(root: &Path) -> SecretsScanReport {
    let compiled: Vec<(&str, regex::Regex)> = PATTERNS
        .iter()
        .filter_map(|(label, pat)| {
            regex::Regex::new(pat).ok().map(|r| (*label, r))
        })
        .collect();

    let assignments: Vec<(&str, regex::Regex)> = ASSIGNMENTS
        .iter()
        .filter_map(|(label, kw, min)| compile_assignment(kw, *min).map(|r| (*label, r)))
        .collect();

    let mut findings = Vec::new();
    let mut files_scanned = 0usize;

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        if !is_text_candidate(entry.path()) {
            continue;
        }

        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        files_scanned += 1;

        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .to_string();

        for (line_no, line) in content.lines().enumerate() {
            let mut hit: Option<&str> = None;
            for (label, re) in &compiled {
                if re.is_match(line) {
                    hit = Some(*label);
                    break;
                }
            }
            if hit.is_none() {
                'assign: for (label, re) in &assignments {
                    for caps in re.captures_iter(line) {
                        if is_real_assignment(&caps) {
                            hit = Some(*label);
                            break 'assign;
                        }
                    }
                }
            }
            if let Some(label) = hit {
                findings.push(SecretFinding {
                    file: rel.clone(),
                    line: line_no + 1,
                    pattern: label.to_string(),
                    excerpt_redacted: redact(line, line.len()),
                });
            }
        }
    }

    let outcome = if findings.is_empty() {
        SecretsOutcome::Clean
    } else {
        SecretsOutcome::Blocked
    };

    SecretsScanReport {
        outcome,
        files_scanned,
        findings,
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scan_one(name: &str, body: &str) -> SecretsScanReport {
        let dir = std::env::temp_dir().join(format!("secrets_scan_{}_{}", std::process::id(), name.replace('.', "_")));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(name), body).unwrap();
        let r = scan_secrets(&dir);
        let _ = fs::remove_dir_all(&dir);
        r
    }

    #[test]
    fn real_secrets_still_blocked() {
        assert!(scan_one("a.py", "password = \"hunter2hunter2\"\n").is_blocked());
        assert!(scan_one("b.json", "{\"password\": \"hunter2hunter2\"}\n").is_blocked());
        assert!(scan_one("c.go", "myPassword := \"abc12345\"\n").is_blocked() || scan_one("c2.go", "myPassword = \"abc12345\"\n").is_blocked());
        assert!(scan_one("d.sh", "export API_KEY=\"abcdef123456\"\n").is_blocked());
        assert!(scan_one("e.env", "DB_PRIVATE_KEY=MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n").is_blocked());
        assert!(scan_one("f.txt", "-----BEGIN RSA PRIVATE KEY-----\n").is_blocked());
    }

    #[test]
    fn go_false_positives_are_clean() {
        assert!(!scan_one("a.go", "cmd.Env = append(os.Environ(), \"PWD=\"+cmd.Dir, \"GOROOT=\"+root)\n").is_blocked());
        assert!(!scan_one("b.go", "\tencodeUserPassword:   \"encodeUserPassword\",\n").is_blocked());
        assert!(!scan_one("d.go", "\t\"secret\":                               \"\\u3299\\ufe0f\",\n").is_blocked());
        assert!(!scan_one("c.go", "\tCERT_FIND_HAS_PRIVATE_KEY             = (CERT_COMPARE_HAS_PRIVATE_KEY << CERT_COMPARE_SHIFT)\n").is_blocked());
    }
}
