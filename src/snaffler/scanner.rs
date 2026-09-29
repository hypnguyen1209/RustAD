use super::rules::{self, ContentMatch, Severity};

#[derive(Debug, Clone)]
pub struct ScanFinding {
    pub file_path: String,
    pub rule_name: String,
    pub severity: Severity,
    pub description: String,
    pub matched_text: String,
    pub line_number: Option<usize>,
}

pub fn scan_content(file_path: &str, content: &str) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let content_rules = rules::content_rules();

    for rule in content_rules {
        for (line_num, line) in content.lines().enumerate() {
            if let Some(m) = rule.pattern.find(line) {
                let matched = redact_secret(m.as_str());
                findings.push(ScanFinding {
                    file_path: file_path.to_string(),
                    rule_name: rule.name.to_string(),
                    severity: rule.severity,
                    description: rule.description.to_string(),
                    matched_text: matched,
                    line_number: Some(line_num + 1),
                });
                break;
            }
        }
    }
    findings
}

pub fn classify_file_extension(filename: &str) -> Option<(Severity, &'static str)> {
    let ext = filename.rsplit('.').next()?;
    rules::classify_extension(ext).map(|sev| (sev, "Sensitive file extension"))
}

pub fn classify_file_name(filename: &str) -> Option<(Severity, &'static str)> {
    let name = filename.rsplit('/').next().unwrap_or(filename);
    let name = name.rsplit('\\').next().unwrap_or(name);
    rules::classify_filename(name)
}

pub fn scan_file(file_path: &str, content: Option<&str>) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    let filename = file_path
        .rsplit('/')
        .next()
        .or_else(|| file_path.rsplit('\\').next())
        .unwrap_or(file_path);

    if let Some((sev, desc)) = classify_file_name(filename) {
        findings.push(ScanFinding {
            file_path: file_path.to_string(),
            rule_name: "filename_match".to_string(),
            severity: sev,
            description: desc.to_string(),
            matched_text: filename.to_string(),
            line_number: None,
        });
    }

    if let Some((sev, desc)) = classify_file_extension(filename) {
        findings.push(ScanFinding {
            file_path: file_path.to_string(),
            rule_name: "extension_match".to_string(),
            severity: sev,
            description: desc.to_string(),
            matched_text: filename.to_string(),
            line_number: None,
        });
    }

    if let Some(content) = content {
        findings.extend(scan_content(file_path, content));
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings
}

fn redact_secret(matched: &str) -> String {
    if let Some(pos) = matched.find('=').or_else(|| matched.find(':')) {
        let prefix = &matched[..=pos];
        format!("{}[REDACTED]", prefix)
    } else if matched.starts_with("-----BEGIN") {
        "-----BEGIN PRIVATE KEY [REDACTED]-----".to_string()
    } else if matched.starts_with("AKIA")
        || matched.starts_with("AGPA")
        || matched.starts_with("AROA")
        || matched.starts_with("ASIA")
    {
        format!("{}...[REDACTED]", &matched[..4.min(matched.len())])
    } else if matched.starts_with("xox") {
        "xox...[REDACTED]".to_string()
    } else {
        let safe_end = matched
            .char_indices()
            .nth(20)
            .map(|(i, _)| i)
            .unwrap_or(matched.len());
        format!("{}...", &matched[..safe_end])
    }
}

pub fn print_findings(findings: &[ScanFinding]) {
    if findings.is_empty() {
        return;
    }
    println!("--- Sensitive File Findings ({}) ---", findings.len());
    for f in findings {
        let line_info = f.line_number.map(|l| format!(":{}", l)).unwrap_or_default();
        println!(
            "  [{}] {} — {} ({}{})",
            f.severity, f.rule_name, f.description, f.file_path, line_info
        );
        if !f.matched_text.is_empty() {
            println!("    Match: {}", f.matched_text);
        }
    }
    println!();
}
