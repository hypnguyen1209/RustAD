use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Green = 1,
    Yellow = 2,
    Red = 3,
    Black = 4,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Severity::Green => write!(f, "Green"),
            Severity::Yellow => write!(f, "Yellow"),
            Severity::Red => write!(f, "Red"),
            Severity::Black => write!(f, "Black"),
        }
    }
}

pub struct ContentRule {
    pub name: &'static str,
    pub pattern: &'static Lazy<Regex>,
    pub severity: Severity,
    pub description: &'static str,
}

pub struct ExtensionRule {
    pub extensions: &'static [&'static str],
    pub severity: Severity,
    pub description: &'static str,
}

pub struct FilenameRule {
    pub names: &'static [&'static str],
    pub severity: Severity,
    pub description: &'static str,
}

// ── Content-matching regex patterns ─────────────────────────────────────────

static RE_PASSWORD_IN_CODE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)passw(?:or)?d\s*[=:]\s*['"][^'"]{4,}"#).unwrap()
});

static RE_API_KEY_IN_CODE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:api[_\-]?key|apikey|api_secret|client_secret|app_secret)\s*[=:]\s*['"][^'"]{4,}"#).unwrap()
});

static RE_AWS_ACCESS_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z2-7]{12,16}").unwrap()
});

static RE_PRIVATE_KEY_HEADER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN\s*(?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY").unwrap()
});

static RE_CONNECTION_STRING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:connection\s*string|data\s*source).{0,100}(?:password|pwd)\s*=").unwrap()
});

static RE_SLACK_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"xox[pboa]-[0-9]{10,}").unwrap()
});

static RE_SQL_CRED_CREATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)CREATE\s+(?:USER|LOGIN).{0,200}(?:IDENTIFIED BY|WITH PASSWORD)").unwrap()
});

static RE_PS_CREDENTIAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:-SecureString|-AsPlainText|\[Net\.NetworkCredential\]::new)").unwrap()
});

static RE_CMD_CREDENTIAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:net\s+user\s+\S+\s+\S+|psexec.*\s-p\s|net\s+use.*/user:|cmdkey\s+/add)").unwrap()
});

static RE_VIEWSTATE_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:validationkey|decryptionkey)\s*=\s*['"][0-9A-Fa-f]{32,}"#).unwrap()
});

static RE_UNATTEND_PASSWORD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)<(?:Administrator)?Password>.*<Value>[^<]+</Value>").unwrap()
});

static RE_RDP_PASSWORD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"password 51:b:").unwrap()
});

static RE_NET_CONFIG_CRED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:enable\s+password|snmp-server\s+community\s+\S+\s+RW)").unwrap()
});

static RE_OAUTH_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:oauth|bearer|token)\s*[=:]\s*['"][a-zA-Z0-9_\-\.]{20,}"#).unwrap()
});

static RE_S3_URI: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"s3a?://[a-zA-Z0-9\-\+/]{2,}").unwrap()
});

static RE_DB_CONN_STRING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:mysql_connect|pg_connect|psycopg2\.connect|\.getConnection\s*\(\s*"jdbc:)"#).unwrap()
});

static RE_GPP_CPASSWORD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)cpassword\s*=\s*"[^"]+"#).unwrap()
});

static RE_GENERIC_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:secret|credential|auth_token|access_token)\s*[=:]\s*['"][^'"]{8,}"#).unwrap()
});

// ── Rule collections ────────────────────────────────────────────────────────

static CONTENT_RULES: &[ContentRule] = &[
    ContentRule {
        name: "GPP_cpassword",
        pattern: &RE_GPP_CPASSWORD,
        severity: Severity::Black,
        description: "GPP cpassword (MS14-025) — AES-encrypted password with published key",
    },
    ContentRule {
        name: "PrivateKey",
        pattern: &RE_PRIVATE_KEY_HEADER,
        severity: Severity::Red,
        description: "PEM private key header (RSA, DSA, EC, OpenSSH, PGP)",
    },
    ContentRule {
        name: "PasswordInCode",
        pattern: &RE_PASSWORD_IN_CODE,
        severity: Severity::Red,
        description: "Hardcoded password assignment in source/config",
    },
    ContentRule {
        name: "ApiKeyInCode",
        pattern: &RE_API_KEY_IN_CODE,
        severity: Severity::Red,
        description: "API key or client secret in source/config",
    },
    ContentRule {
        name: "AwsAccessKey",
        pattern: &RE_AWS_ACCESS_KEY,
        severity: Severity::Red,
        description: "AWS access key ID (AKIA/AGPA/AROA/ASIA prefix)",
    },
    ContentRule {
        name: "ConnectionString",
        pattern: &RE_CONNECTION_STRING,
        severity: Severity::Red,
        description: "Database connection string with embedded password",
    },
    ContentRule {
        name: "SlackToken",
        pattern: &RE_SLACK_TOKEN,
        severity: Severity::Red,
        description: "Slack API token (xoxp/xoxb/xoxo/xoxa)",
    },
    ContentRule {
        name: "SqlCredCreate",
        pattern: &RE_SQL_CRED_CREATE,
        severity: Severity::Red,
        description: "SQL CREATE USER/LOGIN with password",
    },
    ContentRule {
        name: "PsCredential",
        pattern: &RE_PS_CREDENTIAL,
        severity: Severity::Red,
        description: "PowerShell credential handling (SecureString/PlainText/NetworkCredential)",
    },
    ContentRule {
        name: "CmdCredential",
        pattern: &RE_CMD_CREDENTIAL,
        severity: Severity::Red,
        description: "Credential in cmd/batch (net user, psexec -p, net use /user, cmdkey)",
    },
    ContentRule {
        name: "ViewstateKey",
        pattern: &RE_VIEWSTATE_KEY,
        severity: Severity::Red,
        description: "ASP.NET machineKey (validationKey/decryptionKey)",
    },
    ContentRule {
        name: "UnattendPassword",
        pattern: &RE_UNATTEND_PASSWORD,
        severity: Severity::Red,
        description: "Cleartext password in unattend.xml / AutoUnattend.xml",
    },
    ContentRule {
        name: "RdpPassword",
        pattern: &RE_RDP_PASSWORD,
        severity: Severity::Red,
        description: "Encrypted RDP password blob (password 51:b:)",
    },
    ContentRule {
        name: "NetConfigCred",
        pattern: &RE_NET_CONFIG_CRED,
        severity: Severity::Red,
        description: "Network device credential (enable password, SNMP community RW)",
    },
    ContentRule {
        name: "DbConnString",
        pattern: &RE_DB_CONN_STRING,
        severity: Severity::Red,
        description: "Database connection function with inline credentials",
    },
    ContentRule {
        name: "OAuthToken",
        pattern: &RE_OAUTH_TOKEN,
        severity: Severity::Yellow,
        description: "OAuth/bearer/token value in code or config",
    },
    ContentRule {
        name: "S3Uri",
        pattern: &RE_S3_URI,
        severity: Severity::Yellow,
        description: "S3 bucket URI (potential data exposure)",
    },
    ContentRule {
        name: "GenericSecret",
        pattern: &RE_GENERIC_SECRET,
        severity: Severity::Yellow,
        description: "Generic secret/credential/token assignment",
    },
];

static EXTENSION_BLACK: ExtensionRule = ExtensionRule {
    extensions: &[
        "ppk", "kdbx", "kdb", "psafe3", "kwallet",
        "keychain", "agilekeychain", "cred",
    ],
    severity: Severity::Black,
    description: "Credential vault / SSH key / keychain file",
};

static EXTENSION_RED: ExtensionRule = ExtensionRule {
    extensions: &[
        "pfx", "pem", "der", "p12", "pk12", "pkcs12",
        "dmp", "vmdk", "vdi", "vhd", "vhdx",
    ],
    severity: Severity::Red,
    description: "Certificate/private key or memory dump / disk image",
};

static EXTENSION_YELLOW: ExtensionRule = ExtensionRule {
    extensions: &[
        "mdf", "sdf", "sqldump", "bak", "keytab",
        "ccache", "pcap", "cap", "pcapng",
    ],
    severity: Severity::Yellow,
    description: "Database dump / Kerberos keytab or ccache / network capture",
};

static EXTENSION_RULES: &[&ExtensionRule] = &[
    &EXTENSION_BLACK,
    &EXTENSION_RED,
    &EXTENSION_YELLOW,
];

static FILENAME_BLACK: FilenameRule = FilenameRule {
    names: &[
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        "NTDS.DIT", "ntds.dit",
        "SYSTEM", "SAM", "SECURITY",
        "shadow", "pwd.db", "passwd",
        ".tugboat",
    ],
    severity: Severity::Black,
    description: "SSH private key / AD database / system credential store",
};

static FILENAME_RED: FilenameRule = FilenameRule {
    names: &[
        "passwords.txt", "pass.txt", "accounts.txt", "secrets.txt",
        "passwords.doc", "passwords.docx", "passwords.xls", "passwords.xlsx",
        ".git-credentials", "git-credentials",
        "web.config", "appsettings.json", "appsettings.Development.json",
        "BitlockerLAPSPasswords.csv",
    ],
    severity: Severity::Red,
    description: "Password list / git credentials / app config with secrets",
};

static FILENAME_YELLOW: FilenameRule = FilenameRule {
    names: &[
        "unattend.xml", "Unattend.xml",
        "Autounattend.xml", "autounattend.xml",
        "customsettings.ini", "CustomSettings.ini",
        "sysprep.xml", "sysprep.inf",
    ],
    severity: Severity::Yellow,
    description: "Deployment config (may contain cleartext credentials)",
};

static FILENAME_GREEN: FilenameRule = FilenameRule {
    names: &[
        ".bash_history", ".zsh_history", ".sh_history",
        "ConsoleHost_History.txt",
        ".irb_history", ".python_history",
        ".psql_history", ".mysql_history",
    ],
    severity: Severity::Green,
    description: "Shell/command history (may contain typed credentials)",
};

static FILENAME_RULES: &[&FilenameRule] = &[
    &FILENAME_BLACK,
    &FILENAME_RED,
    &FILENAME_YELLOW,
    &FILENAME_GREEN,
];

// ── Public API ──────────────────────────────────────────────────────────────

pub fn content_rules() -> &'static [ContentRule] {
    CONTENT_RULES
}

pub fn extension_rules() -> &'static [&'static ExtensionRule] {
    EXTENSION_RULES
}

pub fn filename_rules() -> &'static [&'static FilenameRule] {
    FILENAME_RULES
}

pub fn classify_extension(ext: &str) -> Option<Severity> {
    let lower = ext.trim_start_matches('.').to_lowercase();
    for rule in EXTENSION_RULES {
        if rule.extensions.iter().any(|e| *e == lower) {
            return Some(rule.severity);
        }
    }
    None
}

pub fn classify_filename(name: &str) -> Option<(Severity, &'static str)> {
    for rule in FILENAME_RULES {
        if rule.names.iter().any(|n| name.ends_with(n) || name == *n) {
            return Some((rule.severity, rule.description));
        }
    }
    None
}

pub fn scan_content(text: &str) -> Vec<ContentMatch> {
    let mut matches = Vec::new();
    for rule in CONTENT_RULES {
        if let Some(m) = rule.pattern.find(text) {
            let start = m.start().saturating_sub(20);
            let end = (m.end() + 20).min(text.len());
            let context = &text[start..end];
            matches.push(ContentMatch {
                rule_name: rule.name,
                severity: rule.severity,
                description: rule.description,
                matched: m.as_str().to_string(),
                context: context.to_string(),
                offset: m.start(),
            });
        }
    }
    matches.sort_by(|a, b| b.severity.cmp(&a.severity));
    matches
}

#[derive(Debug, Clone)]
pub struct ContentMatch {
    pub rule_name: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    pub matched: String,
    pub context: String,
    pub offset: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_password_in_code() {
        let text = r#"config.password = "SuperSecret123""#;
        let hits = scan_content(text);
        assert!(!hits.is_empty());
        assert!(hits.iter().any(|h| h.rule_name == "PasswordInCode"));
    }

    #[test]
    fn detect_aws_key() {
        let text = "aws_key = AKIAIOSFODNN7EXAMPLE";
        let hits = scan_content(text);
        assert!(hits.iter().any(|h| h.rule_name == "AwsAccessKey"));
    }

    #[test]
    fn detect_private_key() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let hits = scan_content(text);
        assert!(hits.iter().any(|h| h.rule_name == "PrivateKey"));
    }

    #[test]
    fn detect_gpp_cpassword() {
        let text = r#"cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw""#;
        let hits = scan_content(text);
        assert!(hits.iter().any(|h| h.rule_name == "GPP_cpassword"));
        assert!(hits.iter().any(|h| h.severity == Severity::Black));
    }

    #[test]
    fn detect_connection_string() {
        let text = r#"Data Source=srv01;Initial Catalog=mydb;User Id=sa;Password=P@ssw0rd"#;
        let hits = scan_content(text);
        assert!(hits.iter().any(|h| h.rule_name == "ConnectionString"));
    }

    #[test]
    fn detect_slack_token() {
        let text = "token=xoxb-9999999999";  // minimal match for regex test
        let hits = scan_content(text);
        assert!(hits.iter().any(|h| h.rule_name == "SlackToken"));
    }

    #[test]
    fn classify_ppk_extension() {
        assert_eq!(classify_extension("ppk"), Some(Severity::Black));
        assert_eq!(classify_extension(".kdbx"), Some(Severity::Black));
        assert_eq!(classify_extension("pfx"), Some(Severity::Red));
        assert_eq!(classify_extension("pcap"), Some(Severity::Yellow));
        assert_eq!(classify_extension("txt"), None);
    }

    #[test]
    fn classify_sensitive_filenames() {
        let (sev, _) = classify_filename("id_rsa").unwrap();
        assert_eq!(sev, Severity::Black);
        let (sev, _) = classify_filename("passwords.txt").unwrap();
        assert_eq!(sev, Severity::Red);
        let (sev, _) = classify_filename("unattend.xml").unwrap();
        assert_eq!(sev, Severity::Yellow);
        assert!(classify_filename("readme.md").is_none());
    }

    #[test]
    fn no_false_positive_on_benign() {
        let text = "This is a normal log message with no secrets.";
        let hits = scan_content(text);
        assert!(hits.is_empty());
    }

    #[test]
    fn detect_unattend_password() {
        let text = r#"<AdministratorPassword><Value>MyP@ss123</Value></AdministratorPassword>"#;
        let hits = scan_content(text);
        assert!(hits.iter().any(|h| h.rule_name == "UnattendPassword"));
    }

    #[test]
    fn detect_ps_credential() {
        let text = r#"$cred = ConvertTo-SecureString "password" -AsPlainText -Force"#;
        let hits = scan_content(text);
        assert!(hits.iter().any(|h| h.rule_name == "PsCredential"));
    }
}
