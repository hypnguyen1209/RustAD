use super::*;
use std::error::Error;
use std::io::Write;

pub fn print_report(report: &AnalysisReport, export_format: Option<&str>, output_dir: &str) {
    println!("\n{}", "=".repeat(80));
    println!("{:^80}", "ATTACK SURFACE ANALYSIS");
    println!("{}\n", "=".repeat(80));

    print_health(&report.health);
    print_section_findings("Kerberoastable Accounts", &report.kerberoastable, 30);
    print_section_findings("AS-REP Roastable Accounts", &report.asrep_roastable, 30);
    print_section_findings("DCSync Rights (CRITICAL)", &report.dcsync, 20);
    print_section_findings(
        "Dangerous Permissions on High-Value Targets",
        &report.dangerous_perms,
        40,
    );
    print_section_findings(
        "Unconstrained Delegation (non-DC)",
        &report.unconstrained,
        20,
    );
    print_adcs(&report.adcs);
    print_section_findings(
        "RBCD (Resource-Based Constrained Delegation)",
        &report.rbcd,
        20,
    );
    print_section_findings(
        "Shadow Credentials (msDS-KeyCredentialLink)",
        &report.shadow_creds,
        20,
    );
    print_section_findings("Constrained Delegation", &report.constrained_deleg, 20);
    print_section_findings("GPO Abuse (writable by non-default)", &report.gpo_abuse, 20);
    print_section_findings("Domain Trusts", &report.trust_info, 20);
    print_section_findings(
        "Deep Group Nesting (>3 hops to HV)",
        &report.deep_nesting,
        20,
    );
    print_section_findings("DNS Zone Abuse (ADIDNS)", &report.dns_abuse, 20);
    print_section_findings("SCCM/MECM Infrastructure", &report.sccm_info, 20);
    print_section_findings("DPAPI Backup Key Exposure", &report.dpapi_exposure, 20);
    print_section_findings("AdminSDHolder Abuse", &report.adminsdholder, 20);
    print_section_findings(
        "Exchange Permissions (WriteDacl on Domain)",
        &report.exchange_perms,
        20,
    );
    print_section_findings("NTLM Coercion Targets", &report.coerce_targets, 20);
    print_section_findings(
        "Print Spooler (SpoolSample/PrinterBug)",
        &report.print_spooler,
        20,
    );
    print_section_findings("LAPS Deployment", &report.laps_status, 20);
    print_section_findings("Machine Account Quota", &report.machine_quota, 10);
    print_section_findings(
        "Pre-Windows 2000 Compatible Access",
        &report.pre_2000_access,
        10,
    );
    print_section_findings(
        "Credential Exposure (Privileged Roastable)",
        &report.cred_exposure,
        20,
    );
    print_section_findings("NTLM Relay Targets", &report.ntlm_relay, 20);
    print_section_findings(
        "GPP Password Exposure (MS14-025)",
        &report.gpp_passwords,
        20,
    );
    print_section_findings("SMB Signing", &report.smb_signing, 5);
    print_section_findings("LDAP Signing", &report.ldap_signing, 5);
    print_section_findings("Privileged Users Summary", &report.priv_summary, 5);
    print_section_findings("Stale Computer Accounts", &report.stale_computers, 5);
    print_section_findings("Coercion Attack Paths", &report.coercion_paths, 20);
    print_section_findings("Delegation Overview", &report.delegation_overview, 30);
    print_section_findings("Domain Recon Summary", &report.recon_summary, 5);
    print_section_findings(
        "Foreign Users (cross-domain membership)",
        &report.foreign_user,
        20,
    );
    print_section_findings("Foreign Group Members", &report.foreign_group, 20);
    print_section_findings("GPO Local Group Modification", &report.gpo_local, 20);
    print_section_findings(
        "Local Admin Targets (lateral movement)",
        &report.local_admin_targets,
        30,
    );
    print_section_findings(
        "Exchange Server Infrastructure",
        &report.exchange_servers,
        10,
    );
    print_section_findings("gMSA Password Exposure", &report.gmsa, 20);
    print_section_findings(
        "RBCD Configurable (can set delegation)",
        &report.rbcd_config,
        20,
    );
    print_section_findings(
        "Shadow Credentials via WriteOwner",
        &report.shadow_owner,
        20,
    );
    print_section_findings("Stale User Accounts (>90 days)", &report.stale_users, 20);
    print_section_findings("Password Age Audit (>1 year)", &report.pwd_age, 20);
    print_section_findings("Account Expiration Audit", &report.acct_expiration, 10);
    print_section_findings("Fine-Grained Password Policy", &report.fgpp, 5);
    print_section_findings("Orphan Accounts", &report.orphan_accts, 20);
    print_section_findings(
        "Indirect Admin Members (nested)",
        &report.indirect_admins,
        10,
    );
    print_section_findings("Service Account Hygiene", &report.svc_hygiene, 20);
    print_section_findings(
        "Protected Users Audit (admins NOT in Protected Users)",
        &report.protected_users,
        20,
    );
    print_section_findings("DC Ownership Audit (non-DA owners)", &report.dc_owners, 10);
    print_section_findings("Read-Only Domain Controllers", &report.rodcs, 10);
    print_section_findings(
        "Recently Created Objects (<30 days)",
        &report.recent_objects,
        20,
    );
    print_section_findings("AD Recycle Bin Status", &report.recycle_bin, 5);
    print_section_findings("Default Domain Policy Audit", &report.default_policy, 10);
    print_section_findings("Old KRBTGT Password (>180 days)", &report.old_krbtgt, 5);
    print_section_findings("Obsolete OS Detection", &report.obsolete_os, 20);
    print_section_count("Empty Groups", &report.empty_groups);
    print_section_findings("Unexpected PrimaryGroupID", &report.unexpected_pg, 20);
    print_section_findings(
        "Paths to DNS Admins (DLL injection)",
        &report.dns_admin_paths,
        20,
    );
    print_section_findings("Paths to Operator Groups", &report.operator_paths, 20);
    print_section_findings(
        "Computer Admin of Computers (lateral)",
        &report.comp_admin_comp,
        20,
    );
    print_section_findings("Enabled Guest Accounts", &report.guest_accts, 5);
    print_section_findings(
        "Tier-0 Session Violations (DA on non-DC)",
        &report.tier0_violations,
        20,
    );
    print_section_findings("Cleartext Password Attributes", &report.cleartext_pwd, 10);
    print_section_findings("Password in Description", &report.pwd_in_desc, 20);
    print_section_count("Password Never Expires", &report.pwd_never_expires);
    print_section_count("Password Not Required", &report.pwd_not_required);
    print_snaffler_findings(&report.snaffler_findings);
    print_paths(&report.paths_to_hv);
    print_stepping_stones(&report.stepping_stones);
    if !report.owned_paths.is_empty() {
        println!(
            "--- Paths from Owned Principals ({}) ---",
            report.owned_paths.len()
        );
        print_paths(&report.owned_paths);
    }

    println!("\n{}", "=".repeat(80));
    println!("{:^80}", "ANALYSIS COMPLETE");
    println!("{}", "=".repeat(80));

    if let Some(fmt) = export_format {
        let result = match fmt {
            "json" => {
                let path = format!("{}/analysis_report.json", output_dir);
                export_json(report, &path).map(|_| path)
            }
            "csv" => export_csv(report, output_dir).map(|_| format!("{}/findings.csv", output_dir)),
            "md" | "markdown" => {
                let path = format!("{}/analysis_report.md", output_dir);
                export_markdown(report, &path).map(|_| path)
            }
            _ => {
                log::warn!("Unknown export format '{}', skipping export", fmt);
                return;
            }
        };
        match result {
            Ok(path) => log::info!("Analysis exported to: {}", path),
            Err(e) => log::error!("Export failed: {}", e),
        }
    }
}

// ─── Console output helpers ─────────────────────────────────────────────────

fn print_health(h: &CollectionHealth) {
    println!("--- Collection Health ---");
    println!(
        "  Objects: users={} computers={} groups={} domains={} gpos={} ous={}",
        h.users, h.computers, h.groups, h.domains, h.gpos, h.ous
    );
    println!("  Graph: {} nodes, {} edges", h.total_nodes, h.total_edges);
    println!(
        "  Edges: HasSession={} LocalAdmin/AdminTo={}",
        h.has_session_edges, h.local_admin_edges
    );
    println!();
}

fn print_section_findings(title: &str, findings: &[Finding], max: usize) {
    if findings.is_empty() {
        return;
    }
    println!("--- {} ({}) ---", title, findings.len());
    for (i, f) in findings.iter().enumerate() {
        if i >= max {
            println!("  ... and {} more", findings.len() - max);
            break;
        }
        let target = f.target.as_deref().unwrap_or("");
        if target.is_empty() {
            println!(
                "  [{}] {} ({}): {}",
                severity_label(f.severity),
                f.principal,
                f.principal_type,
                f.detail
            );
        } else {
            println!(
                "  [{}] {} --> {}: {}",
                severity_label(f.severity),
                f.principal,
                target,
                f.detail
            );
        }
    }
    println!();
}

fn print_section_count(title: &str, findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    println!("--- {} ---", title);
    println!("  {} accounts affected", findings.len());
    println!();
}

fn print_adcs(vulns: &[AdcsVuln]) {
    if vulns.is_empty() {
        return;
    }
    println!("--- ADCS Vulnerabilities ({}) ---", vulns.len());
    for v in vulns {
        println!(
            "  [{}] {}: template={}, CA={}: {}",
            severity_label(v.severity),
            v.esc_type,
            v.template,
            v.ca,
            v.detail
        );
    }
    println!();
}

fn print_paths(paths: &[PathResult]) {
    if paths.is_empty() {
        return;
    }
    println!("--- Paths to High-Value Targets ---");
    for pr in paths {
        println!("\n  Target: {} ({})", pr.target, pr.target_type);
        if pr.paths.is_empty() {
            println!("    No paths found within limit");
            continue;
        }
        for (i, path) in pr.paths.iter().enumerate() {
            let chain: Vec<String> = path
                .hops
                .iter()
                .map(|h| format!("{} --[{}]--> {}", h.source, h.edge, h.target))
                .collect();
            println!(
                "    Path {} (hops: {}): {}",
                i + 1,
                path.hops.len(),
                chain.join(" | ")
            );
        }
    }
    println!();
}

fn print_snaffler_findings(findings: &[crate::snaffler::scanner::ScanFinding]) {
    if findings.is_empty() {
        return;
    }
    println!(
        "--- Sensitive Files / Secrets Found — Snaffler ({}) ---",
        findings.len()
    );
    for (i, f) in findings.iter().enumerate() {
        if i >= 30 {
            println!("  ... and {} more", findings.len() - 30);
            break;
        }
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

fn print_stepping_stones(stones: &[SteppingStone]) {
    if stones.is_empty() {
        return;
    }
    println!("--- Stepping Stones (multi-hop bridges) ---");
    println!(
        "  {:<4} {:<40} {:<12} {:<10} {:<25} {:<15} {}",
        "#", "Principal", "Type", "On paths", "Inbound", "Outbound", "HV Targets"
    );
    for (i, s) in stones.iter().enumerate() {
        println!(
            "  {:<4} {:<40} {:<12} {:<10} {:<25} {:<15} {}",
            i + 1,
            truncate(&s.principal, 38),
            s.principal_type,
            s.on_paths,
            s.inbound_edges.join(", "),
            s.outbound_edges.join(", "),
            s.hv_targets.join(", "),
        );
    }
    println!();
}

fn severity_label(s: u8) -> &'static str {
    match s {
        10 => "CRITICAL",
        9 => "HIGH",
        7..=8 => "MEDIUM",
        4..=6 => "LOW",
        _ => "INFO",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let end: usize = s
        .char_indices()
        .nth(max.saturating_sub(3))
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    format!("{}...", &s[..end])
}

// ─── JSON export ────────────────────────────────────────────────────────────

pub fn export_json(report: &AnalysisReport, path: &str) -> Result<(), Box<dyn Error>> {
    use serde_json::json;

    let findings_to_json = |findings: &[Finding]| -> serde_json::Value {
        findings
            .iter()
            .map(|f| {
                json!({
                    "principal": f.principal,
                    "type": f.principal_type,
                    "severity": f.severity,
                    "severity_label": severity_label(f.severity),
                    "detail": f.detail,
                    "target": f.target,
                })
            })
            .collect::<Vec<_>>()
            .into()
    };

    let adcs_json: Vec<serde_json::Value> = report
        .adcs
        .iter()
        .map(|v| {
            json!({
                "esc_type": v.esc_type,
                "template": v.template,
                "ca": v.ca,
                "severity": v.severity,
                "severity_label": severity_label(v.severity),
                "detail": v.detail,
            })
        })
        .collect();

    let paths_json: Vec<serde_json::Value> = report
        .paths_to_hv
        .iter()
        .map(|pr| {
            json!({
                "target": pr.target,
                "target_type": pr.target_type,
                "paths": pr.paths.iter().map(|p| json!({
                    "hops": p.hops.len(),
                    "chain": p.hops.iter().map(|h| json!({
                        "source": h.source,
                        "edge": h.edge,
                        "target": h.target,
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    let stones_json: Vec<serde_json::Value> = report
        .stepping_stones
        .iter()
        .map(|s| {
            json!({
                "principal": s.principal,
                "type": s.principal_type,
                "on_paths": s.on_paths,
                "inbound_edges": s.inbound_edges,
                "outbound_edges": s.outbound_edges,
                "hv_targets": s.hv_targets,
            })
        })
        .collect();

    let doc = json!({
        "health": {
            "users": report.health.users,
            "computers": report.health.computers,
            "groups": report.health.groups,
            "domains": report.health.domains,
            "gpos": report.health.gpos,
            "ous": report.health.ous,
            "total_nodes": report.health.total_nodes,
            "total_edges": report.health.total_edges,
            "has_session_edges": report.health.has_session_edges,
            "local_admin_edges": report.health.local_admin_edges,
        },
        "kerberoastable": findings_to_json(&report.kerberoastable),
        "asrep_roastable": findings_to_json(&report.asrep_roastable),
        "dcsync": findings_to_json(&report.dcsync),
        "dangerous_permissions": findings_to_json(&report.dangerous_perms),
        "unconstrained_delegation": findings_to_json(&report.unconstrained),
        "adcs": adcs_json,
        "rbcd": findings_to_json(&report.rbcd),
        "shadow_credentials": findings_to_json(&report.shadow_creds),
        "constrained_delegation": findings_to_json(&report.constrained_deleg),
        "gpo_abuse": findings_to_json(&report.gpo_abuse),
        "trust_info": findings_to_json(&report.trust_info),
        "deep_group_nesting": findings_to_json(&report.deep_nesting),
        "dns_zone_abuse": findings_to_json(&report.dns_abuse),
        "sccm_detection": findings_to_json(&report.sccm_info),
        "dpapi_exposure": findings_to_json(&report.dpapi_exposure),
        "adminsdholder_abuse": findings_to_json(&report.adminsdholder),
        "exchange_permissions": findings_to_json(&report.exchange_perms),
        "coercion_targets": findings_to_json(&report.coerce_targets),
        "print_spooler": findings_to_json(&report.print_spooler),
        "laps_deployment": findings_to_json(&report.laps_status),
        "machine_account_quota": findings_to_json(&report.machine_quota),
        "pre_windows_2000_access": findings_to_json(&report.pre_2000_access),
        "credential_exposure": findings_to_json(&report.cred_exposure),
        "ntlm_relay_targets": findings_to_json(&report.ntlm_relay),
        "gpp_passwords": findings_to_json(&report.gpp_passwords),
        "smb_signing": findings_to_json(&report.smb_signing),
        "ldap_signing": findings_to_json(&report.ldap_signing),
        "privileged_users_summary": findings_to_json(&report.priv_summary),
        "stale_computers": findings_to_json(&report.stale_computers),
        "coercion_paths": findings_to_json(&report.coercion_paths),
        "domain_recon_summary": findings_to_json(&report.recon_summary),
        "delegation_overview": findings_to_json(&report.delegation_overview),
        "foreign_users": findings_to_json(&report.foreign_user),
        "foreign_groups": findings_to_json(&report.foreign_group),
        "gpo_local_groups": findings_to_json(&report.gpo_local),
        "local_admin_targets": findings_to_json(&report.local_admin_targets),
        "exchange_servers": findings_to_json(&report.exchange_servers),
        "gmsa_exposure": findings_to_json(&report.gmsa),
        "rbcd_configurable": findings_to_json(&report.rbcd_config),
        "shadow_cred_via_owner": findings_to_json(&report.shadow_owner),
        "stale_users": findings_to_json(&report.stale_users),
        "fine_grained_password_policy": findings_to_json(&report.fgpp),
        "password_age_audit": findings_to_json(&report.pwd_age),
        "account_expiration": findings_to_json(&report.acct_expiration),
        "orphan_accounts": findings_to_json(&report.orphan_accts),
        "indirect_admin_members": findings_to_json(&report.indirect_admins),
        "service_account_hygiene": findings_to_json(&report.svc_hygiene),
        "protected_users_audit": findings_to_json(&report.protected_users),
        "dc_owner_audit": findings_to_json(&report.dc_owners),
        "rodc_detection": findings_to_json(&report.rodcs),
        "recently_created_objects": findings_to_json(&report.recent_objects),
        "locked_accounts": findings_to_json(&report.locked),
        "recycle_bin_status": findings_to_json(&report.recycle_bin),
        "default_domain_policy": findings_to_json(&report.default_policy),
        "old_krbtgt_password": findings_to_json(&report.old_krbtgt),
        "obsolete_os": findings_to_json(&report.obsolete_os),
        "empty_groups": findings_to_json(&report.empty_groups),
        "unexpected_primary_group": findings_to_json(&report.unexpected_pg),
        "paths_to_dns_admins": findings_to_json(&report.dns_admin_paths),
        "paths_to_operators": findings_to_json(&report.operator_paths),
        "computer_admin_of_computers": findings_to_json(&report.comp_admin_comp),
        "guest_accounts": findings_to_json(&report.guest_accts),
        "tier0_session_violations": findings_to_json(&report.tier0_violations),
        "cleartext_passwords": findings_to_json(&report.cleartext_pwd),
        "password_in_description": findings_to_json(&report.pwd_in_desc),
        "password_never_expires_count": report.pwd_never_expires.len(),
        "password_not_required_count": report.pwd_not_required.len(),
        "paths_to_high_value": paths_json,
        "stepping_stones": stones_json,
    });

    let parent = std::path::Path::new(path).parent();
    if let Some(dir) = parent {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = std::fs::File::create(path)?;
    file.write_all(serde_json::to_string_pretty(&doc)?.as_bytes())?;
    Ok(())
}

// ─── CSV export ─────────────────────────────────────────────────────────────

pub fn export_csv(report: &AnalysisReport, dir: &str) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(dir)?;

    // findings.csv — all findings collapsed
    {
        let path = format!("{}/findings.csv", dir);
        let mut f = std::fs::File::create(&path)?;
        writeln!(
            f,
            "category,principal,type,severity,severity_label,detail,target"
        )?;

        let categories: Vec<(&str, &[Finding])> = vec![
            ("Kerberoastable", &report.kerberoastable),
            ("AS-REP Roastable", &report.asrep_roastable),
            ("DCSync", &report.dcsync),
            ("Dangerous Permissions", &report.dangerous_perms),
            ("Unconstrained Delegation", &report.unconstrained),
            ("RBCD", &report.rbcd),
            ("Shadow Credentials", &report.shadow_creds),
            ("Constrained Delegation", &report.constrained_deleg),
            ("GPO Abuse", &report.gpo_abuse),
            ("Trust Info", &report.trust_info),
            ("Deep Group Nesting", &report.deep_nesting),
            ("DNS Zone Abuse", &report.dns_abuse),
            ("SCCM Detection", &report.sccm_info),
            ("DPAPI Exposure", &report.dpapi_exposure),
            ("AdminSDHolder Abuse", &report.adminsdholder),
            ("Exchange Permissions", &report.exchange_perms),
            ("Coercion Targets", &report.coerce_targets),
            ("Print Spooler", &report.print_spooler),
            ("LAPS Deployment", &report.laps_status),
            ("Machine Account Quota", &report.machine_quota),
            ("Pre-Windows 2000 Access", &report.pre_2000_access),
            ("Credential Exposure", &report.cred_exposure),
            ("NTLM Relay Targets", &report.ntlm_relay),
            ("GPP Passwords", &report.gpp_passwords),
            ("SMB Signing", &report.smb_signing),
            ("LDAP Signing", &report.ldap_signing),
            ("Privileged Users Summary", &report.priv_summary),
            ("Stale Computers", &report.stale_computers),
            ("Coercion Paths", &report.coercion_paths),
            ("Delegation Overview", &report.delegation_overview),
            ("Domain Recon Summary", &report.recon_summary),
            ("Foreign Users", &report.foreign_user),
            ("Foreign Groups", &report.foreign_group),
            ("GPO Local Groups", &report.gpo_local),
            ("Local Admin Targets", &report.local_admin_targets),
            ("Exchange Servers", &report.exchange_servers),
            ("gMSA Exposure", &report.gmsa),
            ("RBCD Configurable", &report.rbcd_config),
            ("Shadow Cred via Owner", &report.shadow_owner),
            ("Stale Users", &report.stale_users),
            ("FGPP", &report.fgpp),
            ("Password Age", &report.pwd_age),
            ("Account Expiration", &report.acct_expiration),
            ("Orphan Accounts", &report.orphan_accts),
            ("Indirect Admin Members", &report.indirect_admins),
            ("Service Account Hygiene", &report.svc_hygiene),
            ("Protected Users Audit", &report.protected_users),
            ("DC Owner Audit", &report.dc_owners),
            ("RODC Detection", &report.rodcs),
            ("Recently Created Objects", &report.recent_objects),
            ("Locked Accounts", &report.locked),
            ("Recycle Bin Status", &report.recycle_bin),
            ("Default Domain Policy", &report.default_policy),
            ("Old KRBTGT Password", &report.old_krbtgt),
            ("Obsolete OS", &report.obsolete_os),
            ("Empty Groups", &report.empty_groups),
            ("Unexpected PrimaryGroup", &report.unexpected_pg),
            ("DNS Admins Paths", &report.dns_admin_paths),
            ("Operator Paths", &report.operator_paths),
            ("Computer Admin of Computers", &report.comp_admin_comp),
            ("Guest Accounts", &report.guest_accts),
            ("Tier-0 Session Violations", &report.tier0_violations),
            ("Cleartext Passwords", &report.cleartext_pwd),
            ("Password in Description", &report.pwd_in_desc),
            ("Password Never Expires", &report.pwd_never_expires),
            ("Password Not Required", &report.pwd_not_required),
        ];

        for (cat, findings) in categories {
            for finding in findings {
                writeln!(
                    f,
                    "{},{},{},{},{},{},{}",
                    csv_escape(cat),
                    csv_escape(&finding.principal),
                    csv_escape(&finding.principal_type),
                    finding.severity,
                    severity_label(finding.severity),
                    csv_escape(&finding.detail),
                    csv_escape(finding.target.as_deref().unwrap_or("")),
                )?;
            }
        }
        log::info!("Exported {}", path);
    }

    // adcs.csv
    if !report.adcs.is_empty() {
        let path = format!("{}/adcs.csv", dir);
        let mut f = std::fs::File::create(&path)?;
        writeln!(f, "esc_type,template,ca,severity,severity_label,detail")?;
        for v in &report.adcs {
            writeln!(
                f,
                "{},{},{},{},{},{}",
                csv_escape(&v.esc_type),
                csv_escape(&v.template),
                csv_escape(&v.ca),
                v.severity,
                severity_label(v.severity),
                csv_escape(&v.detail),
            )?;
        }
        log::info!("Exported {}", path);
    }

    // paths.csv
    if !report.paths_to_hv.is_empty() {
        let path = format!("{}/paths.csv", dir);
        let mut f = std::fs::File::create(&path)?;
        writeln!(f, "target,target_type,path_index,hops,chain")?;
        for pr in &report.paths_to_hv {
            for (i, p) in pr.paths.iter().enumerate() {
                let chain: String = p
                    .hops
                    .iter()
                    .map(|h| format!("{} --[{}]--> {}", h.source, h.edge, h.target))
                    .collect::<Vec<_>>()
                    .join(" | ");
                writeln!(
                    f,
                    "{},{},{},{},{}",
                    csv_escape(&pr.target),
                    csv_escape(&pr.target_type),
                    i + 1,
                    p.hops.len(),
                    csv_escape(&chain),
                )?;
            }
        }
        log::info!("Exported {}", path);
    }

    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ─── Markdown export ────────────────────────────────────────────────────────

pub fn export_markdown(report: &AnalysisReport, path: &str) -> Result<(), Box<dyn Error>> {
    let parent = std::path::Path::new(path).parent();
    if let Some(dir) = parent {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::File::create(path)?;

    writeln!(f, "# Attack Surface Analysis Report\n")?;

    // Health
    writeln!(f, "## Collection Health\n")?;
    writeln!(f, "| Metric | Value |")?;
    writeln!(f, "|---|---|")?;
    writeln!(f, "| Users | {} |", report.health.users)?;
    writeln!(f, "| Computers | {} |", report.health.computers)?;
    writeln!(f, "| Groups | {} |", report.health.groups)?;
    writeln!(f, "| Domains | {} |", report.health.domains)?;
    writeln!(f, "| GPOs | {} |", report.health.gpos)?;
    writeln!(f, "| OUs | {} |", report.health.ous)?;
    writeln!(f, "| Total Nodes | {} |", report.health.total_nodes)?;
    writeln!(f, "| Total Edges | {} |", report.health.total_edges)?;
    writeln!(
        f,
        "| HasSession Edges | {} |",
        report.health.has_session_edges
    )?;
    writeln!(
        f,
        "| LocalAdmin Edges | {} |",
        report.health.local_admin_edges
    )?;
    writeln!(f)?;

    // Summary
    writeln!(f, "## Summary\n")?;
    writeln!(f, "| Category | Count | Max Severity |")?;
    writeln!(f, "|---|---|---|")?;
    md_summary_row(&mut f, "Kerberoastable", &report.kerberoastable)?;
    md_summary_row(&mut f, "AS-REP Roastable", &report.asrep_roastable)?;
    md_summary_row(&mut f, "DCSync", &report.dcsync)?;
    md_summary_row(&mut f, "Dangerous Permissions", &report.dangerous_perms)?;
    md_summary_row(&mut f, "Unconstrained Delegation", &report.unconstrained)?;
    writeln!(
        f,
        "| ADCS Vulnerabilities | {} | {} |",
        report.adcs.len(),
        report.adcs.iter().map(|v| v.severity).max().unwrap_or(0)
    )?;
    md_summary_row(&mut f, "RBCD", &report.rbcd)?;
    md_summary_row(&mut f, "Shadow Credentials", &report.shadow_creds)?;
    md_summary_row(&mut f, "Constrained Delegation", &report.constrained_deleg)?;
    md_summary_row(&mut f, "GPO Abuse", &report.gpo_abuse)?;
    md_summary_row(&mut f, "Trust Info", &report.trust_info)?;
    md_summary_row(&mut f, "Deep Group Nesting", &report.deep_nesting)?;
    md_summary_row(&mut f, "DNS Zone Abuse", &report.dns_abuse)?;
    md_summary_row(&mut f, "SCCM Detection", &report.sccm_info)?;
    md_summary_row(&mut f, "DPAPI Exposure", &report.dpapi_exposure)?;
    md_summary_row(&mut f, "AdminSDHolder Abuse", &report.adminsdholder)?;
    md_summary_row(&mut f, "Exchange Permissions", &report.exchange_perms)?;
    md_summary_row(&mut f, "Coercion Targets", &report.coerce_targets)?;
    md_summary_row(&mut f, "Print Spooler", &report.print_spooler)?;
    md_summary_row(&mut f, "LAPS Deployment", &report.laps_status)?;
    md_summary_row(&mut f, "Machine Account Quota", &report.machine_quota)?;
    md_summary_row(&mut f, "Pre-Windows 2000 Access", &report.pre_2000_access)?;
    md_summary_row(&mut f, "Credential Exposure", &report.cred_exposure)?;
    md_summary_row(&mut f, "NTLM Relay Targets", &report.ntlm_relay)?;
    md_summary_row(&mut f, "GPP Passwords", &report.gpp_passwords)?;
    md_summary_row(&mut f, "SMB Signing", &report.smb_signing)?;
    md_summary_row(&mut f, "LDAP Signing", &report.ldap_signing)?;
    md_summary_row(&mut f, "Privileged Users Summary", &report.priv_summary)?;
    md_summary_row(&mut f, "Stale Computers", &report.stale_computers)?;
    md_summary_row(&mut f, "Coercion Paths", &report.coercion_paths)?;
    md_summary_row(&mut f, "Delegation Overview", &report.delegation_overview)?;
    md_summary_row(&mut f, "Stale Users", &report.stale_users)?;
    md_summary_row(&mut f, "Password Age (>1yr)", &report.pwd_age)?;
    md_summary_row(&mut f, "Account Expiration", &report.acct_expiration)?;
    md_summary_row(&mut f, "FGPP", &report.fgpp)?;
    md_summary_row(&mut f, "Orphan Accounts", &report.orphan_accts)?;
    md_summary_row(&mut f, "Indirect Admin Members", &report.indirect_admins)?;
    md_summary_row(&mut f, "Service Account Hygiene", &report.svc_hygiene)?;
    md_summary_row(&mut f, "Password in Description", &report.pwd_in_desc)?;
    md_summary_row(&mut f, "Foreign Users", &report.foreign_user)?;
    md_summary_row(&mut f, "Foreign Groups", &report.foreign_group)?;
    md_summary_row(&mut f, "GPO Local Groups", &report.gpo_local)?;
    md_summary_row(&mut f, "Local Admin Targets", &report.local_admin_targets)?;
    md_summary_row(&mut f, "Exchange Servers", &report.exchange_servers)?;
    md_summary_row(&mut f, "gMSA Exposure", &report.gmsa)?;
    md_summary_row(&mut f, "RBCD Configurable", &report.rbcd_config)?;
    md_summary_row(&mut f, "Shadow Cred via Owner", &report.shadow_owner)?;
    md_summary_row(&mut f, "Protected Users Audit", &report.protected_users)?;
    md_summary_row(&mut f, "DC Owner Audit", &report.dc_owners)?;
    md_summary_row(&mut f, "RODC Detection", &report.rodcs)?;
    md_summary_row(&mut f, "Recently Created Objects", &report.recent_objects)?;
    md_summary_row(&mut f, "Recycle Bin Status", &report.recycle_bin)?;
    md_summary_row(&mut f, "Default Domain Policy", &report.default_policy)?;
    md_summary_row(&mut f, "Old KRBTGT Password", &report.old_krbtgt)?;
    md_summary_row(&mut f, "Obsolete OS", &report.obsolete_os)?;
    md_summary_row(&mut f, "Empty Groups", &report.empty_groups)?;
    md_summary_row(&mut f, "Unexpected PrimaryGroupID", &report.unexpected_pg)?;
    md_summary_row(&mut f, "DNS Admins Paths", &report.dns_admin_paths)?;
    md_summary_row(&mut f, "Operator Paths", &report.operator_paths)?;
    md_summary_row(
        &mut f,
        "Computer Admin of Computers",
        &report.comp_admin_comp,
    )?;
    md_summary_row(&mut f, "Guest Accounts", &report.guest_accts)?;
    md_summary_row(
        &mut f,
        "Tier-0 Session Violations",
        &report.tier0_violations,
    )?;
    md_summary_row(&mut f, "Cleartext Passwords", &report.cleartext_pwd)?;
    writeln!(
        f,
        "| Password Never Expires | {} | LOW |",
        report.pwd_never_expires.len()
    )?;
    writeln!(
        f,
        "| Password Not Required | {} | MEDIUM |",
        report.pwd_not_required.len()
    )?;
    writeln!(f)?;

    // Detailed sections
    md_findings_section(&mut f, "DCSync Rights (CRITICAL)", &report.dcsync)?;
    md_findings_section(&mut f, "Dangerous Permissions", &report.dangerous_perms)?;

    if !report.adcs.is_empty() {
        writeln!(f, "## ADCS Vulnerabilities\n")?;
        writeln!(f, "| ESC | Template | CA | Severity | Detail |")?;
        writeln!(f, "|---|---|---|---|---|")?;
        for v in &report.adcs {
            writeln!(
                f,
                "| {} | {} | {} | {} | {} |",
                v.esc_type,
                md_escape(&v.template),
                md_escape(&v.ca),
                severity_label(v.severity),
                md_escape(&v.detail)
            )?;
        }
        writeln!(f)?;
    }

    md_findings_section(&mut f, "Kerberoastable Accounts", &report.kerberoastable)?;
    md_findings_section(&mut f, "AS-REP Roastable", &report.asrep_roastable)?;
    md_findings_section(&mut f, "Unconstrained Delegation", &report.unconstrained)?;
    md_findings_section(&mut f, "RBCD", &report.rbcd)?;
    md_findings_section(&mut f, "Shadow Credentials", &report.shadow_creds)?;
    md_findings_section(&mut f, "Constrained Delegation", &report.constrained_deleg)?;
    md_findings_section(&mut f, "GPO Abuse", &report.gpo_abuse)?;
    md_findings_section(&mut f, "Domain Trusts", &report.trust_info)?;
    md_findings_section(&mut f, "Deep Group Nesting", &report.deep_nesting)?;
    md_findings_section(&mut f, "DNS Zone Abuse (ADIDNS)", &report.dns_abuse)?;
    md_findings_section(&mut f, "SCCM/MECM Infrastructure", &report.sccm_info)?;
    md_findings_section(&mut f, "DPAPI Backup Key Exposure", &report.dpapi_exposure)?;
    md_findings_section(&mut f, "AdminSDHolder Abuse", &report.adminsdholder)?;
    md_findings_section(&mut f, "Exchange Permissions", &report.exchange_perms)?;
    md_findings_section(&mut f, "NTLM Coercion Targets", &report.coerce_targets)?;
    md_findings_section(&mut f, "Print Spooler Detection", &report.print_spooler)?;
    md_findings_section(&mut f, "LAPS Deployment & Readers", &report.laps_status)?;
    md_findings_section(&mut f, "Machine Account Quota", &report.machine_quota)?;
    md_findings_section(
        &mut f,
        "Pre-Windows 2000 Compatible Access",
        &report.pre_2000_access,
    )?;
    md_findings_section(&mut f, "Foreign Users (cross-domain)", &report.foreign_user)?;
    md_findings_section(&mut f, "Foreign Group Members", &report.foreign_group)?;
    md_findings_section(&mut f, "GPO Local Group Modification", &report.gpo_local)?;
    md_findings_section(&mut f, "Local Admin Targets", &report.local_admin_targets)?;
    md_findings_section(
        &mut f,
        "Exchange Server Infrastructure",
        &report.exchange_servers,
    )?;
    md_findings_section(&mut f, "gMSA Password Exposure", &report.gmsa)?;
    md_findings_section(&mut f, "RBCD Configurable", &report.rbcd_config)?;
    md_findings_section(
        &mut f,
        "Shadow Credentials via WriteOwner",
        &report.shadow_owner,
    )?;
    md_findings_section(&mut f, "Stale User Accounts", &report.stale_users)?;
    md_findings_section(&mut f, "Password Age Audit", &report.pwd_age)?;
    md_findings_section(&mut f, "Account Expiration", &report.acct_expiration)?;
    md_findings_section(&mut f, "Fine-Grained Password Policy", &report.fgpp)?;
    md_findings_section(&mut f, "Orphan Accounts", &report.orphan_accts)?;
    md_findings_section(&mut f, "Indirect Admin Members", &report.indirect_admins)?;
    md_findings_section(&mut f, "Service Account Hygiene", &report.svc_hygiene)?;
    md_findings_section(&mut f, "Coercion Attack Paths", &report.coercion_paths)?;
    md_findings_section(&mut f, "Delegation Overview", &report.delegation_overview)?;
    md_findings_section(&mut f, "Domain Recon Summary", &report.recon_summary)?;
    md_findings_section(&mut f, "Protected Users Audit", &report.protected_users)?;
    md_findings_section(&mut f, "DC Ownership Audit", &report.dc_owners)?;
    md_findings_section(&mut f, "Read-Only Domain Controllers", &report.rodcs)?;
    md_findings_section(&mut f, "Recently Created Objects", &report.recent_objects)?;
    md_findings_section(&mut f, "AD Recycle Bin Status", &report.recycle_bin)?;
    md_findings_section(
        &mut f,
        "Default Domain Policy Audit",
        &report.default_policy,
    )?;
    md_findings_section(&mut f, "Old KRBTGT Password", &report.old_krbtgt)?;
    md_findings_section(&mut f, "Obsolete OS Detection", &report.obsolete_os)?;
    md_findings_section(&mut f, "Unexpected PrimaryGroupID", &report.unexpected_pg)?;
    md_findings_section(&mut f, "Paths to DNS Admins", &report.dns_admin_paths)?;
    md_findings_section(&mut f, "Paths to Operator Groups", &report.operator_paths)?;
    md_findings_section(
        &mut f,
        "Computer Admin of Computers",
        &report.comp_admin_comp,
    )?;
    md_findings_section(&mut f, "Guest Accounts", &report.guest_accts)?;
    md_findings_section(
        &mut f,
        "Tier-0 Session Violations",
        &report.tier0_violations,
    )?;
    md_findings_section(
        &mut f,
        "Cleartext Password Attributes",
        &report.cleartext_pwd,
    )?;

    // Paths
    if !report.paths_to_hv.is_empty() {
        writeln!(f, "## Paths to High-Value Targets\n")?;
        for pr in &report.paths_to_hv {
            writeln!(f, "### Target: {} ({})\n", pr.target, pr.target_type)?;
            if pr.paths.is_empty() {
                writeln!(f, "No paths found within limit.\n")?;
                continue;
            }
            for (i, path) in pr.paths.iter().enumerate() {
                let chain: Vec<String> = path
                    .hops
                    .iter()
                    .map(|h| format!("`{}` --[{}]--> `{}`", h.source, h.edge, h.target))
                    .collect();
                writeln!(
                    f,
                    "**Path {}** ({} hops): {}\n",
                    i + 1,
                    path.hops.len(),
                    chain.join(" ")
                )?;
            }
        }
    }

    // Stepping stones
    if !report.stepping_stones.is_empty() {
        writeln!(f, "## Stepping Stones\n")?;
        writeln!(
            f,
            "| # | Principal | Type | On Paths | Inbound | Outbound | HV Targets |"
        )?;
        writeln!(f, "|---|---|---|---|---|---|---|")?;
        for (i, s) in report.stepping_stones.iter().enumerate() {
            writeln!(
                f,
                "| {} | {} | {} | {} | {} | {} | {} |",
                i + 1,
                md_escape(&s.principal),
                s.principal_type,
                s.on_paths,
                s.inbound_edges.join(", "),
                s.outbound_edges.join(", "),
                s.hv_targets.join(", "),
            )?;
        }
        writeln!(f)?;
    }

    Ok(())
}

fn md_summary_row(
    f: &mut std::fs::File,
    name: &str,
    findings: &[Finding],
) -> Result<(), Box<dyn Error>> {
    if findings.is_empty() {
        return Ok(());
    }
    let max_sev = findings.iter().map(|f| f.severity).max().unwrap_or(0);
    writeln!(
        f,
        "| {} | {} | {} |",
        name,
        findings.len(),
        severity_label(max_sev)
    )?;
    Ok(())
}

fn md_findings_section(
    f: &mut std::fs::File,
    title: &str,
    findings: &[Finding],
) -> Result<(), Box<dyn Error>> {
    if findings.is_empty() {
        return Ok(());
    }
    writeln!(f, "## {}\n", title)?;
    writeln!(f, "| Severity | Principal | Type | Detail | Target |")?;
    writeln!(f, "|---|---|---|---|---|")?;
    for finding in findings.iter().take(50) {
        writeln!(
            f,
            "| {} | {} | {} | {} | {} |",
            severity_label(finding.severity),
            md_escape(&finding.principal),
            finding.principal_type,
            md_escape(&finding.detail),
            md_escape(finding.target.as_deref().unwrap_or("")),
        )?;
    }
    if findings.len() > 50 {
        writeln!(f, "\n*...and {} more findings*\n", findings.len() - 50)?;
    }
    writeln!(f)?;
    Ok(())
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|")
}
