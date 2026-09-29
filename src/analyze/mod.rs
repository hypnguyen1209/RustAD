pub mod checks;
pub mod graph;
pub mod report;

use crate::api::ADResults;
use graph::AdGraph;
use std::error::Error;

pub fn run_analysis(
    ad: &ADResults,
    domain: &str,
    owned: Option<&str>,
) -> Result<AnalysisReport, Box<dyn Error>> {
    let g = graph::build_graph(ad, domain);
    let health = checks::collection_health(&g);
    let kerberoastable = checks::kerberoastable(&g);
    let asrep_roastable = checks::asrep_roastable(&g);
    let dcsync = checks::dcsync_rights(&g);
    let dangerous_perms = checks::dangerous_permissions(&g);
    let unconstrained = checks::unconstrained_delegation(&g);
    let adcs = checks::adcs_vulns(&g);
    let rbcd = checks::rbcd_abuse(&g);
    let pwd_never_expires = checks::password_never_expires(&g);
    let pwd_not_required = checks::password_not_required(&g);
    let pwd_in_desc = checks::password_in_description(&g);
    let shadow_creds = checks::shadow_credentials(&g);
    let constrained_deleg = checks::constrained_delegation(&g);
    let gpo_abuse = checks::gpo_abuse(&g);
    let trust_info = checks::trust_abuse(&g);
    let deep_nesting = checks::deep_group_nesting(&g);
    let dns_abuse = checks::dns_zone_abuse(&g);
    let sccm_info = checks::sccm_detection(&g);
    let dpapi_exposure = checks::dpapi_exposure(&g);
    let paths_to_hv = checks::paths_to_high_value(&g);
    let stepping_stones = checks::stepping_stones(&g, &paths_to_hv);
    let machine_quota = checks::machine_account_quota(&g);
    let pre_2000_access = checks::pre_windows_2000_access(&g);
    let adminsdholder = checks::adminsdholder_abuse(&g);
    let laps_status = checks::laps_deployment(&g);
    let print_spooler = checks::print_spooler_check(&g);
    let coerce_targets = checks::coerce_targets(&g);
    let exchange_perms = checks::exchange_permissions(&g);
    let gpp_passwords = checks::gpp_passwords(&g);
    let smb_signing = checks::smb_signing(&g);
    let ldap_signing = checks::ldap_signing(&g);
    let ntlm_relay = checks::ntlm_relay_targets(&g);
    let stale_computers = checks::stale_computers(&g);
    let priv_summary = checks::privileged_users_summary(&g);
    let cred_exposure = checks::credential_exposure(&g);
    let coercion_paths = checks::coercion_paths(&g);
    let recon_summary = checks::domain_recon_summary(&g);
    let delegation_overview = checks::delegation_overview(&g);
    let foreign_user = checks::foreign_users(&g);
    let foreign_group = checks::foreign_groups(&g);
    let gpo_local = checks::gpo_local_groups(&g);
    let local_admin_targets = checks::find_local_admin_targets(&g);
    let exchange_servers = checks::exchange_server_detection(&g);
    let gmsa = checks::gmsa_exposure(&g);
    let rbcd_config = checks::rbcd_configurable(&g);
    let shadow_owner = checks::shadow_cred_via_owner(&g);
    let stale_users = checks::stale_users(&g);
    let fgpp = checks::fine_grained_password_policy(&g);
    let pwd_age = checks::password_age_audit(&g);
    let acct_expiration = checks::account_expiration(&g);
    let orphan_accts = checks::orphan_accounts(&g);
    let indirect_admins = checks::indirect_admin_members(&g);
    let svc_hygiene = checks::service_account_hygiene(&g);
    let protected_users = checks::protected_users_audit(&g);
    let dc_owners = checks::dc_owner_audit(&g);
    let rodcs = checks::rodc_detection(&g);
    let recent_objects = checks::recently_created_objects(&g);
    let locked = checks::locked_accounts(&g);
    let recycle_bin = checks::tombstone_recycle_bin(&g);
    let default_policy = checks::default_domain_policy_audit(&g);
    let old_krbtgt = checks::old_krbtgt_password(&g);
    let obsolete_os = checks::obsolete_os(&g);
    let empty_groups = checks::empty_groups(&g);
    let unexpected_pg = checks::unexpected_primary_group(&g);
    let dns_admin_paths = checks::paths_to_dns_admins(&g);
    let operator_paths = checks::paths_to_operators(&g);
    let comp_admin_comp = checks::computer_admin_of_computers(&g);
    let guest_accts = checks::guest_accounts(&g);
    let tier0_violations = checks::tier0_session_violations(&g);
    let cleartext_pwd = checks::cleartext_passwords(&g);
    let desc_scan = checks::scan_descriptions_for_secrets(&g);
    let mut snaffler_findings = ad.snaffler_findings.clone();
    // Also add findings from scanning user description fields
    for f in &desc_scan {
        snaffler_findings.push(crate::snaffler::scanner::ScanFinding {
            file_path: format!("AD:description:{}", f.principal),
            rule_name: "description_secret".to_string(),
            severity: crate::snaffler::rules::Severity::Red,
            description: f.detail.clone(),
            matched_text: "[REDACTED]".to_string(),
            line_number: None,
        });
    }
    let owned_paths = match owned {
        Some(list) if !list.is_empty() => checks::owned_paths(&g, list),
        _ => Vec::new(),
    };

    Ok(AnalysisReport {
        health,
        kerberoastable,
        asrep_roastable,
        dcsync,
        dangerous_perms,
        unconstrained,
        adcs,
        rbcd,
        pwd_never_expires,
        pwd_not_required,
        pwd_in_desc,
        shadow_creds,
        constrained_deleg,
        gpo_abuse,
        trust_info,
        deep_nesting,
        dns_abuse,
        sccm_info,
        dpapi_exposure,
        machine_quota,
        pre_2000_access,
        adminsdholder,
        laps_status,
        print_spooler,
        coerce_targets,
        exchange_perms,
        gpp_passwords,
        smb_signing,
        ldap_signing,
        ntlm_relay,
        stale_computers,
        priv_summary,
        cred_exposure,
        coercion_paths,
        recon_summary,
        delegation_overview,
        foreign_user,
        foreign_group,
        gpo_local,
        local_admin_targets,
        exchange_servers,
        gmsa,
        rbcd_config,
        shadow_owner,
        stale_users,
        fgpp,
        pwd_age,
        acct_expiration,
        orphan_accts,
        indirect_admins,
        svc_hygiene,
        protected_users,
        dc_owners,
        rodcs,
        recent_objects,
        locked,
        recycle_bin,
        default_policy,
        old_krbtgt,
        obsolete_os,
        empty_groups,
        unexpected_pg,
        dns_admin_paths,
        operator_paths,
        comp_admin_comp,
        guest_accts,
        tier0_violations,
        cleartext_pwd,
        snaffler_findings,
        paths_to_hv,
        stepping_stones,
        owned_paths,
    })
}

pub struct CollectionHealth {
    pub users: usize,
    pub computers: usize,
    pub groups: usize,
    pub domains: usize,
    pub gpos: usize,
    pub ous: usize,
    pub total_nodes: usize,
    pub total_edges: usize,
    pub has_session_edges: usize,
    pub local_admin_edges: usize,
}

pub struct Finding {
    pub principal: String,
    pub principal_type: String,
    pub detail: String,
    pub target: Option<String>,
    pub severity: u8,
}

pub struct PathResult {
    pub target: String,
    pub target_type: String,
    pub paths: Vec<AttackPath>,
}

pub struct AttackPath {
    pub hops: Vec<PathHop>,
}

pub struct PathHop {
    pub source: String,
    pub source_id: String,
    pub edge: String,
    pub target: String,
    pub target_id: String,
}

pub struct SteppingStone {
    pub principal: String,
    pub principal_type: String,
    pub on_paths: usize,
    pub inbound_edges: Vec<String>,
    pub outbound_edges: Vec<String>,
    pub hv_targets: Vec<String>,
}

pub struct AdcsVuln {
    pub esc_type: String,
    pub template: String,
    pub ca: String,
    pub detail: String,
    pub severity: u8,
}

pub struct AnalysisReport {
    pub health: CollectionHealth,
    pub kerberoastable: Vec<Finding>,
    pub asrep_roastable: Vec<Finding>,
    pub dcsync: Vec<Finding>,
    pub dangerous_perms: Vec<Finding>,
    pub unconstrained: Vec<Finding>,
    pub adcs: Vec<AdcsVuln>,
    pub rbcd: Vec<Finding>,
    pub pwd_never_expires: Vec<Finding>,
    pub pwd_not_required: Vec<Finding>,
    pub pwd_in_desc: Vec<Finding>,
    pub shadow_creds: Vec<Finding>,
    pub constrained_deleg: Vec<Finding>,
    pub gpo_abuse: Vec<Finding>,
    pub trust_info: Vec<Finding>,
    pub deep_nesting: Vec<Finding>,
    pub dns_abuse: Vec<Finding>,
    pub sccm_info: Vec<Finding>,
    pub dpapi_exposure: Vec<Finding>,
    pub machine_quota: Vec<Finding>,
    pub pre_2000_access: Vec<Finding>,
    pub adminsdholder: Vec<Finding>,
    pub laps_status: Vec<Finding>,
    pub print_spooler: Vec<Finding>,
    pub coerce_targets: Vec<Finding>,
    pub exchange_perms: Vec<Finding>,
    pub gpp_passwords: Vec<Finding>,
    pub smb_signing: Vec<Finding>,
    pub ldap_signing: Vec<Finding>,
    pub ntlm_relay: Vec<Finding>,
    pub stale_computers: Vec<Finding>,
    pub priv_summary: Vec<Finding>,
    pub cred_exposure: Vec<Finding>,
    pub coercion_paths: Vec<Finding>,
    pub recon_summary: Vec<Finding>,
    pub delegation_overview: Vec<Finding>,
    pub foreign_user: Vec<Finding>,
    pub foreign_group: Vec<Finding>,
    pub gpo_local: Vec<Finding>,
    pub local_admin_targets: Vec<Finding>,
    pub exchange_servers: Vec<Finding>,
    pub gmsa: Vec<Finding>,
    pub rbcd_config: Vec<Finding>,
    pub shadow_owner: Vec<Finding>,
    pub stale_users: Vec<Finding>,
    pub fgpp: Vec<Finding>,
    pub pwd_age: Vec<Finding>,
    pub acct_expiration: Vec<Finding>,
    pub orphan_accts: Vec<Finding>,
    pub indirect_admins: Vec<Finding>,
    pub svc_hygiene: Vec<Finding>,
    pub protected_users: Vec<Finding>,
    pub dc_owners: Vec<Finding>,
    pub rodcs: Vec<Finding>,
    pub recent_objects: Vec<Finding>,
    pub locked: Vec<Finding>,
    pub recycle_bin: Vec<Finding>,
    pub default_policy: Vec<Finding>,
    pub old_krbtgt: Vec<Finding>,
    pub obsolete_os: Vec<Finding>,
    pub empty_groups: Vec<Finding>,
    pub unexpected_pg: Vec<Finding>,
    pub dns_admin_paths: Vec<Finding>,
    pub operator_paths: Vec<Finding>,
    pub comp_admin_comp: Vec<Finding>,
    pub guest_accts: Vec<Finding>,
    pub tier0_violations: Vec<Finding>,
    pub cleartext_pwd: Vec<Finding>,
    pub snaffler_findings: Vec<crate::snaffler::scanner::ScanFinding>,
    pub paths_to_hv: Vec<PathResult>,
    pub stepping_stones: Vec<SteppingStone>,
    pub owned_paths: Vec<PathResult>,
}
