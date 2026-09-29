use super::graph::AdGraph;
use super::*;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use regex::Regex;
use std::collections::{HashMap, HashSet, VecDeque};

pub fn collection_health(g: &AdGraph) -> CollectionHealth {
    let mut h = CollectionHealth {
        users: 0,
        computers: 0,
        groups: 0,
        domains: 0,
        gpos: 0,
        ous: 0,
        total_nodes: g.node_count(),
        total_edges: g.edge_count(),
        has_session_edges: 0,
        local_admin_edges: 0,
    };
    for idx in g.graph.node_indices() {
        match g.graph[idx].node_type.as_str() {
            "User" => h.users += 1,
            "Computer" => h.computers += 1,
            "Group" => h.groups += 1,
            "Domain" => h.domains += 1,
            "GPO" => h.gpos += 1,
            "OU" => h.ous += 1,
            _ => {}
        }
    }
    for edge in g.graph.edge_references() {
        match edge.weight().label.as_str() {
            "HasSession" => h.has_session_edges += 1,
            "AdminTo" | "LocalAdmin" => h.local_admin_edges += 1,
            _ => {}
        }
    }
    h
}

pub fn kerberoastable(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        if !node.props.has_spn {
            continue;
        }
        if node.name.to_uppercase().starts_with("KRBTGT") {
            continue;
        }

        let is_priv = node.props.admin_count || is_high_priv_name(&node.name);
        results.push(Finding {
            principal: node.name.clone(),
            principal_type: "User".to_string(),
            detail: format!("SPNs: {}", node.props.service_principal_names.join(", ")),
            target: None,
            severity: if is_priv { 9 } else { 5 },
        });
    }
    results.sort_by(|a, b| b.severity.cmp(&a.severity));
    results
}

pub fn asrep_roastable(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        if !node.props.dont_req_preauth {
            continue;
        }

        let is_priv = node.props.admin_count || is_high_priv_name(&node.name);
        results.push(Finding {
            principal: node.name.clone(),
            principal_type: "User".to_string(),
            detail: "DontRequirePreAuth enabled".to_string(),
            target: None,
            severity: if is_priv { 9 } else { 5 },
        });
    }
    results
}

pub fn dcsync_rights(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("Domain") {
        let domain_name = g.graph[idx].name.clone();

        let mut get_changes: HashSet<NodeIndex> = HashSet::new();
        let mut get_changes_all: HashSet<NodeIndex> = HashSet::new();

        for edge in g.graph.edges_directed(idx, Direction::Incoming) {
            let label = edge.weight().label.as_str();
            let src = edge.source();
            match label {
                "GetChanges" => {
                    get_changes.insert(src);
                }
                "GetChangesAll" => {
                    get_changes_all.insert(src);
                }
                "GenericAll" => {
                    get_changes.insert(src);
                    get_changes_all.insert(src);
                }
                _ => {}
            }
        }

        let dcsync_sids: HashSet<NodeIndex> = get_changes
            .intersection(&get_changes_all)
            .copied()
            .collect();
        for sid_idx in dcsync_sids {
            let node = &g.graph[sid_idx];
            if is_expected_dcsync(&node.name, &node.object_id) {
                continue;
            }

            results.push(Finding {
                principal: node.name.clone(),
                principal_type: node.node_type.clone(),
                detail: format!("DCSync (GetChanges + GetChangesAll) on {}", domain_name),
                target: Some(domain_name.clone()),
                severity: 10,
            });
        }
    }
    results
}

pub fn dangerous_permissions(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let dangerous_rights = [
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
        "ForceChangePassword",
        "AddMember",
    ];

    for idx in g.graph.node_indices() {
        let target = &g.graph[idx];
        if !target.high_value {
            continue;
        }

        for edge in g.graph.edges_directed(idx, Direction::Incoming) {
            let label = edge.weight().label.as_str();
            if !dangerous_rights.contains(&label) {
                continue;
            }

            let src = &g.graph[edge.source()];
            if is_default_high_priv(&src.name) {
                continue;
            }

            results.push(Finding {
                principal: src.name.clone(),
                principal_type: src.node_type.clone(),
                detail: format!("{} on {}", label, target.name),
                target: Some(target.name.clone()),
                severity: 9,
            });
        }
    }
    results
}

pub fn unconstrained_delegation(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("Computer") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        if !node.props.unconstrained_delegation {
            continue;
        }

        let is_dc = g.graph.edges(idx).any(|e| {
            e.weight().label == "MemberOf"
                && g.graph[e.target()]
                    .name
                    .to_uppercase()
                    .contains("DOMAIN CONTROLLERS")
        });
        if is_dc {
            continue;
        }

        results.push(Finding {
            principal: node.name.clone(),
            principal_type: "Computer".to_string(),
            detail: "Unconstrained delegation (non-DC)".to_string(),
            target: None,
            severity: 8,
        });
    }
    results
}

pub fn adcs_vulns(g: &AdGraph) -> Vec<AdcsVuln> {
    let mut results = Vec::new();

    for tmpl_idx in g.nodes_by_type("CertTemplate") {
        let tmpl = &g.graph[tmpl_idx];
        if !tmpl.enabled {
            continue;
        }
        let tname = tmpl.name.clone();

        let has_enroll_from_unprivileged = g
            .graph
            .edges_directed(tmpl_idx, Direction::Incoming)
            .any(|e| {
                let label = e.weight().label.as_str();
                (label == "Enroll" || label == "GenericAll") && {
                    let src = &g.graph[e.source()];
                    is_broad_principal(&src.name)
                }
            });

        // ESC1: enrollee supplies subject + client auth + no manager approval + enrolled by low-priv
        if tmpl.props.enrollee_supplies_subject
            && tmpl.props.client_auth
            && !tmpl.props.requires_manager_approval
            && has_enroll_from_unprivileged
        {
            results.push(AdcsVuln {
                esc_type: "ESC1".to_string(),
                template: tname.clone(),
                ca: find_ca_for_template(g, tmpl_idx),
                detail: "Enrollee supplies subject + client auth + low-priv enrollment".to_string(),
                severity: 10,
            });
        }

        // ESC2: SubCA or Any Purpose EKU (not client_auth, not enrollment_agent)
        // Only flag if template has NO specific EKU restrictions (schema_version < 2 or no EKU at all)
        // This indicates SubCA or Any Purpose which can be used for any authentication
        if !tmpl.props.enrollment_agent
            && !tmpl.props.client_auth
            && !tmpl.props.enrollee_supplies_subject
            && tmpl.props.schema_version < 2
            && has_enroll_from_unprivileged
            && !tmpl.props.requires_manager_approval
        {
            results.push(AdcsVuln {
                esc_type: "ESC2".to_string(),
                template: tname.clone(),
                ca: find_ca_for_template(g, tmpl_idx),
                detail:
                    "SubCA/Any Purpose template (no EKU restriction) enrollable by low-priv users"
                        .to_string(),
                severity: 10,
            });
        }

        // ESC3: enrollment agent template (CertRequestAgent EKU)
        if tmpl.props.enrollment_agent
            && has_enroll_from_unprivileged
            && !tmpl.props.requires_manager_approval
        {
            results.push(AdcsVuln {
                esc_type: "ESC3".to_string(),
                template: tname.clone(),
                ca: find_ca_for_template(g, tmpl_idx),
                detail: "Enrollment agent template enrollable by low-priv users".to_string(),
                severity: 9,
            });
        }

        // ESC4: GenericAll/WriteDacl/WriteOwner on template by unprivileged
        let has_write = g
            .graph
            .edges_directed(tmpl_idx, Direction::Incoming)
            .any(|e| {
                let label = e.weight().label.as_str();
                (label == "GenericAll"
                    || label == "WriteDacl"
                    || label == "WriteOwner"
                    || label == "GenericWrite")
                    && is_broad_principal(&g.graph[e.source()].name)
            });
        if has_write {
            results.push(AdcsVuln {
                esc_type: "ESC4".to_string(),
                template: tname.clone(),
                ca: find_ca_for_template(g, tmpl_idx),
                detail: "Template writable by low-priv users".to_string(),
                severity: 10,
            });
        }

        // ESC13: no security extension + client auth + schema v2+ with 0 authorized sigs
        if tmpl.props.no_security_extension
            && tmpl.props.client_auth
            && tmpl.props.schema_version >= 2
            && tmpl.props.authorized_signatures_required == 0
            && has_enroll_from_unprivileged
        {
            results.push(AdcsVuln {
                esc_type: "ESC13".to_string(),
                template: tname.clone(),
                ca: find_ca_for_template(g, tmpl_idx),
                detail: "No security extension + client auth + no sig required".to_string(),
                severity: 10,
            });
        }
    }

    // ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on CA
    for ca_idx in g.nodes_by_type("EnterpriseCA") {
        let ca = &g.graph[ca_idx];
        if ca.props.user_specifies_san {
            results.push(AdcsVuln {
                esc_type: "ESC6".to_string(),
                template: "N/A".to_string(),
                ca: ca.name.clone(),
                detail: "EDITF_ATTRIBUTESUBJECTALTNAME2 enabled — any enrollee can specify SAN"
                    .to_string(),
                severity: 10,
            });
        }
    }

    // ESC7: ManageCA or ManageCertificates on CA by non-default principals
    for ca_idx in g.nodes_by_type("EnterpriseCA") {
        let ca_name = g.graph[ca_idx].name.clone();
        for edge in g.graph.edges_directed(ca_idx, Direction::Incoming) {
            let label = edge.weight().label.as_str();
            if label != "ManageCA" && label != "ManageCertificates" {
                continue;
            }
            let src = &g.graph[edge.source()];
            if is_default_high_priv(&src.name) {
                continue;
            }
            results.push(AdcsVuln {
                esc_type: "ESC7".to_string(),
                template: "N/A".to_string(),
                ca: ca_name.clone(),
                detail: format!("{} has {} on CA", src.name, label),
                severity: 9,
            });
        }
    }

    // ESC8: HTTP web enrollment on enterprise CAs
    for ca_idx in g.nodes_by_type("EnterpriseCA") {
        let ca = &g.graph[ca_idx];
        if ca.props.web_enrollment {
            results.push(AdcsVuln {
                esc_type: "ESC8".to_string(),
                template: "N/A".to_string(),
                ca: ca.name.clone(),
                detail: "HTTP web enrollment enabled".to_string(),
                severity: 9,
            });
        }
    }

    results
}

pub fn rbcd_abuse(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for edge in g.graph.edge_references() {
        if edge.weight().label != "AllowedToAct" {
            continue;
        }
        let src = &g.graph[edge.source()];
        let dst = &g.graph[edge.target()];
        results.push(Finding {
            principal: src.name.clone(),
            principal_type: src.node_type.clone(),
            detail: format!("RBCD: can impersonate to {}", dst.name),
            target: Some(dst.name.clone()),
            severity: 9,
        });
    }
    results
}

pub fn password_never_expires(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        if !node.props.pwd_never_expires {
            continue;
        }
        results.push(Finding {
            principal: node.name.clone(),
            principal_type: "User".to_string(),
            detail: "Password never expires".to_string(),
            target: None,
            severity: 4,
        });
    }
    results
}

pub fn password_not_required(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        if !node.props.pwd_not_required {
            continue;
        }
        results.push(Finding {
            principal: node.name.clone(),
            principal_type: "User".to_string(),
            detail: "Password not required (PASSWD_NOTREQD)".to_string(),
            target: None,
            severity: 8,
        });
    }
    results
}

pub fn password_in_description(g: &AdGraph) -> Vec<Finding> {
    let pattern =
        Regex::new(r"(?i)(password|pwd|pass|p@ss|passwd|p@ssw0rd|credentials?|secret)\s*[:=]")
            .unwrap();
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if let Some(desc) = &node.props.description {
            if pattern.is_match(desc) {
                results.push(Finding {
                    principal: node.name.clone(),
                    principal_type: "User".to_string(),
                    detail: "Password pattern found in description field [REDACTED]".to_string(),
                    target: None,
                    severity: 6,
                });
            }
        }
    }
    results
}

pub fn shadow_credentials(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let shadow_rights = ["GenericAll", "GenericWrite", "WriteProperty"];

    for idx in g.graph.node_indices() {
        let target = &g.graph[idx];
        if target.node_type != "User" && target.node_type != "Computer" {
            continue;
        }

        for edge in g.graph.edges_directed(idx, Direction::Incoming) {
            let label = edge.weight().label.as_str();
            if !shadow_rights.contains(&label) {
                continue;
            }

            let src = &g.graph[edge.source()];
            if is_default_high_priv(&src.name) {
                continue;
            }
            if is_expected_key_cred_holder(&src.name) {
                continue;
            }

            results.push(Finding {
                principal: src.name.clone(),
                principal_type: src.node_type.clone(),
                detail: format!(
                    "Can write msDS-KeyCredentialLink ({}) on {}",
                    label, target.name
                ),
                target: Some(target.name.clone()),
                severity: 8,
            });
        }
    }
    results
}

pub fn paths_to_high_value(g: &AdGraph) -> Vec<PathResult> {
    let hv_targets: Vec<NodeIndex> = g
        .graph
        .node_indices()
        .filter(|&idx| g.graph[idx].high_value)
        .filter(|&idx| matches!(g.graph[idx].node_type.as_str(), "Group" | "Domain"))
        .take(10)
        .collect();

    let mut results = Vec::new();
    for &target_idx in &hv_targets {
        let target = &g.graph[target_idx];
        let paths = bfs_paths_to(g, target_idx, 8, 5);

        if !paths.is_empty() {
            results.push(PathResult {
                target: target.name.clone(),
                target_type: target.node_type.clone(),
                paths,
            });
        }
    }
    results
}

pub fn stepping_stones(g: &AdGraph, paths: &[PathResult]) -> Vec<SteppingStone> {
    let mut intermediate_count: HashMap<NodeIndex, usize> = HashMap::new();
    let mut intermediate_inbound: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
    let mut intermediate_outbound: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
    let mut intermediate_targets: HashMap<NodeIndex, HashSet<String>> = HashMap::new();

    for pr in paths {
        for path in &pr.paths {
            let hops = &path.hops;
            if hops.len() < 2 {
                continue;
            }

            // Intermediates are all nodes except the first source and the final target
            for (i, hop) in hops.iter().enumerate() {
                // hop.source is an intermediate if it's not the very first source
                if i > 0 {
                    if let Some(idx) = g.get_index(&hop.source_id) {
                        *intermediate_count.entry(idx).or_insert(0) += 1;
                        intermediate_inbound
                            .entry(idx)
                            .or_default()
                            .insert(hops[i - 1].edge.clone());
                        intermediate_outbound
                            .entry(idx)
                            .or_default()
                            .insert(hop.edge.clone());
                        intermediate_targets
                            .entry(idx)
                            .or_default()
                            .insert(pr.target.clone());
                    }
                }
            }
        }
    }

    let mut stones: Vec<SteppingStone> = intermediate_count
        .iter()
        .filter(|(_, &count)| count > 1)
        .map(|(&idx, &count)| {
            let node = &g.graph[idx];
            SteppingStone {
                principal: node.name.clone(),
                principal_type: node.node_type.clone(),
                on_paths: count,
                inbound_edges: intermediate_inbound
                    .get(&idx)
                    .map(|s| s.iter().cloned().collect())
                    .unwrap_or_default(),
                outbound_edges: intermediate_outbound
                    .get(&idx)
                    .map(|s| s.iter().cloned().collect())
                    .unwrap_or_default(),
                hv_targets: intermediate_targets
                    .get(&idx)
                    .map(|s| s.iter().cloned().collect())
                    .unwrap_or_default(),
            }
        })
        .collect();

    stones.sort_by(|a, b| b.on_paths.cmp(&a.on_paths));
    stones.truncate(10);
    stones
}

fn bfs_paths_to(
    g: &AdGraph,
    target: NodeIndex,
    max_depth: usize,
    max_paths: usize,
) -> Vec<AttackPath> {
    let abuse_edges: HashSet<&str> = [
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
        "ForceChangePassword",
        "AddMember",
        "AllowedToAct",
        "AdminTo",
        "HasSession",
        "CanRDP",
        "ExecuteDCOM",
        "GetChanges",
        "GetChangesAll",
        "ReadLAPSPassword",
        "MemberOf",
    ]
    .iter()
    .copied()
    .collect();

    let mut results: Vec<AttackPath> = Vec::new();
    let mut queue: VecDeque<(NodeIndex, Vec<(NodeIndex, String, NodeIndex)>)> = VecDeque::new();

    for edge in g.graph.edges_directed(target, Direction::Incoming) {
        let src = edge.source();
        let label = edge.weight().label.clone();
        if !abuse_edges.contains(label.as_str()) {
            continue;
        }
        queue.push_back((src, vec![(src, label, target)]));
    }

    let mut visited: HashSet<NodeIndex> = HashSet::new();
    visited.insert(target);

    while let Some((current, path)) = queue.pop_front() {
        if path.len() > max_depth {
            continue;
        }
        if results.len() >= max_paths {
            break;
        }

        if visited.contains(&current) {
            continue;
        }
        visited.insert(current);

        let node = &g.graph[current];
        if (node.node_type == "User" || node.node_type == "Computer")
            && !node.high_value
            && node.enabled
        {
            let hops: Vec<PathHop> = path
                .iter()
                .rev()
                .map(|(s, e, t)| PathHop {
                    source: g.graph[*s].name.clone(),
                    source_id: g.graph[*s].object_id.clone(),
                    edge: e.clone(),
                    target: g.graph[*t].name.clone(),
                    target_id: g.graph[*t].object_id.clone(),
                })
                .collect();
            results.push(AttackPath { hops });
            continue;
        }

        for edge in g.graph.edges_directed(current, Direction::Incoming) {
            let src = edge.source();
            let label = edge.weight().label.clone();
            if !abuse_edges.contains(label.as_str()) {
                continue;
            }
            if visited.contains(&src) {
                continue;
            }

            let mut new_path = path.clone();
            new_path.push((src, label, current));
            queue.push_back((src, new_path));
        }
    }

    results
}

pub fn gpp_passwords(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for gpo_idx in g.nodes_by_type("GPO") {
        let gpo = &g.graph[gpo_idx];
        let linked_to: Vec<String> = g
            .graph
            .edges_directed(gpo_idx, Direction::Incoming)
            .filter(|e| e.weight().label == "GPLink")
            .map(|e| g.graph[e.source()].name.clone())
            .collect();
        if !linked_to.is_empty() {
            results.push(Finding {
                principal: gpo.name.clone(),
                principal_type: "GPO".to_string(),
                detail: format!(
                    "GPO linked to {} — check SYSVOL for GPP cpassword (MS14-025)",
                    linked_to.join(", ")
                ),
                target: None,
                severity: 8,
            });
        }
    }
    if results.len() > 20 {
        results.truncate(20);
    }
    results
}

pub fn smb_signing(g: &AdGraph) -> Vec<Finding> {
    let mut non_dc_count = 0usize;
    for idx in g.nodes_by_type("Computer") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        let is_dc = g.graph.edges(idx).any(|e| {
            e.weight().label == "MemberOf"
                && g.graph[e.target()]
                    .name
                    .to_uppercase()
                    .contains("DOMAIN CONTROLLERS")
        });
        if !is_dc {
            non_dc_count += 1;
        }
    }
    let mut results = Vec::new();
    if non_dc_count > 0 {
        results.push(Finding {
            principal: format!("{} non-DC computers", non_dc_count),
            principal_type: "Computer".to_string(),
            detail:
                "Workstations do not require SMB signing by default — potential NTLM relay targets"
                    .to_string(),
            target: None,
            severity: 7,
        });
    }
    results
}

pub fn ldap_signing(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    if g.node_count() > 0 {
        results.push(Finding {
            principal: g.domain.clone(),
            principal_type: "Domain".to_string(),
            detail: "Collection succeeded without LDAP signing — verify LdapServerIntegrity GPO"
                .to_string(),
            target: None,
            severity: 6,
        });
    }
    results
}

pub fn ntlm_relay_targets(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("Computer") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        let is_dc = g.graph.edges(idx).any(|e| {
            e.weight().label == "MemberOf"
                && g.graph[e.target()]
                    .name
                    .to_uppercase()
                    .contains("DOMAIN CONTROLLERS")
        });
        let has_admin_from_hv = g.graph.edges_directed(idx, Direction::Incoming).any(|e| {
            matches!(e.weight().label.as_str(), "AdminTo" | "LocalAdmin")
                && g.graph[e.source()].high_value
        });
        if is_dc {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "Computer".to_string(),
                detail: "DC — coercible via PetitPotam/DFSCoerce for NTLM relay".to_string(),
                target: None,
                severity: 8,
            });
        } else if has_admin_from_hv && node.props.unconstrained_delegation {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "Computer".to_string(),
                detail: "Unconstrained delegation + HV admin — high-value relay target".to_string(),
                target: None,
                severity: 9,
            });
        }
    }
    for ca_idx in g.nodes_by_type("EnterpriseCA") {
        if g.graph[ca_idx].props.web_enrollment {
            results.push(Finding {
                principal: g.graph[ca_idx].name.clone(),
                principal_type: "EnterpriseCA".to_string(),
                detail: "ESC8 web enrollment — NTLM relay to certificate enrollment".to_string(),
                target: None,
                severity: 9,
            });
        }
    }
    results
}

pub fn stale_computers(g: &AdGraph) -> Vec<Finding> {
    let now = chrono::Utc::now().timestamp();
    let ninety_days = 90 * 86400;
    let mut stale = 0usize;
    for idx in g.nodes_by_type("Computer") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        let last = node.props.last_logon;
        if last <= 0 || (now - last) > ninety_days {
            stale += 1;
        }
    }
    let mut results = Vec::new();
    if stale > 0 {
        results.push(Finding {
            principal: format!("{} computers", stale),
            principal_type: "Computer".to_string(),
            detail: "Last logon >90 days ago — stale accounts with potentially reusable machine credentials".to_string(),
            target: None,
            severity: 4,
        });
    }
    results
}

pub fn privileged_users_summary(g: &AdGraph) -> Vec<Finding> {
    let mut priv_enabled = 0usize;
    let mut priv_disabled = 0usize;
    let mut admin_count_users = 0usize;
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if node.props.admin_count {
            admin_count_users += 1;
            if node.enabled {
                priv_enabled += 1;
            } else {
                priv_disabled += 1;
            }
        }
    }
    let mut results = Vec::new();
    if admin_count_users > 0 {
        results.push(Finding {
            principal: format!("{} users (adminCount=true)", admin_count_users),
            principal_type: "User".to_string(),
            detail: format!(
                "{} enabled, {} disabled — protected by AdminSDHolder",
                priv_enabled, priv_disabled
            ),
            target: None,
            severity: 5,
        });
    }
    results
}

pub fn credential_exposure(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        let is_priv = node.props.admin_count
            || g.graph
                .edges(idx)
                .any(|e| e.weight().label == "MemberOf" && g.graph[e.target()].high_value);
        if !is_priv {
            continue;
        }
        if node.props.has_spn && !node.name.to_uppercase().starts_with("KRBTGT") {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "User".to_string(),
                detail: format!(
                    "Privileged + Kerberoastable (SPNs: {})",
                    node.props.service_principal_names.join(", ")
                ),
                target: None,
                severity: 9,
            });
        }
        if node.props.dont_req_preauth {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "User".to_string(),
                detail: "Privileged + AS-REP Roastable (DontRequirePreauth)".to_string(),
                target: None,
                severity: 9,
            });
        }
    }
    results
}

fn find_ca_for_template(g: &AdGraph, tmpl_idx: NodeIndex) -> String {
    let tmpl_oid = &g.graph[tmpl_idx].object_id;
    for ca_idx in g.nodes_by_type("EnterpriseCA") {
        if g.graph[ca_idx].props.enabled_templates.contains(tmpl_oid) {
            return g.graph[ca_idx].name.clone();
        }
    }
    for edge in g.graph.edges_directed(tmpl_idx, Direction::Incoming) {
        if edge.weight().label == "PublishedTo" {
            return g.graph[edge.source()].name.clone();
        }
    }
    "Unknown CA".to_string()
}

fn is_high_priv_name(name: &str) -> bool {
    let upper = name.to_uppercase();
    [
        "DOMAIN ADMINS",
        "ENTERPRISE ADMINS",
        "ADMINISTRATORS",
        "DOMAIN CONTROLLERS",
    ]
    .iter()
    .any(|p| upper.contains(p))
}

fn is_default_high_priv(name: &str) -> bool {
    let upper = name.to_uppercase();
    [
        "DOMAIN ADMINS@",
        "ENTERPRISE ADMINS@",
        "ADMINISTRATORS@",
        "DOMAIN CONTROLLERS@",
        "SCHEMA ADMINS@",
        "ACCOUNT OPERATORS@",
        "SYSTEM@",
        "CREATOR OWNER@",
    ]
    .iter()
    .any(|p| upper.starts_with(p))
}

fn is_broad_principal(name: &str) -> bool {
    let upper = name.to_uppercase();
    [
        "AUTHENTICATED USERS@",
        "DOMAIN USERS@",
        "DOMAIN COMPUTERS@",
        "EVERYONE@",
    ]
    .iter()
    .any(|p| upper.starts_with(p))
}

fn is_expected_dcsync(name: &str, sid: &str) -> bool {
    let upper = name.to_uppercase();
    if [
        "DOMAIN ADMINS@",
        "DOMAIN CONTROLLERS@",
        "ENTERPRISE ADMINS@",
        "ADMINISTRATORS@",
    ]
    .iter()
    .any(|p| upper.starts_with(p))
    {
        return true;
    }

    let expected_rids = ["512", "516", "518", "519", "498"];
    if let Some(rid) = sid.rsplit('-').next() {
        if expected_rids.contains(&rid) {
            return true;
        }
    }
    false
}

pub fn dns_zone_abuse(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let dangerous_rights = [
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "WriteProperty",
    ];

    for idx in g.graph.node_indices() {
        let node = &g.graph[idx];
        if !matches!(node.node_type.as_str(), "Container" | "OU") {
            continue;
        }
        let upper = node.name.to_uppercase();
        if !upper.contains("MICROSOFTDNS") && !upper.contains("DNSZONE") {
            continue;
        }

        for edge in g.graph.edges_directed(idx, Direction::Incoming) {
            let label = edge.weight().label.as_str();
            if !dangerous_rights.contains(&label) {
                continue;
            }
            let src = &g.graph[edge.source()];
            if is_default_high_priv(&src.name) {
                continue;
            }

            results.push(Finding {
                principal: src.name.clone(),
                principal_type: src.node_type.clone(),
                detail: format!(
                    "{} on DNS zone {} (ADIDNS record injection)",
                    label, node.name
                ),
                target: Some(node.name.clone()),
                severity: 8,
            });
        }
    }
    results
}

pub fn sccm_detection(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let dangerous_rights = ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner"];

    for idx in g.graph.node_indices() {
        let node = &g.graph[idx];
        let upper = node.name.to_uppercase();
        let is_sccm = match node.node_type.as_str() {
            "Computer" => {
                upper.contains("SCCM") || upper.contains("MECM") || upper.contains("SMS-")
            }
            "Group" => upper.contains("SMS ADMINS") || upper.contains("SCCM"),
            _ => false,
        };
        if !is_sccm {
            continue;
        }

        results.push(Finding {
            principal: node.name.clone(),
            principal_type: node.node_type.clone(),
            detail: "SCCM/MECM infrastructure detected".to_string(),
            target: None,
            severity: 3,
        });

        for edge in g.graph.edges_directed(idx, Direction::Incoming) {
            let label = edge.weight().label.as_str();
            if !dangerous_rights.contains(&label) {
                continue;
            }
            let src = &g.graph[edge.source()];
            if is_default_high_priv(&src.name) {
                continue;
            }

            results.push(Finding {
                principal: src.name.clone(),
                principal_type: src.node_type.clone(),
                detail: format!("{} on SCCM object {}", label, node.name),
                target: Some(node.name.clone()),
                severity: 7,
            });
        }
    }
    results
}

pub fn dpapi_exposure(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let read_rights = [
        "GenericAll",
        "ReadProperty",
        "GenericRead",
        "ReadLAPSPassword",
    ];

    for idx in g.graph.node_indices() {
        let node = &g.graph[idx];
        let upper = node.name.to_uppercase();
        if !matches!(node.node_type.as_str(), "Container" | "Unknown") {
            continue;
        }
        if !upper.contains("BCKUPKEY") && !upper.contains("DPAPI") {
            continue;
        }

        for edge in g.graph.edges_directed(idx, Direction::Incoming) {
            let label = edge.weight().label.as_str();
            if !read_rights.contains(&label) && label != "GenericAll" {
                continue;
            }
            let src = &g.graph[edge.source()];
            if is_default_high_priv(&src.name) {
                continue;
            }

            results.push(Finding {
                principal: src.name.clone(),
                principal_type: src.node_type.clone(),
                detail: format!("{} on DPAPI backup key {}", label, node.name),
                target: Some(node.name.clone()),
                severity: 9,
            });
        }
    }
    results
}

fn is_expected_key_cred_holder(name: &str) -> bool {
    let upper = name.to_uppercase();
    [
        "DOMAIN ADMINS@",
        "ENTERPRISE ADMINS@",
        "KEY ADMINS@",
        "ENTERPRISE KEY ADMINS@",
    ]
    .iter()
    .any(|p| upper.starts_with(p))
}

pub fn constrained_delegation(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();

    for idx in g.graph.node_indices() {
        let node = &g.graph[idx];
        if node.node_type != "User" && node.node_type != "Computer" {
            continue;
        }
        if !node.enabled {
            continue;
        }
        if !node.props.trusted_to_auth {
            continue;
        }

        let is_dc = node.node_type == "Computer"
            && g.graph.edges(idx).any(|e| {
                e.weight().label == "MemberOf"
                    && g.graph[e.target()]
                        .name
                        .to_uppercase()
                        .contains("DOMAIN CONTROLLERS")
            });
        if is_dc {
            continue;
        }

        let delegate_targets: Vec<String> = node.props.allowed_to_delegate.clone();
        let detail = if delegate_targets.is_empty() {
            "TrustedToAuthForDelegation (constrained delegation)".to_string()
        } else {
            format!("Constrained delegation to: {}", delegate_targets.join(", "))
        };

        results.push(Finding {
            principal: node.name.clone(),
            principal_type: node.node_type.clone(),
            detail,
            target: None,
            severity: 7,
        });
    }

    // Also check AllowedToDelegate edges
    for edge in g.graph.edge_references() {
        if edge.weight().label != "AllowedToDelegate" {
            continue;
        }
        let src = &g.graph[edge.source()];
        let dst = &g.graph[edge.target()];
        if !src.enabled {
            continue;
        }

        let already = results.iter().any(|f| f.principal == src.name);
        if already {
            continue;
        }

        results.push(Finding {
            principal: src.name.clone(),
            principal_type: src.node_type.clone(),
            detail: format!("AllowedToDelegate to {}", dst.name),
            target: Some(dst.name.clone()),
            severity: 7,
        });
    }

    results
}

pub fn gpo_abuse(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let dangerous_rights = [
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
    ];

    for gpo_idx in g.nodes_by_type("GPO") {
        let gpo = &g.graph[gpo_idx];
        let gpo_name = gpo.name.clone();

        // Find what the GPO is linked to
        let mut linked_to: Vec<String> = Vec::new();
        for edge in g.graph.edges_directed(gpo_idx, Direction::Outgoing) {
            if edge.weight().label == "GPLink" {
                linked_to.push(g.graph[edge.target()].name.clone());
            }
        }
        // Also check incoming GPLink (GPO -> OU/Domain direction varies)
        for edge in g.graph.edges_directed(gpo_idx, Direction::Incoming) {
            if edge.weight().label == "GPLink" {
                linked_to.push(g.graph[edge.source()].name.clone());
            }
        }

        // Find non-default principals with dangerous rights on this GPO
        for edge in g.graph.edges_directed(gpo_idx, Direction::Incoming) {
            let label = edge.weight().label.as_str();
            if !dangerous_rights.contains(&label) {
                continue;
            }

            let src = &g.graph[edge.source()];
            if is_default_high_priv(&src.name) {
                continue;
            }

            let linked_str = if linked_to.is_empty() {
                "no linked OUs found".to_string()
            } else {
                format!("linked to: {}", linked_to.join(", "))
            };

            results.push(Finding {
                principal: src.name.clone(),
                principal_type: src.node_type.clone(),
                detail: format!("{} on GPO {} ({})", label, gpo_name, linked_str),
                target: Some(gpo_name.clone()),
                severity: 7,
            });
        }
    }

    results
}

pub fn trust_abuse(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();

    for edge in g.graph.edge_references() {
        let label = &edge.weight().label;
        if !label.starts_with("TrustedDomain:") {
            continue;
        }

        let parts: Vec<&str> = label.split(':').collect();
        if parts.len() < 3 {
            continue;
        }

        let direction: u32 = parts[1].parse().unwrap_or(0);
        let trust_type: u32 = parts[2].parse().unwrap_or(0);

        let src = &g.graph[edge.source()];
        let dst = &g.graph[edge.target()];

        let dir_str = match direction {
            0 => "Disabled",
            1 => "Inbound",
            2 => "Outbound",
            3 => "Bidirectional",
            _ => "Unknown",
        };

        let type_str = match trust_type {
            1 => "Downlevel (NT4)",
            2 => "Uplevel (AD)",
            3 => "MIT (Kerberos)",
            4 => "DCE",
            _ => "Unknown",
        };

        let severity = if direction == 3 { 7 } else { 6 };

        results.push(Finding {
            principal: src.name.clone(),
            principal_type: "Domain".to_string(),
            detail: format!("Trust to {} — {} {}", dst.name, dir_str, type_str),
            target: Some(dst.name.clone()),
            severity,
        });
    }

    results
}

pub fn deep_group_nesting(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();

    let hv_group_names: HashSet<String> = g
        .graph
        .node_indices()
        .filter(|&idx| g.graph[idx].high_value && g.graph[idx].node_type == "Group")
        .map(|idx| g.graph[idx].name.clone())
        .collect();

    if hv_group_names.is_empty() {
        return results;
    }

    // For each user, walk MemberOf chains and find deep nesting reaching HV groups
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        if node.props.admin_count {
            continue;
        } // skip known admins

        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut queue: VecDeque<(NodeIndex, usize)> = VecDeque::new();
        queue.push_back((idx, 0));
        visited.insert(idx);

        while let Some((current, depth)) = queue.pop_front() {
            if depth > 10 {
                continue;
            } // cap recursion

            for edge in g.graph.edges(current) {
                if edge.weight().label != "MemberOf" {
                    continue;
                }
                let group_idx = edge.target();
                if visited.contains(&group_idx) {
                    continue;
                }
                visited.insert(group_idx);

                let group = &g.graph[group_idx];
                let new_depth = depth + 1;

                if new_depth > 3 && hv_group_names.contains(&group.name) {
                    results.push(Finding {
                        principal: node.name.clone(),
                        principal_type: "User".to_string(),
                        detail: format!("Nested {} hops deep into {}", new_depth, group.name),
                        target: Some(group.name.clone()),
                        severity: 6,
                    });
                }

                queue.push_back((group_idx, new_depth));
            }
        }
    }

    results.sort_by(|a, b| b.severity.cmp(&a.severity));
    results.truncate(50);
    results
}

pub fn owned_paths(g: &AdGraph, owned_list: &str) -> Vec<PathResult> {
    let abuse_edges: HashSet<&str> = [
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
        "ForceChangePassword",
        "AddMember",
        "AllowedToAct",
        "AdminTo",
        "HasSession",
        "CanRDP",
        "ExecuteDCOM",
        "CanPSRemote",
        "GetChanges",
        "GetChangesAll",
        "ReadLAPSPassword",
        "MemberOf",
    ]
    .iter()
    .copied()
    .collect();

    let owned_names: Vec<String> = owned_list
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();

    if owned_names.is_empty() {
        return Vec::new();
    }

    let owned_indices: Vec<NodeIndex> = owned_names
        .iter()
        .filter_map(|name| {
            g.graph
                .node_indices()
                .find(|&idx| g.graph[idx].name.to_uppercase() == *name)
        })
        .collect();

    if owned_indices.is_empty() {
        log::warn!("owned_paths: none of the specified principals found in graph");
        return Vec::new();
    }

    let mut all_results: Vec<PathResult> = Vec::new();

    for &start_idx in &owned_indices {
        let start_name = g.graph[start_idx].name.clone();
        let mut paths_for_owned: HashMap<NodeIndex, Vec<AttackPath>> = HashMap::new();

        let mut queue: VecDeque<(NodeIndex, Vec<(NodeIndex, String, NodeIndex)>)> = VecDeque::new();
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        visited.insert(start_idx);

        for edge in g.graph.edges(start_idx) {
            let label = edge.weight().label.as_str();
            if !abuse_edges.contains(label) {
                continue;
            }
            let dst = edge.target();
            queue.push_back((dst, vec![(start_idx, label.to_string(), dst)]));
        }

        while let Some((current, path)) = queue.pop_front() {
            if path.len() > 10 {
                continue;
            }
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);

            let node = &g.graph[current];
            if node.high_value {
                let hops: Vec<PathHop> = path
                    .iter()
                    .map(|(s, e, t)| PathHop {
                        source: g.graph[*s].name.clone(),
                        source_id: g.graph[*s].object_id.clone(),
                        edge: e.clone(),
                        target: g.graph[*t].name.clone(),
                        target_id: g.graph[*t].object_id.clone(),
                    })
                    .collect();

                paths_for_owned
                    .entry(current)
                    .or_default()
                    .push(AttackPath { hops });

                if paths_for_owned.values().map(|v| v.len()).sum::<usize>() >= 5 {
                    break;
                }
                continue;
            }

            for edge in g.graph.edges(current) {
                let label = edge.weight().label.as_str();
                if !abuse_edges.contains(label) {
                    continue;
                }
                let dst = edge.target();
                if visited.contains(&dst) {
                    continue;
                }
                let mut new_path = path.clone();
                new_path.push((current, label.to_string(), dst));
                queue.push_back((dst, new_path));
            }
        }

        for (target_idx, paths) in paths_for_owned {
            let target_node = &g.graph[target_idx];
            all_results.push(PathResult {
                target: format!("{} (from {})", target_node.name, start_name),
                target_type: target_node.node_type.clone(),
                paths,
            });
        }
    }

    all_results
}

pub fn compromise_dossier(g: &AdGraph, principal_name: &str) -> Vec<Finding> {
    let upper = principal_name.to_uppercase();
    let idx = match g
        .graph
        .node_indices()
        .find(|&i| g.graph[i].name.to_uppercase() == upper)
    {
        Some(i) => i,
        None => {
            log::warn!(
                "compromise_dossier: '{}' not found in graph",
                principal_name
            );
            return Vec::new();
        }
    };

    let mut results = Vec::new();
    let node = &g.graph[idx];

    results.push(Finding {
        principal: node.name.clone(),
        principal_type: node.node_type.clone(),
        detail: format!(
            "ObjectID: {}, Enabled: {}, HighValue: {}",
            node.object_id, node.enabled, node.high_value
        ),
        target: None,
        severity: 0,
    });

    for edge in g.graph.edges(idx) {
        let label = edge.weight().label.as_str();
        let target = &g.graph[edge.target()];
        let sev = match label {
            "GenericAll" | "WriteDacl" | "WriteOwner" | "Owns" => 9,
            "GenericWrite" | "ForceChangePassword" | "AddMember" => 8,
            "AdminTo" => 8,
            "CanRDP" | "ExecuteDCOM" | "CanPSRemote" => 7,
            "HasSession" => 6,
            "MemberOf" => 5,
            "AllowedToAct" | "AllowedToDelegate" => 7,
            "GetChanges" | "GetChangesAll" => 10,
            "ReadLAPSPassword" => 8,
            _ => 4,
        };
        results.push(Finding {
            principal: node.name.clone(),
            principal_type: node.node_type.clone(),
            detail: format!("{} --> {}", label, target.name),
            target: Some(target.name.clone()),
            severity: sev,
        });
    }

    // Also show incoming edges (who can control this principal)
    for edge in g.graph.edges_directed(idx, Direction::Incoming) {
        let label = edge.weight().label.as_str();
        let src = &g.graph[edge.source()];
        if matches!(
            label,
            "GenericAll"
                | "GenericWrite"
                | "WriteDacl"
                | "WriteOwner"
                | "Owns"
                | "ForceChangePassword"
        ) {
            results.push(Finding {
                principal: src.name.clone(),
                principal_type: src.node_type.clone(),
                detail: format!("INBOUND {} on {}", label, node.name),
                target: Some(node.name.clone()),
                severity: 3,
            });
        }
    }

    results.sort_by(|a, b| b.severity.cmp(&a.severity));
    results
}

// ─── P3 Security Checks ────────────────────────────────────────────────────

pub fn machine_account_quota(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("Domain") {
        let node = &g.graph[idx];
        results.push(Finding {
            principal: node.name.clone(),
            principal_type: "Domain".to_string(),
            detail: "MachineAccountQuota likely > 0 (default 10) — authenticated users can create computer accounts (RBCD abuse path)".to_string(),
            target: None,
            severity: 7,
        });
    }
    results
}

pub fn pre_windows_2000_access(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("Group") {
        let name_upper = g.graph[idx].name.to_uppercase();
        if !name_upper.contains("PRE-WINDOWS 2000") {
            continue;
        }

        let group_name = g.graph[idx].name.clone();
        let mut found_broad = false;
        for edge in g.graph.edges_directed(idx, Direction::Incoming) {
            if edge.weight().label != "MemberOf" {
                continue;
            }
            let member = &g.graph[edge.source()];
            let member_upper = member.name.to_uppercase();
            if member_upper.contains("AUTHENTICATED USERS") || member_upper.contains("EVERYONE") {
                results.push(Finding {
                    principal: member.name.clone(),
                    principal_type: member.node_type.clone(),
                    detail: format!(
                        "Member of {} — allows anonymous/pre-auth LDAP queries",
                        group_name
                    ),
                    target: Some(group_name.clone()),
                    severity: 7,
                });
                found_broad = true;
            }
        }
        if !found_broad {
            results.push(Finding {
                principal: group_name.clone(),
                principal_type: "Group".to_string(),
                detail: "Pre-Windows 2000 Compatible Access group exists — check membership"
                    .to_string(),
                target: None,
                severity: 4,
            });
        }
    }
    results
}

pub fn adminsdholder_abuse(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let dangerous_rights = [
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
    ];

    for idx in g.graph.node_indices() {
        let name_upper = g.graph[idx].name.to_uppercase();
        if !name_upper.contains("ADMINSDHOLDER") {
            continue;
        }

        let target_name = g.graph[idx].name.clone();
        for edge in g.graph.edges_directed(idx, Direction::Incoming) {
            let label = edge.weight().label.as_str();
            if !dangerous_rights.contains(&label) {
                continue;
            }
            let src = &g.graph[edge.source()];
            if is_default_high_priv(&src.name) {
                continue;
            }

            results.push(Finding {
                principal: src.name.clone(),
                principal_type: src.node_type.clone(),
                detail: format!(
                    "{} on AdminSDHolder — ACE propagates to all protected objects every 60 min",
                    label
                ),
                target: Some(target_name.clone()),
                severity: 9,
            });
        }
    }
    results
}

pub fn laps_deployment(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let computers = g.nodes_by_type("Computer");
    let total = computers.len();
    if total == 0 {
        return results;
    }

    let with_laps = computers
        .iter()
        .filter(|&&idx| g.graph[idx].props.has_laps)
        .count();
    let without_laps = total - with_laps;

    if without_laps > 0 {
        results.push(Finding {
            principal: format!("{}/{} computers", without_laps, total),
            principal_type: "Computer".to_string(),
            detail: format!(
                "No LAPS deployed ({:.0}% coverage)",
                (with_laps as f64 / total as f64) * 100.0
            ),
            target: None,
            severity: 6,
        });
    }

    for idx in g.graph.node_indices() {
        for edge in g.graph.edges_directed(idx, Direction::Incoming) {
            if edge.weight().label != "ReadLAPSPassword" {
                continue;
            }
            let src = &g.graph[edge.source()];
            if is_default_high_priv(&src.name) {
                continue;
            }
            let target = &g.graph[idx];
            results.push(Finding {
                principal: src.name.clone(),
                principal_type: src.node_type.clone(),
                detail: format!("Can read LAPS password on {}", target.name),
                target: Some(target.name.clone()),
                severity: 8,
            });
        }
    }
    results
}

pub fn print_spooler_check(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("Computer") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        let has_spooler = node.props.service_principal_names.iter().any(|spn| {
            let upper = spn.to_uppercase();
            upper.contains("SPOOLER") || upper.starts_with("HOST/")
        });

        if !has_spooler {
            continue;
        }

        let is_dc = g.graph.edges(idx).any(|e| {
            e.weight().label == "MemberOf"
                && g.graph[e.target()]
                    .name
                    .to_uppercase()
                    .contains("DOMAIN CONTROLLERS")
        });

        if !is_dc {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "Computer".to_string(),
                detail: "Print Spooler likely running — coercible via SpoolSample/PrinterBug"
                    .to_string(),
                target: None,
                severity: 7,
            });
        }
    }
    results
}

pub fn coerce_targets(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("Computer") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }

        let is_dc = g.graph.edges(idx).any(|e| {
            e.weight().label == "MemberOf"
                && g.graph[e.target()]
                    .name
                    .to_uppercase()
                    .contains("DOMAIN CONTROLLERS")
        });

        let has_unconstrained = node.props.unconstrained_delegation;
        let has_spooler = node
            .props
            .service_principal_names
            .iter()
            .any(|spn| spn.to_uppercase().contains("SPOOLER"));

        if is_dc {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "Computer".to_string(),
                detail: "Domain Controller — coercible via PetitPotam/DFSCoerce/PrinterBug"
                    .to_string(),
                target: None,
                severity: 8,
            });
        } else if has_unconstrained && has_spooler {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "Computer".to_string(),
                detail: "Unconstrained delegation + Spooler = high-value coerce target (relay TGT)"
                    .to_string(),
                target: None,
                severity: 9,
            });
        } else if has_unconstrained {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "Computer".to_string(),
                detail: "Unconstrained delegation — coerce target for TGT relay".to_string(),
                target: None,
                severity: 8,
            });
        }
    }
    results
}

pub fn coercion_paths(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();

    // Collect relay targets: unconstrained delegation hosts + ESC8 CAs
    let mut relay_targets: Vec<String> = Vec::new();
    for idx in g.nodes_by_type("Computer") {
        let n = &g.graph[idx];
        if n.props.unconstrained_delegation && n.enabled {
            relay_targets.push(format!("{} (unconstrained deleg)", n.name));
        }
    }
    for idx in g.nodes_by_type("EnterpriseCA") {
        if g.graph[idx].props.web_enrollment {
            relay_targets.push(format!("{} (ESC8)", g.graph[idx].name));
        }
    }

    // Coercion sources: DCs (PetitPotam/DFSCoerce), computers with spooler (PrinterBug)
    for idx in g.nodes_by_type("Computer") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }

        let is_dc = g.graph.edges(idx).any(|e| {
            e.weight().label == "MemberOf"
                && g.graph[e.target()]
                    .name
                    .to_uppercase()
                    .contains("DOMAIN CONTROLLERS")
        });
        let has_spooler = node
            .props
            .service_principal_names
            .iter()
            .any(|spn| spn.to_uppercase().contains("SPOOLER"));

        if !is_dc && !has_spooler {
            continue;
        }

        let coerce_method = if is_dc {
            "PetitPotam/DFSCoerce/PrinterBug (DC)"
        } else {
            "PrinterBug (MS-RPRN)"
        };

        for target in &relay_targets {
            if target.contains(&node.name) {
                continue;
            }
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "Computer".to_string(),
                detail: format!("Coerce via {} → relay to {}", coerce_method, target),
                target: Some(target.clone()),
                severity: 9,
            });
        }
    }

    results.truncate(50);
    results
}

pub fn domain_recon_summary(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();

    let mut total_users = 0usize;
    let mut enabled_users = 0usize;
    let mut total_computers = 0usize;
    let mut enabled_computers = 0usize;
    let mut dc_count = 0usize;
    let mut domain_count = 0usize;
    let mut trust_count = 0usize;
    let mut adcs_present = false;
    let mut priv_users = 0usize;

    for idx in g.graph.node_indices() {
        let n = &g.graph[idx];
        match n.node_type.as_str() {
            "User" => {
                total_users += 1;
                if n.enabled {
                    enabled_users += 1;
                }
                if n.props.admin_count {
                    priv_users += 1;
                }
            }
            "Computer" => {
                total_computers += 1;
                if n.enabled {
                    enabled_computers += 1;
                }
                let is_dc = g.graph.edges(idx).any(|e| {
                    e.weight().label == "MemberOf"
                        && g.graph[e.target()]
                            .name
                            .to_uppercase()
                            .contains("DOMAIN CONTROLLERS")
                });
                if is_dc {
                    dc_count += 1;
                }
            }
            "Domain" => {
                domain_count += 1;
            }
            "EnterpriseCA" | "RootCA" => {
                adcs_present = true;
            }
            _ => {}
        }
    }

    for edge in g.graph.edge_references() {
        if edge.weight().label.starts_with("TrustedDomain") {
            trust_count += 1;
        }
    }

    results.push(Finding {
        principal: g.domain.clone(),
        principal_type: "Domain".to_string(),
        detail: format!(
            "Users: {}/{} enabled | Computers: {}/{} enabled | DCs: {} | Domains: {} | Trusts: {} | ADCS: {} | Privileged (adminCount): {}",
            enabled_users, total_users,
            enabled_computers, total_computers,
            dc_count, domain_count, trust_count,
            if adcs_present { "yes" } else { "no" },
            priv_users,
        ),
        target: None,
        severity: 3,
    });

    let session_edges = g
        .graph
        .edge_references()
        .filter(|e| e.weight().label == "HasSession")
        .count();
    let admin_edges = g
        .graph
        .edge_references()
        .filter(|e| matches!(e.weight().label.as_str(), "AdminTo" | "LocalAdmin"))
        .count();

    results.push(Finding {
        principal: g.domain.clone(),
        principal_type: "Domain".to_string(),
        detail: format!(
            "Session edges: {} | AdminTo edges: {} | Graph: {} nodes, {} edges",
            session_edges,
            admin_edges,
            g.node_count(),
            g.edge_count()
        ),
        target: None,
        severity: 3,
    });

    results
}

pub fn delegation_overview(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();

    for idx in g.graph.node_indices() {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        if node.node_type != "Computer" && node.node_type != "User" {
            continue;
        }

        let is_dc = node.node_type == "Computer"
            && g.graph.edges(idx).any(|e| {
                e.weight().label == "MemberOf"
                    && g.graph[e.target()]
                        .name
                        .to_uppercase()
                        .contains("DOMAIN CONTROLLERS")
            });

        // Unconstrained delegation (non-DC)
        if node.props.unconstrained_delegation && !is_dc {
            let has_path_to_hv = g.graph.edges(idx).any(|e| g.graph[e.target()].high_value);
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: node.node_type.clone(),
                detail: format!(
                    "Unconstrained delegation{}",
                    if has_path_to_hv {
                        " → reaches high-value target"
                    } else {
                        ""
                    }
                ),
                target: None,
                severity: if has_path_to_hv { 9 } else { 8 },
            });
        }

        // Constrained delegation (TrustedToAuth)
        if node.props.trusted_to_auth {
            let targets: Vec<String> = node.props.allowed_to_delegate.clone();
            let target_str = if targets.is_empty() {
                "none".to_string()
            } else {
                targets.join(", ")
            };
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: node.node_type.clone(),
                detail: format!("Constrained delegation (TrustedToAuth) → {}", target_str),
                target: None,
                severity: 7,
            });
        }

        // RBCD (AllowedToAct incoming edges)
        if node.node_type == "Computer" {
            let rbcd_sources: Vec<String> = g
                .graph
                .edges_directed(idx, Direction::Incoming)
                .filter(|e| e.weight().label == "AllowedToAct")
                .map(|e| g.graph[e.source()].name.clone())
                .collect();
            if !rbcd_sources.is_empty() {
                results.push(Finding {
                    principal: node.name.clone(),
                    principal_type: "Computer".to_string(),
                    detail: format!("RBCD target — allowed to act: {}", rbcd_sources.join(", ")),
                    target: None,
                    severity: 9,
                });
            }
        }
    }

    results.sort_by(|a, b| b.severity.cmp(&a.severity));
    results.truncate(50);
    results
}

// ─── PowerView.py-derived checks ───────────────────────────────────────────

pub fn foreign_users(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let primary_domain = g.domain.to_uppercase();
    for idx in g.graph.node_indices() {
        let node = &g.graph[idx];
        if node.node_type != "User" {
            continue;
        }
        let name_upper = node.name.to_uppercase();
        if name_upper.is_empty() || name_upper.contains(&primary_domain) {
            continue;
        }
        if !name_upper.contains('@') {
            continue;
        }
        let node_domain = name_upper.rsplit('@').next().unwrap_or("");
        if node_domain.is_empty() || node_domain == primary_domain {
            continue;
        }
        let has_cross_membership = g.graph.edges(idx).any(|e| {
            e.weight().label == "MemberOf" && {
                let t = &g.graph[e.target()];
                t.name.to_uppercase().contains(&primary_domain)
            }
        });
        if has_cross_membership {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "User".to_string(),
                detail: format!(
                    "Foreign user from {} with group membership in {}",
                    node_domain, primary_domain
                ),
                target: None,
                severity: 6,
            });
        }
    }
    results
}

pub fn foreign_groups(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let primary_domain = g.domain.to_uppercase();
    for idx in g.nodes_by_type("Group") {
        let group = &g.graph[idx];
        if !group.name.to_uppercase().contains(&primary_domain) {
            continue;
        }
        let foreign_members: Vec<String> = g
            .graph
            .edges_directed(idx, Direction::Incoming)
            .filter(|e| e.weight().label == "MemberOf")
            .filter(|e| {
                let src = &g.graph[e.source()];
                let src_upper = src.name.to_uppercase();
                src_upper.contains('@') && !src_upper.contains(&primary_domain)
            })
            .map(|e| g.graph[e.source()].name.clone())
            .take(5)
            .collect();
        if !foreign_members.is_empty() {
            results.push(Finding {
                principal: group.name.clone(),
                principal_type: "Group".to_string(),
                detail: format!(
                    "{} foreign member(s): {}",
                    foreign_members.len(),
                    foreign_members.join(", ")
                ),
                target: None,
                severity: 6,
            });
        }
    }
    results
}

pub fn gpo_local_groups(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("GPO") {
        let gpo = &g.graph[idx];
        let linked_to: Vec<String> = g
            .graph
            .edges(idx)
            .filter(|e| e.weight().label == "GPLink")
            .map(|e| g.graph[e.target()].name.clone())
            .collect();
        if linked_to.is_empty() {
            continue;
        }
        let admin_edges: Vec<String> = g
            .graph
            .edges_directed(idx, Direction::Incoming)
            .filter(|e| {
                matches!(
                    e.weight().label.as_str(),
                    "GenericAll" | "GenericWrite" | "WriteDacl" | "WriteOwner"
                )
            })
            .filter(|e| !is_default_high_priv(&g.graph[e.source()].name))
            .map(|e| format!("{} ({})", g.graph[e.source()].name, e.weight().label))
            .take(3)
            .collect();
        if !admin_edges.is_empty() {
            results.push(Finding {
                principal: gpo.name.clone(),
                principal_type: "GPO".to_string(),
                detail: format!(
                    "Linked to {} | Writable by: {}",
                    linked_to.join(", "),
                    admin_edges.join("; ")
                ),
                target: None,
                severity: 7,
            });
        }
    }
    results
}

pub fn find_local_admin_targets(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for edge in g.graph.edge_references() {
        let label = edge.weight().label.as_str();
        if label != "AdminTo" && label != "LocalAdmin" {
            continue;
        }
        let src = &g.graph[edge.source()];
        let dst = &g.graph[edge.target()];
        if dst.node_type != "Computer" {
            continue;
        }
        if is_default_high_priv(&src.name) {
            continue;
        }
        results.push(Finding {
            principal: src.name.clone(),
            principal_type: src.node_type.clone(),
            detail: format!("{} on {}", label, dst.name),
            target: Some(dst.name.clone()),
            severity: 7,
        });
    }
    results.truncate(50);
    results
}

pub fn exchange_server_detection(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("Computer") {
        let node = &g.graph[idx];
        let name_upper = node.name.to_uppercase();
        let has_exchange_spn = node.props.service_principal_names.iter().any(|s| {
            s.to_uppercase().contains("EXCHANGEMDB") || s.to_uppercase().contains("EXCHANGEAB")
        });
        if name_upper.contains("EXCHANGE") || has_exchange_spn {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "Computer".to_string(),
                detail: "Exchange server detected".to_string(),
                target: None,
                severity: 7,
            });
        }
    }
    for idx in g.nodes_by_type("Group") {
        let node = &g.graph[idx];
        let upper = node.name.to_uppercase();
        if upper.contains("EXCHANGE WINDOWS PERMISSIONS")
            || upper.contains("EXCHANGE TRUSTED SUBSYSTEM")
            || upper.contains("ORGANIZATION MANAGEMENT")
        {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "Group".to_string(),
                detail: "Exchange privileged group".to_string(),
                target: None,
                severity: 7,
            });
        }
    }
    results
}

pub fn gmsa_exposure(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.graph.node_indices() {
        let node = &g.graph[idx];
        if node.node_type != "User" {
            continue;
        }
        let is_gmsa = node.name.ends_with('$')
            || node
                .props
                .sam_account_name
                .as_deref()
                .map(|s| s.ends_with('$'))
                .unwrap_or(false);
        if !is_gmsa {
            continue;
        }
        let readers: Vec<String> = g
            .graph
            .edges_directed(idx, Direction::Incoming)
            .filter(|e| e.weight().label == "ReadGMSAPassword")
            .filter(|e| !is_default_high_priv(&g.graph[e.source()].name))
            .map(|e| g.graph[e.source()].name.clone())
            .collect();
        if !readers.is_empty() {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "User (gMSA)".to_string(),
                detail: format!("gMSA password readable by: {}", readers.join(", ")),
                target: None,
                severity: 8,
            });
        }
    }
    results
}

pub fn rbcd_configurable(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let write_rights = [
        "GenericAll",
        "GenericWrite",
        "WriteProperty",
        "Owns",
        "WriteOwner",
    ];
    for idx in g.nodes_by_type("Computer") {
        let target = &g.graph[idx];
        let writers: Vec<String> = g
            .graph
            .edges_directed(idx, Direction::Incoming)
            .filter(|e| write_rights.contains(&e.weight().label.as_str()))
            .filter(|e| !is_default_high_priv(&g.graph[e.source()].name))
            .filter(|e| !is_broad_principal(&g.graph[e.source()].name))
            .map(|e| format!("{} ({})", g.graph[e.source()].name, e.weight().label))
            .take(5)
            .collect();
        if !writers.is_empty() {
            results.push(Finding {
                principal: target.name.clone(),
                principal_type: "Computer".to_string(),
                detail: format!("RBCD configurable by: {}", writers.join("; ")),
                target: None,
                severity: 9,
            });
        }
    }
    results.truncate(50);
    results
}

pub fn shadow_cred_via_owner(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.graph.node_indices() {
        let target = &g.graph[idx];
        if target.node_type != "User" && target.node_type != "Computer" {
            continue;
        }
        let owners: Vec<String> = g
            .graph
            .edges_directed(idx, Direction::Incoming)
            .filter(|e| e.weight().label == "WriteOwner")
            .filter(|e| !is_default_high_priv(&g.graph[e.source()].name))
            .filter(|e| !is_expected_key_cred_holder(&g.graph[e.source()].name))
            .map(|e| g.graph[e.source()].name.clone())
            .collect();
        if !owners.is_empty() {
            results.push(Finding {
                principal: owners.join(", "),
                principal_type: "Various".to_string(),
                detail: format!(
                    "WriteOwner on {} — can grant self write to msDS-KeyCredentialLink",
                    target.name
                ),
                target: Some(target.name.clone()),
                severity: 8,
            });
        }
    }
    results.truncate(30);
    results
}

pub fn stale_users(g: &AdGraph) -> Vec<Finding> {
    let now = chrono::Utc::now().timestamp();
    let threshold = 90 * 86400; // 90 days
    let mut results = Vec::new();
    let mut total = 0usize;
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        let last = node.props.last_logon;
        let stale = if last == -1 {
            true
        } else if last > 0 {
            (now - last) > threshold
        } else {
            false
        };
        if !stale {
            continue;
        }
        total += 1;
        if results.len() < 50 {
            let age = if last == -1 {
                "never logged in".to_string()
            } else {
                format!("{} days ago", (now - last) / 86400)
            };
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "User".to_string(),
                detail: format!("Stale account ({})", age),
                target: None,
                severity: 4,
            });
        }
    }
    if total > 50 {
        results.push(Finding {
            principal: format!("{} stale users total", total),
            principal_type: "Summary".to_string(),
            detail: format!("{} enabled users with no logon in >90 days", total),
            target: None,
            severity: 4,
        });
    }
    results
}

pub fn fine_grained_password_policy(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let pso_containers: Vec<NodeIndex> = g
        .graph
        .node_indices()
        .filter(|&idx| {
            let n = &g.graph[idx];
            let upper = n.name.to_uppercase();
            upper.contains("PASSWORD SETTINGS") || upper.contains("PSO")
        })
        .collect();
    if pso_containers.is_empty() {
        results.push(Finding {
            principal: "Domain".to_string(),
            principal_type: "Info".to_string(),
            detail: "No Fine-Grained Password Policy (FGPP/PSO) objects detected. Manual verification recommended.".to_string(),
            target: None,
            severity: 5,
        });
    } else {
        for &idx in &pso_containers {
            let name = g.graph[idx].name.clone();
            results.push(Finding {
                principal: name,
                principal_type: "Container".to_string(),
                detail: "Fine-Grained Password Policy object detected".to_string(),
                target: None,
                severity: 5,
            });
        }
    }
    results
}

pub fn password_age_audit(g: &AdGraph) -> Vec<Finding> {
    let now = chrono::Utc::now().timestamp();
    let year = 365 * 86400i64;
    let mut results = Vec::new();
    let mut old_count = 0usize;
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        let pwd_set = node.props.pwd_last_set;
        if pwd_set <= 0 {
            continue;
        }
        let age_days = (now - pwd_set) / 86400;
        if (now - pwd_set) <= year {
            continue;
        }
        old_count += 1;
        let sev = if node.props.admin_count { 8 } else { 5 };
        if results.len() < 50 {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "User".to_string(),
                detail: format!(
                    "Password age: {} days{}",
                    age_days,
                    if node.props.admin_count {
                        " [PRIVILEGED]"
                    } else {
                        ""
                    }
                ),
                target: None,
                severity: sev,
            });
        }
    }
    results.sort_by(|a, b| b.severity.cmp(&a.severity));
    if old_count > 50 {
        results.push(Finding {
            principal: format!("{} users total", old_count),
            principal_type: "Summary".to_string(),
            detail: format!(
                "{} enabled users with passwords older than 1 year",
                old_count
            ),
            target: None,
            severity: 5,
        });
    }
    results
}

pub fn account_expiration(g: &AdGraph) -> Vec<Finding> {
    let mut priv_no_expire = 0usize;
    let mut total_no_expire = 0usize;
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        total_no_expire += 1;
        if node.props.admin_count {
            priv_no_expire += 1;
            if results.len() < 20 {
                results.push(Finding {
                    principal: node.name.clone(),
                    principal_type: "User".to_string(),
                    detail: "Privileged account with no expiration date".to_string(),
                    target: None,
                    severity: 4,
                });
            }
        }
    }
    if priv_no_expire > 0 {
        results.insert(
            0,
            Finding {
                principal: format!("{} privileged / {} total", priv_no_expire, total_no_expire),
                principal_type: "Summary".to_string(),
                detail: "Accounts without expiration date set".to_string(),
                target: None,
                severity: 4,
            },
        );
    }
    results
}

pub fn orphan_accounts(g: &AdGraph) -> Vec<Finding> {
    let now = chrono::Utc::now().timestamp();
    let threshold = 180 * 86400i64;
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        let has_desc = node
            .props
            .description
            .as_ref()
            .map(|d| !d.is_empty())
            .unwrap_or(false);
        if has_desc {
            continue;
        }
        let stale = node.props.last_logon == -1
            || (node.props.last_logon > 0 && (now - node.props.last_logon) > threshold);
        if !stale {
            continue;
        }
        let membership_count = g
            .graph
            .edges(idx)
            .filter(|e| e.weight().label == "MemberOf")
            .count();
        if membership_count > 1 {
            continue;
        }
        if results.len() >= 50 {
            break;
        }
        results.push(Finding {
            principal: node.name.clone(),
            principal_type: "User".to_string(),
            detail: "Potential orphan: no description, no recent logon, minimal group membership"
                .to_string(),
            target: None,
            severity: 5,
        });
    }
    results
}

pub fn indirect_admin_members(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let hv_groups: Vec<NodeIndex> = g
        .graph
        .node_indices()
        .filter(|&idx| g.graph[idx].high_value && g.graph[idx].node_type == "Group")
        .collect();

    for &hv_idx in &hv_groups {
        let hv_name = g.graph[hv_idx].name.clone();
        let mut indirect_count = 0usize;
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut queue: VecDeque<(NodeIndex, usize)> = VecDeque::new();
        visited.insert(hv_idx);
        for edge in g.graph.edges_directed(hv_idx, Direction::Incoming) {
            if edge.weight().label == "MemberOf" {
                let src = edge.source();
                if visited.insert(src) {
                    queue.push_back((src, 1));
                }
            }
        }
        while let Some((current, depth)) = queue.pop_front() {
            if depth > 1 && g.graph[current].node_type == "User" && g.graph[current].enabled {
                indirect_count += 1;
            }
            if depth >= 10 {
                continue;
            }
            for edge in g.graph.edges_directed(current, Direction::Incoming) {
                if edge.weight().label == "MemberOf" {
                    let src = edge.source();
                    if visited.insert(src) {
                        queue.push_back((src, depth + 1));
                    }
                }
            }
        }
        if indirect_count > 0 {
            results.push(Finding {
                principal: hv_name,
                principal_type: "Group".to_string(),
                detail: format!(
                    "{} indirect members through nested group chains",
                    indirect_count
                ),
                target: None,
                severity: 6,
            });
        }
    }
    results
}

pub fn service_account_hygiene(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        if !node.props.has_spn {
            continue;
        }
        if node.name.to_uppercase().starts_with("KRBTGT") {
            continue;
        }
        let mut risks: Vec<&str> = Vec::new();
        if node.props.pwd_never_expires {
            risks.push("pwd_never_expires");
        }
        if node.props.admin_count {
            risks.push("admin_count");
        }
        if node.props.unconstrained_delegation {
            risks.push("unconstrained_delegation");
        }
        if node.props.pwd_last_set > 0 {
            let now = chrono::Utc::now().timestamp();
            if (now - node.props.pwd_last_set) > 365 * 86400 {
                risks.push("password_age>1yr");
            }
        }
        if risks.is_empty() {
            continue;
        }
        let sev = if risks.len() >= 3 { 7 } else { 5 };
        results.push(Finding {
            principal: node.name.clone(),
            principal_type: "User".to_string(),
            detail: format!("Service account risks: {}", risks.join(", ")),
            target: None,
            severity: sev,
        });
    }
    results.sort_by(|a, b| b.severity.cmp(&a.severity));
    results
}

pub fn protected_users_audit(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let protected_group: Option<NodeIndex> = g.graph.node_indices().find(|&idx| {
        g.graph[idx].node_type == "Group"
            && g.graph[idx].name.to_uppercase().contains("PROTECTED USERS")
    });

    let protected_members: HashSet<NodeIndex> = match protected_group {
        Some(pg) => g
            .graph
            .edges_directed(pg, Direction::Incoming)
            .filter(|e| e.weight().label == "MemberOf")
            .map(|e| e.source())
            .collect(),
        None => HashSet::new(),
    };

    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled || !node.props.admin_count {
            continue;
        }
        if protected_members.contains(&idx) {
            continue;
        }
        if results.len() >= 30 {
            break;
        }
        results.push(Finding {
            principal: node.name.clone(),
            principal_type: "User".to_string(),
            detail: "Privileged account NOT in Protected Users group".to_string(),
            target: None,
            severity: 6,
        });
    }
    results
}

pub fn dc_owner_audit(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let dc_group: Option<NodeIndex> = g.graph.node_indices().find(|&idx| {
        g.graph[idx].node_type == "Group"
            && g.graph[idx]
                .name
                .to_uppercase()
                .contains("DOMAIN CONTROLLERS@")
    });

    let dcs: HashSet<NodeIndex> = match dc_group {
        Some(dcg) => g
            .graph
            .edges_directed(dcg, Direction::Incoming)
            .filter(|e| e.weight().label == "MemberOf")
            .map(|e| e.source())
            .filter(|&s| g.graph[s].node_type == "Computer")
            .collect(),
        None => HashSet::new(),
    };

    for &dc_idx in &dcs {
        for edge in g.graph.edges_directed(dc_idx, Direction::Incoming) {
            if edge.weight().label != "Owns" {
                continue;
            }
            let owner = &g.graph[edge.source()];
            if is_default_high_priv(&owner.name) {
                continue;
            }
            results.push(Finding {
                principal: owner.name.clone(),
                principal_type: owner.node_type.clone(),
                detail: format!("Owns DC {}", g.graph[dc_idx].name),
                target: Some(g.graph[dc_idx].name.clone()),
                severity: 9,
            });
        }
    }
    results
}

pub fn rodc_detection(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let rodc_group: Option<NodeIndex> = g.graph.node_indices().find(|&idx| {
        g.graph[idx].node_type == "Group"
            && g.graph[idx]
                .name
                .to_uppercase()
                .contains("READ-ONLY DOMAIN CONTROLLERS")
    });

    if let Some(rg) = rodc_group {
        for edge in g.graph.edges_directed(rg, Direction::Incoming) {
            if edge.weight().label != "MemberOf" {
                continue;
            }
            let node = &g.graph[edge.source()];
            if node.node_type != "Computer" {
                continue;
            }
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "Computer".to_string(),
                detail: "Read-Only Domain Controller (limited credential caching)".to_string(),
                target: None,
                severity: 3,
            });
        }
    }
    results
}

pub fn recently_created_objects(g: &AdGraph) -> Vec<Finding> {
    let now = chrono::Utc::now().timestamp();
    let thirty_days = 30 * 86400i64;
    let mut results = Vec::new();
    for idx in g.graph.node_indices() {
        let node = &g.graph[idx];
        if !matches!(node.node_type.as_str(), "User" | "Group") {
            continue;
        }
        let created = node.props.when_created;
        if created <= 0 {
            continue;
        }
        if (now - created) > thirty_days {
            continue;
        }
        let age_days = (now - created) / 86400;
        if results.len() >= 50 {
            break;
        }
        results.push(Finding {
            principal: node.name.clone(),
            principal_type: node.node_type.clone(),
            detail: format!("Created {} days ago", age_days),
            target: None,
            severity: 4,
        });
    }
    results
}

pub fn locked_accounts(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    results.push(Finding {
        principal: "Domain".to_string(),
        principal_type: "Info".to_string(),
        detail: "Locked account detection requires live LDAP query (lockoutTime attribute). Use rustad with live connection for accurate results.".to_string(),
        target: None,
        severity: 3,
    });
    results
}

pub fn tombstone_recycle_bin(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let has_deleted = g.graph.node_indices().any(|idx| {
        let n = &g.graph[idx];
        n.name.to_uppercase().contains("DELETED OBJECTS")
            || n.name.to_uppercase().contains("RECYCLE BIN")
    });
    if !has_deleted {
        results.push(Finding {
            principal: "Domain".to_string(),
            principal_type: "Info".to_string(),
            detail:
                "AD Recycle Bin may not be enabled. Deleted objects cannot be recovered without it."
                    .to_string(),
            target: None,
            severity: 4,
        });
    }
    results
}

pub fn default_domain_policy_audit(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let dangerous = ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner"];
    for idx in g.nodes_by_type("GPO") {
        let name_upper = g.graph[idx].name.to_uppercase();
        if !name_upper.contains("DEFAULT DOMAIN POLICY")
            && !name_upper.contains("DEFAULT DOMAIN CONTROLLERS POLICY")
        {
            continue;
        }
        for edge in g.graph.edges_directed(idx, Direction::Incoming) {
            let label = edge.weight().label.as_str();
            if !dangerous.contains(&label) {
                continue;
            }
            let src = &g.graph[edge.source()];
            if is_default_high_priv(&src.name) {
                continue;
            }
            results.push(Finding {
                principal: src.name.clone(),
                principal_type: src.node_type.clone(),
                detail: format!("{} on {}", label, g.graph[idx].name),
                target: Some(g.graph[idx].name.clone()),
                severity: 8,
            });
        }
    }
    results
}

pub fn exchange_permissions(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let exchange_groups: Vec<NodeIndex> = g
        .graph
        .node_indices()
        .filter(|&idx| {
            let n = &g.graph[idx];
            n.node_type == "Group" && {
                let upper = n.name.to_uppercase();
                upper.contains("EXCHANGE WINDOWS PERMISSIONS")
                    || upper.contains("ORGANIZATION MANAGEMENT")
                    || upper.contains("EXCHANGE TRUSTED SUBSYSTEM")
            }
        })
        .collect();

    for &group_idx in &exchange_groups {
        let group_name = g.graph[group_idx].name.clone();
        for edge in g.graph.edges(group_idx) {
            let label = edge.weight().label.as_str();
            let target = &g.graph[edge.target()];
            if target.node_type == "Domain"
                && matches!(label, "WriteDacl" | "GenericAll" | "WriteOwner")
            {
                results.push(Finding {
                    principal: group_name.clone(),
                    principal_type: "Group".to_string(),
                    detail: format!(
                        "{} on Domain {} — can grant DCSync to any user",
                        label, target.name
                    ),
                    target: Some(target.name.clone()),
                    severity: 9,
                });
            }
        }
    }
    results
}

pub fn scan_descriptions_for_secrets(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if let Some(desc) = &node.props.description {
            if desc.is_empty() {
                continue;
            }
            let hits = crate::snaffler::rules::scan_content(desc);
            for hit in hits {
                results.push(Finding {
                    principal: node.name.clone(),
                    principal_type: "User".to_string(),
                    detail: format!("Secret in description: {} [REDACTED]", hit.rule_name),
                    target: None,
                    severity: 7,
                });
            }
        }
    }
    for idx in g.nodes_by_type("Computer") {
        let node = &g.graph[idx];
        if let Some(desc) = &node.props.description {
            if desc.is_empty() {
                continue;
            }
            let hits = crate::snaffler::rules::scan_content(desc);
            for hit in hits {
                results.push(Finding {
                    principal: node.name.clone(),
                    principal_type: "Computer".to_string(),
                    detail: format!("Secret in description: {} [REDACTED]", hit.rule_name),
                    target: None,
                    severity: 7,
                });
            }
        }
    }
    results
}

// ─── AD_Miner checks ──────────────────────────────────────────────────────

pub fn old_krbtgt_password(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let now = chrono::Utc::now().timestamp();
    let threshold = 180 * 86400i64;
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.name.to_uppercase().starts_with("KRBTGT@") {
            continue;
        }
        if node.props.pwd_last_set <= 0 {
            continue;
        }
        let age_secs = now - node.props.pwd_last_set;
        if age_secs > threshold {
            let days = age_secs / 86400;
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "User".to_string(),
                detail: format!("KRBTGT password is {} days old (golden ticket risk)", days),
                target: None,
                severity: 8,
            });
        }
    }
    results
}

pub fn obsolete_os(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let patterns = [
        "2003",
        "2008",
        " XP ",
        "VISTA",
        "WINDOWS 7",
        "WINDOWS 2000",
        "NT 4",
    ];
    for idx in g.nodes_by_type("Computer") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        let desc_upper = node
            .props
            .description
            .as_deref()
            .unwrap_or("")
            .to_uppercase();
        for pat in &patterns {
            if desc_upper.contains(pat) {
                results.push(Finding {
                    principal: node.name.clone(),
                    principal_type: "Computer".to_string(),
                    detail: format!("Potentially obsolete OS (matches '{}')", pat.trim()),
                    target: None,
                    severity: 6,
                });
                break;
            }
        }
    }
    results
}

pub fn empty_groups(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("Group") {
        let node = &g.graph[idx];
        let has_members = g
            .graph
            .edges_directed(idx, Direction::Incoming)
            .any(|e| e.weight().label == "MemberOf");
        if !has_members {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "Group".to_string(),
                detail: "Empty group (no members)".to_string(),
                target: None,
                severity: 3,
            });
        }
    }
    if results.len() > 50 {
        let total = results.len();
        results.truncate(50);
        results.push(Finding {
            principal: format!("...and {} more", total - 50),
            principal_type: "Group".to_string(),
            detail: "Empty groups truncated".to_string(),
            target: None,
            severity: 3,
        });
    }
    results
}

pub fn unexpected_primary_group(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        if node.name.to_uppercase().starts_with("KRBTGT@") {
            continue;
        }
        for edge in g.graph.edges(idx) {
            if edge.weight().label != "MemberOf" {
                continue;
            }
            let target_id = &g.graph[edge.target()].object_id;
            if target_id.ends_with("-513")
                || target_id.ends_with("-515")
                || target_id.ends_with("-516")
            {
                break;
            }
            let target_name = &g.graph[edge.target()].name;
            if target_name.to_uppercase().contains("DOMAIN USERS")
                || target_name.to_uppercase().contains("DOMAIN COMPUTERS")
            {
                break;
            }
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "User".to_string(),
                detail: format!(
                    "Non-standard PrimaryGroupID → {} (may hide membership)",
                    target_name
                ),
                target: Some(target_name.clone()),
                severity: 7,
            });
            break;
        }
    }
    results
}

pub fn paths_to_dns_admins(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let dns_targets: Vec<NodeIndex> = g
        .graph
        .node_indices()
        .filter(|&idx| {
            let n = &g.graph[idx];
            n.node_type == "Group" && n.name.to_uppercase().contains("DNSADMINS")
        })
        .collect();
    for &target_idx in &dns_targets {
        for edge in g.graph.edges_directed(target_idx, Direction::Incoming) {
            let src = &g.graph[edge.source()];
            if is_default_high_priv(&src.name) {
                continue;
            }
            let label = edge.weight().label.as_str();
            if matches!(
                label,
                "MemberOf"
                    | "GenericAll"
                    | "GenericWrite"
                    | "WriteDacl"
                    | "WriteOwner"
                    | "AddMember"
            ) {
                results.push(Finding {
                    principal: src.name.clone(),
                    principal_type: src.node_type.clone(),
                    detail: format!("{} to DNSADMINS (DLL injection → DC compromise)", label),
                    target: Some(g.graph[target_idx].name.clone()),
                    severity: 8,
                });
            }
        }
    }
    results
}

pub fn paths_to_operators(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let op_names = [
        "ACCOUNT OPERATORS@",
        "SERVER OPERATORS@",
        "BACKUP OPERATORS@",
        "PRINT OPERATORS@",
    ];
    for idx in g.nodes_by_type("Group") {
        let node = &g.graph[idx];
        let name_upper = node.name.to_uppercase();
        if !op_names.iter().any(|op| name_upper.starts_with(op)) {
            continue;
        }
        for edge in g.graph.edges_directed(idx, Direction::Incoming) {
            let src = &g.graph[edge.source()];
            if is_default_high_priv(&src.name) {
                continue;
            }
            let label = edge.weight().label.as_str();
            if matches!(label, "MemberOf" | "GenericAll" | "AddMember") {
                results.push(Finding {
                    principal: src.name.clone(),
                    principal_type: src.node_type.clone(),
                    detail: format!("{} to {} (dangerous default privileges)", label, node.name),
                    target: Some(node.name.clone()),
                    severity: 7,
                });
            }
        }
    }
    results
}

pub fn computer_admin_of_computers(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for edge in g.graph.edge_references() {
        let label = edge.weight().label.as_str();
        if !matches!(label, "AdminTo" | "LocalAdmin") {
            continue;
        }
        let src = &g.graph[edge.source()];
        let dst = &g.graph[edge.target()];
        if src.node_type == "Computer" && dst.node_type == "Computer" {
            results.push(Finding {
                principal: src.name.clone(),
                principal_type: "Computer".to_string(),
                detail: format!(
                    "Machine-to-machine admin on {} (lateral movement)",
                    dst.name
                ),
                target: Some(dst.name.clone()),
                severity: 7,
            });
        }
    }
    results
}

pub fn guest_accounts(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        if node.name.to_uppercase().starts_with("GUEST@") {
            results.push(Finding {
                principal: node.name.clone(),
                principal_type: "User".to_string(),
                detail: "Enabled guest account".to_string(),
                target: None,
                severity: 7,
            });
        }
    }
    results
}

pub fn tier0_session_violations(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    let mut tier0_users: HashSet<NodeIndex> = HashSet::new();
    let mut dc_indices: HashSet<NodeIndex> = HashSet::new();
    for idx in g.graph.node_indices() {
        let node = &g.graph[idx];
        if node.node_type != "Group" {
            continue;
        }
        let u = node.name.to_uppercase();
        if u.starts_with("DOMAIN ADMINS@")
            || u.starts_with("ENTERPRISE ADMINS@")
            || u.starts_with("ADMINISTRATORS@")
        {
            for edge in g.graph.edges_directed(idx, Direction::Incoming) {
                if edge.weight().label == "MemberOf" && g.graph[edge.source()].node_type == "User" {
                    tier0_users.insert(edge.source());
                }
            }
        }
        if u.contains("DOMAIN CONTROLLERS") {
            for edge in g.graph.edges_directed(idx, Direction::Incoming) {
                if edge.weight().label == "MemberOf" {
                    dc_indices.insert(edge.source());
                }
            }
        }
    }
    for edge in g.graph.edge_references() {
        if edge.weight().label != "HasSession" {
            continue;
        }
        let user_idx = edge.source();
        let comp_idx = edge.target();
        if !tier0_users.contains(&user_idx) {
            continue;
        }
        if dc_indices.contains(&comp_idx) {
            continue;
        }
        results.push(Finding {
            principal: g.graph[user_idx].name.clone(),
            principal_type: "User".to_string(),
            detail: format!("Tier-0 session on non-DC {}", g.graph[comp_idx].name),
            target: Some(g.graph[comp_idx].name.clone()),
            severity: 9,
        });
    }
    results
}

pub fn cleartext_passwords(g: &AdGraph) -> Vec<Finding> {
    let mut results = Vec::new();
    for idx in g.nodes_by_type("User") {
        let node = &g.graph[idx];
        if !node.enabled {
            continue;
        }
        if let Some(ref desc) = node.props.description {
            let lower = desc.to_lowercase();
            if lower.contains("userpassword")
                || lower.contains("cleartext")
                || lower.contains("plaintext password")
            {
                results.push(Finding {
                    principal: node.name.clone(),
                    principal_type: "User".to_string(),
                    detail: "Cleartext password attribute reference in description [REDACTED]"
                        .to_string(),
                    target: None,
                    severity: 8,
                });
            }
        }
    }
    results
}
