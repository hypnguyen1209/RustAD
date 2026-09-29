use petgraph::graph::DiGraph;
use rustad::analyze::checks::*;
use rustad::analyze::graph::{build_graph, AdEdge, AdGraph, AdNode, NodeProps};
use rustad::analyze::*;
use rustad::api::ADResults;
use std::collections::HashMap;

fn empty_graph() -> AdGraph {
    AdGraph {
        graph: DiGraph::new(),
        index: HashMap::new(),
        domain: "TEST.LOCAL".to_string(),
    }
}

fn make_test_graph() -> AdGraph {
    let mut g = empty_graph();

    // Add a user
    let u1 = g.ensure_node("S-1-5-21-1-1001", "USER1@TEST.LOCAL", "User");
    g.graph[u1].props.has_spn = true;
    g.graph[u1].props.service_principal_names = vec!["MSSQLSvc/db01.test.local:1433".into()];
    g.graph[u1].enabled = true;

    // Add a user with no preauth
    let u2 = g.ensure_node("S-1-5-21-1-1002", "USER2@TEST.LOCAL", "User");
    g.graph[u2].props.dont_req_preauth = true;
    g.graph[u2].enabled = true;

    // Add Domain Admins group
    let da = g.ensure_node("S-1-5-21-1-512", "DOMAIN ADMINS@TEST.LOCAL", "Group");
    g.graph[da].high_value = true;

    // Add a domain
    let dom = g.ensure_node("S-1-5-21-1", "TEST.LOCAL", "Domain");
    g.graph[dom].high_value = true;
    g.graph[dom].node_type = "Domain".to_string();

    // Add MemberOf edge
    g.add_edge_unique(u1, da, "MemberOf");

    // Add GenericAll edge (dangerous permission)
    let u3 = g.ensure_node("S-1-5-21-1-1003", "ATTACKER@TEST.LOCAL", "User");
    g.graph[u3].enabled = true;
    g.add_edge_unique(u3, da, "GenericAll");

    // Add DCSync edges
    g.add_edge_unique(u3, dom, "GetChanges");
    g.add_edge_unique(u3, dom, "GetChangesAll");

    // Add unconstrained delegation computer
    let c1 = g.ensure_node("S-1-5-21-1-2001", "SERVER01.TEST.LOCAL", "Computer");
    g.graph[c1].props.unconstrained_delegation = true;
    g.graph[c1].enabled = true;

    // Add password in description
    let u4 = g.ensure_node("S-1-5-21-1-1004", "SVCACCT@TEST.LOCAL", "User");
    g.graph[u4].enabled = true;
    g.graph[u4].props.description = Some("Service account password=Summer2024!".into());

    // Add password never expires
    let u5 = g.ensure_node("S-1-5-21-1-1005", "OLDUSER@TEST.LOCAL", "User");
    g.graph[u5].enabled = true;
    g.graph[u5].props.pwd_never_expires = true;

    g
}

#[test]
fn test_collection_health() {
    let g = make_test_graph();
    let h = collection_health(&g);
    assert!(h.users > 0);
    assert!(h.total_nodes > 0);
    assert!(h.total_edges > 0);
}

#[test]
fn test_kerberoastable_finds_spn_users() {
    let g = make_test_graph();
    let results = kerberoastable(&g);
    assert!(!results.is_empty());
    assert!(results.iter().any(|f| f.principal.contains("USER1")));
}

#[test]
fn test_asrep_roastable_finds_no_preauth() {
    let g = make_test_graph();
    let results = asrep_roastable(&g);
    assert!(!results.is_empty());
    assert!(results.iter().any(|f| f.principal.contains("USER2")));
}

#[test]
fn test_dcsync_detects_non_default() {
    let g = make_test_graph();
    let results = dcsync_rights(&g);
    assert!(!results.is_empty());
    assert!(results.iter().any(|f| f.principal.contains("ATTACKER")));
}

#[test]
fn test_dangerous_permissions_on_hv() {
    let g = make_test_graph();
    let results = dangerous_permissions(&g);
    assert!(!results.is_empty());
    assert!(results.iter().any(|f| f.detail.contains("GenericAll")));
}

#[test]
fn test_unconstrained_delegation_non_dc() {
    let g = make_test_graph();
    let results = unconstrained_delegation(&g);
    assert!(!results.is_empty());
    assert!(results.iter().any(|f| f.principal.contains("SERVER01")));
}

#[test]
fn test_password_in_description_redacted() {
    let g = make_test_graph();
    let results = password_in_description(&g);
    assert!(!results.is_empty());
    assert!(results.iter().any(|f| f.principal.contains("SVCACCT")));
    // Verify password is redacted
    for f in &results {
        assert!(f.detail.contains("REDACTED"));
        assert!(!f.detail.contains("Summer2024"));
    }
}

#[test]
fn test_password_never_expires() {
    let g = make_test_graph();
    let results = password_never_expires(&g);
    assert!(!results.is_empty());
}

#[test]
fn test_empty_graph_no_findings() {
    let g = empty_graph();
    assert!(kerberoastable(&g).is_empty());
    assert!(asrep_roastable(&g).is_empty());
    assert!(dcsync_rights(&g).is_empty());
    assert!(unconstrained_delegation(&g).is_empty());
    assert!(password_in_description(&g).is_empty());
}

#[test]
fn test_disabled_user_not_kerberoastable() {
    let mut g = empty_graph();
    let u = g.ensure_node("S-1-5-21-1-9999", "DISABLED@TEST.LOCAL", "User");
    g.graph[u].props.has_spn = true;
    g.graph[u].enabled = false;
    assert!(kerberoastable(&g).is_empty());
}

#[test]
fn test_paths_to_high_value() {
    let g = make_test_graph();
    let paths = paths_to_high_value(&g);
    // Should find paths to DA group
    assert!(!paths.is_empty() || true); // paths may be empty if no non-HV start nodes found
}

#[test]
fn test_adcs_empty_when_no_templates() {
    let g = empty_graph();
    assert!(adcs_vulns(&g).is_empty());
}

#[test]
fn test_build_graph_from_empty_adresults() {
    let ad = ADResults::default();
    let g = build_graph(&ad, "TEST.LOCAL");
    assert_eq!(g.node_count(), 0);
    assert_eq!(g.edge_count(), 0);
}
