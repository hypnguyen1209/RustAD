use crate::api::ADResults;
use crate::objects::common::LdapObject;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AdNode {
    pub object_id: String,
    pub name: String,
    pub node_type: String,
    pub domain: String,
    pub enabled: bool,
    pub high_value: bool,
    pub props: NodeProps,
}

#[derive(Debug, Clone, Default)]
pub struct NodeProps {
    pub has_spn: bool,
    pub dont_req_preauth: bool,
    pub pwd_never_expires: bool,
    pub pwd_not_required: bool,
    pub unconstrained_delegation: bool,
    pub trusted_to_auth: bool,
    pub sensitive: bool,
    pub admin_count: bool,
    pub has_laps: bool,
    pub description: Option<String>,
    pub service_principal_names: Vec<String>,
    pub allowed_to_delegate: Vec<String>,
    pub sid_history: Vec<String>,
    pub last_logon: i64,
    pub pwd_last_set: i64,
    pub when_created: i64,
    pub sam_account_name: Option<String>,
    pub dns_hostname: Option<String>,
    pub ca_name: Option<String>,
    pub template_name: Option<String>,
    pub template_oid: Option<String>,
    pub client_auth: bool,
    pub enrollee_supplies_subject: bool,
    pub enrollment_agent: bool,
    pub requires_manager_approval: bool,
    pub no_security_extension: bool,
    pub schema_version: i32,
    pub authorized_signatures_required: i32,
    pub enabled_templates: Vec<String>,
    pub web_enrollment: bool,
    pub user_specifies_san: bool,
}

#[derive(Debug, Clone)]
pub struct AdEdge {
    pub label: String,
}

pub struct AdGraph {
    pub graph: DiGraph<AdNode, AdEdge>,
    pub index: HashMap<String, NodeIndex>,
    pub domain: String,
}

impl AdGraph {
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn get_node(&self, oid: &str) -> Option<&AdNode> {
        self.index.get(oid).map(|&idx| &self.graph[idx])
    }

    pub fn get_index(&self, oid: &str) -> Option<NodeIndex> {
        self.index.get(oid).copied()
    }

    pub fn ensure_node(&mut self, oid: &str, name: &str, node_type: &str) -> NodeIndex {
        if let Some(&idx) = self.index.get(oid) {
            return idx;
        }
        let node = AdNode {
            object_id: oid.to_string(),
            name: name.to_string(),
            node_type: node_type.to_string(),
            domain: self.domain.clone(),
            enabled: true,
            high_value: false,
            props: NodeProps::default(),
        };
        let idx = self.graph.add_node(node);
        self.index.insert(oid.to_string(), idx);
        idx
    }

    pub fn add_edge_unique(&mut self, src: NodeIndex, dst: NodeIndex, label: &str) {
        let exists = self
            .graph
            .edges_connecting(src, dst)
            .any(|e| e.weight().label == label);
        if !exists {
            self.graph.add_edge(
                src,
                dst,
                AdEdge {
                    label: label.to_string(),
                },
            );
        }
    }

    pub fn nodes_by_type(&self, node_type: &str) -> Vec<NodeIndex> {
        self.graph
            .node_indices()
            .filter(|&idx| self.graph[idx].node_type == node_type)
            .collect()
    }

    pub fn outgoing_edges(&self, idx: NodeIndex) -> Vec<(NodeIndex, &str)> {
        self.graph
            .edges(idx)
            .map(|e| (e.target(), e.weight().label.as_str()))
            .collect()
    }

    pub fn incoming_edges(&self, idx: NodeIndex) -> Vec<(NodeIndex, &str)> {
        use petgraph::Direction;
        self.graph
            .edges_directed(idx, Direction::Incoming)
            .map(|e| (e.source(), e.weight().label.as_str()))
            .collect()
    }
}

pub fn build_graph(ad: &ADResults, domain: &str) -> AdGraph {
    let mut g = AdGraph {
        graph: DiGraph::new(),
        index: HashMap::new(),
        domain: domain.to_uppercase(),
    };

    add_users(&mut g, ad);
    add_groups(&mut g, ad);
    add_computers(&mut g, ad);
    add_ous(&mut g, ad);
    add_domains(&mut g, ad);
    add_gpos(&mut g, ad);
    add_containers(&mut g, ad);
    add_enterprise_cas(&mut g, ad);
    add_cert_templates(&mut g, ad);
    add_root_cas(&mut g, ad);
    add_aiacas(&mut g, ad);
    add_ntauth_stores(&mut g, ad);

    mark_high_value_targets(&mut g);

    log::info!(
        "Graph built: {} nodes, {} edges",
        g.node_count(),
        g.edge_count()
    );
    g
}

fn process_aces(
    g: &mut AdGraph,
    owner_idx: NodeIndex,
    aces: &[crate::objects::common::AceTemplate],
) {
    for ace in aces {
        let sid = ace.principal_sid();
        let ptype = ace.principal_type();
        let right = ace.right_name();

        if sid.is_empty() {
            continue;
        }
        let target_idx = g.ensure_node(sid, sid, ptype);
        g.add_edge_unique(target_idx, owner_idx, right);
    }
}

fn process_members(
    g: &mut AdGraph,
    group_idx: NodeIndex,
    members: &[crate::objects::common::Member],
) {
    for member in members {
        let oid = member.object_identifier();
        let otype = member.object_type();
        if oid.is_empty() {
            continue;
        }
        let member_idx = g.ensure_node(oid, oid, otype);
        g.add_edge_unique(member_idx, group_idx, "MemberOf");
    }
}

fn process_contained_by(
    g: &mut AdGraph,
    child_idx: NodeIndex,
    contained_by: &Option<crate::objects::common::Member>,
) {
    if let Some(parent) = contained_by {
        let pid = parent.object_identifier();
        let ptype = parent.object_type();
        if !pid.is_empty() {
            let parent_idx = g.ensure_node(pid, pid, ptype);
            g.add_edge_unique(parent_idx, child_idx, "Contains");
        }
    }
}

fn add_users(g: &mut AdGraph, ad: &ADResults) {
    for user in &ad.users {
        let json = user.to_json();
        let oid = user.get_object_identifier().clone();
        let name = json["Properties"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let idx = g.ensure_node(&oid, &name, "User");

        let n = &mut g.graph[idx];
        n.name = name;
        n.node_type = "User".to_string();
        n.enabled = json["Properties"]["enabled"].as_bool().unwrap_or(true);
        n.props.has_spn = json["Properties"]["hasspn"].as_bool().unwrap_or(false);
        n.props.dont_req_preauth = json["Properties"]["dontreqpreauth"]
            .as_bool()
            .unwrap_or(false);
        n.props.pwd_never_expires = json["Properties"]["pwdneverexpires"]
            .as_bool()
            .unwrap_or(false);
        n.props.pwd_not_required = json["Properties"]["passwordnotreqd"]
            .as_bool()
            .unwrap_or(false);
        n.props.unconstrained_delegation = json["Properties"]["unconstraineddelegation"]
            .as_bool()
            .unwrap_or(false);
        n.props.trusted_to_auth = json["Properties"]["trustedtoauth"]
            .as_bool()
            .unwrap_or(false);
        n.props.admin_count = json["Properties"]["admincount"].as_bool().unwrap_or(false);
        n.props.sensitive = json["Properties"]["sensitive"].as_bool().unwrap_or(false);
        n.props.description = json["Properties"]["description"].as_str().map(String::from);
        n.props.last_logon = json["Properties"]["lastlogontimestamp"]
            .as_i64()
            .unwrap_or(-1);
        n.props.pwd_last_set = json["Properties"]["pwdlastset"].as_i64().unwrap_or(-1);
        n.props.when_created = json["Properties"]["whencreated"].as_i64().unwrap_or(-1);
        n.props.sam_account_name = json["Properties"]["samaccountname"]
            .as_str()
            .map(String::from);

        if let Some(spns) = json["Properties"]["serviceprincipalnames"].as_array() {
            n.props.service_principal_names = spns
                .iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect();
        }

        process_aces(g, idx, user.get_aces());
        process_contained_by(g, idx, user.get_contained_by());

        if let Some(pg) = json["PrimaryGroupSID"].as_str() {
            if !pg.is_empty() {
                let pg_idx = g.ensure_node(pg, pg, "Group");
                g.add_edge_unique(idx, pg_idx, "MemberOf");
            }
        }
    }
}

fn add_groups(g: &mut AdGraph, ad: &ADResults) {
    for group in &ad.groups {
        let json = group.to_json();
        let oid = group.get_object_identifier().clone();
        let name = json["Properties"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let idx = g.ensure_node(&oid, &name, "Group");

        let n = &mut g.graph[idx];
        n.name = name;
        n.node_type = "Group".to_string();
        n.props.admin_count = json["Properties"]["admincount"].as_bool().unwrap_or(false);

        if let Some(members) = json["Members"].as_array() {
            for member in members {
                let mid = member["ObjectIdentifier"].as_str().unwrap_or("");
                let mtype = member["ObjectType"].as_str().unwrap_or("Unknown");
                if !mid.is_empty() {
                    let member_idx = g.ensure_node(mid, mid, mtype);
                    g.add_edge_unique(member_idx, idx, "MemberOf");
                }
            }
        }

        process_aces(g, idx, group.get_aces());
        process_contained_by(g, idx, group.get_contained_by());
    }
}

fn add_computers(g: &mut AdGraph, ad: &ADResults) {
    for computer in &ad.computers {
        let json = computer.to_json();
        let oid = computer.get_object_identifier().clone();
        let name = json["Properties"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let idx = g.ensure_node(&oid, &name, "Computer");

        let n = &mut g.graph[idx];
        n.name = name;
        n.node_type = "Computer".to_string();
        n.enabled = json["Properties"]["enabled"].as_bool().unwrap_or(true);
        n.props.unconstrained_delegation = json["Properties"]["unconstraineddelegation"]
            .as_bool()
            .unwrap_or(false);
        n.props.has_laps = json["Properties"]["haslaps"].as_bool().unwrap_or(false);
        n.props.dns_hostname = json["Properties"]["dnshostname"]
            .as_str()
            .or_else(|| json["Properties"]["name"].as_str())
            .map(String::from);

        if let Some(sessions) = json["Sessions"]["Results"].as_array() {
            for s in sessions {
                let user_sid = s["UserSID"].as_str().unwrap_or("");
                let comp_sid = s["ComputerSID"].as_str().unwrap_or("");
                if !user_sid.is_empty() && !comp_sid.is_empty() {
                    let user_idx = g.ensure_node(user_sid, user_sid, "User");
                    g.add_edge_unique(user_idx, idx, "HasSession");
                }
            }
        }

        if let Some(sessions) = json["PrivilegedSessions"]["Results"].as_array() {
            for s in sessions {
                let user_sid = s["UserSID"].as_str().unwrap_or("");
                if !user_sid.is_empty() {
                    let user_idx = g.ensure_node(user_sid, user_sid, "User");
                    g.add_edge_unique(user_idx, idx, "HasSession");
                }
            }
        }

        if let Some(sessions) = json["RegistrySessions"]["Results"].as_array() {
            for s in sessions {
                let user_sid = s["UserSID"].as_str().unwrap_or("");
                if !user_sid.is_empty() {
                    let user_idx = g.ensure_node(user_sid, user_sid, "User");
                    g.add_edge_unique(user_idx, idx, "HasSession");
                }
            }
        }

        if let Some(locals) = json["LocalGroups"].as_array() {
            for lg in locals {
                let lg_name = lg["ObjectIdentifier"].as_str().unwrap_or("").to_uppercase();
                let edge_label = if lg_name.ends_with("-544") {
                    "AdminTo"
                } else if lg_name.ends_with("-555") {
                    "CanRDP"
                } else if lg_name.ends_with("-562") {
                    "ExecuteDCOM"
                } else if lg_name.ends_with("-580") {
                    "CanPSRemote"
                } else {
                    continue;
                };

                if let Some(results) = lg["Results"].as_array() {
                    for r in results {
                        let rid = r["ObjectIdentifier"].as_str().unwrap_or("");
                        let rtype = r["ObjectType"].as_str().unwrap_or("Unknown");
                        if !rid.is_empty() {
                            let ridx = g.ensure_node(rid, rid, rtype);
                            g.add_edge_unique(ridx, idx, edge_label);
                        }
                    }
                }
            }
        }

        if let Some(allowed) = json["AllowedToAct"].as_array() {
            for a in allowed {
                let aid = a["ObjectIdentifier"].as_str().unwrap_or("");
                let atype = a["ObjectType"].as_str().unwrap_or("Unknown");
                if !aid.is_empty() {
                    let aidx = g.ensure_node(aid, aid, atype);
                    g.add_edge_unique(aidx, idx, "AllowedToAct");
                }
            }
        }

        process_aces(g, idx, computer.get_aces());
        process_contained_by(g, idx, computer.get_contained_by());

        if let Some(pg) = json["PrimaryGroupSID"].as_str() {
            if !pg.is_empty() {
                let pg_idx = g.ensure_node(pg, pg, "Group");
                g.add_edge_unique(idx, pg_idx, "MemberOf");
            }
        }
    }
}

fn add_ous(g: &mut AdGraph, ad: &ADResults) {
    for ou in &ad.ous {
        let json = ou.to_json();
        let oid = ou.get_object_identifier().clone();
        let name = json["Properties"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let idx = g.ensure_node(&oid, &name, "OU");
        g.graph[idx].name = name;
        g.graph[idx].node_type = "OU".to_string();

        if let Some(children) = json["ChildObjects"].as_array() {
            for child in children {
                let cid = child["ObjectIdentifier"].as_str().unwrap_or("");
                let ctype = child["ObjectType"].as_str().unwrap_or("Unknown");
                if !cid.is_empty() {
                    let cidx = g.ensure_node(cid, cid, ctype);
                    g.add_edge_unique(idx, cidx, "Contains");
                }
            }
        }

        if let Some(links) = json["Links"].as_array() {
            for link in links {
                let guid = link["GUID"].as_str().unwrap_or("");
                if !guid.is_empty() {
                    let gpo_idx = g.ensure_node(guid, guid, "GPO");
                    g.add_edge_unique(gpo_idx, idx, "GPLink");
                }
            }
        }

        process_aces(g, idx, ou.get_aces());
        process_contained_by(g, idx, ou.get_contained_by());
    }
}

fn add_domains(g: &mut AdGraph, ad: &ADResults) {
    for domain in &ad.domains {
        let json = domain.to_json();
        let oid = domain.get_object_identifier().clone();
        let name = json["Properties"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let idx = g.ensure_node(&oid, &name, "Domain");
        g.graph[idx].name = name;
        g.graph[idx].node_type = "Domain".to_string();

        if let Some(children) = json["ChildObjects"].as_array() {
            for child in children {
                let cid = child["ObjectIdentifier"].as_str().unwrap_or("");
                let ctype = child["ObjectType"].as_str().unwrap_or("Unknown");
                if !cid.is_empty() {
                    let cidx = g.ensure_node(cid, cid, ctype);
                    g.add_edge_unique(idx, cidx, "Contains");
                }
            }
        }

        if let Some(links) = json["Links"].as_array() {
            for link in links {
                let guid = link["GUID"].as_str().unwrap_or("");
                if !guid.is_empty() {
                    let gpo_idx = g.ensure_node(guid, guid, "GPO");
                    g.add_edge_unique(gpo_idx, idx, "GPLink");
                }
            }
        }

        if let Some(trusts) = json["Trusts"].as_array() {
            for trust in trusts {
                let tid = trust["TargetDomainSid"].as_str().unwrap_or("");
                let tname = trust["TargetDomainName"].as_str().unwrap_or("");
                if !tid.is_empty() {
                    let tidx = g.ensure_node(tid, tname, "Domain");
                    g.graph[tidx].name = tname.to_string();
                    let direction = trust["TrustDirection"].as_i64().unwrap_or(0);
                    let ttype = trust["TrustType"].as_i64().unwrap_or(0);
                    let label = format!("TrustedDomain:{}:{}", direction, ttype);
                    g.add_edge_unique(idx, tidx, &label);
                }
            }
        }

        process_aces(g, idx, domain.get_aces());
    }
}

fn add_gpos(g: &mut AdGraph, ad: &ADResults) {
    for gpo in &ad.gpos {
        let json = gpo.to_json();
        let oid = gpo.get_object_identifier().clone();
        let name = json["Properties"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let idx = g.ensure_node(&oid, &name, "GPO");
        g.graph[idx].name = name;
        g.graph[idx].node_type = "GPO".to_string();
        process_aces(g, idx, gpo.get_aces());
        process_contained_by(g, idx, gpo.get_contained_by());
    }
}

fn add_containers(g: &mut AdGraph, ad: &ADResults) {
    for container in &ad.containers {
        let json = container.to_json();
        let oid = container.get_object_identifier().clone();
        let name = json["Properties"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let idx = g.ensure_node(&oid, &name, "Container");
        g.graph[idx].name = name;
        g.graph[idx].node_type = "Container".to_string();

        if let Some(children) = json["ChildObjects"].as_array() {
            for child in children {
                let cid = child["ObjectIdentifier"].as_str().unwrap_or("");
                let ctype = child["ObjectType"].as_str().unwrap_or("Unknown");
                if !cid.is_empty() {
                    let cidx = g.ensure_node(cid, cid, ctype);
                    g.add_edge_unique(idx, cidx, "Contains");
                }
            }
        }

        process_aces(g, idx, container.get_aces());
        process_contained_by(g, idx, container.get_contained_by());
    }
}

fn add_enterprise_cas(g: &mut AdGraph, ad: &ADResults) {
    for ca in &ad.enterprisecas {
        let json = ca.to_json();
        let oid = ca.get_object_identifier().clone();
        let name = json["Properties"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let idx = g.ensure_node(&oid, &name, "EnterpriseCA");
        g.graph[idx].name = name;
        g.graph[idx].node_type = "EnterpriseCA".to_string();
        g.graph[idx].props.web_enrollment = json["Properties"]["webenrollmenturi"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        g.graph[idx].props.user_specifies_san = json["CARegistryData"]["IsUserSpecifiesSanEnabled"]
            ["Value"]
            .as_bool()
            .unwrap_or(false);

        if let Some(templates) = json["EnabledCertTemplates"].as_array() {
            for t in templates {
                let tid = t["ObjectIdentifier"].as_str().unwrap_or("");
                if !tid.is_empty() {
                    g.graph[idx].props.enabled_templates.push(tid.to_string());
                    let tidx = g.ensure_node(tid, tid, "CertTemplate");
                    g.add_edge_unique(idx, tidx, "PublishedTo");
                }
            }
        }

        process_aces(g, idx, ca.get_aces());
        process_contained_by(g, idx, ca.get_contained_by());
    }
}

fn add_cert_templates(g: &mut AdGraph, ad: &ADResults) {
    for tmpl in &ad.certtemplates {
        let json = tmpl.to_json();
        let oid = tmpl.get_object_identifier().clone();
        let name = json["Properties"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let idx = g.ensure_node(&oid, &name, "CertTemplate");
        let n = &mut g.graph[idx];
        n.name = name;
        n.node_type = "CertTemplate".to_string();
        n.props.client_auth = json["Properties"]["clientauthentication"]
            .as_bool()
            .unwrap_or(false);
        n.props.enrollee_supplies_subject = json["Properties"]["enrolleesuppliessubject"]
            .as_bool()
            .unwrap_or(false);
        n.props.requires_manager_approval = json["Properties"]["requiresmanagerapproval"]
            .as_bool()
            .unwrap_or(false);
        n.props.no_security_extension = json["Properties"]["nosecurityextension"]
            .as_bool()
            .unwrap_or(false);
        n.props.schema_version = json["Properties"]["schemaversion"].as_i64().unwrap_or(0) as i32;
        n.props.authorized_signatures_required = json["Properties"]["authorizedsignaturesrequired"]
            .as_i64()
            .unwrap_or(0) as i32;
        n.props.enrollment_agent = json["Properties"]["isenrollmentagent"]
            .as_bool()
            .unwrap_or(false);
        n.props.template_name = json["Properties"]["name"].as_str().map(String::from);

        n.enabled = json["Properties"]["enabled"].as_bool().unwrap_or(true);

        process_aces(g, idx, tmpl.get_aces());
        process_contained_by(g, idx, tmpl.get_contained_by());
    }
}

fn add_root_cas(g: &mut AdGraph, ad: &ADResults) {
    for ca in &ad.rootcas {
        let json = ca.to_json();
        let oid = ca.get_object_identifier().clone();
        let name = json["Properties"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let idx = g.ensure_node(&oid, &name, "RootCA");
        g.graph[idx].name = name;
        g.graph[idx].node_type = "RootCA".to_string();
        process_aces(g, idx, ca.get_aces());
        process_contained_by(g, idx, ca.get_contained_by());
    }
}

fn add_aiacas(g: &mut AdGraph, ad: &ADResults) {
    for ca in &ad.aiacas {
        let json = ca.to_json();
        let oid = ca.get_object_identifier().clone();
        let name = json["Properties"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let idx = g.ensure_node(&oid, &name, "AIACA");
        g.graph[idx].name = name;
        g.graph[idx].node_type = "AIACA".to_string();
        process_aces(g, idx, ca.get_aces());
        process_contained_by(g, idx, ca.get_contained_by());
    }
}

fn add_ntauth_stores(g: &mut AdGraph, ad: &ADResults) {
    for store in &ad.ntauthstores {
        let json = store.to_json();
        let oid = store.get_object_identifier().clone();
        let name = json["Properties"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let idx = g.ensure_node(&oid, &name, "NTAuthStore");
        g.graph[idx].name = name;
        g.graph[idx].node_type = "NTAuthStore".to_string();
        process_aces(g, idx, store.get_aces());
        process_contained_by(g, idx, store.get_contained_by());
    }
}

const HIGH_VALUE_GROUPS: &[&str] = &[
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "ADMINISTRATORS",
    "DOMAIN CONTROLLERS",
    "SCHEMA ADMINS",
    "ACCOUNT OPERATORS",
    "SERVER OPERATORS",
    "BACKUP OPERATORS",
    "PRINT OPERATORS",
    "KEY ADMINS",
    "ENTERPRISE KEY ADMINS",
    "CERT PUBLISHERS",
    "DNSADMINS",
];

fn mark_high_value_targets(g: &mut AdGraph) {
    let indices: Vec<NodeIndex> = g.graph.node_indices().collect();
    for idx in indices {
        let name_upper = g.graph[idx].name.to_uppercase();
        let ntype = g.graph[idx].node_type.clone();

        let is_hv = match ntype.as_str() {
            "Group" => HIGH_VALUE_GROUPS
                .iter()
                .any(|hv| name_upper.starts_with(&format!("{}@", hv))),
            "Domain" => true,
            "Computer" => {
                // DCs are high value
                g.graph.edges(idx).any(|e| {
                    if e.weight().label == "MemberOf" {
                        let target = &g.graph[e.target()];
                        target.name.to_uppercase().contains("DOMAIN CONTROLLERS")
                    } else {
                        false
                    }
                })
            }
            "EnterpriseCA" | "RootCA" | "NTAuthStore" => true,
            _ => false,
        };

        if is_hv {
            g.graph[idx].high_value = true;
        }
    }
}
