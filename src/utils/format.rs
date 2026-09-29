/// Fonction to parse DOMAIN.LOCAL to DC=DOMAIN,DC=LOCAL
pub fn domain_to_dc(domain: &str) -> String {
    let split = domain.split('.');
    let mut dc = String::new();

    for (i, s) in split.enumerate() {
        dc.push_str("DC=");
        dc.push_str(s);

        if i < domain.split('.').count() - 1 {
            dc.push_str(",");
        }
    }
    dc
}
