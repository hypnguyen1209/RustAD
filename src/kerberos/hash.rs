use super::crypto;

pub fn compute_hashes(password: &str, user: Option<&str>, domain: Option<&str>) -> String {
    let user = user.unwrap_or("");
    let domain = domain.unwrap_or("");

    let keys = crypto::compute_all_keys(password, domain, user);

    let mut out = String::new();
    out.push_str(&format!("Password: {}\n", password));
    if !user.is_empty() {
        out.push_str(&format!("User    : {}\n", user));
    }
    if !domain.is_empty() {
        out.push_str(&format!("Domain  : {}\n", domain));
    }
    out.push_str(&format!("\n{}", keys));
    out
}
