use rustad::kerberos::crypto;

#[test]
fn test_nt_hash_empty() {
    let hash = crypto::nt_hash("");
    assert_eq!(hash.len(), 16);
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(hex, "31d6cfe0d16ae931b73c59d7e0c089c0");
}

#[test]
fn test_nt_hash_password() {
    let hash = crypto::nt_hash("Password");
    assert_eq!(hash.len(), 16);
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(hex, "a4f49c406510bdcab6824ee7c30fd852");
}

#[test]
fn test_nt_hash_password123() {
    let hash = crypto::nt_hash("password");
    assert_eq!(hash.len(), 16);
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(hex, "8846f7eaee8fb117ad06bdd830b7586c");
}

#[test]
fn test_rc4_key_equals_nt_hash() {
    let nt = crypto::nt_hash("test");
    let rc4 = crypto::rc4_hmac_key("test");
    assert_eq!(nt, rc4);
}

#[test]
fn test_aes256_key_length() {
    let key = crypto::aes256_key("password", "DOMAIN.LOCAL", "user");
    assert_eq!(key.len(), 32);
}

#[test]
fn test_aes128_key_length() {
    let key = crypto::aes128_key("password", "DOMAIN.LOCAL", "user");
    assert_eq!(key.len(), 16);
}

#[test]
fn test_des_key_length() {
    let key = crypto::des_string_to_key("password", "DOMAIN.LOCAL", "user");
    assert_eq!(key.len(), 8);
}

#[test]
fn test_compute_all_keys() {
    let keys = crypto::compute_all_keys("Password123", "CORP.LOCAL", "admin");
    assert_eq!(keys.rc4.len(), 16);
    assert_eq!(keys.aes128.len(), 16);
    assert_eq!(keys.aes256.len(), 32);
    assert_eq!(keys.des.len(), 8);
}

#[test]
fn test_aes256_key_deterministic() {
    let k1 = crypto::aes256_key("test", "DOMAIN.LOCAL", "user");
    let k2 = crypto::aes256_key("test", "DOMAIN.LOCAL", "user");
    assert_eq!(k1, k2);
}

#[test]
fn test_aes256_key_salt_sensitive() {
    let k1 = crypto::aes256_key("test", "DOMAIN.LOCAL", "user1");
    let k2 = crypto::aes256_key("test", "DOMAIN.LOCAL", "user2");
    assert_ne!(k1, k2);
}

#[test]
fn test_nt_hash_unicode() {
    let hash = crypto::nt_hash("Pässwörd");
    assert_eq!(hash.len(), 16);
}
