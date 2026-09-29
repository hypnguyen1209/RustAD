use crate::kerberos::crypto;
use hmac::{Hmac, Mac};
use md5::Md5;
use std::error::Error;

// md-5 crate re-exports as md5
type HmacMd5 = Hmac<Md5>;

#[derive(Debug, Clone)]
pub enum KeyMaterial {
    Password(String),
    Rc4Key(Vec<u8>),
    Aes256Key(Vec<u8>),
    Aes128Key(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct AskTgtParams {
    pub user: String,
    pub domain: String,
    pub dc: String,
    pub key: KeyMaterial,
    pub no_preauth: bool,
    pub etype: i32,
    pub nopac: bool,
}

#[derive(Debug, Clone)]
pub struct AskTgtResult {
    pub raw_reply: Vec<u8>,
    pub ticket: Vec<u8>,
    pub session_key: Vec<u8>,
    pub session_key_etype: i32,
    pub etype: i32,
    pub username: String,
    pub domain: String,
}

impl AskTgtResult {
    pub fn to_base64(&self) -> String {
        base64_encode(&self.raw_reply)
    }
}

pub async fn ask_tgt(params: &AskTgtParams) -> Result<AskTgtResult, Box<dyn Error>> {
    let realm = params.domain.to_uppercase();
    let nonce: u32 = rand::random();

    let user_key = resolve_key(&params.key, &params.user, &params.domain, params.etype);
    let etype = effective_etype(&params.key, params.etype);

    let req_body = build_req_body(&params.user, &realm, nonce, etype);

    let as_req = if params.no_preauth {
        build_as_req_no_preauth(&req_body)
    } else {
        let enc_timestamp = encrypt_timestamp(&user_key, etype)?;
        build_as_req_with_preauth(&req_body, &enc_timestamp, etype, !params.nopac)
    };

    let response = crate::kerberos::send_kdc(&params.dc, &as_req, false).await?;

    if response.is_empty() {
        return Err("Empty KDC response".into());
    }

    // KRB-ERROR
    if response[0] == 0x7e {
        let err_code = extract_krb_error_code(&response);
        let msg = err_code
            .map(krb_error_to_string)
            .unwrap_or("unknown error".into());
        return Err(format!("KDC error: {}", msg).into());
    }

    // AS-REP (APPLICATION[11])
    if response[0] != 0x6b && response[0] != 0x7b {
        return Err(format!("Unexpected response tag: 0x{:02x}", response[0]).into());
    }

    let ticket = extract_ticket_from_asrep(&response)?;
    let enc_part = extract_enc_part_from_asrep(&response)?;

    let session_key = if params.no_preauth {
        Vec::new()
    } else {
        decrypt_enc_part(&enc_part, &user_key, etype)?
    };

    let session_key_etype = if session_key.len() == 32 {
        18
    } else if session_key.len() == 16 {
        if etype == 23 {
            23
        } else {
            17
        }
    } else {
        etype
    };

    Ok(AskTgtResult {
        raw_reply: response,
        ticket,
        session_key,
        session_key_etype,
        etype,
        username: params.user.clone(),
        domain: realm,
    })
}

fn resolve_key(key: &KeyMaterial, user: &str, domain: &str, _etype: i32) -> Vec<u8> {
    match key {
        KeyMaterial::Password(pw) => crypto::rc4_hmac_key(pw),
        KeyMaterial::Rc4Key(k) => k.clone(),
        KeyMaterial::Aes256Key(k) => k.clone(),
        KeyMaterial::Aes128Key(k) => k.clone(),
    }
}

fn effective_etype(key: &KeyMaterial, preferred: i32) -> i32 {
    match key {
        KeyMaterial::Aes256Key(_) => crypto::ETYPE_AES256_CTS_HMAC_SHA1,
        KeyMaterial::Aes128Key(_) => crypto::ETYPE_AES128_CTS_HMAC_SHA1,
        KeyMaterial::Rc4Key(_) => crypto::ETYPE_RC4_HMAC,
        KeyMaterial::Password(_) => {
            if preferred != 0 {
                preferred
            } else {
                crypto::ETYPE_RC4_HMAC
            }
        }
    }
}

fn build_req_body(username: &str, realm: &str, nonce: u32, etype: i32) -> Vec<u8> {
    let mut body = Vec::new();
    let kdc_options = encode_bitstring(&0x40810010u32.to_be_bytes());
    let cname = encode_principal_name(1, &[username]);
    let sname = encode_principal_name(2, &["krbtgt", realm]);
    let realm_enc = encode_general_string(realm);
    let till = encode_generalized_time("20370913024805Z");
    let nonce_enc = encode_integer_u32(nonce);

    let mut etypes_items = Vec::new();
    match etype {
        18 => {
            etypes_items.push(encode_integer(18));
            etypes_items.push(encode_integer(17));
        }
        17 => {
            etypes_items.push(encode_integer(17));
        }
        _ => {
            etypes_items.push(encode_integer(23));
        }
    }
    let etype_refs: Vec<&[u8]> = etypes_items.iter().map(|e| e.as_slice()).collect();
    let etypes = encode_sequence_raw(&etype_refs);

    body.extend(encode_context_tag(0, &kdc_options));
    body.extend(encode_context_tag(1, &cname));
    body.extend(encode_context_tag(2, &realm_enc));
    body.extend(encode_context_tag(3, &sname));
    body.extend(encode_context_tag(5, &till));
    body.extend(encode_context_tag(7, &nonce_enc));
    body.extend(encode_context_tag(8, &etypes));
    encode_sequence_raw(&[&body])
}

fn build_as_req_no_preauth(req_body: &[u8]) -> Vec<u8> {
    let mut kdc_req = Vec::new();
    kdc_req.extend(encode_context_tag(1, &encode_integer(5))); // pvno
    kdc_req.extend(encode_context_tag(2, &encode_integer(10))); // msg-type
    kdc_req.extend(encode_context_tag(4, req_body));
    let seq = encode_sequence_raw(&[&kdc_req]);
    encode_application_tag(10, &seq)
}

fn build_as_req_with_preauth(
    req_body: &[u8],
    enc_timestamp: &[u8],
    etype: i32,
    pac_request: bool,
) -> Vec<u8> {
    // PA-ENC-TIMESTAMP: padata-type = 2
    let enc_ts_data = build_encrypted_data(etype, enc_timestamp);
    let pa_enc_ts = build_padata(2, &enc_ts_data);

    // PA-PAC-REQUEST: padata-type = 128
    let pac_req = if pac_request {
        let pac_val = encode_sequence_raw(&[&encode_context_tag(0, &encode_boolean(true))]);
        build_padata(128, &pac_val)
    } else {
        let pac_val = encode_sequence_raw(&[&encode_context_tag(0, &encode_boolean(false))]);
        build_padata(128, &pac_val)
    };

    let padata_seq = encode_sequence_raw(&[&pa_enc_ts, &pac_req]);

    let mut kdc_req = Vec::new();
    kdc_req.extend(encode_context_tag(1, &encode_integer(5))); // pvno
    kdc_req.extend(encode_context_tag(2, &encode_integer(10))); // msg-type
    kdc_req.extend(encode_context_tag(3, &padata_seq)); // padata
    kdc_req.extend(encode_context_tag(4, req_body)); // req-body
    let seq = encode_sequence_raw(&[&kdc_req]);
    encode_application_tag(10, &seq)
}

fn build_padata(padata_type: i32, padata_value: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(encode_context_tag(1, &encode_integer(padata_type)));
    content.extend(encode_context_tag(2, &encode_octet_string(padata_value)));
    encode_sequence_raw(&[&content])
}

fn build_encrypted_data(etype: i32, cipher: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(encode_context_tag(0, &encode_integer(etype)));
    content.extend(encode_context_tag(2, &encode_octet_string(cipher)));
    encode_sequence_raw(&[&content])
}

fn encrypt_timestamp(key: &[u8], etype: i32) -> Result<Vec<u8>, Box<dyn Error>> {
    let now = chrono::Utc::now();
    let ts_str = now.format("%Y%m%d%H%M%SZ").to_string();

    // PA-ENC-TS-ENC ::= SEQUENCE { patimestamp[0] KerberosTime, pausec[1] INTEGER OPTIONAL }
    let mut ts_body = Vec::new();
    ts_body.extend(encode_context_tag(0, &encode_generalized_time(&ts_str)));
    ts_body.extend(encode_context_tag(
        1,
        &encode_integer(now.timestamp_subsec_micros() as i32),
    ));
    let plaintext = encode_sequence_raw(&[&ts_body]);

    match etype {
        23 => rc4_hmac_encrypt(key, 1, &plaintext),
        _ => Err("Only RC4-HMAC timestamp encryption implemented".into()),
    }
}

fn rc4_hmac_encrypt(key: &[u8], usage: u32, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // RFC 4757 - RC4-HMAC encryption
    // K1 = HMAC-MD5(key, usage_le32)
    let usage_bytes = (usage as i32).to_le_bytes();
    let mut mac = HmacMd5::new_from_slice(key).map_err(|e| format!("HMAC key: {}", e))?;
    mac.update(&usage_bytes);
    let k1 = mac.finalize().into_bytes().to_vec();

    // Generate confounder (8 random bytes)
    let confounder: [u8; 8] = rand::random();

    // plaintext_with_confounder = confounder || plaintext
    let mut ptxt = Vec::with_capacity(8 + plaintext.len());
    ptxt.extend_from_slice(&confounder);
    ptxt.extend_from_slice(plaintext);

    // checksum = HMAC-MD5(K1, plaintext_with_confounder)
    let mut mac = HmacMd5::new_from_slice(&k1).map_err(|e| format!("HMAC K1: {}", e))?;
    mac.update(&ptxt);
    let checksum = mac.finalize().into_bytes().to_vec();

    // K3 = HMAC-MD5(K1, checksum)
    let mut mac = HmacMd5::new_from_slice(&k1).map_err(|e| format!("HMAC K3: {}", e))?;
    mac.update(&checksum);
    let k3 = mac.finalize().into_bytes().to_vec();

    // ciphertext = RC4(K3, plaintext_with_confounder)
    let ciphertext = rc4_transform(&k3, &ptxt);

    // output = checksum (16 bytes) || ciphertext
    let mut result = Vec::with_capacity(16 + ciphertext.len());
    result.extend_from_slice(&checksum);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn rc4_transform(key: &[u8], data: &[u8]) -> Vec<u8> {
    // RC4 (ARC4) stream cipher
    let mut s: Vec<u8> = (0..=255).map(|i| i as u8).collect();
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    let mut i: u8 = 0;
    let mut j: u8 = 0;
    data.iter()
        .map(|&byte| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[s[i as usize].wrapping_add(s[j as usize]) as usize];
            byte ^ k
        })
        .collect()
}

fn decrypt_enc_part(
    enc_part_cipher: &[u8],
    key: &[u8],
    etype: i32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    match etype {
        23 => {
            // RC4-HMAC decrypt (key usage 3 for AS-REP enc-part, or 8 for TGS-REP)
            let decrypted = rc4_hmac_decrypt(key, 3, enc_part_cipher)?;
            // Extract session key from EncKDCRepPart
            extract_session_key_from_enc_rep(&decrypted)
        }
        _ => Err("Only RC4-HMAC decryption implemented".into()),
    }
}

fn rc4_hmac_decrypt(key: &[u8], usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if ciphertext.len() < 24 {
        return Err("Ciphertext too short for RC4-HMAC".into());
    }

    let usage_bytes = (usage as i32).to_le_bytes();
    let mut mac = HmacMd5::new_from_slice(key).map_err(|e| format!("HMAC key: {}", e))?;
    mac.update(&usage_bytes);
    let k1 = mac.finalize().into_bytes().to_vec();

    let checksum = &ciphertext[..16];
    let encrypted = &ciphertext[16..];

    // K3 = HMAC-MD5(K1, checksum)
    let mut mac = HmacMd5::new_from_slice(&k1).map_err(|e| format!("HMAC K3: {}", e))?;
    mac.update(checksum);
    let k3 = mac.finalize().into_bytes().to_vec();

    let decrypted = rc4_transform(&k3, encrypted);

    // Verify checksum
    let mut mac = HmacMd5::new_from_slice(&k1).map_err(|e| format!("HMAC verify: {}", e))?;
    mac.update(&decrypted);
    let computed_checksum = mac.finalize().into_bytes().to_vec();

    if computed_checksum != checksum {
        return Err("RC4-HMAC checksum mismatch (wrong key or corrupt data)".into());
    }

    // Strip 8-byte confounder
    Ok(decrypted[8..].to_vec())
}

fn extract_session_key_from_enc_rep(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // EncKDCRepPart = SEQUENCE { key[0] EncryptionKey, ... }
    // EncryptionKey = SEQUENCE { keytype[0] INTEGER, keyvalue[1] OCTET STRING }
    // We need to find the first OCTET STRING inside the first nested SEQUENCE
    // after context tag [0] (the key field).
    let mut pos = 0;

    // Skip outer SEQUENCE/APPLICATION tag
    if pos < data.len() && (data[pos] & 0x20 != 0 || data[pos] >= 0x60) {
        pos += 1;
        let _ = parse_length(data, &mut pos);
    }

    // Look for context tag [0] which holds EncryptionKey
    while pos < data.len() {
        if data[pos] == 0xa0 {
            pos += 1;
            let key_len = parse_length(data, &mut pos).map_err(|_| "bad length")?;
            let key_end = pos + key_len;

            // Inside EncryptionKey SEQUENCE, find keyvalue [1] OCTET STRING
            // Skip SEQUENCE tag
            if pos < key_end && data[pos] == 0x30 {
                pos += 1;
                let _ = parse_length(data, &mut pos);
            }

            while pos < key_end {
                if data[pos] == 0xa1 {
                    // context tag [1] = keyvalue
                    pos += 1;
                    let _ = parse_length(data, &mut pos);
                    if pos < key_end && data[pos] == 0x04 {
                        pos += 1;
                        let oct_len = parse_length(data, &mut pos).map_err(|_| "bad octet len")?;
                        if pos + oct_len <= data.len() {
                            return Ok(data[pos..pos + oct_len].to_vec());
                        }
                    }
                    break;
                }
                // Skip this TLV
                pos += 1;
                if let Ok(len) = parse_length(data, &mut pos) {
                    pos += len;
                } else {
                    break;
                }
            }
            break;
        }
        // Skip this TLV
        let tag = data[pos];
        pos += 1;
        if let Ok(len) = parse_length(data, &mut pos) {
            if tag & 0x20 == 0 {
                pos += len;
            } // skip primitive, recurse constructed
        } else {
            break;
        }
    }

    Err("Could not extract session key from EncKDCRepPart".into())
}

fn extract_ticket_from_asrep(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // AS-REP: APPLICATION[11] SEQUENCE { pvno[0], msg-type[1], padata[2]?, crealm[3], cname[4], ticket[5], enc-part[6] }
    // ticket[5] contains a Ticket (APPLICATION[1])
    // We find context tag [5] and return its content
    let inner = unwrap_application(data)?;
    let mut pos = 0;
    while pos < inner.len() {
        let tag = inner[pos];
        pos += 1;
        let len = parse_length(inner, &mut pos).map_err(|_| "parse error in AS-REP")?;
        if tag == 0xa5 {
            // context tag [5] = ticket
            return Ok(inner[pos..pos + len].to_vec());
        }
        pos += len;
    }
    Err("No ticket field in AS-REP".into())
}

fn extract_enc_part_from_asrep(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // enc-part is at context tag [6], contains EncryptedData
    // EncryptedData = SEQUENCE { etype[0], kvno[1]?, cipher[2] OCTET STRING }
    let inner = unwrap_application(data)?;
    let mut pos = 0;
    while pos < inner.len() {
        let tag = inner[pos];
        pos += 1;
        let len = parse_length(inner, &mut pos).map_err(|_| "parse error")?;
        if tag == 0xa6 {
            // context tag [6] = enc-part
            let enc_data = &inner[pos..pos + len];
            // Find cipher OCTET STRING in EncryptedData
            return extract_cipher_from_encrypted_data(enc_data);
        }
        pos += len;
    }
    Err("No enc-part field in AS-REP".into())
}

fn extract_cipher_from_encrypted_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // EncryptedData = SEQUENCE { etype[0] INTEGER, kvno[1] INTEGER OPTIONAL, cipher[2] OCTET STRING }
    let mut pos = 0;
    // Skip SEQUENCE tag
    if pos < data.len() && data[pos] == 0x30 {
        pos += 1;
        let _ = parse_length(data, &mut pos);
    }
    while pos < data.len() {
        let tag = data[pos];
        pos += 1;
        let len = parse_length(data, &mut pos).map_err(|_| "parse error in EncryptedData")?;
        if tag == 0xa2 {
            // context tag [2] = cipher
            if pos < data.len() && data[pos] == 0x04 {
                pos += 1;
                let oct_len = parse_length(data, &mut pos).map_err(|_| "octet string len")?;
                return Ok(data[pos..pos + oct_len].to_vec());
            }
        }
        pos += len;
    }
    Err("No cipher in EncryptedData".into())
}

fn unwrap_application(data: &[u8]) -> Result<&[u8], Box<dyn Error>> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    let mut pos = 1; // skip APPLICATION tag byte
    let len = parse_length(data, &mut pos).map_err(|_| "bad APPLICATION length")?;
    if pos + len > data.len() {
        return Err("APPLICATION length overflow".into());
    }
    let inner = &data[pos..pos + len];
    // inner should be a SEQUENCE
    if inner.is_empty() || inner[0] != 0x30 {
        return Err("expected SEQUENCE inside APPLICATION".into());
    }
    let mut seq_pos = 1;
    let seq_len = parse_length(inner, &mut seq_pos).map_err(|_| "bad SEQUENCE length")?;
    Ok(&inner[seq_pos..seq_pos + seq_len])
}

// ──────── ASN.1 helpers ────────

fn parse_length(data: &[u8], pos: &mut usize) -> Result<usize, ()> {
    if *pos >= data.len() {
        return Err(());
    }
    let first = data[*pos];
    *pos += 1;
    if first < 0x80 {
        return Ok(first as usize);
    }
    let n = (first & 0x7f) as usize;
    if n > 4 || *pos + n > data.len() {
        return Err(());
    }
    let mut len = 0usize;
    for _ in 0..n {
        len = (len << 8) | data[*pos] as usize;
        *pos += 1;
    }
    Ok(len)
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}
fn encode_sequence_raw(items: &[&[u8]]) -> Vec<u8> {
    let mut c = Vec::new();
    for i in items {
        c.extend_from_slice(i);
    }
    let mut o = vec![0x30];
    o.extend(encode_length(c.len()));
    o.extend(c);
    o
}
fn encode_context_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut o = vec![0xa0 | tag];
    o.extend(encode_length(content.len()));
    o.extend(content);
    o
}
fn encode_application_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut o = vec![0x60 | tag];
    o.extend(encode_length(content.len()));
    o.extend(content);
    o
}
fn encode_integer(val: i32) -> Vec<u8> {
    let mut o = vec![0x02];
    if val >= 0 && val < 128 {
        o.extend(encode_length(1));
        o.push(val as u8);
    } else {
        let b = val.to_be_bytes();
        let s = b.iter().position(|&x| x != 0).unwrap_or(3);
        let slice = &b[s..];
        if !slice.is_empty() && slice[0] & 0x80 != 0 && val >= 0 {
            o.extend(encode_length(slice.len() + 1));
            o.push(0);
            o.extend(slice);
        } else {
            o.extend(encode_length(slice.len()));
            o.extend(slice);
        }
    }
    o
}
fn encode_integer_u32(val: u32) -> Vec<u8> {
    let mut o = vec![0x02];
    let b = val.to_be_bytes();
    let s = b.iter().position(|&x| x != 0).unwrap_or(3);
    let t = &b[s..];
    if t.is_empty() || t[0] & 0x80 != 0 {
        o.extend(encode_length(t.len() + 1));
        o.push(0);
        o.extend(t);
    } else {
        o.extend(encode_length(t.len()));
        o.extend(t);
    }
    o
}
fn encode_general_string(s: &str) -> Vec<u8> {
    let mut o = vec![0x1b];
    o.extend(encode_length(s.len()));
    o.extend(s.as_bytes());
    o
}
fn encode_generalized_time(t: &str) -> Vec<u8> {
    let mut o = vec![0x18];
    o.extend(encode_length(t.len()));
    o.extend(t.as_bytes());
    o
}
fn encode_bitstring(data: &[u8]) -> Vec<u8> {
    let mut o = vec![0x03];
    o.extend(encode_length(data.len() + 1));
    o.push(0);
    o.extend(data);
    o
}
fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut o = vec![0x04];
    o.extend(encode_length(data.len()));
    o.extend(data);
    o
}
fn encode_boolean(val: bool) -> Vec<u8> {
    vec![0x01, 0x01, if val { 0xff } else { 0x00 }]
}
fn encode_principal_name(name_type: i32, names: &[&str]) -> Vec<u8> {
    let nt = encode_integer(name_type);
    let mut ns = Vec::new();
    for n in names {
        ns.extend(encode_general_string(n));
    }
    let nseq = encode_sequence_raw(&[&ns]);
    let mut c = Vec::new();
    c.extend(encode_context_tag(0, &nt));
    c.extend(encode_context_tag(1, &nseq));
    encode_sequence_raw(&[&c])
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        result.push(if chunk.len() > 1 {
            CHARS[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            CHARS[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    result
}

fn extract_krb_error_code(data: &[u8]) -> Option<u32> {
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0xa6 {
            let mut pos = i + 1;
            if let Ok(len) = parse_length(data, &mut pos) {
                if pos + len <= data.len() && data[pos] == 0x02 {
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
        6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN".to_string(),
        12 => "KDC_ERR_POLICY".to_string(),
        14 => "KDC_ERR_TGT_REVOKED".to_string(),
        17 => "KDC_ERR_KEY_EXPIRED".to_string(),
        18 => "KDC_ERR_CLIENT_REVOKED".to_string(),
        23 => "KDC_ERR_ETYPE_NOSUPP".to_string(),
        24 => "KDC_ERR_PREAUTH_FAILED".to_string(),
        25 => "KDC_ERR_PREAUTH_REQUIRED".to_string(),
        37 => "KDC_ERR_SKEW".to_string(),
        _ => format!("KRB_ERROR({})", code),
    }
}

pub fn print_result(result: &AskTgtResult) {
    println!("\n  User         : {}@{}", result.username, result.domain);
    println!("  Etype        : {}", result.etype);
    println!(
        "  Session Key  : {} (etype {})",
        hex_encode(&result.session_key),
        result.session_key_etype
    );
    println!("  Ticket Size  : {} bytes", result.ticket.len());
    println!("  Reply Size   : {} bytes", result.raw_reply.len());
    let b64 = result.to_base64();
    println!("  Base64 ({} chars):", b64.len());
    for line in b64.as_bytes().chunks(76) {
        println!("    {}", std::str::from_utf8(line).unwrap_or(""));
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
