use crate::kerberos::crypto::{ETYPE_AES256_CTS_HMAC_SHA1, ETYPE_RC4_HMAC};
use hmac::{Hmac, Mac};
use std::error::Error;

type HmacMd5 = Hmac<md5::Md5>;

pub struct AskTgsParams {
    pub dc: String,
    pub domain: String,
    pub username: String,
    pub spn: String,
    pub tgt_raw: Vec<u8>,
    pub session_key: Vec<u8>,
    pub session_etype: i32,
    pub target_etype: Option<i32>,
    pub enterprise: bool,
}

pub struct AskTgsResult {
    pub service_ticket: Vec<u8>,
    pub enc_part_cipher: Vec<u8>,
    pub enc_part_etype: i32,
    pub spn: String,
}

pub async fn ask_tgs(params: &AskTgsParams) -> Result<AskTgsResult, Box<dyn Error>> {
    let realm = params.domain.to_uppercase();
    let nonce: u32 = rand::random();

    let now = chrono::Utc::now();
    let time_str = now.format("%Y%m%d%H%M%SZ").to_string();

    // 1. Build the Authenticator and encrypt it
    let authenticator = build_authenticator(&params.username, &realm, &time_str, nonce);
    let encrypted_auth = rc4_encrypt_for_tgs(&params.session_key, &authenticator, 7)?;

    // 2. Extract the raw Ticket from the TGT to embed in the AP-REQ
    let ticket_der = extract_ticket_from_tgt(&params.tgt_raw)?;

    // 3. Build AP-REQ containing TGT ticket + encrypted authenticator
    let ap_req = build_ap_req(&ticket_der, &encrypted_auth, params.session_etype);

    // 4. PA-TGS-REQ: padata type 1, value = AP-REQ
    let pa_tgs_req = build_padata(1, &ap_req);

    // 5. Build KDC-REQ-BODY for TGS
    let preferred_etype = params.target_etype.unwrap_or(ETYPE_RC4_HMAC);
    let sname_type = if params.enterprise { 10 } else { 2 };
    let sname_parts: Vec<&str> = if params.enterprise {
        vec![&params.spn]
    } else {
        params.spn.split('/').collect()
    };

    let req_body = build_tgs_req_body(&realm, sname_type, &sname_parts, nonce, preferred_etype);

    // 6. Wrap in TGS-REQ APPLICATION[12]
    let tgs_req = build_tgs_req(&pa_tgs_req, &req_body);

    // 7. Send to KDC
    let response = crate::kerberos::send_kdc(&params.dc, &tgs_req, false).await?;

    if response.is_empty() {
        return Err("Empty KDC response".into());
    }

    // Check for KRB-ERROR (APPLICATION[30] = 0x7e)
    if response[0] == 0x7e {
        let code = extract_krb_error_code(&response);
        return Err(format!("KRB-ERROR: {}", krb_error_string(code)).into());
    }

    // 8. Parse TGS-REP (APPLICATION[13] = 0x6d)
    if response[0] != 0x6d {
        return Err(format!("Unexpected response tag: 0x{:02x}", response[0]).into());
    }

    let ticket_bytes = extract_ticket_from_rep(&response)?;
    let (enc_etype, cipher) = extract_enc_part_from_rep(&response)?;

    Ok(AskTgsResult {
        service_ticket: ticket_bytes,
        enc_part_cipher: cipher,
        enc_part_etype: enc_etype,
        spn: params.spn.clone(),
    })
}

fn build_authenticator(username: &str, realm: &str, time: &str, nonce: u32) -> Vec<u8> {
    // Authenticator ::= [APPLICATION 2] SEQUENCE {
    //   authenticator-vno[0] INTEGER (5),
    //   crealm[1] GeneralString,
    //   cname[2] PrincipalName,
    //   cksum[3] Checksum OPTIONAL,
    //   cusec[4] INTEGER,
    //   ctime[5] GeneralizedTime,
    //   subkey[6] EncryptionKey OPTIONAL,
    //   seq-number[7] INTEGER OPTIONAL,
    //   authorization-data[8] OPTIONAL
    // }
    let cname = encode_principal_name(1, &[username]);
    let mut content = Vec::new();
    content.extend(encode_context_tag(0, &encode_integer(5))); // authenticator-vno
    content.extend(encode_context_tag(1, &encode_general_string(realm))); // crealm
    content.extend(encode_context_tag(2, &cname)); // cname
    content.extend(encode_context_tag(4, &encode_integer(0))); // cusec
    content.extend(encode_context_tag(5, &encode_generalized_time(time))); // ctime
    content.extend(encode_context_tag(7, &encode_integer_u32(nonce))); // seq-number

    let seq = encode_sequence(&[&content]);
    encode_application_tag(2, &seq)
}

fn rc4_encrypt_for_tgs(
    key: &[u8],
    plaintext: &[u8],
    usage: i32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // RC4-HMAC encryption per RFC 4757:
    // K1 = HMAC-MD5(key, usage_le_bytes)
    // K3 = HMAC-MD5(K1, random_confounder + plaintext)
    // Encrypt = RC4(HMAC-MD5(K1, K3), confounder + plaintext)
    // Output = K3(16 bytes) + encrypted(confounder(8) + plaintext)

    let usage_bytes = (usage as u32).to_le_bytes();
    let k1 = hmac_md5(key, &usage_bytes);

    // 8-byte random confounder
    let confounder: [u8; 8] = rand::random();

    let mut to_encrypt = Vec::with_capacity(8 + plaintext.len());
    to_encrypt.extend_from_slice(&confounder);
    to_encrypt.extend_from_slice(plaintext);

    let checksum = hmac_md5(&k1, &to_encrypt);
    let k3 = hmac_md5(&k1, &checksum);

    let encrypted = rc4_transform(&k3, &to_encrypt);

    let mut result = Vec::with_capacity(16 + encrypted.len());
    result.extend_from_slice(&checksum);
    result.extend(encrypted);
    Ok(result)
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC-MD5 key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn rc4_transform(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255u16).map(|i| i as u8).collect();
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    let mut i: u8 = 0;
    let mut j: u8 = 0;
    let mut output = Vec::with_capacity(data.len());
    for &byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[s[i as usize].wrapping_add(s[j as usize]) as usize];
        output.push(byte ^ k);
    }
    output
}

fn build_ap_req(ticket_der: &[u8], encrypted_auth: &[u8], auth_etype: i32) -> Vec<u8> {
    // AP-REQ ::= [APPLICATION 14] SEQUENCE {
    //   pvno[0] INTEGER (5),
    //   msg-type[1] INTEGER (14),
    //   ap-options[2] BIT STRING,
    //   ticket[3] Ticket,
    //   authenticator[4] EncryptedData
    // }
    let enc_data = build_encrypted_data(auth_etype, None, encrypted_auth);
    let ap_options = encode_bitstring(&[0, 0, 0, 0]); // no flags

    let mut content = Vec::new();
    content.extend(encode_context_tag(0, &encode_integer(5))); // pvno
    content.extend(encode_context_tag(1, &encode_integer(14))); // msg-type
    content.extend(encode_context_tag(2, &ap_options)); // ap-options
    content.extend(encode_context_tag(3, ticket_der)); // ticket (already DER)
    content.extend(encode_context_tag(4, &enc_data)); // authenticator

    let seq = encode_sequence(&[&content]);
    encode_application_tag(14, &seq)
}

fn build_encrypted_data(etype: i32, kvno: Option<u32>, cipher: &[u8]) -> Vec<u8> {
    // EncryptedData ::= SEQUENCE {
    //   etype[0] INTEGER,
    //   kvno[1] INTEGER OPTIONAL,
    //   cipher[2] OCTET STRING
    // }
    let mut content = Vec::new();
    content.extend(encode_context_tag(0, &encode_integer(etype)));
    if let Some(kv) = kvno {
        content.extend(encode_context_tag(1, &encode_integer_u32(kv)));
    }
    content.extend(encode_context_tag(2, &encode_octet_string(cipher)));
    encode_sequence(&[&content])
}

fn build_padata(pa_type: i32, pa_value: &[u8]) -> Vec<u8> {
    // PA-DATA ::= SEQUENCE {
    //   padata-type[1] INTEGER,
    //   padata-value[2] OCTET STRING
    // }
    let mut content = Vec::new();
    content.extend(encode_context_tag(1, &encode_integer(pa_type)));
    content.extend(encode_context_tag(2, &encode_octet_string(pa_value)));
    encode_sequence(&[&content])
}

fn build_tgs_req_body(
    realm: &str,
    sname_type: i32,
    sname_parts: &[&str],
    nonce: u32,
    etype: i32,
) -> Vec<u8> {
    let sname = encode_principal_name(sname_type, sname_parts);
    let realm_enc = encode_general_string(realm);
    let till = encode_generalized_time("20370913024805Z");
    let nonce_enc = encode_integer_u32(nonce);

    // Request preferred etype first, then RC4 as fallback
    let mut etype_list = Vec::new();
    etype_list.extend(encode_integer(etype));
    if etype != ETYPE_RC4_HMAC {
        etype_list.extend(encode_integer(ETYPE_RC4_HMAC));
    }
    if etype != ETYPE_AES256_CTS_HMAC_SHA1 {
        etype_list.extend(encode_integer(ETYPE_AES256_CTS_HMAC_SHA1));
    }
    let etypes = encode_sequence(&[&etype_list]);

    // kdc-options: forwardable(0x40000000), renewable(0x00800000), renewable-ok(0x00000010)
    let kdc_options = encode_bitstring(&0x40810010u32.to_be_bytes());

    let mut body = Vec::new();
    body.extend(encode_context_tag(0, &kdc_options));
    body.extend(encode_context_tag(2, &realm_enc)); // realm
    body.extend(encode_context_tag(3, &sname)); // sname
    body.extend(encode_context_tag(5, &till)); // till
    body.extend(encode_context_tag(7, &nonce_enc)); // nonce
    body.extend(encode_context_tag(8, &etypes)); // etype

    encode_sequence(&[&body])
}

fn build_tgs_req(pa_tgs_req: &[u8], req_body: &[u8]) -> Vec<u8> {
    // TGS-REQ ::= [APPLICATION 12] KDC-REQ
    // KDC-REQ ::= SEQUENCE {
    //   pvno[1] INTEGER (5),
    //   msg-type[2] INTEGER (12),
    //   padata[3] SEQUENCE OF PA-DATA,
    //   req-body[4] KDC-REQ-BODY
    // }
    let padata_seq = encode_sequence(&[pa_tgs_req]);

    let mut content = Vec::new();
    content.extend(encode_context_tag(1, &encode_integer(5))); // pvno
    content.extend(encode_context_tag(2, &encode_integer(12))); // msg-type = TGS-REQ
    content.extend(encode_context_tag(3, &padata_seq)); // padata
    content.extend(encode_context_tag(4, req_body)); // req-body

    let seq = encode_sequence(&[&content]);
    encode_application_tag(12, &seq)
}

fn extract_ticket_from_tgt(tgt_raw: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // The TGT raw bytes may be an AS-REP or a KRB-CRED containing the ticket.
    // Walk the ASN.1 looking for the Ticket (APPLICATION[1]).
    // Ticket = APPLICATION[1] SEQUENCE { tkt-vno, realm, sname, enc-part }
    if let Some(ticket) = find_application_tag(tgt_raw, 1) {
        return Ok(ticket);
    }
    // If the entire blob is the ticket, use it as-is
    if tgt_raw.len() > 4 && (tgt_raw[0] == 0x61) {
        return Ok(tgt_raw.to_vec());
    }
    Err("Could not extract Ticket from TGT data".into())
}

fn extract_ticket_from_rep(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // In TGS-REP, ticket is context tag [5]
    // Walk to find APPLICATION[1] (Ticket)
    if let Some(ticket) = find_application_tag(data, 1) {
        return Ok(ticket);
    }
    Err("Could not extract ticket from TGS-REP".into())
}

fn extract_enc_part_from_rep(data: &[u8]) -> Result<(i32, Vec<u8>), Box<dyn Error>> {
    // In KDC-REP, enc-part is the last EncryptedData (context tag [6])
    // EncryptedData = SEQUENCE { etype[0] INTEGER, kvno[1] INTEGER OPTIONAL, cipher[2] OCTET STRING }
    // We want the etype and the raw cipher bytes.

    // Find the last context tag [6] which is the enc-part of the outer KDC-REP
    // (not the ticket's enc-part)
    let mut last_enc_part_pos = None;
    let mut pos = 0;
    while pos < data.len().saturating_sub(2) {
        if data[pos] == 0xa6 {
            last_enc_part_pos = Some(pos);
        }
        pos += 1;
    }

    if let Some(ep_pos) = last_enc_part_pos {
        let mut p = ep_pos + 1;
        let outer_len = parse_asn1_length(data, &mut p)?;
        let enc_data_bytes = &data[p..p + outer_len.min(data.len() - p)];

        let etype = extract_integer_from_context(enc_data_bytes, 0).unwrap_or(ETYPE_RC4_HMAC);
        let cipher =
            extract_octet_from_context(enc_data_bytes, 2).ok_or("No cipher in enc-part")?;

        return Ok((etype, cipher));
    }

    Err("Could not find enc-part in TGS-REP".into())
}

fn find_application_tag(data: &[u8], tag: u8) -> Option<Vec<u8>> {
    let target = 0x60 | tag; // APPLICATION constructed
    let mut pos = 0;
    while pos < data.len() {
        if data[pos] == target {
            let start = pos;
            pos += 1;
            if let Ok(len) = parse_asn1_length(data, &mut pos) {
                let end = pos + len;
                if end <= data.len() {
                    return Some(data[start..end].to_vec());
                }
            }
        }
        pos += 1;
    }
    None
}

fn extract_integer_from_context(data: &[u8], ctx_tag: u8) -> Option<i32> {
    let target = 0xa0 | ctx_tag;
    let mut pos = 0;
    while pos < data.len().saturating_sub(2) {
        if data[pos] == target {
            pos += 1;
            if let Ok(len) = parse_asn1_length(data, &mut pos) {
                if pos + len <= data.len() && pos < data.len() && data[pos] == 0x02 {
                    let mut ip = pos + 1;
                    if let Ok(int_len) = parse_asn1_length(data, &mut ip) {
                        let mut val = 0i32;
                        for j in 0..int_len.min(4) {
                            val = (val << 8) | data[ip + j] as i32;
                        }
                        return Some(val);
                    }
                }
                pos += len;
                continue;
            }
        }
        pos += 1;
    }
    None
}

fn extract_octet_from_context(data: &[u8], ctx_tag: u8) -> Option<Vec<u8>> {
    let target = 0xa0 | ctx_tag;
    let mut pos = 0;
    while pos < data.len().saturating_sub(2) {
        if data[pos] == target {
            pos += 1;
            if let Ok(len) = parse_asn1_length(data, &mut pos) {
                if pos + len <= data.len() && pos < data.len() && data[pos] == 0x04 {
                    let mut ip = pos + 1;
                    if let Ok(oct_len) = parse_asn1_length(data, &mut ip) {
                        if ip + oct_len <= data.len() {
                            return Some(data[ip..ip + oct_len].to_vec());
                        }
                    }
                }
                pos += len;
                continue;
            }
        }
        pos += 1;
    }
    None
}

fn extract_krb_error_code(data: &[u8]) -> Option<u32> {
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0xa6 {
            let mut pos = i + 1;
            if let Ok(len) = parse_asn1_length(data, &mut pos) {
                if pos + len <= data.len() && data[pos] == 0x02 {
                    pos += 1;
                    if let Ok(int_len) = parse_asn1_length(data, &mut pos) {
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

fn krb_error_string(code: Option<u32>) -> String {
    match code {
        Some(6) => "KDC_ERR_C_PRINCIPAL_UNKNOWN".into(),
        Some(7) => "KDC_ERR_S_PRINCIPAL_UNKNOWN".into(),
        Some(12) => "KDC_ERR_POLICY".into(),
        Some(13) => "KDC_ERR_BADOPTION".into(),
        Some(14) => "KDC_ERR_ETYPE_NOSUPP".into(),
        Some(17) => "KDC_ERR_KEY_EXPIRED".into(),
        Some(18) => "KDC_ERR_CLIENT_REVOKED".into(),
        Some(24) => "KDC_ERR_PREAUTH_FAILED".into(),
        Some(25) => "KDC_ERR_PREAUTH_REQUIRED".into(),
        Some(31) => "KRB_AP_ERR_SKEW".into(),
        Some(32) => "KRB_AP_ERR_BADADDR".into(),
        Some(37) => "KRB_AP_ERR_SKEW".into(),
        Some(41) => "KRB_AP_ERR_REPEAT".into(),
        Some(c) => format!("KRB_ERROR({})", c),
        None => "UNKNOWN_KRB_ERROR".into(),
    }
}

// ─── ASN.1 DER encoding helpers ──────────────────────────────────────

fn parse_asn1_length(data: &[u8], pos: &mut usize) -> Result<usize, Box<dyn Error>> {
    if *pos >= data.len() {
        return Err("unexpected end".into());
    }
    let first = data[*pos];
    *pos += 1;
    if first < 0x80 {
        return Ok(first as usize);
    }
    let n = (first & 0x7f) as usize;
    if n > 4 || *pos + n > data.len() {
        return Err("invalid length".into());
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

fn encode_sequence(items: &[&[u8]]) -> Vec<u8> {
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
        if !slice.is_empty() && slice[0] & 0x80 != 0 {
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

fn encode_principal_name(name_type: i32, names: &[&str]) -> Vec<u8> {
    let nt = encode_integer(name_type);
    let mut ns = Vec::new();
    for n in names {
        ns.extend(encode_general_string(n));
    }
    let nseq = encode_sequence(&[&ns]);
    let mut c = Vec::new();
    c.extend(encode_context_tag(0, &nt));
    c.extend(encode_context_tag(1, &nseq));
    encode_sequence(&[&c])
}
