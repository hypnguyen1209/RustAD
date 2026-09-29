use std::error::Error;

#[derive(Debug, Clone, Default)]
pub struct TicketInfo {
    pub pvno: u32,
    pub realm: String,
    pub sname: Vec<String>,
    pub cname: Vec<String>,
    pub crealm: String,
    pub enc_type: i32,
    pub key_version: Option<u32>,
    pub flags: u32,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub renew_till: Option<String>,
    pub ticket_enc_type: i32,
}

pub fn describe_ticket(data: &[u8]) -> Result<TicketInfo, Box<dyn Error>> {
    if data.is_empty() {
        return Err("empty ticket data".into());
    }

    let app_tag = data[0];
    match app_tag {
        // KRB-CRED APPLICATION[22] (0x76)
        0x76 => parse_krb_cred(data),
        // AS-REP APPLICATION[11] (0x6b)
        0x6b => parse_kdc_rep(data),
        // TGS-REP APPLICATION[13] (0x6d)
        0x6d => parse_kdc_rep(data),
        // Raw Ticket APPLICATION[1] (0x61)
        0x61 => parse_raw_ticket(data),
        // SEQUENCE — might be inside an APPLICATION wrapper
        0x30 => {
            let inner = unwrap_sequence_err(data)?;
            if inner.is_empty() {
                return Err("empty sequence".into());
            }
            parse_krb_cred(data)
        }
        _ => Err(format!("unknown ticket tag 0x{:02x}", app_tag).into()),
    }
}

fn parse_kdc_rep(data: &[u8]) -> Result<TicketInfo, Box<dyn Error>> {
    let inner = unwrap_application(data)?;
    let mut info = TicketInfo::default();

    if let Some(pvno_raw) = extract_context_tag_content(&inner, 0) {
        info.pvno = parse_integer_unsigned(&pvno_raw);
    }

    if let Some(crealm_raw) = extract_context_tag_content(&inner, 3) {
        info.crealm = extract_first_string(&crealm_raw).unwrap_or_default();
        info.realm = info.crealm.clone();
    }

    if let Some(cname_raw) = extract_context_tag_content(&inner, 4) {
        info.cname = extract_principal_names(&cname_raw);
    }

    if let Some(ticket_raw) = extract_context_tag_content(&inner, 5) {
        let ticket_inner = unwrap_application(&ticket_raw).unwrap_or(ticket_raw.clone());
        if let Some(realm_raw) = extract_context_tag_content(&ticket_inner, 1) {
            info.realm = extract_first_string(&realm_raw).unwrap_or_default();
        }
        if let Some(sname_raw) = extract_context_tag_content(&ticket_inner, 2) {
            info.sname = extract_principal_names(&sname_raw);
        }
        if let Some(enc_raw) = extract_context_tag_content(&ticket_inner, 3) {
            let (etype, kvno, _) = parse_encrypted_data_fields(&enc_raw);
            info.ticket_enc_type = etype;
            info.key_version = kvno;
        }
    }

    if let Some(enc_raw) = extract_context_tag_content(&inner, 6) {
        let (etype, _, _) = parse_encrypted_data_fields(&enc_raw);
        info.enc_type = etype;
    }

    Ok(info)
}

fn parse_krb_cred(data: &[u8]) -> Result<TicketInfo, Box<dyn Error>> {
    let inner = unwrap_application(data)?;
    let mut info = TicketInfo::default();

    if let Some(pvno_raw) = extract_context_tag_content(&inner, 0) {
        info.pvno = parse_integer_unsigned(&pvno_raw);
    }

    if let Some(tickets_raw) = extract_context_tag_content(&inner, 2) {
        let tickets_inner = unwrap_sequence_bytes(&tickets_raw);
        // First ticket in the sequence
        if !tickets_inner.is_empty() {
            let ticket_data = &tickets_inner;
            let ticket_inner =
                unwrap_application(ticket_data).unwrap_or_else(|_| ticket_data.to_vec());

            if let Some(realm_raw) = extract_context_tag_content(&ticket_inner, 1) {
                info.realm = extract_first_string(&realm_raw).unwrap_or_default();
            }
            if let Some(sname_raw) = extract_context_tag_content(&ticket_inner, 2) {
                info.sname = extract_principal_names(&sname_raw);
            }
            if let Some(enc_raw) = extract_context_tag_content(&ticket_inner, 3) {
                let (etype, kvno, _) = parse_encrypted_data_fields(&enc_raw);
                info.ticket_enc_type = etype;
                info.key_version = kvno;
            }
        }
    }

    Ok(info)
}

fn parse_raw_ticket(data: &[u8]) -> Result<TicketInfo, Box<dyn Error>> {
    let inner = unwrap_application(data)?;
    let mut info = TicketInfo::default();

    if let Some(vno_raw) = extract_context_tag_content(&inner, 0) {
        info.pvno = parse_integer_unsigned(&vno_raw);
    }
    if let Some(realm_raw) = extract_context_tag_content(&inner, 1) {
        info.realm = extract_first_string(&realm_raw).unwrap_or_default();
    }
    if let Some(sname_raw) = extract_context_tag_content(&inner, 2) {
        info.sname = extract_principal_names(&sname_raw);
    }
    if let Some(enc_raw) = extract_context_tag_content(&inner, 3) {
        let (etype, kvno, _) = parse_encrypted_data_fields(&enc_raw);
        info.ticket_enc_type = etype;
        info.key_version = kvno;
        info.enc_type = etype;
    }

    Ok(info)
}

pub fn print_ticket_info(info: &TicketInfo) {
    println!();
    println!("  Ticket Information:");
    println!("  -------------------");
    if !info.realm.is_empty() {
        println!("  Realm       : {}", info.realm);
    }
    if !info.crealm.is_empty() && info.crealm != info.realm {
        println!("  Client Realm: {}", info.crealm);
    }
    if !info.cname.is_empty() {
        println!("  Client      : {}", info.cname.join("/"));
    }
    if !info.sname.is_empty() {
        println!("  Service     : {}", info.sname.join("/"));
    }
    if info.ticket_enc_type != 0 {
        println!(
            "  Ticket EType: {} ({})",
            info.ticket_enc_type,
            etype_name(info.ticket_enc_type)
        );
    }
    if info.enc_type != 0 && info.enc_type != info.ticket_enc_type {
        println!(
            "  EncPart Type: {} ({})",
            info.enc_type,
            etype_name(info.enc_type)
        );
    }
    if let Some(kvno) = info.key_version {
        println!("  Key Version : {}", kvno);
    }
    if info.flags != 0 {
        println!(
            "  Flags       : 0x{:08x} ({})",
            info.flags,
            decode_flags(info.flags)
        );
    }
    if let Some(ref t) = info.start_time {
        println!("  Start Time  : {}", t);
    }
    if let Some(ref t) = info.end_time {
        println!("  End Time    : {}", t);
    }
    if let Some(ref t) = info.renew_till {
        println!("  Renew Till  : {}", t);
    }
    println!();
}

fn etype_name(e: i32) -> &'static str {
    match e {
        1 => "DES-CBC-CRC",
        3 => "DES-CBC-MD5",
        16 => "DES3-CBC-SHA1",
        17 => "AES128-CTS-HMAC-SHA1",
        18 => "AES256-CTS-HMAC-SHA1",
        23 => "RC4-HMAC",
        24 => "RC4-HMAC-EXP",
        _ => "Unknown",
    }
}

fn decode_flags(f: u32) -> String {
    let mut flags = Vec::new();
    if f & 0x40000000 != 0 {
        flags.push("forwardable");
    }
    if f & 0x20000000 != 0 {
        flags.push("forwarded");
    }
    if f & 0x10000000 != 0 {
        flags.push("proxiable");
    }
    if f & 0x08000000 != 0 {
        flags.push("proxy");
    }
    if f & 0x04000000 != 0 {
        flags.push("may-postdate");
    }
    if f & 0x02000000 != 0 {
        flags.push("postdated");
    }
    if f & 0x01000000 != 0 {
        flags.push("invalid");
    }
    if f & 0x00800000 != 0 {
        flags.push("renewable");
    }
    if f & 0x00400000 != 0 {
        flags.push("initial");
    }
    if f & 0x00200000 != 0 {
        flags.push("pre-authent");
    }
    if f & 0x00100000 != 0 {
        flags.push("hw-authent");
    }
    if f & 0x00080000 != 0 {
        flags.push("ok-as-delegate");
    }
    if f & 0x00010000 != 0 {
        flags.push("enc-pa-rep");
    }
    if flags.is_empty() {
        "none".to_string()
    } else {
        flags.join(", ")
    }
}

// --- ASN.1 helpers ---

fn unwrap_application(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    let tag = data[0];
    if tag & 0x60 != 0x60 && tag != 0x30 {
        return Err(format!("unexpected tag 0x{:02x}", tag).into());
    }
    let mut pos = 1;
    let len = parse_asn1_length(data, &mut pos)?;
    if pos + len > data.len() {
        return Err("truncated data".into());
    }
    let content = &data[pos..pos + len];
    if !content.is_empty() && content[0] == 0x30 {
        return unwrap_sequence_err(content);
    }
    Ok(content.to_vec())
}

fn unwrap_sequence_err(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if data.is_empty() || data[0] != 0x30 {
        return Ok(data.to_vec());
    }
    let mut pos = 1;
    let len = parse_asn1_length(data, &mut pos)?;
    if pos + len > data.len() {
        return Err("truncated SEQUENCE".into());
    }
    Ok(data[pos..pos + len].to_vec())
}

fn unwrap_sequence_bytes(data: &[u8]) -> Vec<u8> {
    unwrap_sequence_err(data).unwrap_or_else(|_| data.to_vec())
}

fn extract_context_tag_content(data: &[u8], target_tag: u8) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos < data.len() {
        if pos >= data.len() {
            break;
        }
        let tag = data[pos];
        pos += 1;
        let len = parse_asn1_length(data, &mut pos).ok()?;
        if pos + len > data.len() {
            return None;
        }
        let ctx = tag & 0x1f;
        if (tag & 0xe0 == 0xa0) && ctx == target_tag {
            return Some(data[pos..pos + len].to_vec());
        }
        pos += len;
    }
    None
}

fn extract_first_string(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    if matches!(tag, 0x1b | 0x0c | 0x16 | 0x13) {
        let mut pos = 1;
        let len = parse_asn1_length(data, &mut pos).ok()?;
        if pos + len <= data.len() {
            return Some(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        }
    }
    None
}

fn extract_principal_names(data: &[u8]) -> Vec<String> {
    let inner = unwrap_sequence_bytes(data);
    let name_string_raw = match extract_context_tag_content(&inner, 1) {
        Some(c) => c,
        None => return Vec::new(),
    };
    let names_inner = unwrap_sequence_bytes(&name_string_raw);
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < names_inner.len() {
        let tag = names_inner[pos];
        pos += 1;
        let len = match parse_asn1_length(&names_inner, &mut pos) {
            Ok(l) => l,
            Err(_) => break,
        };
        if pos + len > names_inner.len() {
            break;
        }
        if matches!(tag, 0x1b | 0x0c | 0x16 | 0x13) {
            result.push(String::from_utf8_lossy(&names_inner[pos..pos + len]).to_string());
        }
        pos += len;
    }
    result
}

fn parse_encrypted_data_fields(data: &[u8]) -> (i32, Option<u32>, Vec<u8>) {
    let inner = unwrap_sequence_bytes(data);
    let etype = extract_context_tag_content(&inner, 0)
        .map(|r| parse_integer_signed(&r))
        .unwrap_or(0);
    let kvno = extract_context_tag_content(&inner, 1).map(|r| parse_integer_unsigned(&r));
    let cipher = extract_context_tag_content(&inner, 2).unwrap_or_default();
    let cipher_bytes = unwrap_octet_string(&cipher);
    (etype, kvno, cipher_bytes)
}

fn unwrap_octet_string(data: &[u8]) -> Vec<u8> {
    if data.is_empty() || data[0] != 0x04 {
        return data.to_vec();
    }
    let mut pos = 1;
    let len = match parse_asn1_length(data, &mut pos) {
        Ok(l) => l,
        Err(_) => return data.to_vec(),
    };
    if pos + len <= data.len() {
        data[pos..pos + len].to_vec()
    } else {
        data.to_vec()
    }
}

fn parse_integer_signed(data: &[u8]) -> i32 {
    let bytes = if !data.is_empty() && data[0] == 0x02 {
        let mut pos = 1;
        let len = match parse_asn1_length(data, &mut pos) {
            Ok(l) => l,
            Err(_) => return 0,
        };
        if pos + len <= data.len() {
            &data[pos..pos + len]
        } else {
            return 0;
        }
    } else {
        data
    };
    let mut val: i32 = if !bytes.is_empty() && bytes[0] & 0x80 != 0 {
        -1
    } else {
        0
    };
    for &b in bytes {
        val = (val << 8) | b as i32;
    }
    val
}

fn parse_integer_unsigned(data: &[u8]) -> u32 {
    let bytes = if !data.is_empty() && data[0] == 0x02 {
        let mut pos = 1;
        let len = match parse_asn1_length(data, &mut pos) {
            Ok(l) => l,
            Err(_) => return 0,
        };
        if pos + len <= data.len() {
            &data[pos..pos + len]
        } else {
            return 0;
        }
    } else {
        data
    };
    let mut val: u32 = 0;
    for &b in bytes {
        val = (val << 8) | b as u32;
    }
    val
}

fn parse_asn1_length(data: &[u8], pos: &mut usize) -> Result<usize, Box<dyn Error>> {
    if *pos >= data.len() {
        return Err("unexpected end".into());
    }
    let first = data[*pos];
    *pos += 1;
    if first < 0x80 {
        return Ok(first as usize);
    }
    let num_bytes = (first & 0x7f) as usize;
    if num_bytes > 4 || *pos + num_bytes > data.len() {
        return Err("invalid ASN.1 length".into());
    }
    let mut len = 0usize;
    for _ in 0..num_bytes {
        len = (len << 8) | (data[*pos] as usize);
        *pos += 1;
    }
    Ok(len)
}
