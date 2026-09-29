use std::error::Error;

#[derive(Debug, Clone)]
pub struct KrbCredTicket {
    pub raw: Vec<u8>,
    pub realm: String,
    pub sname: Vec<String>,
    pub enc_part: Vec<u8>,
    pub etype: i32,
    pub kvno: Option<u32>,
}

impl KrbCredTicket {
    pub fn from_asrep(asrep_bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let inner = unwrap_application(asrep_bytes)?;
        let ticket_raw =
            extract_context_tag_content(&inner, 5).ok_or("ticket field [5] not found in AS-REP")?;
        let realm = extract_string_from_context(&inner, 3).unwrap_or_default();
        let sname = extract_sname_from_ticket(&ticket_raw);
        let enc_part_raw = extract_context_tag_content(&inner, 6).unwrap_or_default();
        let (etype, _kvno, cipher) = parse_encrypted_data(&enc_part_raw);
        Ok(Self {
            raw: ticket_raw,
            realm,
            sname,
            enc_part: cipher,
            etype,
            kvno: None,
        })
    }

    pub fn from_tgsrep(tgsrep_bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let inner = unwrap_application(tgsrep_bytes)?;
        let ticket_raw = extract_context_tag_content(&inner, 5)
            .ok_or("ticket field [5] not found in TGS-REP")?;
        let realm = extract_string_from_context(&inner, 3).unwrap_or_default();
        let sname = extract_sname_from_ticket(&ticket_raw);
        let enc_part_raw = extract_context_tag_content(&inner, 6).unwrap_or_default();
        let (etype, _kvno, cipher) = parse_encrypted_data(&enc_part_raw);
        Ok(Self {
            raw: ticket_raw,
            realm,
            sname,
            enc_part: cipher,
            etype,
            kvno: None,
        })
    }

    pub fn from_kirbi(kirbi_bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let inner = unwrap_application(kirbi_bytes)?;
        let tickets_seq = extract_context_tag_content(&inner, 2)
            .ok_or("tickets field [2] not found in KRB-CRED")?;
        let ticket_inner = unwrap_sequence(&tickets_seq)?;
        let ticket_raw = if ticket_inner.is_empty() {
            return Err("empty tickets sequence".into());
        } else {
            tickets_seq.clone()
        };
        let realm = extract_string_from_ticket(&ticket_raw);
        let sname = extract_sname_from_ticket(&ticket_raw);
        Ok(Self {
            raw: ticket_raw,
            realm,
            sname,
            enc_part: Vec::new(),
            etype: 0,
            kvno: None,
        })
    }

    pub fn to_kirbi(&self) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend(encode_context_tag(0, &encode_integer(5)));
        content.extend(encode_context_tag(1, &encode_integer(22)));
        let tickets_seq = encode_sequence_raw(&[&self.raw]);
        content.extend(encode_context_tag(2, &tickets_seq));
        let enc_data = encode_encrypted_data(0, &[0]);
        content.extend(encode_context_tag(3, &enc_data));
        let seq = encode_sequence_raw(&[&content]);
        encode_application_tag(22, &seq)
    }

    pub fn to_base64(&self) -> String {
        base64_encode(&self.to_kirbi())
    }
}

fn unwrap_application(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    let tag = data[0];
    if tag & 0x60 != 0x60 && tag != 0x30 {
        return Err(format!(
            "unexpected tag 0x{:02x}, expected APPLICATION or SEQUENCE",
            tag
        )
        .into());
    }
    let mut pos = 1;
    let len = parse_asn1_length(data, &mut pos)?;
    if pos + len > data.len() {
        return Err("truncated APPLICATION content".into());
    }
    let content = &data[pos..pos + len];
    if content.is_empty() {
        return Err("empty APPLICATION content".into());
    }
    if content[0] == 0x30 {
        return unwrap_sequence(content);
    }
    Ok(content.to_vec())
}

fn unwrap_sequence(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
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

fn extract_context_tag_content(data: &[u8], target_tag: u8) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos < data.len() {
        let tag = data[pos];
        pos += 1;
        let len = match parse_asn1_length(data, &mut pos) {
            Ok(l) => l,
            Err(_) => return None,
        };
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

fn extract_string_from_context(data: &[u8], target_tag: u8) -> Option<String> {
    let content = extract_context_tag_content(data, target_tag)?;
    extract_first_string(&content)
}

fn extract_first_string(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    // GeneralString (0x1b), UTF8String (0x0c), IA5String (0x16), PrintableString (0x13)
    if matches!(tag, 0x1b | 0x0c | 0x16 | 0x13) {
        let mut pos = 1;
        let len = parse_asn1_length(data, &mut pos).ok()?;
        if pos + len <= data.len() {
            return Some(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        }
    }
    None
}

fn extract_sname_from_ticket(ticket_data: &[u8]) -> Vec<String> {
    let inner = match unwrap_application(ticket_data) {
        Ok(d) => d,
        Err(_) => ticket_data.to_vec(),
    };
    let sname_content = match extract_context_tag_content(&inner, 2) {
        Some(c) => c,
        None => return Vec::new(),
    };
    let seq_inner = match unwrap_sequence(&sname_content) {
        Ok(d) => d,
        Err(_) => sname_content,
    };
    let name_string_content = match extract_context_tag_content(&seq_inner, 1) {
        Some(c) => c,
        None => return Vec::new(),
    };
    let names_inner = match unwrap_sequence(&name_string_content) {
        Ok(d) => d,
        Err(_) => name_string_content,
    };
    extract_all_strings(&names_inner)
}

fn extract_string_from_ticket(ticket_data: &[u8]) -> String {
    let inner = match unwrap_application(ticket_data) {
        Ok(d) => d,
        Err(_) => ticket_data.to_vec(),
    };
    extract_string_from_context(&inner, 1).unwrap_or_default()
}

fn extract_all_strings(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let tag = data[pos];
        pos += 1;
        let len = match parse_asn1_length(data, &mut pos) {
            Ok(l) => l,
            Err(_) => break,
        };
        if pos + len > data.len() {
            break;
        }
        if matches!(tag, 0x1b | 0x0c | 0x16 | 0x13) {
            result.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        }
        pos += len;
    }
    result
}

fn parse_encrypted_data(data: &[u8]) -> (i32, Option<u32>, Vec<u8>) {
    let inner = match unwrap_sequence(data) {
        Ok(d) => d,
        Err(_) => return (0, None, Vec::new()),
    };
    let etype_raw = extract_context_tag_content(&inner, 0).unwrap_or_default();
    let etype = parse_integer(&etype_raw);
    let kvno_raw = extract_context_tag_content(&inner, 1);
    let kvno = kvno_raw.map(|r| parse_integer(&r) as u32);
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

fn parse_integer(data: &[u8]) -> i32 {
    let inner = if !data.is_empty() && data[0] == 0x02 {
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
    let mut val: i32 = 0;
    for &b in inner {
        val = (val << 8) | b as i32;
    }
    val
}

fn parse_asn1_length(data: &[u8], pos: &mut usize) -> Result<usize, Box<dyn Error>> {
    if *pos >= data.len() {
        return Err("unexpected end of data".into());
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

fn encode_sequence_raw(items: &[&[u8]]) -> Vec<u8> {
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
        let start = bytes.iter().position(|&b| b != 0 && b != 0xff).unwrap_or(3);
        let trimmed = &bytes[start..];
        out.extend(encode_length(trimmed.len()));
        out.extend(trimmed);
    }
    out
}

fn encode_encrypted_data(etype: i32, cipher: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(encode_context_tag(0, &encode_integer(etype)));
    let mut octet = vec![0x04];
    octet.extend(encode_length(cipher.len()));
    octet.extend(cipher);
    content.extend(encode_context_tag(2, &octet));
    encode_sequence_raw(&[&content])
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
