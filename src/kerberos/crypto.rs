use sha1::Sha1;
use sha1::Digest as Sha1Digest;

pub const ETYPE_DES_CBC_MD5: i32 = 3;
pub const ETYPE_RC4_HMAC: i32 = 23;
pub const ETYPE_AES128_CTS_HMAC_SHA1: i32 = 17;
pub const ETYPE_AES256_CTS_HMAC_SHA1: i32 = 18;

pub fn nt_hash(password: &str) -> Vec<u8> {
    let utf16: Vec<u8> = password.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    md4_hash(&utf16)
}

fn md4_hash(data: &[u8]) -> Vec<u8> {
    use std::num::Wrapping;

    fn f(x: u32, y: u32, z: u32) -> u32 { (x & y) | (!x & z) }
    fn g(x: u32, y: u32, z: u32) -> u32 { (x & y) | (x & z) | (y & z) }
    fn h(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a, mut b, mut c, mut d) = (
        Wrapping(0x67452301u32), Wrapping(0xefcdab89u32),
        Wrapping(0x98badcfeu32), Wrapping(0x10325476u32),
    );

    for chunk in msg.chunks(64) {
        let mut x = [0u32; 16];
        for (i, word) in chunk.chunks(4).enumerate() {
            x[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let (aa, bb, cc, dd) = (a, b, c, d);

        let r1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
        let s1 = [3,7,11,19,3,7,11,19,3,7,11,19,3,7,11,19];
        for i in 0..16 {
            let val = a + Wrapping(f(b.0, c.0, d.0)) + Wrapping(x[r1[i]]);
            a = d; d = c; c = b; b = Wrapping(val.0.rotate_left(s1[i]));
        }

        let r2 = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15];
        let s2 = [3,5,9,13,3,5,9,13,3,5,9,13,3,5,9,13];
        for i in 0..16 {
            let val = a + Wrapping(g(b.0, c.0, d.0)) + Wrapping(x[r2[i]]) + Wrapping(0x5A827999);
            a = d; d = c; c = b; b = Wrapping(val.0.rotate_left(s2[i]));
        }

        let r3 = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15];
        let s3 = [3,9,11,15,3,9,11,15,3,9,11,15,3,9,11,15];
        for i in 0..16 {
            let val = a + Wrapping(h(b.0, c.0, d.0)) + Wrapping(x[r3[i]]) + Wrapping(0x6ED9EBA1);
            a = d; d = c; c = b; b = Wrapping(val.0.rotate_left(s3[i]));
        }

        a = a + aa; b = b + bb; c = c + cc; d = d + dd;
    }

    let mut result = Vec::with_capacity(16);
    result.extend_from_slice(&a.0.to_le_bytes());
    result.extend_from_slice(&b.0.to_le_bytes());
    result.extend_from_slice(&c.0.to_le_bytes());
    result.extend_from_slice(&d.0.to_le_bytes());
    result
}

pub fn rc4_hmac_key(password: &str) -> Vec<u8> {
    nt_hash(password)
}

pub fn aes_string_to_key(password: &str, salt: &str, iterations: u32, key_len: usize) -> Vec<u8> {
    let password_bytes = password.as_bytes();
    let salt_bytes = salt.as_bytes();
    pbkdf2_sha1(password_bytes, salt_bytes, iterations, key_len)
}

pub fn aes256_key(password: &str, domain: &str, username: &str) -> Vec<u8> {
    let salt = format!("{}{}",
        domain.to_uppercase(),
        username,
    );
    aes_string_to_key(password, &salt, 4096, 32)
}

pub fn aes128_key(password: &str, domain: &str, username: &str) -> Vec<u8> {
    let salt = format!("{}{}",
        domain.to_uppercase(),
        username,
    );
    aes_string_to_key(password, &salt, 4096, 16)
}

pub fn des_string_to_key(password: &str, domain: &str, username: &str) -> Vec<u8> {
    let salt = format!("{}{}", domain.to_uppercase(), username);
    let mut concat = password.as_bytes().to_vec();
    concat.extend_from_slice(salt.as_bytes());

    // Simplified DES key derivation — pad to 8 bytes
    let mut key = [0u8; 8];
    for (i, &b) in concat.iter().enumerate() {
        key[i % 8] ^= b;
    }
    // Set parity bits
    for byte in key.iter_mut() {
        let mut parity = 0u8;
        for bit in 0..7 {
            parity ^= (*byte >> bit) & 1;
        }
        *byte = (*byte & 0xFE) | (parity ^ 1);
    }
    key.to_vec()
}

fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha1 = Hmac<Sha1>;

    let mut dk = Vec::with_capacity(dk_len);
    let mut block = 1u32;

    while dk.len() < dk_len {
        let mut mac = HmacSha1::new_from_slice(password).expect("HMAC key");
        mac.update(salt);
        mac.update(&block.to_be_bytes());
        let mut u = mac.finalize().into_bytes().to_vec();
        let mut result = u.clone();

        for _ in 1..iterations {
            let mut mac = HmacSha1::new_from_slice(password).expect("HMAC key");
            mac.update(&u);
            u = mac.finalize().into_bytes().to_vec();
            for (r, x) in result.iter_mut().zip(u.iter()) {
                *r ^= x;
            }
        }

        dk.extend_from_slice(&result);
        block += 1;
    }

    dk.truncate(dk_len);
    dk
}

pub fn compute_all_keys(password: &str, domain: &str, username: &str) -> KerberosKeys {
    KerberosKeys {
        rc4: rc4_hmac_key(password),
        aes128: aes128_key(password, domain, username),
        aes256: aes256_key(password, domain, username),
        des: des_string_to_key(password, domain, username),
    }
}

pub struct KerberosKeys {
    pub rc4: Vec<u8>,
    pub aes128: Vec<u8>,
    pub aes256: Vec<u8>,
    pub des: Vec<u8>,
}

impl std::fmt::Display for KerberosKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  RC4_HMAC      : {}", hex::encode(&self.rc4))?;
        writeln!(f, "  AES128_CTS    : {}", hex::encode(&self.aes128))?;
        writeln!(f, "  AES256_CTS    : {}", hex::encode(&self.aes256))?;
        writeln!(f, "  DES_CBC_MD5   : {}", hex::encode(&self.des))?;
        Ok(())
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 { return Err("odd length".into()); }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i+2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}
