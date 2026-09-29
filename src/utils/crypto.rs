use sha1::{Digest, Sha1};

/// Easy function to get SHA1 hash
pub fn calculate_sha1(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    format!("{:X}", hasher.finalize())
}

/// Return encryption type msDS-SupportedEncryptionTypes to BloodHound-CE string format.
/// <https://github.com/SpecterOps/SharpHoundCommon/blob/c953260325cbfd335ed2e9726cfe28d4b16357c8/src/CommonLib/Processors/LdapPropertyProcessor.cs#L731>
pub fn convert_encryption_types(encryption_types: i32) -> Vec<String> {
    // Define Kerberos Encryption Types as constants
    const DES_CBC_CRC: i32 = 0x1;
    const DES_CBC_MD5: i32 = 0x2;
    const RC4_HMAC_MD5: i32 = 0x4;
    const AES128_CTS_HMAC_SHA1_96: i32 = 0x8;
    const AES256_CTS_HMAC_SHA1_96: i32 = 0x10;

    let mut supported_encryption_types = Vec::new();

    if encryption_types == 0 {
        supported_encryption_types.push("Not defined".to_string());
    }

    if (encryption_types & DES_CBC_CRC) == DES_CBC_CRC {
        supported_encryption_types.push("DES-CBC-CRC".to_string());
    }

    if (encryption_types & DES_CBC_MD5) == DES_CBC_MD5 {
        supported_encryption_types.push("DES-CBC-MD5".to_string());
    }

    if (encryption_types & RC4_HMAC_MD5) == RC4_HMAC_MD5 {
        supported_encryption_types.push("RC4-HMAC-MD5".to_string());
    }

    if (encryption_types & AES128_CTS_HMAC_SHA1_96) == AES128_CTS_HMAC_SHA1_96 {
        supported_encryption_types.push("AES128-CTS-HMAC-SHA1-96".to_string());
    }

    if (encryption_types & AES256_CTS_HMAC_SHA1_96) == AES256_CTS_HMAC_SHA1_96 {
        supported_encryption_types.push("AES256-CTS-HMAC-SHA1-96".to_string());
    }

    supported_encryption_types
}
