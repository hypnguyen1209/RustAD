use std::error::Error;

pub struct TgtDelegResult {
    pub tgt: Vec<u8>,
    pub session_key: Vec<u8>,
    pub etype: i32,
}

/// Extract the current user's TGT without elevation via Kerberos GSS-API
/// delegation abuse (Kekeo/Rubeus tgtdeleg technique).
///
/// On Windows, this uses SSPI `InitializeSecurityContext` with the
/// `ISC_REQ_DELEGATE` and `ISC_REQ_MUTUAL_AUTH` flags against a target SPN.
/// The resulting AP-REQ contains the delegated TGT in the authenticator's
/// checksum field (GSS checksum Dlgopt=1, deleg_length + KRB-CRED).
///
/// On non-Windows platforms this technique is not available because it
/// relies on the Windows SSPI credential cache.
pub async fn tgt_deleg(
    _dc: &str,
    _domain: &str,
    _target_spn: &str,
) -> Result<TgtDelegResult, Box<dyn Error>> {
    #[cfg(windows)]
    {
        // The Windows SSPI flow:
        // 1. AcquireCredentialsHandle(NEGOSSP_NAME, SECPKG_CRED_OUTBOUND)
        // 2. InitializeSecurityContext with ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH
        //    targeting the provided SPN
        // 3. Parse the output token (SPNEGO wrapping an AP-REQ)
        // 4. Unwrap SPNEGO → AP-REQ → Authenticator
        // 5. The authenticator's Checksum (cksum type 0x8003 = KRB_AP_REQ_CHECKSUM)
        //    contains: Flags(4 bytes, bit 0 = deleg) + Dlgopt(2) + DlgLength(2) + KRB-CRED
        // 6. Extract KRB-CRED → contains the forwarded TGT + session key
        //
        // This requires the `windows` crate with Security feature, which adds
        // significant compile-time overhead. Stubbed for now.
        Err(
            "tgtdeleg: Windows SSPI implementation pending (needs windows crate Security feature)"
                .into(),
        )
    }

    #[cfg(not(windows))]
    {
        Err("tgtdeleg requires Windows SSPI (not available on this platform)".into())
    }
}
