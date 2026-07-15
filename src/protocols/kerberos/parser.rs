//! Kerberos protocol parser — ASN.1 APPLICATION tag detection

use crate::core::types::KerberosMetadata;

/// Kerberos APPLICATION tags
const TAG_AS_REQ: u8 = 0x6a; // APPLICATION 10
const TAG_AS_REP: u8 = 0x6b; // APPLICATION 11
const TAG_TGS_REQ: u8 = 0x6c; // APPLICATION 12
const TAG_TGS_REP: u8 = 0x6d; // APPLICATION 13

pub fn parse_kerberos(data: &[u8]) -> Option<KerberosMetadata> {
    if data.len() < 10 { return None; }
    let msg_type = match data[0] {
        TAG_AS_REQ => 10, TAG_AS_REP => 11, TAG_TGS_REQ => 12, TAG_TGS_REP => 13,
        _ => return None,
    };
    // Check for ASN.1 INTEGER encoding of pvno=5 within reasonable range
    if data.len() < 8 { return None; }
    let has_pvno5 = (2..=6).any(|i| i + 1 < data.len() && data[i] == 0x02 && data[i + 1] == 0x01 && data[i + 2] == 0x05);
    if !has_pvno5 { return None; }
    // Try to extract realm from ASN.1 structure
    let realm = extract_realm(data);
    Some(KerberosMetadata { msg_type, realm })
}

fn extract_realm(data: &[u8]) -> Option<String> {
    // Scan for OCTET STRING tag (0x04) within the payload
    // Realm typically appears after the INTEGER fields
    for i in 6..data.len().saturating_sub(3) {
        if data[i] == 0x04 {
            let len = data[i + 1] as usize;
            if i + 2 + len <= data.len() && len >= 2 && len <= 128 {
                if let Ok(s) = std::str::from_utf8(&data[i + 2..i + 2 + len]) {
                    if s.contains('.') { return Some(s.to_string()); }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    fn build_krb(tag: u8, include_realm: bool) -> Vec<u8> {
        // Build minimal AS-REQ structure:
        // [APPLICATION n] SEQUENCE { INTEGER 5, INTEGER 4, ... }
        let mut inner = vec![
            0x02, 0x01, 0x05, // INTEGER 5
            0x02, 0x01, 0x04, // INTEGER 4
        ];
        if include_realm {
            inner.push(0x04); // OCTET STRING
            inner.push(11);
            inner.extend_from_slice(b"EXAMPLE.COM");
        }
        let mut seq = vec![0x30, inner.len() as u8]; // SEQUENCE
        seq.extend_from_slice(&inner);
        let mut p = vec![tag, seq.len() as u8];
        p.extend_from_slice(&seq);
        p
    }
    #[test] fn test_as_req() { let m=parse_kerberos(&build_krb(TAG_AS_REQ,false)).unwrap(); assert_eq!(m.msg_type,10); }
    #[test] fn test_as_rep() { let m=parse_kerberos(&build_krb(TAG_AS_REP,false)).unwrap(); assert_eq!(m.msg_type,11); }
    #[test] fn test_tgs_req() { let m=parse_kerberos(&build_krb(TAG_TGS_REQ,false)).unwrap(); assert_eq!(m.msg_type,12); }
    #[test] fn test_invalid_tag() { assert!(parse_kerberos(&[0x00;10]).is_none()); }
    #[test] fn test_too_short() { assert!(parse_kerberos(&[0u8;9]).is_none()); }
    #[test] fn test_realm_extraction() { let m=parse_kerberos(&build_krb(TAG_AS_REQ,true)).unwrap(); assert_eq!(m.realm,Some("EXAMPLE.COM".to_string())); }
}
