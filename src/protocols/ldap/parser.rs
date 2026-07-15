//! LDAP protocol parser — ASN.1 SEQUENCE + BindRequest detection

/// Check if payload appears to be an LDAP BindRequest
pub fn is_ldap_bind(data: &[u8]) -> bool {
    if data.len() < 6 { return false; }
    data[0] == 0x30 && data.contains(&0x60) // SEQUENCE + APPLICATION 0
}

#[cfg(test)]
mod tests {
    use super::*;
    fn build_ldap() -> Vec<u8> {
        let mut p = vec![0x30, 0x20]; // SEQUENCE
        p.push(0x02); p.push(0x01); p.push(0x01); // INTEGER msgID=1
        p.push(0x60); p.push(0x18); // APPLICATION 0 (BindRequest)
        p.push(0x02); p.push(0x01); p.push(0x03); // version=3
        p.push(0x04); p.push(0x04); // OCTET STRING "cn=admin"
        p.extend_from_slice(b"cn=admin");
        p
    }
    #[test] fn test_ldap_bind() { assert!(is_ldap_bind(&build_ldap())); }
    #[test] fn test_not_ldap() { assert!(!is_ldap_bind(b"GET / HTTP")); }
    #[test] fn test_too_short() { assert!(!is_ldap_bind(&[0x30])); }
}
