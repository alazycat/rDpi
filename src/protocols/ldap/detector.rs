use crate::core::types::*;
use crate::protocols::ProtocolDetector;
use super::parser::is_ldap_bind;

pub struct LdapDetector { _private: () }
impl LdapDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for LdapDetector { fn default() -> Self { Self::new() } }

impl ProtocolDetector for LdapDetector {
    fn name(&self) -> &'static str { "ldap" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        if is_ldap_bind(p) { Some(DetectionResult::new(Protocol::Ldap).with_confidence(Confidence::Dpi)) } else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn msg() -> Vec<u8> { vec![0x30, 0x05, 0x60, 0x03, 0x02, 0x01, 0x03] }
    #[test] fn test_hit() { let d=LdapDetector::new(); assert_eq!(d.detect(&msg()).unwrap().protocol, Protocol::Ldap); }
    #[test] fn test_reject() { let d=LdapDetector::new(); assert!(d.detect(b"HTTP").is_none()); }
    #[test] fn test_empty() { let d=LdapDetector::new(); assert!(d.detect(b"").is_none()); }
}
