use crate::core::types::*;
use crate::protocols::ProtocolDetector;
use super::parser::parse_kerberos;

pub struct KerberosDetector { _private: () }
impl KerberosDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for KerberosDetector { fn default() -> Self { Self::new() } }

impl ProtocolDetector for KerberosDetector {
    fn name(&self) -> &'static str { "kerberos" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        let meta = parse_kerberos(p)?;
        Some(DetectionResult::new(Protocol::Kerberos).with_metadata(Metadata::Kerberos(meta)).with_confidence(Confidence::Dpi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn msg() -> Vec<u8> { vec![0x6a, 0x08, 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x04] }
    #[test] fn test_hit() { let d=KerberosDetector::new(); assert_eq!(d.detect(&msg()).unwrap().protocol, Protocol::Kerberos); }
    #[test] fn test_reject() { let d=KerberosDetector::new(); assert!(d.detect(b"HTTP").is_none()); }
    #[test] fn test_empty() { let d=KerberosDetector::new(); assert!(d.detect(b"").is_none()); }
}
