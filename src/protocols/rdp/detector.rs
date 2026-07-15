use crate::core::types::*;
use crate::protocols::ProtocolDetector;
use super::parser::is_rdp_connect;

pub struct RdpDetector { _private: () }
impl RdpDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for RdpDetector { fn default() -> Self { Self::new() } }

impl ProtocolDetector for RdpDetector {
    fn name(&self) -> &'static str { "rdp" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        if is_rdp_connect(p) { Some(DetectionResult::new(Protocol::Rdp).with_confidence(Confidence::Dpi)) } else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn msg() -> Vec<u8> { let mut p = vec![0x03,0x00,0x00,0x13,0x0e,0xe0,0x00]; p.extend(vec![0u8;12]); p }
    #[test] fn test_hit() { let d=RdpDetector::new(); assert_eq!(d.detect(&msg()).unwrap().protocol, Protocol::Rdp); }
    #[test] fn test_reject() { let d=RdpDetector::new(); assert!(d.detect(b"HTTP").is_none()); }
    #[test] fn test_empty() { let d=RdpDetector::new(); assert!(d.detect(b"").is_none()); }
}
