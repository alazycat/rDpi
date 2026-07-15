use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser;

pub struct Dhcpv6Detector { _private: () }
impl Dhcpv6Detector { pub fn new() -> Self { Self { _private: () } } }
impl Default for Dhcpv6Detector { fn default() -> Self { Self::new() } }
impl ProtocolDetector for Dhcpv6Detector {
    fn name(&self) -> &'static str { "dhcpv6" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p).then(|| DetectionResult::new(Protocol::Dhcpv6).with_confidence(Confidence::Dpi))
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_hit() { let d=Dhcpv6Detector::new(); assert!(d.detect(&parser::valid_sample()).is_some()); }
    #[test] fn test_empty() { let d=Dhcpv6Detector::new(); assert!(d.detect(b"").is_none()); }
}
