use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser;

pub struct VxlanDetector { _private: () }
impl VxlanDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for VxlanDetector { fn default() -> Self { Self::new() } }
impl ProtocolDetector for VxlanDetector {
    fn name(&self) -> &'static str { "vxlan" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p).then(|| DetectionResult::new(Protocol::Vxlan).with_confidence(Confidence::Dpi))
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_hit() { let d=VxlanDetector::new(); assert!(d.detect(&parser::valid_sample()).is_some()); }
    #[test] fn test_empty() { let d=VxlanDetector::new(); assert!(d.detect(b"").is_none()); }
}
