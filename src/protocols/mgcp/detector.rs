use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser;

pub struct MgcpDetector { _private: () }
impl MgcpDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for MgcpDetector { fn default() -> Self { Self::new() } }
impl ProtocolDetector for MgcpDetector {
    fn name(&self) -> &'static str { "mgcp" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p).then(|| DetectionResult::new(Protocol::Mgcp).with_confidence(Confidence::Dpi))
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_hit() { let d=MgcpDetector::new(); assert!(d.detect(&parser::valid_sample()).is_some()); }
    #[test] fn test_empty() { let d=MgcpDetector::new(); assert!(d.detect(b"").is_none()); }
}
