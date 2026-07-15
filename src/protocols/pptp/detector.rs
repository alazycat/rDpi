use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser;

pub struct PptpDetector { _private: () }
impl PptpDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for PptpDetector { fn default() -> Self { Self::new() } }
impl ProtocolDetector for PptpDetector {
    fn name(&self) -> &'static str { "pptp" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p).then(|| DetectionResult::new(Protocol::Pptp).with_confidence(Confidence::Dpi))
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_hit() { let d=PptpDetector::new(); assert!(d.detect(&parser::valid_sample()).is_some()); }
    #[test] fn test_empty() { let d=PptpDetector::new(); assert!(d.detect(b"").is_none()); }
}
