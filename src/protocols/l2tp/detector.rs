use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser;

pub struct L2tpDetector { _private: () }
impl L2tpDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for L2tpDetector { fn default() -> Self { Self::new() } }
impl ProtocolDetector for L2tpDetector {
    fn name(&self) -> &'static str { "l2tp" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p).then(|| DetectionResult::new(Protocol::L2tp).with_confidence(Confidence::Dpi))
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_hit() { let d=L2tpDetector::new(); assert!(d.detect(&parser::valid_sample()).is_some()); }
    #[test] fn test_empty() { let d=L2tpDetector::new(); assert!(d.detect(b"").is_none()); }
}
