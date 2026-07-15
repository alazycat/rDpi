use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser;

pub struct VncDetector { _private: () }
impl VncDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for VncDetector { fn default() -> Self { Self::new() } }
impl ProtocolDetector for VncDetector {
    fn name(&self) -> &'static str { "vnc" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p).then(|| DetectionResult::new(Protocol::Vnc).with_confidence(Confidence::Dpi))
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_hit() { let d=VncDetector::new(); assert!(d.detect(&parser::valid_sample()).is_some()); }
    #[test] fn test_empty() { let d=VncDetector::new(); assert!(d.detect(b"").is_none()); }
}
