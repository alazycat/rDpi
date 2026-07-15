use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser;

pub struct H323Detector { _private: () }
impl H323Detector { pub fn new() -> Self { Self { _private: () } } }
impl Default for H323Detector { fn default() -> Self { Self::new() } }
impl ProtocolDetector for H323Detector {
    fn name(&self) -> &'static str { "h323" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p).then(|| DetectionResult::new(Protocol::H323).with_confidence(Confidence::Dpi))
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_hit() { let d=H323Detector::new(); assert!(d.detect(&parser::valid_sample()).is_some()); }
    #[test] fn test_empty() { let d=H323Detector::new(); assert!(d.detect(b"").is_none()); }
}
