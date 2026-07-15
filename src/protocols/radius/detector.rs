use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser;

pub struct RadiusDetector { _private: () }
impl RadiusDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for RadiusDetector { fn default() -> Self { Self::new() } }
impl ProtocolDetector for RadiusDetector {
    fn name(&self) -> &'static str { "radius" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p).then(|| DetectionResult::new(Protocol::Radius).with_confidence(Confidence::Dpi))
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_hit() { let d=RadiusDetector::new(); assert!(d.detect(&parser::valid_sample()).is_some()); }
    #[test] fn test_empty() { let d=RadiusDetector::new(); assert!(d.detect(b"").is_none()); }
}
