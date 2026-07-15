use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser;

pub struct TurnDetector { _private: () }
impl TurnDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for TurnDetector { fn default() -> Self { Self::new() } }
impl ProtocolDetector for TurnDetector {
    fn name(&self) -> &'static str { "turn" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p).then(|| DetectionResult::new(Protocol::Turn).with_confidence(Confidence::Dpi))
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_hit() { let d=TurnDetector::new(); assert!(d.detect(&parser::valid_sample()).is_some()); }
    #[test] fn test_empty() { let d=TurnDetector::new(); assert!(d.detect(b"").is_none()); }
}
