use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser;

pub struct IkeDetector { _private: () }
impl IkeDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for IkeDetector { fn default() -> Self { Self::new() } }

impl ProtocolDetector for IkeDetector {
    fn name(&self) -> &'static str { "ike" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p).then(|| DetectionResult::new(Protocol::Ike).with_confidence(Confidence::Dpi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Vec<u8> { parser::valid_sample() }
    #[test] fn test_hit() { let d=IkeDetector::new(); assert!(d.detect(&valid()).is_some()); }
    #[test] fn test_empty() { let d=IkeDetector::new(); assert!(d.detect(b"").is_none()); }
}
