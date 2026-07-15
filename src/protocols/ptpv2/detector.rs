use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser;

pub struct Ptpv2Detector { _private: () }
impl Ptpv2Detector { pub fn new() -> Self { Self { _private: () } } }
impl Default for Ptpv2Detector { fn default() -> Self { Self::new() } }

impl ProtocolDetector for Ptpv2Detector {
    fn name(&self) -> &'static str { "ptpv2" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p).then(|| DetectionResult::new(Protocol::Ptpv2).with_confidence(Confidence::Dpi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Vec<u8> { parser::valid_sample() }
    #[test] fn test_hit() { let d=Ptpv2Detector::new(); assert!(d.detect(&valid()).is_some()); }
    #[test] fn test_empty() { let d=Ptpv2Detector::new(); assert!(d.detect(b"").is_none()); }
}
