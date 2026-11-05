use super::parser;
use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;

pub struct H323Detector {
    _private: (),
}
impl H323Detector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}
impl Default for H323Detector {
    fn default() -> Self {
        Self::new()
    }
}
impl ProtocolDetector for H323Detector {
    fn name(&self) -> &'static str {
        "h323"
    }

    /// 首字节门：TPKT(0x03) 或裸 Q.931(0x08)
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x03u8, 0x03u8), (0x08u8, 0x08u8)])
    }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p)
            .then(|| DetectionResult::new(Protocol::H323).with_confidence(Confidence::Dpi))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hit() {
        let d = H323Detector::new();
        assert!(d.detect(&parser::valid_sample()).is_some());
    }
    #[test]
    fn test_empty() {
        let d = H323Detector::new();
        assert!(d.detect(b"").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = H323Detector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = parser::valid_sample();
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
