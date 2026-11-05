use super::parser;
use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;

pub struct SocksDetector {
    _private: (),
}
impl SocksDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}
impl Default for SocksDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for SocksDetector {
    fn name(&self) -> &'static str {
        "socks"
    }

    /// 首字节门：VER ∈ {4, 5}
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x04u8, 0x05u8)])
    }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p)
            .then(|| DetectionResult::new(Protocol::Socks).with_confidence(Confidence::Dpi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Vec<u8> {
        parser::valid_sample()
    }
    #[test]
    fn test_hit() {
        let d = SocksDetector::new();
        assert!(d.detect(&valid()).is_some());
    }
    #[test]
    fn test_empty() {
        let d = SocksDetector::new();
        assert!(d.detect(b"").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = SocksDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = valid();
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
