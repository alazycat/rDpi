use super::parser;
use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;

pub struct NetflowDetector {
    _private: (),
}
impl NetflowDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}
impl Default for NetflowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for NetflowDetector {
    fn name(&self) -> &'static str {
        "netflow"
    }

    /// 首字节门：版本号高字节恒 0
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x00u8, 0x00u8)])
    }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p)
            .then(|| DetectionResult::new(Protocol::Netflow).with_confidence(Confidence::Dpi))
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
        let d = NetflowDetector::new();
        assert!(d.detect(&valid()).is_some());
    }
    #[test]
    fn test_empty() {
        let d = NetflowDetector::new();
        assert!(d.detect(b"").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = NetflowDetector::new();
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
