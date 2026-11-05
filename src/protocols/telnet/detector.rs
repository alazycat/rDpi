use super::parser;
use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;

pub struct TelnetDetector {
    _private: (),
}
impl TelnetDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}
impl Default for TelnetDetector {
    fn default() -> Self {
        Self::new()
    }
}
impl ProtocolDetector for TelnetDetector {
    fn name(&self) -> &'static str {
        "telnet"
    }

    /// 首字节门：IAC（0xFF）
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0xFFu8, 0xFFu8)])
    }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p)
            .then(|| DetectionResult::new(Protocol::Telnet).with_confidence(Confidence::Dpi))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hit() {
        let d = TelnetDetector::new();
        assert!(d.detect(&parser::valid_sample()).is_some());
    }
    #[test]
    fn test_empty() {
        let d = TelnetDetector::new();
        assert!(d.detect(b"").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = TelnetDetector::new();
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
