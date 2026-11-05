use super::parser;
use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;

pub struct Ptpv2Detector {
    _private: (),
}
impl Ptpv2Detector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}
impl Default for Ptpv2Detector {
    fn default() -> Self {
        Self::new()
    }
}

/// 首字节门：messageType 低半位 ∈ {0x0-0x3, 0x8-0xD}，transportSpecific 高半位任意
const PTPV2_FIRST_BYTE_GATE: [(u8, u8); 32] = [
    (0x00, 0x03),
    (0x08, 0x0D),
    (0x10, 0x13),
    (0x18, 0x1D),
    (0x20, 0x23),
    (0x28, 0x2D),
    (0x30, 0x33),
    (0x38, 0x3D),
    (0x40, 0x43),
    (0x48, 0x4D),
    (0x50, 0x53),
    (0x58, 0x5D),
    (0x60, 0x63),
    (0x68, 0x6D),
    (0x70, 0x73),
    (0x78, 0x7D),
    (0x80, 0x83),
    (0x88, 0x8D),
    (0x90, 0x93),
    (0x98, 0x9D),
    (0xA0, 0xA3),
    (0xA8, 0xAD),
    (0xB0, 0xB3),
    (0xB8, 0xBD),
    (0xC0, 0xC3),
    (0xC8, 0xCD),
    (0xD0, 0xD3),
    (0xD8, 0xDD),
    (0xE0, 0xE3),
    (0xE8, 0xED),
    (0xF0, 0xF3),
    (0xF8, 0xFD),
];

impl ProtocolDetector for Ptpv2Detector {
    fn name(&self) -> &'static str {
        "ptpv2"
    }

    /// 首字节门：messageType 低半位 ∈ {0x0-0x3, 0x8-0xD}
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&PTPV2_FIRST_BYTE_GATE)
    }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p)
            .then(|| DetectionResult::new(Protocol::Ptpv2).with_confidence(Confidence::Dpi))
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
        let d = Ptpv2Detector::new();
        assert!(d.detect(&valid()).is_some());
    }
    #[test]
    fn test_empty() {
        let d = Ptpv2Detector::new();
        assert!(d.detect(b"").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = Ptpv2Detector::new();
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
