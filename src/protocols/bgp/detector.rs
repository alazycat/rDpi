use super::parser::parse_bgp;
use crate::core::types::*;
use crate::protocols::ProtocolDetector;

pub struct BgpDetector {
    _private: (),
}
impl BgpDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}
impl Default for BgpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for BgpDetector {
    fn name(&self) -> &'static str {
        "bgp"
    }

    /// 首字节门：BGP Marker 固定 0xFF。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0xFFu8, 0xFFu8)])
    }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        let _ = parse_bgp(p)?;
        Some(DetectionResult::new(Protocol::Bgp).with_confidence(Confidence::Dpi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn msg() -> Vec<u8> {
        let mut p = vec![0xff; 19];
        p[16..18].copy_from_slice(&[0x00, 0x13]);
        p[18] = 1;
        p
    }
    #[test]
    fn test_hit() {
        let d = BgpDetector::new();
        assert_eq!(d.detect(&msg()).unwrap().protocol, Protocol::Bgp);
    }
    #[test]
    fn test_reject() {
        let d = BgpDetector::new();
        assert!(d.detect(b"HTTP").is_none());
    }
    #[test]
    fn test_empty() {
        let d = BgpDetector::new();
        assert!(d.detect(b"").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = BgpDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = msg();
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
