use super::parser;
use crate::core::types::{Confidence, DetectionResult, Dhcpv6Metadata, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

pub struct Dhcpv6Detector {
    _private: (),
}
impl Dhcpv6Detector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}
impl Default for Dhcpv6Detector {
    fn default() -> Self {
        Self::new()
    }
}
impl ProtocolDetector for Dhcpv6Detector {
    fn name(&self) -> &'static str {
        "dhcpv6"
    }

    /// 首字节门：报文类型 0x01-0x0D
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x01u8, 0x0Du8)])
    }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        // F37：识别语义不变（is_dhcpv6 结构校验，parse_dhcpv6_info 内部同门控），
        // 在此基础上提取 JA4D6 指纹填入 metadata
        let info = parser::parse_dhcpv6_info(p)?;
        let ja4d6 = crate::application::compute_ja4d6(
            info.msg_type,
            info.duid_len,
            info.has_iata,
            info.has_client_fqdn,
            &info.option_codes,
            &info.oro,
        );
        Some(
            DetectionResult::new(Protocol::Dhcpv6)
                .with_confidence(Confidence::Dpi)
                .with_metadata(Metadata::Dhcpv6(Dhcpv6Metadata {
                    msg_type: info.msg_type,
                    ja4d6,
                })),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hit() {
        let d = Dhcpv6Detector::new();
        assert!(d.detect(&parser::valid_sample()).is_some());
    }
    #[test]
    fn test_empty() {
        let d = Dhcpv6Detector::new();
        assert!(d.detect(b"").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = Dhcpv6Detector::new();
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
