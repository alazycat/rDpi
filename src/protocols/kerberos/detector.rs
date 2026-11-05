use super::parser::parse_kerberos;
use crate::core::types::*;
use crate::protocols::ProtocolDetector;

pub struct KerberosDetector {
    _private: (),
}
impl KerberosDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}
impl Default for KerberosDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for KerberosDetector {
    fn name(&self) -> &'static str {
        "kerberos"
    }

    /// 首字节门：Kerberos ASN.1 APPLICATION 标签（0x6A-0x6D）。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x6Au8, 0x6Du8)])
    }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        let meta = parse_kerberos(p)?;
        Some(
            DetectionResult::new(Protocol::Kerberos)
                .with_metadata(Metadata::Kerberos(meta))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn msg() -> Vec<u8> {
        vec![0x6a, 0x08, 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x04]
    }
    #[test]
    fn test_hit() {
        let d = KerberosDetector::new();
        assert_eq!(d.detect(&msg()).unwrap().protocol, Protocol::Kerberos);
    }
    #[test]
    fn test_reject() {
        let d = KerberosDetector::new();
        assert!(d.detect(b"HTTP").is_none());
    }
    #[test]
    fn test_empty() {
        let d = KerberosDetector::new();
        assert!(d.detect(b"").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = KerberosDetector::new();
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
