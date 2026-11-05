use super::parser::is_ldap_bind;
use crate::core::types::*;
use crate::protocols::ProtocolDetector;

pub struct LdapDetector {
    _private: (),
}
impl LdapDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}
impl Default for LdapDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for LdapDetector {
    fn name(&self) -> &'static str {
        "ldap"
    }

    /// 首字节门：LDAP 消息为 ASN.1 SEQUENCE（0x30）。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x30u8, 0x30u8)])
    }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        if is_ldap_bind(p) {
            Some(DetectionResult::new(Protocol::Ldap).with_confidence(Confidence::Dpi))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn msg() -> Vec<u8> {
        // 误报面审计 2026-11-05：样本改为长度字段自洽的 BindRequest——外层
        // SEQUENCE len=0x0A=10（msgID 3 + BindRequest 7），内层 BindRequest
        // len=5（version 3 + 空 OCTET STRING 2）。
        vec![
            0x30, 0x0A, 0x02, 0x01, 0x01, 0x60, 0x05, 0x02, 0x01, 0x03, 0x04, 0x00,
        ]
    }
    #[test]
    fn test_hit() {
        let d = LdapDetector::new();
        assert_eq!(d.detect(&msg()).unwrap().protocol, Protocol::Ldap);
    }
    #[test]
    fn test_reject() {
        let d = LdapDetector::new();
        assert!(d.detect(b"HTTP").is_none());
    }
    #[test]
    fn test_empty() {
        let d = LdapDetector::new();
        assert!(d.detect(b"").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = LdapDetector::new();
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
