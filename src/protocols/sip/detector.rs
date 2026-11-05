use crate::core::types::*;
use crate::protocols::ProtocolDetector;

use super::parser::{is_sip_message, parse_sip_request, parse_sip_response};

pub struct SipDetector;

impl Default for SipDetector {
    fn default() -> Self {
        Self
    }
}

impl SipDetector {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolDetector for SipDetector {
    fn name(&self) -> &'static str {
        "sip"
    }

    /// 首字节门：SIP 请求方法与响应行（SIP/）均以大写字母起始（0x41-0x5A）。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x41u8, 0x5Au8)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if payload.is_empty() {
            return None;
        }

        if !is_sip_message(payload) {
            return None;
        }

        // 尝试解析请求行
        if let Some(req) = parse_sip_request(payload) {
            let meta = SipMetadata {
                is_request: true,
                method: Some(req.method),
                status_code: None,
                user_agent: None,
            };
            return Some(DetectionResult::new(Protocol::Sip).with_metadata(Metadata::Sip(meta)));
        }

        // 尝试解析状态行
        if let Some(resp) = parse_sip_response(payload) {
            let meta = SipMetadata {
                is_request: false,
                method: None,
                status_code: Some(resp.status_code),
                user_agent: None,
            };
            return Some(DetectionResult::new(Protocol::Sip).with_metadata(Metadata::Sip(meta)));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_sip_invite() {
        let detector = SipDetector::new();
        let pkt = b"INVITE sip:user@domain.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nCSeq: 1 INVITE\r\n";
        let result = detector.detect(pkt).unwrap();
        assert_eq!(result.protocol, Protocol::Sip);
    }

    #[test]
    fn test_detect_sip_response() {
        let detector = SipDetector::new();
        let pkt = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nCSeq: 1 INVITE\r\n";
        let result = detector.detect(pkt).unwrap();
        assert_eq!(result.protocol, Protocol::Sip);
    }

    #[test]
    fn test_detect_sip_empty() {
        let detector = SipDetector::new();
        assert!(detector.detect(b"").is_none());
    }

    #[test]
    fn test_detect_sip_non_sip() {
        let detector = SipDetector::new();
        assert!(
            detector
                .detect(b"GET / HTTP/1.1\r\nHost: example.com\r\n")
                .is_none()
        );
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = SipDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = b"INVITE sip:user@domain.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nCSeq: 1 INVITE\r\n";
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
