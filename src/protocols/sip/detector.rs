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
            return Some(
                DetectionResult::new(Protocol::Sip).with_metadata(Metadata::Sip(meta)),
            );
        }

        // 尝试解析状态行
        if let Some(resp) = parse_sip_response(payload) {
            let meta = SipMetadata {
                is_request: false,
                method: None,
                status_code: Some(resp.status_code),
                user_agent: None,
            };
            return Some(
                DetectionResult::new(Protocol::Sip).with_metadata(Metadata::Sip(meta)),
            );
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
        assert!(detector.detect(b"GET / HTTP/1.1\r\nHost: example.com\r\n").is_none());
    }
}
