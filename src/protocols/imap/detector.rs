//! IMAP protocol detector for rDpi

use crate::core::types::{DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::{is_imap_command_prefix, is_imap_response_prefix, parse_imap_command, parse_imap_response};

/// IMAP protocol detector
pub struct ImapDetector {
    _private: (),
}

impl ImapDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for ImapDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for ImapDetector {
    fn name(&self) -> &'static str {
        "imap"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if payload.is_empty() {
            return None;
        }

        let first_byte = payload[0];

        // Path 1: Server response (untagged or tagged)
        if is_imap_response_prefix(first_byte) {
            if parse_imap_response(payload).is_some() {
                return Some(DetectionResult::new(Protocol::Imap));
            }
        }

        // Path 2: Client command
        if is_imap_command_prefix(first_byte) {
            if parse_imap_command(payload).is_some() {
                return Some(DetectionResult::new(Protocol::Imap));
            }
        }

        None
    }

    fn detect_with_context(&self, payload: &[u8], ctx: &crate::core::types::DetectContext) -> Option<DetectionResult> {
        // Check for IMAPS (port 993)
        if ctx.src_port == 993 || ctx.dst_port == 993 {
            return Some(DetectionResult::new(Protocol::Imaps));
        }

        // Otherwise use standard payload detection
        self.detect(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::DetectContext;

    #[test]
    fn test_imap_detector_new() {
        let detector = ImapDetector::new();
        assert_eq!(detector.name(), "imap");
    }

    #[test]
    fn test_detect_imap_untagged_response() {
        let detector = ImapDetector::new();
        let data = b"* OK IMAP4rev1 Service Ready\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Imap);
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn test_detect_imap_tagged_response() {
        let detector = ImapDetector::new();
        let data = b"A001 OK LOGIN completed\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Imap);
    }

    #[test]
    fn test_detect_imap_login_command() {
        let detector = ImapDetector::new();
        let data = b"A001 LOGIN user password\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Imap);
    }

    #[test]
    fn test_detect_imap_select_command() {
        let detector = ImapDetector::new();
        let data = b"A002 SELECT INBOX\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Imap);
    }

    #[test]
    fn test_detect_imap_noop_command() {
        let detector = ImapDetector::new();
        let data = b"A003 NOOP\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Imap);
    }

    #[test]
    fn test_detect_imap_empty() {
        let detector = ImapDetector::new();
        assert!(detector.detect(b"").is_none());
    }

    #[test]
    fn test_detect_imap_invalid() {
        let detector = ImapDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
        assert!(detector.detect(b"random data\r\n").is_none());
    }

    #[test]
    fn test_detect_imaps_port() {
        let detector = ImapDetector::new();
        let ctx = DetectContext {
            src_port: 12345,
            dst_port: 993,
            is_http3_port: false,
        };
        let result = detector.detect_with_context(b"", &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Imaps);
    }

    #[test]
    fn test_detect_imaps_port_src() {
        let detector = ImapDetector::new();
        let ctx = DetectContext {
            src_port: 993,
            dst_port: 12345,
            is_http3_port: false,
        };
        let result = detector.detect_with_context(b"", &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Imaps);
    }
}
