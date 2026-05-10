//! POP3 protocol detector for rDpi

use crate::core::types::{DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::{is_pop3_command_prefix, is_pop3_response_prefix, parse_pop3_command, parse_pop3_response};

/// POP3 protocol detector
pub struct Pop3Detector {
    _private: (),
}

impl Pop3Detector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for Pop3Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for Pop3Detector {
    fn name(&self) -> &'static str {
        "pop3"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if payload.is_empty() {
            return None;
        }

        let first_byte = payload[0];

        // Path 1: Server response
        if is_pop3_response_prefix(first_byte) {
            if parse_pop3_response(payload).is_some() {
                return Some(DetectionResult::new(Protocol::Pop3));
            }
        }

        // Path 2: Client command
        if is_pop3_command_prefix(first_byte) {
            if parse_pop3_command(payload).is_some() {
                return Some(DetectionResult::new(Protocol::Pop3));
            }
        }

        None
    }

    fn detect_with_context(&self, payload: &[u8], ctx: &crate::core::types::DetectContext) -> Option<DetectionResult> {
        // Check for POP3S (port 995)
        if ctx.src_port == 995 || ctx.dst_port == 995 {
            return Some(DetectionResult::new(Protocol::Pop3s));
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
    fn test_pop3_detector_new() {
        let detector = Pop3Detector::new();
        assert_eq!(detector.name(), "pop3");
    }

    #[test]
    fn test_detect_pop3_ok_response() {
        let detector = Pop3Detector::new();
        let data = b"+OK POP3 server ready\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Pop3);
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn test_detect_pop3_err_response() {
        let detector = Pop3Detector::new();
        let data = b"-ERR Authentication failed\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Pop3);
    }

    #[test]
    fn test_detect_pop3_user_command() {
        let detector = Pop3Detector::new();
        let data = b"USER test@example.com\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Pop3);
    }

    #[test]
    fn test_detect_pop3_quit_command() {
        let detector = Pop3Detector::new();
        let data = b"QUIT\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Pop3);
    }

    #[test]
    fn test_detect_pop3_empty() {
        let detector = Pop3Detector::new();
        assert!(detector.detect(b"").is_none());
    }

    #[test]
    fn test_detect_pop3_invalid() {
        let detector = Pop3Detector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
        assert!(detector.detect(b"random data\r\n").is_none());
    }

    #[test]
    fn test_detect_pop3s_port() {
        let detector = Pop3Detector::new();
        let ctx = DetectContext {
            src_port: 12345,
            dst_port: 995,
            is_http3_port: false,
        };
        // Even with empty payload, port 995 should return Pop3s
        let result = detector.detect_with_context(b"", &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Pop3s);
    }

    #[test]
    fn test_detect_pop3s_port_src() {
        let detector = Pop3Detector::new();
        let ctx = DetectContext {
            src_port: 995,
            dst_port: 12345,
            is_http3_port: false,
        };
        let result = detector.detect_with_context(b"", &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Pop3s);
    }
}