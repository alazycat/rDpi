//! FTP protocol detector for rDpi
//!
//! Detects FTP traffic by recognising server responses (three-digit code)
//! and client commands (known FTP verbs).

use crate::core::types::*;
use crate::protocols::ProtocolDetector;

use super::parser::{
    is_ftp_command_prefix, is_ftp_response_prefix, parse_ftp_command, parse_ftp_response,
};

/// FTP protocol detector
pub struct FtpDetector;

impl Default for FtpDetector {
    fn default() -> Self {
        Self
    }
}

impl FtpDetector {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolDetector for FtpDetector {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if payload.is_empty() {
            return None;
        }

        let first = payload[0];

        // Path 1: Server response — starts with digit + space separator
        if first.is_ascii_digit() && is_ftp_response_prefix(payload) {
            if let Some(resp) = parse_ftp_response(payload) {
                let meta = Metadata::Ftp(FtpMetadata {
                    is_client: false,
                    verb: None,
                    argument: None,
                    response_code: Some(resp.code),
                });
                return Some(
                    DetectionResult::new(Protocol::Ftp).with_metadata(meta),
                );
            }
        }

        // Path 2: Client command — uppercase letter prefix
        if (b'A'..=b'Z').contains(&first) && is_ftp_command_prefix(payload) {
            if let Some(cmd) = parse_ftp_command(payload) {
                let meta = Metadata::Ftp(FtpMetadata {
                    is_client: true,
                    verb: Some(cmd.verb),
                    argument: cmd.argument,
                    response_code: None,
                });
                return Some(
                    DetectionResult::new(Protocol::Ftp).with_metadata(meta),
                );
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ftp_banner() {
        let detector = FtpDetector::new();
        let result = detector.detect(b"220 FTP server ready\r\n").unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
    }

    #[test]
    fn test_detect_ftp_command() {
        let detector = FtpDetector::new();
        let result = detector.detect(b"USER anonymous\r\n").unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
    }

    #[test]
    fn test_detect_ftp_empty() {
        let detector = FtpDetector::new();
        assert!(detector.detect(b"").is_none());
    }

    #[test]
    fn test_detect_ftp_non_ftp() {
        let detector = FtpDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn test_detect_ftp_response_with_metadata() {
        let detector = FtpDetector::new();
        let result = detector.detect(b"331 Password required for user\r\n").unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
        if let Metadata::Ftp(ref meta) = result.metadata {
            assert!(!meta.is_client);
            assert_eq!(meta.response_code, Some(331));
        } else {
            panic!("expected Ftp metadata");
        }
    }

    #[test]
    fn test_detect_ftp_command_with_metadata() {
        let detector = FtpDetector::new();
        let result = detector.detect(b"RETR report.pdf\r\n").unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
        if let Metadata::Ftp(ref meta) = result.metadata {
            assert!(meta.is_client);
            assert_eq!(meta.verb, Some("RETR".to_string()));
            assert_eq!(meta.argument, Some("report.pdf".to_string()));
        } else {
            panic!("expected Ftp metadata");
        }
    }
}
