//! SMTP protocol detector for rDpi

use crate::core::types::{DetectionResult, Metadata, Protocol, SmtpMetadata};
use crate::protocols::ProtocolDetector;

use super::parser::{
    is_smtp_command_prefix, is_smtp_response_prefix, parse_smtp_command, parse_smtp_response,
};

/// SMTP protocol detector
pub struct SmtpDetector {
    _private: (),
}

impl SmtpDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for SmtpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for SmtpDetector {
    fn name(&self) -> &'static str {
        "smtp"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if payload.is_empty() {
            return None;
        }

        let first_byte = payload[0];

        // Path 1: Server response
        if is_smtp_response_prefix(first_byte) {
            if let Some(resp) = parse_smtp_response(payload) {
                let hostname = extract_hostname_from_banner(&resp.message);
                let metadata = Metadata::Smtp(SmtpMetadata {
                    hostname,
                    is_client: false,
                });

                return Some(
                    DetectionResult::new(Protocol::Smtp)
                        .with_metadata(metadata)
                        .with_confidence(1.0),
                );
            }
        }

        // Path 2: Client command
        if is_smtp_command_prefix(first_byte) {
            if let Some(cmd) = parse_smtp_command(payload) {
                let hostname = extract_hostname_from_command(&cmd);
                let metadata = Metadata::Smtp(SmtpMetadata {
                    hostname,
                    is_client: true,
                });

                return Some(
                    DetectionResult::new(Protocol::Smtp)
                        .with_metadata(metadata)
                        .with_confidence(1.0),
                );
            }
        }

        None
    }
}

/// Extract hostname from SMTP banner message
fn extract_hostname_from_banner(message: &str) -> Option<String> {
    // Banner format: "hostname ESMTP ..."
    // Take the first word
    message.split_whitespace().next().map(|s| s.to_string())
}

/// Extract hostname from SMTP command
fn extract_hostname_from_command(cmd: &super::parser::SmtpCommand) -> Option<String> {
    match cmd.command.as_str() {
        "EHLO" | "HELO" => cmd.argument.clone(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_detector_new() {
        let detector = SmtpDetector::new();
        assert_eq!(detector.name(), "smtp");
    }

    #[test]
    fn test_detect_smtp_banner() {
        let detector = SmtpDetector::new();
        let data = b"220 mail.example.com ESMTP Postfix\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Smtp);
        assert_eq!(result.confidence, 1.0);

        if let Metadata::Smtp(meta) = result.metadata {
            assert_eq!(meta.hostname, Some("mail.example.com".to_string()));
            assert!(!meta.is_client);
        } else {
            panic!("Expected Smtp metadata");
        }
    }

    #[test]
    fn test_detect_smtp_ehlo() {
        let detector = SmtpDetector::new();
        let data = b"EHLO client.example.com\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Smtp);

        if let Metadata::Smtp(meta) = result.metadata {
            assert_eq!(meta.hostname, Some("client.example.com".to_string()));
            assert!(meta.is_client);
        } else {
            panic!("Expected Smtp metadata");
        }
    }

    #[test]
    fn test_detect_smtp_quit() {
        let detector = SmtpDetector::new();
        let data = b"QUIT\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Smtp);

        if let Metadata::Smtp(meta) = result.metadata {
            assert!(meta.hostname.is_none()); // QUIT has no hostname
            assert!(meta.is_client);
        } else {
            panic!("Expected Smtp metadata");
        }
    }

    #[test]
    fn test_detect_smtp_empty() {
        let detector = SmtpDetector::new();
        assert!(detector.detect(b"").is_none());
    }

    #[test]
    fn test_detect_smtp_invalid() {
        let detector = SmtpDetector::new();
        // Not an SMTP response or command
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
        assert!(detector.detect(b"random data\r\n").is_none());
    }

    #[test]
    fn test_extract_hostname_from_banner() {
        assert_eq!(
            extract_hostname_from_banner("mail.example.com ESMTP"),
            Some("mail.example.com".to_string())
        );
        assert_eq!(
            extract_hostname_from_banner("smtp.google.com ESMTP Google"),
            Some("smtp.google.com".to_string())
        );
        assert_eq!(extract_hostname_from_banner(""), None);
    }

    #[test]
    fn test_extract_hostname_from_command() {
        let ehlo_cmd = super::super::parser::SmtpCommand {
            command: "EHLO".to_string(),
            argument: Some("client.example.com".to_string()),
        };
        assert_eq!(
            extract_hostname_from_command(&ehlo_cmd),
            Some("client.example.com".to_string())
        );

        let mail_cmd = super::super::parser::SmtpCommand {
            command: "MAIL".to_string(),
            argument: Some("FROM:<test@example.com>".to_string()),
        };
        assert_eq!(extract_hostname_from_command(&mail_cmd), None);
    }
}