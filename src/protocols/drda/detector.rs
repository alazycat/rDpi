//! DRDA protocol detector for rDpi

use crate::core::types::{Confidence, DetectionResult, DrdaMetadata, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_drda;

/// DRDA protocol detector
pub struct DrdaDetector {
    _private: (),
}

impl DrdaDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for DrdaDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for DrdaDetector {
    fn name(&self) -> &'static str {
        "drda"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_drda(payload)?;
        Some(
            DetectionResult::new(Protocol::Drda)
                .with_metadata(Metadata::Drda(DrdaMetadata {
                    message_count: parsed.message_count,
                    message_length: parsed.message_length,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&16u16.to_be_bytes());
        message.push(0xD0);
        message.push(0x41);
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&10u16.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&[0u8; 6]);
        message
    }

    #[test]
    fn test_detect_single_message() {
        let detector = DrdaDetector::new();
        let result = detector.detect(&message()).unwrap();
        assert_eq!(result.protocol, Protocol::Drda);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Drda(meta) => {
                assert_eq!(meta.message_count, 1);
                assert_eq!(meta.message_length, 16);
            }
            _ => panic!("expected DRDA metadata"),
        }
    }

    #[test]
    fn test_reject_http() {
        let detector = DrdaDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_first_byte_gate_is_none() {
        let detector = DrdaDetector::new();
        assert!(detector.first_byte_gate().is_none());
    }
}
