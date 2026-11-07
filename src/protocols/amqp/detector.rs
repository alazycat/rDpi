//! AMQP protocol detector for rDpi

use crate::core::types::{AmqpMetadata, Confidence, DetectionResult, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_amqp;

/// AMQP protocol detector
pub struct AmqpDetector {
    _private: (),
}

impl AmqpDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for AmqpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for AmqpDetector {
    fn name(&self) -> &'static str {
        "amqp"
    }

    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x00, 0x03), (0x41, 0x41)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_amqp(payload)?;
        Some(
            DetectionResult::new(Protocol::Amqp)
                .with_metadata(Metadata::Amqp(AmqpMetadata {
                    version: parsed.version.to_string(),
                    frame_type: parsed.frame_type,
                    channel: parsed.channel,
                    class_id: parsed.class_id,
                    method: parsed.method,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method_frame() -> [u8; 12] {
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0A, 0x00, 0x0A, 0xCE,
        ]
    }

    #[test]
    fn test_detect_method_frame() {
        let detector = AmqpDetector::new();
        let result = detector.detect(&method_frame()).unwrap();
        assert_eq!(result.protocol, Protocol::Amqp);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Amqp(meta) => {
                assert_eq!(meta.version, "0-9-1");
                assert_eq!(meta.frame_type, Some(1));
                assert_eq!(meta.channel, Some(0));
                assert_eq!(meta.class_id, Some(10));
                assert_eq!(meta.method, Some(10));
            }
            _ => panic!("expected AMQP metadata"),
        }
    }

    #[test]
    fn test_detect_amqp_10_header() {
        let detector = AmqpDetector::new();
        let result = detector.detect(b"AMQP\x00\x01\x00\x00").unwrap();
        assert_eq!(result.protocol, Protocol::Amqp);
        match result.metadata {
            Metadata::Amqp(meta) => {
                assert_eq!(meta.version, "1.0");
                assert_eq!(meta.frame_type, None);
            }
            _ => panic!("expected AMQP metadata"),
        }
    }

    #[test]
    fn test_detect_rejects_garbage() {
        let detector = AmqpDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
        assert!(detector.detect(&[0x05; 12]).is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_samples() {
        let detector = AmqpDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        for sample in [&method_frame()[..], &b"AMQP\x00\x00\x09\x01"[..]] {
            assert!(
                gate.iter()
                    .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
                "门区间不覆盖合法样本首字节 0x{:02X}",
                sample[0]
            );
        }
    }
}
