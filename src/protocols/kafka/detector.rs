//! Kafka protocol detector for rDpi

use crate::core::types::{Confidence, DetectionResult, KafkaMetadata, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_kafka_request;

/// Kafka protocol detector
pub struct KafkaDetector {
    _private: (),
}

impl KafkaDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for KafkaDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for KafkaDetector {
    fn name(&self) -> &'static str {
        "kafka"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_kafka_request(payload)?;
        Some(
            DetectionResult::new(Protocol::Kafka)
                .with_metadata(Metadata::Kafka(KafkaMetadata {
                    api_key: parsed.api_key,
                    api_version: parsed.api_version,
                    correlation_id: parsed.correlation_id,
                    client_id: parsed.client_id,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(api_key: u16, api_version: u16, correlation_id: u32, client_id: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&api_key.to_be_bytes());
        body.extend_from_slice(&api_version.to_be_bytes());
        body.extend_from_slice(&correlation_id.to_be_bytes());
        body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        body.extend_from_slice(client_id);
        let mut payload = (body.len() as u32).to_be_bytes().to_vec();
        payload.extend_from_slice(&body);
        payload
    }

    #[test]
    fn test_detect_request() {
        let detector = KafkaDetector::new();
        let payload = request(3, 1, 42, b"rdpi-test");
        let result = detector.detect(&payload).unwrap();
        assert_eq!(result.protocol, Protocol::Kafka);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Kafka(meta) => {
                assert_eq!(meta.api_key, 3);
                assert_eq!(meta.api_version, 1);
                assert_eq!(meta.correlation_id, 42);
                assert_eq!(meta.client_id, "rdpi-test");
            }
            _ => panic!("expected Kafka metadata"),
        }
    }

    #[test]
    fn test_reject_response_shape() {
        // 响应：长度前缀 + correlation id，无客户端 ID 段；12 < 14 应拒绝
        let detector = KafkaDetector::new();
        let payload = vec![0, 0, 0, 8, 0, 0, 0, 1];
        assert!(detector.detect(&payload).is_none());
    }

    #[test]
    fn test_reject_http() {
        let detector = KafkaDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_has_no_first_byte_gate() {
        let detector = KafkaDetector::new();
        assert!(detector.first_byte_gate().is_none());
    }
}
