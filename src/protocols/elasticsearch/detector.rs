//! Elasticsearch 二进制协议 detector

use crate::core::types::{
    Confidence, DetectionResult, ElasticsearchMetadata, ElasticsearchSource, Metadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::parse_elasticsearch;

/// Elasticsearch protocol detector
pub struct ElasticsearchDetector {
    _private: (),
}

impl ElasticsearchDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for ElasticsearchDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for ElasticsearchDetector {
    fn name(&self) -> &'static str {
        "elasticsearch"
    }

    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(b'E', b'E')])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let message_length = parse_elasticsearch(payload)?;
        Some(
            DetectionResult::new(Protocol::Elasticsearch)
                .with_metadata(Metadata::Elasticsearch(ElasticsearchMetadata {
                    message_length: Some(message_length),
                    source: ElasticsearchSource::Binary,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_binary() {
        let detector = ElasticsearchDetector::new();
        let result = detector.detect(b"ES\x00\x00\x00\x05hello").unwrap();
        assert_eq!(result.protocol, Protocol::Elasticsearch);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Elasticsearch(meta) => {
                assert_eq!(meta.message_length, Some(5));
                assert_eq!(meta.source, ElasticsearchSource::Binary);
            }
            _ => panic!("expected Elasticsearch metadata"),
        }
    }

    #[test]
    fn test_detect_rejects_non_es_payload() {
        let detector = ElasticsearchDetector::new();
        assert!(detector.detect(b"EX\x00\x00\x00\x00").is_none());
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        let detector = ElasticsearchDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = b"ES\x00\x00\x00\x00";
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
        assert!(!gate.iter().any(|&(lo, hi)| b'G' >= lo && b'G' <= hi));
    }
}
