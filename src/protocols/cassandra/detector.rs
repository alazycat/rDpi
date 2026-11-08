//! Apache Cassandra CQL protocol detector for rDpi

use crate::core::types::{
    CassandraMetadata, CassandraSource, Confidence, DetectionResult, Metadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::{CassandraParsed, parse_cassandra};

/// Apache Cassandra protocol detector
pub struct CassandraDetector {
    _private: (),
}

impl CassandraDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for CassandraDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for CassandraDetector {
    fn name(&self) -> &'static str {
        "cassandra"
    }

    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x02, 0x05), (0xCA, 0xCA)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_cassandra(payload)?;
        let metadata = match parsed {
            CassandraParsed::Internode => CassandraMetadata {
                source: CassandraSource::Internode,
                ..Default::default()
            },
            CassandraParsed::Cql(startup) => CassandraMetadata {
                source: CassandraSource::Cql,
                version: Some(startup.version),
                stream_id: Some(startup.stream_id),
                opcode: Some(startup.opcode),
                cql_version: Some(startup.cql_version),
            },
        };
        Some(
            DetectionResult::new(Protocol::Cassandra)
                .with_metadata(Metadata::Cassandra(metadata))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn internode() -> Vec<u8> {
        let mut payload = vec![0xCA, 0x55, 0x2D, 0xFA];
        payload.extend_from_slice(&[0u8; 15]);
        payload
    }

    fn startup(cql_version: &str) -> Vec<u8> {
        let key = b"CQL_VERSION";
        let value = cql_version.as_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&(key.len() as u16).to_be_bytes());
        body.extend_from_slice(key);
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value);
        let mut frame = vec![0x04, 0x00, 0x00, 0x01, 0x01];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn test_detect_internode() {
        let detector = CassandraDetector::new();
        let result = detector.detect(&internode()).unwrap();
        assert_eq!(result.protocol, Protocol::Cassandra);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Cassandra(meta) => {
                assert_eq!(meta.source, CassandraSource::Internode);
                assert_eq!(meta.version, None);
                assert_eq!(meta.cql_version, None);
            }
            _ => panic!("expected Cassandra metadata"),
        }
    }

    #[test]
    fn test_detect_startup() {
        let detector = CassandraDetector::new();
        let result = detector.detect(&startup("3.0.0")).unwrap();
        match result.metadata {
            Metadata::Cassandra(meta) => {
                assert_eq!(meta.source, CassandraSource::Cql);
                assert_eq!(meta.version, Some(0x04));
                assert_eq!(meta.stream_id, Some(1));
                assert_eq!(meta.opcode, Some(0x01));
                assert_eq!(meta.cql_version.as_deref(), Some("3.0.0"));
            }
            _ => panic!("expected Cassandra metadata"),
        }
    }

    #[test]
    fn test_reject_http() {
        let detector = CassandraDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_samples() {
        let detector = CassandraDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let samples = [internode(), startup("3.0.0")];
        for payload in &samples {
            assert!(
                gate.iter()
                    .any(|&(lo, hi)| payload[0] >= lo && payload[0] <= hi),
                "门区间不覆盖合法样本首字节 0x{:02X}",
                payload[0]
            );
        }
        for byte in [0u8, 0x01, 0x06, 0x80, 0xCB] {
            assert!(!gate.iter().any(|&(lo, hi)| byte >= lo && byte <= hi));
        }
    }
}
