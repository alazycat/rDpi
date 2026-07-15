//! PostgreSQL protocol detector for rDpi

use crate::core::types::{Confidence, DetectionResult, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_pg_startup;

/// PostgreSQL protocol detector
pub struct PostgresqlDetector {
    _private: (),
}

impl PostgresqlDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for PostgresqlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for PostgresqlDetector {
    fn name(&self) -> &'static str {
        "postgresql"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if let Some(metadata) = parse_pg_startup(payload) {
            return Some(
                DetectionResult::new(Protocol::Postgresql)
                    .with_metadata(Metadata::Postgresql(metadata))
                    .with_confidence(Confidence::Dpi),
            );
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_startup_message(user: &str, database: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Length placeholder
        msg.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // Protocol v3.0
        msg.extend_from_slice(b"user");
        msg.push(0x00);
        msg.extend_from_slice(user.as_bytes());
        msg.push(0x00);
        msg.extend_from_slice(b"database");
        msg.push(0x00);
        msg.extend_from_slice(database.as_bytes());
        msg.push(0x00);
        msg.push(0x00); // terminator
        let len = msg.len() as u32;
        msg[0..4].copy_from_slice(&len.to_be_bytes());
        msg
    }

    #[test]
    fn test_postgresql_detector_startup() {
        let detector = PostgresqlDetector::new();
        let msg = create_startup_message("postgres", "testdb");
        let result = detector.detect(&msg).unwrap();

        assert_eq!(result.protocol, Protocol::Postgresql);
        assert_eq!(result.confidence, Confidence::Dpi);
    }

    #[test]
    fn test_postgresql_detector_empty() {
        let detector = PostgresqlDetector::new();
        assert!(detector.detect(&[]).is_none());
    }

    #[test]
    fn test_postgresql_detector_invalid() {
        let detector = PostgresqlDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
        assert!(detector.detect(b"220 OK\r\n").is_none());
    }
}
