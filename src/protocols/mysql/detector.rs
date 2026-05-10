//! MySQL protocol detector for rDpi

use crate::core::types::{DetectionResult, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_mysql_handshake;

/// MySQL protocol detector
pub struct MysqlDetector {
    _private: (),
}

impl MysqlDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for MysqlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for MysqlDetector {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if let Some(metadata) = parse_mysql_handshake(payload) {
            return Some(
                DetectionResult::new(Protocol::Mysql)
                    .with_metadata(Metadata::Mysql(metadata))
                    .with_confidence(1.0),
            );
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_handshake_packet(version: &str, auth_plugin: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0x0a);
        packet.extend_from_slice(version.as_bytes());
        packet.push(0x00);
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        packet.push(0x00);
        packet.extend_from_slice(&[0xff, 0xf7]);
        packet.push(0x21);
        packet.extend_from_slice(&[0x02, 0x00]);
        packet.extend_from_slice(&[0xff, 0x81]);
        packet.push(0x15);
        packet.extend_from_slice(&[0x00; 10]);
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
        packet.extend_from_slice(auth_plugin.as_bytes());
        packet.push(0x00);
        packet
    }

    #[test]
    fn test_mysql_detector_handshake() {
        let detector = MysqlDetector::new();
        let packet = create_handshake_packet("8.0.33", "mysql_native_password");
        let result = detector.detect(&packet).unwrap();

        assert_eq!(result.protocol, Protocol::Mysql);
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn test_mysql_detector_empty() {
        let detector = MysqlDetector::new();
        assert!(detector.detect(&[]).is_none());
    }

    #[test]
    fn test_mysql_detector_invalid() {
        let detector = MysqlDetector::new();
        // Not a MySQL packet
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
        assert!(detector.detect(b"220 OK\r\n").is_none());
    }
}
