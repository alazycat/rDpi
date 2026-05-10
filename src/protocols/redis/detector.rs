//! Redis protocol detector for rDpi

use crate::core::types::{DetectionResult, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_redis_command;

/// Redis protocol detector
pub struct RedisDetector {
    _private: (),
}

impl RedisDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for RedisDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for RedisDetector {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if let Some(metadata) = parse_redis_command(payload) {
            return Some(
                DetectionResult::new(Protocol::Redis)
                    .with_metadata(Metadata::Redis(metadata))
                    .with_confidence(1.0),
            );
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_array_command(cmd: &str) -> Vec<u8> {
        let cmd_len = cmd.len();
        format!("*1\r\n${}\r\n{}\r\n", cmd_len, cmd).into_bytes()
    }

    #[test]
    fn test_redis_detector_get() {
        let detector = RedisDetector::new();
        let data = create_array_command("GET");
        let result = detector.detect(&data).unwrap();

        assert_eq!(result.protocol, Protocol::Redis);
        assert_eq!(result.confidence, 1.0);

        if let Metadata::Redis(meta) = result.metadata {
            assert_eq!(meta.command, Some("GET".to_string()));
        } else {
            panic!("Expected Redis metadata");
        }
    }

    #[test]
    fn test_redis_detector_set() {
        let detector = RedisDetector::new();
        let data = b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n";
        let result = detector.detect(data).unwrap();

        assert_eq!(result.protocol, Protocol::Redis);
    }

    #[test]
    fn test_redis_detector_ping() {
        let detector = RedisDetector::new();
        let data = b"+PING\r\n";
        let result = detector.detect(data).unwrap();

        assert_eq!(result.protocol, Protocol::Redis);
    }

    #[test]
    fn test_redis_detector_empty() {
        let detector = RedisDetector::new();
        assert!(detector.detect(&[]).is_none());
    }

    #[test]
    fn test_redis_detector_invalid() {
        let detector = RedisDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
        assert!(detector.detect(b"220 OK\r\n").is_none());
    }
}