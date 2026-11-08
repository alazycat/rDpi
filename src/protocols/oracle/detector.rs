//! Oracle TNS protocol detector for rDpi

use crate::core::types::{
    Confidence, DetectContext, DetectionResult, Metadata, OracleMetadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::parse_oracle_connect;

/// Oracle TNS 默认端口
const ORACLE_PORT: u16 = 1521;

/// Oracle TNS protocol detector
pub struct OracleDetector {
    _private: (),
}

impl OracleDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for OracleDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for OracleDetector {
    fn name(&self) -> &'static str {
        "oracle"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_oracle_connect(payload)?;
        Some(
            DetectionResult::new(Protocol::Oracle)
                .with_metadata(Metadata::Oracle(OracleMetadata {
                    packet_length: parsed.packet_length,
                    packet_type: parsed.packet_type,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }

    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        if ctx.src_port != ORACLE_PORT && ctx.dst_port != ORACLE_PORT {
            return None;
        }
        self.detect(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect(body: &[u8]) -> Vec<u8> {
        let total = (8 + body.len()) as u16;
        let mut packet = Vec::new();
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.push(0x01);
        packet.push(0x00);
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(body);
        packet
    }

    fn ctx(src_port: u16, dst_port: u16) -> DetectContext {
        DetectContext {
            src_port,
            dst_port,
            is_http3_port: false,
        }
    }

    #[test]
    fn test_detect_connect() {
        let detector = OracleDetector::new();
        let result = detector.detect(&connect(b"\x00\x00")).unwrap();
        assert_eq!(result.protocol, Protocol::Oracle);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Oracle(meta) => {
                assert_eq!(meta.packet_length, 10);
                assert_eq!(meta.packet_type, 1);
            }
            _ => panic!("expected Oracle metadata"),
        }
    }

    #[test]
    fn test_reject_http() {
        let detector = OracleDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_detect_with_context_requires_port_1521() {
        let detector = OracleDetector::new();
        let payload = connect(b"");
        assert!(
            detector
                .detect_with_context(&payload, &ctx(50000, 1521))
                .is_some()
        );
        assert!(
            detector
                .detect_with_context(&payload, &ctx(1521, 50000))
                .is_some()
        );
        assert!(
            detector
                .detect_with_context(&payload, &ctx(50000, 1522))
                .is_none()
        );
    }

    #[test]
    fn test_first_byte_gate_is_none() {
        let detector = OracleDetector::new();
        assert!(detector.first_byte_gate().is_none());
    }
}
