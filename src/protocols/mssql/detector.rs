//! MSSQL/TDS protocol detector for rDpi

use crate::core::types::{
    Confidence, DetectContext, DetectionResult, Metadata, MssqlMetadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::parse_mssql_tds;

/// TPKT over ISO 8072 使用的 TCP 端口（nDPI 排除，避免与 TDS 头混淆）
const TPKT_PORT: u16 = 102;

/// MSSQL/TDS protocol detector
pub struct MssqlDetector {
    _private: (),
}

impl MssqlDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for MssqlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for MssqlDetector {
    fn name(&self) -> &'static str {
        "mssql"
    }

    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(1, 8), (14, 18)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_mssql_tds(payload)?;
        Some(
            DetectionResult::new(Protocol::Mssql)
                .with_metadata(Metadata::Mssql(MssqlMetadata {
                    packet_type: parsed.packet_type,
                    status: parsed.status,
                    length: parsed.length,
                    channel: parsed.channel,
                    packet_id: parsed.packet_id,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }

    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        if ctx.src_port == TPKT_PORT || ctx.dst_port == TPKT_PORT {
            return None;
        }
        self.detect(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tds(packet_type: u8, status: u8, packet_id: u8, window: u8, body: &[u8]) -> Vec<u8> {
        let total = (8 + body.len()) as u16;
        let mut packet = vec![packet_type, status];
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.push(packet_id);
        packet.push(window);
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
    fn test_detect_prelogin() {
        let detector = MssqlDetector::new();
        let payload = tds(0x12, 0x01, 1, 0, &[0x00, 0x00, 0x1a, 0x00]);
        let result = detector.detect(&payload).unwrap();
        assert_eq!(result.protocol, Protocol::Mssql);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Mssql(meta) => {
                assert_eq!(meta.packet_type, 0x12);
                assert_eq!(meta.status, 0x01);
                assert_eq!(meta.length, 12);
                assert_eq!(meta.channel, 0);
                assert_eq!(meta.packet_id, 1);
            }
            _ => panic!("expected Mssql metadata"),
        }
    }

    #[test]
    fn test_detect_sql_batch_and_reply() {
        let detector = MssqlDetector::new();
        for packet_type in [1u8, 2, 4, 7] {
            let payload = tds(packet_type, 0x01, 1, 0, b"query");
            assert_eq!(detector.detect(&payload).unwrap().protocol, Protocol::Mssql);
        }
    }

    #[test]
    fn test_detect_transaction_manager_types() {
        let detector = MssqlDetector::new();
        for packet_type in [14u8, 15, 16, 17, 18] {
            let payload = tds(packet_type, 0x01, 0, 0, b"body");
            assert_eq!(detector.detect(&payload).unwrap().protocol, Protocol::Mssql);
        }
    }

    #[test]
    fn test_reject_http() {
        let detector = MssqlDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_detect_with_context_excludes_tpkt_port() {
        let detector = MssqlDetector::new();
        let payload = tds(0x12, 0x01, 1, 0, b"body");
        assert!(
            detector
                .detect_with_context(&payload, &ctx(50000, 102))
                .is_none()
        );
        assert!(
            detector
                .detect_with_context(&payload, &ctx(102, 50000))
                .is_none()
        );
        assert!(
            detector
                .detect_with_context(&payload, &ctx(50000, 1433))
                .is_some()
        );
    }

    #[test]
    fn test_first_byte_gate_covers_valid_types() {
        let detector = MssqlDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        for packet_type in [1u8, 2, 3, 4, 5, 6, 7, 8, 14, 15, 16, 17, 18] {
            let payload = tds(packet_type, 0x01, 1, 0, b"body");
            assert!(
                gate.iter()
                    .any(|&(lo, hi)| payload[0] >= lo && payload[0] <= hi),
                "门区间不覆盖合法样本首字节 0x{:02X}",
                payload[0]
            );
        }
        for byte in [0u8, 9, 13, 19, b'G'] {
            assert!(!gate.iter().any(|&(lo, hi)| byte >= lo && byte <= hi));
        }
    }
}
