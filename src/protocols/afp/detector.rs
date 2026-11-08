//! Apple Filing Protocol detector for rDpi

use crate::core::types::{
    AfpMetadata, Confidence, DetectContext, DetectionResult, Metadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::parse_afp_dsi;

/// AFP DSI protocol detector
pub struct AfpDetector {
    _private: (),
}

impl AfpDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for AfpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for AfpDetector {
    fn name(&self) -> &'static str {
        "afp"
    }

    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x00, 0x01)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_afp_dsi(payload)?;
        Some(
            DetectionResult::new(Protocol::Afp)
                .with_metadata(Metadata::Afp(AfpMetadata {
                    flags: parsed.flags,
                    command: parsed.command,
                    request_id: parsed.request_id,
                    length: parsed.length,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }

    fn detect_with_context(&self, payload: &[u8], _ctx: &DetectContext) -> Option<DetectionResult> {
        // 与 nDPI 一致：AFP detector 不检查端口，548 仅用于回退猜测。
        self.detect(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dsi(flags: u8, command: u8, request_id: u16, length: u32, body: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(flags);
        packet.push(command);
        packet.extend_from_slice(&request_id.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
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
    fn test_detect_request() {
        let detector = AfpDetector::new();
        let result = detector.detect(&dsi(0, 1, 3, 0, b"")).unwrap();
        assert_eq!(result.protocol, Protocol::Afp);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Afp(meta) => {
                assert_eq!(meta.flags, 0);
                assert_eq!(meta.command, 1);
                assert_eq!(meta.request_id, 3);
                assert_eq!(meta.length, 0);
            }
            _ => panic!("expected AFP metadata"),
        }
    }

    #[test]
    fn test_reject_http() {
        let detector = AfpDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_detect_is_port_independent() {
        let detector = AfpDetector::new();
        let payload = dsi(0, 1, 1, 0, b"");
        assert!(
            detector
                .detect_with_context(&payload, &ctx(50000, 9999))
                .is_some()
        );
        assert!(
            detector
                .detect_with_context(&payload, &ctx(50000, 548))
                .is_some()
        );
    }

    #[test]
    fn test_first_byte_gate_covers_valid_samples() {
        let detector = AfpDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        for flags in [0u8, 1] {
            let sample = dsi(flags, 1, 1, 0, b"");
            assert!(
                gate.iter()
                    .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
                "门区间不覆盖合法样本首字节 0x{:02X}",
                sample[0]
            );
        }
        for byte in [2u8, 0xFF, b'G'] {
            assert!(!gate.iter().any(|&(lo, hi)| byte >= lo && byte <= hi));
        }
    }
}
