//! WireGuard protocol detector for rDpi
//!
//! Detects WireGuard VPN messages using handshake header inspection.
//! Uses port 51820 context for confidence adjustment.

use crate::core::types::{Confidence, DetectContext, DetectionResult, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_wireguard_handshake;

/// WireGuard protocol detector
pub struct WireGuardDetector {
    _private: (),
}

impl WireGuardDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for WireGuardDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for WireGuardDetector {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    fn detect(&self, _payload: &[u8]) -> Option<DetectionResult> {
        // WireGuard detection needs port context
        None
    }

    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        if payload.is_empty() {
            return None;
        }

        let is_wg_port = ctx.dst_port == 51820 || ctx.src_port == 51820;

        // Quick pre-check: message_type range 1-4
        if payload[0] < 1 || payload[0] > 4 {
            return None;
        }

        let meta = parse_wireguard_handshake(payload)?;

        let confidence = if is_wg_port {
            Confidence::Dpi
        } else {
            Confidence::DpiPartial
        };

        Some(
            DetectionResult::new(Protocol::WireGuard)
                .with_metadata(Metadata::WireGuard(meta))
                .with_confidence(confidence),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::ProtocolCategory;

    fn build_wg_message(msg_type: u8, extra_len: usize) -> Vec<u8> {
        let mut packet = vec![msg_type, 0x00, 0x00, 0x00];
        packet.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // sender_index
        packet.extend_from_slice(&vec![0u8; extra_len]);
        packet
    }

    #[test]
    fn test_wireguard_detector_standard_port() {
        let detector = WireGuardDetector::new();
        let packet = build_wg_message(1, 140); // Initiation
        let ctx = DetectContext {
            src_port: 12345,
            dst_port: 51820,
            is_http3_port: false,
        };

        let result = detector.detect_with_context(&packet, &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::WireGuard);
        assert_eq!(result.confidence, Confidence::Dpi);
        assert_eq!(result.category, ProtocolCategory::Vpn);
    }

    #[test]
    fn test_wireguard_detector_non_standard_port() {
        let detector = WireGuardDetector::new();
        let packet = build_wg_message(1, 140);
        let ctx = DetectContext {
            src_port: 12345,
            dst_port: 9999,
            is_http3_port: false,
        };

        let result = detector.detect_with_context(&packet, &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::WireGuard);
        assert_eq!(result.confidence, Confidence::DpiPartial);
    }

    #[test]
    fn test_wireguard_detector_reject_http() {
        let detector = WireGuardDetector::new();
        let ctx = DetectContext {
            src_port: 12345,
            dst_port: 80,
            is_http3_port: false,
        };

        // HTTP data should not match
        assert!(detector.detect_with_context(b"GET / HTTP/1.1\r\n", &ctx).is_none());
        assert!(detector.detect_with_context(b"", &ctx).is_none());
    }

    #[test]
    fn test_wireguard_detector_response_port() {
        let detector = WireGuardDetector::new();
        let packet = build_wg_message(2, 120); // Response
        let ctx = DetectContext {
            src_port: 51820,
            dst_port: 12345,
            is_http3_port: false,
        };

        let result = detector.detect_with_context(&packet, &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::WireGuard);
        assert_eq!(result.confidence, Confidence::Dpi);
    }
}
