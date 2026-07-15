//! QUIC protocol detection and parsing for rDpi
//!
//! This module provides QUIC protocol identification and Initial packet parsing.

mod parser;

pub use parser::*;

use crate::core::types::{Confidence, DetectionResult, Metadata, Protocol, QuicMetadata};
use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(QuicDetector::new()));
}

/// QUIC protocol detector
pub struct QuicDetector {
    _private: (),
}

impl QuicDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for QuicDetector {
    fn default() -> Self {
        Self::new()
    }
}

use crate::core::types::DetectContext;

impl crate::protocols::ProtocolDetector for QuicDetector {
    fn name(&self) -> &'static str {
        "quic"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        // Quick check: QUIC Long Header Initial
        if !is_quic_initial(payload) {
            return None;
        }

        // Parse QUIC header
        let info = parse_quic_initial(payload)?;

        // Build metadata - convert version to hex string format
        let metadata = QuicMetadata {
            sni: None, // Would need decryption for SNI
            version: Some(format!("{:08x}", info.version)),
            destination_connection_id: Some(info.dcid),
            application: None,
        };

        // Report QUIC with high confidence since we successfully parsed an Initial packet
        Some(
            DetectionResult::new(Protocol::Quic)
                .with_metadata(Metadata::Quic(metadata))
                .with_confidence(Confidence::Dpi),
        )
    }

    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        if !is_quic_initial(payload) {
            return None;
        }

        let info = parse_quic_initial(payload)?;

        // 判断是否为标准版本（v1 或 v2）
        let is_standard_version = matches!(info.version, QUIC_VERSION_1 | QUIC_VERSION_2);

        let metadata = QuicMetadata {
            sni: None,
            version: Some(format!("{:08x}", info.version)),
            destination_connection_id: Some(info.dcid),
            application: None,
        };

        // HTTP/3 判断：UDP 443 + 标准版本
        let (protocol, confidence) = if ctx.is_http3_port && is_standard_version {
            (Protocol::Http3, Confidence::DpiPartial)  // HTTP/3 需要端口+版本双重确认
        } else {
            (Protocol::Quic, Confidence::Dpi)
        };

        Some(
            DetectionResult::new(protocol)
                .with_metadata(Metadata::Quic(metadata))
                .with_confidence(confidence),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ProtocolDetector;

    #[test]
    fn test_quic_detector_new() {
        let detector = QuicDetector::new();
        assert_eq!(detector.name(), "quic");
    }
}
