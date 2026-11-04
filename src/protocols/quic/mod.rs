//! QUIC protocol detection and parsing for rDpi
//!
//! This module provides QUIC protocol identification and Initial packet parsing.
//! Initial 包解密（RFC 9001 §5，全手写密码学原语见 [`crypto`]）可提取
//! CRYPTO 帧中的 TLS ClientHello，从而获得真实 SNI/ALPN。

mod crypto;
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

use crate::core::types::{Application, DetectContext};

/// 尝试解密 Initial 包提取 TLS ClientHello 元数据（SNI, ALPN, 应用识别）
///
/// 仅在 QUIC v1 上生效；解密失败/非 ClientHello/未启用 tls feature 时返回 None，
/// 调用方降级为仅头部信息（性能：仅 Initial 包触发，失败路径为常数次 AES 尝试）。
#[cfg(feature = "tls")]
fn try_extract_tls_meta(
    payload: &[u8],
) -> Option<(Option<String>, Option<String>, Option<Application>)> {
    let ch = parser::decrypt_client_hello(payload)?;
    let application = ch.sni.as_deref().and_then(crate::application::identify);
    Some((ch.sni, ch.alpn, application))
}

/// 非 tls feature 下无 ClientHello 提取能力（保持降级行为一致）
#[cfg(not(feature = "tls"))]
fn try_extract_tls_meta(
    _payload: &[u8],
) -> Option<(Option<String>, Option<String>, Option<Application>)> {
    None
}

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

        // 尝试解密提取 ClientHello（失败降级为 None）
        let (sni, alpn, application) = try_extract_tls_meta(payload).unwrap_or((None, None, None));

        // Build metadata - convert version to hex string format
        let metadata = QuicMetadata {
            sni,
            version: Some(format!("{:08x}", info.version)),
            destination_connection_id: Some(info.dcid),
            application,
            alpn,
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

        // 尝试解密 Initial 包提取 ClientHello（失败降级为 None，不影响判定）
        let (sni, alpn, application) = try_extract_tls_meta(payload).unwrap_or((None, None, None));

        let metadata = QuicMetadata {
            sni,
            version: Some(format!("{:08x}", info.version)),
            destination_connection_id: Some(info.dcid),
            application,
            alpn,
        };

        // HTTP/3 判断：UDP 443 + 标准版本
        let (protocol, confidence) = if ctx.is_http3_port && is_standard_version {
            (Protocol::Http3, Confidence::DpiPartial) // HTTP/3 需要端口+版本双重确认
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
