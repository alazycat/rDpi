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

impl QuicDetector {
    /// 非 Initial 长包头识别（0-RTT 0xD0 / Handshake 0xE0 / Retry 0xF0 / VN version=0）
    ///
    /// 仅提取 version + DCID 元数据（这些包不含明文 ClientHello，无解密富化）。
    /// VN 包（version=0）不要求 Fixed Bit；其余类型要求 Fixed Bit=1（RFC 8999 §5.1）。
    fn detect_other_long_header(&self, payload: &[u8]) -> Option<DetectionResult> {
        if !is_quic_long_header(payload) {
            return None;
        }
        let version = parse_quic_version(payload)?;
        if version != 0 && (payload[0] & 0x40) == 0 {
            return None; // Fixed Bit 未置位：非法 QUIC 长包头
        }
        let dcid = parse_long_header_dcid(payload)?;
        let metadata = QuicMetadata {
            sni: None,
            alpn: None,
            ja4: None,
            version: Some(format!("{:08x}", version)),
            destination_connection_id: Some(dcid),
            application: None,
            transport_parameters: None,
        };
        Some(
            DetectionResult::new(Protocol::Quic)
                .with_metadata(Metadata::Quic(metadata))
                .with_confidence(Confidence::Dpi),
        )
    }
}

use crate::core::types::{Application, DetectContext, QuicTransportParams};

/// Initial 解密富化结果：(sni, alpn, ja4, application, transport_parameters)
type ExtractedTlsMeta = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Application>,
    Option<QuicTransportParams>,
);

/// 尝试解密 Initial 包提取 TLS 元数据（SNI, ALPN, JA4, 应用识别, Transport Parameters）
///
/// 先按客户端方向解（ClientHello → SNI/ALPN/JA4/应用识别/Transport Parameters），
/// 失败再按服务端方向解（ServerHello → 仅 ALPN）。解密失败/未启用 tls feature 时
/// 返回 None，调用方降级为仅头部信息（性能：仅 Initial 包触发，两条方向路径为
/// 常数次 AES 尝试）。
#[cfg(feature = "tls")]
fn try_extract_tls_meta(payload: &[u8]) -> Option<ExtractedTlsMeta> {
    // 客户端 Initial：CRYPTO 帧为 ClientHello
    if let Some((ch, tp)) = parser::decrypt_client_meta(payload) {
        let application = ch.sni.as_deref().and_then(crate::application::identify);
        // JA4 指纹与 TLS 路径同源（application::compute_ja4），ClientHelloInfo
        // 自带全部输入（version/ciphers/extensions/groups）
        let ja4 = ch.version.as_ref().map(|ver| {
            crate::application::compute_ja4(
                ver,
                &ch.cipher_suites,
                &ch.extensions,
                &ch.supported_groups,
            )
        });
        return Some((ch.sni, ch.alpn, ja4, application, tp));
    }
    // 服务端 Initial：CRYPTO 帧为 ServerHello（无 SNI/JA4/TP，仅 ALPN）
    let alpn = parser::decrypt_server_alpn(payload)?;
    Some((None, Some(alpn), None, None, None))
}

/// 非 tls feature 下无 ClientHello 提取能力（保持降级行为一致）
#[cfg(not(feature = "tls"))]
fn try_extract_tls_meta(_payload: &[u8]) -> Option<ExtractedTlsMeta> {
    None
}

impl crate::protocols::ProtocolDetector for QuicDetector {
    fn name(&self) -> &'static str {
        "quic"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        // Quick check: QUIC Long Header Initial
        if !is_quic_initial(payload) {
            // 非 Initial 长包头（0-RTT/Handshake/Retry/VN）也识别为 QUIC
            return self.detect_other_long_header(payload);
        }

        // Parse QUIC header
        let info = parse_quic_initial(payload)?;

        // 尝试解密提取 ClientHello（失败降级为 None）
        let (sni, alpn, ja4, application, transport_parameters) =
            try_extract_tls_meta(payload).unwrap_or((None, None, None, None, None));

        // Build metadata - convert version to hex string format
        let metadata = QuicMetadata {
            sni,
            version: Some(format!("{:08x}", info.version)),
            destination_connection_id: Some(info.dcid),
            application,
            alpn,
            ja4,
            transport_parameters,
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
            // 非 Initial 长包头不参与 HTTP/3 判定（端口+版本双重确认仅对 Initial 有效）
            return self.detect_other_long_header(payload);
        }

        let info = parse_quic_initial(payload)?;

        // 判断是否为标准版本（v1 或 v2）
        let is_standard_version = matches!(info.version, QUIC_VERSION_1 | QUIC_VERSION_2);

        // 尝试解密 Initial 包提取 ClientHello（失败降级为 None，不影响判定）
        let (sni, alpn, ja4, application, transport_parameters) =
            try_extract_tls_meta(payload).unwrap_or((None, None, None, None, None));

        let metadata = QuicMetadata {
            sni,
            version: Some(format!("{:08x}", info.version)),
            destination_connection_id: Some(info.dcid),
            application,
            alpn,
            ja4,
            transport_parameters,
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
