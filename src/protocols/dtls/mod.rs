//! DTLS 协议检测与 JA4/JA4S d 前缀指纹（F38，2026-11-06）
//!
//! 权威规格：FoxIO technical_details/JA4.md —— JA4/JA4S 的 proto 首字符
//! QUIC="q"、DTLS="d"、TLS over TCP="t"；DTLS 版本映射 0xfeff→"d1"、
//! 0xfefd→"d2"、0xfefc→"d3"（zeek ssl-consts.h TLS_VERSION_MAPPER 同源，
//! Wireshark packet-ja4.c `case 'd'` 印证）。
//!
//! 握手解析复用 tls 解析器：DTLS 12 字节握手头剥离
//! message_seq/fragment_offset/fragment_length 后合成 TLS 记录
//! （[`parser::synthesize_tls_record`]），零改动复用
//! `parse_client_hello` / `parse_server_hello`（QUIC 解密路径同法先例）。
//! 无 tls feature 时降级为仅识别 + 记录层版本（QUIC 先例同款降级模式）。

mod parser;

use crate::core::types::{Confidence, DetectionResult, DtlsMetadata, Metadata, Protocol};
use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(DtlsDetector::new()));
}

/// DTLS protocol detector
pub struct DtlsDetector {
    _private: (),
}

impl DtlsDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for DtlsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::protocols::ProtocolDetector for DtlsDetector {
    fn name(&self) -> &'static str {
        "dtls"
    }

    /// 首字节门：仅 handshake 记录（content_type=0x16）参与识别。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x16u8, 0x16u8)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let hs = parser::parse_handshake(payload)?;

        let mut meta = DtlsMetadata::default();
        match hs.msg_type {
            // ClientHello：客户端流定型；supported_versions 扩展原始值
            // （非 GREASE 最大者）优先于记录层版本。合成时区分 DTLS 1.3
            // （无 cookie）与 1.2（legacy cookie 向量剥离）两种布局。
            1 => {
                let synth = parser::synthesize_client_hello(payload, &hs);
                let negotiated = synth
                    .as_deref()
                    .and_then(parser::client_hello_supported_version)
                    .unwrap_or(hs.version);
                meta.version = parser::version_string(negotiated).map(str::to_string);
                #[cfg(feature = "tls")]
                if let Some(ch) = synth
                    .as_deref()
                    .and_then(crate::protocols::tls::parse_client_hello)
                {
                    meta.sni = ch.sni;
                    meta.alpn = ch.alpn;
                    meta.application = meta.sni.as_deref().and_then(crate::application::identify);
                    // 客户端 JA4：与 TLS/QUIC 路径同源占位格式。"DTLS x.y"
                    // 版本串落入 tls10 桶为已知局限（官方 d1/d2/d3 版本码待
                    // 占位表升级，见 risks.md F38 边界）
                    meta.ja4 = meta.version.as_ref().map(|ver| {
                        crate::application::compute_ja4(
                            ver,
                            &ch.cipher_suites,
                            &ch.extensions,
                            &ch.supported_groups,
                        )
                    });
                }
            }
            // ServerHello：服务端流定型（JA4S d 前缀）。DTLS 1.2 服务端首包
            // 常为 HelloVerifyRequest(3)——不定型，避免在 ServerHello 到达前
            // 提前定型丢元数据；此后 ServerHello 到达时本 detector 命中。
            2 => {
                meta.version = parser::version_string(hs.version).map(str::to_string);
                #[cfg(feature = "tls")]
                {
                    let synth = parser::synthesize_server_hello(payload, &hs);
                    if let Some(sh) = crate::protocols::tls::parse_server_hello(&synth) {
                        meta.alpn = sh.alpn.clone();
                        meta.version = sh
                            .supported_version
                            .or(Some(sh.legacy_version))
                            .and_then(parser::version_string)
                            .map(str::to_string)
                            .or(meta.version);
                        meta.ja4s = Some(crate::application::compute_ja4s(
                            crate::application::Ja4Transport::Dtls,
                            sh.legacy_version,
                            sh.supported_version,
                            sh.cipher_suite,
                            &sh.extensions,
                            sh.alpn.as_deref(),
                        ));
                    }
                }
            }
            // HelloVerifyRequest(3)/Certificate(11)/Finished(20) 等不定型
            _ => return None,
        }

        Some(
            DetectionResult::new(Protocol::Dtls)
                .with_metadata(Metadata::Dtls(meta))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ProtocolDetector;

    #[test]
    fn test_dtls_detector_new() {
        let detector = DtlsDetector::new();
        assert_eq!(detector.name(), "dtls");
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        let detector = DtlsDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = [0x16, 0xfe, 0xfd, 0x00, 0x00];
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
