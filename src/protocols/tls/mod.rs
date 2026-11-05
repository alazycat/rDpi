//! TLS protocol detection module for rDpi
//!
//! Provides TLS record layer detection and ClientHello parsing
//! to extract SNI (Server Name Indication) and TLS version.

mod certificate;
mod parser;

pub use certificate::{CertInfo, is_certificate_message, parse_certificate};
pub use parser::{
    ClientHelloInfo, ServerHelloInfo, extract_quic_transport_parameters, extract_sni,
    extract_tls_version, is_client_hello, is_tls_record, iter_tls_records, parse_client_hello,
    parse_server_hello, parse_server_hello_alpn,
};

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(TlsDetector::new()));
}

/// 协商版本 u16 → 版本字符串（ServerHello 元数据展示用，GREASE 值返回 None）
fn negotiated_version_string(version: Option<u16>) -> Option<String> {
    match version {
        Some(0x0301) => Some("TLS 1.0".to_string()),
        Some(0x0302) => Some("TLS 1.1".to_string()),
        Some(0x0303) => Some("TLS 1.2".to_string()),
        Some(0x0304) => Some("TLS 1.3".to_string()),
        _ => None,
    }
}

/// TLS protocol detector
pub struct TlsDetector {
    _private: (),
}

impl TlsDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for TlsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::protocols::ProtocolDetector for TlsDetector {
    fn name(&self) -> &'static str {
        "tls"
    }

    /// 首字节门：TLS 记录层 handshake content_type=0x16。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x16u8, 0x16u8)])
    }

    fn detect(&self, payload: &[u8]) -> Option<crate::core::types::DetectionResult> {
        if !is_tls_record(payload) {
            return None;
        }

        use crate::core::types::{Confidence, DetectionResult, Metadata, Protocol, TlsMetadata};

        let mut tls_meta = TlsMetadata::default();

        // a3 修复：单个 TCP 段可能串联多条记录（如服务器把 ServerHello +
        // Certificate 合并发送，或 ClientHello 后紧跟 Certificate），逐记录
        // 解析而非只看段首。ClientHello/Certificate 各取首个命中。
        for record in iter_tls_records(payload) {
            // ClientHello（SNI, version, JA4, ALPN）；非 ClientHello 记录
            // （ServerHello/Finished 等）在 is_client_hello 的 data[5] 检查处
            // 快速失败，AppData 记录在 content_type 检查处失败
            if let Some(ref info) = parse_client_hello(record) {
                tls_meta.sni = info.sni.clone();
                tls_meta.version = info.version.clone();
                tls_meta.cipher_suites = info.cipher_suites.clone();
                tls_meta.alpn = info.alpn.clone();
                tls_meta.application = info
                    .sni
                    .as_ref()
                    .and_then(|sni| crate::application::identify(sni));
                let ja4 = info.version.as_ref().map(|ver| {
                    crate::application::compute_ja4(
                        ver,
                        &info.cipher_suites,
                        &info.extensions,
                        &info.supported_groups,
                    )
                });
                tls_meta.ja4 = ja4;
            } else if let Some(ref sh) = parse_server_hello(record) {
                // ServerHello（msg_type 0x02）：服务端流首个明文记录（TLS 1.3 下
                // 证书已加密，明文只有 ServerHello）。提取协商版本 + JA4S。
                // 影响面：纯 ServerHello 的服务端流自此可定型为 TLS（此前无
                // ClientHello/Certificate 时返回 None，服务端流靠 guess 回退）。
                if tls_meta.version.is_none() {
                    tls_meta.version = negotiated_version_string(sh.supported_version)
                        .or_else(|| negotiated_version_string(Some(sh.legacy_version)));
                }
                if tls_meta.alpn.is_none() {
                    tls_meta.alpn = sh.alpn.clone();
                }
                if tls_meta.ja4s.is_none() {
                    tls_meta.ja4s = Some(crate::application::compute_ja4s(
                        false,
                        sh.legacy_version,
                        sh.supported_version,
                        sh.cipher_suite,
                        &sh.extensions,
                        sh.alpn.as_deref(),
                    ));
                }
            }

            // Try Certificate message for cert fields (even if ClientHello was found)
            if tls_meta.cert_subject.is_none()
                && let Some(cert_info) = certificate::parse_certificate(record)
            {
                tls_meta.cert_subject = cert_info.subject;
                tls_meta.cert_issuer = cert_info.issuer;
                tls_meta.cert_valid_from = cert_info.not_before;
                tls_meta.cert_valid_to = cert_info.not_after;
            }
        }

        // Return None if nothing matched (no ClientHello / ServerHello / Certificate)
        if tls_meta.sni.is_none()
            && tls_meta.version.is_none()
            && tls_meta.cert_subject.is_none()
            && tls_meta.ja4s.is_none()
        {
            return None;
        }

        Some(
            DetectionResult::new(Protocol::Tls)
                .with_metadata(Metadata::Tls(tls_meta))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ProtocolDetector;

    #[test]
    fn test_tls_detector_new() {
        let detector = TlsDetector::new();
        assert_eq!(detector.name(), "tls");
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = TlsDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = [0x16, 0x03, 0x01, 0x00, 0x2F];
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
