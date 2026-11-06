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

use crate::core::types::{
    DetectContext, Direction, DissectorOutcome, DissectorState, TlsDissectorState,
};
use crate::protocols::Registry;

/// TLS 记录载荷上限（RFC 5246：ciphertext ≤ 2^14 + 2048）
const TLS_MAX_RECORD_BYTES: usize = 18_432;
/// 单方向不完整记录的缓冲上限（5 字节记录头 + 最大记录）
const TLS_MAX_BUFFER_BYTES: usize = 5 + TLS_MAX_RECORD_BYTES;

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

    /// 有状态逐包 TLS 记录重组
    ///
    /// 两个方向独立缓冲；凑齐完整 TLS record（5 字节头 + record_len）后交给
    /// 无状态 [`Self::detect`]。非 handshake 记录（CCS/Alert/AppData）直接
    /// 丢弃，继续等待后续记录。当前只做 record 级重组，不处理 handshake
    /// 消息跨 TLS record 分片。
    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        direction: Direction,
        ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        // 端口 53 的 TCP 流交给 DNS-over-TCP，避免长度前缀首字节恰为 0x16 时误接管。
        if ctx.src_port == 53 || ctx.dst_port == 53 {
            return None;
        }

        match state {
            DissectorState::None => {
                if payload.first() != Some(&0x16) {
                    return None;
                }
                *state = DissectorState::Tls(TlsDissectorState::default());
            }
            DissectorState::Tls(_) => {}
            _ => return None,
        }

        let DissectorState::Tls(tls_state) = state else {
            return None;
        };
        let buffer = match direction {
            Direction::Forward => &mut tls_state.client_buffer,
            Direction::Reverse => &mut tls_state.server_buffer,
        };
        buffer.extend_from_slice(payload);

        loop {
            if buffer.len() < 5 {
                break;
            }
            let content_type = buffer[0];
            if !(0x14..=0x17).contains(&content_type) || buffer[1] != 0x03 {
                return Some(DissectorOutcome::GiveUp);
            }
            let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
            if record_len > TLS_MAX_RECORD_BYTES {
                return Some(DissectorOutcome::GiveUp);
            }
            if buffer.len() < 5 + record_len {
                break;
            }

            let detected = if content_type == 0x16 {
                self.detect(&buffer[..5 + record_len])
            } else {
                None
            };
            if let Some(result) = detected {
                buffer.clear();
                return Some(DissectorOutcome::Classified(result));
            }
            buffer.drain(..5 + record_len);
        }

        if buffer.len() > TLS_MAX_BUFFER_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        Some(DissectorOutcome::Continue)
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
                let ja4 = crate::application::compute_ja4(
                    crate::application::Ja4Transport::Tcp,
                    info.negotiated_version,
                    &info.cipher_suites,
                    &info.extensions,
                    &info.signature_algorithms,
                    info.alpn.as_deref(),
                    info.sni.is_some(),
                );
                tls_meta.ja4 = Some(ja4);
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
                        crate::application::Ja4Transport::Tcp,
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
                tls_meta.cert_ja4x = cert_info.ja4x;
            }
        }

        // Return None if nothing matched (no ClientHello / ServerHello / Certificate)
        if tls_meta.sni.is_none()
            && tls_meta.version.is_none()
            && tls_meta.cert_subject.is_none()
            && tls_meta.cert_ja4x.is_none()
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
