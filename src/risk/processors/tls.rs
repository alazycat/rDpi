//! TLS security risk processors
//!
//! Detects TLS-related risks using TlsMetadata from protocol detection.

use crate::core::flow::Flow;
use crate::core::types::{Metadata, Protocol, TlsMetadata, TransportProto};
use crate::parser::ParsedPacket;
use crate::risk::RiskProcessor;
use crate::risk::types::{RiskFlag, RiskResult, RiskSeverity};

/// 已知弱密码套件 ID 列表
const WEAK_CIPHER_SUITES: &[u16] = &[
    // NULL (无加密)
    0x0000, 0x0001, 0x0002, 0x003B, 0x003C, 0x003D, 0x0060, 0x0061, 0x0062,
    // EXPORT (40 位密钥)
    0x0003, 0x0006, 0x0008, 0x0012, 0x0015, 0x001A, 0x001D, 0x0022, 0x0025, // RC4
    0x0004, 0x0005, 0x0011, 0x0018, 0x001B, 0x0020, 0x0023, 0x0042, 0x0043,
    // DES / 3DES
    0x0007, 0x0009, 0x000A, 0x0013, 0x0014, 0x0016, 0x0017, 0x0019, 0x001C, 0x001E, 0x001F, 0x0021,
    0x0024, 0x008C, 0x008D,
];

/// TLS 安全风险处理器
pub struct TlsRiskProcessor;

impl TlsRiskProcessor {
    pub fn new() -> Self {
        Self
    }

    fn get_tls<'a>(&self, flow: &'a Flow) -> Option<&'a TlsMetadata> {
        match &flow.metadata {
            Some(Metadata::Tls(tls)) => {
                if flow.protocol == Some(Protocol::Tls) {
                    Some(tls)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl Default for TlsRiskProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskProcessor for TlsRiskProcessor {
    fn name(&self) -> &'static str {
        "tls_risk"
    }

    fn analyze_packet(&self, _parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
        let tls = match self.get_tls(flow) {
            Some(t) => t,
            None => return vec![],
        };

        let mut results = Vec::new();

        // 1. TlsMissingSni: ClientHello 没有 SNI
        if tls.sni.is_none() || tls.sni.as_deref() == Some("") {
            results.push(RiskResult::new(
                RiskFlag::TlsMissingSni,
                RiskSeverity::Medium,
                "TLS ClientHello without SNI extension — potential covert tunnel",
            ));
        }

        // 2. TlsObsoleteVersion: TLS 1.0/1.1
        // 注意：版本字符串由 tls/parser.rs:decode_tls_version 产出，格式为 "TLS 1.0"（带前缀）
        if let Some(ref ver) = tls.version
            && (ver == "TLS 1.0" || ver == "TLS 1.1")
        {
            results.push(RiskResult::new(
                RiskFlag::TlsObsoleteVersion,
                RiskSeverity::High,
                format!("Obsolete TLS version {}. Use TLS 1.2 or later.", ver),
            ));
        }

        // 3. TlsWeakCipher: 检查密码套件
        let has_weak = tls
            .cipher_suites
            .iter()
            .any(|c| WEAK_CIPHER_SUITES.contains(c));
        if has_weak {
            let weak_list: Vec<String> = tls
                .cipher_suites
                .iter()
                .filter(|c| WEAK_CIPHER_SUITES.contains(c))
                .map(|c| format!("0x{:04X}", c))
                .collect();
            results.push(RiskResult::new(
                RiskFlag::TlsWeakCipher,
                RiskSeverity::High,
                format!("Weak TLS cipher suites offered: {}", weak_list.join(", ")),
            ));
        }

        // 4. TlsAlpnSniMismatch: ALPN 与连接上下文不一致（F2 修复：原为死旗标，
        //    tls.rs 原 96-98 行只有占位注释）。启发式：ALPN 通告 "h3"（HTTP/3
        //    仅存在于 QUIC/UDP 传输），但当前流承载于 TCP——通告的传输协议与
        //    实际连接矛盾（伪装/异常客户端信号）。severity Medium 维持原定义。
        if tls.alpn.as_deref() == Some("h3") && flow.key.transport != TransportProto::Udp {
            results.push(RiskResult::new(
                RiskFlag::TlsAlpnSniMismatch,
                RiskSeverity::Medium,
                format!(
                    "ALPN advertises h3 (QUIC-only) over {:?} transport — inconsistent client advertisement",
                    flow.key.transport
                ),
            ));
        }

        results
    }

    fn analyze_flow(&self, _flow: &Flow) -> Vec<RiskResult> {
        vec![] // TLS 风险在逐包分析中完成
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::flow::Flow;
    use crate::core::types::{FlowKey, TlsMetadata, TransportProto};

    fn make_tls_flow(sni: Option<&str>, version: Option<&str>, cipher_suites: Vec<u16>) -> Flow {
        let mut flow = Flow::new(FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 54321,
            dst_port: 443,
            transport: TransportProto::Tcp,
        });
        flow.protocol = Some(Protocol::Tls);
        flow.metadata = Some(Metadata::Tls(TlsMetadata {
            sni: sni.map(|s| s.to_string()),
            version: version.map(|v| v.to_string()),
            application: None,
            ja4: None,
            ja4s: None,
            cipher_suites,
            alpn: None,
            cert_subject: None,
            cert_issuer: None,
            cert_valid_from: None,
            cert_valid_to: None,
        }));
        flow
    }

    fn make_parsed() -> ParsedPacket {
        ParsedPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 54321,
            dst_port: 443,
            transport: TransportProto::Tcp,
            payload: vec![],
        }
    }

    #[test]
    fn test_tls_missing_sni() {
        let proc = TlsRiskProcessor::new();
        let flow = make_tls_flow(None, Some("1.3"), vec![]);
        let parsed = make_parsed();
        let risks = proc.analyze_packet(&parsed, &flow);
        assert!(risks.iter().any(|r| r.flag == RiskFlag::TlsMissingSni));
    }

    #[test]
    fn test_tls_with_sni_no_risk() {
        let proc = TlsRiskProcessor::new();
        let flow = make_tls_flow(Some("example.com"), Some("1.3"), vec![0x1301]);
        let parsed = make_parsed();
        let risks = proc.analyze_packet(&parsed, &flow);
        assert!(!risks.iter().any(|r| r.flag == RiskFlag::TlsMissingSni));
    }

    #[test]
    fn test_tls_obsolete_version() {
        let proc = TlsRiskProcessor::new();
        // 版本字符串使用解析器真实产出格式 "TLS 1.0"（tls/parser.rs:decode_tls_version）
        let flow = make_tls_flow(Some("x.com"), Some("TLS 1.0"), vec![]);
        let parsed = make_parsed();
        let risks = proc.analyze_packet(&parsed, &flow);
        assert!(risks.iter().any(|r| r.flag == RiskFlag::TlsObsoleteVersion));
    }

    #[test]
    fn test_tls_modern_version_no_risk() {
        let proc = TlsRiskProcessor::new();
        let flow = make_tls_flow(Some("x.com"), Some("1.3"), vec![]);
        let parsed = make_parsed();
        let risks = proc.analyze_packet(&parsed, &flow);
        assert!(!risks.iter().any(|r| r.flag == RiskFlag::TlsObsoleteVersion));
    }

    #[test]
    fn test_tls_weak_cipher() {
        let proc = TlsRiskProcessor::new();
        let flow = make_tls_flow(Some("x.com"), Some("1.2"), vec![0x0004, 0x1301]); // RC4 + AES
        let parsed = make_parsed();
        let risks = proc.analyze_packet(&parsed, &flow);
        assert!(risks.iter().any(|r| r.flag == RiskFlag::TlsWeakCipher));
    }

    #[test]
    fn test_tls_strong_cipher_no_risk() {
        let proc = TlsRiskProcessor::new();
        let flow = make_tls_flow(Some("x.com"), Some("1.3"), vec![0x1301, 0x1302]);
        let parsed = make_parsed();
        let risks = proc.analyze_packet(&parsed, &flow);
        assert!(!risks.iter().any(|r| r.flag == RiskFlag::TlsWeakCipher));
    }

    /// F2 修复：ALPN 通告 h3（QUIC-only）但流承载于 TCP → 触发 TlsAlpnSniMismatch
    #[test]
    fn test_tls_alpn_h3_over_tcp_mismatch() {
        let proc = TlsRiskProcessor::new();
        let mut flow = make_tls_flow(Some("x.com"), Some("1.3"), vec![0x1301]);
        if let Some(Metadata::Tls(ref mut tls)) = flow.metadata {
            tls.alpn = Some("h3".to_string());
        }
        let parsed = make_parsed();
        let risks = proc.analyze_packet(&parsed, &flow);
        assert!(
            risks.iter().any(|r| r.flag == RiskFlag::TlsAlpnSniMismatch),
            "F2: h3 advertised over TCP must trigger TlsAlpnSniMismatch"
        );
    }

    /// F2：一致的 ALPN（h2 over TCP）与 UDP 上的 h3 均不触发
    #[test]
    fn test_tls_alpn_consistent_no_mismatch() {
        let proc = TlsRiskProcessor::new();
        // h2 over TCP：正常
        let mut flow = make_tls_flow(Some("x.com"), Some("1.3"), vec![0x1301]);
        if let Some(Metadata::Tls(ref mut tls)) = flow.metadata {
            tls.alpn = Some("h2".to_string());
        }
        let parsed = make_parsed();
        assert!(proc.analyze_packet(&parsed, &flow).is_empty());

        // h3 over UDP（QUIC）：一致，不触发（注：QUIC 流通常不进入本处理器，此处钉住传输判定）
        let mut udp_flow = make_tls_flow(Some("x.com"), Some("1.3"), vec![0x1301]);
        udp_flow.key.transport = TransportProto::Udp;
        if let Some(Metadata::Tls(ref mut tls)) = udp_flow.metadata {
            tls.alpn = Some("h3".to_string());
        }
        assert!(proc.analyze_packet(&parsed, &udp_flow).is_empty());
    }

    #[test]
    fn test_non_tls_flow_no_risk() {
        let proc = TlsRiskProcessor::new();
        let flow = make_tls_flow(Some("x.com"), Some("1.3"), vec![]);
        // Make it non-TLS
        let parsed = make_parsed();
        let risks = proc.analyze_packet(&parsed, &flow);
        // Should still be TLS
        assert!(risks.is_empty());
    }
}
