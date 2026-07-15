//! Behavioral risk processors
//!
//! Detects network behavior-based risks using flow analysis.

use crate::core::flow::Flow;
use crate::risk::types::{RiskFlag, RiskResult, RiskSeverity};
use crate::parser::ParsedPacket;
use crate::risk::RiskProcessor;

/// 二进制数据检测: 不可打印字符比例阈值
const BINARY_RATIO_THRESHOLD: f64 = 0.3;

/// 网络行为风险处理器
pub struct BehavioralRiskProcessor;

impl BehavioralRiskProcessor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BehavioralRiskProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// 检查 payload 是否为二进制数据
fn is_binary_payload(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let non_printable = data.iter().filter(|&&b| b < 32 && b != b'\t' && b != b'\n' && b != b'\r').count();
    (non_printable as f64 / data.len() as f64) > BINARY_RATIO_THRESHOLD
}

/// 检查是否为混淆流量的特征模式
fn has_obfuscation_patterns(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    // 特征1: 高熵头部 + 低熵内容 或反之
    let first_20 = &data[..20.min(data.len())];
    let printable = first_20.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count();
    let printable_ratio = printable as f64 / first_20.len() as f64;

    // 特征2: 非 HTTP 端口上的 HTTP-like 数据
    // (由协议检测器处理, 这里不重复)

    // 特征3: 全是相同字节的模式
    let all_same = data.iter().all(|&b| b == data[0]);

    // 混合特征: 头部看起来像文本但内容像二进制, 或反之
    let mixed = printable_ratio > 0.3 && printable_ratio < 0.7;

    // 全是相同字节 (如 \x00 填充)
    let uniform = all_same && data.len() > 50;

    mixed || uniform
}

impl RiskProcessor for BehavioralRiskProcessor {
    fn name(&self) -> &'static str {
        "behavioral_risk"
    }

    fn analyze_packet(&self, parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
        let mut results = Vec::new();

        // 1. BinaryDataTransfer: 不可打印字符比例高
        if is_binary_payload(&parsed.payload) && parsed.payload.len() > 100 {
            // 排除已知的二进制协议 (TLS/QUIC 等加密隧道已有 breed 评级)
            let is_encrypted = is_encrypted_protocol(flow.protocol);
            if !is_encrypted {
                results.push(RiskResult::new(
                    RiskFlag::BinaryDataTransfer,
                    RiskSeverity::Medium,
                    format!("Binary data transfer in {} protocol ({} bytes)",
                        flow.protocol.map(|p| format!("{:?}", p)).unwrap_or_default(),
                        parsed.payload.len()),
                ));
            }
        }

        // 2. ObfuscatedTraffic: 混淆流量特征
        if has_obfuscation_patterns(&parsed.payload) && parsed.payload.len() > 50 {
            results.push(RiskResult::new(
                RiskFlag::ObfuscatedTraffic,
                RiskSeverity::High,
                format!("Obfuscated traffic pattern detected ({} bytes)", parsed.payload.len()),
            ));
        }

        results
    }

    fn analyze_flow(&self, flow: &Flow) -> Vec<RiskResult> {
        let mut results = Vec::new();

        // 3. UnidirectionalTraffic: 流量单向
        let is_unidirectional = flow.stats.packets <= 3
            && flow.protocol.is_none()
            && flow.packets_seen > 0;

        if is_unidirectional {
            results.push(RiskResult::new(
                RiskFlag::UnidirectionalTraffic,
                RiskSeverity::Medium,
                format!("Unidirectional traffic: {} packets, no response", flow.packets_seen),
            ));
        }

        // 4. ProbingAttempt: 探测尝试
        let is_probe = flow.stats.packets <= 2
            && flow.protocol.is_none()
            && flow.packets_seen > 0;

        if is_probe {
            results.push(RiskResult::new(
                RiskFlag::ProbingAttempt,
                RiskSeverity::High,
                format!("Probing attempt: {} packet(s) to port {}",
                    flow.packets_seen, flow.key.dst_port),
            ));
        }

        // 5. PeriodicFlow: 需要包时间戳历史
        // 暂不实现 — 需要 Flow 中存储包间隔信息

        results
    }
}

fn is_encrypted_protocol(p: Option<crate::core::types::Protocol>) -> bool {
    match p {
        Some(crate::core::types::Protocol::Tls
            | crate::core::types::Protocol::Quic
            | crate::core::types::Protocol::Http3) => true,
        #[cfg(feature = "vpn")]
        Some(crate::core::types::Protocol::WireGuard
            | crate::core::types::Protocol::OpenVpn) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::flow::Flow;
    use crate::core::types::{FlowKey, TransportProto};

    fn make_flow() -> Flow {
        Flow::new(FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 54321, dst_port: 80,
            transport: TransportProto::Tcp,
        })
    }

    fn make_parsed(payload: Vec<u8>) -> ParsedPacket {
        ParsedPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 54321, dst_port: 80,
            transport: TransportProto::Tcp, payload,
        }
    }

    #[test]
    fn test_binary_data_detection() {
        let proc = BehavioralRiskProcessor::new();
        // Binary payload with many non-printable bytes
        let header = b"HTTP/1.1 header ";
        let mut payload = vec![0u8; 200];
        for i in 0..5 { payload[i*16..(i+1)*16].copy_from_slice(header); }
        let (p, f) = (make_parsed(payload), make_flow());
        let risks = proc.analyze_packet(&p, &f);
        assert!(risks.iter().any(|r| r.flag == RiskFlag::BinaryDataTransfer));
    }

    #[test]
    fn test_obfuscated_traffic() {
        let proc = BehavioralRiskProcessor::new();
        // Mixed printable/non-printable: first 20 bytes have ~50% ratio
        let mut payload = vec![0u8; 100];
        for i in 0..8 { payload[i] = b'A'; }  // 8 printable in first 20
        for i in 8..20 { payload[i] = 0x00; }  // 12 non-printable in first 20
        // ratio = 8/20 = 0.4 which is between 0.3 and 0.7
        for i in 50..100 { payload[i] = 0xFF; } // uniform pattern
        let (p, f) = (make_parsed(payload), make_flow());
        let risks = proc.analyze_packet(&p, &f);
        assert!(risks.iter().any(|r| r.flag == RiskFlag::ObfuscatedTraffic));
    }

    #[test]
    fn test_unidirectional_flow() {
        let proc = BehavioralRiskProcessor::new();
        let mut flow = make_flow();
        flow.packets_seen = 1;
        flow.stats.packets = 1;
        // protocol is None (not identified)
        let risks = proc.analyze_flow(&flow);
        assert!(risks.iter().any(|r| r.flag == RiskFlag::UnidirectionalTraffic));
    }

    #[test]
    fn test_probing_attempt() {
        let proc = BehavioralRiskProcessor::new();
        let mut flow = make_flow();
        flow.packets_seen = 1;
        flow.stats.packets = 1;
        let risks = proc.analyze_flow(&flow);
        assert!(risks.iter().any(|r| r.flag == RiskFlag::ProbingAttempt));
    }

    #[test]
    fn test_established_flow_no_behavioral_risk() {
        let proc = BehavioralRiskProcessor::new();
        let mut flow = make_flow();
        flow.packets_seen = 10;
        flow.stats.packets = 10;
        flow.protocol = Some(crate::core::types::Protocol::Http);
        let risks = proc.analyze_flow(&flow);
        assert!(!risks.iter().any(|r| r.flag == RiskFlag::ProbingAttempt));
        assert!(!risks.iter().any(|r| r.flag == RiskFlag::UnidirectionalTraffic));
    }


    #[test]
    fn test_clean_text_no_binary() {
        let proc = BehavioralRiskProcessor::new();
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let (p, f) = (make_parsed(payload), make_flow());
        let risks = proc.analyze_packet(&p, &f);
        assert!(!risks.iter().any(|r| r.flag == RiskFlag::BinaryDataTransfer));
    }
}
