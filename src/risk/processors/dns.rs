//! DNS anomaly risk processors
//!
//! Detects DNS-related risks using payload inspection.

use crate::core::flow::Flow;
use crate::core::types::Protocol;
use crate::risk::types::{RiskFlag, RiskResult, RiskSeverity};
use crate::parser::ParsedPacket;
use crate::risk::RiskProcessor;

/// DNS 异常风险处理器
pub struct DnsRiskProcessor;

impl DnsRiskProcessor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DnsRiskProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskProcessor for DnsRiskProcessor {
    fn name(&self) -> &'static str {
        "dns_risk"
    }

    fn analyze_packet(&self, parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
        if flow.protocol != Some(Protocol::Dns) {
            return vec![];
        }

        let mut results = Vec::new();

        // 1. DnsLargePacket: DNS 响应过大
        if parsed.payload.len() > 512 {
            results.push(RiskResult::new(
                RiskFlag::DnsLargePacket,
                RiskSeverity::Medium,
                format!(
                    "Large DNS response: {} bytes (exceeds 512 byte limit)",
                    parsed.payload.len()
                ),
            ));
        }

        // 2. DnsFragmented: 需要 IP 层碎片信息
        // ParsedPacket 当前未暴露 IP 碎片标志，暂不实现
        // 未来可通过扩展 ParsedPacket 增加 ip_flags 字段

        results
    }

    fn analyze_flow(&self, _flow: &Flow) -> Vec<RiskResult> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::flow::Flow;
    use crate::core::types::{FlowKey, TransportProto};

    fn make_dns_flow(payload_size: usize) -> (ParsedPacket, Flow) {
        let mut flow = Flow::new(FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 12345, dst_port: 53,
            transport: TransportProto::Udp,
        });
        flow.protocol = Some(Protocol::Dns);
        let parsed = ParsedPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 12345, dst_port: 53,
            transport: TransportProto::Udp,
            payload: vec![0u8; payload_size],
        };
        (parsed, flow)
    }

    fn make_non_dns_flow() -> (ParsedPacket, Flow) {
        let flow = Flow::new(FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 12345, dst_port: 80,
            transport: TransportProto::Tcp,
        });
        let parsed = ParsedPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 12345, dst_port: 80,
            transport: TransportProto::Tcp,
            payload: vec![0u8; 1024],
        };
        (parsed, flow)
    }

    #[test]
    fn test_dns_large_packet() {
        let proc = DnsRiskProcessor::new();
        let (parsed, flow) = make_dns_flow(1024);
        let risks = proc.analyze_packet(&parsed, &flow);
        assert!(risks.iter().any(|r| r.flag == RiskFlag::DnsLargePacket));
    }

    #[test]
    fn test_dns_small_packet_no_risk() {
        let proc = DnsRiskProcessor::new();
        let (parsed, flow) = make_dns_flow(200);
        let risks = proc.analyze_packet(&parsed, &flow);
        assert!(!risks.iter().any(|r| r.flag == RiskFlag::DnsLargePacket));
    }

    #[test]
    fn test_non_dns_no_risk() {
        let proc = DnsRiskProcessor::new();
        let (parsed, flow) = make_non_dns_flow();
        let risks = proc.analyze_packet(&parsed, &flow);
        assert!(risks.is_empty());
    }
}
