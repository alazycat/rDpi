//! SMB risk processor (`feature: smb`)
//!
//! SMBv1 是已知不安全版本（WannaCry/EternalBlue）；nDPI 5.0 以
//! `NDPI_SMB_INSECURE_VERSION`（HIGH）报告。

use crate::core::flow::Flow;
use crate::core::types::Protocol;
use crate::parser::ParsedPacket;
use crate::protocols::smb::parser;
use crate::risk::RiskProcessor;
use crate::risk::types::{RiskFlag, RiskResult, RiskSeverity};

pub struct SmbRiskProcessor;

impl SmbRiskProcessor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SmbRiskProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskProcessor for SmbRiskProcessor {
    fn name(&self) -> &'static str {
        "smb_risk"
    }

    fn analyze_packet(&self, parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
        if flow.protocol != Some(Protocol::Smb1) {
            return Vec::new();
        }
        if parser::is_smb1_trans(&parsed.payload) {
            return Vec::new();
        }
        if flow
            .risks
            .iter()
            .any(|risk| risk.flag == RiskFlag::SmbInsecureVersion)
        {
            return Vec::new();
        }
        // 对齐 nDPI 5.0 golden：SMBv1 流同时触发 unsafe_protocol（协议不安全）
        // 与 smb_insecure_version（版本已知漏洞面）
        vec![
            RiskResult::new(
                RiskFlag::UnsafeProtocol,
                RiskSeverity::High,
                "SMBv1 is an unsafe protocol",
            ),
            RiskResult::new(
                RiskFlag::SmbInsecureVersion,
                RiskSeverity::High,
                "SMBv1 is insecure and vulnerable to known exploits",
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{FlowKey, TransportProto};

    fn flow(protocol: Protocol) -> Flow {
        let mut flow = Flow::new(FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 50000,
            dst_port: 445,
            transport: TransportProto::Tcp,
        });
        flow.protocol = Some(protocol);
        flow
    }

    fn parsed(payload: &[u8]) -> ParsedPacket {
        ParsedPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 50000,
            dst_port: 445,
            transport: TransportProto::Tcp,
            payload: payload.to_vec(),
            tcp: None,
            ttl: 0,
        }
    }

    fn smb1(command: u8) -> Vec<u8> {
        let mut smb = b"\xFFSMB".to_vec();
        smb.push(command);
        smb.extend_from_slice(&0u32.to_le_bytes());
        smb.resize(32, 0);
        let length = smb.len();
        let mut out = vec![0x00, (length >> 16) as u8, (length >> 8) as u8, length as u8];
        out.extend_from_slice(&smb);
        out
    }

    #[test]
    fn smb1_flow_reports_insecure_version() {
        let processor = SmbRiskProcessor::new();
        let risks = processor.analyze_packet(&parsed(&smb1(0x73)), &flow(Protocol::Smb1));
        assert!(risks
            .iter()
            .any(|risk| risk.flag == RiskFlag::SmbInsecureVersion));
    }

    #[test]
    fn smb23_flow_does_not_report() {
        let processor = SmbRiskProcessor::new();
        let risks = processor.analyze_packet(&parsed(&smb1(0x73)), &flow(Protocol::Smb23));
        assert!(risks.is_empty());
    }

    #[test]
    fn smb1_trans_does_not_report() {
        let processor = SmbRiskProcessor::new();
        let risks = processor.analyze_packet(&parsed(&smb1(0x25)), &flow(Protocol::Smb1));
        assert!(risks.is_empty());
    }

    #[test]
    fn existing_risk_is_not_duplicated() {
        let processor = SmbRiskProcessor::new();
        let mut flow = flow(Protocol::Smb1);
        flow.risks.push(RiskResult::new(
            RiskFlag::SmbInsecureVersion,
            RiskSeverity::High,
            "existing",
        ));
        let risks = processor.analyze_packet(&parsed(&smb1(0x73)), &flow);
        assert!(risks.is_empty());
    }
}
