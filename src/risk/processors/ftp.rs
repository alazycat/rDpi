//! FTP risk processor (`feature: proto3`)
//!
//! FTP 以明文传输命令与凭据。nDPI 5.0 对 FTP 流报告 `Unsafe Protocol` 与
//! `Clear-Text Credentials`；rDpi 在此对齐这两个确定性风险。

use crate::core::flow::Flow;
use crate::core::types::Protocol;
use crate::parser::ParsedPacket;
use crate::risk::RiskProcessor;
use crate::risk::types::{RiskFlag, RiskResult, RiskSeverity};

/// FTP 风险处理器
pub struct FtpRiskProcessor;

impl FtpRiskProcessor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FtpRiskProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// 明文凭据命令（RFC 959：USER/PASS/ACCT）
const CREDENTIAL_COMMANDS: &[&[u8]] = &[b"USER ", b"PASS ", b"ACCT "];

fn is_credential_command(payload: &[u8]) -> bool {
    CREDENTIAL_COMMANDS.iter().any(|command| {
        payload.len() >= command.len() && payload[..command.len()].eq_ignore_ascii_case(command)
    })
}

impl RiskProcessor for FtpRiskProcessor {
    fn name(&self) -> &'static str {
        "ftp_risk"
    }

    fn analyze_packet(&self, parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
        if flow.protocol != Some(Protocol::Ftp) {
            return Vec::new();
        }

        let mut results = Vec::new();

        // FTP 控制/数据连接均为明文；risk 在流生命周期内只上报一次
        if !flow
            .risks
            .iter()
            .any(|risk| risk.flag == RiskFlag::UnsafeProtocol)
        {
            results.push(RiskResult::new(
                RiskFlag::UnsafeProtocol,
                RiskSeverity::High,
                "FTP transmits commands and data in cleartext",
            ));
        }

        if is_credential_command(&parsed.payload)
            && !flow
                .risks
                .iter()
                .any(|risk| risk.flag == RiskFlag::ClearTextCredentials)
        {
            results.push(RiskResult::new(
                RiskFlag::ClearTextCredentials,
                RiskSeverity::Critical,
                "FTP USER/PASS/ACCT command carries credentials in cleartext",
            ));
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{FlowKey, TransportProto};

    fn make_ftp_flow() -> Flow {
        let mut flow = Flow::new(FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 50002,
            dst_port: 21,
            transport: TransportProto::Tcp,
        });
        flow.protocol = Some(Protocol::Ftp);
        flow
    }

    fn make_parsed(payload: &[u8]) -> ParsedPacket {
        ParsedPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 50002,
            dst_port: 21,
            transport: TransportProto::Tcp,
            payload: payload.to_vec(),
            tcp: None,
            ttl: 0,
        }
    }

    #[test]
    fn ftp_flow_reports_unsafe_protocol() {
        let proc = FtpRiskProcessor::new();
        let flow = make_ftp_flow();
        let risks = proc.analyze_packet(&make_parsed(b"220 ready\r\n"), &flow);
        assert!(
            risks
                .iter()
                .any(|risk| risk.flag == RiskFlag::UnsafeProtocol)
        );
    }

    #[test]
    fn user_and_pass_report_clear_text_credentials() {
        let proc = FtpRiskProcessor::new();
        let flow = make_ftp_flow();
        for payload in [
            b"USER anonymous\r\n".as_slice(),
            b"pass anonymous@example.com\r\n".as_slice(),
            b"ACCT billing\r\n".as_slice(),
        ] {
            let risks = proc.analyze_packet(&make_parsed(payload), &flow);
            assert!(
                risks
                    .iter()
                    .any(|risk| risk.flag == RiskFlag::ClearTextCredentials),
                "payload {payload:?} must report clear-text credentials"
            );
        }
    }

    #[test]
    fn server_banner_has_no_clear_text_credentials() {
        let proc = FtpRiskProcessor::new();
        let flow = make_ftp_flow();
        let risks = proc.analyze_packet(&make_parsed(b"220 (vsFTPd 3.0.5)\r\n"), &flow);
        assert!(
            !risks
                .iter()
                .any(|risk| risk.flag == RiskFlag::ClearTextCredentials)
        );
    }

    #[test]
    fn risks_already_on_flow_are_not_duplicated() {
        let proc = FtpRiskProcessor::new();
        let mut flow = make_ftp_flow();
        flow.risks.push(RiskResult::new(
            RiskFlag::UnsafeProtocol,
            RiskSeverity::High,
            "existing",
        ));
        flow.risks.push(RiskResult::new(
            RiskFlag::ClearTextCredentials,
            RiskSeverity::Critical,
            "existing",
        ));
        let risks = proc.analyze_packet(&make_parsed(b"PASS secret\r\n"), &flow);
        assert!(risks.is_empty());
    }

    #[test]
    fn non_ftp_flow_is_ignored() {
        let proc = FtpRiskProcessor::new();
        let mut flow = make_ftp_flow();
        flow.protocol = Some(Protocol::Http);
        let risks = proc.analyze_packet(&make_parsed(b"USER anonymous\r\n"), &flow);
        assert!(risks.is_empty());
    }
}
