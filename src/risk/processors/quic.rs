//! QUIC security risk processors
//!
//! Detects QUIC-related risks from packet-level signals (long header type /
//! version 字段)，不依赖解密——0-RTT 与非标准版本在包头即可判定。
//! Retry 完整性校验（RFC 9001 §5.8）需要 ODCID：仅当流元数据中已有客户端
//! Initial 的 DCID 时才校验（缺 ODCID 或版本不支持时返回 None，不报警）。

use crate::core::flow::Flow;
use crate::core::types::{Metadata, TransportProto};
use crate::parser::ParsedPacket;
use crate::protocols::quic::{
    QUIC_VERSION_DRAFT28, QUIC_VERSION_DRAFT29, parse_quic_version, parse_retry_packet,
    verify_retry_integrity,
};
use crate::risk::RiskProcessor;
use crate::risk::types::{RiskFlag, RiskResult, RiskSeverity};

/// 该流上是否已产出过指定 flag（逐包处理器按流去重，避免 flow.risks 膨胀）
fn already_flagged(flow: &Flow, flag: RiskFlag) -> bool {
    flow.risks.iter().any(|r| r.flag == flag)
}

/// QUIC 安全风险处理器
///
/// 逐包分析 QUIC 长包头（仅 UDP）：
/// - 0-RTT 包（Long Header type=01）→ [`RiskFlag::QuicZeroRtt`]（0-RTT 数据可重放，常被用于绕过防护）
/// - Initial 包使用 draft-28/29 版本 → [`RiskFlag::QuicNonStandardVersion`]（非标准版本指纹）
/// - Retry 包完整性标签校验失败（RFC 9001 §5.8）→ [`RiskFlag::QuicRetryIntegrityFail`]。
///   仅当流上已有客户端 Initial 元数据（ODCID 可用）且版本为 v1/v2 时才校验；
///   校验无法判定（`None`）时不产出，避免对抓包起点晚于 Retry 或非标准版本的流误报。
pub struct QuicRiskProcessor;

impl QuicRiskProcessor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for QuicRiskProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskProcessor for QuicRiskProcessor {
    fn name(&self) -> &'static str {
        "quic_risk"
    }

    fn analyze_packet(&self, parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
        if parsed.transport != TransportProto::Udp || parsed.payload.is_empty() {
            return vec![];
        }
        let first = parsed.payload[0];
        let mut results = Vec::new();

        // 1. QuicZeroRtt: Long Header + 0-RTT 类型（bits 5-4 = 01 → 0xD0）
        if (first & 0xF0) == 0xD0 {
            if !already_flagged(flow, RiskFlag::QuicZeroRtt) {
                results.push(RiskResult::new(
                    RiskFlag::QuicZeroRtt,
                    RiskSeverity::Medium,
                    "QUIC 0-RTT packet observed — early data is replayable and may bypass controls",
                ));
            }
            return results;
        }

        // 2. QuicNonStandardVersion: Initial 包携带 draft-28/29 版本号
        if (first & 0xF0) == 0xC0
            && !already_flagged(flow, RiskFlag::QuicNonStandardVersion)
            && let Some(v) = parse_quic_version(&parsed.payload)
            && (v == QUIC_VERSION_DRAFT29 || v == QUIC_VERSION_DRAFT28)
        {
            results.push(RiskResult::new(
                RiskFlag::QuicNonStandardVersion,
                RiskSeverity::Low,
                "QUIC Initial with non-standard draft version (draft-28/29)",
            ));
        }

        // 3. QuicRetryIntegrityFail: Retry 包完整性标签校验失败（RFC 9001 §5.8）
        //    ODCID 取自流元数据（客户端 Initial 的 DCID）；无元数据/版本不支持时
        //    verify_retry_integrity 返回 None，跳过判定。
        if parse_retry_packet(&parsed.payload).is_some()
            && let Some(odcid) = flow.metadata.as_ref().and_then(|m| match m {
                Metadata::Quic(q) => q.destination_connection_id.clone(),
                _ => None,
            })
            && verify_retry_integrity(&parsed.payload, &odcid) == Some(false)
            && !already_flagged(flow, RiskFlag::QuicRetryIntegrityFail)
        {
            results.push(RiskResult::new(
                RiskFlag::QuicRetryIntegrityFail,
                RiskSeverity::Medium,
                "QUIC Retry packet failed integrity verification (RFC 9001 §5.8) — \
                 packet may be forged or injected",
            ));
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::flow::Flow;
    use crate::core::types::{FlowKey, QuicMetadata};
    use std::net::IpAddr;

    /// Retry 包 golden 向量（与 quic/parser.rs 测试同源：Node OpenSSL 独立生成）
    const RETRY_V1_GOOD: &str = "f000000001041122334408aabbccddeeff0102202122232425262728292a2b2c2d2e2f\
303132333435363738393a3b3c3d3e3f4041424355a0da97d3ec181617daab18fc9a0334";
    /// ODCID = 0102030405060708（触发 Retry 的客户端 Initial 的 DCID）
    const ODCID: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    fn retry_good() -> Vec<u8> {
        (0..RETRY_V1_GOOD.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&RETRY_V1_GOOD[i..i + 2], 16).unwrap())
            .collect()
    }

    fn retry_tampered() -> Vec<u8> {
        let mut data = retry_good();
        let last = data.len() - 1;
        data[last] ^= 0x01;
        data
    }

    fn flow_with_odcid() -> Flow {
        let mut flow = udp_flow();
        flow.metadata = Some(Metadata::Quic(QuicMetadata {
            sni: None,
            alpn: None,
            ja4: None,
            version: Some("00000001".to_string()),
            destination_connection_id: Some(ODCID.to_vec()),
            application: None,
            transport_parameters: None,
        }));
        flow
    }

    fn udp_flow() -> Flow {
        Flow::new(FlowKey {
            src_ip: IpAddr::from([10, 0, 0, 1]),
            dst_ip: IpAddr::from([10, 0, 0, 2]),
            src_port: 12345,
            dst_port: 443,
            transport: TransportProto::Udp,
        })
    }

    fn udp_packet(payload: &[u8]) -> ParsedPacket {
        ParsedPacket {
            src_ip: IpAddr::from([10, 0, 0, 1]),
            dst_ip: IpAddr::from([10, 0, 0, 2]),
            src_port: 12345,
            dst_port: 443,
            transport: TransportProto::Udp,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn test_zero_rtt_flagged_once_per_flow() {
        let proc = QuicRiskProcessor::new();
        let flow = udp_flow();
        // 0-RTT 长包头（bits 7-6 = 11, bits 5-4 = 01）
        let pkt = udp_packet(&[0xD0, 0x00, 0x00, 0x00, 0x01]);

        let risks = proc.analyze_packet(&pkt, &flow);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].flag, RiskFlag::QuicZeroRtt);
        assert_eq!(risks[0].severity, RiskSeverity::Medium);

        // 流上已记录后不再重复产出（按流去重）
        let mut flow2 = udp_flow();
        flow2.risks.extend(risks);
        assert!(proc.analyze_packet(&pkt, &flow2).is_empty());
    }

    #[test]
    fn test_draft_version_flagged() {
        let proc = QuicRiskProcessor::new();
        let flow = udp_flow();
        // draft-29 Initial
        let pkt = udp_packet(&[0xC0, 0xff, 0x00, 0x00, 0x1d]);
        let risks = proc.analyze_packet(&pkt, &flow);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].flag, RiskFlag::QuicNonStandardVersion);
        assert_eq!(risks[0].severity, RiskSeverity::Low);

        // draft-28 Initial
        let pkt = udp_packet(&[0xC0, 0xff, 0x00, 0x00, 0x1c]);
        let mut flow3 = udp_flow();
        assert_eq!(proc.analyze_packet(&pkt, &flow3).len(), 1);
        flow3.risks.push(RiskResult::new(
            RiskFlag::QuicNonStandardVersion,
            RiskSeverity::Low,
            "x",
        ));
        assert!(proc.analyze_packet(&pkt, &flow3).is_empty());
    }

    #[test]
    fn test_standard_initial_no_risk() {
        let proc = QuicRiskProcessor::new();
        let flow = udp_flow();
        // QUIC v1 Initial：无风险信号
        let pkt = udp_packet(&[0xC0, 0x00, 0x00, 0x00, 0x01]);
        assert!(proc.analyze_packet(&pkt, &flow).is_empty());

        // 短包头（0x40）：非长包头，不判定
        let pkt = udp_packet(&[0x40, 0x00, 0x00, 0x00, 0x01]);
        assert!(proc.analyze_packet(&pkt, &flow).is_empty());
    }

    #[test]
    fn test_non_udp_ignored() {
        let proc = QuicRiskProcessor::new();
        let mut flow = udp_flow();
        flow.key.transport = TransportProto::Tcp;
        let mut pkt = udp_packet(&[0xD0, 0x00, 0x00, 0x00, 0x01]);
        pkt.transport = TransportProto::Tcp;
        assert!(proc.analyze_packet(&pkt, &flow).is_empty());

        // 空 payload
        let pkt = udp_packet(&[]);
        assert!(proc.analyze_packet(&pkt, &udp_flow()).is_empty());
    }

    #[test]
    fn test_retry_integrity_fail_flagged_once() {
        let proc = QuicRiskProcessor::new();
        let flow = flow_with_odcid();
        let pkt = udp_packet(&retry_tampered());

        let risks = proc.analyze_packet(&pkt, &flow);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].flag, RiskFlag::QuicRetryIntegrityFail);
        assert_eq!(risks[0].severity, RiskSeverity::Medium);

        // 按流去重：同流第二次不再产出
        let mut flow2 = flow_with_odcid();
        flow2.risks.extend(risks);
        assert!(proc.analyze_packet(&pkt, &flow2).is_empty());
    }

    #[test]
    fn test_retry_integrity_ok_no_flag() {
        let proc = QuicRiskProcessor::new();
        // 合法 Retry：校验通过，无风险信号
        let pkt = udp_packet(&retry_good());
        assert!(proc.analyze_packet(&pkt, &flow_with_odcid()).is_empty());
    }

    #[test]
    fn test_retry_without_odcid_no_flag() {
        let proc = QuicRiskProcessor::new();
        // 流上无 Initial 元数据（抓包起点晚于 Retry）：无法判定，不报警
        let pkt = udp_packet(&retry_tampered());
        assert!(proc.analyze_packet(&pkt, &udp_flow()).is_empty());

        // 元数据非 QUIC 类型：同样跳过
        let mut flow = udp_flow();
        flow.metadata = Some(Metadata::Tls(Default::default()));
        assert!(proc.analyze_packet(&pkt, &flow).is_empty());
    }
}
