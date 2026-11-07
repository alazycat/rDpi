//! P0 差分链路：rDpi per-flow 归一化导出测试
//!
//! 依赖 `json` feature（serde/serde_json）。默认 features 下本测试不编译。

#![cfg(feature = "json")]

use rdpi::Detector;
use rdpi::core::flow::Flow;
use rdpi::core::types::{
    Application, Confidence, DnsMetadata, FlowKey, Metadata, Protocol, TlsMetadata, TransportProto,
};
use rdpi::parity::NormalizedFlow;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};

fn key() -> FlowKey {
    FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: 12345,
        dst_port: 443,
        transport: TransportProto::Tcp,
    }
}

fn make_dns_query_payload() -> Vec<u8> {
    let mut packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in ["example", "com"] {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    packet
}

fn make_eth_udp(dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = (20 + 8 + payload.len()) as u16;
    let udp_len = (8 + payload.len()) as u16;
    let mut packet = vec![
        // Ethernet
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55, // dst MAC
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb, // src MAC
        0x08,
        0x00, // IPv4
        // IPv4
        0x45,
        0x00,
        (total_len >> 8) as u8,
        (total_len & 0xff) as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        0x40,
        0x11,
        0x00,
        0x00,
        192,
        168,
        1,
        1,
        10,
        0,
        0,
        1,
        // UDP
        (12345u16 >> 8) as u8,
        (12345u16 & 0xff) as u8,
        (dst_port >> 8) as u8,
        (dst_port & 0xff) as u8,
        (udp_len >> 8) as u8,
        (udp_len & 0xff) as u8,
        0x00,
        0x00,
    ];
    packet.extend_from_slice(payload);
    packet
}

#[test]
fn normalized_flow_maps_protocol_metadata_and_stack() {
    let mut flow = Flow::new(key());
    flow.protocol = Some(Protocol::Tls);
    flow.confidence = Some(Confidence::Dpi);
    flow.metadata = Some(Metadata::Tls(TlsMetadata {
        sni: Some("www.youtube.com".to_string()),
        application: Some(Application::YouTube),
        ..Default::default()
    }));
    flow.protocol_stack.push(Protocol::Tls);

    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.src_ip, "10.0.0.1");
    assert_eq!(normalized.dst_ip, "10.0.0.2");
    assert_eq!(normalized.src_port, 12345);
    assert_eq!(normalized.dst_port, 443);
    assert_eq!(normalized.transport, "tcp");
    assert_eq!(normalized.master_protocol.as_deref(), Some("Tls"));
    assert_eq!(normalized.app_protocol.as_deref(), Some("YouTube"));
    // category/breed 以 nDPI 5.0 兼容名称导出（YouTube → Media/Fun）
    assert_eq!(normalized.category.as_deref(), Some("Media"));
    assert_eq!(normalized.breed.as_deref(), Some("Fun"));
    assert_eq!(normalized.confidence.as_deref(), Some("Dpi"));
    assert_eq!(normalized.protocol_stack, vec!["Tls".to_string()]);
    assert!(normalized.risk_mask.is_empty());

    let json = serde_json::to_string(&normalized).unwrap();
    assert!(json.contains("\"master_protocol\":\"Tls\""));
    assert!(json.contains("\"app_protocol\":\"YouTube\""));
}

#[test]
fn dns_keeps_master_taxonomy_even_with_application() {
    // nDPI 对 DNS 查询不产出 app 层分类，category/breed 固定在 master 上；
    // rDpi 仍保留应用识别结果，但导出分类应与 nDPI 对齐。
    let mut flow = Flow::new(key());
    flow.protocol = Some(Protocol::Dns);
    flow.metadata = Some(Metadata::Dns(DnsMetadata {
        query_domain: Some("youtube.com".to_string()),
        application: Some(Application::YouTube),
    }));

    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.app_protocol.as_deref(), Some("YouTube"));
    assert_eq!(normalized.category.as_deref(), Some("Network"));
    assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
}

#[test]
fn uncovered_protocol_falls_back_to_native_taxonomy() {
    // QUIC 尚未纳入已验证映射表：导出使用 rDpi 原生分类名
    let mut flow = Flow::new(key());
    flow.protocol = Some(Protocol::Quic);

    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.category.as_deref(), Some("WebTunnel"));
    assert_eq!(normalized.breed.as_deref(), Some("Safe"));
}

#[test]
fn detector_exports_classified_flow() {
    let mut detector = Detector::new();
    let packet = make_eth_udp(53, &make_dns_query_payload());
    detector
        .detect_at(&packet, SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .unwrap();

    let flows = detector.normalized_flows();
    assert_eq!(flows.len(), 1);
    let flow = &flows[0];
    assert_eq!(flow.master_protocol.as_deref(), Some("Dns"));
    assert_eq!(flow.category.as_deref(), Some("Network"));
    assert_eq!(flow.breed.as_deref(), Some("Acceptable"));
    assert_eq!(flow.confidence.as_deref(), Some("Dpi"));
    assert_eq!(flow.src_port, 12345);
    assert_eq!(flow.dst_port, 53);
    assert_eq!(flow.transport, "udp");
    assert_eq!(flow.protocol_stack, vec!["Dns".to_string()]);
}

#[test]
fn detector_exports_unclassified_flow_with_none_fields() {
    let mut detector = Detector::new();
    let packet = make_eth_udp(9999, b"\x00\x01\x02");
    detector
        .detect_at(&packet, SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .unwrap();

    let flows = detector.normalized_flows();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].master_protocol, None);
    assert_eq!(flows[0].confidence, None);
    assert!(flows[0].protocol_stack.is_empty());
}

#[cfg(feature = "risk")]
#[test]
fn detector_export_includes_risk_mask() {
    let mut detector = Detector::new();
    let query = make_eth_udp(53, &make_dns_query_payload());
    detector
        .detect_at(&query, SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .unwrap();
    let large = make_eth_udp(53, &[0u8; 600]);
    detector
        .detect_at(&large, SystemTime::UNIX_EPOCH + Duration::from_secs(2))
        .unwrap();

    let flows = detector.normalized_flows();
    assert_eq!(flows.len(), 1);
    assert!(
        flows[0]
            .risk_mask
            .iter()
            .any(|risk| risk == "dns_large_packet"),
        "risk mask must contain the DNS large packet flag"
    );
}

/// risk_mask 导出为 nDPI 5.0 风险名并去重（真实 ndpiReader 输出：
/// rDpi `tls_missing_sni` 对应 nDPI "Missing SNI TLS Extn"；
/// 同一风险可能因逐包分析重复累积）
#[cfg(feature = "risk")]
#[test]
fn risk_mask_exports_ndpi_names_and_deduplicates() {
    use rdpi::risk::{RiskFlag, RiskResult, RiskSeverity};

    let mut flow = Flow::new(key());
    flow.risks.push(RiskResult::new(
        RiskFlag::TlsMissingSni,
        RiskSeverity::Medium,
        "first",
    ));
    flow.risks.push(RiskResult::new(
        RiskFlag::TlsMissingSni,
        RiskSeverity::Medium,
        "duplicate",
    ));
    flow.risks.push(RiskResult::new(
        RiskFlag::UnsafeProtocol,
        RiskSeverity::High,
        "unsafe",
    ));

    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(
        normalized.risk_mask,
        vec![
            "missing_sni_tls_extn".to_string(),
            "unsafe_protocol".to_string()
        ]
    );
}

/// P0：企业协议的 nDPI 5.0 兼容分类名（用真实 ndpiReader 5.0 输出验证）
#[test]
fn ndpi_compat_enterprise_taxonomy() {
    fn export(protocol: Protocol) -> NormalizedFlow {
        let mut flow = Flow::new(key());
        flow.protocol = Some(protocol);
        flow.confidence = Some(Confidence::Dpi);
        NormalizedFlow::from_flow(&flow)
    }

    let cases = [
        (Protocol::Ssh, "Ssh", "RemoteAccess", "Acceptable"),
        (Protocol::Smtp, "Smtp", "Email", "Acceptable"),
        (Protocol::Ntp, "Ntp", "System", "Acceptable"),
        (Protocol::Dhcp, "Dhcp", "Network", "Acceptable"),
        (Protocol::Snmp, "Snmp", "Network", "Acceptable"),
        (Protocol::Modbus, "Modbus", "IoT-Scada", "Acceptable"),
        (Protocol::Mysql, "Mysql", "Database", "Acceptable"),
        (Protocol::Postgresql, "Postgresql", "Database", "Acceptable"),
        (Protocol::Redis, "RESP", "Database", "Acceptable"),
    ];
    for (protocol, master, category, breed) in cases {
        let flow = export(protocol);
        assert_eq!(
            flow.master_protocol.as_deref(),
            Some(master),
            "{protocol:?}"
        );
        assert_eq!(flow.category.as_deref(), Some(category), "{protocol:?}");
        assert_eq!(flow.breed.as_deref(), Some(breed), "{protocol:?}");
    }

    #[cfg(feature = "proto3")]
    {
        let flow = export(Protocol::Ftp);
        assert_eq!(flow.master_protocol.as_deref(), Some("FTP_CONTROL"));
        assert_eq!(flow.category.as_deref(), Some("Download"));
        assert_eq!(flow.breed.as_deref(), Some("Unsafe"));

        let flow = export(Protocol::Sip);
        assert_eq!(flow.category.as_deref(), Some("VoIP"));
        assert_eq!(flow.breed.as_deref(), Some("Acceptable"));
    }

    #[cfg(feature = "iot")]
    {
        let flow = export(Protocol::Mqtt);
        assert_eq!(flow.category.as_deref(), Some("RPC"));
        assert_eq!(flow.breed.as_deref(), Some("Acceptable"));
    }
}
