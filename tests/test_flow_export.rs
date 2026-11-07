//! P0 差分链路：rDpi per-flow 归一化导出测试
//!
//! 依赖 `json` feature（serde/serde_json）。默认 features 下本测试不编译。

#![cfg(feature = "json")]

use rdpi::Detector;
use rdpi::core::flow::Flow;
use rdpi::core::types::{
    Application, Confidence, FlowKey, Metadata, Protocol, TlsMetadata, TransportProto,
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
    assert_eq!(normalized.category.as_deref(), Some("WebTunnel"));
    assert_eq!(normalized.breed.as_deref(), Some("Safe"));
    assert_eq!(normalized.confidence.as_deref(), Some("Dpi"));
    assert_eq!(normalized.protocol_stack, vec!["Tls".to_string()]);
    assert!(normalized.risk_mask.is_empty());

    let json = serde_json::to_string(&normalized).unwrap();
    assert!(json.contains("\"master_protocol\":\"Tls\""));
    assert!(json.contains("\"app_protocol\":\"YouTube\""));
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
    assert_eq!(flow.category.as_deref(), Some("Dns"));
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
