//! F44 Task 6：parity 导出映射测试（feature: json）
//!
//! 验证新协议变体在归一化导出中的 nDPI 兼容命名与分类映射。

#![cfg(feature = "json")]

use rdpi::core::flow::Flow;
use rdpi::core::types::{Confidence, FlowKey, Protocol, TransportProto};
use rdpi::parity::NormalizedFlow;
use std::net::{IpAddr, Ipv4Addr};

fn flow_with_protocol(protocol: Protocol) -> Flow {
    let key = FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: 50000,
        dst_port: 443,
        transport: TransportProto::Tcp,
    };
    let mut flow = Flow::new(key);
    flow.protocol = Some(protocol);
    flow.confidence = Some(Confidence::Dpi);
    flow
}

#[test]
fn test_protocol_name_http_connect_proxy() {
    let flow = flow_with_protocol(Protocol::HttpConnect);
    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.master_protocol.as_deref(), Some("HTTP_CONNECT"));
    assert_eq!(normalized.category.as_deref(), Some("Web"));
    assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));

    let flow = flow_with_protocol(Protocol::HttpProxy);
    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.master_protocol.as_deref(), Some("HTTP_PROXY"));
    assert_eq!(normalized.category.as_deref(), Some("Web"));
    assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
}

#[test]
fn test_protocol_name_doh_dot_doq() {
    for (protocol, expected) in [
        (Protocol::Doh, "DNSoverHTTPS"),
        (Protocol::Dot, "DNSoverTLS"),
        (Protocol::Doq, "DNSoverQUIC"),
    ] {
        let flow = flow_with_protocol(protocol);
        let normalized = NormalizedFlow::from_flow(&flow);
        assert_eq!(normalized.master_protocol.as_deref(), Some(expected));
        assert_eq!(normalized.category.as_deref(), Some("Network"));
        assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
    }
}

#[test]
fn test_protocol_stack_uses_compat_names() {
    let mut flow = flow_with_protocol(Protocol::HttpConnect);
    flow.protocol_stack.push(Protocol::HttpConnect);
    let normalized = NormalizedFlow::from_flow(&flow);
    assert!(
        normalized
            .protocol_stack
            .contains(&"HTTP_CONNECT".to_string())
    );
}

#[test]
fn test_protocol_name_tls_unchanged() {
    let flow = flow_with_protocol(Protocol::Tls);
    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.master_protocol.as_deref(), Some("Tls"));
    assert_eq!(normalized.category.as_deref(), Some("Web"));
    assert_eq!(normalized.breed.as_deref(), Some("Safe"));
}
