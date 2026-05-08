use rdpi::core::types::*;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_protocol_tcp() {
    let p = Protocol::Tcp;
    assert!(matches!(p, Protocol::Tcp));
}

#[test]
fn test_protocol_dns() {
    let p = Protocol::Dns;
    assert!(matches!(p, Protocol::Dns));
}

#[test]
fn test_protocol_other() {
    let p = Protocol::Other(999);
    assert!(matches!(p, Protocol::Other(999)));
}

#[test]
fn test_flow_key() {
    let key = FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 12345,
        dst_port: 53,
        transport: TransportProto::Udp,
    };
    assert_eq!(key.src_port, 12345);
    assert_eq!(key.transport, TransportProto::Udp);
}