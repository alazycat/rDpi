//! P1 分类核心：双向流基础行为测试
//!
//! 首个垂直切片：FlowKey 规范化 + Direction。
//! 后续测试逐步覆盖 Flow 双向计数、L3 入口、caller-owned Flow API、
//! 逐包分类状态机。

use rdpi::Detector;
use rdpi::core::flow::Flow;
use rdpi::core::types::{ClassificationState, Direction, FlowKey, Protocol, TransportProto};
use rdpi::parser::parse_l3_packet;
use std::net::{IpAddr, Ipv4Addr};

fn key(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> FlowKey {
    FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::from(src)),
        dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
        src_port,
        dst_port,
        transport: TransportProto::Tcp,
    }
}

#[test]
fn flow_key_canonicalizes_both_directions_to_same_key() {
    let forward = key([10, 0, 0, 1], 12345, [10, 0, 0, 2], 80);
    let reverse = forward.reverse();

    let (canonical, forward_dir) = forward.canonical();
    let (canonical_reverse, reverse_dir) = reverse.canonical();

    assert_eq!(canonical, canonical_reverse);
    assert_eq!(canonical, forward);
    assert_eq!(forward_dir, Direction::Forward);
    assert_eq!(reverse_dir, Direction::Reverse);
}

#[test]
fn bidirectional_flow_uses_canonical_key_and_reports_direction() {
    let forward = key([10, 0, 0, 1], 12345, [10, 0, 0, 2], 80);
    let reverse = forward.reverse();

    let flow = Flow::new_bidirectional(forward.clone());
    assert_eq!(flow.key, forward.canonical().0);
    assert_eq!(flow.initiator, Direction::Forward);
    assert_eq!(flow.direction_of(&forward), Some(Direction::Forward));
    assert_eq!(flow.direction_of(&reverse), Some(Direction::Reverse));

    // 首包方向为反向时，initiator 记录反向，但流键仍规范化。
    let flow_from_reverse = Flow::new_bidirectional(reverse.clone());
    assert_eq!(flow_from_reverse.key, forward.canonical().0);
    assert_eq!(flow_from_reverse.initiator, Direction::Reverse);
}

fn make_l3_udp_packet_between(
    src: [u8; 4],
    src_port: u16,
    dst: [u8; 4],
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = (20 + 8 + payload.len()) as u16;
    let udp_len = (8 + payload.len()) as u16;
    let mut packet = vec![
        0x45,
        0x00, // IPv4, IHL=5, DSCP=0
        (total_len >> 8) as u8,
        (total_len & 0xff) as u8,
        0x00,
        0x01, // identification
        0x00,
        0x00, // flags + fragment offset
        0x40, // TTL
        0x11, // UDP
        0x00,
        0x00, // checksum (unchecked by parser)
        src[0],
        src[1],
        src[2],
        src[3],
        dst[0],
        dst[1],
        dst[2],
        dst[3],
        (src_port >> 8) as u8,
        (src_port & 0xff) as u8,
        (dst_port >> 8) as u8,
        (dst_port & 0xff) as u8,
        (udp_len >> 8) as u8,
        (udp_len & 0xff) as u8,
        0x00,
        0x00, // checksum
    ];
    packet.extend_from_slice(payload);
    packet
}

fn make_l3_udp_packet(payload: &[u8]) -> Vec<u8> {
    make_l3_udp_packet_between([192, 168, 1, 1], 12345, [10, 0, 0, 1], 53, payload)
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

#[test]
fn parse_l3_packet_parses_ipv4_without_ethernet() {
    let parsed = parse_l3_packet(&make_l3_udp_packet(b"hello")).unwrap();

    assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(parsed.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(parsed.src_port, 12345);
    assert_eq!(parsed.dst_port, 53);
    assert_eq!(parsed.transport, TransportProto::Udp);
    assert_eq!(parsed.payload, b"hello");
}

#[test]
fn parse_l3_packet_rejects_non_ip_input() {
    assert!(parse_l3_packet(&[0x00u8; 14]).is_err());
}

#[test]
fn process_l3_packet_classifies_and_tracks_both_directions() {
    let mut detector = Detector::new();
    let payload = make_dns_query_payload();
    let client_packet =
        make_l3_udp_packet_between([192, 168, 1, 1], 12345, [10, 0, 0, 1], 53, &payload);
    let parsed = parse_l3_packet(&client_packet).unwrap();
    let packet_key = FlowKey {
        src_ip: parsed.src_ip,
        dst_ip: parsed.dst_ip,
        src_port: parsed.src_port,
        dst_port: parsed.dst_port,
        transport: parsed.transport,
    };
    let mut flow = Flow::new_bidirectional(packet_key);

    let result = detector
        .process_l3_packet(&mut flow, &client_packet, 1_000)
        .unwrap()
        .expect("DNS query should be classified");
    assert_eq!(result.protocol, Protocol::Dns);
    assert_eq!(flow.protocol, Some(Protocol::Dns));
    assert_eq!(flow.classification_state, ClassificationState::Classified);
    assert_eq!(flow.packets_seen, 1);
    assert_eq!(flow.packets_forward, 1);
    assert_eq!(flow.packets_reverse, 0);
    assert_eq!(flow.first_seen_ms, Some(1_000));
    assert_eq!(flow.last_seen_ms, Some(1_000));

    // 反向包应映射到同一条双向流，且不重复分类。
    let server_packet =
        make_l3_udp_packet_between([10, 0, 0, 1], 53, [192, 168, 1, 1], 12345, &payload);
    let result = detector
        .process_l3_packet(&mut flow, &server_packet, 1_010)
        .unwrap()
        .expect("已定型流应回显协议");
    assert_eq!(result.protocol, Protocol::Dns);
    assert_eq!(flow.packets_seen, 2);
    assert_eq!(flow.packets_forward, 1);
    assert_eq!(flow.packets_reverse, 1);
    assert_eq!(flow.last_seen_ms, Some(1_010));
}

#[test]
fn process_l3_packet_rejects_packet_from_another_flow() {
    let mut detector = Detector::new();
    let mut flow = Flow::new_bidirectional(key([10, 0, 0, 1], 12345, [10, 0, 0, 2], 80));
    let other = make_l3_udp_packet_between([192, 168, 1, 1], 1, [10, 0, 0, 9], 2, b"x");

    assert!(detector.process_l3_packet(&mut flow, &other, 0).is_err());
}
