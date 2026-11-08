//! `Detector::process_ip_packet`：L3（IPv4/IPv6 头起始）入口。
//!
//! 锁定与 `process_packet` 的一致性：同一 IP 包分别走以太网入口与 L3 入口，
//! 协议、流数、双向计数一致；字节统计口径不同（以太网含链路头）。

use rdpi::Detector;

const CLIENT: [u8; 4] = [192, 168, 1, 1];
const SERVER: [u8; 4] = [10, 0, 0, 1];

fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
    let total_len = 20 + l4.len();
    let mut packet = Vec::with_capacity(total_len);
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.push(64);
    packet.push(proto);
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(l4);
    packet
}

fn ethernet(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
    ];
    frame.extend_from_slice(payload);
    frame
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::with_capacity(8 + payload.len());
    segment.extend_from_slice(&sport.to_be_bytes());
    segment.extend_from_slice(&dport.to_be_bytes());
    segment.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes());
    segment.extend_from_slice(payload);
    segment
}

fn tcp(sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend_from_slice(&sport.to_be_bytes());
    segment.extend_from_slice(&dport.to_be_bytes());
    segment.extend_from_slice(&1000u32.to_be_bytes());
    segment.extend_from_slice(&0u32.to_be_bytes());
    segment.push(0x50);
    segment.push(flags);
    segment.extend_from_slice(&0xffffu16.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes());
    segment.extend_from_slice(payload);
    segment
}

fn dns_query(domain: &str) -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    query
}

#[test]
fn process_ip_packet_matches_ethernet_entry_for_udp() {
    let l3 = ipv4(
        17,
        CLIENT,
        SERVER,
        &udp(40000, 53, &dns_query("example.com")),
    );
    let frame = ethernet(&l3);

    let mut ethernet_detector = Detector::new();
    let mut l3_detector = Detector::new();

    let from_ethernet = ethernet_detector
        .process_packet(&frame, 1_700_000_000_000)
        .unwrap()
        .expect("ethernet path should detect DNS");
    let from_l3 = l3_detector
        .process_ip_packet(&l3, 1_700_000_000_000)
        .unwrap()
        .expect("L3 path should detect DNS");

    assert_eq!(from_ethernet.protocol, from_l3.protocol);
    assert_eq!(ethernet_detector.flow_count(), l3_detector.flow_count());

    let flow_from_ethernet = ethernet_detector.flows().next().unwrap().1;
    let flow_from_l3 = l3_detector.flows().next().unwrap().1;
    assert_eq!(flow_from_ethernet.stats.packets, flow_from_l3.stats.packets);
    assert_eq!(
        flow_from_ethernet.packets_forward,
        flow_from_l3.packets_forward
    );
    assert_eq!(
        flow_from_ethernet.packets_reverse,
        flow_from_l3.packets_reverse
    );
    // 字节统计口径不同：以太网路径含 14 字节链路头
    assert_eq!(
        flow_from_ethernet.stats.bytes,
        flow_from_l3.stats.bytes + 14
    );
}

#[test]
fn process_ip_packet_aggregates_tcp_flow_both_directions() {
    let mut detector = Detector::new();

    detector
        .process_ip_packet(&ipv4(6, CLIENT, SERVER, &tcp(50001, 53, 0x02, b"")), 1)
        .unwrap();
    detector
        .process_ip_packet(&ipv4(6, SERVER, CLIENT, &tcp(53, 50001, 0x12, b"")), 2)
        .unwrap();
    detector
        .process_ip_packet(&ipv4(6, CLIENT, SERVER, &tcp(50001, 53, 0x10, b"")), 3)
        .unwrap();

    assert_eq!(detector.flow_count(), 1);
    let flow = detector.flows().next().unwrap().1;
    assert_eq!(flow.stats.packets, 3);
    assert_eq!(flow.packets_forward, 2);
    assert_eq!(flow.packets_reverse, 1);
}

#[test]
fn process_ip_packet_handles_icmp() {
    let mut detector = Detector::new();
    let icmp = [8u8, 0, 0, 0, 0, 1, 0, 1];

    detector
        .process_ip_packet(&ipv4(1, CLIENT, SERVER, &icmp), 1)
        .unwrap();

    assert_eq!(detector.flow_count(), 1);
    assert_eq!(detector.flows().next().unwrap().1.stats.packets, 1);
}

#[test]
fn process_ip_packet_rejects_truncated_packet() {
    let mut detector = Detector::new();
    assert!(detector.process_ip_packet(&[0x45, 0x00], 0).is_err());
}
