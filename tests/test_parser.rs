use rdpi::core::TransportProto;
use rdpi::parser::{parse_l3_packet, parse_packet};
use std::net::IpAddr;

/// 构造 L3 IPv4 + UDP 包（20 字节 IPv4 头 + 8 字节 UDP 头）
fn make_ipv4_udp(
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
        0x00, // IPv4, IHL=5
        (total_len >> 8) as u8,
        (total_len & 0xff) as u8,
        0x00,
        0x01, // identification
        0x00,
        0x00, // flags + fragment offset
        0x40, // TTL
        0x11, // UDP
        0x00,
        0x00, // checksum
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

/// 构造 L3 IPv6 + UDP 包（40 字节 IPv6 头 + 8 字节 UDP 头）
fn make_ipv6_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut packet = vec![
        0x60,
        0x00,
        0x00,
        0x00, // version / traffic class / flow label
        ((8 + payload.len()) >> 8) as u8,
        ((8 + payload.len()) & 0xff) as u8, // payload length
        17,                                 // next header: UDP
        64,                                 // hop limit
    ];
    packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // checksum
    packet.extend_from_slice(payload);
    packet
}

/// 用 IPv4 IP-in-IP 头包裹内层 L3 包（外层端点 192.168.1.1 → 10.0.0.1）
fn wrap_ipv4_tunnel(protocol: u8, inner: &[u8]) -> Vec<u8> {
    let total_len = (20 + inner.len()) as u16;
    let mut packet = vec![
        0x45,
        0x00,
        (total_len >> 8) as u8,
        (total_len & 0xff) as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        0x3f, // TTL
        protocol,
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
    ];
    packet.extend_from_slice(inner);
    packet
}

/// 用 IPv6 头包裹内层 L3 包
fn wrap_ipv6_tunnel(next_header: u8, inner: &[u8]) -> Vec<u8> {
    let mut packet = vec![
        0x60,
        0x00,
        0x00,
        0x00,
        (inner.len() >> 8) as u8,
        (inner.len() & 0xff) as u8,
        next_header,
        64,
    ];
    packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    packet.extend_from_slice(inner);
    packet
}

/// 以太网帧封装，`vlans` 为 (TPID, VID) 标签栈（空表示普通 IPv4 帧）
fn make_ethernet(l3: &[u8], vlans: &[(u16, u16)]) -> Vec<u8> {
    let mut packet = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
    ];
    // MAC 之后是 TPID/TCI 交替的 16 位字流，最后以 IPv4 EtherType 结束
    for (tpid, vid) in vlans {
        packet.extend_from_slice(&tpid.to_be_bytes());
        packet.extend_from_slice(&vid.to_be_bytes());
    }
    packet.extend_from_slice(&0x0800u16.to_be_bytes());
    packet.extend_from_slice(l3);
    packet
}

// 一个简单的以太网 + IPv4 + UDP 包
// 以太网头: 14 bytes, IPv4 头: 20 bytes, UDP 头: 8 bytes
fn make_udp_packet() -> Vec<u8> {
    make_ethernet(
        &make_ipv4_udp([192, 168, 1, 1], 12345, [10, 0, 0, 1], 53, &[]),
        &[],
    )
}

#[test]
fn test_parse_udp_packet() {
    let packet = make_udp_packet();
    let result = parse_packet(&packet).unwrap();

    assert_eq!(result.transport, TransportProto::Udp);
    assert_eq!(result.src_port, 12345);
    assert_eq!(result.dst_port, 53);
}

#[test]
fn test_parse_single_vlan_udp_packet() {
    let l3 = make_ipv4_udp([192, 168, 1, 1], 12345, [10, 0, 0, 1], 53, b"dns");
    let frame = make_ethernet(&l3, &[(0x8100, 100)]);

    let result = parse_packet(&frame).unwrap();
    assert_eq!(result.transport, TransportProto::Udp);
    assert_eq!(result.src_port, 12345);
    assert_eq!(result.dst_port, 53);
    assert_eq!(result.payload, b"dns");
}

#[test]
fn test_parse_qinq_stacked_vlan_udp_packet() {
    let l3 = make_ipv4_udp([192, 168, 1, 1], 5353, [10, 0, 0, 1], 53, b"qinq");
    let frame = make_ethernet(&l3, &[(0x88a8, 100), (0x8100, 200)]);

    let result = parse_packet(&frame).unwrap();
    assert_eq!(result.transport, TransportProto::Udp);
    assert_eq!(result.src_port, 5353);
    assert_eq!(result.dst_port, 53);
    assert_eq!(result.payload, b"qinq");
}

#[test]
fn test_parse_truncated_vlan_tag_is_error() {
    let l3 = make_ipv4_udp([192, 168, 1, 1], 12345, [10, 0, 0, 1], 53, &[]);
    let mut frame = make_ethernet(&l3, &[(0x8100, 100)]);
    frame.truncate(16); // MAC + TPID，缺 TCI 与内层 EtherType

    assert!(parse_packet(&frame).is_err());
}

#[test]
fn test_parse_ipv4_in_ipv4_udp_packet() {
    let inner = make_ipv4_udp([10, 1, 1, 1], 5353, [10, 2, 2, 2], 53, b"tunnel");
    let packet = wrap_ipv4_tunnel(4, &inner);

    let result = parse_l3_packet(&packet).unwrap();
    // 流身份保留外层端点；传输层来自内层
    assert_eq!(result.src_ip, "192.168.1.1".parse::<IpAddr>().unwrap());
    assert_eq!(result.dst_ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(result.transport, TransportProto::Udp);
    assert_eq!(result.src_port, 5353);
    assert_eq!(result.dst_port, 53);
    assert_eq!(result.payload, b"tunnel");
}

#[test]
fn test_parse_ipv6_in_ipv4_udp_packet() {
    let inner = make_ipv6_udp(8443, 443, b"6in4");
    let packet = wrap_ipv4_tunnel(41, &inner);

    let result = parse_l3_packet(&packet).unwrap();
    assert_eq!(result.transport, TransportProto::Udp);
    assert_eq!(result.src_port, 8443);
    assert_eq!(result.dst_port, 443);
    assert_eq!(result.payload, b"6in4");
}

#[test]
fn test_parse_ipv4_in_ipv6_udp_packet() {
    let inner = make_ipv4_udp([10, 1, 1, 1], 5353, [10, 2, 2, 2], 53, b"4in6");
    let packet = wrap_ipv6_tunnel(4, &inner);

    let result = parse_l3_packet(&packet).unwrap();
    assert_eq!(result.src_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    assert_eq!(result.dst_ip, "2001:db8::2".parse::<IpAddr>().unwrap());
    assert_eq!(result.transport, TransportProto::Udp);
    assert_eq!(result.src_port, 5353);
    assert_eq!(result.dst_port, 53);
    assert_eq!(result.payload, b"4in6");
}

#[test]
fn test_parse_tunnel_at_max_depth_is_decapsulated() {
    let inner = make_ipv4_udp([10, 1, 1, 1], 5353, [10, 2, 2, 2], 53, b"deep");
    let mut packet = inner;
    for _ in 0..4 {
        packet = wrap_ipv4_tunnel(4, &packet);
    }

    let result = parse_l3_packet(&packet).unwrap();
    assert_eq!(result.transport, TransportProto::Udp);
    assert_eq!(result.dst_port, 53);
}

#[test]
fn test_parse_tunnel_exceeding_max_depth_is_opaque() {
    let inner = make_ipv4_udp([10, 1, 1, 1], 5353, [10, 2, 2, 2], 53, b"deep");
    let mut packet = inner;
    for _ in 0..5 {
        packet = wrap_ipv4_tunnel(4, &packet);
    }

    let result = parse_l3_packet(&packet).unwrap();
    // 超过 4 层后按不透明 IP-in-IP 载荷处理，而不是报错或无限递归
    assert_eq!(result.transport, TransportProto::Other(4));
    assert_eq!(result.dst_port, 0);
}
