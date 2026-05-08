use rdpi::{Detector, Protocol};

/// 构建一个完整的 UDP 包
fn build_udp_packet(payload: &[u8], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut packet = vec![
        // Ethernet header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        // IPv4 header
        0x45, 0x00,
    ];
    let total_len = (20 + 8 + payload.len()) as u16;
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&[
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,  // 192.168.1.1
        0x0a, 0x00, 0x00, 0x01,  // 10.0.0.1
    ]);
    // UDP header
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(payload);
    packet
}

#[test]
fn test_end_to_end_dns_detection() {
    let mut detector = Detector::new();

    // DNS query for example.com
    let dns_query = vec![
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
    ];

    let packet = build_udp_packet(&dns_query, 12345, 53);
    let result = detector.detect(&packet).unwrap();

    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.protocol, Protocol::Dns);
}

#[test]
fn test_non_dns_packet() {
    let mut detector = Detector::new();

    // 随机数据，不是 DNS
    let payload = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
    let packet = build_udp_packet(&payload, 12345, 8080);

    let result = detector.detect(&packet).unwrap();
    assert!(result.is_none());
}
