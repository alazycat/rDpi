use rdpi::parser::parse_packet;
use rdpi::core::TransportProto;

// 一个简单的以太网 + IPv4 + UDP 包
// 以太网头: 14 bytes, IPv4 头: 20 bytes, UDP 头: 8 bytes
fn make_udp_packet() -> Vec<u8> {
    vec![
        // Ethernet header (14 bytes)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // dst MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,  // src MAC
        0x08, 0x00,                          // EtherType: IPv4
        // IPv4 header (20 bytes)
        0x45,                                // version + IHL
        0x00,                                // DSCP
        0x00, 0x1c,                          // total length
        0x00, 0x01,                          // identification
        0x00, 0x00,                          // flags + fragment offset
        0x40,                                // TTL
        0x11,                                // protocol: UDP
        0x00, 0x00,                          // checksum (placeholder)
        0xc0, 0xa8, 0x01, 0x01,              // src IP: 192.168.1.1
        0x0a, 0x00, 0x00, 0x01,              // dst IP: 10.0.0.1
        // UDP header (8 bytes)
        0x30, 0x39,                          // src port: 12345
        0x00, 0x35,                          // dst port: 53
        0x00, 0x08,                          // length
        0x00, 0x00,                          // checksum
    ]
}

#[test]
fn test_parse_udp_packet() {
    let packet = make_udp_packet();
    let result = parse_packet(&packet).unwrap();

    assert_eq!(result.transport, TransportProto::Udp);
    assert_eq!(result.src_port, 12345);
    assert_eq!(result.dst_port, 53);
}
