use rdpi::{Detector, Protocol};

/// 构建一个完整的 UDP 包
fn build_udp_packet(payload: &[u8], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut packet = vec![
        // Ethernet header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        // IPv4 header
        0x45, 0x00,
    ];
    let total_len = (20 + 8 + payload.len()) as u16;
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&[
        0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, // 192.168.1.1
        0x0a, 0x00, 0x00, 0x01, // 10.0.0.1
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
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
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

#[cfg(feature = "quic")]
#[test]
fn test_end_to_end_quic_detection() {
    let mut detector = Detector::new();

    // Build a QUIC v1 Initial packet
    let quic_payload = vec![
        0xC0, // Long Header + Initial
        0x00, 0x00, 0x00, 0x01, // QUIC v1
        0x08, // DCID length
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
        0x00, // SCID length
        0x00, // Token length
        0x40, 0x10, // Length (varint)
    ];

    // Build complete packet using existing build_udp_packet helper
    let mut payload = quic_payload.clone();
    payload.extend(vec![0u8; 16]); // Padding for packet number + payload

    let packet = build_udp_packet(&payload, 12345, 443);

    let result = detector.detect(&packet).unwrap();
    assert!(result.is_some());
    let result = result.unwrap();
    // UDP port 443 with standard QUIC version is detected as HTTP/3
    assert_eq!(result.protocol, Protocol::Http3);
}

// ============================================================================
// POP3 Tests
// ============================================================================

#[test]
#[cfg(feature = "mail")]
fn test_end_to_end_pop3_server_banner() {
    use rdpi::protocols::Registry;

    let registry = Registry::default();

    // POP3 server banner
    let pop3_banner = b"+OK POP3 server ready\r\n";
    let result = registry.detect(pop3_banner);

    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.protocol, Protocol::Pop3);
}

#[test]
#[cfg(feature = "mail")]
fn test_end_to_end_pop3_client_command() {
    use rdpi::protocols::Registry;

    let registry = Registry::default();

    // POP3 client command
    let pop3_command = b"USER test@example.com\r\n";
    let result = registry.detect(pop3_command);

    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.protocol, Protocol::Pop3);
}

// ============================================================================
// IMAP Tests
// ============================================================================

#[test]
#[cfg(feature = "mail")]
fn test_end_to_end_imap_server_banner() {
    use rdpi::protocols::Registry;

    let registry = Registry::default();

    // IMAP server banner
    let imap_banner = b"* OK IMAP4rev1 Service Ready\r\n";
    let result = registry.detect(imap_banner);

    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.protocol, Protocol::Imap);
}

#[test]
#[cfg(feature = "mail")]
fn test_end_to_end_imap_client_command() {
    use rdpi::protocols::Registry;

    let registry = Registry::default();

    // IMAP client command
    let imap_command = b"A001 LOGIN user password\r\n";
    let result = registry.detect(imap_command);

    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.protocol, Protocol::Imap);
}

// ============================================================================
// NTP Tests
// ============================================================================

#[test]
#[cfg(feature = "infra")]
fn test_end_to_end_ntp_detection() {
    let mut detector = Detector::new();

    // Build NTP v4 client request (mode 3, stratum 0 for client)
    let mut ntp_payload = vec![0u8; 48];
    // First byte: LI=0, VN=4, Mode=3 (client)
    ntp_payload[0] = (4 << 3) | 3; // version 4, mode 3
    ntp_payload[1] = 0; // stratum 0 for client

    let packet = build_udp_packet(&ntp_payload, 12345, 123);
    let result = detector.detect(&packet).unwrap();

    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.protocol, Protocol::Ntp);
}

#[test]
#[cfg(feature = "infra")]
fn test_end_to_end_ntp_server_response() {
    let mut detector = Detector::new();

    // Build NTP v4 server response (mode 4, stratum 2)
    let mut ntp_payload = vec![0u8; 48];
    // First byte: LI=0, VN=4, Mode=4 (server)
    ntp_payload[0] = (4 << 3) | 4; // version 4, mode 4
    ntp_payload[1] = 2; // stratum 2

    let packet = build_udp_packet(&ntp_payload, 123, 12345);
    let result = detector.detect(&packet).unwrap();

    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.protocol, Protocol::Ntp);
}

// ============================================================================
// DHCP Tests
// ============================================================================

#[test]
#[cfg(feature = "infra")]
fn test_end_to_end_dhcp_detection() {
    let mut detector = Detector::new();

    // Build DHCP discover packet (minimum 244 bytes)
    let mut dhcp_payload = vec![0u8; 244];
    dhcp_payload[0] = 1; // opcode: BOOTREQUEST
    dhcp_payload[1] = 1; // htype: Ethernet
    dhcp_payload[2] = 6; // hlen: 6 bytes for MAC
    // Client MAC at offset 28-33
    dhcp_payload[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // Magic cookie at offset 236-239
    dhcp_payload[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);

    let packet = build_udp_packet(&dhcp_payload, 68, 67);
    let result = detector.detect(&packet).unwrap();

    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.protocol, Protocol::Dhcp);
}

// ============================================================================
// SNMP Tests
// ============================================================================

#[test]
#[cfg(feature = "snmp")]
fn test_end_to_end_snmp_detection() {
    use rdpi::protocols::Registry;

    let registry = Registry::default();

    // SNMP v1 GetRequest for sysDescr.0
    let snmp_payload = vec![
        0x30, 0x26,           // SEQUENCE, length 38
        0x02, 0x01, 0x00,     // INTEGER: version 0 (v1)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // OCTET STRING: "public"
        0xA0, 0x19,           // GetRequest (context-specific 0, constructed)
        0x02, 0x01, 0x01,     // request-id: 1
        0x02, 0x01, 0x00,     // error-status: 0
        0x02, 0x01, 0x00,     // error-index: 0
        0x30, 0x0E,           // varbind-list SEQUENCE
        0x30, 0x0C,           // varbind SEQUENCE
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: 1.3.6.1.2.1.1.1.0
        0x05, 0x00,           // NULL
    ];

    let result = registry.detect(&snmp_payload);

    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.protocol, Protocol::Snmp);
}

// ============================================================================
// Modbus Tests
// ============================================================================

#[test]
#[cfg(feature = "modbus")]
fn test_end_to_end_modbus_detection() {
    use rdpi::protocols::Registry;

    let registry = Registry::default();

    // Modbus TCP Read Coils request
    let modbus_payload = vec![
        0x00, 0x01,       // Transaction ID: 1
        0x00, 0x00,       // Protocol ID: 0
        0x00, 0x06,       // Length: 6 bytes following
        0x01,             // Unit ID: 1
        0x01,             // Function Code: Read Coils
        0x00, 0x01,       // Address: 1
        0x00, 0x08,       // Quantity: 8 coils
    ];

    let result = registry.detect(&modbus_payload);

    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.protocol, Protocol::Modbus);
}
