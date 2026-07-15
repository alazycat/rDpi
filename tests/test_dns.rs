use rdpi::Detector;
use rdpi::core::types::*;
use rdpi::protocols::{ProtocolDetector, Registry};

/// Build a minimal DNS query for a given domain name
fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut pkt = vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answers: 0
        0x00, 0x00, // Authority: 0
        0x00, 0x00, // Additional: 0
    ];
    // Encode domain name as length-prefixed labels
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00); // End of name
    pkt.extend_from_slice(&[0x00, 0x01]); // Type: A
    pkt.extend_from_slice(&[0x00, 0x01]); // Class: IN
    pkt
}

#[test]
fn test_registry_new() {
    let registry = Registry::new();
    assert_eq!(registry.detector_count(), 0);
}

#[test]
fn test_registry_register() {
    let mut registry = Registry::new();
    registry.register(Box::new(rdpi::protocols::dns::DnsDetector::new()));
    assert_eq!(registry.detector_count(), 1);
}

// DNS query for "example.com"
fn make_dns_query() -> Vec<u8> {
    vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answers: 0
        0x00, 0x00, // Authority: 0
        0x00, 0x00, // Additional: 0
        0x07, // Label length: 7
        b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, // Label length: 3
        b'c', b'o', b'm', 0x00, // End of name
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
    ]
}

#[test]
fn test_dns_detector() {
    let detector = rdpi::protocols::dns::DnsDetector::new();
    let payload = make_dns_query();

    let result = detector.detect(&payload);
    assert!(result.is_some());

    let result = result.unwrap();
    assert_eq!(result.protocol, Protocol::Dns);
}

#[test]
fn test_dns_detector_metadata() {
    let detector = rdpi::protocols::dns::DnsDetector::new();
    let payload = make_dns_query();

    let result = detector.detect(&payload).unwrap();

    match result.metadata {
        Metadata::Dns(meta) => {
            assert_eq!(meta.query_domain, Some("example.com".to_string()));
        }
        _ => panic!("Expected DNS metadata"),
    }
}

#[test]
fn test_detector_with_dns() {
    let mut detector = Detector::new();

    // Build complete Ethernet + IP + UDP packet
    let dns_payload = make_dns_query();
    let mut packet = vec![
        // Ethernet header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        // IPv4 header
        0x45, 0x00,
    ];
    let total_len = (20 + 8 + dns_payload.len()) as u16;
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&[
        0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0x0a, 0x00, 0x00,
        0x01, // UDP header
        0x30, 0x39, 0x00, 0x35,
    ]);
    let udp_len = (8 + dns_payload.len()) as u16;
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&dns_payload);

    let result = detector.detect(&packet).unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().protocol, Protocol::Dns);
}

#[test]
fn test_dns_query_to_application() {
    let detector = rdpi::protocols::dns::DnsDetector::new();
    // DNS 查询 netflix.com
    let pkt = build_dns_query("netflix.com");
    let result = detector.detect(&pkt).unwrap();
    if let Metadata::Dns(meta) = result.metadata {
        assert_eq!(meta.application, Some(Application::Netflix));
    } else {
        panic!("Expected Dns metadata");
    }
}
