//! 回归测试
//!
//! 多包流处理测试，确保检测器在不同包序列下行为一致。

use rdpi::Detector;
use rdpi::core::types::{Confidence, Protocol};
use std::time::{Duration, Instant};

// ============================================================================
// 辅助：包构造
// ============================================================================

fn build_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 14 + 20 + 8 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16 - 14).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(0x40);
    pkt.push(0x11);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&(payload.len() as u16 + 8).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

fn build_tls_client_hello() -> Vec<u8> {
    use etherparse::*;
    let mut payload = Vec::new();
    // TLS 1.2 ClientHello
    payload.push(0x16); // ContentType: Handshake
    payload.push(0x03); payload.push(0x03); // Version: TLS 1.2
    let record_len: u16 = 100;
    payload.extend_from_slice(&record_len.to_be_bytes());
    payload.push(0x01); // Handshake: ClientHello
    let hs_len: u32 = 96;
    payload.extend_from_slice(&hs_len.to_be_bytes()[1..]);
    payload.push(0x03); payload.push(0x03); // TLS 1.2
    payload.extend_from_slice(&[0x00; 32]); // Random
    payload.push(0x00); // Session ID length
    payload.extend_from_slice(&[0x00, 0x02]);
    payload.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_AES_128_CBC_SHA
    payload.push(0x01); payload.push(0x00); // Compression
    let sni = b"example.com";
    let sni_ext_len = sni.len() as u16 + 9;
    payload.extend_from_slice(&sni_ext_len.to_be_bytes());
    payload.extend_from_slice(&[0x00, 0x00]); // SNI
    let body_len = sni.len() as u16 + 5;
    payload.extend_from_slice(&body_len.to_be_bytes());
    payload.extend_from_slice(&body_len.to_be_bytes());
    payload.push(0x00);
    payload.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    payload.extend_from_slice(sni);

    // TCP + IP + Ethernet headers (manual byte construction)
    let total_len = 14 + 20 + 20 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);

    // Ethernet header
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);

    // IPv4 header
    pkt.push(0x45); pkt.push(0x00);
    pkt.extend_from_slice(&((total_len - 14) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    pkt.push(0x40); pkt.push(0x06);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);

    // TCP header (20 bytes)
    pkt.extend_from_slice(&12345u16.to_be_bytes());
    pkt.extend_from_slice(&443u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.push(0x50); pkt.push(0x00);
    pkt.extend_from_slice(&[0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);

    pkt.extend_from_slice(&payload);
    pkt
}

fn build_dns_query_packet() -> Vec<u8> {
    // DNS query for example.com
    let mut payload = vec![
        0xaa, 0xaa, // TXID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer/Authority/Additional: 0
        // Query: example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // End of domain
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
    ];
    build_udp_packet(12345, 53, &payload)
}

// ============================================================================
// 回归测试
// ============================================================================

#[test]
fn test_regression_dns_query() {
    let mut detector = Detector::new();
    let pkt = build_dns_query_packet();
    let result = detector.detect(&pkt).unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().protocol, Protocol::Dns);
}

#[test]
fn test_regression_tls_handshake() {
    let mut detector = Detector::new();
    let pkt = build_tls_client_hello();
    let result = detector.detect(&pkt).unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().protocol, Protocol::Tls);
}

#[test]
fn test_regression_multi_packet_flow() {
    let mut detector = Detector::new();
    // DNS query + same flow continuation
    let pkt = build_dns_query_packet();
    let r1 = detector.detect(&pkt).unwrap();
    assert!(r1.is_some());
    let flow_count_before = detector.flow_count();

    // Same packet again (same flow, should use cached protocol)
    let r2 = detector.detect(&pkt).unwrap();
    assert!(r2.is_some());
    assert_eq!(r2.unwrap().protocol, Protocol::Dns);

    // Flow count should not increase (same 5-tuple)
    assert_eq!(detector.flow_count(), flow_count_before);
}

#[test]
fn test_regression_multiple_flows() {
    let mut detector = Detector::new();
    let dns = build_dns_query_packet();
    let tls = build_tls_client_hello();

    detector.detect(&dns).unwrap();
    detector.detect(&tls).unwrap();

    // Should have 2 flows
    assert_eq!(detector.flow_count(), 2);
}

#[test]
fn test_regression_confidence_integration() {
    let mut detector = Detector::new();
    let pkt = build_dns_query_packet();
    let result = detector.detect(&pkt).unwrap().unwrap();
    assert_eq!(result.confidence, Confidence::Dpi);
    assert_eq!(result.category, rdpi::core::types::ProtocolCategory::Dns);
    assert_eq!(result.breed, rdpi::core::types::ProtocolBreed::Safe);
}

#[test]
fn test_regression_detector_lifecycle() {
    let mut detector = Detector::new();
    // Clear flows on empty detector
    assert_eq!(detector.flow_count(), 0);
    detector.clear_flows();

    // Detect and expire
    let pkt = build_dns_query_packet();
    detector.detect(&pkt).unwrap();
    assert_eq!(detector.flow_count(), 1);

    // Expire with very short timeout (won't actually expire since test is fast)
    let expired = detector.expire_flows();
    assert!(expired.is_empty());
}

#[test]
fn test_regression_protocol_category_all() {
    // Verify all built-in protocols have categories
    use rdpi::core::types::*;
    assert_ne!(Protocol::Dns.category(), ProtocolCategory::Other);
    assert_ne!(Protocol::Http.category(), ProtocolCategory::Other);
    assert_ne!(Protocol::Tls.category(), ProtocolCategory::Other);
    assert_ne!(Protocol::Ssh.category(), ProtocolCategory::Other);
}

// ============================================================================
// 性能基准（简单计时，非精确 bench）
// ============================================================================

#[test]
fn test_regression_detection_throughput() {
    let pkt = build_dns_query_packet();
    let iterations = 1000;

    let start = Instant::now();
    for _ in 0..iterations {
        let mut detector = Detector::new();
        let _ = detector.detect(&pkt);
    }
    let elapsed = start.elapsed();

    let per_op = elapsed / iterations;
    // 每次检测 < 50μs（Debug 模式基准，Release 更快）
    assert!(per_op < Duration::from_micros(50),
        "Detection too slow: {:?} per operation", per_op);
}
