//! 猜测引擎集成测试
//!
//! 测试端口回退、IP 子网匹配、域名匹配引擎和 Giveup 机制的集成。

use rdpi::core::guess::{GuessEngine, GuessContext};
use rdpi::core::guess::info::DomainInfo;
use rdpi::core::types::*;
use rdpi::Detector;

// ============================================================================
// 辅助：构造 UDP 包（手工字节数组）
// ============================================================================

fn build_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 14 + 20 + 8 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x00; 6]); // dst MAC
    pkt.extend_from_slice(&[0xff; 6]); // src MAC
    pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // IPv4 header (20 bytes)
    pkt.push(0x45); // version + IHL
    pkt.push(0x00); // DSCP
    pkt.extend_from_slice(&(total_len as u16 - 14).to_be_bytes()); // total length
    pkt.extend_from_slice(&[0x00, 0x01]); // id
    pkt.extend_from_slice(&[0x00, 0x00]); // flags + fragment
    pkt.push(0x40); // TTL
    pkt.push(0x11); // protocol: UDP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&[10, 0, 0, 1]); // src IP
    pkt.extend_from_slice(&[10, 0, 0, 2]); // dst IP

    // UDP header (8 bytes)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&(payload.len() as u16 + 8).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum

    pkt.extend_from_slice(payload);
    pkt
}

/// 构造 TCP 包（手工字节数组）
fn build_tcp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 14 + 20 + 20 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);

    // IPv4 header (20 bytes)
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16 - 14).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(0x40);
    pkt.push(0x06); // protocol: TCP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);

    // TCP header (20 bytes, data offset=5)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
    pkt.push(0x50); // data offset=5, reserved
    pkt.push(0x00); // flags
    pkt.extend_from_slice(&[0xff, 0xff]); // window
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // urgent

    pkt.extend_from_slice(payload);
    pkt
}

/// 构造 TLS ClientHello 包
fn build_tls_client_hello(sni: &str) -> Vec<u8> {
    let mut tls_payload = Vec::new();

    // TLS Record: ContentType=0x16 (Handshake), Version=0x0303 (TLS 1.2)
    tls_payload.push(0x16);
    tls_payload.push(0x03);
    tls_payload.push(0x03);
    let record_len: u16 = 100 + sni.len() as u16;
    tls_payload.extend_from_slice(&record_len.to_be_bytes());

    // Handshake: ClientHello (type=0x01)
    tls_payload.push(0x01);
    let handshake_len: u32 = 96 + sni.len() as u32;
    tls_payload.extend_from_slice(&handshake_len.to_be_bytes()[1..]);

    // Protocol version (TLS 1.2 = 0x0303)
    tls_payload.push(0x03);
    tls_payload.push(0x03);

    // Random (32 bytes)
    tls_payload.extend_from_slice(&[0x00; 32]);

    // Session ID length = 0
    tls_payload.push(0x00);

    // Cipher suites: 2 suites (4 bytes)
    tls_payload.extend_from_slice(&[0x00, 0x02]);
    tls_payload.extend_from_slice(&[0x00, 0x2f]);

    // Compression methods: null (1 byte)
    tls_payload.push(0x01);
    tls_payload.push(0x00);

    // Extensions
    let sni_len = sni.len() as u16;
    let ext_total = sni_len + 9;
    tls_payload.extend_from_slice(&ext_total.to_be_bytes());

    // SNI extension (type=0x0000)
    tls_payload.extend_from_slice(&[0x00, 0x00]);
    let sni_ext_body = sni_len + 5;
    tls_payload.extend_from_slice(&sni_ext_body.to_be_bytes());
    tls_payload.extend_from_slice(&sni_ext_body.to_be_bytes());
    tls_payload.push(0x00); // host_name type
    tls_payload.extend_from_slice(&sni_len.to_be_bytes());
    tls_payload.extend_from_slice(sni.as_bytes());

    build_tcp_packet(12345, 443, &tls_payload)
}

/// 不可被任何 DPI 检测器识别的 payload
fn garbage_payload() -> Vec<u8> {
    vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
         0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]
}

// ============================================================================
// 端口猜测测试
// ============================================================================

#[test]
fn test_guess_engine_port_fallback() {
    let ctx = GuessContext::new(80);
    let result = GuessEngine::new().guess(&ctx);
    let r = result.expect("Should match port 80");
    assert_eq!(r.protocol, Protocol::Http);
    assert_eq!(r.confidence, Confidence::MatchByPort);
}

#[test]
fn test_guess_engine_unknown_port() {
    let ctx = GuessContext::new(9999);
    let result = GuessEngine::new().guess(&ctx);
    assert!(result.is_none());
}

// ============================================================================
// IP 子网猜测测试
// ============================================================================

#[test]
fn test_guess_engine_ip_match() {
    let mut ctx = GuessContext::new(9999);
    ctx.dst_ip = Some("142.250.80.1".parse().unwrap());
    let result = GuessEngine::new().guess(&ctx);
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.protocol, Protocol::Http);
    assert_eq!(r.confidence, Confidence::MatchByIp);
}

#[test]
fn test_guess_engine_ip_before_port() {
    // IP 匹配（MatchByIp）应优先于端口匹配（MatchByPort）
    let mut ctx = GuessContext::new(53);
    ctx.dst_ip = Some("142.250.80.1".parse().unwrap());
    let result = GuessEngine::new().guess(&ctx);
    assert!(result.is_some());
    // 预期为 IP 匹配的 HTTP，而非端口匹配的 DNS
    let r = result.unwrap();
    assert_eq!(r.protocol, Protocol::Http);
    assert_eq!(r.confidence, Confidence::MatchByIp);
}

// ============================================================================
// 域名匹配测试
// ============================================================================

#[test]
fn test_guess_engine_domain_match() {
    let mut ctx = GuessContext::new(9999);
    ctx.domain_info = DomainInfo {
        sni: Some("www.youtube.com".to_string()),
        http_host: None,
        dns_query: None,
    };
    let result = GuessEngine::new().guess(&ctx);
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.protocol, Protocol::Http);
    assert_eq!(r.confidence, Confidence::DpiPartial);
}

#[test]
fn test_guess_engine_domain_no_match() {
    let mut ctx = GuessContext::new(9999);
    ctx.domain_info = DomainInfo {
        sni: Some("unknown-service.example.com".to_string()),
        http_host: None,
        dns_query: None,
    };
    // 域名不匹配，端口 9999 也不在表中 → None
    let result = GuessEngine::new().guess(&ctx);
    assert!(result.is_none());
}

// ============================================================================
// Giveup 机制集成测试
// ============================================================================

#[test]
fn test_udp_giveup_triggers_port_guess() {
    let mut detector = Detector::new();
    let packet = build_udp_packet(12345, 53, &garbage_payload());

    // UDP 阈值为 5，第 5 个包触发端口猜测
    for _ in 0..4 {
        let _ = detector.detect(&packet).unwrap();
    }
    let result = detector.detect(&packet).unwrap();

    let r = result.expect("Should have a guess result");
    assert_eq!(r.protocol, Protocol::Dns);
    assert_eq!(r.confidence, Confidence::MatchByPort);
}

#[test]
fn test_tcp_giveup_triggers_port_guess() {
    let mut detector = Detector::new();
    let packet = build_tcp_packet(12345, 22, &garbage_payload());

    // TCP 阈值为 20，第 20 个包触发端口猜测
    for _ in 0..19 {
        let _ = detector.detect(&packet).unwrap();
    }
    let result = detector.detect(&packet).unwrap();

    let r = result.expect("Should have a guess result");
    assert_eq!(r.protocol, Protocol::Ssh);
    assert_eq!(r.confidence, Confidence::MatchByPort);
}

#[test]
fn test_dpi_before_giveup() {
    let mut detector = Detector::new();
    // DNS 查询包 → DPI 应直接识别，不进入 giveup
    let mut pkt = build_udp_packet(12345, 53, &[0x00; 12]);
    // 添加一些 DNS 头部特征
    pkt[28] = 0xaa; // transaction ID
    pkt[29] = 0xaa;
    pkt[30] = 0x01; // flags: standard query
    pkt[31] = 0x00;

    let result = detector.detect(&pkt).unwrap();
    let r = result.expect("Should detect DNS");
    assert_eq!(r.confidence, Confidence::Dpi);
}

#[test]
fn test_dpi_only_mode() {
    let mut detector = Detector::new();
    detector.disable_guess();
    let packet = build_udp_packet(12345, 53, &garbage_payload());

    for _ in 0..10 {
        let result = detector.detect(&packet).unwrap();
        if result.is_some() {
            panic!("Should not guess in DPI-only mode");
        }
    }
}

#[test]
fn test_tls_detected_before_giveup() {
    let mut detector = Detector::new();
    // TLS ClientHello → DPI 应直接识别
    let pkt = build_tls_client_hello("example.com");
    let result = detector.detect(&pkt).unwrap();
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.protocol, Protocol::Tls);
    assert_eq!(r.confidence, Confidence::Dpi);
}

// ============================================================================
// Confidence 枚举测试
// ============================================================================

#[test]
fn test_confidence_as_u8() {
    assert_eq!(Confidence::Unknown as u8, 0);
    assert_eq!(Confidence::MatchByPort as u8, 1);
    assert_eq!(Confidence::MatchByIp as u8, 2);
    assert_eq!(Confidence::Dpi as u8, 5);
    assert_eq!(Confidence::CustomRule as u8, 6);
}

#[test]
fn test_confidence_ordering() {
    assert!(Confidence::Dpi > Confidence::DpiPartial);
    assert!(Confidence::DpiPartial > Confidence::MatchByIp);
    assert!(Confidence::MatchByIp > Confidence::MatchByPort);
    assert!(Confidence::MatchByPort > Confidence::Unknown);
}
