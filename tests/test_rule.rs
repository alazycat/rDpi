#![cfg(feature = "rule")]

use rdpi::core::types::{Confidence, Protocol};
use rdpi::rule::*;
use rdpi::Detector;

/// 构造简单的 UDP 包
fn build_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 14 + 20 + 8 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x00; 6]); // dst MAC
    pkt.extend_from_slice(&[0xff; 6]); // src MAC
    pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

    // IPv4 header (20 bytes)
    pkt.push(0x45); // version + IHL
    pkt.push(0x00); // DSCP + ECN
    pkt.extend_from_slice(&(total_len as u16 - 14).to_be_bytes()); // Total length
    pkt.extend_from_slice(&[0x00, 0x01]); // Identification
    pkt.extend_from_slice(&[0x00, 0x00]); // Flags + Fragment Offset
    pkt.push(0x40); // TTL
    pkt.push(0x11); // Protocol (17 = UDP)
    pkt.extend_from_slice(&[0x00, 0x00]); // Header checksum (ignored)
    pkt.extend_from_slice(&[10, 0, 0, 1]); // src IP
    pkt.extend_from_slice(&[10, 0, 0, 2]); // dst IP

    // UDP header (8 bytes)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&(payload.len() as u16 + 8).to_be_bytes()); // Length
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum (ignored)

    // Payload
    pkt.extend_from_slice(payload);
    pkt
}

#[test]
fn test_detector_with_rules_port_based() {
    let rules = vec![Rule {
        id: "alt-dns".into(),
        protocol: Protocol::Dns,
        condition: RuleCondition {
            dst_port: Some(5353),
            ..Default::default()
        },
        metadata: None,
    }];
    let mut detector = Detector::with_rules(rules);
    let pkt = build_udp_packet(12345, 5353, &[0x00; 16]);
    let result = detector.detect(&pkt).unwrap();
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.protocol, Protocol::Dns);
    assert_eq!(r.confidence, Confidence::CustomRule);
}

#[test]
fn test_detector_with_rules_no_match() {
    let rules = vec![Rule {
        id: "only-5353".into(),
        protocol: Protocol::Dns,
        condition: RuleCondition {
            dst_port: Some(5353),
            ..Default::default()
        },
        metadata: None,
    }];
    let mut detector = Detector::with_rules(rules);
    // 不匹配的端口 → 规则不应命中，走 DPI（或 None）
    // 使用短 payload (4 字节) 避免 DNS、NTP 等解析器误匹配全零数据
    let pkt = build_udp_packet(12345, 9999, &[0xde, 0xad, 0xbe, 0xef]);
    let result = detector.detect(&pkt).unwrap();
    // 9999 不在端口映射表中，DPI 也不识别 → None
    assert!(result.is_none());
}

#[test]
fn test_rules_only_mode_match() {
    let rules = vec![Rule {
        id: "match-8080".into(),
        protocol: Protocol::Http,
        condition: RuleCondition {
            dst_port: Some(8080),
            ..Default::default()
        },
        metadata: None,
    }];
    let mut detector = Detector::with_rules(rules);
    detector.set_rules_only(true);

    let pkt = build_udp_packet(12345, 8080, b"GET / HTTP/1.1\r\n");
    let result = detector.detect(&pkt).unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().protocol, Protocol::Http);
}

#[test]
fn test_rules_only_mode_no_match() {
    let rules = vec![Rule {
        id: "match-8080".into(),
        protocol: Protocol::Http,
        condition: RuleCondition {
            dst_port: Some(8080),
            ..Default::default()
        },
        metadata: None,
    }];
    let mut detector = Detector::with_rules(rules);
    detector.set_rules_only(true);

    // rules_only 且规则未命中 → None
    let pkt = build_udp_packet(12345, 9999, &[0x00; 16]);
    let result = detector.detect(&pkt).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_add_rule_dynamic() {
    let mut detector = Detector::new();
    detector.add_rule(Rule {
        id: "dynamic".into(),
        protocol: Protocol::Ssh,
        condition: RuleCondition {
            dst_port: Some(2222),
            ..Default::default()
        },
        metadata: None,
    });
    let pkt = build_udp_packet(12345, 2222, &[0x00; 8]);
    let result = detector.detect(&pkt).unwrap();
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.protocol, Protocol::Ssh);
    assert_eq!(r.confidence, Confidence::CustomRule);
}

#[test]
fn test_load_rules_json() {
    let mut detector = Detector::new();
    let json = r#"{
        "rules": [
            { "id": "custom-dns", "protocol": "Dns", "condition": { "dst_port": 5353 } }
        ]
    }"#;
    detector.load_rules_json(json).unwrap();
    let pkt = build_udp_packet(12345, 5353, &[0x00; 8]);
    let result = detector.detect(&pkt).unwrap();
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.protocol, Protocol::Dns);
    assert_eq!(r.confidence, Confidence::CustomRule);
}

#[test]
fn test_rule_engine_sni_match() {
    // 测试通过 RuleEngine 直接匹配 SNI 规则
    let mut engine = RuleEngine::new();
    engine.add_rule(Rule {
        id: "zoom-detect".into(),
        protocol: Protocol::Tls,
        condition: RuleCondition {
            sni_contains: Some("zoom".into()),
            ..Default::default()
        },
        metadata: None,
    });
    let ctx = RuleContext {
        src_port: 12345,
        dst_port: 443,
        sni: Some("client.zoom.us".into()),
        payload: vec![],
    };
    let result = engine.match_rule(&ctx).unwrap();
    assert_eq!(result.protocol, Protocol::Tls);
    assert_eq!(result.confidence, Confidence::CustomRule);
}

#[test]
fn test_detector_new_with_rule_feature() {
    // 验证当 feature=rule 时 Detector::new() 能正常构造
    let detector = Detector::new();
    let _ = detector;
}
