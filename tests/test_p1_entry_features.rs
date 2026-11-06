//! P1 新入口（`Detector::process_l3_packet`）的规则 / 风险 / JA4 集成测试

use rdpi::Detector;
use rdpi::core::flow::Flow;
use rdpi::core::types::{FlowKey, Protocol, TransportProto};
use rdpi::parser::parse_l3_packet;
use std::net::{IpAddr, Ipv4Addr};

fn make_l3_udp_between(
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
        0x00,
        (total_len >> 8) as u8,
        (total_len & 0xff) as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        0x40,
        0x11,
        0x00,
        0x00,
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
        0x00,
    ];
    packet.extend_from_slice(payload);
    packet
}

fn make_l3_tcp_with_seq(
    src: [u8; 4],
    src_port: u16,
    dst: [u8; 4],
    dst_port: u16,
    seq: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = (20 + 20 + payload.len()) as u16;
    let mut packet = vec![
        0x45,
        0x00,
        (total_len >> 8) as u8,
        (total_len & 0xff) as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        0x40,
        0x06,
        0x00,
        0x00,
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
        (seq >> 24) as u8,
        (seq >> 16) as u8,
        (seq >> 8) as u8,
        (seq & 0xff) as u8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x50,
        flags,
        0xff,
        0xff,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    packet.extend_from_slice(payload);
    packet
}

fn key_of(packet: &[u8]) -> FlowKey {
    let parsed = parse_l3_packet(packet).unwrap();
    FlowKey {
        src_ip: parsed.src_ip,
        dst_ip: parsed.dst_ip,
        src_port: parsed.src_port,
        dst_port: parsed.dst_port,
        transport: parsed.transport,
    }
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

const CLIENT: [u8; 4] = [192, 168, 1, 1];
const SERVER: [u8; 4] = [10, 0, 0, 1];

fn tcp(
    src: [u8; 4],
    src_port: u16,
    dst: [u8; 4],
    dst_port: u16,
    seq: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    make_l3_tcp_with_seq(src, src_port, dst, dst_port, seq, flags, payload)
}

#[test]
fn process_l3_packet_observes_tcp_ja4_fingerprints() {
    let mut detector = Detector::new();
    let syn = tcp(CLIENT, 12345, SERVER, 80, 1_000, 0x02, b"");
    let syn_ack = tcp(SERVER, 80, CLIENT, 12345, 5_000, 0x12, b"");
    let http = tcp(
        CLIENT,
        12345,
        SERVER,
        80,
        1_001,
        0x18,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    let mut flow = Flow::new_bidirectional(key_of(&syn));

    assert!(
        detector
            .process_l3_packet(&mut flow, &syn, 1_000)
            .unwrap()
            .is_none()
    );
    assert!(
        detector
            .process_l3_packet(&mut flow, &syn_ack, 1_010)
            .unwrap()
            .is_none()
    );
    let result = detector
        .process_l3_packet(&mut flow, &http, 1_020)
        .unwrap()
        .expect("HTTP request should classify");

    assert_eq!(result.protocol, Protocol::Http);
    assert!(result.ja4t.is_some(), "initial SYN must yield JA4T");
    assert!(result.ja4ts.is_some(), "SYN-ACK must yield JA4TS");
    assert_eq!(
        result.ja4ls.as_deref(),
        Some("5000_64"),
        "JA4L-S = (SYN-ACK - SYN)/2 with server TTL"
    );
    assert_eq!(
        result.ja4lc.as_deref(),
        Some("5000_64"),
        "JA4L-C = (client packet - SYN-ACK)/2 with client TTL"
    );
    assert_eq!(flow.ja4t, result.ja4t);
    assert_eq!(flow.ja4ls, result.ja4ls);
}

#[cfg(feature = "tls")]
fn tls_record(body: &[u8]) -> Vec<u8> {
    let mut record = vec![0x16, 0x03, 0x03];
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(body);
    record
}

#[cfg(feature = "tls")]
fn handshake_header(msg_type: u8, body_len: usize) -> Vec<u8> {
    let mut header = vec![msg_type];
    header.extend_from_slice(&(body_len as u32).to_be_bytes()[1..]);
    header
}

#[cfg(feature = "tls")]
fn client_hello_payload() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x11; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x00, 0x02]);
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&[0x00, 0x00]);
    let mut hs = handshake_header(0x01, body.len());
    hs.extend_from_slice(&body);
    tls_record(&hs)
}

#[cfg(feature = "tls")]
fn server_hello_payload() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x22; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&[0x00, 0x00]);
    let mut hs = handshake_header(0x02, body.len());
    hs.extend_from_slice(&body);
    tls_record(&hs)
}

#[cfg(feature = "tls")]
#[test]
fn process_l3_packet_appends_tls_ja4l_deltas() {
    let mut detector = Detector::new();
    let syn = tcp(CLIENT, 54321, SERVER, 443, 1_000, 0x02, b"");
    let syn_ack = tcp(SERVER, 443, CLIENT, 54321, 5_000, 0x12, b"");
    let ack = tcp(CLIENT, 54321, SERVER, 443, 1_001, 0x10, b"");
    let client_hello = tcp(
        CLIENT,
        54321,
        SERVER,
        443,
        1_001,
        0x18,
        &client_hello_payload(),
    );
    let server_hello = tcp(
        SERVER,
        443,
        CLIENT,
        54321,
        5_001,
        0x18,
        &server_hello_payload(),
    );
    let data = tcp(CLIENT, 54321, SERVER, 443, 2_001, 0x18, &[1, 2, 3]);
    let mut flow = Flow::new_bidirectional(key_of(&syn));

    detector.process_l3_packet(&mut flow, &syn, 1_000).unwrap();
    detector
        .process_l3_packet(&mut flow, &syn_ack, 1_010)
        .unwrap();
    detector.process_l3_packet(&mut flow, &ack, 1_030).unwrap();

    // D：ClientHello（t=40ms）→ 基指纹 ja4ls = (10ms)/2 = 5000
    let result = detector
        .process_l3_packet(&mut flow, &client_hello, 1_040)
        .unwrap()
        .expect("ClientHello should classify as TLS");
    assert_eq!(result.protocol, Protocol::Tls);
    assert_eq!(result.ja4ls.as_deref(), Some("5000_64"));

    // E：ServerHello（t=50ms）→ ja4ls 追加 (E-D)/2 = 5000
    let result = detector
        .process_l3_packet(&mut flow, &server_hello, 1_050)
        .unwrap()
        .expect("ServerHello should enrich TLS metadata");
    assert_eq!(result.ja4ls.as_deref(), Some("5000_64_5000"));

    // F：首个有载荷客户端包（t=62ms）→ ja4lc 追加 (F-E)/2 = 6000
    let result = detector
        .process_l3_packet(&mut flow, &data, 1_062)
        .unwrap()
        .expect("classified TLS flow should replay");
    assert_eq!(result.ja4lc.as_deref(), Some("10000_64_6000"));
}

#[cfg(feature = "ssh")]
#[test]
fn process_l3_packet_builds_ja4ssh_window() {
    let mut detector = Detector::new();
    let syn = tcp(CLIENT, 40000, SERVER, 22, 100, 0x02, b"");
    let banner = tcp(
        CLIENT,
        40000,
        SERVER,
        22,
        101,
        0x18,
        b"SSH-2.0-OpenSSH_9.0\r\n",
    );
    let mut flow = Flow::new_bidirectional(key_of(&syn));
    detector.process_l3_packet(&mut flow, &syn, 1).unwrap();
    let result = detector
        .process_l3_packet(&mut flow, &banner, 2)
        .unwrap()
        .expect("SSH banner should classify");
    assert_eq!(result.protocol, Protocol::Ssh);

    let mut client_seq = 101 + b"SSH-2.0-OpenSSH_9.0\r\n".len() as u32;
    let mut server_seq = 5_000u32;
    let mut last = None;
    for i in 0..200u64 {
        let packet = if i % 2 == 0 {
            let p = tcp(CLIENT, 40000, SERVER, 22, client_seq, 0x18, &[0x01]);
            client_seq += 1;
            p
        } else {
            let p = tcp(SERVER, 22, CLIENT, 40000, server_seq, 0x18, &[0x02]);
            server_seq += 1;
            p
        };
        last = detector
            .process_l3_packet(&mut flow, &packet, 3 + i)
            .unwrap();
    }

    let result = last.expect("classified SSH flow should replay");
    assert_eq!(result.ja4ssh.as_deref(), Some("c1s1_c100s100_c0s0"));
    assert!(flow.ja4ssh.is_some());
}

#[cfg(feature = "rule")]
#[test]
fn process_l3_packet_applies_custom_rules_before_dpi() {
    use rdpi::rule::{Rule, RuleCondition};

    let detector_with_rule = vec![Rule {
        id: "custom-8080".to_string(),
        protocol: Protocol::Http,
        condition: RuleCondition {
            dst_port: Some(8080),
            ..Default::default()
        },
        metadata: None,
    }];
    let mut detector = Detector::with_rules(detector_with_rule);
    let packet = make_l3_udp_between(CLIENT, 12345, SERVER, 8080, b"not-http");
    let mut flow = Flow::new_bidirectional(key_of(&packet));

    let result = detector
        .process_l3_packet(&mut flow, &packet, 1)
        .unwrap()
        .expect("custom rule should classify before DPI");
    assert_eq!(result.protocol, Protocol::Http);
    assert_eq!(result.confidence, rdpi::Confidence::CustomRule);
    assert_eq!(flow.protocol, Some(Protocol::Http));
    assert_eq!(
        flow.classification_state,
        rdpi::core::types::ClassificationState::Classified
    );
}

#[cfg(feature = "rule")]
#[test]
fn process_l3_packet_rules_only_skips_dpi() {
    let mut detector = Detector::with_rules(Vec::new());
    detector.set_rules_only(true);
    let packet = make_l3_udp_between(CLIENT, 12345, SERVER, 53, &make_dns_query_payload());
    let mut flow = Flow::new_bidirectional(key_of(&packet));

    let result = detector.process_l3_packet(&mut flow, &packet, 1).unwrap();
    assert!(
        result.is_none(),
        "rules-only mode must not fall back to DPI"
    );
    assert!(flow.protocol.is_none());
    assert_eq!(
        flow.classification_state,
        rdpi::core::types::ClassificationState::Inspecting
    );
}

#[cfg(feature = "risk")]
#[test]
fn process_l3_packet_attaches_risk_results() {
    use rdpi::risk::types::RiskFlag;

    let mut detector = Detector::new();
    let query = make_dns_query_payload();
    let first = make_l3_udp_between(CLIENT, 12345, SERVER, 53, &query);
    let mut flow = Flow::new_bidirectional(key_of(&first));
    let result = detector
        .process_l3_packet(&mut flow, &first, 1)
        .unwrap()
        .expect("DNS query should classify");
    assert_eq!(result.protocol, Protocol::Dns);

    // 已定型 DNS 流上的大响应包触发 DnsLargePacket
    let large = make_l3_udp_between(CLIENT, 12345, SERVER, 53, &[0u8; 600]);
    let result = detector
        .process_l3_packet(&mut flow, &large, 2)
        .unwrap()
        .expect("classified flow should replay");
    assert!(
        result
            .risks
            .iter()
            .any(|r| r.flag == RiskFlag::DnsLargePacket),
        "risk must be attached to the detection result"
    );
    assert!(
        flow.risks
            .iter()
            .any(|r| r.flag == RiskFlag::DnsLargePacket),
        "risk must be recorded on the flow"
    );
}

#[test]
fn process_l3_packet_tracks_packet_flow_ownership() {
    // 非本流包必须报错，避免跨流状态污染
    let mut detector = Detector::new();
    let packet = make_l3_udp_between(CLIENT, 12345, SERVER, 53, &make_dns_query_payload());
    let other = make_l3_udp_between(
        [172, 16, 0, 1],
        9999,
        [172, 16, 0, 2],
        53,
        &make_dns_query_payload(),
    );
    let mut flow = Flow::new_bidirectional(key_of(&packet));
    assert!(detector.process_l3_packet(&mut flow, &other, 1).is_err());

    let parsed = parse_l3_packet(&packet).unwrap();
    assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(parsed.transport, TransportProto::Udp);
}
