//! P1 分类核心：双向流基础行为测试
//!
//! 首个垂直切片：FlowKey 规范化 + Direction。
//! 后续测试逐步覆盖 Flow 双向计数、L3 入口、caller-owned Flow API、
//! 逐包分类状态机。

use rdpi::Detector;
use rdpi::core::flow::Flow;
use rdpi::core::types::{
    ClassificationState, Confidence, Direction, DissectorState, FlowKey, MAX_PROTOCOL_STACK,
    Metadata, Protocol, ProtocolStack, TransportProto,
};
use rdpi::parser::parse_l3_packet;
use rdpi::protocols::{ProtocolDetector, Registry};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

fn key(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> FlowKey {
    FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::from(src)),
        dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
        src_port,
        dst_port,
        transport: TransportProto::Tcp,
    }
}

#[test]
fn flow_key_canonicalizes_both_directions_to_same_key() {
    let forward = key([10, 0, 0, 1], 12345, [10, 0, 0, 2], 80);
    let reverse = forward.reverse();

    let (canonical, forward_dir) = forward.canonical();
    let (canonical_reverse, reverse_dir) = reverse.canonical();

    assert_eq!(canonical, canonical_reverse);
    assert_eq!(canonical, forward);
    assert_eq!(forward_dir, Direction::Forward);
    assert_eq!(reverse_dir, Direction::Reverse);
}

#[test]
fn bidirectional_flow_uses_canonical_key_and_reports_direction() {
    let forward = key([10, 0, 0, 1], 12345, [10, 0, 0, 2], 80);
    let reverse = forward.reverse();

    let flow = Flow::new_bidirectional(forward.clone());
    assert_eq!(flow.key, forward.canonical().0);
    assert_eq!(flow.initiator, Direction::Forward);
    assert_eq!(flow.direction_of(&forward), Some(Direction::Forward));
    assert_eq!(flow.direction_of(&reverse), Some(Direction::Reverse));

    // 首包方向为反向时，initiator 记录反向，但流键仍规范化。
    let flow_from_reverse = Flow::new_bidirectional(reverse.clone());
    assert_eq!(flow_from_reverse.key, forward.canonical().0);
    assert_eq!(flow_from_reverse.initiator, Direction::Reverse);
}

fn make_l3_udp_packet_between(
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
        0x00, // IPv4, IHL=5, DSCP=0
        (total_len >> 8) as u8,
        (total_len & 0xff) as u8,
        0x00,
        0x01, // identification
        0x00,
        0x00, // flags + fragment offset
        0x40, // TTL
        0x11, // UDP
        0x00,
        0x00, // checksum (unchecked by parser)
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

fn make_l3_udp_packet(payload: &[u8]) -> Vec<u8> {
    make_l3_udp_packet_between([192, 168, 1, 1], 12345, [10, 0, 0, 1], 53, payload)
}

fn make_l3_tcp_packet_between(
    src: [u8; 4],
    src_port: u16,
    dst: [u8; 4],
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = (20 + 20 + payload.len()) as u16;
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
        0x06, // TCP
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
        0x00,
        0x00,
        0x00,
        0x01, // seq
        0x00,
        0x00,
        0x00,
        0x00, // ack
        0x50, // data offset = 5 * 4
        0x18, // PSH | ACK
        0xff,
        0xff, // window
        0x00,
        0x00, // checksum
        0x00,
        0x00, // urgent
    ];
    packet.extend_from_slice(payload);
    packet
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

fn frame_dns_over_tcp(message: &[u8]) -> Vec<u8> {
    let mut framed = (message.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    framed
}

/// 构造带 SNI 的 TLS 1.3 ClientHello 记录（单条完整 TLS record）
fn make_tls_client_hello_with_sni(hostname: &str) -> Vec<u8> {
    let hostname_bytes = hostname.as_bytes();

    let mut sni_ext = vec![
        0x00, 0x00, // Extension Type: SNI
        0x00, 0x00, // Extension Length: placeholder
        0x00, 0x00, // Server Name List Length: placeholder
        0x00, // Server Name Type: hostname
    ];
    let name_len = hostname_bytes.len() as u16;
    sni_ext.push((name_len >> 8) as u8);
    sni_ext.push((name_len & 0xFF) as u8);
    sni_ext.extend_from_slice(hostname_bytes);

    let list_len = (hostname_bytes.len() + 3) as u16;
    sni_ext[4] = (list_len >> 8) as u8;
    sni_ext[5] = (list_len & 0xFF) as u8;
    let ext_len = (hostname_bytes.len() + 5) as u16;
    sni_ext[2] = (ext_len >> 8) as u8;
    sni_ext[3] = (ext_len & 0xFF) as u8;

    let versions_ext = vec![
        0x00, 0x2b, // supported_versions
        0x00, 0x03, // length
        0x02, // list length
        0x03, 0x04, // TLS 1.3
    ];

    let extensions_len = (sni_ext.len() + versions_ext.len()) as u16;
    let mut extensions = vec![(extensions_len >> 8) as u8, (extensions_len & 0xFF) as u8];
    extensions.extend(sni_ext);
    extensions.extend(versions_ext);

    let mut data = vec![
        0x16, // Handshake
        0x03, 0x01, // record version
        0x00, 0x00, // record length placeholder
    ];
    data.push(0x01); // ClientHello
    data.extend_from_slice(&[0x00, 0x00, 0x00]); // handshake length placeholder
    data.extend_from_slice(&[0x03, 0x03]); // client version
    data.extend_from_slice(&[0u8; 32]); // random
    data.push(0x00); // session id length
    data.extend_from_slice(&[0x00, 0x02]); // cipher suites length
    data.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    data.push(0x01); // compression methods length
    data.push(0x00); // null compression
    data.extend(extensions);

    let handshake_len = data.len() - 9;
    let record_len = data.len() - 5;
    data[6] = ((handshake_len >> 16) & 0xFF) as u8;
    data[7] = ((handshake_len >> 8) & 0xFF) as u8;
    data[8] = (handshake_len & 0xFF) as u8;
    data[3] = ((record_len >> 8) & 0xFF) as u8;
    data[4] = (record_len & 0xFF) as u8;
    data
}

#[test]
fn protocol_stack_pushes_in_order_and_reports_master_app() {
    let mut stack = ProtocolStack::new();
    assert!(stack.is_empty());
    assert_eq!(stack.master(), None);
    assert_eq!(stack.app(), None);

    assert!(stack.push(Protocol::Tls));
    assert!(stack.push(Protocol::Http));
    assert_eq!(stack.len(), 2);
    assert_eq!(stack.master(), Some(Protocol::Tls));
    assert_eq!(stack.app(), Some(Protocol::Http));
    assert_eq!(
        stack.iter().collect::<Vec<_>>(),
        vec![Protocol::Tls, Protocol::Http]
    );
    assert!(stack.contains(Protocol::Tls));
    assert!(!stack.contains(Protocol::Dns));

    stack.clear();
    assert!(stack.is_empty());
}

#[test]
fn protocol_stack_deduplicates_and_enforces_capacity() {
    let mut stack = ProtocolStack::new();
    assert!(stack.push(Protocol::Tls));
    assert!(!stack.push(Protocol::Tls), "duplicate must be ignored");
    assert_eq!(stack.len(), 1);

    let distinct = [
        Protocol::Tcp,
        Protocol::Udp,
        Protocol::Icmp,
        Protocol::Dns,
        Protocol::Http,
        Protocol::Tls,
        Protocol::Quic,
        Protocol::Http3,
    ];
    stack.clear();
    for protocol in distinct {
        assert!(stack.push(protocol));
    }
    assert_eq!(stack.len(), MAX_PROTOCOL_STACK);
    assert!(!stack.push(Protocol::Dtls), "full stack must reject");
    assert_eq!(stack.len(), MAX_PROTOCOL_STACK);
}

#[test]
fn parse_l3_packet_parses_ipv4_without_ethernet() {
    let parsed = parse_l3_packet(&make_l3_udp_packet(b"hello")).unwrap();

    assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(parsed.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(parsed.src_port, 12345);
    assert_eq!(parsed.dst_port, 53);
    assert_eq!(parsed.transport, TransportProto::Udp);
    assert_eq!(parsed.payload, b"hello");
}

#[test]
fn parse_l3_packet_rejects_non_ip_input() {
    assert!(parse_l3_packet(&[0x00u8; 14]).is_err());
}

#[test]
fn process_l3_packet_classifies_and_tracks_both_directions() {
    let mut detector = Detector::new();
    let payload = make_dns_query_payload();
    let client_packet =
        make_l3_udp_packet_between([192, 168, 1, 1], 12345, [10, 0, 0, 1], 53, &payload);
    let parsed = parse_l3_packet(&client_packet).unwrap();
    let packet_key = FlowKey {
        src_ip: parsed.src_ip,
        dst_ip: parsed.dst_ip,
        src_port: parsed.src_port,
        dst_port: parsed.dst_port,
        transport: parsed.transport,
    };
    let mut flow = Flow::new_bidirectional(packet_key);

    let result = detector
        .process_l3_packet(&mut flow, &client_packet, 1_000)
        .unwrap()
        .expect("DNS query should be classified");
    assert_eq!(result.protocol, Protocol::Dns);
    assert_eq!(result.protocol_stack.master(), Some(Protocol::Dns));
    assert_eq!(flow.protocol, Some(Protocol::Dns));
    assert_eq!(flow.protocol_stack.master(), Some(Protocol::Dns));
    assert_eq!(flow.classification_state, ClassificationState::Classified);
    assert_eq!(flow.dissector_state, DissectorState::None);
    assert_eq!(flow.packets_seen, 1);
    assert_eq!(flow.packets_forward, 1);
    assert_eq!(flow.packets_reverse, 0);
    assert_eq!(flow.first_seen_ms, Some(1_000));
    assert_eq!(flow.last_seen_ms, Some(1_000));

    // 反向包应映射到同一条双向流，且不重复分类。
    let server_packet =
        make_l3_udp_packet_between([10, 0, 0, 1], 53, [192, 168, 1, 1], 12345, &payload);
    let result = detector
        .process_l3_packet(&mut flow, &server_packet, 1_010)
        .unwrap()
        .expect("已定型流应回显协议");
    assert_eq!(result.protocol, Protocol::Dns);
    assert_eq!(result.protocol_stack.master(), Some(Protocol::Dns));
    assert_eq!(flow.packets_seen, 2);
    assert_eq!(flow.packets_forward, 1);
    assert_eq!(flow.packets_reverse, 1);
    assert_eq!(flow.last_seen_ms, Some(1_010));
}

struct PartialThenFull {
    calls: Arc<AtomicU32>,
}

impl ProtocolDetector for PartialThenFull {
    fn name(&self) -> &'static str {
        "partial_then_full"
    }

    fn detect(&self, _payload: &[u8]) -> Option<rdpi::DetectionResult> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            Some(rdpi::DetectionResult::new(Protocol::Dns).with_confidence(Confidence::DpiPartial))
        } else {
            Some(rdpi::DetectionResult::new(Protocol::Http).with_confidence(Confidence::Dpi))
        }
    }
}

#[test]
fn process_l3_packet_upgrades_partial_to_classified() {
    let calls = Arc::new(AtomicU32::new(0));
    let mut registry = Registry::new();
    registry.register(Box::new(PartialThenFull {
        calls: calls.clone(),
    }));
    let mut detector = Detector::with_registry(registry);

    let packet = make_l3_udp_packet_between([10, 0, 0, 1], 12345, [10, 0, 0, 2], 80, b"partial");
    let parsed = parse_l3_packet(&packet).unwrap();
    let packet_key = FlowKey {
        src_ip: parsed.src_ip,
        dst_ip: parsed.dst_ip,
        src_port: parsed.src_port,
        dst_port: parsed.dst_port,
        transport: parsed.transport,
    };
    let mut flow = Flow::new_bidirectional(packet_key);

    let first = detector
        .process_l3_packet(&mut flow, &packet, 1)
        .unwrap()
        .expect("first packet should return a partial result");
    assert_eq!(first.protocol, Protocol::Dns);
    assert_eq!(first.confidence, Confidence::DpiPartial);
    assert_eq!(flow.classification_state, ClassificationState::Partial);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let second = detector
        .process_l3_packet(&mut flow, &packet, 2)
        .unwrap()
        .expect("second packet should upgrade the classification");
    assert_eq!(second.protocol, Protocol::Http);
    assert_eq!(second.confidence, Confidence::Dpi);
    assert_eq!(flow.protocol, Some(Protocol::Http));
    assert_eq!(flow.classification_state, ClassificationState::Classified);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(flow.protocol_stack.contains(Protocol::Dns));
    assert!(flow.protocol_stack.contains(Protocol::Http));

    let third = detector
        .process_l3_packet(&mut flow, &packet, 3)
        .unwrap()
        .expect("classified flow should replay");
    assert_eq!(third.protocol, Protocol::Http);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "classified flow must not re-run DPI"
    );
}

#[test]
fn http_request_split_across_tcp_packets_is_reassembled() {
    let mut detector = Detector::new();
    let first = make_l3_tcp_packet_between(
        [192, 168, 1, 1],
        12345,
        [10, 0, 0, 1],
        80,
        b"GET /index.html HTTP/1.1\r\nHost: exa",
    );
    let second = make_l3_tcp_packet_between(
        [192, 168, 1, 1],
        12345,
        [10, 0, 0, 1],
        80,
        b"mple.com\r\n\r\n",
    );
    let parsed = parse_l3_packet(&first).unwrap();
    let packet_key = FlowKey {
        src_ip: parsed.src_ip,
        dst_ip: parsed.dst_ip,
        src_port: parsed.src_port,
        dst_port: parsed.dst_port,
        transport: parsed.transport,
    };
    let mut flow = Flow::new_bidirectional(packet_key);

    let first_result = detector.process_l3_packet(&mut flow, &first, 1).unwrap();
    assert!(
        first_result.is_none(),
        "partial header must not classify yet"
    );
    assert!(matches!(flow.dissector_state, DissectorState::Http(_)));
    assert_eq!(flow.classification_state, ClassificationState::Inspecting);
    assert!(flow.protocol.is_none());

    let second_result = detector
        .process_l3_packet(&mut flow, &second, 2)
        .unwrap()
        .expect("complete header should classify");
    assert_eq!(second_result.protocol, Protocol::Http);
    assert_eq!(flow.classification_state, ClassificationState::Classified);
    match second_result.metadata {
        Metadata::Http(meta) => {
            assert_eq!(meta.host.as_deref(), Some("example.com"));
            assert_eq!(meta.method.as_deref(), Some("GET"));
            assert_eq!(meta.path.as_deref(), Some("/index.html"));
        }
        _ => panic!("expected HTTP metadata"),
    }
}

#[test]
fn dns_over_tcp_reassembles_split_message() {
    let mut detector = Detector::new();
    let query = make_dns_query_payload();
    let framed = frame_dns_over_tcp(&query);
    let split = 2 + query.len() / 2;
    let first_packet =
        make_l3_tcp_packet_between([192, 168, 1, 1], 23456, [10, 0, 0, 1], 53, &framed[..split]);
    let second_packet =
        make_l3_tcp_packet_between([192, 168, 1, 1], 23456, [10, 0, 0, 1], 53, &framed[split..]);
    let parsed = parse_l3_packet(&first_packet).unwrap();
    let packet_key = FlowKey {
        src_ip: parsed.src_ip,
        dst_ip: parsed.dst_ip,
        src_port: parsed.src_port,
        dst_port: parsed.dst_port,
        transport: parsed.transport,
    };
    let mut flow = Flow::new_bidirectional(packet_key);

    let first = detector
        .process_l3_packet(&mut flow, &first_packet, 1)
        .unwrap();
    assert!(first.is_none(), "partial DNS-over-TCP message must wait");
    assert!(matches!(flow.dissector_state, DissectorState::DnsTcp(_)));
    assert_eq!(flow.classification_state, ClassificationState::Inspecting);

    let second = detector
        .process_l3_packet(&mut flow, &second_packet, 2)
        .unwrap()
        .expect("complete DNS-over-TCP message should classify");
    assert_eq!(second.protocol, Protocol::Dns);
    match second.metadata {
        Metadata::Dns(meta) => {
            assert_eq!(meta.query_domain.as_deref(), Some("example.com"));
        }
        _ => panic!("expected DNS metadata"),
    }
}

#[test]
fn dns_over_tcp_buffers_split_length_prefix() {
    let mut detector = Detector::new();
    let query = make_dns_query_payload();
    let framed = frame_dns_over_tcp(&query);
    let first_packet =
        make_l3_tcp_packet_between([192, 168, 1, 1], 23457, [10, 0, 0, 1], 53, &framed[..1]);
    let second_packet =
        make_l3_tcp_packet_between([192, 168, 1, 1], 23457, [10, 0, 0, 1], 53, &framed[1..]);
    let parsed = parse_l3_packet(&first_packet).unwrap();
    let packet_key = FlowKey {
        src_ip: parsed.src_ip,
        dst_ip: parsed.dst_ip,
        src_port: parsed.src_port,
        dst_port: parsed.dst_port,
        transport: parsed.transport,
    };
    let mut flow = Flow::new_bidirectional(packet_key);

    let first = detector
        .process_l3_packet(&mut flow, &first_packet, 1)
        .unwrap();
    assert!(first.is_none(), "1-byte length prefix must be buffered");
    assert!(matches!(flow.dissector_state, DissectorState::DnsTcp(_)));

    let second = detector
        .process_l3_packet(&mut flow, &second_packet, 2)
        .unwrap()
        .expect("message after split length prefix should classify");
    assert_eq!(second.protocol, Protocol::Dns);
    match second.metadata {
        Metadata::Dns(meta) => {
            assert_eq!(meta.query_domain.as_deref(), Some("example.com"));
        }
        _ => panic!("expected DNS metadata"),
    }
}

#[test]
fn tls_client_hello_split_across_tcp_packets_is_reassembled() {
    let mut detector = Detector::new();
    let hello = make_tls_client_hello_with_sni("example.com");
    let split = 7; // record header + 2 bytes of handshake header
    let first_packet =
        make_l3_tcp_packet_between([192, 168, 1, 1], 12345, [10, 0, 0, 1], 443, &hello[..split]);
    let second_packet =
        make_l3_tcp_packet_between([192, 168, 1, 1], 12345, [10, 0, 0, 1], 443, &hello[split..]);
    let parsed = parse_l3_packet(&first_packet).unwrap();
    let packet_key = FlowKey {
        src_ip: parsed.src_ip,
        dst_ip: parsed.dst_ip,
        src_port: parsed.src_port,
        dst_port: parsed.dst_port,
        transport: parsed.transport,
    };
    let mut flow = Flow::new_bidirectional(packet_key);

    let first = detector
        .process_l3_packet(&mut flow, &first_packet, 1)
        .unwrap();
    assert!(first.is_none(), "partial TLS record must wait");
    assert!(matches!(flow.dissector_state, DissectorState::Tls(_)));
    assert_eq!(flow.classification_state, ClassificationState::Inspecting);

    let second = detector
        .process_l3_packet(&mut flow, &second_packet, 2)
        .unwrap()
        .expect("complete TLS record should classify");
    assert_eq!(second.protocol, Protocol::Tls);
    match second.metadata {
        Metadata::Tls(meta) => assert_eq!(meta.sni.as_deref(), Some("example.com")),
        _ => panic!("expected TLS metadata"),
    }
}

#[test]
fn tls_record_header_split_across_tcp_packets_is_reassembled() {
    let mut detector = Detector::new();
    let hello = make_tls_client_hello_with_sni("example.com");
    let split = 3; // inside the 5-byte TLS record header
    let first_packet =
        make_l3_tcp_packet_between([192, 168, 1, 1], 12346, [10, 0, 0, 1], 443, &hello[..split]);
    let second_packet =
        make_l3_tcp_packet_between([192, 168, 1, 1], 12346, [10, 0, 0, 1], 443, &hello[split..]);
    let parsed = parse_l3_packet(&first_packet).unwrap();
    let packet_key = FlowKey {
        src_ip: parsed.src_ip,
        dst_ip: parsed.dst_ip,
        src_port: parsed.src_port,
        dst_port: parsed.dst_port,
        transport: parsed.transport,
    };
    let mut flow = Flow::new_bidirectional(packet_key);

    let first = detector
        .process_l3_packet(&mut flow, &first_packet, 1)
        .unwrap();
    assert!(first.is_none(), "partial record header must be buffered");
    assert!(matches!(flow.dissector_state, DissectorState::Tls(_)));

    let second = detector
        .process_l3_packet(&mut flow, &second_packet, 2)
        .unwrap()
        .expect("record after split header should classify");
    assert_eq!(second.protocol, Protocol::Tls);
    match second.metadata {
        Metadata::Tls(meta) => assert_eq!(meta.sni.as_deref(), Some("example.com")),
        _ => panic!("expected TLS metadata"),
    }
}

#[test]
fn process_l3_packet_rejects_packet_from_another_flow() {
    let mut detector = Detector::new();
    let mut flow = Flow::new_bidirectional(key([10, 0, 0, 1], 12345, [10, 0, 0, 2], 80));
    let other = make_l3_udp_packet_between([192, 168, 1, 1], 1, [10, 0, 0, 9], 2, b"x");

    assert!(detector.process_l3_packet(&mut flow, &other, 0).is_err());
}
