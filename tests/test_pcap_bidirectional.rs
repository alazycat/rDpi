//! P1：pcap/以太网入口接入双向流引擎
//!
//! 旧的 `detect_at` 是单向流模型（同一连接的两个方向各建一条流）；
//! 本文件锁定新入口的行为：
//! - `Detector::process_packet` 按双向规范五元组聚合；
//! - `PcapProcessor` 使用同一引擎，因此 DNS-over-TCP 等有状态协议可被识别；
//! - 一条连接只导出一条归一化记录。

#![cfg(all(feature = "pcap", feature = "json"))]

use rdpi::Detector;
use rdpi::pcap::PcapProcessor;
use std::path::PathBuf;

const CLIENT: [u8; 4] = [192, 168, 1, 1];
const SERVER: [u8; 4] = [10, 0, 0, 1];
const BASE_TS_US: u64 = 1_700_000_000_000_000;

fn eth_ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + 20 + l4.len());
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.push(64);
    frame.push(proto);
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(l4);
    frame
}

fn tcp(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend_from_slice(&sport.to_be_bytes());
    segment.extend_from_slice(&dport.to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&ack.to_be_bytes());
    segment.push(0x50);
    segment.push(flags);
    segment.extend_from_slice(&0xffffu16.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes());
    segment.extend_from_slice(payload);
    segment
}

fn dns_tcp_query(name: &str) -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    framed
}

/// DNS-over-TCP 会话：SYN / SYN-ACK / ACK / 客户端查询（长度前缀跨包场景由
/// `test_p1_flow.rs` 覆盖，此处只验证入口接线与双向聚合）
fn dns_over_tcp_frames() -> Vec<Vec<u8>> {
    let query = dns_tcp_query("example.com");
    vec![
        eth_ipv4(CLIENT, SERVER, 6, &tcp(50011, 53, 1000, 0, 0x02, b"")),
        eth_ipv4(SERVER, CLIENT, 6, &tcp(53, 50011, 5000, 1001, 0x12, b"")),
        eth_ipv4(CLIENT, SERVER, 6, &tcp(50011, 53, 1001, 5001, 0x10, b"")),
        eth_ipv4(CLIENT, SERVER, 6, &tcp(50011, 53, 1001, 5001, 0x18, &query)),
    ]
}

fn write_pcap(path: &PathBuf, frames: &[Vec<u8>]) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&65535u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    for (index, frame) in frames.iter().enumerate() {
        let ts = BASE_TS_US + index as u64 * 10_000;
        bytes.extend_from_slice(&((ts / 1_000_000) as u32).to_le_bytes());
        bytes.extend_from_slice(&((ts % 1_000_000) as u32).to_le_bytes());
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes.extend_from_slice(frame);
    }
    std::fs::write(path, bytes).expect("write pcap");
}

#[test]
fn process_packet_binds_both_directions_into_one_flow() {
    let mut detector = Detector::new();
    for frame in dns_over_tcp_frames() {
        detector.process_packet(&frame, BASE_TS_US / 1000).unwrap();
    }

    assert_eq!(detector.flow_count(), 1, "两个方向必须归入同一条双向流");
    let flows = detector.normalized_flows();
    assert_eq!(flows.len(), 1, "一条连接只导出一条记录");
    assert_eq!(
        flows[0].master_protocol.as_deref(),
        Some("Dns"),
        "DNS-over-TCP 需要经有状态 dissector 识别"
    );
}

#[test]
fn pcap_processor_uses_bidirectional_engine() {
    let path = std::env::temp_dir().join(format!("rdpi_bidirectional_{}.pcap", std::process::id()));
    write_pcap(&path, &dns_over_tcp_frames());

    let mut iter = PcapProcessor::new().process_file(&path).expect("open pcap");
    for item in iter.by_ref() {
        item.expect("process packet");
    }
    assert_eq!(iter.detector().flow_count(), 1);
    let flows = iter.detector().normalized_flows();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].master_protocol.as_deref(), Some("Dns"));

    let _ = std::fs::remove_file(&path);
}

fn eth_ipv4_udp(dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(8 + payload.len());
    datagram.extend_from_slice(&50020u16.to_be_bytes());
    datagram.extend_from_slice(&dst_port.to_be_bytes());
    datagram.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    datagram.extend_from_slice(&0u16.to_be_bytes());
    datagram.extend_from_slice(payload);
    eth_ipv4(CLIENT, SERVER, 17, &datagram)
}

#[test]
fn process_packet_applies_guess_after_giveup() {
    use rdpi::core::guess::GuessEngine;
    use rdpi::core::types::Protocol;

    let mut detector = Detector::new();
    detector.set_guess_engine(
        GuessEngine::builder()
            .with_custom_ports(vec![(9000, Protocol::Other(9000))])
            .build(),
    );

    let payload = b"\x00\x01\x02\x03";
    let mut last = None;
    for index in 0..5 {
        last = detector
            .process_packet(&eth_ipv4_udp(9000, payload), BASE_TS_US / 1000 + index)
            .unwrap();
    }

    assert_eq!(
        last.expect("giveup 后应产生猜测结果").protocol,
        Protocol::Other(9000)
    );
}

fn ssh_banner_frames(split_at: Option<usize>) -> Vec<Vec<u8>> {
    let banner = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n";
    let mut frames = vec![
        eth_ipv4(CLIENT, SERVER, 6, &tcp(50030, 22, 3000, 0, 0x02, b"")),
        eth_ipv4(SERVER, CLIENT, 6, &tcp(22, 50030, 7000, 3001, 0x12, b"")),
        eth_ipv4(CLIENT, SERVER, 6, &tcp(50030, 22, 3001, 7001, 0x10, b"")),
    ];
    match split_at {
        None => frames.push(eth_ipv4(
            SERVER,
            CLIENT,
            6,
            &tcp(22, 50030, 7001, 3001, 0x18, banner),
        )),
        Some(split) => {
            frames.push(eth_ipv4(
                SERVER,
                CLIENT,
                6,
                &tcp(22, 50030, 7001, 3001, 0x18, &banner[..split]),
            ));
            frames.push(eth_ipv4(
                SERVER,
                CLIENT,
                6,
                &tcp(22, 50030, 7001 + split as u32, 3001, 0x18, &banner[split..]),
            ));
        }
    }
    frames
}

#[test]
fn process_packet_reassembles_split_ssh_banner() {
    let mut detector = Detector::new();
    for (index, frame) in ssh_banner_frames(Some(8)).into_iter().enumerate() {
        detector
            .process_packet(&frame, BASE_TS_US / 1000 + index as u64)
            .unwrap();
    }

    let flows = detector.normalized_flows();
    assert_eq!(flows.len(), 1);
    assert_eq!(
        flows[0].master_protocol.as_deref(),
        Some("Ssh"),
        "跨 TCP 段的 SSH banner 必须按累积字节流识别"
    );
}

#[test]
fn process_packet_does_not_treat_continuation_as_new_payload() {
    // 前半段为无法识别的二进制；后半段恰好是完整 HTTP 请求。
    // 续段不得脱离流前缀单独参与无状态检测。
    let mut detector = Detector::new();
    let frames = vec![
        eth_ipv4(SERVER, CLIENT, 6, &tcp(80, 50031, 9000, 0, 0x02, b"")),
        eth_ipv4(CLIENT, SERVER, 6, &tcp(50031, 80, 500, 9001, 0x12, b"")),
        eth_ipv4(SERVER, CLIENT, 6, &tcp(80, 50031, 9001, 501, 0x10, b"")),
        eth_ipv4(
            SERVER,
            CLIENT,
            6,
            &tcp(80, 50031, 9001, 501, 0x18, b"\x00\x01\x02\x03"),
        ),
        eth_ipv4(
            SERVER,
            CLIENT,
            6,
            &tcp(
                80,
                50031,
                9005,
                501,
                0x18,
                b"GET / HTTP/1.1\r\nHost: late.example\r\n\r\n",
            ),
        ),
    ];
    for (index, frame) in frames.into_iter().enumerate() {
        detector
            .process_packet(&frame, BASE_TS_US / 1000 + index as u64)
            .unwrap();
    }

    assert_eq!(
        detector.normalized_flows()[0].master_protocol,
        None,
        "续段单独命中不得产生分类"
    );
}

#[test]
fn process_packet_reassembles_ssh_banner_split_mid_line() {
    // 在 banner 中部切分：前半段仍以 "SSH-" 开头但行未结束。
    // 若此时让低特异性 detector 先行，会被 IKE 等抢走。
    let mut detector = Detector::new();
    for (index, frame) in ssh_banner_frames(Some(23)).into_iter().enumerate() {
        detector
            .process_packet(&frame, BASE_TS_US / 1000 + index as u64)
            .unwrap();
    }

    let flows = detector.normalized_flows();
    assert_eq!(flows.len(), 1);
    assert_eq!(
        flows[0].master_protocol.as_deref(),
        Some("Ssh"),
        "banner 行未结束时不得被其他探测器抢占"
    );
}
