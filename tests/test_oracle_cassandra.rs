//! F50：Oracle/Cassandra 经双向入口的跨段识别

#![cfg(feature = "database")]

use rdpi::{Detector, Protocol};

const CLIENT: [u8; 4] = [192, 168, 1, 1];
const SERVER: [u8; 4] = [10, 0, 0, 1];
const BASE_TS_MS: u64 = 1_700_000_000_000;

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

/// 三次握手 + 客户端按 `segments` 顺序发送的多个 TCP 段
fn client_session(client_port: u16, server_port: u16, segments: &[&[u8]]) -> Vec<Vec<u8>> {
    let cseq = 1000u32;
    let sseq = 5000u32;
    let mut frames = vec![
        eth_ipv4(
            CLIENT,
            SERVER,
            6,
            &tcp(client_port, server_port, cseq, 0, 0x02, b""),
        ),
        eth_ipv4(
            SERVER,
            CLIENT,
            6,
            &tcp(server_port, client_port, sseq, cseq + 1, 0x12, b""),
        ),
        eth_ipv4(
            CLIENT,
            SERVER,
            6,
            &tcp(client_port, server_port, cseq + 1, sseq + 1, 0x10, b""),
        ),
    ];
    let mut offset = 0u32;
    for segment in segments {
        frames.push(eth_ipv4(
            CLIENT,
            SERVER,
            6,
            &tcp(
                client_port,
                server_port,
                cseq + 1 + offset,
                sseq + 1,
                0x18,
                segment,
            ),
        ));
        offset += segment.len() as u32;
    }
    frames
}

fn detect(frames: &[Vec<u8>]) -> Option<Protocol> {
    let mut detector = Detector::new();
    let mut last = None;
    for (index, frame) in frames.iter().enumerate() {
        if let Some(result) = detector
            .process_packet(frame, BASE_TS_MS + index as u64 * 10)
            .unwrap()
        {
            last = Some(result.protocol);
        }
    }
    last
}

#[test]
fn oracle_connect_split_across_segments_is_detected() {
    let payload = [0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    let frames = client_session(50030, 1521, &[&payload[..4], &payload[4..]]);
    assert_eq!(detect(&frames), Some(Protocol::Oracle));
}

fn cql_startup(cql_version: &str) -> Vec<u8> {
    let key = b"CQL_VERSION";
    let value = cql_version.as_bytes();
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&(key.len() as u16).to_be_bytes());
    body.extend_from_slice(key);
    body.extend_from_slice(&(value.len() as u16).to_be_bytes());
    body.extend_from_slice(value);
    let mut frame = vec![0x04, 0x00, 0x00, 0x01, 0x01];
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

#[test]
fn cassandra_startup_split_across_segments_is_detected() {
    let payload = cql_startup("3.0.0");
    let split = payload.len() / 2;
    let frames = client_session(50031, 9042, &[&payload[..split], &payload[split..]]);
    assert_eq!(detect(&frames), Some(Protocol::Cassandra));
}

#[test]
fn cassandra_internode_is_port_independent() {
    let mut payload = vec![0xCA, 0x55, 0x2D, 0xFA];
    payload.extend_from_slice(&[0u8; 15]);
    let frames = client_session(50032, 9999, &[&payload]);
    assert_eq!(detect(&frames), Some(Protocol::Cassandra));
}
