//! F51：AFP/DRDA 经双向入口的跨段识别

#![cfg(any(feature = "storage", feature = "database"))]

use rdpi::Detector;

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

fn detect(frames: &[Vec<u8>]) -> Option<rdpi::Protocol> {
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

#[cfg(feature = "storage")]
#[test]
fn afp_dsi_split_across_segments_is_detected() {
    let payload = [
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let frames = client_session(50040, 548, &[&payload[..8], &payload[8..]]);
    assert_eq!(detect(&frames), Some(rdpi::Protocol::Afp));
}

#[cfg(feature = "database")]
#[test]
fn drda_message_split_across_segments_is_detected() {
    let payload = [
        0x00, 0x10, 0xD0, 0x41, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let frames = client_session(50041, 50000, &[&payload[..8], &payload[8..]]);
    assert_eq!(detect(&frames), Some(rdpi::Protocol::Drda));
}
