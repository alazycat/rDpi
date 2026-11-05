#![cfg(feature = "proto3")]

use rdpi::core::types::{Metadata, Protocol};
use rdpi::protocols::ProtocolDetector;
use rdpi::protocols::http2::{Http2Detector, extract_request_headers, is_http2_preface};

// ============================================================================
// Helper Functions
// ============================================================================

/// RFC 7541 C.4.1 头块：GET / :authority=www.example.com（索引 + Huffman）
const C41_BLOCK: &[u8] = &[
    0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
    0xff,
];

/// 构造帧：9 字节帧头 + 帧体
fn h2_frame(ftype: u8, flags: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(9 + body.len());
    let len = body.len() as u32;
    v.extend_from_slice(&len.to_be_bytes()[1..4]);
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&[0, 0, 0, 1]); // stream id = 1
    v.extend_from_slice(body);
    v
}

/// 客户端 SETTINGS 空帧
fn settings_frame() -> Vec<u8> {
    h2_frame(0x04, 0x00, &[])
}

/// 构造以太网 + IPv4 + TCP 帧封装载荷（Detector::detect 需要完整帧）
fn build_tcp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 14 + 20 + 20 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

    // IPv4 header (20 bytes)
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16 - 14).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(0x40);
    pkt.push(0x06); // TCP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);

    // TCP header (20 bytes，无选项)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0, 0, 0, 1]); // seq
    pkt.extend_from_slice(&[0, 0, 0, 1]); // ack
    pkt.push(0x50); // 数据偏移 5（无选项）
    pkt.push(0x18); // PSH|ACK
    pkt.extend_from_slice(&[0xff, 0xff]); // window
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);

    pkt.extend_from_slice(payload);
    pkt
}

// ============================================================================
// is_http2_preface Tests
// ============================================================================

#[test]
fn test_is_http2_preface_valid() {
    assert!(is_http2_preface(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
}

#[test]
fn test_is_http2_preface_rejects_http11() {
    assert!(!is_http2_preface(b"GET / HTTP/1.1\r\n"));
}

// ============================================================================
// extract_request_headers Tests
// ============================================================================

#[test]
fn test_extract_same_packet_preface_settings_headers() {
    let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    payload.extend_from_slice(&settings_frame());
    payload.extend_from_slice(&h2_frame(0x01, 0x04, C41_BLOCK));
    let md = extract_request_headers(&payload).unwrap();
    assert_eq!(md.method.as_deref(), Some("GET"));
    assert_eq!(md.path.as_deref(), Some("/"));
    assert_eq!(md.authority.as_deref(), Some("www.example.com"));
}

#[test]
fn test_extract_truncated_headers_frame() {
    // 帧体跨包截断 → None（R14 边界：不做重组）
    let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    let mut f = h2_frame(0x01, 0x04, C41_BLOCK);
    f.truncate(f.len() - 1);
    payload.extend_from_slice(&f);
    assert!(extract_request_headers(&payload).is_none());
}

// ============================================================================
// Http2Detector Tests
// ============================================================================

#[test]
fn test_http2_detector_identifies_preface() {
    let detector = Http2Detector::new();
    let result = detector
        .detect(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .unwrap();
    assert_eq!(result.protocol, Protocol::Http2);
    match result.metadata {
        Metadata::Http2(md) => {
            // preface 单独到达时尚无请求头 → 全空（后续包富化补齐）
            assert!(md.authority.is_none() && md.method.is_none() && md.path.is_none());
        }
        other => panic!("期望 Metadata::Http2，实际 {:?}", other),
    }
}

#[test]
fn test_http2_detector_same_packet_metadata() {
    let detector = Http2Detector::new();
    let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    payload.extend_from_slice(&h2_frame(0x01, 0x04, C41_BLOCK));
    let result = detector.detect(&payload).unwrap();
    match result.metadata {
        Metadata::Http2(md) => {
            assert_eq!(md.authority.as_deref(), Some("www.example.com"));
            assert_eq!(md.method.as_deref(), Some("GET"));
        }
        other => panic!("期望 Metadata::Http2，实际 {:?}", other),
    }
}

#[test]
fn test_http2_detector_rejects_http11() {
    let detector = Http2Detector::new();
    assert!(
        detector
            .detect(b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n")
            .is_none()
    );
}

// ============================================================================
// Detector 端到端：定型流富化路径（preface 与 HEADERS 分包到达）
// ============================================================================

#[test]
fn test_detector_flow_enrichment_second_packet() {
    let mut detector = rdpi::Detector::new();

    // 包 1：connection preface → 识别 Http2，元数据为空
    let frame1 = build_tcp_frame(51000, 443, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let r1 = detector.detect(&frame1).unwrap().unwrap();
    assert_eq!(r1.protocol, Protocol::Http2);
    match &r1.metadata {
        Metadata::Http2(md) => assert!(md.authority.is_none()),
        other => panic!("期望 Metadata::Http2，实际 {:?}", other),
    }

    // 包 2（同向同流）：SETTINGS + 首个请求 HEADERS → 富化路径补齐元数据
    let mut payload2 = settings_frame();
    payload2.extend_from_slice(&h2_frame(0x01, 0x04, C41_BLOCK));
    let frame2 = build_tcp_frame(51000, 443, &payload2);
    let r2 = detector.detect(&frame2).unwrap().unwrap();
    assert_eq!(r2.protocol, Protocol::Http2);
    match &r2.metadata {
        Metadata::Http2(md) => {
            assert_eq!(md.authority.as_deref(), Some("www.example.com"));
            assert_eq!(md.method.as_deref(), Some("GET"));
            assert_eq!(md.path.as_deref(), Some("/"));
        }
        other => panic!("期望 Metadata::Http2，实际 {:?}", other),
    }

    // 包 3（回显路径）：元数据已在流上定型，不再重复提取
    let frame3 = build_tcp_frame(51000, 443, &h2_frame(0x06, 0x01, &[])); // PING ACK
    let r3 = detector.detect(&frame3).unwrap().unwrap();
    match &r3.metadata {
        Metadata::Http2(md) => {
            assert_eq!(md.authority.as_deref(), Some("www.example.com"));
        }
        other => panic!("期望 Metadata::Http2，实际 {:?}", other),
    }

    // 流统计确认是同一条流
    assert_eq!(detector.flow_count(), 1);
}

#[test]
fn test_detector_flow_no_enrich_from_response_frames() {
    // 服务端响应帧（:status）不应触发请求头提取失败后的误写
    let mut detector = rdpi::Detector::new();
    let frame1 = build_tcp_frame(51000, 443, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    assert_eq!(
        detector.detect(&frame1).unwrap().unwrap().protocol,
        Protocol::Http2
    );

    // 服务端 HEADERS（:status 200 = 静态索引 8 → 0x88）：无请求伪头部，元数据保持为空
    let frame2 = build_tcp_frame(51000, 443, &h2_frame(0x01, 0x04, &[0x88]));
    let r2 = detector.detect(&frame2).unwrap().unwrap();
    match &r2.metadata {
        Metadata::Http2(md) => {
            assert!(md.authority.is_none() && md.method.is_none() && md.path.is_none());
        }
        other => panic!("期望 Metadata::Http2，实际 {:?}", other),
    }
}
