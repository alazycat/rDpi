//! rDpi 检测性能基准
//!
//! 运行: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rdpi::Detector;

// 辅助：构造 UDP 包
fn build_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 14 + 20 + 8 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45); pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16 - 14).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    pkt.push(0x40); pkt.push(0x11);
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

fn build_dns_packet() -> Vec<u8> {
    let payload = vec![
        0xaa, 0xaa, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a',
        b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    build_udp_packet(12345, 53, &payload)
}

fn build_http_packet() -> Vec<u8> {
    // TCP 包上 HTTP GET
    let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    let total_len = payload.len() + 20 + 20 + 14;
    pkt.push(0x45); pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16 - 14).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    pkt.push(0x40); pkt.push(0x06);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&12345u16.to_be_bytes());
    pkt.extend_from_slice(&80u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.push(0x50); pkt.push(0x00);
    pkt.extend_from_slice(&[0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

fn bench_dns_detection(c: &mut Criterion) {
    let pkt = build_dns_packet();
    c.bench_function("detect_dns", |b| {
        b.iter(|| {
            let mut detector = Detector::new();
            let _ = detector.detect(black_box(&pkt));
        });
    });
}

fn bench_http_detection(c: &mut Criterion) {
    let pkt = build_http_packet();
    c.bench_function("detect_http", |b| {
        b.iter(|| {
            let mut detector = Detector::new();
            let _ = detector.detect(black_box(&pkt));
        });
    });
}

fn bench_detector_create(c: &mut Criterion) {
    c.bench_function("detector_new", |b| {
        b.iter(|| {
            let _ = Detector::new();
        });
    });
}

criterion_group!(benches, bench_dns_detection, bench_http_detection, bench_detector_create);
criterion_main!(benches);
