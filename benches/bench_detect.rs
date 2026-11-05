//! rDpi 检测性能基准
//!
//! 运行: cargo bench

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rdpi::Detector;

// 辅助：构造 UDP 包
fn build_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 14 + 20 + 8 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16 - 14).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
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

fn build_dns_packet() -> Vec<u8> {
    let payload = vec![
        0xaa, 0xaa, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
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
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16 - 14).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    pkt.push(0x40);
    pkt.push(0x06);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&12345u16.to_be_bytes());
    pkt.extend_from_slice(&80u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.push(0x50);
    pkt.push(0x00);
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

// ============================================================================
// QUIC 基准（quic feature 下编译）
// ============================================================================

#[cfg(feature = "quic")]
mod quic_benches {
    use super::*;

    /// RFC 9001 §A.2 官方样本包（1200B 受保护 Initial，可成功解密）
    const A2_HEX: &str = concat!(
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8ba",
        "b936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a12",
        "82a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6",
        "005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
        "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde5",
        "35d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e",
        "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e3",
        "0c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
        "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63",
        "ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d874",
        "3eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf8",
        "2a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
        "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc29",
        "62e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f0",
        "5796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c",
        "1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
        "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a",
        "0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd",
        "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de3",
        "54270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
        "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a",
        "4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e5",
        "66d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef",
        "023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
        "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbb",
        "e2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd8",
        "04a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc852",
        "44259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
        "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5",
        "e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934",
    );

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// 头部判定 + 解密失败兜底路径（最小 v1 Initial，载荷非法）
    fn build_minimal_initial() -> Vec<u8> {
        let mut payload = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 4];
        payload.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        payload.push(0x00); // SCID len
        payload.push(0x00); // Token len
        payload.extend_from_slice(&[0x00, 0x01]);
        build_udp_packet(12345, 443, &payload)
    }

    /// Initial 全解密路径：AES-GCM 解密 + CRYPTO 帧 + ClientHello 解析 + JA4
    fn build_a2_initial() -> Vec<u8> {
        build_udp_packet(12345, 443, &hex_to_bytes(A2_HEX))
    }

    pub fn bench_quic_header_only(c: &mut Criterion) {
        let pkt = build_minimal_initial();
        c.bench_function("detect_quic_header_only", |b| {
            b.iter(|| {
                let mut detector = Detector::new();
                let _ = detector.detect(black_box(&pkt));
            });
        });
    }

    pub fn bench_quic_initial_decrypt(c: &mut Criterion) {
        let pkt = build_a2_initial();
        c.bench_function("detect_quic_initial_decrypt", |b| {
            b.iter(|| {
                let mut detector = Detector::new();
                let _ = detector.detect(black_box(&pkt));
            });
        });
    }
}

#[cfg(not(feature = "quic"))]
criterion_group!(
    benches,
    bench_dns_detection,
    bench_http_detection,
    bench_detector_create
);
#[cfg(feature = "quic")]
criterion_group!(
    benches,
    bench_dns_detection,
    bench_http_detection,
    bench_detector_create,
    quic_benches::bench_quic_header_only,
    quic_benches::bench_quic_initial_decrypt
);
criterion_main!(benches);
