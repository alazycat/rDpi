//! JA4 客户端 TLS 指纹测试（F39：官方 ja4.py to_ja4 格式）
//!
//! 黄金向量与语义细节的完整覆盖在 src/application/ja4.rs 单元测试内；
//! 本文件为公开 API 层的格式钉住。

use rdpi::application::{Ja4Transport, compute_ja4};

#[test]
fn test_ja4_official_golden_vector() {
    // 官方 JA4.md 黄金向量（TLS 1.3、有 SNI、15 密码、16 扩展、ALPN h2）
    let ciphers: [u16; 15] = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ];
    let extensions: [u16; 16] = [
        0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
        0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
    ];
    let sig_algs: [u16; 8] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let ja4 = compute_ja4(
        Ja4Transport::Tcp,
        0x0304,
        &ciphers,
        &extensions,
        &sig_algs,
        Some("h2"),
        true,
    );
    assert_eq!(ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
}

#[test]
fn test_ja4_format() {
    // 格式：{proto1}{ver2}{sni1}{ccnt2}{ecnt2}{alpn2}_{hash12}_{hash12} = 36 字符
    let ja4 = compute_ja4(
        Ja4Transport::Tcp,
        0x0303,
        &[0x1301],
        &[0x001b],
        &[],
        None,
        false,
    );
    assert!(ja4.starts_with("t12i010100_"), "{}", ja4);
    assert_eq!(ja4.len(), 36);
}

#[test]
fn test_ja4_empty_lists() {
    // 空输入：计数 "00"、哈希段固定 12 个 0
    let ja4 = compute_ja4(Ja4Transport::Quic, 0x0303, &[], &[], &[], None, false);
    assert_eq!(ja4, "q12i000000_000000000000_000000000000");
}

#[test]
fn test_ja4_version_codes() {
    let ja4 = |v| compute_ja4(Ja4Transport::Tcp, v, &[0x1301], &[0x001b], &[], None, false);
    assert!(ja4(0x0304).starts_with("t13i"));
    assert!(ja4(0x0303).starts_with("t12i"));
    assert!(ja4(0x0302).starts_with("t11i"));
    assert!(ja4(0x0301).starts_with("t10i"));
    // 未知版本记 "00"——JA4 恒可计算
    assert!(ja4(0x0999).starts_with("t00i"));
}

#[test]
fn test_ja4_dtls_transport_prefix() {
    let ja4 = compute_ja4(
        Ja4Transport::Dtls,
        0xfefc,
        &[0x1301],
        &[0x001b],
        &[],
        None,
        false,
    );
    assert!(ja4.starts_with("dd3i"), "{}", ja4);
}
