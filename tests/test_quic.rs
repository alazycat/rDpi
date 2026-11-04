#![cfg(feature = "quic")]

use rdpi::core::types::{Confidence, Metadata, Protocol};
use rdpi::protocols::ProtocolDetector;
use rdpi::protocols::quic::{
    QUIC_VERSION_1, QUIC_VERSION_DRAFT29, QuicDetector, is_quic_initial, parse_quic_initial,
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper to construct a minimal QUIC v1 Initial packet for testing
fn make_quic_v1_initial(dcid: &[u8]) -> Vec<u8> {
    let mut data = vec![
        0xC0, // Long Header + Initial (bits 7-6 = 11, bits 5-4 = 00)
        0x00, 0x00, 0x00, 0x01, // Version: QUIC v1 (0x00000001)
    ];
    // DCID Length + DCID
    data.push(dcid.len() as u8);
    data.extend_from_slice(dcid);
    // SCID Length: 0
    data.push(0x00);
    // Token Length: 0 (1-byte varint)
    data.push(0x00);
    // Minimal payload placeholder
    data.extend_from_slice(&[0x00, 0x01]);

    data
}

// ============================================================================
// is_quic_initial Tests
// ============================================================================

#[test]
fn test_is_quic_initial_valid() {
    // Initial packet: Long Header (bit 7=1) + Fixed Bit (bit 6=1) + Initial type (bits 5-4=00)
    // First byte: 0xC0 = 0b11000000
    let data = [0xC0, 0x00, 0x00, 0x00, 0x01];
    assert!(is_quic_initial(&data));
}

#[test]
fn test_is_quic_initial_with_dcid() {
    // QUIC v1 Initial with DCID
    let data = make_quic_v1_initial(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert!(is_quic_initial(&data));
}

#[test]
fn test_is_quic_initial_invalid_short() {
    // Too short packet - empty
    let data: [u8; 0] = [];
    assert!(!is_quic_initial(&data));
}

#[test]
fn test_is_quic_initial_invalid_wrong_type() {
    // Short header packet (bit 7 = 0)
    let data = [0x40, 0x00, 0x00, 0x00, 0x01];
    assert!(!is_quic_initial(&data));

    // Long Header but not Initial - Handshake (0xD0 = 0b11010000)
    let data = [0xD0, 0x00, 0x00, 0x00, 0x01];
    assert!(!is_quic_initial(&data));

    // Long Header but not Initial - 0-RTT (0xD0 = 0b11010000 with different bits)
    let data = [0xC0 | 0x10, 0x00, 0x00, 0x00, 0x01]; // 0xD0
    assert!(!is_quic_initial(&data));
}

// ============================================================================
// parse_quic_initial Tests
// ============================================================================

#[test]
fn test_parse_quic_initial_version() {
    let data = make_quic_v1_initial(&[0x01, 0x02, 0x03, 0x04]);
    let result = parse_quic_initial(&data);
    assert!(result.is_some());

    let info = result.unwrap();
    assert_eq!(info.version, QUIC_VERSION_1);
}

#[test]
fn test_parse_quic_initial_dcid() {
    let dcid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
    let data = make_quic_v1_initial(&dcid);
    let result = parse_quic_initial(&data);
    assert!(result.is_some());

    let info = result.unwrap();
    assert_eq!(info.dcid_len, 8);
    assert_eq!(info.dcid, dcid.to_vec());
}

#[test]
fn test_parse_quic_draft29() {
    // QUIC Draft-29 version: 0xff00001d
    let mut data = vec![
        0xC0, // Long Header + Initial
        0xff, 0x00, 0x00, 0x1d, // Version: Draft-29
        0x08, // DCID Length: 8
    ];
    data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    data.push(0x00); // SCID Length: 0
    data.push(0x00); // Token Length: 0
    data.extend_from_slice(&[0x00, 0x01]); // Minimal payload

    let result = parse_quic_initial(&data);
    assert!(result.is_some());

    let info = result.unwrap();
    assert_eq!(info.version, QUIC_VERSION_DRAFT29);
}

// ============================================================================
// QuicDetector Tests
// ============================================================================

#[test]
fn test_quic_detector_v1() {
    let detector = QuicDetector::new();
    let data = make_quic_v1_initial(&[0x01, 0x02, 0x03, 0x04]);

    let result = detector.detect(&data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Quic);
}

#[test]
fn test_quic_detector_metadata() {
    let detector = QuicDetector::new();
    let dcid = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let data = make_quic_v1_initial(&dcid);

    let result = detector.detect(&data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Quic);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Quic(meta) = detection.metadata {
        assert_eq!(meta.version, Some("00000001".to_string())); // QUIC v1 in hex
        assert_eq!(meta.destination_connection_id, Some(dcid));
        assert!(meta.sni.is_none()); // SNI requires decryption
    } else {
        panic!("Expected Quic metadata");
    }
}

#[test]
fn test_quic_detector_non_quic() {
    let detector = QuicDetector::new();

    // HTTP request - should not be detected as QUIC
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = detector.detect(data);
    assert!(result.is_none());

    // TLS ClientHello - should not be detected as QUIC
    let data = [0x16, 0x03, 0x03, 0x00, 0x50, 0x01, 0x00, 0x00, 0x00];
    let result = detector.detect(&data);
    assert!(result.is_none());

    // DNS query - should not be detected as QUIC
    let data = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00];
    let result = detector.detect(&data);
    assert!(result.is_none());

    // Short header QUIC (not Initial) - should not be detected
    let data = [0x40, 0x00, 0x00, 0x00, 0x01];
    let result = detector.detect(&data);
    assert!(result.is_none());
}

#[test]
fn test_quic_detector_empty() {
    let detector = QuicDetector::new();

    // Empty input
    let result = detector.detect(&[]);
    assert!(result.is_none());

    // Single byte
    let result = detector.detect(&[0xC0]);
    assert!(result.is_none());
}

#[test]
fn test_quic_detector_name() {
    let detector = QuicDetector::new();
    assert_eq!(detector.name(), "quic");
}

// ============================================================================
// detect_with_context Tests
// ============================================================================

#[test]
fn test_quic_detector_detect_with_context_default() {
    use rdpi::core::types::DetectContext;

    let detector = QuicDetector::new();
    let data = make_quic_v1_initial(&[0x01, 0x02, 0x03, 0x04]);

    // HTTP/3 识别：QUIC v1 + is_http3_port=true
    let ctx = DetectContext {
        src_port: 12345,
        dst_port: 443,
        is_http3_port: true,
    };

    let result = detector.detect_with_context(&data, &ctx);
    assert!(result.is_some());

    let detection = result.unwrap();
    // QUIC v1 + 端口 443 应该识别为 HTTP/3
    assert_eq!(detection.protocol, Protocol::Http3);
}

#[test]
fn test_registry_detect_with_ports() {
    use rdpi::protocols::Registry;

    let mut registry = Registry::new();
    registry.register(Box::new(QuicDetector::new()));

    let data = make_quic_v1_initial(&[0x01, 0x02, 0x03, 0x04]);

    // 测试 detect_with_ports - QUIC v1 + 端口 443 应识别为 HTTP/3
    let result = registry.detect_with_ports(&data, 12345, 443);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Http3);
}

// ============================================================================
// HTTP/3 Detection Tests
// ============================================================================

/// Helper to construct a minimal QUIC v2 Initial packet for testing
fn make_quic_v2_initial(dcid: &[u8]) -> Vec<u8> {
    let mut data = vec![
        0xC0, // Long Header + Initial
        0x6b, 0x33, 0x43, 0xcf, // Version: QUIC v2 (0x6b3343cf)
    ];
    data.push(dcid.len() as u8);
    data.extend_from_slice(dcid);
    data.push(0x00); // SCID Length: 0
    data.push(0x00); // Token Length: 0
    data.extend_from_slice(&[0x00, 0x01]);
    data
}

/// Helper for Draft-29 packet
fn make_quic_draft29(dcid: &[u8]) -> Vec<u8> {
    let mut data = vec![0xC0, 0xff, 0x00, 0x00, 0x1d];
    data.push(dcid.len() as u8);
    data.extend_from_slice(dcid);
    data.push(0x00);
    data.push(0x00);
    data.extend_from_slice(&[0x00, 0x01]);
    data
}

#[test]
fn test_http3_detection_quic_v1_port_443() {
    use rdpi::core::types::DetectContext;

    let detector = QuicDetector::new();
    let data = make_quic_v1_initial(&[0x01, 0x02, 0x03, 0x04]);

    let ctx = DetectContext {
        src_port: 12345,
        dst_port: 443,
        is_http3_port: true,
    };

    let result = detector.detect_with_context(&data, &ctx);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Http3);
    assert_eq!(detection.confidence, Confidence::DpiPartial);
}

#[test]
fn test_http3_detection_quic_v2_port_443() {
    use rdpi::core::types::DetectContext;

    let detector = QuicDetector::new();
    let data = make_quic_v2_initial(&[0x01, 0x02, 0x03, 0x04]);

    let ctx = DetectContext {
        src_port: 443,
        dst_port: 8443,
        is_http3_port: true,
    };

    let result = detector.detect_with_context(&data, &ctx);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Http3);
    assert_eq!(detection.confidence, Confidence::DpiPartial);
}

#[test]
fn test_http3_detection_quic_v1_non_443_port() {
    use rdpi::core::types::DetectContext;

    let detector = QuicDetector::new();
    let data = make_quic_v1_initial(&[0x01, 0x02, 0x03, 0x04]);

    let ctx = DetectContext {
        src_port: 12345,
        dst_port: 8443,
        is_http3_port: false,
    };

    let result = detector.detect_with_context(&data, &ctx);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Quic);
    assert_eq!(detection.confidence, Confidence::Dpi);
}

#[test]
fn test_http3_detection_draft29_port_443() {
    use rdpi::core::types::DetectContext;

    let detector = QuicDetector::new();
    let data = make_quic_draft29(&[0x01, 0x02, 0x03, 0x04]);

    let ctx = DetectContext {
        src_port: 12345,
        dst_port: 443,
        is_http3_port: true,
    };

    let result = detector.detect_with_context(&data, &ctx);
    assert!(result.is_some());

    let detection = result.unwrap();
    // Draft 版本不识别为 HTTP/3
    assert_eq!(detection.protocol, Protocol::Quic);
}

// ============================================================================
// Initial 解密 + SNI/ALPN 提取（RFC 9001 附录 A.2 官方样例钉住）
// ============================================================================

/// RFC 9001 附录 A.2 样例：客户端受保护 Initial 包（DCID=8394c8f03e515708，pn=2）
///
/// 载荷为官方 CRYPTO 帧（完整 ClientHello，SNI="example.com"、ALPN="alpn"）+ 零填充。
/// 夹具由 src/protocols/quic/parser.rs 的 test_print_a2_fixture 生成（构造链
/// 经 RFC 8439/FIPS-197/RFC 4231/RFC 5869/RFC 9001 A.1 向量逐层验证）。
const A2_PROTECTED_PACKET_HEX: &str = concat!(
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

// tls feature 关闭时解密仍可用，但 Metadata 无 SNI 提取路径，正向断言仅在 tls 下成立
#[test]
#[cfg(feature = "tls")]
fn test_decrypt_initial_sni_alpn_via_detector() {
    let detector = QuicDetector::new();
    let data = hex_to_bytes(A2_PROTECTED_PACKET_HEX);

    let result = detector.detect(&data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Quic);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Quic(meta) = detection.metadata {
        assert_eq!(meta.sni.as_deref(), Some("example.com"));
        assert_eq!(meta.alpn.as_deref(), Some("alpn"));
        assert_eq!(meta.version.as_deref(), Some("00000001"));
        assert_eq!(
            meta.destination_connection_id,
            Some(vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08])
        );
    } else {
        panic!("expected Quic metadata");
    }
}

#[test]
#[cfg(feature = "tls")]
fn test_decrypt_initial_sni_via_detector_with_context_http3() {
    use rdpi::core::types::DetectContext;

    let detector = QuicDetector::new();
    let data = hex_to_bytes(A2_PROTECTED_PACKET_HEX);

    let ctx = DetectContext {
        src_port: 12345,
        dst_port: 443,
        is_http3_port: true,
    };

    let result = detector.detect_with_context(&data, &ctx);
    assert!(result.is_some());

    let detection = result.unwrap();
    // UDP 443 + 标准版本 → HTTP/3，且解密出 SNI
    assert_eq!(detection.protocol, Protocol::Http3);
    if let Metadata::Quic(meta) = detection.metadata {
        assert_eq!(meta.sni.as_deref(), Some("example.com"));
        assert_eq!(meta.alpn.as_deref(), Some("alpn"));
    } else {
        panic!("expected Quic metadata");
    }
}

#[test]
fn test_decrypt_initial_tampered_payload_degrades_to_header_only() {
    let detector = QuicDetector::new();
    let mut data = hex_to_bytes(A2_PROTECTED_PACKET_HEX);
    // 篡改密文中间 1 字节 → GCM tag 校验失败 → 降级为仅头部信息（sni=None）
    data[600] ^= 0x01;

    let result = detector.detect(&data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Quic);
    if let Metadata::Quic(meta) = detection.metadata {
        assert!(meta.sni.is_none());
        assert!(meta.alpn.is_none());
        // 头部信息不受影响
        assert_eq!(meta.version.as_deref(), Some("00000001"));
    } else {
        panic!("expected Quic metadata");
    }
}
