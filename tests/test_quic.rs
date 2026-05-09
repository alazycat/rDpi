#![cfg(feature = "quic")]

use rdpi::core::types::{Metadata, Protocol};
use rdpi::protocols::quic::{
    is_quic_initial, parse_quic_initial, QuicDetector, QUIC_VERSION_1, QUIC_VERSION_DRAFT29,
};
use rdpi::protocols::ProtocolDetector;

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
    assert!(!detection.confidence.is_nan());
    assert!(detection.confidence > 0.0);

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

    // 默认行为：忽略上下文，返回 QUIC
    let ctx = DetectContext {
        src_port: 12345,
        dst_port: 443,
        is_http3_port: true,
    };

    let result = detector.detect_with_context(&data, &ctx);
    assert!(result.is_some());

    let detection = result.unwrap();
    // 当前默认实现应该返回 QUIC（尚未实现 HTTP/3 逻辑）
    assert_eq!(detection.protocol, Protocol::Quic);
}
