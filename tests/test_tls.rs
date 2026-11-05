use rdpi::core::types::{Confidence, Metadata, Protocol};
use rdpi::protocols::ProtocolDetector;
use rdpi::protocols::tls::{
    TlsDetector, extract_sni, extract_tls_version, is_client_hello, is_tls_record,
    parse_client_hello, parse_server_hello,
};

// ============================================================================
// Basic TLS Record Detection Tests
// ============================================================================

#[test]
fn test_is_tls_record() {
    // Valid TLS handshake record (TLS 1.2)
    let data = [0x16, 0x03, 0x03, 0x00, 0x50, 0x01, 0x00, 0x00, 0x00];
    assert!(is_tls_record(&data));

    // Valid TLS handshake record (TLS 1.0)
    let data = [0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x00, 0x00, 0x00];
    assert!(is_tls_record(&data));

    // Invalid: wrong content type
    let data = [0x15, 0x03, 0x03, 0x00, 0x50];
    assert!(!is_tls_record(&data));

    // Invalid: wrong version
    let data = [0x16, 0x02, 0x03, 0x00, 0x50];
    assert!(!is_tls_record(&data));

    // Too short
    let data = [0x16, 0x03];
    assert!(!is_tls_record(&data));
}

#[test]
fn test_is_client_hello() {
    // Valid ClientHello
    let data = [0x16, 0x03, 0x03, 0x00, 0x50, 0x01, 0x00, 0x00, 0x00];
    assert!(is_client_hello(&data));

    // Not a ClientHello (Alert)
    let data = [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
    assert!(!is_client_hello(&data));

    // Handshake but not ClientHello (ServerHello = 0x02)
    let data = [0x16, 0x03, 0x03, 0x00, 0x50, 0x02, 0x00, 0x00, 0x00];
    assert!(!is_client_hello(&data));
}

#[test]
fn test_parse_non_tls() {
    // HTTP request should not be detected as TLS
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert!(!is_tls_record(data));
    assert!(parse_client_hello(data).is_none());

    // DNS query should not be detected as TLS
    let dns_query = [
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
    ];
    assert!(!is_tls_record(&dns_query));

    // Random binary data
    let random_data = [0x00, 0x01, 0x02, 0x03, 0x04];
    assert!(!is_tls_record(&random_data));
}

// ============================================================================
// ClientHello Parsing Tests
// ============================================================================

/// Helper to construct a minimal ClientHello for testing
fn make_minimal_client_hello() -> Vec<u8> {
    // TLS record header
    let mut data = vec![
        0x16, // ContentType: Handshake
        0x03, 0x03, // Version: TLS 1.2
        0x00, 0x00, // Length: placeholder
    ];

    // Handshake header
    data.push(0x01); // Handshake Type: ClientHello
    data.extend_from_slice(&[0x00, 0x00, 0x00]); // Length: placeholder

    // Client Version
    data.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

    // Random (32 bytes)
    data.extend_from_slice(&[0u8; 32]);

    // Session ID (empty)
    data.push(0x00);

    // Cipher Suites (2 bytes length + minimal)
    data.extend_from_slice(&[0x00, 0x02]); // Length: 2
    data.extend_from_slice(&[0x00, 0x00]); // Null cipher suite

    // Compression Methods (1 byte length + null)
    data.push(0x01); // Length: 1
    data.push(0x00); // Null compression

    // Extensions (empty)
    data.extend_from_slice(&[0x00, 0x00]);

    // Update lengths
    let handshake_len = data.len() - 9;
    let record_len = data.len() - 5;

    data[6] = ((handshake_len >> 16) & 0xFF) as u8;
    data[7] = ((handshake_len >> 8) & 0xFF) as u8;
    data[8] = (handshake_len & 0xFF) as u8;

    data[3] = ((record_len >> 8) & 0xFF) as u8;
    data[4] = (record_len & 0xFF) as u8;

    data
}

/// Helper to construct a ClientHello with SNI extension
fn make_client_hello_with_sni(hostname: &str) -> Vec<u8> {
    let hostname_bytes = hostname.as_bytes();

    // Build SNI extension
    let mut sni_ext = vec![
        0x00, 0x00, // Extension Type: SNI (0x0000)
        0x00, 0x00, // Extension Length: placeholder
        0x00, 0x00, // Server Name List Length: placeholder
        0x00, // Server Name Type: hostname (0x00)
    ];

    let name_len = hostname_bytes.len() as u16;
    sni_ext.push(((name_len >> 8) & 0xFF) as u8);
    sni_ext.push((name_len & 0xFF) as u8);
    sni_ext.extend_from_slice(hostname_bytes);

    // Server Name List Length = hostname + type (1 byte) + length (2 bytes) = hostname + 3
    let list_len = (hostname_bytes.len() + 3) as u16;
    sni_ext[4] = ((list_len >> 8) & 0xFF) as u8;
    sni_ext[5] = (list_len & 0xFF) as u8;
    // Extension Length = list_len + 2 bytes for list length field
    let ext_len = (hostname_bytes.len() + 5) as u16;
    sni_ext[2] = ((ext_len >> 8) & 0xFF) as u8;
    sni_ext[3] = (ext_len & 0xFF) as u8;

    // Build supported_versions extension for TLS 1.3
    let versions_ext = vec![
        0x00, 0x2b, // Extension Type: supported_versions (0x002b)
        0x00, 0x03, // Extension Length: 3
        0x02, // Supported Versions Length: 2
        0x03, 0x04, // TLS 1.3
    ];

    let extensions_len = (sni_ext.len() + versions_ext.len()) as u16;
    let mut extensions = vec![
        ((extensions_len >> 8) & 0xFF) as u8,
        (extensions_len & 0xFF) as u8,
    ];
    extensions.extend(sni_ext);
    extensions.extend(versions_ext);

    let mut data = vec![
        0x16, // ContentType: Handshake
        0x03, 0x01, // Version: TLS 1.0 (record layer)
        0x00, 0x00, // Length: placeholder
    ];

    data.push(0x01); // Handshake Type: ClientHello
    data.extend_from_slice(&[0x00, 0x00, 0x00]); // Length: placeholder
    data.extend_from_slice(&[0x03, 0x03]); // Client Version: TLS 1.2 (legacy)
    data.extend_from_slice(&[0u8; 32]); // Random
    data.push(0x00); // Session ID (empty)
    data.extend_from_slice(&[0x00, 0x02]); // Cipher Suites Length: 2
    data.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    data.push(0x01); // Compression Methods Length: 1
    data.push(0x00); // Null compression
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

/// Helper to construct a ClientHello with SNI and TLS 1.2 only (no supported_versions)
fn make_client_hello_tls12_only(hostname: &str) -> Vec<u8> {
    let hostname_bytes = hostname.as_bytes();

    // Build SNI extension
    let mut sni_ext = vec![
        0x00, 0x00, // Extension Type: SNI (0x0000)
        0x00, 0x00, // Extension Length: placeholder
        0x00, 0x00, // Server Name List Length: placeholder
        0x00, // Server Name Type: hostname (0x00)
    ];

    let name_len = hostname_bytes.len() as u16;
    sni_ext.push(((name_len >> 8) & 0xFF) as u8);
    sni_ext.push((name_len & 0xFF) as u8);
    sni_ext.extend_from_slice(hostname_bytes);

    // Server Name List Length = hostname + type (1 byte) + length (2 bytes) = hostname + 3
    let list_len = (hostname_bytes.len() + 3) as u16;
    sni_ext[4] = ((list_len >> 8) & 0xFF) as u8;
    sni_ext[5] = (list_len & 0xFF) as u8;
    // Extension Length = list_len + 2 bytes for list length field
    let ext_len = (hostname_bytes.len() + 5) as u16;
    sni_ext[2] = ((ext_len >> 8) & 0xFF) as u8;
    sni_ext[3] = (ext_len & 0xFF) as u8;

    let extensions_len = sni_ext.len() as u16;
    let mut extensions = vec![
        ((extensions_len >> 8) & 0xFF) as u8,
        (extensions_len & 0xFF) as u8,
    ];
    extensions.extend(sni_ext);

    let mut data = vec![
        0x16, // ContentType: Handshake
        0x03, 0x03, // Version: TLS 1.2 (record layer)
        0x00, 0x00, // Length: placeholder
    ];

    data.push(0x01); // Handshake Type: ClientHello
    data.extend_from_slice(&[0x00, 0x00, 0x00]); // Length: placeholder
    data.extend_from_slice(&[0x03, 0x03]); // Client Version: TLS 1.2
    data.extend_from_slice(&[0u8; 32]); // Random
    data.push(0x00); // Session ID (empty)
    data.extend_from_slice(&[0x00, 0x02]); // Cipher Suites Length: 2
    data.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
    data.push(0x01); // Compression Methods Length: 1
    data.push(0x00); // Null compression
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
fn test_parse_client_hello_with_sni() {
    let data = make_client_hello_with_sni("example.com");
    assert!(is_client_hello(&data));

    let result = parse_client_hello(&data);
    assert!(result.is_some());

    let info = result.unwrap();
    assert_eq!(info.sni, Some("example.com".to_string()));
    assert_eq!(info.version, Some("TLS 1.3".to_string()));
}

#[test]
fn test_parse_client_hello_version() {
    // TLS 1.3 via supported_versions extension
    let data = make_client_hello_with_sni("test.com");
    let version = extract_tls_version(&data);
    assert_eq!(version, Some("TLS 1.3".to_string()));

    // TLS 1.2 without supported_versions (uses record layer version)
    let data = make_client_hello_tls12_only("test.com");
    let version = extract_tls_version(&data);
    assert_eq!(version, Some("TLS 1.2".to_string()));
}

#[test]
fn test_extract_sni() {
    let test_cases = vec![
        "example.com",
        "api.example.com",
        "subdomain.api.example.com",
        "example.co.uk",
        "xn--nxasmq5b.com", // Punycode
    ];

    for hostname in test_cases {
        let data = make_client_hello_with_sni(hostname);
        let sni = extract_sni(&data);
        assert_eq!(
            sni,
            Some(hostname.to_string()),
            "Failed for hostname: {}",
            hostname
        );
    }
}

#[test]
fn test_parse_client_hello_no_sni() {
    let data = make_minimal_client_hello();
    let result = parse_client_hello(&data);
    assert!(result.is_some());

    let info = result.unwrap();
    assert!(info.sni.is_none());
    // Should still have version from record layer
    assert_eq!(info.version, Some("TLS 1.2".to_string()));
}

#[test]
fn test_parse_client_hello_with_port_in_hostname() {
    // SNI typically doesn't include port, but we handle it if present
    let data = make_client_hello_with_sni("example.com:443");
    let sni = extract_sni(&data);
    assert_eq!(sni, Some("example.com:443".to_string()));
}

#[test]
fn test_empty_payload() {
    let data: &[u8] = &[];
    assert!(!is_tls_record(data));
    assert!(!is_client_hello(data));
    assert!(parse_client_hello(data).is_none());
}

#[test]
fn test_truncated_payload() {
    // Valid start but too short
    let data = [0x16, 0x03, 0x03, 0x00, 0x50, 0x01];
    assert!(is_tls_record(&data));
    assert!(!is_client_hello(&data));
    assert!(parse_client_hello(&data).is_none());
}

// ============================================================================
// TLS Detector Tests
// ============================================================================

#[test]
fn test_tls_detector_with_sni() {
    let detector = TlsDetector::new();
    let data = make_client_hello_with_sni("example.com");

    let result = detector.detect(&data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Tls);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Tls(meta) = detection.metadata {
        assert_eq!(meta.sni, Some("example.com".to_string()));
        assert_eq!(meta.version, Some("TLS 1.3".to_string()));
    } else {
        panic!("Expected TLS metadata");
    }
}

#[test]
fn test_tls_detector_without_sni() {
    let detector = TlsDetector::new();
    let data = make_minimal_client_hello();

    let result = detector.detect(&data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Tls);

    if let Metadata::Tls(meta) = detection.metadata {
        assert!(meta.sni.is_none());
        assert_eq!(meta.version, Some("TLS 1.2".to_string()));
    } else {
        panic!("Expected TLS metadata");
    }
}

#[test]
fn test_tls_detector_non_tls() {
    let detector = TlsDetector::new();

    // HTTP request should not be detected as TLS
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = detector.detect(data);
    assert!(result.is_none());

    // Alert record (not ClientHello)
    let data = [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
    let result = detector.detect(&data);
    assert!(result.is_none());

    // Random data
    let data = [0x00, 0x01, 0x02, 0x03, 0x04];
    let result = detector.detect(&data);
    assert!(result.is_none());
}

#[test]
fn test_tls_detector_various_hostnames() {
    let detector = TlsDetector::new();

    let test_cases = vec![
        ("google.com", "TLS 1.3"),
        ("github.com", "TLS 1.3"),
        ("api.stripe.com", "TLS 1.3"),
        ("wildcard.example.org", "TLS 1.3"),
    ];

    for (hostname, expected_version) in test_cases {
        let data = make_client_hello_with_sni(hostname);
        let result = detector.detect(&data);
        assert!(result.is_some(), "Should detect TLS for {}", hostname);

        let detection = result.unwrap();
        if let Metadata::Tls(meta) = detection.metadata {
            assert_eq!(meta.sni, Some(hostname.to_string()));
            assert_eq!(meta.version, Some(expected_version.to_string()));
        } else {
            panic!("Expected TLS metadata for {}", hostname);
        }
    }
}

#[test]
fn test_tls_detector_empty_payload() {
    let detector = TlsDetector::new();
    let result = detector.detect(b"");
    assert!(result.is_none());
}

#[test]
fn test_tls_detector_name() {
    let detector = TlsDetector::new();
    assert_eq!(detector.name(), "tls");
}

// ============================================================================
// Application Identification Tests
// ============================================================================

#[test]
fn test_tls_youtube_application() {
    use rdpi::core::types::Application;
    use rdpi::protocols::ProtocolDetector;

    let detector = TlsDetector::new();

    // ClientHello with SNI: www.youtube.com
    let sni = "www.youtube.com";
    let packet = make_client_hello_with_sni(sni);

    let result = detector.detect(&packet);
    assert!(result.is_some());

    let detection = result.unwrap();
    if let rdpi::core::types::Metadata::Tls(meta) = detection.metadata {
        assert_eq!(meta.sni, Some(sni.to_string()));
        assert_eq!(meta.application, Some(Application::YouTube));
    } else {
        panic!("Expected TLS metadata");
    }
}

#[test]
fn test_tls_netflix_application() {
    use rdpi::core::types::Application;
    use rdpi::protocols::ProtocolDetector;

    let detector = TlsDetector::new();
    let sni = "www.nflxvideo.net";
    let packet = make_client_hello_with_sni(sni);

    let result = detector.detect(&packet);
    assert!(result.is_some());

    let detection = result.unwrap();
    if let rdpi::core::types::Metadata::Tls(meta) = detection.metadata {
        assert_eq!(meta.application, Some(Application::Netflix));
    } else {
        panic!("Expected TLS metadata");
    }
}

#[test]
fn test_tls_wechat_application() {
    use rdpi::core::types::Application;
    use rdpi::protocols::ProtocolDetector;

    let detector = TlsDetector::new();
    let sni = "weixin.qq.com";
    let packet = make_client_hello_with_sni(sni);

    let result = detector.detect(&packet);
    assert!(result.is_some());

    let detection = result.unwrap();
    if let rdpi::core::types::Metadata::Tls(meta) = detection.metadata {
        assert_eq!(meta.application, Some(Application::WeChat));
    } else {
        panic!("Expected TLS metadata");
    }
}

#[test]
fn test_tls_unknown_domain_no_application() {
    use rdpi::protocols::ProtocolDetector;

    let detector = TlsDetector::new();
    let sni = "www.unknown-site.example";
    let packet = make_client_hello_with_sni(sni);

    let result = detector.detect(&packet);
    assert!(result.is_some());

    let detection = result.unwrap();
    if let rdpi::core::types::Metadata::Tls(meta) = detection.metadata {
        assert!(meta.application.is_none());
    } else {
        panic!("Expected TLS metadata");
    }
}

// ============================================================================
// ServerHello / JA4S Tests
// ============================================================================

/// 构造 TLS 1.3 形态 ServerHello record（legacy 0x0303 + supported_versions
/// 0x0304 + cipher 0x1302 + ALPN "h2" + 扩展 [0x002b, 0x0010]）
fn make_server_hello_tls13() -> Vec<u8> {
    let mut sh = Vec::new();
    sh.push(0x02); // msg_type ServerHello
    sh.extend_from_slice(&[0x00, 0x00, 0x00]); // 握手长度占位，最后回填
    sh.extend_from_slice(&[0x03, 0x03]); // legacy_version
    sh.extend_from_slice(&[0x11u8; 32]); // random
    sh.push(32); // legacy_session_id_echo 长度
    sh.extend_from_slice(&[0x22u8; 32]);
    sh.extend_from_slice(&[0x13, 0x02]); // cipher_suite TLS_AES_256_GCM_SHA384
    sh.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods
    // 扩展区：总长(2B) + supported_versions(0x002b) + ALPN(0x0010)
    let sv_data: [u8; 2] = [0x03, 0x04]; // TLS 1.3
    let alpn_data: [u8; 5] = [0x00, 0x03, 0x02, 0x68, 0x32]; // "h2"
    let exts_len = (4 + sv_data.len() + 4 + alpn_data.len()) as u16;
    sh.extend_from_slice(&exts_len.to_be_bytes());
    sh.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02]);
    sh.extend_from_slice(&sv_data);
    sh.extend_from_slice(&[0x00, 0x10, 0x00, 0x05]);
    sh.extend_from_slice(&alpn_data);

    let hs_len = sh.len() - 4;
    sh[1..4].copy_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);
    let mut record = vec![0x16, 0x03, 0x03, (sh.len() >> 8) as u8, sh.len() as u8];
    record.extend_from_slice(&sh);
    record
}

#[test]
fn test_parse_server_hello_fields() {
    let record = make_server_hello_tls13();
    let sh = parse_server_hello(&record).expect("ServerHello 应可解析");
    assert_eq!(sh.legacy_version, 0x0303);
    assert_eq!(sh.supported_version, Some(0x0304));
    assert_eq!(sh.cipher_suite, 0x1302);
    assert_eq!(sh.alpn.as_deref(), Some("h2"));
    // 扩展按服务端发送顺序保留
    assert_eq!(sh.extensions, vec![0x002b, 0x0010]);
}

#[test]
fn test_parse_server_hello_rejects_non_server_hello() {
    // ClientHello（msg_type 0x01）拒绝
    let record = make_server_hello_tls13();
    let mut ch = record.clone();
    ch[5] = 0x01;
    assert!(parse_server_hello(&ch).is_none());

    // 非 TLS 记录拒绝
    assert!(parse_server_hello(b"GET / HTTP/1.1\r\n").is_none());

    // 截断载荷拒绝
    let truncated = &record[..40];
    assert!(parse_server_hello(truncated).is_none());
}

/// 纯 ServerHello 的服务端流可定型为 TLS 并携带 JA4S（TLS 1.3 明文只有 ServerHello）
#[test]
fn test_tls_detector_server_hello_yields_ja4s() {
    let detector = TlsDetector::new();
    let record = make_server_hello_tls13();

    let result = detector.detect(&record).expect("应识别为 TLS");
    assert_eq!(result.protocol, Protocol::Tls);
    if let Metadata::Tls(meta) = result.metadata {
        assert_eq!(meta.version, Some("TLS 1.3".to_string()));
        assert_eq!(meta.alpn.as_deref(), Some("h2"));
        // golden 向量：t + 13 + 02 扩展 + h2 | 1302 | sha256("0x002b,0x0010")[:12]
        assert_eq!(meta.ja4s.as_deref(), Some("t1302h2_1302_60694de2240d"));
        assert!(meta.sni.is_none(), "ServerHello 无 SNI");
        assert!(meta.ja4.is_none(), "服务端流无客户端 JA4");
    } else {
        panic!("Expected TLS metadata");
    }
}

/// 构造完整以太网+IPv4+TCP 包（手工字节数组，风格对齐 test_guess.rs）
fn build_tcp_packet(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 14 + 20 + 20 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);

    // IPv4 header (20 bytes)
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16 - 14).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(0x40);
    pkt.push(0x06); // protocol: TCP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);

    // TCP header (20 bytes, data offset=5)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
    pkt.push(0x50); // data offset=5
    pkt.push(0x18); // flags PSH|ACK
    pkt.extend_from_slice(&[0xff, 0xff]); // window
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer

    pkt.extend_from_slice(payload);
    pkt
}

/// Detector 全链路：客户端 CH 流与服务端 SH 流各自定型，回显包元数据不丢（F7）
#[test]
fn test_detector_tls_server_flow_ja4s_persists_across_echo() {
    let mut detector = rdpi::Detector::new();

    // 客户端→服务端：ClientHello 定型
    let client_packet = build_tcp_packet(
        [10, 0, 0, 1],
        54321,
        [10, 0, 0, 2],
        443,
        &make_client_hello_with_sni("example.com"),
    );
    let r1 = detector.detect(&client_packet).unwrap().unwrap();
    assert_eq!(r1.protocol, Protocol::Tls);
    if let Metadata::Tls(ref meta) = r1.metadata {
        assert_eq!(meta.sni.as_deref(), Some("example.com"));
        assert!(meta.ja4s.is_none(), "客户端流不应携带 JA4S");
    }

    // 服务端→客户端（反向流）：纯 ServerHello 定型（TLS 1.3 明文首包）
    let server_packet = build_tcp_packet(
        [10, 0, 0, 2],
        443,
        [10, 0, 0, 1],
        54321,
        &make_server_hello_tls13(),
    );
    let r2 = detector.detect(&server_packet).unwrap().unwrap();
    assert_eq!(r2.protocol, Protocol::Tls);
    if let Metadata::Tls(ref meta) = r2.metadata {
        assert_eq!(
            meta.ja4s.as_deref(),
            Some("t1302h2_1302_60694de2240d"),
            "服务端流首包即携带 JA4S"
        );
        assert_eq!(meta.version.as_deref(), Some("TLS 1.3"));
    } else {
        panic!("Expected TLS metadata");
    }

    // 服务端流回显包（AppData 空记录）：元数据（含 JA4S）不被抹掉（F7 语义）
    let echo_packet = build_tcp_packet(
        [10, 0, 0, 2],
        443,
        [10, 0, 0, 1],
        54321,
        &[0x17, 0x03, 0x03, 0x00, 0x00],
    );
    let r3 = detector.detect(&echo_packet).unwrap().unwrap();
    assert_eq!(r3.protocol, Protocol::Tls);
    if let Metadata::Tls(ref meta) = r3.metadata {
        assert_eq!(
            meta.ja4s.as_deref(),
            Some("t1302h2_1302_60694de2240d"),
            "回显包应携带已保存的 JA4S"
        );
    }
}

/// 一次性富化语义（ADR-0004）：定型 TLS 流后续包收到 ServerHello 时补算 JA4S，
/// 且已有元数据（SNI）保持不覆盖
#[test]
fn test_detector_tls_ja4s_enrich_once() {
    let mut detector = rdpi::Detector::new();

    // 先用 ClientHello 定型 TLS 流（此时无 JA4S）
    let ch_packet = build_tcp_packet(
        [10, 0, 0, 1],
        54321,
        [10, 0, 0, 2],
        443,
        &make_client_hello_with_sni("example.com"),
    );
    let r1 = detector.detect(&ch_packet).unwrap().unwrap();
    if let Metadata::Tls(ref meta) = r1.metadata {
        assert!(meta.ja4s.is_none());
    }

    // 同一流后续包携带 ServerHello → 富化补算 JA4S
    let sh_packet = build_tcp_packet(
        [10, 0, 0, 1],
        54321,
        [10, 0, 0, 2],
        443,
        &make_server_hello_tls13(),
    );
    let r2 = detector.detect(&sh_packet).unwrap().unwrap();
    if let Metadata::Tls(ref meta) = r2.metadata {
        assert_eq!(
            meta.ja4s.as_deref(),
            Some("t1302h2_1302_60694de2240d"),
            "富化路径应补算 JA4S"
        );
        // SNI 保持富化前的值（元数据合并非覆盖）
        assert_eq!(meta.sni.as_deref(), Some("example.com"));
    }

    // 再来一个不含 ServerHello 的包：JA4S 保持
    let app_packet = build_tcp_packet(
        [10, 0, 0, 1],
        54321,
        [10, 0, 0, 2],
        443,
        &[0x17, 0x03, 0x03, 0x00, 0x00],
    );
    let r3 = detector.detect(&app_packet).unwrap().unwrap();
    if let Metadata::Tls(ref meta) = r3.metadata {
        assert_eq!(meta.ja4s.as_deref(), Some("t1302h2_1302_60694de2240d"));
    }
}

// ============================================================================
// JA4X 证书指纹测试（F32）
// ============================================================================

/// 追加单 CN 属性的 Name（SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String } } }）
fn append_dn_cn(data: &mut Vec<u8>, cn: &str) {
    let mut attr = Vec::new();
    attr.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]); // OID commonName
    attr.push(0x0C); // UTF8String
    attr.push(cn.len() as u8);
    attr.extend_from_slice(cn.as_bytes());

    let mut seq = vec![0x30, attr.len() as u8];
    seq.extend_from_slice(&attr);
    let mut set = vec![0x31, seq.len() as u8];
    set.extend_from_slice(&seq);
    let mut dn = vec![0x30, set.len() as u8];
    dn.extend_from_slice(&set);
    data.extend_from_slice(&dn);
}

/// 构造 TLS Certificate 记录（简化 v3 证书：issuer/subject 均为单 CN 属性、无扩展）
fn make_certificate_record() -> Vec<u8> {
    let mut tbs_inner = Vec::new();
    tbs_inner.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]); // version [0] v3
    tbs_inner.extend_from_slice(&[0x02, 0x01, 0x01]); // serialNumber INTEGER 1
    // signature SEQUENCE { OID 1.2.840.113549.1.1.11 }
    tbs_inner.extend_from_slice(&[
        0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00,
    ]);
    append_dn_cn(&mut tbs_inner, "CA Inc"); // issuer
    // validity SEQUENCE { UTCTime, UTCTime }
    tbs_inner.extend_from_slice(&[
        0x30, 0x1E, 0x17, 0x0D, b'2', b'4', b'0', b'3', b'0', b'9', b'1', b'2', b'0', b'0', b'0',
        b'0', b'Z', 0x17, 0x0D, b'2', b'5', b'0', b'3', b'0', b'9', b'1', b'2', b'0', b'0', b'0',
        b'0', b'Z',
    ]);
    append_dn_cn(&mut tbs_inner, "example.com"); // subject

    let mut tbs = vec![0x30, 0x00];
    tbs.extend_from_slice(&tbs_inner);
    tbs[1] = (tbs.len() - 2) as u8;

    let mut cert = vec![0x30, 0x00];
    cert.extend_from_slice(&tbs);
    cert[1] = (cert.len() - 2) as u8;

    // TLS 记录封装：Handshake Certificate(0x0B) + 证书列表
    let mut handshake = Vec::new();
    handshake.push(0x0B); // Certificate
    handshake.extend_from_slice(&[0x00, 0x00, (cert.len() + 6) as u8]); // handshake length
    handshake.extend_from_slice(&[0x00, 0x00, cert.len() as u8]); // list length
    handshake.extend_from_slice(&[0x00, 0x00, cert.len() as u8]); // cert entry length
    handshake.extend_from_slice(&cert);

    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.push(0x03);
    record.push(0x03);
    record.extend_from_slice(&((handshake.len()) as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// 纯 Certificate 记录的服务端流：定型 TLS + 证书字段含 JA4X
/// golden 向量：sha256("550403")[:12] 两段 + 空扩展全零段（PowerShell .NET SHA256 交叉验证）
#[test]
fn test_tls_detector_certificate_yields_ja4x() {
    let detector = TlsDetector::new();
    let record = make_certificate_record();

    let result = detector.detect(&record).expect("应识别为 TLS");
    assert_eq!(result.protocol, Protocol::Tls);
    if let Metadata::Tls(meta) = result.metadata {
        assert_eq!(meta.cert_subject.as_deref(), Some("example.com"));
        assert_eq!(meta.cert_issuer.as_deref(), Some("CA Inc"));
        assert_eq!(
            meta.cert_ja4x.as_deref(),
            Some("7022c563de38_7022c563de38_000000000000")
        );
        assert!(meta.ja4.is_none());
        assert!(meta.ja4s.is_none(), "证书记录不含 ServerHello");
    } else {
        panic!("Expected TLS metadata");
    }
}

/// 一次性富化语义（ADR-0004）：定型 TLS 流的后续包携带 Certificate 时补算 JA4X，
/// 已有元数据（SNI）保持不覆盖；后续包 JA4X 持久
#[test]
fn test_detector_tls_ja4x_enrich_once() {
    let mut detector = rdpi::Detector::new();

    // 先用 ClientHello 定型 TLS 流（此时无证书字段）
    let ch_packet = build_tcp_packet(
        [10, 0, 0, 1],
        54321,
        [10, 0, 0, 2],
        443,
        &make_client_hello_with_sni("example.com"),
    );
    let r1 = detector.detect(&ch_packet).unwrap().unwrap();
    if let Metadata::Tls(ref meta) = r1.metadata {
        assert!(meta.cert_ja4x.is_none());
    }

    // 同一流后续包携带 Certificate → 富化补算 JA4X
    let cert_packet = build_tcp_packet(
        [10, 0, 0, 1],
        54321,
        [10, 0, 0, 2],
        443,
        &make_certificate_record(),
    );
    let r2 = detector.detect(&cert_packet).unwrap().unwrap();
    if let Metadata::Tls(ref meta) = r2.metadata {
        assert_eq!(
            meta.cert_ja4x.as_deref(),
            Some("7022c563de38_7022c563de38_000000000000"),
            "富化路径应补算 JA4X"
        );
        assert_eq!(meta.sni.as_deref(), Some("example.com"), "SNI 保持");
    }

    // 再来一个应用数据包：JA4X 保持
    let app_packet = build_tcp_packet(
        [10, 0, 0, 1],
        54321,
        [10, 0, 0, 2],
        443,
        &[0x17, 0x03, 0x03, 0x00, 0x00],
    );
    let r3 = detector.detect(&app_packet).unwrap().unwrap();
    if let Metadata::Tls(ref meta) = r3.metadata {
        assert_eq!(
            meta.cert_ja4x.as_deref(),
            Some("7022c563de38_7022c563de38_000000000000"),
            "回显包应携带已保存的 JA4X"
        );
    }
}
