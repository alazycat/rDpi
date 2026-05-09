use rdpi::protocols::tls::{
    is_tls_record, is_client_hello, parse_client_hello, extract_sni, extract_tls_version,
    TlsDetector,
};
use rdpi::protocols::ProtocolDetector;
use rdpi::core::types::{Protocol, Metadata};

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
        0x16,       // ContentType: Handshake
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
        0x16,       // ContentType: Handshake
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
        0x16,       // ContentType: Handshake
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
        assert_eq!(sni, Some(hostname.to_string()), "Failed for hostname: {}", hostname);
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
    assert_eq!(detection.confidence, 1.0);

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
