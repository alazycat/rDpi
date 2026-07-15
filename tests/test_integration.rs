//! Integration tests for Phase 2 HTTP + TLS detection
//!
//! Tests the complete detection pipeline including:
//! - Protocol registry and detector ordering
//! - End-to-end detection through Registry
//! - Metadata extraction through full pipeline
//! - Edge cases and priority handling

use rdpi::core::types::{Confidence, Metadata, Protocol};
use rdpi::protocols::dns::DnsDetector;
use rdpi::protocols::http::HttpDetector;
use rdpi::protocols::tls::TlsDetector;
use rdpi::protocols::{ProtocolDetector, Registry};

// ============================================================================
// Helper Functions for TLS Test Data
// ============================================================================

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

    let list_len = (hostname_bytes.len() + 3) as u16;
    sni_ext[4] = ((list_len >> 8) & 0xFF) as u8;
    sni_ext[5] = (list_len & 0xFF) as u8;
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

/// Helper to construct a minimal ClientHello without SNI
fn make_minimal_client_hello() -> Vec<u8> {
    let mut data = vec![
        0x16, // ContentType: Handshake
        0x03, 0x03, // Version: TLS 1.2
        0x00, 0x00, // Length: placeholder
    ];

    data.push(0x01); // Handshake Type: ClientHello
    data.extend_from_slice(&[0x00, 0x00, 0x00]); // Length: placeholder
    data.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    data.extend_from_slice(&[0u8; 32]); // Random
    data.push(0x00); // Session ID (empty)
    data.extend_from_slice(&[0x00, 0x02]); // Cipher Suites Length: 2
    data.extend_from_slice(&[0x00, 0x00]); // Null cipher suite
    data.push(0x01); // Compression Methods Length: 1
    data.push(0x00); // Null compression
    data.extend_from_slice(&[0x00, 0x00]); // Extensions (empty)

    let handshake_len = data.len() - 9;
    let record_len = data.len() - 5;

    data[6] = ((handshake_len >> 16) & 0xFF) as u8;
    data[7] = ((handshake_len >> 8) & 0xFF) as u8;
    data[8] = (handshake_len & 0xFF) as u8;

    data[3] = ((record_len >> 8) & 0xFF) as u8;
    data[4] = (record_len & 0xFF) as u8;

    data
}

/// Helper to construct a DNS query packet
fn make_dns_query(domain: &str) -> Vec<u8> {
    let mut data = vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
    ];

    // Encode domain name (example.com -> 7example3com0)
    for label in domain.split('.') {
        data.push(label.len() as u8);
        data.extend_from_slice(label.as_bytes());
    }
    data.push(0x00); // End of domain name

    // Query type and class
    data.extend_from_slice(&[0x00, 0x01]); // Type: A
    data.extend_from_slice(&[0x00, 0x01]); // Class: IN

    data
}

// ============================================================================
// Protocol Registry Tests
// ============================================================================

#[test]
fn test_registry_default_detector_count() {
    let registry = Registry::default();
    // All detectors should be registered by default
    // (assuming all features are enabled)
    let expected_count = {
        let mut count = 0;
        #[cfg(feature = "tls")]
        {
            count += 1;
        }
        #[cfg(feature = "http")]
        {
            count += 1;
        }
        #[cfg(feature = "dns")]
        {
            count += 1;
        }
        #[cfg(feature = "ssh")]
        {
            count += 1;
        }
        #[cfg(feature = "smtp")]
        {
            count += 1;
        }
        #[cfg(feature = "quic")]
        {
            count += 1;
        }
        #[cfg(feature = "mail")]
        {
            count += 2; // POP3 + IMAP
        }
        #[cfg(feature = "infra")]
        {
            count += 2; // NTP + DHCP
        }
        #[cfg(feature = "snmp")]
        {
            count += 1; // SNMP
        }
        #[cfg(feature = "modbus")]
        {
            count += 1; // Modbus
        }
        #[cfg(feature = "database")]
        {
            count += 3; // MySQL + PostgreSQL + Redis
        }
        #[cfg(feature = "proto3")]
        {
            count += 5; // FTP + SIP + RTP + HTTP2 + WebSocket
        }
        #[cfg(feature = "iot")]
        {
            count += 1; // MQTT
        }
        #[cfg(feature = "vpn")]
        {
            count += 1; // WireGuard
        }
        count
    };
    assert_eq!(registry.detector_count(), expected_count);
}

#[test]
fn test_registry_manual_registration() {
    let mut registry = Registry::new();
    assert_eq!(registry.detector_count(), 0);

    // Register detectors manually
    registry.register(Box::new(TlsDetector::new()));
    assert_eq!(registry.detector_count(), 1);

    registry.register(Box::new(HttpDetector::new()));
    assert_eq!(registry.detector_count(), 2);

    registry.register(Box::new(DnsDetector::new()));
    assert_eq!(registry.detector_count(), 3);
}

#[test]
fn test_registry_detector_order() {
    // Test that detectors are registered in correct order: TLS -> HTTP -> DNS
    // This is important because TLS magic bytes are more distinctive than HTTP text
    let mut registry = Registry::new();

    // Register in expected order
    registry.register(Box::new(TlsDetector::new()));
    registry.register(Box::new(HttpDetector::new()));
    registry.register(Box::new(DnsDetector::new()));

    // The registry should detect TLS first when payload is TLS
    let tls_payload = make_client_hello_with_sni("example.com");
    let result = registry.detect(&tls_payload);
    assert!(result.is_some());
    assert_eq!(result.unwrap().protocol, Protocol::Tls);
}

// ============================================================================
// End-to-End Detection Tests
// ============================================================================

#[test]
fn test_registry_detects_http_request() {
    let registry = Registry::default();
    let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Http);
    assert_eq!(detection.confidence, Confidence::Dpi);
}

#[test]
fn test_registry_detects_http_response() {
    let registry = Registry::default();
    let payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Http);
}

#[test]
fn test_registry_detects_tls_with_sni() {
    let registry = Registry::default();
    let payload = make_client_hello_with_sni("example.com");

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Tls);
    assert_eq!(detection.confidence, Confidence::Dpi);
}

#[test]
fn test_registry_detects_tls_without_sni() {
    let registry = Registry::default();
    let payload = make_minimal_client_hello();

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Tls);
}

#[test]
fn test_registry_detects_dns() {
    let registry = Registry::default();
    let payload = make_dns_query("example.com");

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Dns);
}

#[test]
fn test_registry_no_match() {
    let registry = Registry::default();

    // Random binary data that is too short for any protocol (less than 5 bytes)
    let payload = [0x00, 0x01, 0x02, 0x03];
    let result = registry.detect(&payload);
    assert!(result.is_none());

    // Random binary data - need to avoid accidental DNS pattern match
    // DNS requires 12 bytes minimum, so shorter payloads won't match
    let payload = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let result = registry.detect(&payload);
    assert!(result.is_none());
}

// ============================================================================
// Detection Priority Tests
// ============================================================================

#[test]
fn test_detection_priority_tls_over_http() {
    // TLS magic bytes 0x16 0x03 are most distinctive
    // HTTP text patterns are less distinctive
    // Verify TLS is detected first when payload is TLS
    let registry = Registry::default();

    let tls_payload = make_client_hello_with_sni("example.com");
    let result = registry.detect(&tls_payload);

    assert!(result.is_some());
    // Must be TLS, not HTTP (even though detector order could matter)
    assert_eq!(result.unwrap().protocol, Protocol::Tls);
}

#[test]
fn test_detection_priority_http_over_dns() {
    // HTTP detection should happen before DNS for HTTP traffic
    let registry = Registry::default();

    // HTTP request
    let http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = registry.detect(http_payload);

    assert!(result.is_some());
    assert_eq!(result.unwrap().protocol, Protocol::Http);
}

#[test]
fn test_each_detector_is_specific() {
    // Verify that each detector matches its own protocol
    let tls_detector = TlsDetector::new();
    let http_detector = HttpDetector::new();
    let dns_detector = DnsDetector::new();

    let tls_payload = make_client_hello_with_sni("example.com");
    let http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let dns_payload = make_dns_query("example.com");

    // TLS detector should only match TLS
    assert!(tls_detector.detect(&tls_payload).is_some());
    assert!(tls_detector.detect(http_payload).is_none());
    assert!(tls_detector.detect(&dns_payload).is_none());

    // HTTP detector should only match HTTP
    assert!(http_detector.detect(&tls_payload).is_none());
    assert!(http_detector.detect(http_payload).is_some());
    // Note: DNS payload starts with 0x12 0x34, which won't match HTTP prefixes
    assert!(http_detector.detect(&dns_payload).is_none());

    // DNS detector should match DNS
    assert!(dns_detector.detect(&dns_payload).is_some());
    // Note: DNS detector may match other payloads if they look like valid DNS
    // (this is a known limitation of heuristic-based detection)
}

// ============================================================================
// Metadata Extraction Tests
// ============================================================================

#[test]
fn test_http_metadata_extraction_through_pipeline() {
    let registry = Registry::default();
    let payload =
        b"POST /api/users HTTP/1.1\r\nHost: api.example.com:8080\r\nContent-Length: 42\r\n\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Http);

    if let Metadata::Http(meta) = detection.metadata {
        assert_eq!(meta.method, Some("POST".to_string()));
        assert_eq!(meta.path, Some("/api/users".to_string()));
        assert_eq!(meta.host, Some("api.example.com:8080".to_string()));
    } else {
        panic!("Expected HTTP metadata");
    }
}

#[test]
fn test_http_response_metadata() {
    let registry = Registry::default();
    let payload = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Http);

    if let Metadata::Http(meta) = detection.metadata {
        // Responses don't have method/path/host
        assert!(meta.method.is_none());
        assert!(meta.path.is_none());
        assert!(meta.host.is_none());
    } else {
        panic!("Expected HTTP metadata");
    }
}

#[test]
fn test_tls_metadata_extraction_with_sni() {
    let registry = Registry::default();
    let payload = make_client_hello_with_sni("api.example.com");

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Tls);

    if let Metadata::Tls(meta) = detection.metadata {
        assert_eq!(meta.sni, Some("api.example.com".to_string()));
        assert_eq!(meta.version, Some("TLS 1.3".to_string()));
    } else {
        panic!("Expected TLS metadata");
    }
}

#[test]
fn test_tls_metadata_extraction_without_sni() {
    let registry = Registry::default();
    let payload = make_minimal_client_hello();

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Tls);

    if let Metadata::Tls(meta) = detection.metadata {
        // No SNI but version should still be extracted
        assert!(meta.sni.is_none());
        assert_eq!(meta.version, Some("TLS 1.2".to_string()));
    } else {
        panic!("Expected TLS metadata");
    }
}

#[test]
fn test_tls_various_hostnames() {
    let registry = Registry::default();

    let test_cases = vec![
        "google.com",
        "api.stripe.com",
        "subdomain.example.org",
        "xn--nxasmq5b.com", // Punycode
        "example.co.uk",
    ];

    for hostname in test_cases {
        let payload = make_client_hello_with_sni(hostname);
        let result = registry.detect(&payload);

        assert!(result.is_some(), "Should detect TLS for {}", hostname);
        let detection = result.unwrap();

        if let Metadata::Tls(meta) = detection.metadata {
            assert_eq!(meta.sni, Some(hostname.to_string()));
        } else {
            panic!("Expected TLS metadata for {}", hostname);
        }
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_payload() {
    let registry = Registry::default();
    let payload: &[u8] = &[];

    let result = registry.detect(payload);
    assert!(result.is_none());
}

#[test]
fn test_invalid_payload() {
    let registry = Registry::default();

    // Random binary data (too short for DNS detection which requires 12 bytes)
    let payload = [0x00, 0x01, 0x02, 0x03, 0x04];
    assert!(registry.detect(&payload).is_none());

    // Partial TLS (too short)
    let payload = [0x16, 0x03, 0x03];
    assert!(registry.detect(&payload).is_none());
}

#[test]
fn test_truncated_http() {
    let registry = Registry::default();

    // Start of HTTP but truncated
    let payload = b"GET / HTTP/1.1\r\n";
    // Should still detect HTTP because request line is valid
    // (depends on implementation - may or may not require headers)
    // If it requires a complete request, this should return None
    // For now, we just verify no panic
    let _ = registry.detect(payload);
}

#[test]
fn test_truncated_tls() {
    let registry = Registry::default();

    // Valid TLS record header but truncated body
    let payload = [0x16, 0x03, 0x03, 0x00, 0x50, 0x01];
    let result = registry.detect(&payload);
    // Should not detect TLS because ClientHello is incomplete
    assert!(result.is_none());
}

#[test]
fn test_multiple_protocol_markers_confusion() {
    // Test payloads that might confuse detectors
    let registry = Registry::default();

    // HTTP request with TLS-looking bytes in body
    // (should still be detected as HTTP)
    let http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n\x16\x03\x03";
    let result = registry.detect(http_payload);
    // HTTP should match first
    assert!(result.is_some());
    assert_eq!(result.unwrap().protocol, Protocol::Http);

    // TLS ClientHello (should be detected as TLS, not confused with anything)
    let tls_payload = make_client_hello_with_sni("example.com");
    let result = registry.detect(&tls_payload);
    assert!(result.is_some());
    assert_eq!(result.unwrap().protocol, Protocol::Tls);
}

#[test]
fn test_various_http_methods() {
    let registry = Registry::default();

    let methods = [
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
    ];

    for method in methods {
        let payload = format!("{} / HTTP/1.1\r\nHost: test.com\r\n\r\n", method);
        let result = registry.detect(payload.as_bytes());

        assert!(result.is_some(), "Should detect HTTP for {}", method);
        let detection = result.unwrap();
        assert_eq!(detection.protocol, Protocol::Http);

        if let Metadata::Http(meta) = detection.metadata {
            assert_eq!(meta.method, Some(method.to_string()));
        } else {
            panic!("Expected HTTP metadata for {}", method);
        }
    }
}

#[test]
fn test_various_http_status_codes() {
    let registry = Registry::default();

    let status_codes = [
        (200, "OK"),
        (201, "Created"),
        (301, "Moved Permanently"),
        (400, "Bad Request"),
        (404, "Not Found"),
        (500, "Internal Server Error"),
        (503, "Service Unavailable"),
    ];

    for (code, reason) in status_codes {
        let payload = format!("HTTP/1.1 {} {}\r\n\r\n", code, reason);
        let result = registry.detect(payload.as_bytes());

        assert!(result.is_some(), "Should detect HTTP for {}", code);
        let detection = result.unwrap();
        assert_eq!(detection.protocol, Protocol::Http);
    }
}

// ============================================================================
// Confidence Score Tests
// ============================================================================

#[test]
fn test_confidence_scores() {
    let registry = Registry::default();

    // All detectors should return confidence of 1.0 for valid matches
    let http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = registry.detect(http_payload).unwrap();
    assert_eq!(result.confidence, Confidence::Dpi);

    let tls_payload = make_client_hello_with_sni("example.com");
    let result = registry.detect(&tls_payload).unwrap();
    assert_eq!(result.confidence, Confidence::Dpi);

    let dns_payload = make_dns_query("example.com");
    let result = registry.detect(&dns_payload).unwrap();
    assert_eq!(result.confidence, Confidence::Dpi);
}

// ============================================================================
// Detector Name Tests
// ============================================================================

#[test]
fn test_detector_names() {
    let tls_detector = TlsDetector::new();
    let http_detector = HttpDetector::new();
    let dns_detector = DnsDetector::new();

    assert_eq!(tls_detector.name(), "tls");
    assert_eq!(http_detector.name(), "http");
    assert_eq!(dns_detector.name(), "dns");
}

// ============================================================================
// SSH Tests
// ============================================================================

#[test]
#[cfg(feature = "ssh")]
fn test_registry_detects_ssh() {
    let registry = Registry::default();
    let payload = b"SSH-2.0-OpenSSH_8.9p1\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Ssh);
    assert_eq!(detection.confidence, Confidence::Dpi);
}

#[test]
#[cfg(feature = "ssh")]
fn test_ssh_metadata_through_pipeline() {
    let registry = Registry::default();
    let payload = b"SSH-2.0-dropbear_2022.83\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    if let Metadata::Ssh(meta) = result.unwrap().metadata {
        assert_eq!(meta.version, Some("2.0".to_string()));
        assert_eq!(meta.software, Some("dropbear_2022.83".to_string()));
    } else {
        panic!("Expected Ssh metadata");
    }
}

// ============================================================================
// SMTP Tests
// ============================================================================

#[test]
#[cfg(feature = "smtp")]
fn test_registry_detects_smtp_banner() {
    let registry = Registry::default();
    let payload = b"220 mail.example.com ESMTP Postfix\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Smtp);
}

#[test]
#[cfg(feature = "smtp")]
fn test_registry_detects_smtp_command() {
    let registry = Registry::default();
    let payload = b"EHLO client.example.com\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Smtp);

    if let Metadata::Smtp(meta) = detection.metadata {
        assert!(meta.is_client);
        assert_eq!(meta.hostname, Some("client.example.com".to_string()));
    } else {
        panic!("Expected Smtp metadata");
    }
}

#[test]
#[cfg(feature = "smtp")]
fn test_smtp_metadata_through_pipeline() {
    let registry = Registry::default();
    let payload = b"220 smtp.gmail.com ESMTP\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    if let Metadata::Smtp(meta) = result.unwrap().metadata {
        assert_eq!(meta.hostname, Some("smtp.gmail.com".to_string()));
        assert!(!meta.is_client);
    } else {
        panic!("Expected Smtp metadata");
    }
}

// ============================================================================
// Detection Priority Tests
// ============================================================================

#[test]
#[cfg(feature = "ssh")]
fn test_detection_priority_ssh_over_http() {
    // SSH starts with 'S', HTTP doesn't start with 'S'
    // Verify SSH is detected correctly
    let registry = Registry::default();

    let ssh_payload = b"SSH-2.0-OpenSSH_8.9\r\n";
    let result = registry.detect(ssh_payload);
    assert!(result.is_some());
    assert_eq!(result.unwrap().protocol, Protocol::Ssh);
}

#[test]
#[cfg(feature = "smtp")]
fn test_detection_priority_smtp_vs_http() {
    // SMTP responses start with 2-5, HTTP doesn't
    // SMTP EHLO starts with E, HTTP doesn't
    let registry = Registry::default();

    let smtp_banner = b"220 mail.example.com ESMTP\r\n";
    let result = registry.detect(smtp_banner);
    assert!(result.is_some());
    assert_eq!(result.unwrap().protocol, Protocol::Smtp);
}

#[test]
#[cfg(all(
    feature = "tls",
    feature = "ssh",
    feature = "smtp",
    feature = "http",
    feature = "dns"
))]
fn test_all_protocols_detected() {
    let registry = Registry::default();

    // TLS
    let tls = make_client_hello_with_sni("example.com");
    assert_eq!(registry.detect(&tls).unwrap().protocol, Protocol::Tls);

    // SSH
    let ssh = b"SSH-2.0-OpenSSH_8.9\r\n";
    assert_eq!(registry.detect(ssh).unwrap().protocol, Protocol::Ssh);

    // SMTP
    let smtp = b"220 mail.example.com ESMTP\r\n";
    assert_eq!(registry.detect(smtp).unwrap().protocol, Protocol::Smtp);

    // HTTP
    let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert_eq!(registry.detect(http).unwrap().protocol, Protocol::Http);

    // DNS
    let dns = make_dns_query("example.com");
    assert_eq!(registry.detect(&dns).unwrap().protocol, Protocol::Dns);
}

#[test]
#[cfg(feature = "ssh")]
fn test_detector_names_ssh() {
    let ssh_detector = rdpi::protocols::ssh::SshDetector::new();
    assert_eq!(ssh_detector.name(), "ssh");
}

#[test]
#[cfg(feature = "smtp")]
fn test_detector_names_smtp() {
    let smtp_detector = rdpi::protocols::smtp::SmtpDetector::new();
    assert_eq!(smtp_detector.name(), "smtp");
}

// ============================================================================
// Phase 5.1: POP3 Tests
// ============================================================================

#[test]
#[cfg(feature = "mail")]
fn test_registry_detects_pop3_response() {
    let registry = Registry::default();
    let payload = b"+OK POP3 server ready\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Pop3);
    assert_eq!(detection.confidence, Confidence::Dpi);
}

#[test]
#[cfg(feature = "mail")]
fn test_registry_detects_pop3_err_response() {
    let registry = Registry::default();
    let payload = b"-ERR Authentication failed\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Pop3);
}

#[test]
#[cfg(feature = "mail")]
fn test_registry_detects_pop3_user_command() {
    let registry = Registry::default();
    let payload = b"USER test@example.com\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Pop3);
}

#[test]
#[cfg(feature = "mail")]
fn test_pop3_detector_name() {
    let pop3_detector = rdpi::protocols::pop3::Pop3Detector::new();
    assert_eq!(pop3_detector.name(), "pop3");
}

// ============================================================================
// Phase 5.1: IMAP Tests
// ============================================================================

#[test]
#[cfg(feature = "mail")]
fn test_registry_detects_imap_untagged_response() {
    let registry = Registry::default();
    let payload = b"* OK IMAP4rev1 Service Ready\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Imap);
    assert_eq!(detection.confidence, Confidence::Dpi);
}

#[test]
#[cfg(feature = "mail")]
fn test_registry_detects_imap_tagged_response() {
    let registry = Registry::default();
    let payload = b"A001 OK LOGIN completed\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Imap);
}

#[test]
#[cfg(feature = "mail")]
fn test_registry_detects_imap_login_command() {
    let registry = Registry::default();
    let payload = b"A001 LOGIN user password\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Imap);
}

#[test]
#[cfg(feature = "mail")]
fn test_registry_detects_imap_select_command() {
    let registry = Registry::default();
    let payload = b"A002 SELECT INBOX\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Imap);
}

#[test]
#[cfg(feature = "mail")]
fn test_imap_detector_name() {
    let imap_detector = rdpi::protocols::imap::ImapDetector::new();
    assert_eq!(imap_detector.name(), "imap");
}

// ============================================================================
// Phase 5.1: NTP Tests
// ============================================================================

/// Helper to construct an NTP packet
#[cfg(feature = "infra")]
fn make_ntp_packet(version: u8, mode: u8, stratum: u8) -> Vec<u8> {
    let first_byte = (version << 3) | (mode & 0x07);
    let mut packet = vec![0u8; 48];
    packet[0] = first_byte;
    packet[1] = stratum;
    packet
}

#[test]
#[cfg(feature = "infra")]
fn test_registry_detects_ntp_v4_client() {
    let registry = Registry::default();
    let payload = make_ntp_packet(4, 3, 2); // v4, mode 3 (client), stratum 2

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Ntp);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Ntp(meta) = detection.metadata {
        assert_eq!(meta.version, 4);
        assert_eq!(meta.mode, 3);
        assert_eq!(meta.stratum, 2);
    } else {
        panic!("Expected Ntp metadata");
    }
}

#[test]
#[cfg(feature = "infra")]
fn test_registry_detects_ntp_v4_server() {
    let registry = Registry::default();
    let payload = make_ntp_packet(4, 4, 1); // v4, mode 4 (server), stratum 1

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Ntp);

    if let Metadata::Ntp(meta) = detection.metadata {
        assert_eq!(meta.version, 4);
        assert_eq!(meta.mode, 4);
        assert_eq!(meta.stratum, 1);
    } else {
        panic!("Expected Ntp metadata");
    }
}

#[test]
#[cfg(feature = "infra")]
fn test_registry_detects_ntp_v3() {
    let registry = Registry::default();
    let payload = make_ntp_packet(3, 3, 1);

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Ntp);

    if let Metadata::Ntp(meta) = detection.metadata {
        assert_eq!(meta.version, 3);
    } else {
        panic!("Expected Ntp metadata");
    }
}

// Note: These tests verify the detector's strictness, not Registry behavior.
// Registry may match invalid data with other detectors (e.g., DNS may match short binary data).
#[test]
#[cfg(feature = "infra")]
fn test_ntp_detector_invalid_too_short() {
    let ntp_detector = rdpi::protocols::ntp::NtpDetector::new();
    let payload = vec![0u8; 47];
    assert!(ntp_detector.detect(&payload).is_none());
}

#[test]
#[cfg(feature = "infra")]
fn test_ntp_detector_invalid_version() {
    let ntp_detector = rdpi::protocols::ntp::NtpDetector::new();
    let payload = make_ntp_packet(5, 3, 1); // v5 (invalid)
    assert!(ntp_detector.detect(&payload).is_none());
}

#[test]
#[cfg(feature = "infra")]
fn test_ntp_detector_invalid_mode() {
    let ntp_detector = rdpi::protocols::ntp::NtpDetector::new();
    let payload = make_ntp_packet(4, 0, 1); // mode 0 (reserved)
    assert!(ntp_detector.detect(&payload).is_none());
}

// ============================================================================
// Phase 5.1: DHCP Tests
// ============================================================================

/// DHCP Magic Cookie (RFC 1497)
#[cfg(feature = "infra")]
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Helper to construct a DHCP packet
#[cfg(feature = "infra")]
fn make_dhcp_packet(opcode: u8, mac: [u8; 6]) -> Vec<u8> {
    let mut packet = vec![0u8; 244];
    packet[0] = opcode; // opcode: 1=request, 2=reply
    packet[1] = 1; // htype: Ethernet
    packet[2] = 6; // hlen: MAC address length
    packet[28..34].copy_from_slice(&mac); // chaddr: client MAC
    packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    packet
}

#[test]
#[cfg(feature = "infra")]
fn test_registry_detects_dhcp_request() {
    let registry = Registry::default();
    let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let payload = make_dhcp_packet(1, mac);

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Dhcp);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Dhcp(meta) = detection.metadata {
        assert_eq!(meta.opcode, 1);
        assert_eq!(meta.client_mac, mac);
    } else {
        panic!("Expected Dhcp metadata");
    }
}

#[test]
#[cfg(feature = "infra")]
fn test_registry_detects_dhcp_reply() {
    let registry = Registry::default();
    let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let payload = make_dhcp_packet(2, mac);

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Dhcp);

    if let Metadata::Dhcp(meta) = detection.metadata {
        assert_eq!(meta.opcode, 2);
        assert_eq!(meta.client_mac, mac);
    } else {
        panic!("Expected Dhcp metadata");
    }
}

// Note: These tests verify the detector's strictness, not Registry behavior.
#[test]
#[cfg(feature = "infra")]
fn test_dhcp_detector_invalid_too_short() {
    let dhcp_detector = rdpi::protocols::dhcp::DhcpDetector::new();
    let payload = vec![0u8; 243];
    assert!(dhcp_detector.detect(&payload).is_none());
}

#[test]
#[cfg(feature = "infra")]
fn test_dhcp_detector_invalid_opcode() {
    let dhcp_detector = rdpi::protocols::dhcp::DhcpDetector::new();
    let payload = make_dhcp_packet(3, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert!(dhcp_detector.detect(&payload).is_none());
}

#[test]
#[cfg(feature = "infra")]
fn test_dhcp_detector_invalid_magic_cookie() {
    let dhcp_detector = rdpi::protocols::dhcp::DhcpDetector::new();
    let mut payload = make_dhcp_packet(1, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    payload[236] = 0x00; // Corrupt magic cookie
    assert!(dhcp_detector.detect(&payload).is_none());
}

// ============================================================================
// Phase 5.1: SNMP Tests
// ============================================================================

/// Helper to construct SNMP v1 GetRequest
#[cfg(feature = "snmp")]
fn make_snmp_v1_get_request() -> Vec<u8> {
    vec![
        0x30, 0x26, // SEQUENCE, length 38
        0x02, 0x01, 0x00, // INTEGER: version 0 (v1)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // OCTET STRING: "public"
        0xA0, 0x19, // GetRequest (context-specific 0, constructed)
        0x02, 0x01, 0x01, // request-id: 1
        0x02, 0x01, 0x00, // error-status: 0
        0x02, 0x01, 0x00, // error-index: 0
        0x30, 0x0E, // varbind-list SEQUENCE
        0x30, 0x0C, // varbind SEQUENCE
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: 1.3.6.1.2.1.1.1.0
        0x05, 0x00, // NULL
    ]
}

#[test]
#[cfg(feature = "snmp")]
fn test_registry_detects_snmp_v1() {
    let registry = Registry::default();
    let payload = make_snmp_v1_get_request();

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Snmp);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Snmp(meta) = detection.metadata {
        assert_eq!(meta.version, rdpi::core::types::SnmpVersion::V1);
        assert_eq!(meta.community, "public");
        assert_eq!(meta.pdu_type, rdpi::core::types::SnmpPduType::GetRequest);
        assert_eq!(meta.request_id, 1);
    } else {
        panic!("Expected Snmp metadata");
    }
}

#[test]
#[cfg(feature = "snmp")]
fn test_registry_detects_snmp_v2c() {
    let registry = Registry::default();
    let mut payload = make_snmp_v1_get_request();
    payload[4] = 0x01; // version 1 = v2c

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Snmp);

    if let Metadata::Snmp(meta) = detection.metadata {
        assert_eq!(meta.version, rdpi::core::types::SnmpVersion::V2c);
    } else {
        panic!("Expected Snmp metadata");
    }
}

#[test]
#[cfg(feature = "snmp")]
fn test_snmp_too_short() {
    let registry = Registry::default();
    let payload = [0x30, 0x02, 0x02, 0x01];
    assert!(registry.detect(&payload).is_none());
}

// ============================================================================
// Phase 5.1: Modbus Tests
// ============================================================================

/// Helper to construct a Modbus TCP Read Coils request
#[cfg(feature = "modbus")]
fn make_modbus_read_coils_request() -> Vec<u8> {
    vec![
        0x00, 0x01, // Transaction ID: 1
        0x00, 0x00, // Protocol ID: 0
        0x00, 0x06, // Length: 6 bytes following
        0x01, // Unit ID: 1
        0x01, // Function Code: Read Coils
        0x00, 0x01, // Address: 1
        0x00, 0x08, // Quantity: 8 coils
    ]
}

#[test]
#[cfg(feature = "modbus")]
fn test_registry_detects_modbus_request() {
    let registry = Registry::default();
    let payload = make_modbus_read_coils_request();

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Modbus);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Modbus(meta) = detection.metadata {
        assert_eq!(meta.transaction_id, 1);
        assert_eq!(meta.unit_id, 1);
        assert_eq!(meta.function_code, 1);
        assert!(!meta.is_response);
    } else {
        panic!("Expected Modbus metadata");
    }
}

/// Helper to construct a Modbus TCP Read Coils response
#[cfg(feature = "modbus")]
fn make_modbus_read_coils_response() -> Vec<u8> {
    vec![
        0x00, 0x01, // Transaction ID: 1
        0x00, 0x00, // Protocol ID: 0
        0x00, 0x04, // Length: 4 bytes
        0x01, // Unit ID: 1
        0x01, // Function Code: Read Coils
        0x01, // Byte Count: 1
        0x55, // Data: 0x55 (bits: 01010101)
    ]
}

#[test]
#[cfg(feature = "modbus")]
fn test_registry_detects_modbus_response() {
    let registry = Registry::default();
    let payload = make_modbus_read_coils_response();

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Modbus);

    if let Metadata::Modbus(meta) = detection.metadata {
        assert!(meta.is_response);
    } else {
        panic!("Expected Modbus metadata");
    }
}

// Note: This test verifies the detector's strictness, not Registry behavior.
#[test]
#[cfg(feature = "modbus")]
fn test_modbus_detector_invalid_protocol_id() {
    let modbus_detector = rdpi::protocols::modbus::ModbusDetector::new();
    let mut payload = make_modbus_read_coils_request();
    payload[3] = 0x01; // Protocol ID: 1 (invalid)
    assert!(modbus_detector.detect(&payload).is_none());
}

#[test]
#[cfg(feature = "modbus")]
fn test_modbus_too_short() {
    let registry = Registry::default();
    let payload = [0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
    assert!(registry.detect(&payload).is_none());
}

// ============================================================================
// Phase 5.1: All Protocols Integration Test
// ============================================================================

#[test]
#[cfg(all(feature = "mail", feature = "infra", feature = "snmp", feature = "modbus"))]
fn test_phase51_all_protocols_detected() {
    let registry = Registry::default();

    // POP3
    let pop3 = b"+OK POP3 ready\r\n";
    assert_eq!(registry.detect(pop3).unwrap().protocol, Protocol::Pop3);

    // IMAP
    let imap = b"* OK IMAP4rev1 ready\r\n";
    assert_eq!(registry.detect(imap).unwrap().protocol, Protocol::Imap);

    // NTP
    let ntp = make_ntp_packet(4, 3, 2);
    assert_eq!(registry.detect(&ntp).unwrap().protocol, Protocol::Ntp);

    // DHCP
    let dhcp = make_dhcp_packet(1, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(registry.detect(&dhcp).unwrap().protocol, Protocol::Dhcp);

    // SNMP
    let snmp = make_snmp_v1_get_request();
    assert_eq!(registry.detect(&snmp).unwrap().protocol, Protocol::Snmp);

    // Modbus
    let modbus = make_modbus_read_coils_request();
    assert_eq!(registry.detect(&modbus).unwrap().protocol, Protocol::Modbus);
}

// ============================================================================
// Phase 5.2: Database Protocol Tests
// ============================================================================

/// Helper to construct a MySQL handshake packet (payload only, without MySQL packet header)
#[cfg(feature = "database")]
fn make_mysql_handshake_packet(version: &str) -> Vec<u8> {
    let mut packet = vec![
        // Protocol version (must be 0x0a)
        0x0a,
    ];
    // Server version (null-terminated)
    packet.extend_from_slice(version.as_bytes());
    packet.push(0x00);
    // Connection ID (4 bytes)
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    // Auth plugin data part 1 (8 bytes)
    packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    // Filler
    packet.push(0x00);
    // Capability flags lower 2 bytes
    packet.extend_from_slice(&[0xff, 0xf7]);
    // Character set
    packet.push(0x21);
    // Status flags
    packet.extend_from_slice(&[0x02, 0x00]);
    // Capability flags upper 2 bytes (includes CLIENT_PLUGIN_AUTH = 0x0008)
    packet.extend_from_slice(&[0xff, 0x8f]);
    // Auth plugin data length
    packet.push(0x15);
    // Reserved (10 bytes)
    packet.extend_from_slice(&[0x00; 10]);
    // Auth plugin data part 2 (21 - 8 = 13 bytes)
    packet.extend_from_slice(&[0x01; 13]);
    // Auth plugin name (null-terminated)
    packet.extend_from_slice(b"mysql_native_password");
    packet.push(0x00);
    packet
}

#[test]
#[cfg(feature = "database")]
fn test_registry_detects_mysql_handshake() {
    let registry = Registry::default();
    let payload = make_mysql_handshake_packet("8.0.33");

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Mysql);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Mysql(meta) = detection.metadata {
        assert_eq!(meta.version, Some("8.0.33".to_string()));
    } else {
        panic!("Expected Mysql metadata");
    }
}

#[test]
#[cfg(feature = "database")]
fn test_mysql_detector_name() {
    let mysql_detector = rdpi::protocols::mysql::MysqlDetector::new();
    assert_eq!(mysql_detector.name(), "mysql");
}

/// Helper to construct a PostgreSQL startup message
#[cfg(feature = "database")]
fn make_pg_startup_message(user: &str, database: &str) -> Vec<u8> {
    let mut packet = vec![
        // Message length (4 bytes, big-endian) - will be updated
        0x00, 0x00, 0x00, 0x00,
        // Protocol version 3.0
        0x00, 0x03, 0x00, 0x00,
    ];

    // Add user parameter
    packet.extend_from_slice(b"user");
    packet.push(0x00);
    packet.extend_from_slice(user.as_bytes());
    packet.push(0x00);

    // Add database parameter
    packet.extend_from_slice(b"database");
    packet.push(0x00);
    packet.extend_from_slice(database.as_bytes());
    packet.push(0x00);

    // Terminator
    packet.push(0x00);

    // Update message length
    let len = packet.len() as u32;
    packet[0] = ((len >> 24) & 0xff) as u8;
    packet[1] = ((len >> 16) & 0xff) as u8;
    packet[2] = ((len >> 8) & 0xff) as u8;
    packet[3] = (len & 0xff) as u8;

    packet
}

#[test]
#[cfg(feature = "database")]
fn test_registry_detects_postgresql_startup() {
    let registry = Registry::default();
    let payload = make_pg_startup_message("postgres", "testdb");

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Postgresql);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Postgresql(meta) = detection.metadata {
        assert_eq!(meta.user, Some("postgres".to_string()));
        assert_eq!(meta.database, Some("testdb".to_string()));
    } else {
        panic!("Expected Postgresql metadata");
    }
}

#[test]
#[cfg(feature = "database")]
fn test_postgresql_detector_name() {
    let pg_detector = rdpi::protocols::postgresql::PostgresqlDetector::new();
    assert_eq!(pg_detector.name(), "postgresql");
}

/// Helper to construct a Redis GET command
#[cfg(feature = "database")]
fn make_redis_get_command(key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let mut packet = vec![
        b'*', b'2', b'\r', b'\n',
        b'$', b'3', b'\r', b'\n',
        b'G', b'E', b'T', b'\r', b'\n',
    ];
    // Key length
    let key_len = format!("${}\r\n", key_bytes.len());
    packet.extend_from_slice(key_len.as_bytes());
    // Key value
    packet.extend_from_slice(key_bytes);
    packet.extend_from_slice(b"\r\n");
    packet
}

#[test]
#[cfg(feature = "database")]
fn test_registry_detects_redis_get_command() {
    let registry = Registry::default();
    let payload = make_redis_get_command("mykey");

    let result = registry.detect(&payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Redis);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Redis(meta) = detection.metadata {
        assert_eq!(meta.command, Some("GET".to_string()));
    } else {
        panic!("Expected Redis metadata");
    }
}

#[test]
#[cfg(feature = "database")]
fn test_registry_detects_redis_ping() {
    let registry = Registry::default();
    let payload = b"*1\r\n$4\r\nPING\r\n";

    let result = registry.detect(payload);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Redis);

    if let Metadata::Redis(meta) = detection.metadata {
        assert_eq!(meta.command, Some("PING".to_string()));
    } else {
        panic!("Expected Redis metadata");
    }
}

#[test]
#[cfg(feature = "database")]
fn test_redis_detector_name() {
    let redis_detector = rdpi::protocols::redis::RedisDetector::new();
    assert_eq!(redis_detector.name(), "redis");
}

#[test]
#[cfg(feature = "database")]
fn test_phase52_all_protocols_detected() {
    let registry = Registry::default();

    // MySQL
    let mysql = make_mysql_handshake_packet("5.7.42");
    assert_eq!(registry.detect(&mysql).unwrap().protocol, Protocol::Mysql);

    // PostgreSQL
    let pg = make_pg_startup_message("admin", "mydb");
    assert_eq!(registry.detect(&pg).unwrap().protocol, Protocol::Postgresql);

    // Redis
    let redis = make_redis_get_command("test");
    assert_eq!(registry.detect(&redis).unwrap().protocol, Protocol::Redis);
}
