use rdpi::core::types::{Application, Confidence, Metadata, Protocol};
use rdpi::protocols::ProtocolDetector;
use rdpi::protocols::http::{
    HttpDetector, is_http_prefix, parse_host_header, parse_request_line, parse_response_line,
};

#[test]
fn test_detector_http_request_yields_ja4h() {
    let detector = HttpDetector::new();
    let payload =
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test/1\r\nAccept: */*\r\n\r\n";

    let result = detector.detect(payload).expect("应识别为 HTTP");
    assert_eq!(result.protocol, Protocol::Http);
    if let Metadata::Http(meta) = result.metadata {
        assert_eq!(meta.host.as_deref(), Some("example.com"));
        assert_eq!(meta.method.as_deref(), Some("GET"));
        // golden 向量：ge11nn030000 | sha256("Host,User-Agent,Accept")[:12]
        assert_eq!(
            meta.ja4h.as_deref(),
            Some("ge11nn030000_fe444ad14866_000000000000_000000000000"),
            "HTTP/1.x 请求应携带 JA4H"
        );
    } else {
        panic!("Expected Http metadata");
    }
}

#[test]
fn test_detector_http_response_has_no_ja4h() {
    let detector = HttpDetector::new();
    let payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    let result = detector.detect(payload).expect("应识别为 HTTP");
    assert_eq!(result.protocol, Protocol::Http);
    if let Metadata::Http(meta) = result.metadata {
        assert!(meta.ja4h.is_none(), "响应不携带 JA4H（仅客户端指纹）");
    } else {
        panic!("Expected Http metadata");
    }
}

#[test]
fn test_detector_http_request_with_cookie_ja4h() {
    let detector = HttpDetector::new();
    let payload = b"POST /login HTTP/1.1\r\nHost: example.com\r\nCookie: theme=dark; session_id=abc123\r\nAccept-Language: en-US,en;q=0.9\r\n\r\nbody";

    let result = detector.detect(payload).unwrap();
    if let Metadata::Http(meta) = result.metadata {
        // c 置位 + lang "enus"；参与计数头部 2 个（Host、Accept-Language）
        assert_eq!(
            meta.ja4h.as_deref(),
            Some("po11cn02enus_09e340ee0db0_ae523545408f_12670912ce0c"),
            "cookie 字段/值按名排序哈希"
        );
    } else {
        panic!("Expected Http metadata");
    }
}

/// 构造完整以太网+IPv4+TCP 包（Detector.detect 需要完整帧，风格对齐 test_tls.rs）
fn build_tcp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
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
    pkt.extend_from_slice(&[10, 0, 0, 1]); // src ip
    pkt.extend_from_slice(&[10, 0, 0, 2]); // dst ip

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

/// Detector 全链路：HTTP 流回显包元数据（含 JA4H）不丢（F7 语义）
#[test]
fn test_detector_http_ja4h_persists_across_echo() {
    let mut detector = rdpi::Detector::new();
    let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let r1 = detector
        .detect(&build_tcp_packet(54321, 80, payload))
        .unwrap()
        .unwrap();
    assert_eq!(r1.protocol, Protocol::Http);
    if let Metadata::Http(ref meta) = r1.metadata {
        assert!(meta.ja4h.as_deref().unwrap().starts_with("ge11nn010000_"));
    }

    // 回显包（同五元组）：元数据（含 JA4H）保持
    let echo = build_tcp_packet(54321, 80, b"HTTP/1.1 200 OK\r\n\r\n");
    let r2 = detector.detect(&echo).unwrap().unwrap();
    if let Metadata::Http(ref meta) = r2.metadata {
        assert!(
            meta.ja4h.as_deref().unwrap().starts_with("ge11nn010000_"),
            "回显包应携带已保存的 JA4H"
        );
    }
}

#[test]
fn test_parse_request_line() {
    let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = parse_request_line(data);
    assert!(result.is_some());

    let req = result.unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/index.html");
    assert_eq!(req.version, "HTTP/1.1");
}

#[test]
fn test_parse_response_line() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let result = parse_response_line(data);
    assert!(result.is_some());

    let resp = result.unwrap();
    assert_eq!(resp.version, "HTTP/1.1");
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.reason, "OK");
}

#[test]
fn test_parse_host_header() {
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    let host = parse_host_header(data);
    assert!(host.is_some());
    assert_eq!(host.unwrap(), "example.com");
}

#[test]
fn test_is_http_prefix() {
    assert!(is_http_prefix(b'G')); // GET
    assert!(is_http_prefix(b'P')); // POST, PUT
    assert!(is_http_prefix(b'H')); // HEAD, HTTP
    assert!(!is_http_prefix(b'A'));
}

#[test]
fn test_parse_request_line_various_methods() {
    let test_cases = vec![
        ("GET", "/"),
        ("POST", "/api/users"),
        ("PUT", "/resource/1"),
        ("DELETE", "/resource/1"),
        ("HEAD", "/index.html"),
        ("OPTIONS", "*"),
        ("PATCH", "/resource/1"),
        ("TRACE", "/"),
        ("CONNECT", "server:443"),
    ];

    for (method, path) in test_cases {
        let data = format!("{} {} HTTP/1.1\r\n\r\n", method, path);
        let result = parse_request_line(data.as_bytes());
        assert!(result.is_some(), "Failed to parse {} request", method);
        let req = result.unwrap();
        assert_eq!(req.method, method);
        assert_eq!(req.path, path);
    }
}

#[test]
fn test_parse_response_line_various_codes() {
    let test_cases = vec![
        (200, "OK"),
        (201, "Created"),
        (301, "Moved Permanently"),
        (400, "Bad Request"),
        (404, "Not Found"),
        (500, "Internal Server Error"),
        (503, "Service Unavailable"),
    ];

    for (code, reason) in test_cases {
        let data = format!("HTTP/1.1 {} {}\r\n\r\n", code, reason);
        let result = parse_response_line(data.as_bytes());
        assert!(result.is_some(), "Failed to parse {} response", code);
        let resp = result.unwrap();
        assert_eq!(resp.status_code, code);
        assert_eq!(resp.reason, reason);
    }
}

#[test]
fn test_parse_invalid_request() {
    // Invalid method
    let data = b"INVALID /path HTTP/1.1\r\n\r\n";
    assert!(parse_request_line(data).is_none());

    // Invalid version
    let data = b"GET /path HTTP/2.0\r\n\r\n";
    assert!(parse_request_line(data).is_none());

    // Missing parts
    let data = b"GET\r\n\r\n";
    assert!(parse_request_line(data).is_none());
}

#[test]
fn test_parse_invalid_response() {
    // Invalid status code
    let data = b"HTTP/1.1 999 Invalid\r\n\r\n";
    assert!(parse_response_line(data).is_none());

    // Not HTTP response
    let data = b"GET / HTTP/1.1\r\n\r\n";
    assert!(parse_response_line(data).is_none());
}

#[test]
fn test_parse_host_header_with_port() {
    let data = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
    let host = parse_host_header(data);
    assert!(host.is_some());
    assert_eq!(host.unwrap(), "example.com:8080");
}

#[test]
fn test_parse_host_header_case_insensitive() {
    let data = b"GET / HTTP/1.1\r\nHOST: Example.COM\r\n\r\n";
    let host = parse_host_header(data);
    assert!(host.is_some());
    assert_eq!(host.unwrap(), "Example.COM");
}

// ============================================================================
// HTTP Detector Tests
// ============================================================================

#[test]
fn test_http_detector_request() {
    let detector = HttpDetector::new();
    let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Http);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Http(meta) = detection.metadata {
        assert_eq!(meta.method, Some("GET".to_string()));
        assert_eq!(meta.path, Some("/index.html".to_string()));
        assert_eq!(meta.host, Some("example.com".to_string()));
    } else {
        panic!("Expected Http metadata");
    }
}

#[test]
fn test_http_detector_response() {
    let detector = HttpDetector::new();
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Http);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Http(meta) = detection.metadata {
        // Responses don't have method/path/host
        assert!(meta.method.is_none());
        assert!(meta.path.is_none());
        assert!(meta.host.is_none());
    } else {
        panic!("Expected Http metadata");
    }
}

#[test]
fn test_http_detector_with_host() {
    let detector = HttpDetector::new();
    let data =
        b"POST /api/users HTTP/1.1\r\nHost: api.example.com:8080\r\nContent-Length: 42\r\n\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Http);

    if let Metadata::Http(meta) = detection.metadata {
        assert_eq!(meta.method, Some("POST".to_string()));
        assert_eq!(meta.path, Some("/api/users".to_string()));
        assert_eq!(meta.host, Some("api.example.com:8080".to_string()));
    } else {
        panic!("Expected Http metadata");
    }
}

#[test]
fn test_http_detector_non_http() {
    let detector = HttpDetector::new();

    // Non-HTTP data
    let test_cases = vec![
        b"Hello World".as_slice(),
        b"\x00\x01\x02\x03".as_slice(),
        b"random binary data".as_slice(),
        b"SSH-2.0-OpenSSH_8.4".as_slice(), // SSH starts with 'S', not a HTTP prefix
        b"220 smtp.example.com ESMTP".as_slice(), // SMTP starts with '2'
    ];

    for data in test_cases {
        let result = detector.detect(data);
        assert!(
            result.is_none(),
            "Should not detect HTTP in: {:?}",
            std::str::from_utf8(data)
        );
    }
}

#[test]
fn test_http_detector_empty_payload() {
    let detector = HttpDetector::new();
    let result = detector.detect(b"");
    assert!(result.is_none());
}

#[test]
fn test_http_detector_various_methods() {
    let detector = HttpDetector::new();

    let methods = [
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
    ];
    for method in methods {
        let data = format!("{} / HTTP/1.1\r\n\r\n", method);
        let result = detector.detect(data.as_bytes());
        assert!(result.is_some(), "Should detect {} request", method);

        let detection = result.unwrap();
        if let Metadata::Http(meta) = detection.metadata {
            assert_eq!(meta.method, Some(method.to_string()));
        } else {
            panic!("Expected Http metadata for {}", method);
        }
    }
}

#[test]
fn test_http_detector_various_status_codes() {
    let detector = HttpDetector::new();

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
        let data = format!("HTTP/1.1 {} {}\r\n\r\n", code, reason);
        let result = detector.detect(data.as_bytes());
        assert!(result.is_some(), "Should detect {} response", code);

        let detection = result.unwrap();
        assert_eq!(detection.protocol, Protocol::Http);
    }
}

#[test]
fn test_http_host_to_application() {
    let detector = HttpDetector::new();
    // 构造带 Netflix 域名 Host 头的 HTTP 请求
    let data = b"GET / HTTP/1.1\r\nHost: www.netflix.com\r\n\r\n";
    let result = detector.detect(data).unwrap();
    if let Metadata::Http(meta) = result.metadata {
        assert_eq!(meta.application, Some(Application::Netflix));
    } else {
        panic!("Expected Http metadata");
    }
}
