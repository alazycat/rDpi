use rdpi::protocols::http::{parse_host_header, parse_request_line, parse_response_line, is_http_prefix};

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
    assert!(is_http_prefix(b'G'));  // GET
    assert!(is_http_prefix(b'P'));  // POST, PUT
    assert!(is_http_prefix(b'H'));  // HEAD, HTTP
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
