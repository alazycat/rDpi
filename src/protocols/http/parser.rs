//! HTTP protocol parser for rDpi
//!
//! Parses HTTP request and response lines.

/// HTTP 请求行解析结果
#[derive(Debug, Clone)]
pub struct HttpRequestLine {
    pub method: String,
    pub path: String,
    pub version: String,
}

/// HTTP 响应行解析结果
#[derive(Debug, Clone)]
pub struct HttpResponseLine {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
}

/// 解析 HTTP 请求行
/// 格式: METHOD SP PATH SP HTTP/1.x CRLF
pub fn parse_request_line(data: &[u8]) -> Option<HttpRequestLine> {
    let line_end = find_line_end(data)?;
    let line = std::str::from_utf8(&data[..line_end]).ok()?;

    // 分割: METHOD PATH HTTP/1.x
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() != 3 {
        return None;
    }

    // 验证方法（在分配内存前）
    if !is_valid_method(parts[0]) {
        return None;
    }

    // 验证版本（在分配内存前）
    if !parts[2].starts_with("HTTP/1.") {
        return None;
    }

    Some(HttpRequestLine {
        method: parts[0].to_string(),
        path: parts[1].to_string(),
        version: parts[2].to_string(),
    })
}

/// 解析 HTTP 响应行
/// 格式: HTTP/1.x SP STATUS SP REASON CRLF
pub fn parse_response_line(data: &[u8]) -> Option<HttpResponseLine> {
    let line_end = find_line_end(data)?;
    let line = std::str::from_utf8(&data[..line_end]).ok()?;

    // 格式: HTTP/1.x STATUS REASON
    if !line.starts_with("HTTP/1.") {
        return None;
    }

    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }

    // 验证版本（在分配内存前）
    if !parts[0].starts_with("HTTP/1.") {
        return None;
    }

    let status_code: u16 = parts[1].parse().ok()?;

    // 验证状态码范围
    if status_code < 100 || status_code > 599 {
        return None;
    }

    let reason = if parts.len() > 2 {
        parts[2].to_string()
    } else {
        String::new()
    };

    Some(HttpResponseLine {
        version: parts[0].to_string(),
        status_code,
        reason,
    })
}

/// 解析 Host 头
/// 查找 \r\n 之后、\r\n\r\n 之前的 Host: 头
pub fn parse_host_header(data: &[u8]) -> Option<String> {
    let data_str = std::str::from_utf8(data).ok()?;

    for line in data_str.lines() {
        // 使用大小写不敏感比较，避免分配新字符串
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case("host:") {
            let host = line[5..].trim();
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }
    }

    None
}

/// 检查首字节是否为 HTTP 方法起始字符
pub fn is_http_prefix(byte: u8) -> bool {
    matches!(byte, b'G' | b'P' | b'H' | b'D' | b'C' | b'O' | b'T')
}

/// 检查是否为有效的 HTTP 方法
fn is_valid_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "CONNECT" | "TRACE" | "PATCH"
    )
}

/// 查找行结束位置（\r\n 或 \n）
/// 返回不包含换行符的行结束位置
fn find_line_end(data: &[u8]) -> Option<usize> {
    for (i, &byte) in data.iter().enumerate() {
        if byte == b'\n' {
            // 如果 \n 前面是 \r，返回 \r 的位置（不包含 \r）
            if i > 0 && data[i - 1] == b'\r' {
                return Some(i - 1);
            }
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_line_get() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = parse_request_line(data);
        assert!(result.is_some());

        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/index.html");
        assert_eq!(req.version, "HTTP/1.1");
    }

    #[test]
    fn test_parse_request_line_post() {
        let data = b"POST /api/users HTTP/1.0\r\nContent-Length: 0\r\n\r\n";
        let result = parse_request_line(data);
        assert!(result.is_some());

        let req = result.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/users");
        assert_eq!(req.version, "HTTP/1.0");
    }

    #[test]
    fn test_parse_request_line_invalid_method() {
        let data = b"INVALID /path HTTP/1.1\r\n\r\n";
        let result = parse_request_line(data);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_response_line_ok() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let result = parse_response_line(data);
        assert!(result.is_some());

        let resp = result.unwrap();
        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
    }

    #[test]
    fn test_parse_response_line_not_found() {
        let data = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let result = parse_response_line(data);
        assert!(result.is_some());

        let resp = result.unwrap();
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.reason, "Not Found");
    }

    #[test]
    fn test_parse_host_header() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let host = parse_host_header(data);
        assert!(host.is_some());
        assert_eq!(host.unwrap(), "example.com");
    }

    #[test]
    fn test_parse_host_header_case_insensitive() {
        let data = b"GET / HTTP/1.1\r\nHOST: Example.COM\r\n\r\n";
        let host = parse_host_header(data);
        assert!(host.is_some());
        assert_eq!(host.unwrap(), "Example.COM");
    }

    #[test]
    fn test_is_http_prefix() {
        assert!(is_http_prefix(b'G'));  // GET
        assert!(is_http_prefix(b'P'));  // POST, PUT
        assert!(is_http_prefix(b'H'));  // HEAD, HTTP
        assert!(!is_http_prefix(b'A'));
    }
}
