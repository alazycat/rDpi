//! Elasticsearch 二进制协议与 HTTP 响应头识别

const ELASTICSEARCH_HEADER_LEN: usize = 6;

/// 解析二进制 `ES` + BE u32 长度头，返回消息长度
///
/// 与 nDPI 5.0 `elastic_search.c` 一致：载荷 ≥ 6 字节、magic 为 `ES`、
/// 载荷长度 ≥ `message_length + 6`（允许头部后跟完整消息体）。
pub fn parse_elasticsearch(payload: &[u8]) -> Option<u32> {
    if payload.len() < ELASTICSEARCH_HEADER_LEN || !payload.starts_with(b"ES") {
        return None;
    }
    let message_length = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
    if payload.len() < message_length as usize + ELASTICSEARCH_HEADER_LEN {
        return None;
    }
    Some(message_length)
}

/// 是否为带 `X-elastic-product: Elasticsearch` 的 HTTP 响应
///
/// 只扫描头部区域（到 `\r\n\r\n` 为止），名称与值大小写不敏感。
pub fn is_elasticsearch_http_response(payload: &[u8]) -> bool {
    if !payload.starts_with(b"HTTP/1.") {
        return false;
    }
    let headers_end = payload
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(payload.len());
    let headers = &payload[..headers_end];
    let Some(first_line_end) = find_crlf(headers) else {
        return false;
    };
    let mut offset = first_line_end + 2;
    while offset < headers.len() {
        let line_end = find_crlf(&headers[offset..])
            .map(|index| offset + index)
            .unwrap_or(headers.len());
        let line = &headers[offset..line_end];
        if let Some(colon) = line.iter().position(|&byte| byte == b':') {
            let (name, value) = line.split_at(colon);
            if trim_ascii(name).eq_ignore_ascii_case(b"x-elastic-product")
                && trim_ascii(&value[1..]).eq_ignore_ascii_case(b"Elasticsearch")
            {
                return true;
            }
        }
        offset = line_end.saturating_add(2);
    }
    false
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if !first.is_ascii_whitespace() {
            break;
        }
        bytes = rest;
    }
    while let Some((last, rest)) = bytes.split_last() {
        if !last.is_ascii_whitespace() {
            break;
        }
        bytes = rest;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_valid() {
        assert_eq!(parse_elasticsearch(b"ES\x00\x00\x00\x05hello"), Some(5));
    }

    #[test]
    fn test_binary_zero_length() {
        assert_eq!(parse_elasticsearch(b"ES\x00\x00\x00\x00"), Some(0));
    }

    #[test]
    fn test_binary_truncated() {
        assert_eq!(parse_elasticsearch(b"ES\x00\x00\x00\x06hello"), None);
    }

    #[test]
    fn test_binary_wrong_magic() {
        assert_eq!(parse_elasticsearch(b"EX\x00\x00\x00\x00"), None);
    }

    #[test]
    fn test_binary_short() {
        assert_eq!(parse_elasticsearch(b"ES\x00"), None);
    }

    #[test]
    fn test_http_response_header() {
        assert!(is_elasticsearch_http_response(
            b"HTTP/1.1 200 OK\r\nX-elastic-product: Elasticsearch\r\n\r\n{}"
        ));
    }

    #[test]
    fn test_http_response_header_case_insensitive() {
        assert!(is_elasticsearch_http_response(
            b"HTTP/1.1 200 OK\r\nx-elastic-product:   elasticsearch  \r\n\r\n"
        ));
    }

    #[test]
    fn test_http_response_header_wrong_value() {
        assert!(!is_elasticsearch_http_response(
            b"HTTP/1.1 200 OK\r\nX-elastic-product: OpenSearch\r\n\r\n"
        ));
    }

    #[test]
    fn test_http_body_header_not_scanned() {
        assert!(!is_elasticsearch_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nX-elastic-product: Elasticsearch\r\n"
        ));
    }

    #[test]
    fn test_http_request_not_matched() {
        assert!(!is_elasticsearch_http_response(
            b"GET / HTTP/1.1\r\nX-elastic-product: Elasticsearch\r\n\r\n"
        ));
    }
}
