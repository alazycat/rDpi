//! WebSocket protocol parser for rDpi
//!
//! Detects WebSocket connections via the HTTP Upgrade header.
//! Checks for "Upgrade: websocket" and "Connection: Upgrade" headers.

/// ASCII 大小写不敏感子串查找（零堆分配）。
///
/// 误报面审计 2026-11-05：原实现经 `to_lowercase()` 在 detect 热路径做堆分配，
/// 违反项目铁律 2（detect 路径禁止分配密集逻辑）；改为逐字节 ASCII 折叠比较，
/// 语义不变（两个字节模式各匹配一次，大小写不敏感）。
fn contains_case_insensitive(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    'outer: for i in 0..=(hay.len() - needle.len()) {
        for j in 0..needle.len() {
            if !hay[i + j].eq_ignore_ascii_case(&needle[j]) {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

/// Check if payload is an HTTP request upgrading to WebSocket
pub fn is_websocket_upgrade(data: &[u8]) -> bool {
    // Must contain both Upgrade: websocket and Connection: Upgrade
    contains_case_insensitive(data, b"upgrade: websocket")
        && contains_case_insensitive(data, b"connection: upgrade")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_upgrade_request() {
        let req = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        assert!(is_websocket_upgrade(req));
    }

    #[test]
    fn test_websocket_response() {
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        assert!(is_websocket_upgrade(resp));
    }

    #[test]
    fn test_websocket_case_insensitive() {
        let req = b"GET /chat HTTP/1.1\r\nUPGRADE: WebSocket\r\nCONNECTION: upgrade\r\n\r\n";
        assert!(is_websocket_upgrade(req));
    }

    #[test]
    fn test_websocket_regular_http() {
        assert!(!is_websocket_upgrade(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ));
        assert!(!is_websocket_upgrade(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        ));
    }

    #[test]
    fn test_websocket_truncated() {
        assert!(!is_websocket_upgrade(b""));
        assert!(!is_websocket_upgrade(b"GET / HTTP/1.1"));
    }

    #[test]
    fn test_websocket_not_utf8() {
        assert!(!is_websocket_upgrade(&[0xff, 0xfe, 0x00]));
    }

    // ---- 误报面审计 2026-11-05 探针 ----
    #[test]
    fn test_websocket_partial_headers_rejected() {
        // 仅有 upgrade 头、connection 值非 upgrade：两个模式须同时满足
        assert!(!is_websocket_upgrade(
            b"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: keep-alive\r\n\r\n"
        ));
        // 模式内多一个空格（"Upgrade:  websocket"）不算命中
        assert!(!is_websocket_upgrade(
            b"GET /chat HTTP/1.1\r\nUpgrade:  websocket\r\nConnection: Upgrade\r\n\r\n"
        ));
    }

    #[test]
    fn test_websocket_binary_noise_with_valid_headers() {
        // 误报面审计 2026-11-05：去 UTF-8 前置校验后的等价行为锁定——
        // 报文前后夹带非 UTF-8 二进制噪声，ASCII 头部完整时仍应命中
        // （旧实现因 from_utf8 失败而拒绝，属对真实流量的误拒）
        let mut buf = vec![0xffu8, 0xfe];
        buf.extend_from_slice(
            b"GET /chat HTTP/1.1\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n\r\n",
        );
        buf.push(0x80);
        assert!(is_websocket_upgrade(&buf));
    }
}
