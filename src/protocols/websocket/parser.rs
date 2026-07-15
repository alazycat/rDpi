//! WebSocket protocol parser for rDpi
//!
//! Detects WebSocket connections via the HTTP Upgrade header.
//! Checks for "Upgrade: websocket" and "Connection: Upgrade" headers.

/// Check if payload is an HTTP request upgrading to WebSocket
pub fn is_websocket_upgrade(data: &[u8]) -> bool {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Must contain both Upgrade: websocket and Connection: Upgrade
    let lower = s.to_lowercase();
    lower.contains("upgrade: websocket") && lower.contains("connection: upgrade")
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
        assert!(!is_websocket_upgrade(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"));
        assert!(!is_websocket_upgrade(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"));
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
}
