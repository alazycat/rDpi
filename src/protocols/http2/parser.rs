//! HTTP/2 protocol parser for rDpi
//!
//! Detects HTTP/2 via the 24-byte connection preface:
//! "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

/// HTTP/2 connection preface (24 bytes)
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Check if payload starts with HTTP/2 connection preface
pub fn is_http2_preface(data: &[u8]) -> bool {
    data.len() >= 24 && data[..24] == *HTTP2_PREFACE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_preface_valid() {
        assert!(is_http2_preface(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    }

    #[test]
    fn test_http2_preface_truncated() {
        assert!(!is_http2_preface(b"PRI * HTTP/2.0"));
        assert!(!is_http2_preface(b""));
    }

    #[test]
    fn test_http2_preface_http11() {
        assert!(!is_http2_preface(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn test_http2_preface_random() {
        assert!(!is_http2_preface(&[0u8; 24]));
    }
}
