//! WebSocket protocol detector for rDpi

use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::is_websocket_upgrade;

pub struct WebSocketDetector {
    _private: (),
}

impl WebSocketDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for WebSocketDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for WebSocketDetector {
    fn name(&self) -> &'static str {
        "websocket"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if is_websocket_upgrade(payload) {
            Some(DetectionResult::new(Protocol::WebSocket).with_confidence(Confidence::Dpi))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_detector_upgrade() {
        let detector = WebSocketDetector::new();
        let req = b"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let result = detector.detect(req).unwrap();
        assert_eq!(result.protocol, Protocol::WebSocket);
    }

    #[test]
    fn test_websocket_detector_regular_http() {
        let detector = WebSocketDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
    }

    #[test]
    fn test_websocket_detector_empty() {
        let detector = WebSocketDetector::new();
        assert!(detector.detect(b"").is_none());
    }
}
