//! WebSocket protocol detector for rDpi

use crate::core::types::{
    Confidence, DetectContext, DetectionResult, Direction, DissectorOutcome, DissectorState,
    Protocol, WebSocketDissectorState,
};
use crate::protocols::ProtocolDetector;

use super::parser::is_websocket_upgrade;

/// WebSocket HTTP 头缓冲上限
const WEBSOCKET_HEADER_MAX_BYTES: usize = 8192;

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

/// 首字节是否可能是 HTTP 请求方法或响应行起始
fn is_http_prefix(byte: u8) -> bool {
    matches!(byte, b'G' | b'H' | b'P' | b'D' | b'O' | b'T' | b'C')
}

/// 不区分大小写地检查 payload 是否包含 "upgrade" 子串
fn contains_upgrade(payload: &[u8]) -> bool {
    payload
        .windows(7)
        .any(|w| w.eq_ignore_ascii_case(b"upgrade"))
}

impl ProtocolDetector for WebSocketDetector {
    fn name(&self) -> &'static str {
        "websocket"
    }

    /// 有状态逐包处理：WebSocket 升级握手头可跨 TCP 段
    ///
    /// 仅当 payload 已出现 `upgrade` 字样（不区分大小写）时才接管，避免抢占普通
    /// HTTP 流的有状态重组；缓冲至 `\r\n\r\n` 后交给无状态判定；非升级流量
    /// GiveUp 回退无状态路径。
    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        _direction: Direction,
        _ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        match state {
            DissectorState::None => {
                // 首段必须已出现 upgrade 关键字，否则不接管（让 HTTP 等 detector 处理）
                if payload.is_empty() || !is_http_prefix(payload[0]) || !contains_upgrade(payload) {
                    return None;
                }
                *state = DissectorState::WebSocket(WebSocketDissectorState::default());
            }
            DissectorState::WebSocket(_) => {}
            _ => return None,
        }
        let DissectorState::WebSocket(ws) = state else {
            return None;
        };

        if ws.buffer.len() + payload.len() > WEBSOCKET_HEADER_MAX_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        ws.buffer.extend_from_slice(payload);

        if is_websocket_upgrade(&ws.buffer) {
            ws.buffer.clear();
            return Some(DissectorOutcome::Classified(
                DetectionResult::new(Protocol::WebSocket).with_confidence(Confidence::Dpi),
            ));
        }
        // 头已结束仍非升级：放弃
        if ws.buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            return Some(DissectorOutcome::GiveUp);
        }
        Some(DissectorOutcome::Continue)
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
        assert!(
            detector
                .detect(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                .is_none()
        );
    }

    #[test]
    fn test_websocket_detector_empty() {
        let detector = WebSocketDetector::new();
        assert!(detector.detect(b"").is_none());
    }

    // ---- 有状态跨段重组测试 ----
    #[test]
    fn test_stateful_websocket_upgrade_split() {
        let detector = WebSocketDetector::new();
        let mut state = DissectorState::None;
        let ctx = DetectContext {
            src_port: 12345,
            dst_port: 80,
            is_http3_port: false,
        };
        let r1 = detector.process(
            &mut state,
            b"GET /chat HTTP/1.1\r\nUpgrade: ",
            Direction::Forward,
            &ctx,
        );
        assert!(matches!(r1, Some(DissectorOutcome::Continue)));
        let r2 = detector.process(
            &mut state,
            b"websocket\r\nConnection: Upgrade\r\n\r\n",
            Direction::Forward,
            &ctx,
        );
        match r2 {
            Some(DissectorOutcome::Classified(det)) => {
                assert_eq!(det.protocol, Protocol::WebSocket);
            }
            other => panic!("expected Classified, got {:?}", other),
        }
    }

    #[test]
    fn test_stateful_websocket_non_upgrade_gives_up() {
        let detector = WebSocketDetector::new();
        let mut state = DissectorState::None;
        let ctx = DetectContext {
            src_port: 12345,
            dst_port: 80,
            is_http3_port: false,
        };
        // 不含 upgrade 关键字，WebSocket 不接管，交由 HTTP 等 detector 处理
        let r = detector.process(
            &mut state,
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            Direction::Forward,
            &ctx,
        );
        assert!(r.is_none());
        assert!(matches!(state, DissectorState::None));
    }
}
