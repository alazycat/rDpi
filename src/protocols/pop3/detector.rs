//! POP3 protocol detector for rDpi

#[cfg(test)]
use crate::core::types::Confidence;
use crate::core::types::{
    DetectContext, DetectionResult, Direction, DissectorOutcome, DissectorState, Metadata,
    Pop3DissectorState, Pop3Metadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::{
    is_pop3_command_prefix, is_pop3_response_prefix, parse_pop3_command, parse_pop3_response,
};

/// POP3 行缓冲上限（RFC 1939 单行 ≤ 512 字节，留足余量）
const POP3_LINE_MAX_BYTES: usize = 1024;

/// POP3 protocol detector
pub struct Pop3Detector {
    _private: (),
}

impl Pop3Detector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for Pop3Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for Pop3Detector {
    fn name(&self) -> &'static str {
        "pop3"
    }

    /// 有状态逐包处理：POP3 行可能跨 TCP 段
    ///
    /// 仅在服务端响应前缀（+/-）时接管——POP3 为服务端先发 banner 协议，
    /// 接管后进入监测模式，后续客户端命令（USER 等）均经此路径解析。
    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        _direction: Direction,
        _ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        match state {
            DissectorState::None => {
                if payload.is_empty() || !is_pop3_response_prefix(payload[0]) {
                    return None;
                }
                *state = DissectorState::Pop3(Pop3DissectorState::default());
            }
            DissectorState::Pop3(_) => {}
            _ => return None,
        }
        let DissectorState::Pop3(pop3) = state else {
            return None;
        };

        if pop3.buffer.len() + payload.len() > POP3_LINE_MAX_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        pop3.buffer.extend_from_slice(payload);

        // 解析当前完整行，提取 USER 命令的用户名
        if pop3.buffer.contains(&b'\n')
            && let Some(cmd) = parse_pop3_command(&pop3.buffer)
            && cmd.command == "USER"
        {
            pop3.username = cmd.argument;
        }

        if self.detect(&pop3.buffer).is_some() {
            let metadata = Metadata::Pop3(Pop3Metadata {
                username: pop3.username.clone(),
            });
            pop3.buffer.clear();
            return Some(DissectorOutcome::Classified(
                DetectionResult::new(Protocol::Pop3).with_metadata(metadata),
            ));
        }
        if pop3.buffer.contains(&b'\n') {
            return Some(DissectorOutcome::GiveUp);
        }
        Some(DissectorOutcome::Continue)
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if payload.is_empty() {
            return None;
        }

        let first_byte = payload[0];

        // Path 1: Server response
        if is_pop3_response_prefix(first_byte) && parse_pop3_response(payload).is_some() {
            return Some(DetectionResult::new(Protocol::Pop3));
        }

        // Path 2: Client command
        if is_pop3_command_prefix(first_byte) && parse_pop3_command(payload).is_some() {
            return Some(DetectionResult::new(Protocol::Pop3));
        }

        None
    }

    fn detect_with_context(
        &self,
        payload: &[u8],
        ctx: &crate::core::types::DetectContext,
    ) -> Option<DetectionResult> {
        // Check for POP3S (port 995)
        if ctx.src_port == 995 || ctx.dst_port == 995 {
            return Some(DetectionResult::new(Protocol::Pop3s));
        }

        // Otherwise use standard payload detection
        self.detect(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::DetectContext;

    #[test]
    fn test_pop3_detector_new() {
        let detector = Pop3Detector::new();
        assert_eq!(detector.name(), "pop3");
    }

    #[test]
    fn test_detect_pop3_ok_response() {
        let detector = Pop3Detector::new();
        let data = b"+OK POP3 server ready\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Pop3);
        assert_eq!(result.confidence, Confidence::Dpi);
    }

    #[test]
    fn test_detect_pop3_err_response() {
        let detector = Pop3Detector::new();
        let data = b"-ERR Authentication failed\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Pop3);
    }

    #[test]
    fn test_detect_pop3_user_command() {
        let detector = Pop3Detector::new();
        let data = b"USER test@example.com\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Pop3);
    }

    #[test]
    fn test_detect_pop3_quit_command() {
        let detector = Pop3Detector::new();
        let data = b"QUIT\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Pop3);
    }

    #[test]
    fn test_detect_pop3_empty() {
        let detector = Pop3Detector::new();
        assert!(detector.detect(b"").is_none());
    }

    #[test]
    fn test_detect_pop3_invalid() {
        let detector = Pop3Detector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
        assert!(detector.detect(b"random data\r\n").is_none());
    }

    #[test]
    fn test_detect_pop3s_port() {
        let detector = Pop3Detector::new();
        let ctx = DetectContext {
            src_port: 12345,
            dst_port: 995,
            is_http3_port: false,
        };
        // Even with empty payload, port 995 should return Pop3s
        let result = detector.detect_with_context(b"", &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Pop3s);
    }

    #[test]
    fn test_detect_pop3s_port_src() {
        let detector = Pop3Detector::new();
        let ctx = DetectContext {
            src_port: 995,
            dst_port: 12345,
            is_http3_port: false,
        };
        let result = detector.detect_with_context(b"", &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Pop3s);
    }

    // ---- 有状态跨段重组测试 ----
    #[test]
    fn test_stateful_pop3_banner_split() {
        let detector = Pop3Detector::new();
        let mut state = DissectorState::None;
        let ctx = DetectContext {
            src_port: 110,
            dst_port: 12345,
            is_http3_port: false,
        };
        let r1 = detector.process(&mut state, b"+OK POP3 ", Direction::Reverse, &ctx);
        assert!(matches!(r1, Some(DissectorOutcome::Continue)));
        let r2 = detector.process(&mut state, b"server ready\r\n", Direction::Reverse, &ctx);
        match r2 {
            Some(DissectorOutcome::Classified(det)) => assert_eq!(det.protocol, Protocol::Pop3),
            other => panic!("expected Classified, got {:?}", other),
        }
    }

    #[test]
    fn test_stateful_pop3_user_extraction() {
        let detector = Pop3Detector::new();
        let mut state = DissectorState::None;
        let ctx = DetectContext {
            src_port: 12345,
            dst_port: 110,
            is_http3_port: false,
        };
        let _ = detector.process(&mut state, b"+OK ready\r\n", Direction::Reverse, &ctx);
        let r = detector.process(&mut state, b"USER alice\r\n", Direction::Forward, &ctx);
        match r {
            Some(DissectorOutcome::Classified(det)) => {
                if let Metadata::Pop3(meta) = det.metadata {
                    assert_eq!(meta.username, Some("alice".to_string()));
                } else {
                    panic!("expected Pop3 metadata");
                }
            }
            other => panic!("expected Classified, got {:?}", other),
        }
    }
}
