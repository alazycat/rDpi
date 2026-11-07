//! IMAP protocol detector for rDpi

#[cfg(test)]
use crate::core::types::Confidence;
use crate::core::types::{
    DetectContext, DetectionResult, Direction, DissectorOutcome, DissectorState,
    ImapDissectorState, ImapMetadata, Metadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::{
    is_imap_command_prefix, is_imap_response_prefix, parse_imap_command, parse_imap_response,
};

/// IMAP 行缓冲上限（RFC 3501 §7.1 命令行 ≤ 1000 字节，留足余量）
const IMAP_LINE_MAX_BYTES: usize = 2048;

/// IMAP protocol detector
pub struct ImapDetector {
    _private: (),
}

impl ImapDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for ImapDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for ImapDetector {
    fn name(&self) -> &'static str {
        "imap"
    }

    /// 有状态逐包处理：IMAP 行可能跨 TCP 段
    ///
    /// 仅在 untagged 响应前缀 `*` 时接管——IMAP 为服务端先发 banner 协议，
    /// 接管后进入监测模式，后续客户端命令（LOGIN 等）均经此路径解析。
    /// IMAP 命令前缀（标签字母数字）与 HTTP 方法重叠，故首段不接管命令前缀。
    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        _direction: Direction,
        _ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        match state {
            DissectorState::None => {
                if payload.is_empty() || payload[0] != b'*' {
                    return None;
                }
                *state = DissectorState::Imap(ImapDissectorState::default());
            }
            DissectorState::Imap(_) => {}
            _ => return None,
        }
        let DissectorState::Imap(imap) = state else {
            return None;
        };

        if imap.buffer.len() + payload.len() > IMAP_LINE_MAX_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        imap.buffer.extend_from_slice(payload);

        // 解析当前完整行，提取 LOGIN 命令的用户名
        if imap.buffer.contains(&b'\n')
            && let Some(cmd) = parse_imap_command(&imap.buffer)
            && cmd.command == "LOGIN"
            && let Some(user) = cmd
                .argument
                .as_deref()
                .and_then(|a| a.split_whitespace().next())
        {
            imap.username = Some(user.to_string());
        }

        if self.detect(&imap.buffer).is_some() {
            let metadata = Metadata::Imap(ImapMetadata {
                username: imap.username.clone(),
            });
            imap.buffer.clear();
            return Some(DissectorOutcome::Classified(
                DetectionResult::new(Protocol::Imap).with_metadata(metadata),
            ));
        }
        if imap.buffer.contains(&b'\n') {
            return Some(DissectorOutcome::GiveUp);
        }
        Some(DissectorOutcome::Continue)
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if payload.is_empty() {
            return None;
        }

        let first_byte = payload[0];

        // Path 1: Server response (untagged or tagged)
        if is_imap_response_prefix(first_byte) && parse_imap_response(payload).is_some() {
            return Some(DetectionResult::new(Protocol::Imap));
        }

        // Path 2: Client command
        if is_imap_command_prefix(first_byte) && parse_imap_command(payload).is_some() {
            return Some(DetectionResult::new(Protocol::Imap));
        }

        None
    }

    fn detect_with_context(
        &self,
        payload: &[u8],
        ctx: &crate::core::types::DetectContext,
    ) -> Option<DetectionResult> {
        // Check for IMAPS (port 993)
        if ctx.src_port == 993 || ctx.dst_port == 993 {
            return Some(DetectionResult::new(Protocol::Imaps));
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
    fn test_imap_detector_new() {
        let detector = ImapDetector::new();
        assert_eq!(detector.name(), "imap");
    }

    #[test]
    fn test_detect_imap_untagged_response() {
        let detector = ImapDetector::new();
        let data = b"* OK IMAP4rev1 Service Ready\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Imap);
        assert_eq!(result.confidence, Confidence::Dpi);
    }

    #[test]
    fn test_detect_imap_tagged_response() {
        let detector = ImapDetector::new();
        let data = b"A001 OK LOGIN completed\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Imap);
    }

    #[test]
    fn test_detect_imap_login_command() {
        let detector = ImapDetector::new();
        let data = b"A001 LOGIN user password\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Imap);
    }

    #[test]
    fn test_detect_imap_select_command() {
        let detector = ImapDetector::new();
        let data = b"A002 SELECT INBOX\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Imap);
    }

    #[test]
    fn test_detect_imap_noop_command() {
        let detector = ImapDetector::new();
        let data = b"A003 NOOP\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Imap);
    }

    #[test]
    fn test_detect_imap_empty() {
        let detector = ImapDetector::new();
        assert!(detector.detect(b"").is_none());
    }

    #[test]
    fn test_detect_imap_invalid() {
        let detector = ImapDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
        assert!(detector.detect(b"random data\r\n").is_none());
    }

    #[test]
    fn test_detect_imaps_port() {
        let detector = ImapDetector::new();
        let ctx = DetectContext {
            src_port: 12345,
            dst_port: 993,
            is_http3_port: false,
        };
        let result = detector.detect_with_context(b"", &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Imaps);
    }

    #[test]
    fn test_detect_imaps_port_src() {
        let detector = ImapDetector::new();
        let ctx = DetectContext {
            src_port: 993,
            dst_port: 12345,
            is_http3_port: false,
        };
        let result = detector.detect_with_context(b"", &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Imaps);
    }

    // ---- 有状态跨段重组测试 ----
    #[test]
    fn test_stateful_imap_banner_split() {
        let detector = ImapDetector::new();
        let mut state = DissectorState::None;
        let ctx = DetectContext {
            src_port: 143,
            dst_port: 12345,
            is_http3_port: false,
        };
        let r1 = detector.process(&mut state, b"* OK IMAP ", Direction::Reverse, &ctx);
        assert!(matches!(r1, Some(DissectorOutcome::Continue)));
        let r2 = detector.process(&mut state, b"server ready\r\n", Direction::Reverse, &ctx);
        match r2 {
            Some(DissectorOutcome::Classified(det)) => assert_eq!(det.protocol, Protocol::Imap),
            other => panic!("expected Classified, got {:?}", other),
        }
    }

    #[test]
    fn test_stateful_imap_login_extraction() {
        let detector = ImapDetector::new();
        let mut state = DissectorState::None;
        let ctx = DetectContext {
            src_port: 12345,
            dst_port: 143,
            is_http3_port: false,
        };
        let _ = detector.process(&mut state, b"* OK ready\r\n", Direction::Reverse, &ctx);
        let r = detector.process(
            &mut state,
            b"A001 LOGIN bob secret\r\n",
            Direction::Forward,
            &ctx,
        );
        match r {
            Some(DissectorOutcome::Classified(det)) => {
                if let Metadata::Imap(meta) = det.metadata {
                    assert_eq!(meta.username, Some("bob".to_string()));
                } else {
                    panic!("expected Imap metadata");
                }
            }
            other => panic!("expected Classified, got {:?}", other),
        }
    }
}
