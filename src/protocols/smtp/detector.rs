//! SMTP protocol detector for rDpi

use crate::core::types::{
    Confidence, DetectContext, DetectionResult, Direction, DissectorOutcome, DissectorState,
    Metadata, Protocol, SmtpDissectorState, SmtpMetadata,
};
use crate::protocols::ProtocolDetector;

use super::parser::{
    extract_address_from_command, is_smtp_command_prefix, is_smtp_response_prefix,
    parse_smtp_command, parse_smtp_response,
};

/// SMTP 服务端口——`220 ...` 数字问候码为 FTP 与 SMTP 共有语法（F10）。
/// 非 SMTP 端口上的数字响应让位给 FTP（对称于 FTP detect_with_context 在 SMTP 端口让位）。
const SMTP_PORTS: [u16; 3] = [25, 465, 587];

fn is_smtp_port(port: u16) -> bool {
    SMTP_PORTS.contains(&port)
}

/// SMTP 行缓冲上限（RFC 5321 §4.5.3.1.6 单行 ≤ 998 字节，留足余量）
const SMTP_LINE_MAX_BYTES: usize = 2048;

/// SMTP protocol detector
pub struct SmtpDetector {
    _private: (),
}

impl SmtpDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for SmtpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for SmtpDetector {
    fn name(&self) -> &'static str {
        "smtp"
    }

    /// 首字节门：SMTP 数字响应（0x32-0x35）与大写命令（0x41-0x5A）。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x32u8, 0x35u8), (0x41u8, 0x5Au8)])
    }

    /// 有状态逐包处理：SMTP 行可能跨 TCP 段
    ///
    /// 仅在服务端响应前缀（数字 2-5）时接管——SMTP 为服务端先发 banner 协议，
    /// 接管后进入监测模式，后续客户端命令（EHLO/MAIL/RCPT）均经此路径解析。
    /// 避免与 HTTP 等客户端前缀协议争抢。
    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        _direction: Direction,
        ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        match state {
            DissectorState::None => {
                // 服务端数字响应在非 SMTP 端口上让位给 FTP（F10 共有语法）
                if payload.is_empty()
                    || !is_smtp_response_prefix(payload[0])
                    || (!is_smtp_port(ctx.src_port) && !is_smtp_port(ctx.dst_port))
                {
                    return None;
                }
                *state = DissectorState::Smtp(SmtpDissectorState::default());
            }
            DissectorState::Smtp(_) => {}
            _ => return None,
        }
        let DissectorState::Smtp(smtp) = state else {
            return None;
        };

        if smtp.buffer.len() + payload.len() > SMTP_LINE_MAX_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        smtp.buffer.extend_from_slice(payload);

        // 解析当前完整行，提取多命令元数据（MAIL FROM / RCPT TO）
        if smtp.buffer.contains(&b'\n')
            && let Some(cmd) = parse_smtp_command(&smtp.buffer)
            && let Some(addr) = extract_address_from_command(&cmd)
        {
            match cmd.command.as_str() {
                "MAIL" => smtp.sender = Some(addr),
                "RCPT" => smtp.recipient = Some(addr),
                _ => {}
            }
        }

        if let Some(mut result) = self.detect(&smtp.buffer) {
            // 注入累积的多命令元数据
            if let Metadata::Smtp(ref mut meta) = result.metadata {
                meta.sender = smtp.sender.clone();
                meta.recipient = smtp.recipient.clone();
            }
            smtp.buffer.clear();
            return Some(DissectorOutcome::Classified(result));
        }
        // 行已结束仍解析失败：放弃，回退无状态路径
        if smtp.buffer.contains(&b'\n') {
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
        if is_smtp_response_prefix(first_byte)
            && let Some(resp) = parse_smtp_response(payload)
        {
            let hostname = extract_hostname_from_banner(&resp.message);
            let metadata = Metadata::Smtp(SmtpMetadata {
                hostname,
                is_client: false,
                sender: None,
                recipient: None,
            });

            return Some(
                DetectionResult::new(Protocol::Smtp)
                    .with_metadata(metadata)
                    .with_confidence(Confidence::Dpi),
            );
        }

        // Path 2: Client command
        if is_smtp_command_prefix(first_byte)
            && let Some(cmd) = parse_smtp_command(payload)
        {
            let hostname = extract_hostname_from_command(&cmd);
            let metadata = Metadata::Smtp(SmtpMetadata {
                hostname,
                is_client: true,
                sender: None,
                recipient: None,
            });

            return Some(
                DetectionResult::new(Protocol::Smtp)
                    .with_metadata(metadata)
                    .with_confidence(Confidence::Dpi),
            );
        }

        None
    }
}

/// Extract hostname from SMTP banner message
fn extract_hostname_from_banner(message: &str) -> Option<String> {
    // Banner format: "hostname ESMTP ..."
    // Take the first word
    message.split_whitespace().next().map(|s| s.to_string())
}

/// Extract hostname from SMTP command
fn extract_hostname_from_command(cmd: &super::parser::SmtpCommand) -> Option<String> {
    match cmd.command.as_str() {
        "EHLO" | "HELO" => cmd.argument.clone(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_detector_new() {
        let detector = SmtpDetector::new();
        assert_eq!(detector.name(), "smtp");
    }

    #[test]
    fn test_detect_smtp_banner() {
        let detector = SmtpDetector::new();
        let data = b"220 mail.example.com ESMTP Postfix\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Smtp);
        assert_eq!(result.confidence, Confidence::Dpi);

        if let Metadata::Smtp(meta) = result.metadata {
            assert_eq!(meta.hostname, Some("mail.example.com".to_string()));
            assert!(!meta.is_client);
        } else {
            panic!("Expected Smtp metadata");
        }
    }

    #[test]
    fn test_detect_smtp_ehlo() {
        let detector = SmtpDetector::new();
        let data = b"EHLO client.example.com\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Smtp);

        if let Metadata::Smtp(meta) = result.metadata {
            assert_eq!(meta.hostname, Some("client.example.com".to_string()));
            assert!(meta.is_client);
        } else {
            panic!("Expected Smtp metadata");
        }
    }

    #[test]
    fn test_detect_smtp_quit() {
        let detector = SmtpDetector::new();
        let data = b"QUIT\r\n";
        let result = detector.detect(data).unwrap();
        assert_eq!(result.protocol, Protocol::Smtp);

        if let Metadata::Smtp(meta) = result.metadata {
            assert!(meta.hostname.is_none()); // QUIT has no hostname
            assert!(meta.is_client);
        } else {
            panic!("Expected Smtp metadata");
        }
    }

    #[test]
    fn test_detect_smtp_empty() {
        let detector = SmtpDetector::new();
        assert!(detector.detect(b"").is_none());
    }

    #[test]
    fn test_detect_smtp_invalid() {
        let detector = SmtpDetector::new();
        // Not an SMTP response or command
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
        assert!(detector.detect(b"random data\r\n").is_none());
    }

    #[test]
    fn test_extract_hostname_from_banner() {
        assert_eq!(
            extract_hostname_from_banner("mail.example.com ESMTP"),
            Some("mail.example.com".to_string())
        );
        assert_eq!(
            extract_hostname_from_banner("smtp.google.com ESMTP Google"),
            Some("smtp.google.com".to_string())
        );
        assert_eq!(extract_hostname_from_banner(""), None);
    }

    #[test]
    fn test_extract_hostname_from_command() {
        let ehlo_cmd = super::super::parser::SmtpCommand {
            command: "EHLO".to_string(),
            argument: Some("client.example.com".to_string()),
        };
        assert_eq!(
            extract_hostname_from_command(&ehlo_cmd),
            Some("client.example.com".to_string())
        );

        let mail_cmd = super::super::parser::SmtpCommand {
            command: "MAIL".to_string(),
            argument: Some("FROM:<test@example.com>".to_string()),
        };
        assert_eq!(extract_hostname_from_command(&mail_cmd), None);
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = SmtpDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = b"220 mail.example.com ESMTP Postfix\r\n";
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }

    // ---- 有状态跨段重组测试 ----
    #[test]
    fn test_stateful_banner_split_across_segments() {
        let detector = SmtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = DetectContext {
            src_port: 25,
            dst_port: 12345,
            is_http3_port: false,
        };
        // 第一段：banner 前半
        let r1 = detector.process(&mut state, b"220 mail.exa", Direction::Reverse, &ctx);
        assert!(matches!(r1, Some(DissectorOutcome::Continue)));
        // 第二段：banner 后半 + CRLF
        let r2 = detector.process(&mut state, b"mple.com ESMTP\r\n", Direction::Reverse, &ctx);
        match r2 {
            Some(DissectorOutcome::Classified(det)) => {
                assert_eq!(det.protocol, Protocol::Smtp);
            }
            other => panic!("expected Classified, got {:?}", other),
        }
    }

    #[test]
    fn test_stateful_mail_from_extraction() {
        let detector = SmtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = DetectContext {
            src_port: 25,
            dst_port: 12345,
            is_http3_port: false,
        };
        // 服务端先发 banner 定型，进入监测模式
        let _ = detector.process(
            &mut state,
            b"220 mail.example.com ESMTP\r\n",
            Direction::Reverse,
            &ctx,
        );
        // 客户端发 MAIL FROM
        let r = detector.process(
            &mut state,
            b"MAIL FROM:<sender@example.com>\r\n",
            Direction::Forward,
            &ctx,
        );
        match r {
            Some(DissectorOutcome::Classified(det)) => {
                if let Metadata::Smtp(meta) = det.metadata {
                    assert_eq!(meta.sender, Some("sender@example.com".to_string()));
                } else {
                    panic!("expected Smtp metadata");
                }
            }
            other => panic!("expected Classified, got {:?}", other),
        }
    }

    #[test]
    fn test_stateful_rcpt_to_extraction() {
        let detector = SmtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = DetectContext {
            src_port: 25,
            dst_port: 12345,
            is_http3_port: false,
        };
        let _ = detector.process(
            &mut state,
            b"220 mail.example.com ESMTP\r\n",
            Direction::Reverse,
            &ctx,
        );
        let _ = detector.process(
            &mut state,
            b"MAIL FROM:<a@b.com>\r\n",
            Direction::Forward,
            &ctx,
        );
        let r = detector.process(
            &mut state,
            b"RCPT TO:<rcpt@example.com>\r\n",
            Direction::Forward,
            &ctx,
        );
        match r {
            Some(DissectorOutcome::Classified(det)) => {
                if let Metadata::Smtp(meta) = det.metadata {
                    assert_eq!(meta.sender, Some("a@b.com".to_string()));
                    assert_eq!(meta.recipient, Some("rcpt@example.com".to_string()));
                } else {
                    panic!("expected Smtp metadata");
                }
            }
            other => panic!("expected Classified, got {:?}", other),
        }
    }

    #[test]
    fn test_stateful_non_smtp_gives_up() {
        let detector = SmtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = DetectContext {
            src_port: 12345,
            dst_port: 80,
            is_http3_port: false,
        };
        // GET 不是 SMTP 响应（非 2-5）也非命令（G 不在命令首字母集）
        let r = detector.process(&mut state, b"GET / HTTP/1.1\r\n", Direction::Forward, &ctx);
        assert!(r.is_none());
    }
}
