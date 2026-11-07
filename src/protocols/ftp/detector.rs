//! FTP protocol detector for rDpi
//!
//! Detects FTP traffic by recognising server responses (three-digit code)
//! and client commands (known FTP verbs).

use crate::core::types::*;
use crate::protocols::ProtocolDetector;

use super::parser::{
    complete_line_end, is_ftp_command_prefix, is_ftp_response_prefix, parse_ftp_command,
    parse_ftp_response,
};

/// FTP 与 POP3 共有的命令动词——仅凭 payload 无法区分（F8，risks.md）。
/// 当这类命令出现在 POP3 端口（110/995）上时，detect_with_context 让位给 Pop3Detector。
const FTP_POP3_AMBIGUOUS_VERBS: &[&str] = &[
    "USER", "PASS", "QUIT", "RETR", "DELE", "STAT", "NOOP", "LIST",
];

fn is_pop3_port(port: u16) -> bool {
    port == 110 || port == 995
}

/// SMTP 服务端口——`220 ...` 数字问候码为 FTP 与 SMTP 共有语法（F10，risks.md）。
/// 这类响应出现在 SMTP 端口上时，detect_with_context 让位给 SmtpDetector。
fn is_smtp_port(port: u16) -> bool {
    port == 25 || port == 465 || port == 587
}

/// FTP 行缓冲上限（RFC 959 命令/响应 ≤ 512 字节，留足余量）
const FTP_LINE_MAX_BYTES: usize = 4096;

/// 判断首字节是否可能为 FTP 数字响应（200–600）
fn is_ftp_response_start(byte: u8) -> bool {
    (b'2'..=b'6').contains(&byte)
}

/// FTP protocol detector
pub struct FtpDetector;

impl Default for FtpDetector {
    fn default() -> Self {
        Self
    }
}

impl FtpDetector {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolDetector for FtpDetector {
    fn name(&self) -> &'static str {
        "ftp"
    }

    /// 首字节门：FTP 数字响应（0x30-0x39）与大写命令动词（0x41-0x5A）。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x30u8, 0x39u8), (0x41u8, 0x5Au8)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if payload.is_empty() {
            return None;
        }

        let first = payload[0];

        // Path 1: Server response — starts with digit + space separator
        if first.is_ascii_digit()
            && is_ftp_response_prefix(payload)
            && let Some(resp) = parse_ftp_response(payload)
        {
            let meta = Metadata::Ftp(FtpMetadata {
                is_client: false,
                verb: None,
                argument: None,
                response_code: Some(resp.code),
                username: None,
                filename: None,
            });
            return Some(DetectionResult::new(Protocol::Ftp).with_metadata(meta));
        }

        // Path 2: Client command — uppercase letter prefix
        if first.is_ascii_uppercase()
            && is_ftp_command_prefix(payload)
            && let Some(cmd) = parse_ftp_command(payload)
        {
            let meta = Metadata::Ftp(FtpMetadata {
                is_client: true,
                verb: Some(cmd.verb),
                argument: cmd.argument,
                response_code: None,
                username: None,
                filename: None,
            });
            return Some(DetectionResult::new(Protocol::Ftp).with_metadata(meta));
        }

        None
    }

    /// 带端口上下文的检测（F8 修复）：
    /// FTP/POP3 共有命令出现在 POP3 端口上时让位，交由注册顺序在后的 Pop3Detector 判定。
    /// FTP 独有命令（PORT/PASV/TYPE/STOR/CWD 等）不受端口影响，维持原判定。
    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        let result = self.detect(payload)?;

        if let Metadata::Ftp(ref meta) = result.metadata {
            if meta.is_client {
                if let Some(ref verb) = meta.verb
                    && FTP_POP3_AMBIGUOUS_VERBS.contains(&verb.as_str())
                    && (is_pop3_port(ctx.src_port) || is_pop3_port(ctx.dst_port))
                {
                    return None;
                }
            } else if meta.response_code.is_some()
                && (is_smtp_port(ctx.src_port) || is_smtp_port(ctx.dst_port))
            {
                // F10: 数字响应（如 `220 mail.example.com ESMTP`）与 SMTP banner 共有语法，
                // SMTP 端口上让位，交由注册顺序在后的 SmtpDetector 判定。
                return None;
            }
        }

        Some(result)
    }

    /// 有状态逐包处理：FTP 命令/响应行可能跨 TCP 段
    ///
    /// 仅服务端数字响应前缀（2–6）且非 SMTP 端口时接管；FTP 为 server-first
    /// 协议，正常抓包从 banner 开始。接管后进入 monitoring，后续 USER /
    /// RETR / STOR 命令持续富化 username/filename。
    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        _direction: Direction,
        ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        let was_none = matches!(state, DissectorState::None);
        match state {
            DissectorState::None => {
                if payload.is_empty()
                    || !is_ftp_response_start(payload[0])
                    || is_smtp_port(ctx.src_port)
                    || is_smtp_port(ctx.dst_port)
                {
                    return None;
                }
                *state = DissectorState::Ftp(FtpDissectorState::default());
            }
            DissectorState::Ftp(_) => {}
            _ => return None,
        }
        let DissectorState::Ftp(ftp) = state else {
            return None;
        };

        if ftp.buffer.len() + payload.len() > FTP_LINE_MAX_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        ftp.buffer.extend_from_slice(payload);

        let pending = std::mem::take(&mut ftp.buffer);
        let mut start = 0;
        let mut first_complete_line = was_none;
        let mut last_metadata = None;

        while let Some(end_rel) = complete_line_end(&pending[start..]) {
            let end = start + end_rel;
            let line = &pending[start..end];
            start = end;

            match self.detect(line) {
                Some(result) => {
                    if let Metadata::Ftp(ref meta) = result.metadata
                        && meta.is_client
                    {
                        match meta.verb.as_deref() {
                            Some("USER") => {
                                if ftp.username.is_none() {
                                    ftp.username = meta.argument.clone();
                                }
                            }
                            Some("RETR" | "STOR") => {
                                if ftp.filename.is_none() {
                                    ftp.filename = meta.argument.clone();
                                }
                            }
                            _ => {}
                        }
                    }
                    let mut metadata = match result.metadata {
                        Metadata::Ftp(meta) => meta,
                        _ => unreachable!("FTP detector always returns Ftp metadata"),
                    };
                    metadata.username = ftp.username.clone();
                    metadata.filename = ftp.filename.clone();
                    last_metadata = Some(metadata);
                }
                None => {
                    if first_complete_line {
                        return Some(DissectorOutcome::GiveUp);
                    }
                }
            }
            first_complete_line = false;
        }

        ftp.buffer.extend_from_slice(&pending[start..]);

        last_metadata
            .map(|metadata| {
                DissectorOutcome::Classified(
                    DetectionResult::new(Protocol::Ftp).with_metadata(Metadata::Ftp(metadata)),
                )
            })
            .or(Some(DissectorOutcome::Continue))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ftp_banner() {
        let detector = FtpDetector::new();
        let result = detector.detect(b"220 FTP server ready\r\n").unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
    }

    #[test]
    fn test_detect_ftp_command() {
        let detector = FtpDetector::new();
        let result = detector.detect(b"USER anonymous\r\n").unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
    }

    #[test]
    fn test_detect_ftp_empty() {
        let detector = FtpDetector::new();
        assert!(detector.detect(b"").is_none());
    }

    #[test]
    fn test_detect_ftp_non_ftp() {
        let detector = FtpDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn test_detect_ftp_response_with_metadata() {
        let detector = FtpDetector::new();
        let result = detector
            .detect(b"331 Password required for user\r\n")
            .unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
        if let Metadata::Ftp(ref meta) = result.metadata {
            assert!(!meta.is_client);
            assert_eq!(meta.response_code, Some(331));
        } else {
            panic!("expected Ftp metadata");
        }
    }

    #[test]
    fn test_detect_ftp_command_with_metadata() {
        let detector = FtpDetector::new();
        let result = detector.detect(b"RETR report.pdf\r\n").unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
        if let Metadata::Ftp(ref meta) = result.metadata {
            assert!(meta.is_client);
            assert_eq!(meta.verb, Some("RETR".to_string()));
            assert_eq!(meta.argument, Some("report.pdf".to_string()));
        } else {
            panic!("expected Ftp metadata");
        }
    }

    // ---- F8: FTP/POP3 歧义命令的端口上下文让位 ----

    fn ctx_with(src_port: u16, dst_port: u16) -> DetectContext {
        DetectContext {
            src_port,
            dst_port,
            is_http3_port: false,
        }
    }

    #[test]
    fn test_f8_ambiguous_command_yields_on_pop3_port() {
        let detector = FtpDetector::new();
        // USER/PASS/RETR/QUIT 在 POP3 端口（110/995）上必须让位
        for payload in [
            &b"USER test@example.com\r\n"[..],
            b"PASS secret\r\n",
            b"RETR mail.txt\r\n",
            b"QUIT\r\n",
        ] {
            assert!(
                detector
                    .detect_with_context(payload, &ctx_with(12345, 110))
                    .is_none(),
                "ambiguous command must yield on POP3 dst port: {:?}",
                String::from_utf8_lossy(payload)
            );
            assert!(
                detector
                    .detect_with_context(payload, &ctx_with(110, 12345))
                    .is_none(),
                "ambiguous command must yield on POP3 src port"
            );
            assert!(
                detector
                    .detect_with_context(payload, &ctx_with(12345, 995))
                    .is_none(),
                "ambiguous command must yield on POP3S port"
            );
        }
    }

    #[test]
    fn test_f8_ambiguous_command_kept_on_ftp_port() {
        let detector = FtpDetector::new();
        // FTP 端口（21）上同样的命令仍是 FTP（防止修复矫枉过正）
        let result = detector
            .detect_with_context(b"USER anonymous\r\n", &ctx_with(12345, 21))
            .unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
    }

    #[test]
    fn test_f8_ftp_only_command_ignores_pop3_port() {
        let detector = FtpDetector::new();
        // FTP 独有命令不受 POP3 端口影响
        let result = detector
            .detect_with_context(b"PORT 192,168,1,1,10,20\r\n", &ctx_with(12345, 110))
            .unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
    }

    #[test]
    fn test_f8_ambiguous_command_default_stays_ftp_without_context() {
        let detector = FtpDetector::new();
        // 无端口上下文的 detect() 保持现状：歧义命令默认 FTP（注册顺序语义，R11）
        let result = detector.detect(b"USER test@example.com\r\n").unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
    }

    // ---- F10: 数字响应在 SMTP 端口上让位 ----

    #[test]
    fn test_f10_numeric_response_yields_on_smtp_port() {
        let detector = FtpDetector::new();
        // `220 mail.example.com ESMTP` 是 SMTP banner 与 FTP greeting 的共有语法
        let payload = &b"220 mail.example.com ESMTP\r\n"[..];
        assert!(
            detector
                .detect_with_context(payload, &ctx_with(25, 12345))
                .is_none(),
            "numeric response must yield on SMTP src port"
        );
        assert!(
            detector
                .detect_with_context(payload, &ctx_with(12345, 25))
                .is_none(),
            "numeric response must yield on SMTP dst port"
        );
        assert!(
            detector
                .detect_with_context(payload, &ctx_with(12345, 465))
                .is_none(),
            "numeric response must yield on SMTPS port"
        );
        assert!(
            detector
                .detect_with_context(payload, &ctx_with(12345, 587))
                .is_none(),
            "numeric response must yield on submission port"
        );
    }

    #[test]
    fn test_f10_numeric_response_kept_on_ftp_port() {
        let detector = FtpDetector::new();
        // FTP 端口（21）上同样的数字响应仍是 FTP（防止修复矫枉过正）
        let result = detector
            .detect_with_context(b"220 FTP server ready\r\n", &ctx_with(21, 12345))
            .unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
    }

    #[test]
    fn test_f10_numeric_response_default_stays_ftp_without_context() {
        let detector = FtpDetector::new();
        // 无端口上下文的 detect() 保持现状：数字响应默认 FTP（注册顺序语义，R11）
        let result = detector.detect(b"220 mail.example.com ESMTP\r\n").unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = FtpDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = b"220 FTP server ready\r\n";
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }

    // ---- F44: FTP 有状态会话 ----

    #[test]
    fn test_process_reassembles_split_banner() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(50000, 21);

        let first = detector
            .process(&mut state, b"220 FTP ser", Direction::Reverse, &ctx)
            .unwrap();
        assert!(matches!(first, DissectorOutcome::Continue));

        let second = detector
            .process(&mut state, b"ver ready\r\n", Direction::Reverse, &ctx)
            .unwrap();
        match second {
            DissectorOutcome::Classified(result) => {
                assert_eq!(result.protocol, Protocol::Ftp);
            }
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn test_process_extracts_username_across_segments() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(50000, 21);

        detector
            .process(&mut state, b"220 FTP ready\r\n", Direction::Reverse, &ctx)
            .unwrap();
        detector
            .process(&mut state, b"US", Direction::Forward, &ctx)
            .unwrap();
        let result = detector
            .process(&mut state, b"ER alice\r\n", Direction::Forward, &ctx)
            .unwrap();

        match result {
            DissectorOutcome::Classified(result) => match result.metadata {
                Metadata::Ftp(meta) => {
                    assert_eq!(meta.username.as_deref(), Some("alice"));
                }
                other => panic!("expected Ftp metadata, got {other:?}"),
            },
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn test_process_extracts_filename_for_retr_and_stor() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(50000, 21);
        detector
            .process(&mut state, b"220 FTP ready\r\n", Direction::Reverse, &ctx)
            .unwrap();

        let result = detector
            .process(&mut state, b"RETR report.pdf\r\n", Direction::Forward, &ctx)
            .unwrap();
        match result {
            DissectorOutcome::Classified(result) => match result.metadata {
                Metadata::Ftp(meta) => assert_eq!(meta.filename.as_deref(), Some("report.pdf")),
                other => panic!("expected Ftp metadata, got {other:?}"),
            },
            other => panic!("expected Classified, got {other:?}"),
        }

        let result = detector
            .process(&mut state, b"STOR upload.bin\r\n", Direction::Forward, &ctx)
            .unwrap();
        match result {
            DissectorOutcome::Classified(result) => match result.metadata {
                Metadata::Ftp(meta) => assert_eq!(meta.filename.as_deref(), Some("report.pdf")),
                other => panic!("expected Ftp metadata, got {other:?}"),
            },
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn test_process_multiple_commands_in_one_segment() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(50000, 21);
        detector
            .process(&mut state, b"220 FTP ready\r\n", Direction::Reverse, &ctx)
            .unwrap();

        let result = detector
            .process(
                &mut state,
                b"USER bob\r\nRETR notes.txt\r\n",
                Direction::Forward,
                &ctx,
            )
            .unwrap();
        match result {
            DissectorOutcome::Classified(result) => match result.metadata {
                Metadata::Ftp(meta) => {
                    assert_eq!(meta.username.as_deref(), Some("bob"));
                    assert_eq!(meta.filename.as_deref(), Some("notes.txt"));
                }
                other => panic!("expected Ftp metadata, got {other:?}"),
            },
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn test_process_does_not_take_over_on_smtp_port() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(12345, 25);
        assert!(
            detector
                .process(
                    &mut state,
                    b"220 mail.example.com ESMTP\r\n",
                    Direction::Reverse,
                    &ctx
                )
                .is_none()
        );
        assert_eq!(state, DissectorState::None);
    }

    #[test]
    fn test_process_gives_up_when_first_line_is_not_ftp() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(12345, 21);
        let outcome = detector
            .process(&mut state, b"6xx not-an-ftp-line\r\n", Direction::Reverse, &ctx)
            .unwrap();
        assert!(matches!(outcome, DissectorOutcome::GiveUp));
    }

    #[test]
    fn test_process_buffer_overflow_gives_up() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(12345, 21);
        let payload = vec![b'2'; FTP_LINE_MAX_BYTES + 1];
        let outcome = detector
            .process(&mut state, &payload, Direction::Reverse, &ctx)
            .unwrap();
        assert!(matches!(outcome, DissectorOutcome::GiveUp));
    }
}
