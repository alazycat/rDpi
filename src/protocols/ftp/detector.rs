//! FTP protocol detector for rDpi
//!
//! Detects FTP traffic by recognising server responses (three-digit code)
//! and client commands (known FTP verbs).

use crate::core::types::*;
use crate::protocols::ProtocolDetector;

use super::parser::{
    is_ftp_command_prefix, is_ftp_response_prefix, parse_ftp_command, parse_ftp_response,
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

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if payload.is_empty() {
            return None;
        }

        let first = payload[0];

        // Path 1: Server response — starts with digit + space separator
        if first.is_ascii_digit() && is_ftp_response_prefix(payload) {
            if let Some(resp) = parse_ftp_response(payload) {
                let meta = Metadata::Ftp(FtpMetadata {
                    is_client: false,
                    verb: None,
                    argument: None,
                    response_code: Some(resp.code),
                });
                return Some(DetectionResult::new(Protocol::Ftp).with_metadata(meta));
            }
        }

        // Path 2: Client command — uppercase letter prefix
        if first.is_ascii_uppercase() && is_ftp_command_prefix(payload) {
            if let Some(cmd) = parse_ftp_command(payload) {
                let meta = Metadata::Ftp(FtpMetadata {
                    is_client: true,
                    verb: Some(cmd.verb),
                    argument: cmd.argument,
                    response_code: None,
                });
                return Some(DetectionResult::new(Protocol::Ftp).with_metadata(meta));
            }
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
                if let Some(ref verb) = meta.verb {
                    if FTP_POP3_AMBIGUOUS_VERBS.contains(&verb.as_str())
                        && (is_pop3_port(ctx.src_port) || is_pop3_port(ctx.dst_port))
                    {
                        return None;
                    }
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
}
