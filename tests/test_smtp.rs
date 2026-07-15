#![cfg(feature = "smtp")]

use rdpi::protocols::smtp::{
    is_smtp_command_prefix, is_smtp_response_prefix, parse_smtp_command, parse_smtp_response,
};

#[test]
fn test_is_smtp_response_prefix() {
    assert!(is_smtp_response_prefix(b'2')); // 220, 250, etc.
    assert!(is_smtp_response_prefix(b'3')); // 354
    assert!(is_smtp_response_prefix(b'4')); // 4xx
    assert!(is_smtp_response_prefix(b'5')); // 5xx
    assert!(!is_smtp_response_prefix(b'1'));
    assert!(!is_smtp_response_prefix(b'E')); // EHLO
}

#[test]
fn test_is_smtp_command_prefix() {
    assert!(is_smtp_command_prefix(b'E')); // EHLO
    assert!(is_smtp_command_prefix(b'H')); // HELO
    assert!(is_smtp_command_prefix(b'M')); // MAIL
    assert!(is_smtp_command_prefix(b'R')); // RCPT, RSET
    assert!(is_smtp_command_prefix(b'D')); // DATA
    assert!(is_smtp_command_prefix(b'Q')); // QUIT
    assert!(is_smtp_command_prefix(b'S')); // STARTTLS
    assert!(is_smtp_command_prefix(b'N')); // NOOP
    assert!(is_smtp_command_prefix(b'V')); // VRFY
    assert!(!is_smtp_command_prefix(b'2'));
}

#[test]
fn test_parse_smtp_response_postfix() {
    let data = b"220 mail.example.com ESMTP Postfix\r\n";
    let result = parse_smtp_response(data);
    assert!(result.is_some());

    let resp = result.unwrap();
    assert_eq!(resp.code, 220);
    assert_eq!(resp.message, "mail.example.com ESMTP Postfix");
}

#[test]
fn test_parse_smtp_response_gmail() {
    let data = b"220 smtp.gmail.com ESMTP\r\n";
    let result = parse_smtp_response(data);
    assert!(result.is_some());

    let resp = result.unwrap();
    assert_eq!(resp.code, 220);
    assert_eq!(resp.message, "smtp.gmail.com ESMTP");
}

#[test]
fn test_parse_smtp_response_ok() {
    let data = b"250 OK\r\n";
    let result = parse_smtp_response(data);
    assert!(result.is_some());

    let resp = result.unwrap();
    assert_eq!(resp.code, 250);
    assert_eq!(resp.message, "OK");
}

#[test]
fn test_parse_smtp_response_error() {
    let data = b"550 User not found\r\n";
    let result = parse_smtp_response(data);
    assert!(result.is_some());

    let resp = result.unwrap();
    assert_eq!(resp.code, 550);
    assert_eq!(resp.message, "User not found");
}

#[test]
fn test_parse_smtp_response_invalid_code() {
    let data = b"220XYZ message\r\n";
    let result = parse_smtp_response(data);
    assert!(result.is_none());
}

#[test]
fn test_parse_smtp_response_code_out_of_range() {
    let data = b"600 Invalid\r\n";
    let result = parse_smtp_response(data);
    assert!(result.is_none());
}

#[test]
fn test_parse_smtp_command_ehlo() {
    let data = b"EHLO client.example.com\r\n";
    let result = parse_smtp_command(data);
    assert!(result.is_some());

    let cmd = result.unwrap();
    assert_eq!(cmd.command, "EHLO");
    assert_eq!(cmd.argument, Some("client.example.com".to_string()));
}

#[test]
fn test_parse_smtp_command_helo() {
    let data = b"HELO client.local\r\n";
    let result = parse_smtp_command(data);
    assert!(result.is_some());

    let cmd = result.unwrap();
    assert_eq!(cmd.command, "HELO");
    assert_eq!(cmd.argument, Some("client.local".to_string()));
}

#[test]
fn test_parse_smtp_command_mail() {
    let data = b"MAIL FROM:<user@example.com>\r\n";
    let result = parse_smtp_command(data);
    assert!(result.is_some());

    let cmd = result.unwrap();
    assert_eq!(cmd.command, "MAIL");
    assert_eq!(cmd.argument, Some("FROM:<user@example.com>".to_string()));
}

#[test]
fn test_parse_smtp_command_rcpt() {
    let data = b"RCPT TO:<user@example.com>\r\n";
    let result = parse_smtp_command(data);
    assert!(result.is_some());

    let cmd = result.unwrap();
    assert_eq!(cmd.command, "RCPT");
    assert_eq!(cmd.argument, Some("TO:<user@example.com>".to_string()));
}

#[test]
fn test_parse_smtp_command_quit() {
    let data = b"QUIT\r\n";
    let result = parse_smtp_command(data);
    assert!(result.is_some());

    let cmd = result.unwrap();
    assert_eq!(cmd.command, "QUIT");
    assert!(cmd.argument.is_none());
}

#[test]
fn test_parse_smtp_command_data() {
    let data = b"DATA\r\n";
    let result = parse_smtp_command(data);
    assert!(result.is_some());

    let cmd = result.unwrap();
    assert_eq!(cmd.command, "DATA");
    assert!(cmd.argument.is_none());
}

#[test]
fn test_parse_smtp_command_no_newline() {
    let data = b"EHLO client.example.com";
    let result = parse_smtp_command(data);
    assert!(result.is_none());
}

#[test]
fn test_parse_smtp_command_empty() {
    let data = b"";
    let result = parse_smtp_command(data);
    assert!(result.is_none());
}

// ============================================================================
// SMTP Detector Tests
// ============================================================================

use rdpi::core::types::{Confidence, Metadata, Protocol};
use rdpi::protocols::ProtocolDetector;
use rdpi::protocols::smtp::SmtpDetector;

#[test]
fn test_smtp_detector_postfix_banner() {
    let detector = SmtpDetector::new();
    let data = b"220 mail.example.com ESMTP Postfix\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Smtp);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Smtp(meta) = detection.metadata {
        assert_eq!(meta.hostname, Some("mail.example.com".to_string()));
        assert!(!meta.is_client);
    } else {
        panic!("Expected Smtp metadata");
    }
}

#[test]
fn test_smtp_detector_gmail_banner() {
    let detector = SmtpDetector::new();
    let data = b"220 smtp.gmail.com ESMTP\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Smtp);

    if let Metadata::Smtp(meta) = detection.metadata {
        assert_eq!(meta.hostname, Some("smtp.gmail.com".to_string()));
        assert!(!meta.is_client);
    } else {
        panic!("Expected Smtp metadata");
    }
}

#[test]
fn test_smtp_detector_exchange_banner() {
    let detector = SmtpDetector::new();
    let data = b"220 mx1.example.org Microsoft ESMTP MAIL\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    if let Metadata::Smtp(meta) = result.unwrap().metadata {
        assert_eq!(meta.hostname, Some("mx1.example.org".to_string()));
    } else {
        panic!("Expected Smtp metadata");
    }
}

#[test]
fn test_smtp_detector_ehlo_command() {
    let detector = SmtpDetector::new();
    let data = b"EHLO client.example.com\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Smtp);

    if let Metadata::Smtp(meta) = detection.metadata {
        assert_eq!(meta.hostname, Some("client.example.com".to_string()));
        assert!(meta.is_client);
    } else {
        panic!("Expected Smtp metadata");
    }
}

#[test]
fn test_smtp_detector_helo_command() {
    let detector = SmtpDetector::new();
    let data = b"HELO client.local\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    if let Metadata::Smtp(meta) = result.unwrap().metadata {
        assert_eq!(meta.hostname, Some("client.local".to_string()));
        assert!(meta.is_client);
    } else {
        panic!("Expected Smtp metadata");
    }
}

#[test]
fn test_smtp_detector_mail_command() {
    let detector = SmtpDetector::new();
    let data = b"MAIL FROM:<user@example.com>\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    if let Metadata::Smtp(meta) = result.unwrap().metadata {
        // MAIL command doesn't have hostname in argument
        assert!(meta.hostname.is_none());
        assert!(meta.is_client);
    } else {
        panic!("Expected Smtp metadata");
    }
}

#[test]
fn test_smtp_detector_quit_command() {
    let detector = SmtpDetector::new();
    let data = b"QUIT\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    if let Metadata::Smtp(meta) = result.unwrap().metadata {
        assert!(meta.is_client);
    } else {
        panic!("Expected Smtp metadata");
    }
}

#[test]
fn test_smtp_detector_non_smtp() {
    let detector = SmtpDetector::new();

    let test_cases = vec![
        b"GET / HTTP/1.1\r\n".as_slice(),
        b"SSH-2.0-OpenSSH_8.9\r\n".as_slice(),
        b"\x16\x03\x03".as_slice(), // TLS
        b"".as_slice(),
    ];

    for data in test_cases {
        let result = detector.detect(data);
        assert!(
            result.is_none(),
            "Should not detect SMTP in: {:?}",
            std::str::from_utf8(data)
        );
    }
}

#[test]
fn test_smtp_detector_empty_payload() {
    let detector = SmtpDetector::new();
    let result = detector.detect(b"");
    assert!(result.is_none());
}

#[test]
fn test_smtp_detector_banner_without_hostname() {
    let detector = SmtpDetector::new();
    let data = b"220 ESMTP ready\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    if let Metadata::Smtp(meta) = result.unwrap().metadata {
        assert_eq!(meta.hostname, Some("ESMTP".to_string()));
    }
}

#[test]
fn test_smtp_detector_various_response_codes() {
    let detector = SmtpDetector::new();

    let test_cases: Vec<(u16, &[u8])> = vec![
        (220, b"220 service ready\r\n"),
        (250, b"250 OK\r\n"),
        (354, b"354 Start mail input\r\n"),
        (421, b"421 Service not available\r\n"),
        (450, b"450 Mailbox busy\r\n"),
        (550, b"550 User not found\r\n"),
    ];

    for (expected_code, data) in test_cases {
        let result = detector.detect(data);
        assert!(
            result.is_some(),
            "Should detect SMTP for code {}",
            expected_code
        );
    }
}
