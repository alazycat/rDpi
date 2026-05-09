//! SMTP protocol parser for rDpi
//!
//! Parses SMTP server responses and client commands.

/// SMTP server response
#[derive(Debug, Clone)]
pub struct SmtpResponse {
    /// Response code (200-599)
    pub code: u16,
    /// Response message
    pub message: String,
}

/// SMTP client command
#[derive(Debug, Clone)]
pub struct SmtpCommand {
    /// Command name (EHLO, HELO, MAIL, etc.)
    pub command: String,
    /// Optional command argument
    pub argument: Option<String>,
}

/// Check if byte is SMTP response code prefix (2, 3, 4, 5)
pub fn is_smtp_response_prefix(byte: u8) -> bool {
    matches!(byte, b'2' | b'3' | b'4' | b'5')
}

/// Check if byte is SMTP command prefix
pub fn is_smtp_command_prefix(byte: u8) -> bool {
    matches!(
        byte,
        b'E' | b'H' | b'M' | b'R' | b'D' | b'Q' | b'S' | b'N' | b'V' | b'A' | b'O' | b'L'
    )
}

/// Parse SMTP server response
///
/// Format: <code> SP <message> CRLF
pub fn parse_smtp_response(data: &[u8]) -> Option<SmtpResponse> {
    // Minimum: "220 x\r\n" = 7 bytes
    if data.len() < 7 {
        return None;
    }

    // Find end of line
    let line_end = find_line_end(data)?;
    let line = std::str::from_utf8(&data[..line_end]).ok()?;

    // Parse code (3 digits)
    if line.len() < 4 {
        return None;
    }

    // Code must be 3 digits followed by space or dash
    let code_str = &line[..3];
    let code: u16 = code_str.parse().ok()?;

    // Validate code range
    if code < 200 || code > 599 {
        return None;
    }

    // Check separator (space or dash for multi-line)
    if line.len() > 3 && line.as_bytes()[3] != b' ' && line.as_bytes()[3] != b'-' {
        return None;
    }

    // Extract message (after "code ")
    let message = if line.len() > 4 && line.as_bytes()[3] == b' ' {
        line[4..].to_string()
    } else {
        String::new()
    };

    Some(SmtpResponse { code, message })
}

/// Parse SMTP client command
///
/// Format: <COMMAND> [SP <argument>] CRLF
pub fn parse_smtp_command(data: &[u8]) -> Option<SmtpCommand> {
    // Minimum: "QUIT\r\n" = 6 bytes
    if data.len() < 6 {
        return None;
    }

    // Find end of line
    let line_end = find_line_end(data)?;
    let line = std::str::from_utf8(&data[..line_end]).ok()?;

    // Split on space
    let parts: Vec<&str> = line.splitn(2, ' ').collect();
    if parts.is_empty() {
        return None;
    }

    let command = parts[0].to_uppercase();

    // Validate command
    let valid_commands = [
        "EHLO", "HELO", "MAIL", "RCPT", "DATA", "QUIT",
        "RSET", "VRFY", "NOOP", "STARTTLS", "AUTH", "HELP", "EXPN"
    ];

    if !valid_commands.contains(&command.as_str()) {
        return None;
    }

    let argument = if parts.len() > 1 {
        Some(parts[1].to_string())
    } else {
        None
    };

    Some(SmtpCommand { command, argument })
}

/// Find line end position (before \r\n or \n)
fn find_line_end(data: &[u8]) -> Option<usize> {
    for (i, &byte) in data.iter().enumerate() {
        if byte == b'\n' {
            if i > 0 && data[i - 1] == b'\r' {
                return Some(i - 1);
            }
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_smtp_response_prefix() {
        assert!(is_smtp_response_prefix(b'2'));
        assert!(is_smtp_response_prefix(b'3'));
        assert!(is_smtp_response_prefix(b'4'));
        assert!(is_smtp_response_prefix(b'5'));
        assert!(!is_smtp_response_prefix(b'1'));
        assert!(!is_smtp_response_prefix(b'6'));
    }

    #[test]
    fn test_is_smtp_command_prefix() {
        assert!(is_smtp_command_prefix(b'E')); // EHLO, EXPN
        assert!(is_smtp_command_prefix(b'H')); // HELO, HELP
        assert!(is_smtp_command_prefix(b'M')); // MAIL
        assert!(is_smtp_command_prefix(b'R')); // RCPT, RSET
        assert!(is_smtp_command_prefix(b'Q')); // QUIT
        assert!(is_smtp_command_prefix(b'S')); // STARTTLS
        assert!(is_smtp_command_prefix(b'A')); // AUTH
        assert!(is_smtp_command_prefix(b'N')); // NOOP
        assert!(is_smtp_command_prefix(b'V')); // VRFY
        assert!(is_smtp_command_prefix(b'D')); // DATA
        assert!(is_smtp_command_prefix(b'O')); // obsolete commands
        assert!(is_smtp_command_prefix(b'L')); // LHELO (rare)
        assert!(!is_smtp_command_prefix(b'X'));
        assert!(!is_smtp_command_prefix(b'Z'));
    }

    #[test]
    fn test_parse_smtp_response_banner() {
        let data = b"220 mail.example.com ESMTP\r\n";
        let resp = parse_smtp_response(data).unwrap();
        assert_eq!(resp.code, 220);
        assert_eq!(resp.message, "mail.example.com ESMTP");
    }

    #[test]
    fn test_parse_smtp_response_ok() {
        let data = b"250 OK\r\n";
        let resp = parse_smtp_response(data).unwrap();
        assert_eq!(resp.code, 250);
        assert_eq!(resp.message, "OK");
    }

    #[test]
    fn test_parse_smtp_response_multiline() {
        // Multi-line response with dash separator
        let data = b"250-mail.example.com\r\n";
        let resp = parse_smtp_response(data).unwrap();
        assert_eq!(resp.code, 250);
        assert_eq!(resp.message, ""); // Dash separator, no message extracted
    }

    #[test]
    fn test_parse_smtp_response_too_short() {
        assert!(parse_smtp_response(b"220\r\n").is_none());
        assert!(parse_smtp_response(b"220\n").is_none());
        assert!(parse_smtp_response(b"abc\r\n").is_none());
    }

    #[test]
    fn test_parse_smtp_response_invalid_code() {
        assert!(parse_smtp_response(b"100 OK\r\n").is_none()); // Too low
        assert!(parse_smtp_response(b"600 OK\r\n").is_none()); // Too high
        assert!(parse_smtp_response(b"abc OK\r\n").is_none()); // Not digits
    }

    #[test]
    fn test_parse_smtp_command_ehlo() {
        let data = b"EHLO client.example.com\r\n";
        let cmd = parse_smtp_command(data).unwrap();
        assert_eq!(cmd.command, "EHLO");
        assert_eq!(cmd.argument, Some("client.example.com".to_string()));
    }

    #[test]
    fn test_parse_smtp_command_helo() {
        let data = b"HELO client.example.com\r\n";
        let cmd = parse_smtp_command(data).unwrap();
        assert_eq!(cmd.command, "HELO");
        assert_eq!(cmd.argument, Some("client.example.com".to_string()));
    }

    #[test]
    fn test_parse_smtp_command_mail() {
        let data = b"MAIL FROM:<sender@example.com>\r\n";
        let cmd = parse_smtp_command(data).unwrap();
        assert_eq!(cmd.command, "MAIL");
        assert_eq!(cmd.argument, Some("FROM:<sender@example.com>".to_string()));
    }

    #[test]
    fn test_parse_smtp_command_quit() {
        let data = b"QUIT\r\n";
        let cmd = parse_smtp_command(data).unwrap();
        assert_eq!(cmd.command, "QUIT");
        assert_eq!(cmd.argument, None);
    }

    #[test]
    fn test_parse_smtp_command_starttls() {
        let data = b"STARTTLS\r\n";
        let cmd = parse_smtp_command(data).unwrap();
        assert_eq!(cmd.command, "STARTTLS");
        assert_eq!(cmd.argument, None);
    }

    #[test]
    fn test_parse_smtp_command_case_insensitive() {
        let data = b"ehlo client.example.com\r\n";
        let cmd = parse_smtp_command(data).unwrap();
        assert_eq!(cmd.command, "EHLO");
    }

    #[test]
    fn test_parse_smtp_command_invalid() {
        assert!(parse_smtp_command(b"INVALID arg\r\n").is_none());
        assert!(parse_smtp_command(b"FOO\r\n").is_none());
    }

    #[test]
    fn test_parse_smtp_command_too_short() {
        assert!(parse_smtp_command(b"QUIT\r").is_none());
        assert!(parse_smtp_command(b"QUIT").is_none());
    }

    #[test]
    fn test_find_line_end_crlf() {
        assert_eq!(find_line_end(b"hello\r\n"), Some(5));
        assert_eq!(find_line_end(b"test\r\nmore"), Some(4));
    }

    #[test]
    fn test_find_line_end_lf() {
        assert_eq!(find_line_end(b"hello\n"), Some(5));
        assert_eq!(find_line_end(b"test\nmore"), Some(4));
    }

    #[test]
    fn test_find_line_end_no_terminator() {
        assert!(find_line_end(b"hello").is_none());
    }
}