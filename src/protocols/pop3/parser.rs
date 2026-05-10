//! POP3 protocol parser for rDpi
//!
//! Parses POP3 server responses and client commands.

/// POP3 server response
#[derive(Debug, Clone)]
pub struct Pop3Response {
    /// Response status: true for +OK, false for -ERR
    pub success: bool,
    /// Response message
    pub message: Option<String>,
}

/// POP3 client command
#[derive(Debug, Clone)]
pub struct Pop3Command {
    /// Command name (USER, PASS, STAT, etc.)
    pub command: String,
    /// Optional command argument
    pub argument: Option<String>,
}

/// Check if byte is POP3 response prefix ('+' or '-')
pub fn is_pop3_response_prefix(byte: u8) -> bool {
    byte == b'+' || byte == b'-'
}

/// Check if byte is POP3 command prefix
pub fn is_pop3_command_prefix(byte: u8) -> bool {
    matches!(
        byte,
        b'U' | b'P' | b'S' | b'L' | b'R' | b'D' | b'Q' | b'N' | b'T' | b'A' | b'C' | b'W' | b'H' | b'K'
    )
}

/// Parse POP3 server response
///
/// Format: +OK [message] or -ERR [message]
pub fn parse_pop3_response(data: &[u8]) -> Option<Pop3Response> {
    // Minimum: "+OK\r\n" = 5 bytes
    if data.len() < 5 {
        return None;
    }

    // Check prefix
    let first_byte = data[0];
    if first_byte != b'+' && first_byte != b'-' {
        return None;
    }

    // Find line end
    let line_end = find_line_end(data)?;
    let line = std::str::from_utf8(&data[..line_end]).ok()?;

    // Parse status
    let success = if line.starts_with("+OK") {
        true
    } else if line.starts_with("-ERR") {
        false
    } else {
        return None;
    };

    // Extract message
    let message = if success {
        if line.len() > 3 {
            let msg = line[3..].trim_start();
            if msg.is_empty() {
                None
            } else {
                Some(msg.to_string())
            }
        } else {
            None
        }
    } else {
        if line.len() > 4 {
            let msg = line[4..].trim_start();
            if msg.is_empty() {
                None
            } else {
                Some(msg.to_string())
            }
        } else {
            None
        }
    };

    Some(Pop3Response { success, message })
}

/// Parse POP3 client command
///
/// Format: COMMAND [argument]
pub fn parse_pop3_command(data: &[u8]) -> Option<Pop3Command> {
    // Minimum: "QUIT\r\n" = 6 bytes
    if data.len() < 6 {
        return None;
    }

    // Find line end
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
        "USER", "PASS", "STAT", "LIST", "RETR", "DELE", "QUIT", "NOOP", "RSET", "TOP", "UIDL",
        "APOP", "CAPA", "AUTH", "STLS", "LAST",
    ];

    if !valid_commands.contains(&command.as_str()) {
        return None;
    }

    let argument = if parts.len() > 1 {
        Some(parts[1].to_string())
    } else {
        None
    };

    Some(Pop3Command { command, argument })
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
    fn test_is_pop3_response_prefix() {
        assert!(is_pop3_response_prefix(b'+'));
        assert!(is_pop3_response_prefix(b'-'));
        assert!(!is_pop3_response_prefix(b'2'));
        assert!(!is_pop3_response_prefix(b'O'));
    }

    #[test]
    fn test_is_pop3_command_prefix() {
        assert!(is_pop3_command_prefix(b'U')); // USER
        assert!(is_pop3_command_prefix(b'P')); // PASS
        assert!(is_pop3_command_prefix(b'S')); // STAT, STLS
        assert!(is_pop3_command_prefix(b'L')); // LIST, LAST
        assert!(is_pop3_command_prefix(b'R')); // RETR, RSET
        assert!(is_pop3_command_prefix(b'D')); // DELE
        assert!(is_pop3_command_prefix(b'Q')); // QUIT
        assert!(is_pop3_command_prefix(b'N')); // NOOP
        assert!(is_pop3_command_prefix(b'T')); // TOP
        assert!(is_pop3_command_prefix(b'A')); // APOP, AUTH
        assert!(is_pop3_command_prefix(b'C')); // CAPA
        assert!(is_pop3_command_prefix(b'W')); // (obsolete)
        assert!(is_pop3_command_prefix(b'H')); // (obsolete)
        assert!(is_pop3_command_prefix(b'K')); // (obsolete)
        assert!(!is_pop3_command_prefix(b'X'));
        assert!(!is_pop3_command_prefix(b'Z'));
    }

    #[test]
    fn test_parse_pop3_response_ok() {
        let data = b"+OK\r\n";
        let resp = parse_pop3_response(data).unwrap();
        assert!(resp.success);
        assert!(resp.message.is_none());
    }

    #[test]
    fn test_parse_pop3_response_ok_with_message() {
        let data = b"+OK Message follows\r\n";
        let resp = parse_pop3_response(data).unwrap();
        assert!(resp.success);
        assert_eq!(resp.message, Some("Message follows".to_string()));
    }

    #[test]
    fn test_parse_pop3_response_err() {
        let data = b"-ERR Invalid user\r\n";
        let resp = parse_pop3_response(data).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.message, Some("Invalid user".to_string()));
    }

    #[test]
    fn test_parse_pop3_response_too_short() {
        assert!(parse_pop3_response(b"+OK\r").is_none());
        assert!(parse_pop3_response(b"+OK").is_none());
        assert!(parse_pop3_response(b"").is_none());
    }

    #[test]
    fn test_parse_pop3_command_user() {
        let data = b"USER test@example.com\r\n";
        let cmd = parse_pop3_command(data).unwrap();
        assert_eq!(cmd.command, "USER");
        assert_eq!(cmd.argument, Some("test@example.com".to_string()));
    }

    #[test]
    fn test_parse_pop3_command_pass() {
        let data = b"PASS secret123\r\n";
        let cmd = parse_pop3_command(data).unwrap();
        assert_eq!(cmd.command, "PASS");
        assert_eq!(cmd.argument, Some("secret123".to_string()));
    }

    #[test]
    fn test_parse_pop3_command_quit() {
        let data = b"QUIT\r\n";
        let cmd = parse_pop3_command(data).unwrap();
        assert_eq!(cmd.command, "QUIT");
        assert!(cmd.argument.is_none());
    }

    #[test]
    fn test_parse_pop3_command_stat() {
        let data = b"STAT\r\n";
        let cmd = parse_pop3_command(data).unwrap();
        assert_eq!(cmd.command, "STAT");
        assert!(cmd.argument.is_none());
    }

    #[test]
    fn test_parse_pop3_command_retr() {
        let data = b"RETR 1\r\n";
        let cmd = parse_pop3_command(data).unwrap();
        assert_eq!(cmd.command, "RETR");
        assert_eq!(cmd.argument, Some("1".to_string()));
    }

    #[test]
    fn test_parse_pop3_command_case_insensitive() {
        let data = b"user test@example.com\r\n";
        let cmd = parse_pop3_command(data).unwrap();
        assert_eq!(cmd.command, "USER");
    }

    #[test]
    fn test_parse_pop3_command_invalid() {
        assert!(parse_pop3_command(b"INVALID arg\r\n").is_none());
        assert!(parse_pop3_command(b"FOO\r\n").is_none());
    }

    #[test]
    fn test_find_line_end() {
        assert_eq!(find_line_end(b"hello\r\n"), Some(5));
        assert_eq!(find_line_end(b"test\n"), Some(4));
        assert!(find_line_end(b"hello").is_none());
    }
}
