//! IMAP protocol parser for rDpi
//!
//! Parses IMAP server responses and client commands.

/// IMAP server response
#[derive(Debug, Clone)]
pub struct ImapResponse {
    /// Response tag (None for untagged responses starting with *)
    pub tag: Option<String>,
    /// Response status: OK, NO, BAD, etc.
    pub status: String,
}

/// IMAP client command
#[derive(Debug, Clone)]
pub struct ImapCommand {
    /// Command tag (usually A001, A002, etc.)
    pub tag: String,
    /// Command name (CAPABILITY, LOGIN, etc.)
    pub command: String,
    /// Optional command argument
    pub argument: Option<String>,
}

/// Check if byte is IMAP response prefix ('*' or alphanumeric for tag)
pub fn is_imap_response_prefix(byte: u8) -> bool {
    byte == b'*' || byte.is_ascii_alphanumeric()
}

/// Check if byte is IMAP command prefix (alphanumeric for tag)
pub fn is_imap_command_prefix(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

/// Parse IMAP server response
///
/// Format: * OK/NO/BAD message  or  A001 OK/NO/BAD message
pub fn parse_imap_response(data: &[u8]) -> Option<ImapResponse> {
    // Minimum: "* OK\r\n" = 6 bytes
    if data.len() < 6 {
        return None;
    }

    // Find line end
    let line_end = find_line_end(data)?;
    let line = std::str::from_utf8(&data[..line_end]).ok()?;

    // Untagged response: * OK, * NO, * BAD, etc.
    if line.starts_with("* ") {
        let rest = &line[2..];
        let status = rest.split_whitespace().next()?;
        if is_valid_status(status) {
            return Some(ImapResponse {
                tag: None,
                status: status.to_uppercase(),
            });
        }
    }

    // Tagged response: A001 OK, A001 NO, etc.
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 {
        let tag = parts[0];
        let status = parts[1];
        if is_valid_status(status) && tag.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Some(ImapResponse {
                tag: Some(tag.to_string()),
                status: status.to_uppercase(),
            });
        }
    }

    None
}

/// Parse IMAP client command
///
/// Format: <tag> <COMMAND> [argument]
pub fn parse_imap_command(data: &[u8]) -> Option<ImapCommand> {
    // Minimum: "A001 Q\r\n" = 9 bytes (realistic minimum: "A001 NOOP\r\n" = 10)
    if data.len() < 9 {
        return None;
    }

    // Find line end
    let line_end = find_line_end(data)?;
    let line = std::str::from_utf8(&data[..line_end]).ok()?;

    // Split into parts
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }

    let tag = parts[0];
    let command = parts[1].to_uppercase();

    // Validate tag (alphanumeric)
    if !tag.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }

    // Validate command
    let valid_commands = [
        "CAPABILITY", "NOOP", "LOGOUT", "LOGIN", "AUTHENTICATE", "SELECT", "EXAMINE", "CREATE",
        "DELETE", "RENAME", "SUBSCRIBE", "UNSUBSCRIBE", "LIST", "LSUB", "STATUS", "APPEND",
        "CHECK", "CLOSE", "EXPUNGE", "SEARCH", "FETCH", "STORE", "COPY", "UID", "STARTTLS",
        "IDLE", "NAMESPACE", "GETQUOTAROOT", "GETQUOTA", "SETACL", "DELETEACL", "LISTRIGHTS",
        "MYRIGHTS", "ENABLE", "COMPRESS", "SORT", "THREAD", "MULTIAPPEND", "URLFETCH",
        "CATENATE", "MOVE", "UTF8", "ID",
    ];

    if !valid_commands.contains(&command.as_str()) {
        return None;
    }

    let argument = if parts.len() > 2 {
        Some(parts[2].to_string())
    } else {
        None
    };

    Some(ImapCommand {
        tag: tag.to_string(),
        command,
        argument,
    })
}

/// Check if status is valid IMAP status
fn is_valid_status(status: &str) -> bool {
    matches!(
        status.to_uppercase().as_str(),
        "OK" | "NO" | "BAD" | "PREAUTH" | "BYE"
    )
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
    fn test_is_imap_response_prefix() {
        assert!(is_imap_response_prefix(b'*'));
        assert!(is_imap_response_prefix(b'A'));
        assert!(is_imap_response_prefix(b'a'));
        assert!(is_imap_response_prefix(b'1'));
        assert!(!is_imap_response_prefix(b'-'));
        assert!(!is_imap_response_prefix(b'+'));
    }

    #[test]
    fn test_is_imap_command_prefix() {
        assert!(is_imap_command_prefix(b'A'));
        assert!(is_imap_command_prefix(b'a'));
        assert!(is_imap_command_prefix(b'1'));
        assert!(!is_imap_command_prefix(b'*'));
        assert!(!is_imap_command_prefix(b'-'));
    }

    #[test]
    fn test_parse_imap_response_untagged_ok() {
        let data = b"* OK IMAP4rev1 Service Ready\r\n";
        let resp = parse_imap_response(data).unwrap();
        assert!(resp.tag.is_none());
        assert_eq!(resp.status, "OK");
    }

    #[test]
    fn test_parse_imap_response_untagged_no() {
        let data = b"* NO Disk is full\r\n";
        let resp = parse_imap_response(data).unwrap();
        assert!(resp.tag.is_none());
        assert_eq!(resp.status, "NO");
    }

    #[test]
    fn test_parse_imap_response_tagged_ok() {
        let data = b"A001 OK LOGIN completed\r\n";
        let resp = parse_imap_response(data).unwrap();
        assert_eq!(resp.tag, Some("A001".to_string()));
        assert_eq!(resp.status, "OK");
    }

    #[test]
    fn test_parse_imap_response_tagged_bad() {
        let data = b"A002 BAD Invalid command\r\n";
        let resp = parse_imap_response(data).unwrap();
        assert_eq!(resp.tag, Some("A002".to_string()));
        assert_eq!(resp.status, "BAD");
    }

    #[test]
    fn test_parse_imap_response_too_short() {
        assert!(parse_imap_response(b"* OK\r").is_none());
        assert!(parse_imap_response(b"* OK").is_none());
        assert!(parse_imap_response(b"").is_none());
    }

    #[test]
    fn test_parse_imap_command_login() {
        let data = b"A001 LOGIN user password\r\n";
        let cmd = parse_imap_command(data).unwrap();
        assert_eq!(cmd.tag, "A001");
        assert_eq!(cmd.command, "LOGIN");
        assert_eq!(cmd.argument, Some("user password".to_string()));
    }

    #[test]
    fn test_parse_imap_command_select() {
        let data = b"A002 SELECT INBOX\r\n";
        let cmd = parse_imap_command(data).unwrap();
        assert_eq!(cmd.tag, "A002");
        assert_eq!(cmd.command, "SELECT");
        assert_eq!(cmd.argument, Some("INBOX".to_string()));
    }

    #[test]
    fn test_parse_imap_command_noop() {
        let data = b"A003 NOOP\r\n";
        let cmd = parse_imap_command(data).unwrap();
        assert_eq!(cmd.tag, "A003");
        assert_eq!(cmd.command, "NOOP");
        assert!(cmd.argument.is_none());
    }

    #[test]
    fn test_parse_imap_command_logout() {
        let data = b"A004 LOGOUT\r\n";
        let cmd = parse_imap_command(data).unwrap();
        assert_eq!(cmd.tag, "A004");
        assert_eq!(cmd.command, "LOGOUT");
    }

    #[test]
    fn test_parse_imap_command_case_insensitive() {
        let data = b"a001 login user pass\r\n";
        let cmd = parse_imap_command(data).unwrap();
        assert_eq!(cmd.tag, "a001");
        assert_eq!(cmd.command, "LOGIN");
    }

    #[test]
    fn test_parse_imap_command_invalid() {
        assert!(parse_imap_command(b"INVALID arg\r\n").is_none());
        assert!(parse_imap_command(b"* OK\r\n").is_none());
    }

    #[test]
    fn test_is_valid_status() {
        assert!(is_valid_status("OK"));
        assert!(is_valid_status("ok"));
        assert!(is_valid_status("NO"));
        assert!(is_valid_status("BAD"));
        assert!(is_valid_status("PREAUTH"));
        assert!(is_valid_status("BYE"));
        assert!(!is_valid_status("YES"));
        assert!(!is_valid_status("ERROR"));
    }

    #[test]
    fn test_find_line_end() {
        assert_eq!(find_line_end(b"hello\r\n"), Some(5));
        assert_eq!(find_line_end(b"test\n"), Some(4));
        assert!(find_line_end(b"hello").is_none());
    }
}
