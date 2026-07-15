//! FTP protocol parser for rDpi
//!
//! Parses FTP commands (e.g., USER, PASS, RETR) and server responses
//! (e.g., "220 FTP server ready").

const FTP_VERBS: &[&str] = &[
    "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN",
    "PORT", "PASV", "TYPE", "STRU", "MODE", "RETR", "STOR", "STOU",
    "APPE", "ALLO", "REST", "RNFR", "RNTO", "ABOR", "DELE", "RMD",
    "MKD", "PWD", "LIST", "NLST", "SITE", "SYST", "STAT", "HELP",
    "NOOP", "AUTH", "FEAT", "OPTS", "SIZE", "MDTM", "EPSV", "EPRT",
];

/// FTP client command
#[derive(Debug, Clone)]
pub struct FtpCommand {
    /// Command verb (e.g., "USER", "PWD")
    pub verb: String,
    /// Optional command argument
    pub argument: Option<String>,
}

/// FTP server response
#[derive(Debug, Clone)]
pub struct FtpResponse {
    /// Response code (e.g., 220, 331, 550)
    pub code: u16,
    /// Response message text
    pub message: String,
}

/// Parse an FTP client command from a byte payload.
///
/// Returns `None` if the payload does not contain a valid FTP verb.
pub fn parse_ftp_command(payload: &[u8]) -> Option<FtpCommand> {
    if payload.is_empty() {
        return None;
    }
    let end = payload.iter().position(|&b| b == b'\n')
        .unwrap_or(payload.len().saturating_sub(1));
    let line = std::str::from_utf8(&payload[..=end]).ok()?
        .trim_end_matches('\r')
        .trim_end_matches('\n');

    if line.is_empty() {
        return None;
    }

    let upper = line.to_uppercase();
    for verb in FTP_VERBS {
        if upper.starts_with(verb) {
            let arg = line[verb.len()..].trim().to_string();
            let argument = if arg.is_empty() { None } else { Some(arg) };
            return Some(FtpCommand {
                verb: upper[..verb.len()].to_string(),
                argument,
            });
        }
    }
    None
}

/// Parse an FTP server response from a byte payload.
///
/// Expects the standard FTP response format: "NNN message".
pub fn parse_ftp_response(payload: &[u8]) -> Option<FtpResponse> {
    if payload.len() < 4 {
        return None;
    }
    let line = std::str::from_utf8(payload).ok()?;
    let end = line.find('\n').unwrap_or(line.len());
    let line = line[..end].trim_end_matches('\r').trim_end_matches('\n');

    if line.len() < 3 {
        return None;
    }
    let code: u16 = line[..3].parse().ok()?;
    if !(200..=600).contains(&code) {
        return None;
    }
    let message = if line.len() > 4 {
        line[4..].to_string()
    } else {
        String::new()
    };
    Some(FtpResponse { code, message })
}

/// Quick check whether the payload starts with a valid FTP response prefix
/// (three ASCII digits followed by a space).
pub fn is_ftp_response_prefix(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }
    payload[3] == b' '
        && payload[0].is_ascii_digit()
        && payload[1].is_ascii_digit()
        && payload[2].is_ascii_digit()
}

/// Quick check whether the first byte looks like an FTP command letter (A-Z).
pub fn is_ftp_command_prefix(payload: &[u8]) -> bool {
    payload.first().copied().is_some_and(|first| (b'A'..=b'Z').contains(&first))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ftp_command_user() {
        let cmd = parse_ftp_command(b"USER anonymous\r\n").unwrap();
        assert_eq!(cmd.verb, "USER");
        assert_eq!(cmd.argument, Some("anonymous".to_string()));
    }

    #[test]
    fn test_parse_ftp_command_no_arg() {
        let cmd = parse_ftp_command(b"PWD\r\n").unwrap();
        assert_eq!(cmd.verb, "PWD");
        assert!(cmd.argument.is_none());
    }

    #[test]
    fn test_parse_ftp_command_lowercase() {
        let cmd = parse_ftp_command(b"list\r\n").unwrap();
        assert_eq!(cmd.verb, "LIST");
    }

    #[test]
    fn test_parse_ftp_command_invalid() {
        assert!(parse_ftp_command(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn test_parse_ftp_command_empty() {
        assert!(parse_ftp_command(b"").is_none());
    }

    #[test]
    fn test_parse_ftp_response() {
        let resp = parse_ftp_response(b"220 FTP server ready\r\n").unwrap();
        assert_eq!(resp.code, 220);
        assert_eq!(resp.message, "FTP server ready");
    }

    #[test]
    fn test_parse_ftp_response_invalid_code() {
        assert!(parse_ftp_response(b"999 unknown\r\n").is_none());
    }

    #[test]
    fn test_parse_ftp_response_no_newline() {
        let resp = parse_ftp_response(b"331 Password required").unwrap();
        assert_eq!(resp.code, 331);
    }

    #[test]
    fn test_parse_ftp_verb_list() {
        // Verify every verb in FTP_VERBS parses correctly
        for verb in FTP_VERBS {
            let cmd = parse_ftp_command(format!("{}\r\n", verb).as_bytes()).unwrap();
            assert_eq!(cmd.verb, *verb);
        }
    }
}
