//! SSH protocol parser for rDpi
//!
//! Parses SSH version identification string.

/// SSH version identification parsing result
#[derive(Debug, Clone)]
pub struct SshVersionInfo {
    /// Protocol version (e.g., "2.0", "1.99")
    pub protocol_version: String,
    /// Software version string (e.g., "OpenSSH_8.9p1")
    pub software_version: Option<String>,
}

/// Check if byte is SSH prefix ('S')
pub fn is_ssh_prefix(byte: u8) -> bool {
    byte == b'S'
}

/// Parse SSH version identification string
///
/// Format: SSH-<protocol_version>-<software_version> CRLF
///
/// Valid protocol versions: 2.0, 1.99
pub fn parse_ssh_version(data: &[u8]) -> Option<SshVersionInfo> {
    // Minimum: "SSH-2.0\r\n" = 8 bytes
    if data.len() < 8 {
        return None;
    }

    // Must start with "SSH-"
    if !data.starts_with(b"SSH-") {
        return None;
    }

    // Find end of line
    let line_end = find_line_end(data)?;
    let line = std::str::from_utf8(&data[..line_end]).ok()?;

    // Parse: SSH-<version>-<software>
    // Split on '-' after "SSH-"
    let after_ssh = &line[4..]; // Skip "SSH-"

    // Find the next '-' to separate protocol version from software
    let (proto_version, software) = if let Some(dash_pos) = after_ssh.find('-') {
        let proto = &after_ssh[..dash_pos];
        let sw = &after_ssh[dash_pos + 1..];
        (proto, Some(sw.to_string()))
    } else {
        // No software version: SSH-2.0
        (after_ssh, None)
    };

    // Validate protocol version (only 2.0 and 1.99 are valid)
    if proto_version != "2.0" && proto_version != "1.99" {
        return None;
    }

    Some(SshVersionInfo {
        protocol_version: proto_version.to_string(),
        software_version: software,
    })
}

/// Find line end position (before \r\n or \n)
fn find_line_end(data: &[u8]) -> Option<usize> {
    for (i, &byte) in data.iter().enumerate() {
        if byte == b'\n' {
            // If \n is preceded by \r, return position before \r
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
    fn test_is_ssh_prefix() {
        assert!(is_ssh_prefix(b'S'));
        assert!(!is_ssh_prefix(b'H'));
    }

    #[test]
    fn test_parse_ssh_version_openssh() {
        let data = b"SSH-2.0-OpenSSH_8.9p1\r\n";
        let result = parse_ssh_version(data).unwrap();
        assert_eq!(result.protocol_version, "2.0");
        assert_eq!(result.software_version, Some("OpenSSH_8.9p1".to_string()));
    }

    #[test]
    fn test_parse_ssh_version_no_software() {
        let data = b"SSH-2.0\r\n";
        let result = parse_ssh_version(data).unwrap();
        assert_eq!(result.protocol_version, "2.0");
        assert_eq!(result.software_version, None);
    }

    #[test]
    fn test_parse_ssh_version_invalid() {
        let data = b"SSH-1.0-xxx\r\n";
        assert!(parse_ssh_version(data).is_none());
    }
}
