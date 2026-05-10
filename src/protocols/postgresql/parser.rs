//! PostgreSQL protocol parser for rDpi
//!
//! Parses PostgreSQL startup messages and extracts connection parameters.

use crate::core::types::PostgresqlMetadata;

/// Parse PostgreSQL startup message
///
/// Format:
/// - length (4 bytes, big-endian, includes self)
/// - protocol version (4 bytes): 0x00030000 for v3.0
/// - parameters: key\x00value\x00 pairs, terminated by \x00
pub fn parse_pg_startup(data: &[u8]) -> Option<PostgresqlMetadata> {
    // Minimum: length(4) + version(4) + terminating \x00 = 9 bytes
    if data.len() < 9 {
        return None;
    }

    // Check protocol version (3.0 = 0x00030000)
    if data[4..8] != [0x00, 0x03, 0x00, 0x00] {
        return None;
    }

    // Parse parameters (key-value pairs)
    let params = parse_parameters(&data[8..]);

    let user = params.get("user").cloned();
    let database = params.get("database").cloned();
    let application_name = params.get("application_name").cloned();

    Some(PostgresqlMetadata {
        user,
        database,
        application_name,
    })
}

/// Parse key-value parameters from startup message
fn parse_parameters(data: &[u8]) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    let mut pos = 0;

    while pos < data.len() {
        // Check for terminating null
        if data[pos] == 0 {
            break;
        }

        // Find key (null-terminated)
        let key_end = match data[pos..].iter().position(|&b| b == 0) {
            Some(i) => i,
            None => break,
        };

        let key = match std::str::from_utf8(&data[pos..pos + key_end]) {
            Ok(s) => s.to_string(),
            Err(_) => break,
        };

        pos += key_end + 1;

        // Check if we have more data for value
        if pos >= data.len() {
            break;
        }

        // Find value (null-terminated)
        let value_end = match data[pos..].iter().position(|&b| b == 0) {
            Some(i) => i,
            None => break,
        };

        let value = match std::str::from_utf8(&data[pos..pos + value_end]) {
            Ok(s) => s.to_string(),
            Err(_) => break,
        };

        pos += value_end + 1;

        params.insert(key, value);
    }

    params
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a PostgreSQL startup message for testing
    fn create_startup_message(user: Option<&str>, database: Option<&str>, app_name: Option<&str>) -> Vec<u8> {
        let mut msg = Vec::new();

        // Protocol version 3.0
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Length placeholder
        msg.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // Protocol v3.0

        // Add parameters
        if let Some(u) = user {
            msg.extend_from_slice(b"user");
            msg.push(0x00);
            msg.extend_from_slice(u.as_bytes());
            msg.push(0x00);
        }

        if let Some(d) = database {
            msg.extend_from_slice(b"database");
            msg.push(0x00);
            msg.extend_from_slice(d.as_bytes());
            msg.push(0x00);
        }

        if let Some(a) = app_name {
            msg.extend_from_slice(b"application_name");
            msg.push(0x00);
            msg.extend_from_slice(a.as_bytes());
            msg.push(0x00);
        }

        // Terminating null
        msg.push(0x00);

        // Update length (includes itself)
        let len = msg.len() as u32;
        msg[0..4].copy_from_slice(&len.to_be_bytes());

        msg
    }

    #[test]
    fn test_parse_pg_startup_basic() {
        let msg = create_startup_message(Some("postgres"), Some("testdb"), None);
        let meta = parse_pg_startup(&msg).unwrap();

        assert_eq!(meta.user, Some("postgres".to_string()));
        assert_eq!(meta.database, Some("testdb".to_string()));
        assert_eq!(meta.application_name, None);
    }

    #[test]
    fn test_parse_pg_startup_with_app_name() {
        let msg = create_startup_message(
            Some("admin"),
            Some("mydb"),
            Some("psql")
        );
        let meta = parse_pg_startup(&msg).unwrap();

        assert_eq!(meta.user, Some("admin".to_string()));
        assert_eq!(meta.database, Some("mydb".to_string()));
        assert_eq!(meta.application_name, Some("psql".to_string()));
    }

    #[test]
    fn test_parse_pg_startup_minimal() {
        let msg = create_startup_message(Some("test"), None, None);
        let meta = parse_pg_startup(&msg).unwrap();

        assert_eq!(meta.user, Some("test".to_string()));
        assert_eq!(meta.database, None);
    }

    #[test]
    fn test_parse_pg_startup_invalid_version() {
        let msg = vec![
            0x00, 0x00, 0x00, 0x10,  // Length
            0x00, 0x02, 0x00, 0x00,  // Protocol v2.0 (old)
            0x00,  // terminator
        ];
        assert!(parse_pg_startup(&msg).is_none());
    }

    #[test]
    fn test_parse_pg_startup_too_short() {
        assert!(parse_pg_startup(&[]).is_none());
        assert!(parse_pg_startup(&[0x00, 0x00, 0x00, 0x08]).is_none());
        assert!(parse_pg_startup(&[0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_parse_pg_startup_ssl_request() {
        // SSL request uses special protocol number 1234.5678 (0x04d2162e)
        // This should NOT be detected as a regular startup
        let msg = vec![
            0x00, 0x00, 0x00, 0x08,  // Length: 8
            0x04, 0xd2, 0x16, 0x2e,  // SSL request magic number
        ];
        assert!(parse_pg_startup(&msg).is_none());
    }
}
