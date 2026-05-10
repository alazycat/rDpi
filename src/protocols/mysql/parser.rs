//! MySQL protocol parser for rDpi
//!
//! Parses MySQL server handshake and client authentication packets.

use crate::core::types::MysqlMetadata;

/// Parse MySQL server handshake packet
///
/// MySQL handshake packet format (protocol version 10):
/// - protocol_version (1 byte, 0x0a)
/// - server_version (null-terminated string)
/// - connection_id (4 bytes)
/// - auth_plugin_data_part_1 (8 bytes)
/// - filler (1 byte, 0x00)
/// - capability_flag_1 (2 bytes, lower 16 bits)
/// - character_set (1 byte)
/// - status_flags (2 bytes)
/// - capability_flags_2 (2 bytes, upper 16 bits)
/// - auth_plugin_data_len (1 byte, if CLIENT_PLUGIN_AUTH)
/// - reserved (10 bytes)
/// - auth_plugin_data_part_2 (variable length)
/// - auth_plugin_name (null-terminated, if CLIENT_PLUGIN_AUTH)
pub fn parse_mysql_handshake(data: &[u8]) -> Option<MysqlMetadata> {
    // Minimum reasonable handshake packet
    if data.len() < 20 {
        return None;
    }

    // Protocol version must be 10 (0x0a)
    if data[0] != 0x0a {
        return None;
    }

    // Extract version string (null-terminated)
    let version_null_pos = data[1..].iter().position(|&b| b == 0)?;
    let version = std::str::from_utf8(&data[1..=version_null_pos]).ok()?;

    // Calculate offsets
    // After version: protocol_version(1) + version(N) + null(1)
    let after_version = 1 + version_null_pos + 1;

    // Extract auth plugin name (optional)
    let auth_plugin = extract_auth_plugin(data, after_version);

    Some(MysqlMetadata {
        version: Some(version.to_string()),
        auth_plugin,
    })
}

/// Extract auth plugin name from handshake packet
fn extract_auth_plugin(data: &[u8], after_version: usize) -> Option<String> {
    // Fixed fields after version string (null-terminated):
    // connection_id(4) + auth_data_1(8) + filler(1) + cap1(2) + charset(1) + status(2) + cap2(2) + auth_len(1) + reserved(10)
    // Total: 31 bytes
    let fixed_size = 31;

    // Check minimum data length for fixed fields
    if after_version + fixed_size > data.len() {
        return None;
    }

    // Offsets relative to after_version
    // cap2 is at: after_version + 4 + 8 + 1 + 2 + 1 + 2 = after_version + 18
    let cap2_offset = after_version + 18;

    // Check CLIENT_PLUGIN_AUTH flag (bit 19 = 0x00080000 in full 32-bit flags)
    // In cap2 (upper 16 bits), this is bit 3 (0x0008)
    let cap2 = u16::from_le_bytes([data[cap2_offset], data[cap2_offset + 1]]);
    let has_plugin_auth = (cap2 & 0x0008) != 0;

    if !has_plugin_auth {
        return None;
    }

    // auth_data_len is at: after_version + 4 + 8 + 1 + 2 + 1 + 2 + 2 = after_version + 20
    let auth_len_offset = after_version + 20;
    let auth_data_len = data[auth_len_offset] as usize;

    // auth_plugin_data_part_2 length = auth_data_len - 8 (part 1)
    let auth_part2_len = if auth_data_len > 8 { auth_data_len - 8 } else { 0 };

    // auth_plugin_name starts after fixed fields + auth_part2
    let plugin_offset = after_version + fixed_size + auth_part2_len;
    if plugin_offset >= data.len() {
        return None;
    }

    // Find null-terminated auth plugin name
    let plugin_data = &data[plugin_offset..];
    let plugin_end = plugin_data.iter().position(|&b| b == 0)?;
    let plugin_name = std::str::from_utf8(&plugin_data[..plugin_end]).ok()?;

    if plugin_name.is_empty() {
        None
    } else {
        Some(plugin_name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a MySQL handshake packet for testing
    fn create_handshake_packet(version: &str, auth_plugin: &str, auth_data_len: u8) -> Vec<u8> {
        let mut packet = Vec::new();

        // Protocol version
        packet.push(0x0a);

        // Server version (null-terminated)
        packet.extend_from_slice(version.as_bytes());
        packet.push(0x00);

        // Connection ID (4 bytes)
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        // Auth-plugin-data-part-1 (8 bytes)
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        // Filler (1 byte)
        packet.push(0x00);

        // Capability flags 1 (2 bytes) - includes CLIENT_PROTOCOL_41
        packet.extend_from_slice(&[0xff, 0xf7]);

        // Character set (1 byte) - utf8
        packet.push(0x21);

        // Status flags (2 bytes)
        packet.extend_from_slice(&[0x02, 0x00]);

        // Capability flags 2 (2 bytes) - includes CLIENT_PLUGIN_AUTH (0x0008)
        packet.extend_from_slice(&[0xff, 0x8f]); // 0x8f has bit 3 set = CLIENT_PLUGIN_AUTH in upper half

        // Auth plugin data len (1 byte)
        packet.push(auth_data_len);

        // Reserved (10 bytes)
        packet.extend_from_slice(&[0x00; 10]);

        // Auth-plugin-data-part-2 (auth_data_len - 8 bytes)
        let part2_len = auth_data_len as usize - 8;
        for i in 0..part2_len {
            packet.push(i as u8 + 1);
        }

        // Auth plugin name (null-terminated)
        packet.extend_from_slice(auth_plugin.as_bytes());
        packet.push(0x00);

        packet
    }

    #[test]
    fn test_parse_mysql_handshake_basic() {
        // auth_data_len = 21, so part2 = 13 bytes
        let packet = create_handshake_packet("8.0.33", "mysql_native_password", 21);
        let meta = parse_mysql_handshake(&packet).unwrap();

        assert_eq!(meta.version, Some("8.0.33".to_string()));
        assert_eq!(meta.auth_plugin, Some("mysql_native_password".to_string()));
    }

    #[test]
    fn test_parse_mysql_handshake_mariadb() {
        let packet = create_handshake_packet("10.6.12-MariaDB", "mysql_native_password", 21);
        let meta = parse_mysql_handshake(&packet).unwrap();

        assert_eq!(meta.version, Some("10.6.12-MariaDB".to_string()));
    }

    #[test]
    fn test_parse_mysql_handshake_caching_sha2() {
        let packet = create_handshake_packet("8.0.33", "caching_sha2_password", 21);
        let meta = parse_mysql_handshake(&packet).unwrap();

        assert_eq!(meta.version, Some("8.0.33".to_string()));
        assert_eq!(meta.auth_plugin, Some("caching_sha2_password".to_string()));
    }

    #[test]
    fn test_parse_mysql_handshake_invalid_protocol() {
        let packet = vec![0x00, b'5', b'.', b'7', 0x00];
        assert!(parse_mysql_handshake(&packet).is_none());
    }

    #[test]
    fn test_parse_mysql_handshake_too_short() {
        assert!(parse_mysql_handshake(&[]).is_none());
        assert!(parse_mysql_handshake(&[0x0a]).is_none());
        assert!(parse_mysql_handshake(&[0x0a, 0x00]).is_none());
    }

    #[test]
    fn test_parse_mysql_handshake_missing_null_terminator() {
        let packet = vec![0x0a, b'5', b'.', b'7'];
        assert!(parse_mysql_handshake(&packet).is_none());
    }
}