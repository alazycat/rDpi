//! QUIC protocol parser for rDpi
//!
//! Parses QUIC Initial packets for protocol detection.
//!
//! QUIC v1 Long Header first byte format (bits 7-0):
//! - Bit 7: Header Form (1 = Long Header)
//! - Bit 6: Fixed Bit (1 = QUIC v1 compliant)
//! - Bits 5-4: Packet Type (00 = Initial)
//! - Bits 3-2: Reserved
//! - Bits 1-0: Packet Number Length
//!
//! Initial packet detection: (first_byte & 0xF0) == 0xC0
//! This checks for Long Header (bit 7=1), Fixed Bit (bit 6=1), and Initial type (bits 5-4=00)

/// QUIC version constants (32-bit, big-endian on wire)
pub const QUIC_VERSION_1: u32 = 0x00000001;
pub const QUIC_VERSION_2: u32 = 0x6b3343cf;
pub const QUIC_VERSION_DRAFT29: u32 = 0xff00001d;
pub const QUIC_VERSION_DRAFT28: u32 = 0xff00001c;

/// QUIC Initial packet info extracted from the header
#[derive(Debug, Clone)]
pub struct QuicInitialInfo {
    /// QUIC version number
    pub version: u32,
    /// Destination Connection ID length
    pub dcid_len: u8,
    /// Destination Connection ID bytes
    pub dcid: Vec<u8>,
    /// Source Connection ID length
    pub scid_len: u8,
    /// Source Connection ID bytes
    pub scid: Vec<u8>,
    /// Token length (varint)
    pub token_len: u64,
    /// Token bytes
    pub token: Vec<u8>,
}

/// Check if the packet is a QUIC Initial packet
///
/// Returns true if:
/// - First byte indicates Long Header with Initial type
/// - (first_byte & 0xF0) == 0xC0
///
/// This means:
/// - Bit 7 (Header Form) = 1 (Long Header)
/// - Bit 6 (Fixed Bit) = 1 (QUIC v1 compliant)
/// - Bits 5-4 (Packet Type) = 00 (Initial)
pub fn is_quic_initial(data: &[u8]) -> bool {
    !data.is_empty() && (data[0] & 0xF0) == 0xC0
}

/// Parse QUIC version from packet
///
/// For Long Header packets, version is at offset 1-4 (4 bytes, big-endian).
/// Returns None if packet is too short.
pub fn parse_quic_version(data: &[u8]) -> Option<u32> {
    if data.len() < 5 {
        return None;
    }

    // Version is bytes 1-4 for Long Header
    Some(u32::from_be_bytes([data[1], data[2], data[3], data[4]]))
}

/// Parse a QUIC varint from the data
///
/// QUIC varint format:
/// | Prefix | Length | Value range |
/// |--------|--------|-------------|
/// | 00     | 1 byte | 0-63        |
/// | 01     | 2 bytes| 0-16383     |
/// | 10     | 4 bytes| 0-1073741823|
/// | 11     | 8 bytes| 0-4611686018427387903|
///
/// Returns (value, bytes_consumed) on success, None on failure.
pub fn parse_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];
    let prefix = (first_byte >> 6) & 0x03;
    let length = 1 << prefix; // 1, 2, 4, or 8 bytes

    if data.len() < length {
        return None;
    }

    let value = match prefix {
        0 => {
            // 1 byte: lower 6 bits
            u64::from(first_byte & 0x3F)
        }
        1 => {
            // 2 bytes: lower 6 bits + next byte
            u64::from(first_byte & 0x3F) << 8 | u64::from(data[1])
        }
        2 => {
            // 4 bytes: lower 6 bits + next 3 bytes
            u64::from(first_byte & 0x3F) << 24
                | u64::from(data[1]) << 16
                | u64::from(data[2]) << 8
                | u64::from(data[3])
        }
        3 => {
            // 8 bytes: lower 6 bits + next 7 bytes
            u64::from(first_byte & 0x3F) << 56
                | u64::from(data[1]) << 48
                | u64::from(data[2]) << 40
                | u64::from(data[3]) << 32
                | u64::from(data[4]) << 24
                | u64::from(data[5]) << 16
                | u64::from(data[6]) << 8
                | u64::from(data[7])
        }
        _ => unreachable!(), // prefix is always 0-3
    };

    Some((value, length))
}

/// Parse a QUIC Initial packet
///
/// Long Header format:
/// - First byte: Header Form + Packet Type + Reserved + Packet Number Length
/// - Version (4 bytes)
/// - DCID Length (1 byte) + DCID (0-20 bytes)
/// - SCID Length (1 byte) + SCID (0-20 bytes)
/// - Token Length (varint) + Token
/// - Packet Number + Payload
///
/// Note: This parser only extracts header information, not the encrypted payload.
pub fn parse_quic_initial(data: &[u8]) -> Option<QuicInitialInfo> {
    if !is_quic_initial(data) {
        return None;
    }

    // Minimum: 1 (type) + 4 (version) + 1 (dcid_len) + 1 (scid_len) + 1 (token_len min)
    if data.len() < 8 {
        return None;
    }

    // Parse version
    let version = parse_quic_version(data)?;

    // Offset after version (byte 5)
    let mut offset = 5;

    // Parse DCID length and DCID
    let dcid_len = data[offset];
    offset += 1;

    if offset + dcid_len as usize > data.len() {
        return None;
    }

    let dcid = data[offset..offset + dcid_len as usize].to_vec();
    offset += dcid_len as usize;

    // Parse SCID length and SCID
    if offset >= data.len() {
        return None;
    }

    let scid_len = data[offset];
    offset += 1;

    if offset + scid_len as usize > data.len() {
        return None;
    }

    let scid = data[offset..offset + scid_len as usize].to_vec();
    offset += scid_len as usize;

    // Parse token length (varint)
    if offset >= data.len() {
        return None;
    }

    let (token_len, varint_len) = parse_varint(&data[offset..])?;
    offset += varint_len;

    // Check token length doesn't overflow
    if token_len > usize::MAX as u64 {
        return None;
    }

    let token_len_usize = token_len as usize;

    if offset + token_len_usize > data.len() {
        return None;
    }

    let token = data[offset..offset + token_len_usize].to_vec();

    Some(QuicInitialInfo {
        version,
        dcid_len,
        dcid,
        scid_len,
        scid,
        token_len,
        token,
    })
}

/// Convert QUIC version number to human-readable string
pub fn version_to_string(version: u32) -> Option<String> {
    match version {
        QUIC_VERSION_1 => Some("QUIC v1".to_string()),
        QUIC_VERSION_2 => Some("QUIC v2".to_string()),
        QUIC_VERSION_DRAFT29 => Some("QUIC Draft-29".to_string()),
        QUIC_VERSION_DRAFT28 => Some("QUIC Draft-28".to_string()),
        0 => None, // Version negotiation packet
        v => Some(format!("QUIC 0x{:08x}", v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_quic_initial_valid() {
        // Initial packet: Long Header (1) + Fixed Bit (1) + Initial (00) = 0xC0
        let data = [0xC0, 0x00, 0x00, 0x00, 0x01];
        assert!(is_quic_initial(&data));
    }

    #[test]
    fn test_is_quic_initial_invalid_short_header() {
        // Short header: bit 7 = 0
        let data = [0x40, 0x00, 0x00, 0x00, 0x01];
        assert!(!is_quic_initial(&data));
    }

    #[test]
    fn test_is_quic_initial_invalid_not_initial() {
        // Long Header but not Initial (e.g., 0xD0 = 0b11010000 = Handshake)
        let data = [0xD0, 0x00, 0x00, 0x00, 0x01];
        assert!(!is_quic_initial(&data));
    }

    #[test]
    fn test_is_quic_initial_empty() {
        let data: [u8; 0] = [];
        assert!(!is_quic_initial(&data));
    }

    #[test]
    fn test_parse_quic_version_valid() {
        // QUIC v1
        let data = [0xC0, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(parse_quic_version(&data), Some(QUIC_VERSION_1));
    }

    #[test]
    fn test_parse_quic_version_v2() {
        // QUIC v2: 0x6b3343cf
        let data = [0xC0, 0x6b, 0x33, 0x43, 0xcf, 0x00];
        assert_eq!(parse_quic_version(&data), Some(QUIC_VERSION_2));
    }

    #[test]
    fn test_parse_quic_version_too_short() {
        let data = [0xC0, 0x00, 0x00];
        assert_eq!(parse_quic_version(&data), None);
    }

    #[test]
    fn test_parse_varint_1_byte() {
        // Prefix 00: 1 byte, value in lower 6 bits
        let data = [0x25]; // 0b00100101 = 37
        assert_eq!(parse_varint(&data), Some((37, 1)));
    }

    #[test]
    fn test_parse_varint_2_bytes() {
        // Prefix 01: 2 bytes
        let data = [0x40 | 0x00, 0x10]; // 16
        assert_eq!(parse_varint(&data), Some((16, 2)));
    }

    #[test]
    fn test_parse_varint_4_bytes() {
        // Prefix 10: 4 bytes
        let data = [0x80 | 0x00, 0x01, 0x00, 0x00]; // 65536
        assert_eq!(parse_varint(&data), Some((65536, 4)));
    }

    #[test]
    fn test_parse_varint_8_bytes() {
        // Prefix 11: 8 bytes
        let data = [
            0xC0 | 0x01, // Lower 6 bits = 1
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        // Value = 1 << 56
        assert_eq!(parse_varint(&data), Some((72057594037927936, 8)));
    }

    #[test]
    fn test_parse_varint_max_1_byte() {
        // Max 1-byte varint: 63 (0x3F)
        let data = [0x3F];
        assert_eq!(parse_varint(&data), Some((63, 1)));
    }

    #[test]
    fn test_parse_varint_empty() {
        let data: [u8; 0] = [];
        assert_eq!(parse_varint(&data), None);
    }

    #[test]
    fn test_parse_varint_too_short() {
        // Needs 2 bytes but only 1 provided
        let data = [0x40];
        assert_eq!(parse_varint(&data), None);
    }

    /// Helper to construct a minimal QUIC Initial packet for testing
    fn make_minimal_quic_initial() -> Vec<u8> {
        let mut data = vec![
            0xC0, // Long Header + Initial
            0x00, 0x00, 0x00, 0x01, // Version: QUIC v1
            0x08, // DCID Length: 8
        ];
        // DCID: 8 bytes
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        data.push(0x00); // SCID Length: 0
        data.push(0x00); // Token Length: 0 (1-byte varint)
        data.push(0x02); // Packet Number Length: 2 bytes (encoded in first byte bits 1-0)
        data.extend_from_slice(&[0x00, 0x01]); // Minimal payload placeholder
        data
    }

    #[test]
    fn test_parse_quic_initial_minimal() {
        let data = make_minimal_quic_initial();
        assert!(is_quic_initial(&data));

        let result = parse_quic_initial(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.version, QUIC_VERSION_1);
        assert_eq!(info.dcid_len, 8);
        assert_eq!(
            info.dcid,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(info.scid_len, 0);
        assert!(info.scid.is_empty());
        assert_eq!(info.token_len, 0);
        assert!(info.token.is_empty());
    }

    #[test]
    fn test_parse_quic_initial_with_token() {
        let mut data = vec![
            0xC0, // Long Header + Initial
            0x00, 0x00, 0x00, 0x01, // Version: QUIC v1
            0x00, // DCID Length: 0
            0x00, // SCID Length: 0
            0x05, // Token Length: 5 (1-byte varint)
        ];
        data.extend_from_slice(b"token"); // Token
        data.extend_from_slice(&[0x00, 0x01]); // Minimal payload placeholder

        let result = parse_quic_initial(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.version, QUIC_VERSION_1);
        assert_eq!(info.token_len, 5);
        assert_eq!(info.token, b"token".to_vec());
    }

    #[test]
    fn test_parse_quic_initial_with_scid() {
        let mut data = vec![
            0xC0, // Long Header + Initial
            0x00, 0x00, 0x00, 0x01, // Version: QUIC v1
            0x00, // DCID Length: 0
            0x04, // SCID Length: 4
        ];
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // SCID
        data.push(0x00); // Token Length: 0
        data.extend_from_slice(&[0x00, 0x01]); // Minimal payload placeholder

        let result = parse_quic_initial(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.scid_len, 4);
        assert_eq!(info.scid, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_parse_quic_initial_quic_v2() {
        let data = vec![
            0xC0, // Long Header + Initial
            0x6b, 0x33, 0x43, 0xcf, // Version: QUIC v2
            0x00, // DCID Length: 0
            0x00, // SCID Length: 0
            0x00, // Token Length: 0
            0x00, 0x01, // Minimal payload
        ];

        let result = parse_quic_initial(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.version, QUIC_VERSION_2);
    }

    #[test]
    fn test_parse_quic_initial_too_short() {
        // Too short for parsing
        let data = [0xC0, 0x00, 0x00];
        assert!(parse_quic_initial(&data).is_none());
    }

    #[test]
    fn test_parse_quic_initial_not_initial() {
        // Handshake packet (0xD0)
        let data = [0xD0, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert!(parse_quic_initial(&data).is_none());
    }

    #[test]
    fn test_version_to_string() {
        assert_eq!(
            version_to_string(QUIC_VERSION_1),
            Some("QUIC v1".to_string())
        );
        assert_eq!(
            version_to_string(QUIC_VERSION_2),
            Some("QUIC v2".to_string())
        );
        assert_eq!(
            version_to_string(QUIC_VERSION_DRAFT29),
            Some("QUIC Draft-29".to_string())
        );
        assert_eq!(version_to_string(0), None); // Version negotiation
        assert_eq!(
            version_to_string(0x12345678),
            Some("QUIC 0x12345678".to_string())
        );
    }

    #[test]
    fn test_varint_integration_in_packet() {
        // Test with 2-byte token length varint
        let mut data = vec![
            0xC0, // Long Header + Initial
            0x00, 0x00, 0x00, 0x01, // Version: QUIC v1
            0x00, // DCID Length: 0
            0x00, // SCID Length: 0
            0x40, 0x64, // Token Length: 100 (2-byte varint: 0x4064)
        ];
        data.extend_from_slice(&[0u8; 100]); // Token: 100 zero bytes
        data.extend_from_slice(&[0x00, 0x01]); // Minimal payload

        let result = parse_quic_initial(&data);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.token_len, 100);
    }
}
