//! WireGuard protocol parser for rDpi
//!
//! Parses WireGuard handshake messages for protocol identification.
//!
//! ## Wire Format
//!
//! All WireGuard messages start with:
//! - Byte 0: message_type (u8): 1=Initiation, 2=Response, 3=CookieReply, 4=Transport
//! - Byte 1-3: reserved_zero (must be 0x00 0x00 0x00)
//! - Byte 4-7: sender_index (u32, little-endian)
//!
//! See https://www.wireguard.com/protocol/ for full reference.

use crate::core::types::WireGuardMetadata;

/// Minimum type values for each WireGuard message type
const MIN_LEN_INITIATION: usize = 148;   // Handshake Initiation
const MIN_LEN_RESPONSE: usize = 128;     // Handshake Response
const MIN_LEN_COOKIE: usize = 64;        // Cookie Reply
const MIN_LEN_TRANSPORT: usize = 32;     // Transport Data

/// Parse WireGuard handshake message
///
/// Validates:
/// 1. message_type ∈ {1, 2, 3, 4}
/// 2. reserved bytes (1-3) are zero
/// 3. payload length >= minimum for the message type
pub fn parse_wireguard_handshake(data: &[u8]) -> Option<WireGuardMetadata> {
    // Minimum: header(4) + sender_index(4) = 8 bytes
    if data.len() < 8 {
        return None;
    }

    // Message type must be 1-4
    let message_type = data[0];
    if message_type < 1 || message_type > 4 {
        return None;
    }

    // Reserved bytes must be zero
    if data[1] != 0 || data[2] != 0 || data[3] != 0 {
        return None;
    }

    // Minimum length check per message type
    let min_len = match message_type {
        1 => MIN_LEN_INITIATION,
        2 => MIN_LEN_RESPONSE,
        3 => MIN_LEN_COOKIE,
        4 => MIN_LEN_TRANSPORT,
        _ => return None,
    };
    if data.len() < min_len {
        return None;
    }

    // Read sender index (bytes 4-7, little-endian)
    let sender_index = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    Some(WireGuardMetadata {
        message_type,
        sender_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_wg_message(msg_type: u8, sender_index: u32, extra_len: usize) -> Vec<u8> {
        let mut packet = Vec::with_capacity(8 + extra_len);
        packet.push(msg_type);
        packet.extend_from_slice(&[0x00, 0x00, 0x00]); // reserved
        packet.extend_from_slice(&sender_index.to_le_bytes());
        packet.extend_from_slice(&vec![0u8; extra_len]);
        packet
    }

    #[test]
    fn test_parse_wg_initiation() {
        // Initiation: type=1, extra_len >= 140 (total >= 148)
        let data = build_wg_message(1, 0x12345678, 140);
        let meta = parse_wireguard_handshake(&data).unwrap();

        assert_eq!(meta.message_type, 1);
        assert_eq!(meta.sender_index, 0x12345678);
    }

    #[test]
    fn test_parse_wg_response() {
        let data = build_wg_message(2, 0x87654321, 120);
        let meta = parse_wireguard_handshake(&data).unwrap();

        assert_eq!(meta.message_type, 2);
        assert_eq!(meta.sender_index, 0x87654321);
    }

    #[test]
    fn test_parse_wg_cookie_reply() {
        let data = build_wg_message(3, 0x11111111, 56);
        let meta = parse_wireguard_handshake(&data).unwrap();

        assert_eq!(meta.message_type, 3);
    }

    #[test]
    fn test_parse_wg_transport_data() {
        let data = build_wg_message(4, 0x22222222, 24);
        let meta = parse_wireguard_handshake(&data).unwrap();

        assert_eq!(meta.message_type, 4);
    }

    #[test]
    fn test_parse_wg_invalid_type() {
        // type=0 (invalid)
        let data = build_wg_message(0, 0, 100);
        assert!(parse_wireguard_handshake(&data).is_none());

        // type=5 (invalid)
        let data = build_wg_message(5, 0, 100);
        assert!(parse_wireguard_handshake(&data).is_none());
    }

    #[test]
    fn test_parse_wg_reserved_nonzero() {
        let mut data = build_wg_message(1, 0x12345678, 140);
        data[1] = 0x01; // reserved byte non-zero
        assert!(parse_wireguard_handshake(&data).is_none());
    }

    #[test]
    fn test_parse_wg_too_short() {
        assert!(parse_wireguard_handshake(&[]).is_none());
        assert!(parse_wireguard_handshake(&[0x01, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_parse_wg_initiation_too_short() {
        // Initiation with not enough extra data
        let data = build_wg_message(1, 0, 100); // total = 108 < 148
        assert!(parse_wireguard_handshake(&data).is_none());
    }

    #[test]
    fn test_parse_wg_zero_sender_index() {
        let data = build_wg_message(1, 0, 140);
        let meta = parse_wireguard_handshake(&data).unwrap();
        assert_eq!(meta.sender_index, 0); // valid, first handshake
    }
}
