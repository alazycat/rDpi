//! NTP protocol parser for rDpi
//!
//! Parses NTP (Network Time Protocol) packets and extracts metadata.

use crate::core::types::{DetectionResult, Metadata, NtpMetadata, Protocol};

/// NTP packet header (first byte contains LI, VN, Mode)
///
/// First byte structure:
/// Bits 0-1: LI (Leap Indicator)
/// Bits 2-4: VN (Version Number)
/// Bits 5-7: Mode
#[derive(Debug, Clone)]
pub struct NtpHeader {
    pub leap_indicator: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
}

/// Parse NTP packet header
///
/// Returns None if:
/// - Packet is too short (< 48 bytes)
/// - Version is invalid (not 1-4)
/// - Mode is invalid (0 is reserved)
pub fn parse_ntp_packet(data: &[u8]) -> Option<NtpHeader> {
    // NTP packets are at least 48 bytes
    if data.len() < 48 {
        return None;
    }

    // Parse first byte
    let first_byte = data[0];

    // LI: bits 0-1 (shift right 6 bits)
    let leap_indicator = (first_byte >> 6) & 0x03;

    // VN: bits 2-4 (shift right 3 bits, mask 3 bits)
    let version = (first_byte >> 3) & 0x07;

    // Mode: bits 5-7 (mask 3 bits)
    let mode = first_byte & 0x07;

    // Validate version (1-4)
    if version < 1 || version > 4 {
        return None;
    }

    // Validate mode (0 is reserved, 1-7 valid)
    if mode == 0 {
        return None;
    }

    // Parse stratum (second byte)
    let stratum = data[1];

    // Validate stratum (0-15, 16 is unsynchronized)
    if stratum > 16 {
        return None;
    }

    Some(NtpHeader {
        leap_indicator,
        version,
        mode,
        stratum,
    })
}

/// Detect NTP protocol from packet
pub fn detect_ntp(data: &[u8]) -> Option<DetectionResult> {
    let header = parse_ntp_packet(data)?;

    Some(
        DetectionResult::new(Protocol::Ntp).with_metadata(Metadata::Ntp(NtpMetadata {
            version: header.version,
            mode: header.mode,
            stratum: header.stratum,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal NTP packet for testing
    fn create_ntp_packet(version: u8, mode: u8, stratum: u8) -> Vec<u8> {
        let first_byte = (version << 3) | (mode & 0x07);
        let mut packet = vec![0u8; 48];
        packet[0] = first_byte;
        packet[1] = stratum;
        packet
    }

    #[test]
    fn test_parse_ntp_packet_v4_client() {
        // Version 4, Mode 3 (client), Stratum 1
        let packet = create_ntp_packet(4, 3, 1);
        let header = parse_ntp_packet(&packet).unwrap();
        assert_eq!(header.version, 4);
        assert_eq!(header.mode, 3);
        assert_eq!(header.stratum, 1);
    }

    #[test]
    fn test_parse_ntp_packet_v4_server() {
        // Version 4, Mode 4 (server), Stratum 2
        let packet = create_ntp_packet(4, 4, 2);
        let header = parse_ntp_packet(&packet).unwrap();
        assert_eq!(header.version, 4);
        assert_eq!(header.mode, 4);
        assert_eq!(header.stratum, 2);
    }

    #[test]
    fn test_parse_ntp_packet_v3() {
        let packet = create_ntp_packet(3, 3, 1);
        let header = parse_ntp_packet(&packet).unwrap();
        assert_eq!(header.version, 3);
    }

    #[test]
    fn test_parse_ntp_packet_v2() {
        let packet = create_ntp_packet(2, 3, 1);
        let header = parse_ntp_packet(&packet).unwrap();
        assert_eq!(header.version, 2);
    }

    #[test]
    fn test_parse_ntp_packet_v1() {
        let packet = create_ntp_packet(1, 3, 1);
        let header = parse_ntp_packet(&packet).unwrap();
        assert_eq!(header.version, 1);
    }

    #[test]
    fn test_parse_ntp_packet_mode_symmetric_active() {
        // Mode 1: symmetric active
        let packet = create_ntp_packet(4, 1, 1);
        let header = parse_ntp_packet(&packet).unwrap();
        assert_eq!(header.mode, 1);
    }

    #[test]
    fn test_parse_ntp_packet_mode_symmetric_passive() {
        // Mode 2: symmetric passive
        let packet = create_ntp_packet(4, 2, 1);
        let header = parse_ntp_packet(&packet).unwrap();
        assert_eq!(header.mode, 2);
    }

    #[test]
    fn test_parse_ntp_packet_mode_broadcast() {
        // Mode 5: broadcast
        let packet = create_ntp_packet(4, 5, 1);
        let header = parse_ntp_packet(&packet).unwrap();
        assert_eq!(header.mode, 5);
    }

    #[test]
    fn test_parse_ntp_packet_too_short() {
        let packet = vec![0u8; 47];
        assert!(parse_ntp_packet(&packet).is_none());
    }

    #[test]
    fn test_parse_ntp_packet_invalid_version_0() {
        let packet = create_ntp_packet(0, 3, 1);
        assert!(parse_ntp_packet(&packet).is_none());
    }

    #[test]
    fn test_parse_ntp_packet_invalid_version_5() {
        let packet = create_ntp_packet(5, 3, 1);
        assert!(parse_ntp_packet(&packet).is_none());
    }

    #[test]
    fn test_parse_ntp_packet_invalid_mode_0() {
        let packet = create_ntp_packet(4, 0, 1);
        assert!(parse_ntp_packet(&packet).is_none());
    }

    #[test]
    fn test_parse_ntp_packet_stratum_16() {
        // Stratum 16 (unsynchronized) is valid
        let packet = create_ntp_packet(4, 4, 16);
        let header = parse_ntp_packet(&packet).unwrap();
        assert_eq!(header.stratum, 16);
    }

    #[test]
    fn test_parse_ntp_packet_invalid_stratum_17() {
        let packet = create_ntp_packet(4, 4, 17);
        assert!(parse_ntp_packet(&packet).is_none());
    }

    #[test]
    fn test_detect_ntp() {
        let packet = create_ntp_packet(4, 3, 2);
        let result = detect_ntp(&packet).unwrap();
        assert_eq!(result.protocol, Protocol::Ntp);

        if let Metadata::Ntp(meta) = result.metadata {
            assert_eq!(meta.version, 4);
            assert_eq!(meta.mode, 3);
            assert_eq!(meta.stratum, 2);
        } else {
            panic!("Expected Ntp metadata");
        }
    }

    #[test]
    fn test_detect_ntp_invalid() {
        let packet = vec![0u8; 47];
        assert!(detect_ntp(&packet).is_none());
    }
}