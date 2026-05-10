//! DHCP protocol parser for rDpi
//!
//! Parses DHCP (Dynamic Host Configuration Protocol) packets and extracts metadata.

use crate::core::types::{DetectionResult, DhcpMetadata, Metadata, Protocol};

/// DHCP Magic Cookie (RFC 1497)
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// DHCP packet header structure
///
/// Key fields for identification and metadata:
/// - op: Opcode (1=BOOTREQUEST/client, 2=BOOTREPLY/server)
/// - htype: Hardware type (1=Ethernet)
/// - hlen: Hardware address length (6 for Ethernet MAC)
/// - chaddr: Client hardware address (MAC)
#[derive(Debug, Clone)]
pub struct DhcpHeader {
    pub opcode: u8,
    pub htype: u8,
    pub hlen: u8,
    pub client_mac: [u8; 6],
}

/// Parse DHCP packet header
///
/// Returns None if:
/// - Packet is too short (< 244 bytes minimum)
/// - Opcode is invalid (not 1 or 2)
/// - Hardware type is not Ethernet (1)
/// - Hardware address length is not 6
/// - Magic cookie is missing or invalid
pub fn parse_dhcp_packet(data: &[u8]) -> Option<DhcpHeader> {
    // Minimum DHCP packet with magic cookie at offset 236
    // 236 bytes header + 4 bytes magic cookie + 4 bytes minimal options
    if data.len() < 244 {
        return None;
    }

    // Parse opcode (first byte)
    let opcode = data[0];

    // Validate opcode (1=request, 2=reply)
    if opcode != 1 && opcode != 2 {
        return None;
    }

    // Parse htype (hardware type, second byte)
    let htype = data[1];

    // Validate htype (1=Ethernet)
    if htype != 1 {
        return None;
    }

    // Parse hlen (hardware address length, third byte)
    let hlen = data[2];

    // Validate hlen (6 for Ethernet MAC)
    if hlen != 6 {
        return None;
    }

    // Extract client hardware address (MAC)
    // chaddr starts at offset 28, 16 bytes total, but MAC is first 6 bytes
    let client_mac: [u8; 6] = data[28..34].try_into().ok()?;

    // Validate magic cookie at offset 236
    if data[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }

    Some(DhcpHeader {
        opcode,
        htype,
        hlen,
        client_mac,
    })
}

/// Detect DHCP protocol from packet
pub fn detect_dhcp(data: &[u8]) -> Option<DetectionResult> {
    let header = parse_dhcp_packet(data)?;

    Some(
        DetectionResult::new(Protocol::Dhcp).with_metadata(Metadata::Dhcp(DhcpMetadata {
            opcode: header.opcode,
            client_mac: header.client_mac,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal DHCP packet for testing
    fn create_dhcp_packet(opcode: u8, mac: [u8; 6]) -> Vec<u8> {
        let mut packet = vec![0u8; 244];

        // Opcode
        packet[0] = opcode;

        // Hardware type (Ethernet)
        packet[1] = 1;

        // Hardware address length (6 for MAC)
        packet[2] = 6;

        // Client MAC address at offset 28-33
        packet[28..34].copy_from_slice(&mac);

        // Magic cookie at offset 236-239
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        packet
    }

    #[test]
    fn test_parse_dhcp_packet_request() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let packet = create_dhcp_packet(1, mac);
        let header = parse_dhcp_packet(&packet).unwrap();

        assert_eq!(header.opcode, 1);
        assert_eq!(header.htype, 1);
        assert_eq!(header.hlen, 6);
        assert_eq!(header.client_mac, mac);
    }

    #[test]
    fn test_parse_dhcp_packet_reply() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let packet = create_dhcp_packet(2, mac);
        let header = parse_dhcp_packet(&packet).unwrap();

        assert_eq!(header.opcode, 2);
        assert_eq!(header.client_mac, mac);
    }

    #[test]
    fn test_parse_dhcp_packet_too_short() {
        let packet = vec![0u8; 243];
        assert!(parse_dhcp_packet(&packet).is_none());
    }

    #[test]
    fn test_parse_dhcp_packet_invalid_opcode_0() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let packet = create_dhcp_packet(0, mac);
        assert!(parse_dhcp_packet(&packet).is_none());
    }

    #[test]
    fn test_parse_dhcp_packet_invalid_opcode_3() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let packet = create_dhcp_packet(3, mac);
        assert!(parse_dhcp_packet(&packet).is_none());
    }

    #[test]
    fn test_parse_dhcp_packet_invalid_htype() {
        let mut packet = create_dhcp_packet(1, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        packet[1] = 2; // Invalid hardware type
        assert!(parse_dhcp_packet(&packet).is_none());
    }

    #[test]
    fn test_parse_dhcp_packet_invalid_hlen() {
        let mut packet = create_dhcp_packet(1, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        packet[2] = 4; // Invalid hardware length
        assert!(parse_dhcp_packet(&packet).is_none());
    }

    #[test]
    fn test_parse_dhcp_packet_invalid_magic_cookie() {
        let mut packet = create_dhcp_packet(1, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        packet[236] = 0x00; // Invalid magic cookie
        assert!(parse_dhcp_packet(&packet).is_none());
    }

    #[test]
    fn test_detect_dhcp_request() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let packet = create_dhcp_packet(1, mac);
        let result = detect_dhcp(&packet).unwrap();

        assert_eq!(result.protocol, Protocol::Dhcp);

        if let Metadata::Dhcp(meta) = result.metadata {
            assert_eq!(meta.opcode, 1);
            assert_eq!(meta.client_mac, mac);
        } else {
            panic!("Expected Dhcp metadata");
        }
    }

    #[test]
    fn test_detect_dhcp_reply() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let packet = create_dhcp_packet(2, mac);
        let result = detect_dhcp(&packet).unwrap();

        assert_eq!(result.protocol, Protocol::Dhcp);

        if let Metadata::Dhcp(meta) = result.metadata {
            assert_eq!(meta.opcode, 2);
            assert_eq!(meta.client_mac, mac);
        } else {
            panic!("Expected Dhcp metadata");
        }
    }

    #[test]
    fn test_detect_dhcp_invalid() {
        let packet = vec![0u8; 243];
        assert!(detect_dhcp(&packet).is_none());
    }

    #[test]
    fn test_magic_cookie_value() {
        assert_eq!(DHCP_MAGIC_COOKIE, [0x63, 0x82, 0x53, 0x63]);
    }
}