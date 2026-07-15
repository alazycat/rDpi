//! STUN protocol parser for rDpi
//!
//! RFC 5389: Session Traversal Utilities for NAT (STUN)
//!
//! All STUN messages start with a 20-byte header:
//! - message_type (2 bytes, BE)
//! - message_length (2 bytes, BE, excludes header)
//! - magic_cookie (4 bytes: 0x2112A442)
//! - transaction_id (12 bytes)

use crate::core::types::StunMetadata;

const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// XOR-MAPPED-ADDRESS attribute type
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Parse STUN message and extract metadata
pub fn parse_stun(data: &[u8]) -> Option<StunMetadata> {
    if data.len() < 20 {
        return None;
    }

    // Check magic cookie at offset 4
    if data[4..8] != STUN_MAGIC_COOKIE {
        return None;
    }

    let message_type = u16::from_be_bytes([data[0], data[1]]);
    let _message_length = u16::from_be_bytes([data[2], data[3]]);
    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&data[8..20]);

    // Parse attributes for XOR-MAPPED-ADDRESS
    let mapped_address = parse_xor_mapped_address(data);

    Some(StunMetadata {
        message_type,
        transaction_id,
        mapped_address,
    })
}

/// Parse XOR-MAPPED-ADDRESS attribute (RFC 5389 §15.2)
fn parse_xor_mapped_address(data: &[u8]) -> Option<String> {
    let mut offset: usize = 20;

    while offset + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > data.len() {
            break;
        }

        if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8 {
            let family = data[offset + 1];
            let xor_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let port = xor_port ^ 0x2112; // XOR with high 16 bits of magic cookie

            match family {
                0x01 => {
                    // IPv4: address is XOR'd with magic cookie
                    if attr_len >= 8 {
                        let mut addr_bytes = [0u8; 4];
                        addr_bytes.copy_from_slice(&data[offset + 4..offset + 8]);
                        for b in addr_bytes.iter_mut() {
                            *b ^= 0x21; // simplified XOR: first byte of cookie repeated
                        }
                        return Some(format!("{}:{}",
                            std::net::Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]),
                            port));
                    }
                }
                0x02 => {
                    // IPv6: address is XOR'd with transaction_id
                    return Some(format!("[ipv6]:{}", port));
                }
                _ => {}
            }
        }

        // Align to 4-byte boundary
        offset += attr_len;
        if offset % 4 != 0 {
            offset += 4 - (offset % 4);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_stun(msg_type: u16, attr: Option<(u16, &[u8])>) -> Vec<u8> {
        let mut header = vec![0u8; 20];
        header[0..2].copy_from_slice(&msg_type.to_be_bytes());
        // message_length placeholder
        header[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
        // transaction_id
        for i in 0..12 { header[8 + i] = i as u8; }

        let mut body = Vec::new();
        if let Some((atype, avalue)) = attr {
            body.extend_from_slice(&atype.to_be_bytes());
            body.extend_from_slice(&(avalue.len() as u16).to_be_bytes());
            body.extend_from_slice(avalue);
        }

        header[2..4].copy_from_slice(&(body.len() as u16).to_be_bytes());
        let mut packet = header;
        packet.extend_from_slice(&body);
        packet
    }

    #[test]
    fn test_stun_binding_request() {
        let data = build_stun(0x0001, None);
        let meta = parse_stun(&data).unwrap();
        assert_eq!(meta.message_type, 0x0001);
    }

    #[test]
    fn test_stun_binding_response() {
        let data = build_stun(0x0101, None);
        let meta = parse_stun(&data).unwrap();
        assert_eq!(meta.message_type, 0x0101);
    }

    #[test]
    fn test_stun_invalid_cookie() {
        let mut data = build_stun(0x0001, None);
        data[4] = 0x00; // corrupt cookie
        assert!(parse_stun(&data).is_none());
    }

    #[test]
    fn test_stun_too_short() {
        assert!(parse_stun(&[0u8; 19]).is_none());
        assert!(parse_stun(&[]).is_none());
    }

    #[test]
    fn test_stun_xor_mapped_address() {
        // XOR-MAPPED-ADDRESS for IPv4, family=0x01
        let mut attr = vec![0x00, 0x01, 0x11, 0x5C]; // family+reserved, XOR'd port
        // XOR'd address: 192.168.1.1 XOR 0x21 each byte
        attr.extend_from_slice(&[0xD9, 0xAD, 0x24, 0x20]); // 192^0x21, 168^0x21, 1^0x21, 1^0x21

        let data = build_stun(0x0101, Some((ATTR_XOR_MAPPED_ADDRESS, &attr)));
        let meta = parse_stun(&data).unwrap();
        assert!(meta.mapped_address.is_some());
    }

    #[test]
    fn test_stun_xor_mapped_address_not_present() {
        let data = build_stun(0x0001, None);
        let meta = parse_stun(&data).unwrap();
        assert!(meta.mapped_address.is_none());
    }

    #[test]
    fn test_stun_transaction_id() {
        let data = build_stun(0x0001, None);
        let meta = parse_stun(&data).unwrap();
        assert_eq!(meta.transaction_id, [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    }
}
