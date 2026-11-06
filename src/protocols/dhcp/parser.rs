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

/// DHCP 选项区解析结果（JA4D 指纹输入，F37）
///
/// 从偏移 240（magic cookie 之后）遍历 TLV 选项：
/// - option 0（Pad，无长度字段）跳过 1 字节继续；
/// - option 255（End，无长度字段）终止遍历；
/// - 其余选项为 code(1) + len(1) + value(len)，截断时停止。
#[derive(Debug, Clone, Default)]
pub struct DhcpOptions {
    /// option 53 消息类型（缺省 None → JA4D 首段 "00000"）
    pub msg_type: Option<u8>,
    /// option 57 最大报文尺寸（缺省 None → JA4D 尺寸段 "0000"）
    pub max_msg_size: Option<u16>,
    /// option 50（Requested IP）出现标志 → JA4D 第 3 段 'i'
    pub has_requested_ip: bool,
    /// option 81（Client FQDN）出现标志 → JA4D 第 4 段 'd'
    pub has_fqdn: bool,
    /// 选项码列表（按包内出现序，剔除 0/53/50/81，含 57）
    pub option_codes: Vec<u16>,
    /// option 55 参数请求列表（按包内字节序）
    pub param_req_list: Vec<u16>,
}

/// 解析 DHCP 选项区（偏移 240 起），提取 JA4D 指纹所需字段
///
/// 畸形输入（长度越界）就地停止，返回已解析部分，不产生错误。
pub fn parse_dhcp_options(data: &[u8]) -> DhcpOptions {
    let mut opts = DhcpOptions::default();
    let mut i = 240;
    while i < data.len() {
        let code = data[i];
        i += 1;
        match code {
            0 => continue, // Pad：无长度字段
            255 => break,  // End：终止遍历
            _ => {}
        }
        if i >= data.len() {
            break;
        }
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            break; // 值被截断，停止解析
        }
        let value = &data[i..i + len];
        match code {
            53 => opts.msg_type = value.first().copied(),
            57 => {
                if len >= 2 {
                    opts.max_msg_size = Some(u16::from_be_bytes([value[0], value[1]]));
                }
                opts.option_codes.push(57);
            }
            50 => opts.has_requested_ip = true,
            81 => opts.has_fqdn = true,
            55 => {
                // 55 出现在选项列表（zeek 仅剔除 53/50/81），其值进参数请求列表
                opts.option_codes.push(55);
                opts.param_req_list.extend(value.iter().map(|&b| b as u16));
            }
            _ => opts.option_codes.push(code as u16),
        }
        i += len;
    }
    opts
}

/// Detect DHCP protocol from packet
pub fn detect_dhcp(data: &[u8]) -> Option<DetectionResult> {
    let header = parse_dhcp_packet(data)?;
    let opts = parse_dhcp_options(data);
    let ja4d = crate::application::compute_ja4d(
        opts.msg_type,
        opts.max_msg_size,
        opts.has_requested_ip,
        opts.has_fqdn,
        &opts.option_codes,
        &opts.param_req_list,
    );

    Some(
        DetectionResult::new(Protocol::Dhcp).with_metadata(Metadata::Dhcp(DhcpMetadata {
            opcode: header.opcode,
            client_mac: header.client_mac,
            ja4d,
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
