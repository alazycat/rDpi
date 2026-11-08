//! 支持的链路层类型与 L3 载荷定位。
//!
//! 不伪造以太网头：SLL/SLL2/RAW 帧只剥离链路层头，返回 IPv4/IPv6 起始切片。

/// 支持的链路层类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// DLT_EN10MB (1)
    Ethernet,
    /// DLT_LINUX_SLL (113)
    LinuxSll,
    /// DLT_LINUX_SLL2 (276)
    LinuxSll2,
    /// DLT_RAW (12) / DLT_IPV4 (228) / DLT_IPV6 (229)
    RawIp,
}

/// VLAN TPID（与 `parser::ethernet` 保持一致）
const VLAN_TPIDS: [u16; 3] = [0x8100, 0x88a8, 0x9100];
/// VLAN 标签栈深度上限（防止恶意嵌套消耗解析时间）
const MAX_VLAN_TAGS: usize = 4;

impl LinkType {
    /// 从 `pcap_datalink` 值映射；不支持时返回 `None`。
    pub fn from_datalink(datalink: i32) -> Option<Self> {
        match datalink {
            1 => Some(Self::Ethernet),
            113 => Some(Self::LinuxSll),
            276 => Some(Self::LinuxSll2),
            12 | 228 | 229 => Some(Self::RawIp),
            _ => None,
        }
    }

    /// 剥离链路层头，返回 IPv4/IPv6 起始切片；非 IP 或截断返回 `None`。
    pub fn l3_payload<'a>(&self, frame: &'a [u8]) -> Option<&'a [u8]> {
        match self {
            Self::Ethernet => ethernet_payload(frame),
            Self::LinuxSll => sll_l3_payload(frame, 16, 14),
            Self::LinuxSll2 => sll_l3_payload(frame, 20, 0),
            Self::RawIp => raw_ip_payload(frame),
        }
    }
}

fn ethernet_payload(frame: &[u8]) -> Option<&[u8]> {
    let (payload, ether_type) = crate::parser::ethernet_l3_payload(frame).ok()?;
    is_ip_protocol(ether_type).then_some(payload)
}

/// SLL（16 字节头）与 SLL2（20 字节头）共用剥离逻辑。
///
/// `protocol_offset` 是协议字段在帧内的偏移：SLL 为 14，SLL2 为 0。
fn sll_l3_payload(frame: &[u8], header_len: usize, protocol_offset: usize) -> Option<&[u8]> {
    if frame.len() < header_len {
        return None;
    }
    let mut protocol = u16::from_be_bytes([frame[protocol_offset], frame[protocol_offset + 1]]);
    let mut offset = header_len;
    let mut tags = 0usize;

    while VLAN_TPIDS.contains(&protocol) {
        if tags == MAX_VLAN_TAGS || frame.len() < offset + 4 {
            return None;
        }
        protocol = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
        tags += 1;
    }

    is_ip_protocol(protocol).then(|| &frame[offset..])
}

fn raw_ip_payload(frame: &[u8]) -> Option<&[u8]> {
    match frame.first().map(|byte| byte >> 4) {
        Some(4 | 6) => Some(frame),
        _ => None,
    }
}

fn is_ip_protocol(protocol: u16) -> bool {
    matches!(protocol, 0x0800 | 0x86dd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ether_type.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4_header() -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet
    }

    fn ipv6_header() -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet
    }

    #[test]
    fn from_datalink_maps_supported_values() {
        assert_eq!(LinkType::from_datalink(1), Some(LinkType::Ethernet));
        assert_eq!(LinkType::from_datalink(113), Some(LinkType::LinuxSll));
        assert_eq!(LinkType::from_datalink(276), Some(LinkType::LinuxSll2));
        assert_eq!(LinkType::from_datalink(12), Some(LinkType::RawIp));
        assert_eq!(LinkType::from_datalink(228), Some(LinkType::RawIp));
        assert_eq!(LinkType::from_datalink(229), Some(LinkType::RawIp));
        assert_eq!(LinkType::from_datalink(0), None);
    }

    #[test]
    fn ethernet_strips_header_and_vlan_stack() {
        let ipv4 = ipv4_header();
        let frame = ethernet(0x0800, &ipv4);
        assert_eq!(LinkType::Ethernet.l3_payload(&frame), Some(ipv4.as_slice()));

        let mut vlan = Vec::new();
        vlan.extend_from_slice(&0x0001u16.to_be_bytes());
        vlan.extend_from_slice(&0x0800u16.to_be_bytes());
        vlan.extend_from_slice(&ipv4);
        let frame = ethernet(0x8100, &vlan);
        assert_eq!(LinkType::Ethernet.l3_payload(&frame), Some(ipv4.as_slice()));

        let mut qinq = Vec::new();
        qinq.extend_from_slice(&0x0001u16.to_be_bytes());
        qinq.extend_from_slice(&0x8100u16.to_be_bytes());
        qinq.extend_from_slice(&0x0002u16.to_be_bytes());
        qinq.extend_from_slice(&0x0800u16.to_be_bytes());
        qinq.extend_from_slice(&ipv4);
        let frame = ethernet(0x88a8, &qinq);
        assert_eq!(LinkType::Ethernet.l3_payload(&frame), Some(ipv4.as_slice()));
    }

    #[test]
    fn sll_strips_16_byte_header() {
        let ipv4 = ipv4_header();
        let mut frame = vec![0u8; 14];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ipv4);
        assert_eq!(LinkType::LinuxSll.l3_payload(&frame), Some(ipv4.as_slice()));
    }

    #[test]
    fn sll2_strips_20_byte_header() {
        let ipv4 = ipv4_header();
        let mut frame = Vec::new();
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 18]);
        frame.extend_from_slice(&ipv4);
        assert_eq!(
            LinkType::LinuxSll2.l3_payload(&frame),
            Some(ipv4.as_slice())
        );
    }

    #[test]
    fn sll_vlan_tag_shifts_payload() {
        let ipv4 = ipv4_header();
        let mut frame = vec![0u8; 14];
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&0x0001u16.to_be_bytes());
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ipv4);
        assert_eq!(LinkType::LinuxSll.l3_payload(&frame), Some(ipv4.as_slice()));
    }

    #[test]
    fn raw_requires_ip_version_nibble() {
        let ipv4 = ipv4_header();
        assert_eq!(LinkType::RawIp.l3_payload(&ipv4), Some(ipv4.as_slice()));
        let ipv6 = ipv6_header();
        assert_eq!(LinkType::RawIp.l3_payload(&ipv6), Some(ipv6.as_slice()));
        assert_eq!(LinkType::RawIp.l3_payload(&[0x00, 0x01]), None);
        assert_eq!(LinkType::RawIp.l3_payload(&[]), None);
    }

    #[test]
    fn non_ip_and_truncated_frames_return_none() {
        let arp = ethernet(0x0806, &[0u8; 28]);
        assert_eq!(LinkType::Ethernet.l3_payload(&arp), None);
        assert_eq!(LinkType::Ethernet.l3_payload(&[0u8; 10]), None);
        assert_eq!(LinkType::LinuxSll.l3_payload(&[0u8; 10]), None);
        assert_eq!(LinkType::LinuxSll2.l3_payload(&[0u8; 10]), None);
    }
}
