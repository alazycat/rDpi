use crate::error::{Error, Result};

/// 802.1Q / 802.1ad（QinQ）/ legacy 0x9100 的 VLAN TPID
const VLAN_TPIDS: [u16; 3] = [0x8100, 0x88A8, 0x9100];
/// VLAN 标签栈深度上限（防止恶意嵌套消耗解析时间）
const MAX_VLAN_TAGS: usize = 4;

pub fn parse(data: &[u8]) -> Result<(&[u8], EthernetHeader)> {
    if data.len() < 14 {
        return Err(Error::TruncatedHeader);
    }

    let mut ether_type = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14usize;
    let mut vlan_tags = 0usize;

    // 每个 VLAN 标签为 4 字节：2 字节 TCI + 2 字节内层 EtherType/TPID
    while VLAN_TPIDS.contains(&ether_type) {
        if vlan_tags == MAX_VLAN_TAGS {
            return Err(Error::InvalidPacket("too many VLAN tags".to_string()));
        }
        if data.len() < offset + 4 {
            return Err(Error::TruncatedHeader);
        }
        ether_type = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
        vlan_tags += 1;
    }

    let header = EthernetHeader { ether_type };

    Ok((&data[offset..], header))
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Field reserved for future use
pub struct EthernetHeader {
    pub ether_type: u16,
}
