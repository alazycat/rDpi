use crate::error::{Error, Result};

pub fn parse(data: &[u8]) -> Result<(&[u8], EthernetHeader)> {
    if data.len() < 14 {
        return Err(Error::TruncatedHeader);
    }

    let ether_type = u16::from_be_bytes([data[12], data[13]]);
    let header = EthernetHeader { ether_type };

    Ok((&data[14..], header))
}

#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub ether_type: u16,
}