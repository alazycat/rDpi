use crate::core::TransportProto;
use crate::error::{Error, Result};
use crate::parser::ParsedPacket;
use std::net::IpAddr;

pub fn parse(data: &[u8], src_ip: IpAddr, dst_ip: IpAddr) -> Result<ParsedPacket> {
    if data.len() < 8 {
        return Err(Error::TruncatedHeader);
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]) as usize;

    let payload = if data.len() >= length && length > 8 {
        data[8..length].to_vec()
    } else {
        vec![]
    };

    Ok(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        transport: TransportProto::Udp,
        payload,
    })
}
