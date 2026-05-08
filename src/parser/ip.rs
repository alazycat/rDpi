use crate::error::{Error, Result};
use std::net::IpAddr;

pub fn parse(data: &[u8]) -> Result<(&[u8], IpInfo)> {
    if data.is_empty() {
        return Err(Error::TruncatedHeader);
    }

    let version = data[0] >> 4;

    match version {
        4 => parse_ipv4(data),
        6 => parse_ipv6(data),
        _ => Err(Error::InvalidPacket(format!("Unknown IP version: {}", version))),
    }
}

fn parse_ipv4(data: &[u8]) -> Result<(&[u8], IpInfo)> {
    if data.len() < 20 {
        return Err(Error::TruncatedHeader);
    }

    let ihl = (data[0] & 0x0f) as usize * 4;
    if data.len() < ihl {
        return Err(Error::TruncatedHeader);
    }

    let src = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let protocol = data[9];

    Ok((
        &data[ihl..],
        IpInfo {
            src: IpAddr::V4(src),
            dst: IpAddr::V4(dst),
            protocol,
        },
    ))
}

fn parse_ipv6(data: &[u8]) -> Result<(&[u8], IpInfo)> {
    if data.len() < 40 {
        return Err(Error::TruncatedHeader);
    }

    let src_bytes: [u8; 16] = data[8..24].try_into().unwrap();
    let dst_bytes: [u8; 16] = data[24..40].try_into().unwrap();

    let src = std::net::Ipv6Addr::from(src_bytes);
    let dst = std::net::Ipv6Addr::from(dst_bytes);
    let protocol = data[6];

    Ok((
        &data[40..],
        IpInfo {
            src: IpAddr::V6(src),
            dst: IpAddr::V6(dst),
            protocol,
        },
    ))
}

#[derive(Debug, Clone)]
pub struct IpInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
}