mod ethernet;
mod ip;
mod tcp;
mod udp;

use crate::error::Result;

/// 解析后的包信息
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub src_ip: std::net::IpAddr,
    pub dst_ip: std::net::IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub transport: crate::core::TransportProto,
    pub payload: Vec<u8>,
}

/// 解析原始包
pub fn parse_packet(data: &[u8]) -> Result<ParsedPacket> {
    // 先解析以太网头
    let (remainder, _eth_header) = ethernet::parse(data)?;

    // 再解析 IP 头
    let (remainder, ip_info) = ip::parse(remainder)?;

    // 根据协议解析传输层
    match ip_info.protocol {
        6 => tcp::parse(remainder, ip_info.src, ip_info.dst),
        17 => udp::parse(remainder, ip_info.src, ip_info.dst),
        1 => {
            // ICMP 没有端口
            Ok(ParsedPacket {
                src_ip: ip_info.src,
                dst_ip: ip_info.dst,
                src_port: 0,
                dst_port: 0,
                transport: crate::core::TransportProto::Icmp,
                payload: remainder.to_vec(),
            })
        }
        p => Ok(ParsedPacket {
            src_ip: ip_info.src,
            dst_ip: ip_info.dst,
            src_port: 0,
            dst_port: 0,
            transport: crate::core::TransportProto::Other(p),
            payload: remainder.to_vec(),
        }),
    }
}
