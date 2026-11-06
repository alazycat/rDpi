mod ethernet;
mod ip;
mod tcp;
mod udp;

pub use tcp::TcpHeaderInfo;

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
    /// TCP 头部关键字段（F33：仅 TCP 包为 Some，供 JA4T 指纹使用）
    pub tcp: Option<TcpHeaderInfo>,
    /// IP TTL / IPv6 hop limit（F41：QUIC JA4L 时延指纹所需，顶层对齐
    /// TcpHeaderInfo.ttl——UDP 路径此前无 TTL 传递）
    pub ttl: u8,
}

/// 解析原始包（以太网帧）
pub fn parse_packet(data: &[u8]) -> Result<ParsedPacket> {
    // 先解析以太网头，再交给 L3 入口
    let (remainder, _eth_header) = ethernet::parse(data)?;
    parse_l3_packet(remainder)
}

/// IP-in-IP 封装协议号：IPv4-in-IP（4）、IPv6-in-IP（41）
const TUNNEL_PROTOCOLS: [u8; 2] = [4, 41];
/// IP-in-IP 解封装深度上限（防止恶意嵌套隧道耗尽栈/时间）
const MAX_TUNNEL_DEPTH: usize = 4;

/// 解析 L3 包（IPv4/IPv6 头起始，不含以太网头）
///
/// 逐层剥离 IP-in-IP 封装（4/41），传输层信息取自最内层；最外层端点
/// 保留为流身份（与 nDPI 一致：隧道流按外层 5 元组归并）。超过
/// [`MAX_TUNNEL_DEPTH`] 时按不透明载荷处理，避免无限递归。
///
/// 与 [`parse_packet`] 共用传输层解析逻辑，供调用方持有 flow 的
/// `Detector::process_l3_packet` 入口使用。
pub fn parse_l3_packet(data: &[u8]) -> Result<ParsedPacket> {
    let (mut remainder, mut ip_info) = ip::parse(data)?;
    let mut depth = 0usize;

    while TUNNEL_PROTOCOLS.contains(&ip_info.protocol) {
        if depth == MAX_TUNNEL_DEPTH {
            return Ok(ParsedPacket {
                src_ip: ip_info.src,
                dst_ip: ip_info.dst,
                src_port: 0,
                dst_port: 0,
                transport: crate::core::TransportProto::Other(ip_info.protocol),
                payload: remainder.to_vec(),
                tcp: None,
                ttl: ip_info.ttl,
            });
        }
        let (inner_remainder, inner_info) = ip::parse(remainder)?;
        ip_info.protocol = inner_info.protocol;
        remainder = inner_remainder;
        depth += 1;
    }

    parse_l4(remainder, ip_info)
}

fn parse_l4(remainder: &[u8], ip_info: ip::IpInfo) -> Result<ParsedPacket> {
    // 根据协议解析传输层
    match ip_info.protocol {
        6 => tcp::parse(remainder, ip_info.src, ip_info.dst, ip_info.ttl),
        17 => udp::parse(remainder, ip_info.src, ip_info.dst, ip_info.ttl),
        1 => {
            // ICMP 没有端口
            Ok(ParsedPacket {
                src_ip: ip_info.src,
                dst_ip: ip_info.dst,
                src_port: 0,
                dst_port: 0,
                transport: crate::core::TransportProto::Icmp,
                payload: remainder.to_vec(),
                tcp: None,
                ttl: ip_info.ttl,
            })
        }
        p => Ok(ParsedPacket {
            src_ip: ip_info.src,
            dst_ip: ip_info.dst,
            src_port: 0,
            dst_port: 0,
            transport: crate::core::TransportProto::Other(p),
            payload: remainder.to_vec(),
            tcp: None,
            ttl: ip_info.ttl,
        }),
    }
}
