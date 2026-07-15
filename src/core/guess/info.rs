//! 猜测引擎上下文

use std::net::IpAddr;

/// 域名信息来源
#[derive(Debug, Clone, Default)]
pub(crate) struct DomainInfo {
    /// TLS/QUIC SNI
    pub sni: Option<String>,
    /// HTTP Host 头
    pub http_host: Option<String>,
    /// DNS 查询域名
    pub dns_query: Option<String>,
}

/// 猜测引擎上下文
#[derive(Debug, Clone, Default)]
pub(crate) struct GuessContext {
    /// 目的端口
    pub dst_port: u16,
    /// 对端 IP 地址（用于 IP 子网匹配）
    pub dst_ip: Option<IpAddr>,
    /// 域名信息（用于域名匹配引擎）
    pub domain_info: DomainInfo,
}

impl GuessContext {
    pub fn new(dst_port: u16) -> Self {
        Self {
            dst_port,
            dst_ip: None,
            domain_info: DomainInfo::default(),
        }
    }
}
