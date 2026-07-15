//! 猜测引擎上下文

use std::net::IpAddr;

/// 猜测引擎上下文
#[derive(Debug, Clone, Default)]
pub(crate) struct GuessContext {
    /// 目的端口
    pub dst_port: u16,
    /// 对端 IP 地址（用于 IP 子网匹配）
    pub dst_ip: Option<IpAddr>,
}

impl GuessContext {
    pub fn new(dst_port: u16) -> Self {
        Self {
            dst_port,
            dst_ip: None,
        }
    }
}
