//! Memcached protocol detection module for rDpi
//!
//! 支持 nDPI 5.0 的文本命令/响应签名（TCP 11211 或非标端口 2 次匹配）
//! 与 UDP 请求头（仅 11211）。

mod detector;
mod parser;

pub use detector::MemcachedDetector;
pub use parser::{MemcachedParsed, parse_memcached, parse_memcached_udp};

use crate::protocols::Registry;

/// Register Memcached detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(MemcachedDetector::new()));
}
