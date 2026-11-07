//! Memcached protocol detection module for rDpi
//!
//! 支持 nDPI 5.0 的文本命令/响应签名（TCP 11211 或非标端口 2 次匹配）
//! 与 UDP 请求头（仅 11211）。

mod parser;

pub use parser::{MemcachedParsed, parse_memcached, parse_memcached_udp};
