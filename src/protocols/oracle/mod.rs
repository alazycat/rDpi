//! Oracle TNS protocol detection module for rDpi
//!
//! 识别 TCP 1521 上的 TNS Connect 报文头（8 字节）。

mod detector;
pub mod parser;

pub use detector::OracleDetector;
pub use parser::{ORACLE_CONNECT_HEADER_LEN, OracleParsed, parse_oracle_connect};

use crate::protocols::Registry;

/// Register Oracle detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(OracleDetector::new()));
}
