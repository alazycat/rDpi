//! MSSQL/TDS protocol detection module for rDpi
//!
//! 识别 TDS 报文头（8 字节）并提取类型/状态/长度/通道/报文序号。

mod detector;
mod parser;

pub use detector::MssqlDetector;
pub use parser::{MSSQL_TDS_HEADER_LEN, MssqlParsed, parse_mssql_tds};

use crate::protocols::Registry;

/// Register MSSQL/TDS detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(MssqlDetector::new()));
}
