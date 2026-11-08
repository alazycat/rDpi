//! DRDA protocol detection module for rDpi
//!
//! 识别 IBM DB2 DRDA 的 DSS/DDM 消息头（无默认端口）。

mod detector;
pub mod parser;

pub use detector::DrdaDetector;
pub use parser::{DRDA_HEADER_LEN, DRDA_MAGIC, DrdaParsed, parse_drda};

use crate::protocols::Registry;

/// Register DRDA detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(DrdaDetector::new()));
}
