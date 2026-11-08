//! Apple Filing Protocol detection module for rDpi
//!
//! 识别 16 字节 DSI 头（AFP over TCP/UDP 548）。

mod detector;
pub mod parser;

pub use detector::AfpDetector;
pub use parser::{AFP_DSI_HEADER_LEN, AFP_MAX_DETECT_LEN, AfpParsed, parse_afp_dsi};

use crate::protocols::Registry;

/// Register AFP detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(AfpDetector::new()));
}
