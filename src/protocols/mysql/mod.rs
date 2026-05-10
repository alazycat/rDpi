//! MySQL protocol detection module for rDpi
//!
//! Provides MySQL server handshake packet detection.
//!
//! ## Supported Detection
//!
//! - Server handshake packets (protocol version 10)
//! - Server version extraction
//! - Authentication plugin name extraction
//!
//! ## Example
//!
//! ```ignore
//! use rdpi::protocols::mysql::MysqlDetector;
//! use rdpi::protocols::ProtocolDetector;
//!
//! let detector = MysqlDetector::new();
//! // MySQL handshake packet
//! let packet = &[0x0a, b'8', b'.', b'0', b'.','3', b'3', 0x00, /* ... */];
//! if let Some(result) = detector.detect(packet) {
//!     println!("Detected MySQL: {:?}", result);
//! }
//! ```

mod detector;
mod parser;

pub use detector::MysqlDetector;
pub use parser::parse_mysql_handshake;

use crate::protocols::Registry;

/// Register MySQL detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(MysqlDetector::new()));
}
