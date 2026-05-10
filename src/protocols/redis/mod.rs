//! Redis protocol detection module for rDpi
//!
//! Provides Redis RESP command detection.
//!
//! ## Supported Detection
//!
//! - RESP array commands (most common format)
//! - RESP simple strings (+PING, +OK, etc.)
//! - Top 30 command identification
//!
//! ## Example
//!
//! ```ignore
//! use rdpi::protocols::redis::RedisDetector;
//! use rdpi::protocols::ProtocolDetector;
//!
//! let detector = RedisDetector::new();
//! // Redis GET command
//! let cmd = b"*1\r\n$3\r\nGET\r\n";
//! if let Some(result) = detector.detect(cmd) {
//!     println!("Detected Redis: {:?}", result);
//! }
//! ```

mod detector;
mod parser;

pub use detector::RedisDetector;
pub use parser::parse_redis_command;

use crate::protocols::Registry;

/// Register Redis detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(RedisDetector::new()));
}