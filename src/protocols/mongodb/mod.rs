//! MongoDB protocol detection module for rDpi
//!
//! Provides MongoDB isMaster/hello handshake detection for protocol identification.
//!
//! ## Supported Detection
//!
//! - MongoDB isMaster/hello handshake (OP_MSG, OP_QUERY, OP_REPLY)
//! - Server version, maxWireVersion, maxMsgSizeBytes extraction
//!
//! ## Example
//!
//! ```ignore
//! use rdpi::protocols::mongodb::MongodbDetector;
//! use rdpi::protocols::ProtocolDetector;
//!
//! let detector = MongodbDetector::new();
//! if let Some(result) = detector.detect(payload) {
//!     println!("Detected MongoDB: {:?}", result);
//! }
//! ```

mod detector;
mod parser;

pub use detector::MongodbDetector;
pub use parser::parse_mongodb_handshake;

use crate::protocols::Registry;

/// Register MongoDB detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(MongodbDetector::new()));
}
