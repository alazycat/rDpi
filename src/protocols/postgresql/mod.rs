//! PostgreSQL protocol detection module for rDpi
//!
//! Provides PostgreSQL startup message detection.
//!
//! ## Supported Detection
//!
//! - Startup messages (protocol version 3.0)
//! - User name extraction
//! - Database name extraction
//! - Application name extraction
//!
//! ## Example
//!
//! ```ignore
//! use rdpi::protocols::postgresql::PostgresqlDetector;
//! use rdpi::protocols::ProtocolDetector;
//!
//! let detector = PostgresqlDetector::new();
//! // PostgreSQL startup message
//! let msg = &[/* startup message bytes */];
//! if let Some(result) = detector.detect(msg) {
//!     println!("Detected PostgreSQL: {:?}", result);
//! }
//! ```

mod detector;
mod parser;

pub use detector::PostgresqlDetector;
pub use parser::parse_pg_startup;

use crate::protocols::Registry;

/// Register PostgreSQL detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(PostgresqlDetector::new()));
}
