//! IMAP protocol detection module for rDpi
//!
//! Provides IMAP/IMAPS server response and client command detection.
//!
//! ## Supported Detection
//!
//! - Server responses: untagged (* OK, * NO, * BAD) and tagged (A001 OK, etc.)
//! - Client commands: LOGIN, SELECT, FETCH, etc.
//! - IMAPS detection via port 993
//!
//! ## Example
//!
//! ```
//! use rdpi::protocols::imap::ImapDetector;
//! use rdpi::protocols::ProtocolDetector;
//!
//! let detector = ImapDetector::new();
//!
//! // Detect server response
//! let response = b"* OK IMAP4rev1 Service Ready\r\n";
//! if let Some(result) = detector.detect(response) {
//!     println!("Detected: {:?}", result.protocol);
//! }
//!
//! // Detect client command
//! let command = b"A001 LOGIN user password\r\n";
//! if let Some(result) = detector.detect(command) {
//!     println!("Detected: {:?}", result.protocol);
//! }
//! ```

mod detector;
mod parser;

pub use detector::ImapDetector;
pub use parser::{
    ImapCommand, ImapResponse, is_imap_command_prefix, is_imap_response_prefix, parse_imap_command,
    parse_imap_response,
};

use crate::protocols::Registry;

/// Register IMAP detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(ImapDetector::new()));
}