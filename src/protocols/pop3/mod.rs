//! POP3 protocol detection module for rDpi
//!
//! Provides POP3/POP3S server response and client command detection.
//!
//! ## Supported Detection
//!
//! - Server responses: `+OK` and `-ERR`
//! - Client commands: USER, PASS, STAT, LIST, RETR, DELE, QUIT, etc.
//! - POP3S detection via port 995
//!
//! ## Example
//!
//! ```
//! use rdpi::protocols::pop3::Pop3Detector;
//! use rdpi::protocols::ProtocolDetector;
//!
//! let detector = Pop3Detector::new();
//!
//! // Detect server response
//! let response = b"+OK POP3 server ready\r\n";
//! if let Some(result) = detector.detect(response) {
//!     println!("Detected: {:?}", result.protocol);
//! }
//!
//! // Detect client command
//! let command = b"USER test@example.com\r\n";
//! if let Some(result) = detector.detect(command) {
//!     println!("Detected: {:?}", result.protocol);
//! }
//! ```

mod detector;
mod parser;

pub use detector::Pop3Detector;
pub use parser::{
    Pop3Command, Pop3Response, is_pop3_command_prefix, is_pop3_response_prefix, parse_pop3_command,
    parse_pop3_response,
};

use crate::protocols::Registry;

/// Register POP3 detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(Pop3Detector::new()));
}
