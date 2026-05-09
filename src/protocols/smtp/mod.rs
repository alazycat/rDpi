//! SMTP protocol detection module for rDpi
//!
//! Provides SMTP server banner and client command detection.
//!
//! ## Supported Detection
//!
//! - Server banner responses (220, 250, etc.)
//! - Client commands (EHLO, HELO, MAIL, RCPT, QUIT, etc.)
//! - Hostname extraction from banner and EHLO/HELO commands
//!
//! ## Example
//!
//! ```
//! use rdpi::protocols::smtp::SmtpDetector;
//! use rdpi::protocols::ProtocolDetector;
//!
//! let detector = SmtpDetector::new();
//!
//! // Detect server banner
//! let banner = b"220 mail.example.com ESMTP\r\n";
//! if let Some(result) = detector.detect(banner) {
//!     println!("Detected: {:?}", result.protocol);
//! }
//!
//! // Detect client command
//! let ehlo = b"EHLO client.example.com\r\n";
//! if let Some(result) = detector.detect(ehlo) {
//!     println!("Detected: {:?}", result.protocol);
//! }
//! ```

mod detector;
mod parser;

pub use detector::SmtpDetector;
pub use parser::{
    SmtpCommand, SmtpResponse, is_smtp_command_prefix, is_smtp_response_prefix, parse_smtp_command,
    parse_smtp_response,
};

use crate::protocols::Registry;

/// Register SMTP detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(SmtpDetector::new()));
}
