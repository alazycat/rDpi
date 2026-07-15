//! FTP protocol module for rDpi
//!
//! Provides FTP command/response parsing and protocol detection.
//! Available under the `proto3` feature flag.

mod detector;
mod parser;

pub use detector::FtpDetector;
pub use parser::{
    parse_ftp_command, parse_ftp_response, FtpCommand, FtpResponse,
};

use crate::protocols::Registry;

/// Register the FTP detector into the protocol registry.
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(FtpDetector::new()));
}
