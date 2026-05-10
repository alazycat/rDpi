//! NTP protocol detection module for rDpi
//!
//! Provides NTP (Network Time Protocol) packet detection with metadata extraction.
//!
//! ## Supported Detection
//!
//! - NTP versions 1-4
//! - Mode identification (client, server, symmetric, broadcast)
//! - Stratum extraction (clock hierarchy level)
//!
//! ## Example
//!
//! ```
//! use rdpi::protocols::ntp::detect_ntp;
//!
//! // Create a minimal NTP v4 client packet
//! let mut packet = vec![0u8; 48];
//! packet[0] = (4 << 3) | 3; // Version 4, Mode 3 (client)
//! packet[1] = 1; // Stratum 1
//!
//! if let Some(result) = detect_ntp(&packet) {
//!     println!("Detected: {:?}", result.protocol);
//! }
//! ```

mod parser;

pub use parser::{NtpHeader, detect_ntp, parse_ntp_packet};

use crate::protocols::Registry;

use crate::protocols::ProtocolDetector;

/// NTP protocol detector
pub struct NtpDetector {
    _private: (),
}

impl NtpDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for NtpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for NtpDetector {
    fn name(&self) -> &'static str {
        "ntp"
    }

    fn detect(&self, payload: &[u8]) -> Option<crate::core::types::DetectionResult> {
        detect_ntp(payload)
    }
}

/// Register NTP detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(NtpDetector::new()));
}