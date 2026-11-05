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

    /// 首字节门：VN 字段（bit3-5）非零
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[
            (0x08u8, 0x27u8),
            (0x48u8, 0x67u8),
            (0x88u8, 0xA7u8),
            (0xC8u8, 0xE7u8),
        ])
    }

    fn detect(&self, payload: &[u8]) -> Option<crate::core::types::DetectionResult> {
        detect_ntp(payload)
    }
}

/// Register NTP detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(NtpDetector::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = NtpDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = [0x23u8, 0x00, 0x00, 0x00];
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
