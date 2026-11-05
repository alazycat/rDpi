//! DHCP protocol detection module for rDpi
//!
//! Provides DHCP (Dynamic Host Configuration Protocol) packet detection with metadata extraction.
//!
//! ## Supported Detection
//!
//! - DHCP request (opcode 1) and reply (opcode 2)
//! - Ethernet hardware type validation
//! - Client MAC address extraction
//! - Magic cookie validation
//!
//! ## Example
//!
//! ```
//! use rdpi::protocols::dhcp::detect_dhcp;
//!
//! // Create a minimal DHCP request packet
//! let mut packet = vec![0u8; 244];
//! packet[0] = 1; // Opcode: BOOTREQUEST
//! packet[1] = 1; // Hardware type: Ethernet
//! packet[2] = 6; // Hardware address length
//! packet[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Client MAC
//! packet[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]); // Magic cookie
//!
//! if let Some(result) = detect_dhcp(&packet) {
//!     println!("Detected: {:?}", result.protocol);
//! }
//! ```

mod parser;

pub use parser::{DhcpHeader, detect_dhcp, parse_dhcp_packet};

use crate::protocols::ProtocolDetector;
use crate::protocols::Registry;

/// DHCP protocol detector
pub struct DhcpDetector {
    _private: (),
}

impl DhcpDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for DhcpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for DhcpDetector {
    fn name(&self) -> &'static str {
        "dhcp"
    }

    /// 首字节门：opcode 0x01-0x02（BootRequest/BootReply）
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x01u8, 0x02u8)])
    }

    fn detect(&self, payload: &[u8]) -> Option<crate::core::types::DetectionResult> {
        detect_dhcp(payload)
    }
}

/// Register DHCP detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(DhcpDetector::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = DhcpDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = vec![0x01u8; 244];
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
