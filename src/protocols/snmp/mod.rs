//! SNMP (Simple Network Management Protocol) detection module for rDpi
//!
//! Provides SNMP v1/v2c packet detection with metadata extraction.
//!
//! ## Supported Detection
//!
//! - SNMPv1 and SNMPv2c
//! - PDU types: GetRequest, GetNext, GetResponse, SetRequest, Trap, GetBulk, Inform, TrapV2
//! - VarBind extraction with OID and value
//! - v1 Trap special fields: enterprise, agent-addr, generic-trap, specific-trap, timestamp
//!
//! ## Example
//!
//! ```
//! use rdpi::protocols::snmp::detect_snmp;
//!
//! // Create a simple SNMP v1 GetRequest
//! let packet = vec![
//!     0x30, 0x26, 0x02, 0x01, 0x00,
//!     0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,
//!     0xA0, 0x19, 0x02, 0x01, 0x01,
//!     0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
//!     0x30, 0x0E, 0x30, 0x0C,
//!     0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
//!     0x05, 0x00,
//! ];
//!
//! if let Some(result) = detect_snmp(&packet) {
//!     println!("Detected: {:?}", result.protocol);
//! }
//! ```

mod parser;

pub use parser::{detect_snmp, parse_snmp_message};

use crate::protocols::Registry;
use crate::protocols::ProtocolDetector;

/// SNMP protocol detector
pub struct SnmpDetector {
    _private: (),
}

impl SnmpDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for SnmpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for SnmpDetector {
    fn name(&self) -> &'static str {
        "snmp"
    }

    fn detect(&self, payload: &[u8]) -> Option<crate::core::types::DetectionResult> {
        detect_snmp(payload)
    }
}

/// Register SNMP detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(SnmpDetector::new()));
}
