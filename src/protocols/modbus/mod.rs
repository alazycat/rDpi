//! Modbus TCP protocol detection module for rDpi
//!
//! Provides Modbus TCP frame detection with metadata extraction.
//!
//! ## Supported Detection
//!
//! - Standard function codes: 01-06, 15-16, 23
//! - Request/Response distinction
//! - Exception response parsing
//!
//! ## Example
//!
//! ```
//! use rdpi::protocols::modbus::detect_modbus;
//!
//! // Create a Read Coils request
//! let packet = vec![
//!     0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01,
//!     0x01, 0x00, 0x01, 0x00, 0x08,
//! ];
//!
//! if let Some(result) = detect_modbus(&packet) {
//!     println!("Detected: {:?}", result.protocol);
//! }
//! ```

mod parser;

pub use parser::{detect_modbus, parse_modbus_frame};

use crate::protocols::Registry;
use crate::protocols::ProtocolDetector;

/// Modbus TCP protocol detector
pub struct ModbusDetector {
    _private: (),
}

impl ModbusDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for ModbusDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for ModbusDetector {
    fn name(&self) -> &'static str {
        "modbus"
    }

    fn detect(&self, payload: &[u8]) -> Option<crate::core::types::DetectionResult> {
        detect_modbus(payload)
    }
}

/// Register Modbus detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(ModbusDetector::new()));
}