//! DNS protocol detector
//!
//! Detects DNS traffic and extracts query information.

use crate::core::types::*;
use crate::protocols::{ProtocolDetector, Registry};

/// DNS protocol detector
pub struct DnsDetector;

impl ProtocolDetector for DnsDetector {
    fn name(&self) -> &'static str {
        "DNS"
    }

    fn detect(&self, _payload: &[u8]) -> Option<DetectionResult> {
        // TODO: Implement DNS detection in Task 6
        None
    }
}

/// Register DNS detector with the registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(DnsDetector));
}
