//! SSH protocol detection module for rDpi
//!
//! Provides SSH version banner detection and parsing.

mod parser;

pub use parser::{SshVersionInfo, is_ssh_prefix, parse_ssh_version};

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(SshDetector::new()));
}

/// SSH protocol detector
pub struct SshDetector {
    _private: (),
}

impl SshDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for SshDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::protocols::ProtocolDetector for SshDetector {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn detect(&self, payload: &[u8]) -> Option<crate::core::types::DetectionResult> {
        // Quick check: SSH prefix byte
        if !is_ssh_prefix(*payload.first()?) {
            return None;
        }

        // Parse SSH version banner
        let info = parse_ssh_version(payload)?;

        use crate::core::types::{DetectionResult, Metadata, Protocol, SshMetadata};

        let metadata = SshMetadata {
            version: Some(info.protocol_version),
            software: info.software_version,
        };

        Some(
            DetectionResult::new(Protocol::Ssh)
                .with_metadata(Metadata::Ssh(metadata))
                .with_confidence(1.0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ProtocolDetector;

    #[test]
    fn test_ssh_detector_new() {
        let detector = SshDetector::new();
        assert_eq!(detector.name(), "ssh");
    }
}
