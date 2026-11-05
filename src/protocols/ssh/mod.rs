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

    /// 首字节门：SSH banner 以 "SSH-" 起始（0x53）。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x53u8, 0x53u8)])
    }

    fn detect(&self, payload: &[u8]) -> Option<crate::core::types::DetectionResult> {
        // Quick check: SSH prefix byte
        if !is_ssh_prefix(*payload.first()?) {
            return None;
        }

        // Parse SSH version banner
        let info = parse_ssh_version(payload)?;

        use crate::core::types::{Confidence, DetectionResult, Metadata, Protocol, SshMetadata};

        let metadata = SshMetadata {
            version: Some(info.protocol_version),
            software: info.software_version,
        };

        Some(
            DetectionResult::new(Protocol::Ssh)
                .with_metadata(Metadata::Ssh(metadata))
                .with_confidence(Confidence::Dpi),
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

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = SshDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = b"SSH-2.0-OpenSSH_8.9\r\n";
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
