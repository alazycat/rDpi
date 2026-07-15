//! STUN protocol detector for rDpi

use crate::core::types::{Confidence, DetectionResult, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_stun;

pub struct StunDetector {
    _private: (),
}

impl StunDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for StunDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for StunDetector {
    fn name(&self) -> &'static str {
        "stun"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let meta = parse_stun(payload)?;
        Some(
            DetectionResult::new(Protocol::Stun)
                .with_metadata(Metadata::Stun(meta))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_stun(msg_type: u16) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0..2].copy_from_slice(&msg_type.to_be_bytes());
        p[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        for i in 0..12 { p[8 + i] = i as u8; }
        p
    }

    #[test]
    fn test_stun_detector_binding() {
        let detector = StunDetector::new();
        let result = detector.detect(&build_stun(0x0001)).unwrap();
        assert_eq!(result.protocol, Protocol::Stun);
    }

    #[test]
    fn test_stun_detector_reject() {
        let detector = StunDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1").is_none());
    }

    #[test]
    fn test_stun_detector_empty() {
        let detector = StunDetector::new();
        assert!(detector.detect(b"").is_none());
    }
}
