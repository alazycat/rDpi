//! TLS protocol detection module for rDpi
//!
//! Provides TLS record layer detection and ClientHello parsing
//! to extract SNI (Server Name Indication) and TLS version.

mod parser;

pub use parser::{
    ClientHelloInfo, extract_sni, extract_tls_version, is_client_hello, is_tls_record,
    parse_client_hello,
};

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(TlsDetector::new()));
}

/// TLS protocol detector
pub struct TlsDetector {
    _private: (),
}

impl TlsDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for TlsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::protocols::ProtocolDetector for TlsDetector {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn detect(&self, payload: &[u8]) -> Option<crate::core::types::DetectionResult> {
        // Quick check: TLS record layer magic bytes
        if !is_tls_record(payload) {
            return None;
        }

        // Parse ClientHello to extract SNI and version
        let info = parse_client_hello(payload)?;

        use crate::core::types::{DetectionResult, Metadata, Protocol, TlsMetadata};

        let metadata = TlsMetadata {
            sni: info.sni,
            version: info.version,
            application: None,
        };

        Some(
            DetectionResult::new(Protocol::Tls)
                .with_metadata(Metadata::Tls(metadata))
                .with_confidence(1.0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ProtocolDetector;

    #[test]
    fn test_tls_detector_new() {
        let detector = TlsDetector::new();
        assert_eq!(detector.name(), "tls");
    }
}
