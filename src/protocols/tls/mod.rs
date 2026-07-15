//! TLS protocol detection module for rDpi
//!
//! Provides TLS record layer detection and ClientHello parsing
//! to extract SNI (Server Name Indication) and TLS version.

mod certificate;
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
        if !is_tls_record(payload) {
            return None;
        }

        use crate::core::types::{Confidence, DetectionResult, Metadata, Protocol, TlsMetadata};

        // Try ClientHello first (for SNI, version, JA4), then Certificate (for cert fields)
        let mut tls_meta = TlsMetadata::default();

        if let Some(ref info) = parse_client_hello(payload) {
            tls_meta.sni = info.sni.clone();
            tls_meta.version = info.version.clone();
            tls_meta.cipher_suites = info.cipher_suites.clone();
            tls_meta.alpn = info.alpn.clone();
            tls_meta.application = info.sni.as_ref()
                .and_then(|sni| crate::application::identify(sni));
            let ja4 = info.version.as_ref().map(|ver| {
                crate::application::compute_ja4(ver, &info.cipher_suites, &info.extensions, &info.supported_groups)
            });
            tls_meta.ja4 = ja4;
        }

        // Try Certificate message for cert fields (even if ClientHello was found)
        if let Some(cert_info) = certificate::parse_certificate(payload) {
            tls_meta.cert_subject = cert_info.subject;
            tls_meta.cert_issuer = cert_info.issuer;
            tls_meta.cert_valid_from = cert_info.not_before;
            tls_meta.cert_valid_to = cert_info.not_after;
        }

        // Return None if nothing matched (neither ClientHello nor Certificate)
        if tls_meta.sni.is_none() && tls_meta.version.is_none() && tls_meta.cert_subject.is_none() {
            return None;
        }

        Some(
            DetectionResult::new(Protocol::Tls)
                .with_metadata(Metadata::Tls(tls_meta))
                .with_confidence(Confidence::Dpi),
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
