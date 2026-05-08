use crate::core::types::*;
use crate::protocols::ProtocolDetector;
use super::parser::{is_http_prefix, parse_request_line, parse_response_line, parse_host_header};

pub struct HttpDetector;

impl HttpDetector {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolDetector for HttpDetector {
    fn name(&self) -> &'static str {
        "http"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        // Layer 1: Quick pre-check - first byte must be HTTP method prefix
        if payload.is_empty() || !is_http_prefix(payload[0]) {
            return None;
        }

        // Layer 2: Try parsing as HTTP request
        if let Some(req) = parse_request_line(payload) {
            // Layer 3: Extract metadata
            let host = parse_host_header(payload);
            let metadata = Metadata::Http(HttpMetadata {
                host,
                method: Some(req.method),
                path: Some(req.path),
            });

            return Some(
                DetectionResult::new(Protocol::Http)
                    .with_metadata(metadata)
                    .with_confidence(1.0)
            );
        }

        // Layer 2: Try parsing as HTTP response
        if let Some(_resp) = parse_response_line(payload) {
            // Layer 3: For responses, we just detect protocol (status code is in response line)
            let metadata = Metadata::Http(HttpMetadata {
                host: None,
                method: None,
                path: None,
            });

            return Some(
                DetectionResult::new(Protocol::Http)
                    .with_metadata(metadata)
                    .with_confidence(1.0)
            );
        }

        None
    }
}
