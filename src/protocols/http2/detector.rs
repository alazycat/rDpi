//! HTTP/2 protocol detector for rDpi

use crate::core::types::{Confidence, DetectionResult, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::{extract_request_headers, is_http2_preface};

pub struct Http2Detector {
    _private: (),
}

impl Http2Detector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for Http2Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for Http2Detector {
    fn name(&self) -> &'static str {
        "http2"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        if !is_http2_preface(payload) {
            return None;
        }
        // preface 包内若已含首个请求 HEADERS 帧则顺带提取；否则由 lib.rs
        // 定型流富化路径在后续包补齐（Http2Metadata::default 起步）
        let metadata = extract_request_headers(payload).unwrap_or_default();
        Some(
            DetectionResult::new(Protocol::Http2)
                .with_confidence(Confidence::Dpi)
                .with_metadata(Metadata::Http2(metadata)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_detector_preface() {
        let detector = Http2Detector::new();
        let result = detector
            .detect(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .unwrap();
        assert_eq!(result.protocol, Protocol::Http2);
    }

    #[test]
    fn test_http2_detector_http11() {
        let detector = Http2Detector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn test_http2_detector_empty() {
        let detector = Http2Detector::new();
        assert!(detector.detect(b"").is_none());
    }
}
