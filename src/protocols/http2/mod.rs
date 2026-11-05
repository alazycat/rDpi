//! HTTP/2 protocol detection module for rDpi
//!
//! Detects HTTP/2 via the 24-byte connection preface.

mod detector;
mod hpack;
mod parser;

pub use detector::Http2Detector;
pub use parser::{extract_request_headers, is_http2_preface};

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(Http2Detector::new()));
}
