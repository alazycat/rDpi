//! RTP/RTCP protocol module for rDpi
//!
//! Provides RTP (Real-time Transport Protocol) and RTCP header parsing
//! and protocol detection. Available under the `proto3` feature flag.

mod detector;
mod parser;

pub use detector::RtpDetector;
pub use parser::{parse_rtp_header, RtpHeader};

use crate::protocols::Registry;

/// Register the RTP/RTCP detector into the protocol registry.
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(RtpDetector::new()));
}
