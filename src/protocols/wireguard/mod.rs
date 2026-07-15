//! WireGuard protocol detection module for rDpi
//!
//! Provides WireGuard VPN handshake message detection.
//!
//! ## Supported Detection
//!
//! - Handshake Initiation (type=1)
//! - Handshake Response (type=2)
//! - Cookie Reply (type=3)
//! - Transport Data (type=4)
//!
//! ## Example
//!
//! ```ignore
//! use rdpi::protocols::wireguard::WireGuardDetector;
//! use rdpi::protocols::ProtocolDetector;
//!
//! let detector = WireGuardDetector::new();
//! let ctx = rdpi::DetectContext { src_port: 51820, dst_port: 12345, is_http3_port: false };
//! if let Some(result) = detector.detect_with_context(payload, &ctx) {
//!     println!("Detected WireGuard: {:?}", result);
//! }
//! ```

mod detector;
mod parser;

pub use detector::WireGuardDetector;
pub use parser::parse_wireguard_handshake;

use crate::protocols::Registry;

/// Register WireGuard detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(WireGuardDetector::new()));
}
