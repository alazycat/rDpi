//! STUN protocol detection module for rDpi

mod detector;
mod parser;

pub use detector::StunDetector;
pub use parser::parse_stun;

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(StunDetector::new()));
}
