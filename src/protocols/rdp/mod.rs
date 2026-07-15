mod detector; mod parser;
pub use detector::RdpDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(RdpDetector::new())); }
