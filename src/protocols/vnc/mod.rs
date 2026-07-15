mod detector; mod parser;
pub use detector::VncDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(VncDetector::new())); }
