mod detector; mod parser;
pub use detector::VxlanDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(VxlanDetector::new())); }
