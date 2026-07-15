mod detector; mod parser;
pub use detector::L2tpDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(L2tpDetector::new())); }
