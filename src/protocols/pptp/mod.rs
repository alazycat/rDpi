mod detector; mod parser;
pub use detector::PptpDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(PptpDetector::new())); }
