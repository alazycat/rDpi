mod detector; mod parser;
pub use detector::BgpDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(BgpDetector::new())); }
