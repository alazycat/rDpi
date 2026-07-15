mod detector;
mod parser;
pub use detector::RtmpDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(RtmpDetector::new())); }
