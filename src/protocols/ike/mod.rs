mod detector;
mod parser;
pub use detector::IkeDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(IkeDetector::new())); }
