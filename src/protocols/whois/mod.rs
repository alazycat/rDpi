mod detector;
mod parser;
pub use detector::WhoisDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(WhoisDetector::new())); }
