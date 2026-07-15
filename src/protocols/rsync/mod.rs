mod detector;
mod parser;
pub use detector::RsyncDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(RsyncDetector::new())); }
