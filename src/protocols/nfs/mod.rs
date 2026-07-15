mod detector;
mod parser;
pub use detector::NfsDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(NfsDetector::new())); }
