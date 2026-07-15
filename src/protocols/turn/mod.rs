mod detector; mod parser;
pub use detector::TurnDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(TurnDetector::new())); }
