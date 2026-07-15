mod detector; mod parser;
pub use detector::RadiusDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(RadiusDetector::new())); }
