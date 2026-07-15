mod detector; mod parser;
pub use detector::TelnetDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(TelnetDetector::new())); }
