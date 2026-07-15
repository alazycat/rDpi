mod detector;
mod parser;
pub use detector::SocksDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(SocksDetector::new())); }
