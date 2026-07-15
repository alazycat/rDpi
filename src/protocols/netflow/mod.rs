mod detector;
mod parser;
pub use detector::NetflowDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(NetflowDetector::new())); }
