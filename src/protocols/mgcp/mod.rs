mod detector; mod parser;
pub use detector::MgcpDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(MgcpDetector::new())); }
