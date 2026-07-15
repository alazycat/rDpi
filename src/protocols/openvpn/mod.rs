mod detector; mod parser;
pub use detector::OpenVpnDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(OpenVpnDetector::new())); }
