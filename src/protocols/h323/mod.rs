mod detector; mod parser;
pub use detector::H323Detector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(H323Detector::new())); }
