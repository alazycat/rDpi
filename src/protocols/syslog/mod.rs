mod detector;
mod parser;
pub use detector::SyslogDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(SyslogDetector::new())); }
