mod detector;
mod parser;
pub use detector::TftpDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(TftpDetector::new())); }
