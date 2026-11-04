mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::RdpDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(RdpDetector::new()));
}
