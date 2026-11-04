mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::MgcpDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(MgcpDetector::new()));
}
