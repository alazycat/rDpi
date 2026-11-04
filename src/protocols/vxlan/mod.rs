mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::VxlanDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(VxlanDetector::new()));
}
