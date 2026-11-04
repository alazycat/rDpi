mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::L2tpDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(L2tpDetector::new()));
}
