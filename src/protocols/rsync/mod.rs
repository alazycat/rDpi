mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::RsyncDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(RsyncDetector::new()));
}
