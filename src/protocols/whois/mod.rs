mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::WhoisDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(WhoisDetector::new()));
}
