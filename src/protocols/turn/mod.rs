mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::TurnDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(TurnDetector::new()));
}
