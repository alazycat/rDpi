mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::RadiusDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(RadiusDetector::new()));
}
