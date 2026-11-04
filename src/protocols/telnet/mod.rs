mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::TelnetDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(TelnetDetector::new()));
}
