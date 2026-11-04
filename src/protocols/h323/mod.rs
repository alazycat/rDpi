mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::H323Detector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(H323Detector::new()));
}
