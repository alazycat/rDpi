mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::OpenVpnDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(OpenVpnDetector::new()));
}
