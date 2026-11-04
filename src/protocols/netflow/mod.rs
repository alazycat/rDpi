mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::NetflowDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(NetflowDetector::new()));
}
