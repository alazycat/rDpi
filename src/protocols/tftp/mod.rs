mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::TftpDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(TftpDetector::new()));
}
