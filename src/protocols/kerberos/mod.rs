mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::KerberosDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(KerberosDetector::new()));
}
