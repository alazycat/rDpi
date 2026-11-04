mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::LdapDetector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(LdapDetector::new()));
}
