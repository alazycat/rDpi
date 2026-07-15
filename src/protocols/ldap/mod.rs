mod detector; mod parser;
pub use detector::LdapDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(LdapDetector::new())); }
