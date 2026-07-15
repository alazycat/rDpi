mod detector; mod parser;
pub use detector::KerberosDetector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(KerberosDetector::new())); }
