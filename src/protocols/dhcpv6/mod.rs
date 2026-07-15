mod detector; mod parser;
pub use detector::Dhcpv6Detector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(Dhcpv6Detector::new())); }
