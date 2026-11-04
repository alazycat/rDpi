mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::Dhcpv6Detector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(Dhcpv6Detector::new()));
}
