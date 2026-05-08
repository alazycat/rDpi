mod parser;
mod detector;

pub use detector::DnsDetector;

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(DnsDetector::new()));
}
