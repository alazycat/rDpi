//! NetBIOS protocol module (feature: smb)

mod detector;
mod parser;

pub use detector::NetBiosDetector;

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(NetBiosDetector::new()));
}
