//! SMB protocol module (feature: smb)

mod detector;
pub(crate) mod parser;

pub use detector::SmbDetector;

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(SmbDetector::new()));
}
