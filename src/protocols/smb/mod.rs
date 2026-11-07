//! SMB protocol module (feature: smb)

mod detector;
pub(crate) mod parser;

pub use detector::SmbDetector;
