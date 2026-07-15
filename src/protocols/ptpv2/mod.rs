mod detector;
mod parser;
pub use detector::Ptpv2Detector;
use crate::protocols::Registry;
pub fn register(registry: &mut Registry) { registry.register(Box::new(Ptpv2Detector::new())); }
