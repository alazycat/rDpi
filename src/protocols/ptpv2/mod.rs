mod detector;
mod parser;
use crate::protocols::Registry;
pub use detector::Ptpv2Detector;
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(Ptpv2Detector::new()));
}
