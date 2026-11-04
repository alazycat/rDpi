mod detector;
mod parser;

pub use detector::SipDetector;
pub use parser::{SipRequest, SipResponse, is_sip_message, parse_sip_request, parse_sip_response};

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(SipDetector::new()));
}
