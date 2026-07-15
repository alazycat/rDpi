mod detector;
mod parser;

pub use detector::SipDetector;
pub use parser::{
    is_sip_message, parse_sip_request, parse_sip_response, SipRequest, SipResponse,
};

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(SipDetector::new()));
}
