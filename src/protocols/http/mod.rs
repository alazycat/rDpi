mod parser;
mod detector;

pub use detector::HttpDetector;
pub use parser::{parse_host_header, parse_request_line, parse_response_line, is_http_prefix};

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(HttpDetector::new()));
}
