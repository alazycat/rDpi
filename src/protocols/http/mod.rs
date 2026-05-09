mod detector;
mod parser;

pub use detector::HttpDetector;
pub use parser::{is_http_prefix, parse_host_header, parse_request_line, parse_response_line};

use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(HttpDetector::new()));
}
