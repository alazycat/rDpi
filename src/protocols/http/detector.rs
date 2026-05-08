use crate::core::types::*;
use crate::protocols::ProtocolDetector;

pub struct HttpDetector;

impl HttpDetector {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolDetector for HttpDetector {
    fn name(&self) -> &'static str {
        "http"
    }

    fn detect(&self, _payload: &[u8]) -> Option<DetectionResult> {
        None
    }
}
