use crate::core::types::{Confidence, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser;

pub struct TelnetDetector { _private: () }
impl TelnetDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for TelnetDetector { fn default() -> Self { Self::new() } }
impl ProtocolDetector for TelnetDetector {
    fn name(&self) -> &'static str { "telnet" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        parser::detect(p).then(|| DetectionResult::new(Protocol::Telnet).with_confidence(Confidence::Dpi))
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_hit() { let d=TelnetDetector::new(); assert!(d.detect(&parser::valid_sample()).is_some()); }
    #[test] fn test_empty() { let d=TelnetDetector::new(); assert!(d.detect(b"").is_none()); }
}
