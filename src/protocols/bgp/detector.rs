use crate::core::types::*;
use crate::protocols::ProtocolDetector;
use super::parser::parse_bgp;

pub struct BgpDetector { _private: () }
impl BgpDetector { pub fn new() -> Self { Self { _private: () } } }
impl Default for BgpDetector { fn default() -> Self { Self::new() } }

impl ProtocolDetector for BgpDetector {
    fn name(&self) -> &'static str { "bgp" }
    fn detect(&self, p: &[u8]) -> Option<DetectionResult> {
        let _ = parse_bgp(p)?;
        Some(DetectionResult::new(Protocol::Bgp).with_confidence(Confidence::Dpi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn msg() -> Vec<u8> { let mut p = vec![0xff; 19]; p[16..18].copy_from_slice(&[0x00,0x13]); p[18]=1; p }
    #[test] fn test_hit() { let d=BgpDetector::new(); assert_eq!(d.detect(&msg()).unwrap().protocol, Protocol::Bgp); }
    #[test] fn test_reject() { let d=BgpDetector::new(); assert!(d.detect(b"HTTP").is_none()); }
    #[test] fn test_empty() { let d=BgpDetector::new(); assert!(d.detect(b"").is_none()); }
}
