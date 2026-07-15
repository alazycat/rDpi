//! OpenVPN protocol detector

use crate::core::types::{Confidence, DetectContext, DetectionResult, Protocol};
use crate::protocols::ProtocolDetector;
use super::parser::parse_openvpn;

pub struct OpenVpnDetector { _private: () }

impl OpenVpnDetector {
    pub fn new() -> Self { Self { _private: () } }
}
impl Default for OpenVpnDetector { fn default() -> Self { Self::new() } }

impl ProtocolDetector for OpenVpnDetector {
    fn name(&self) -> &'static str { "openvpn" }
    fn detect(&self, _p: &[u8]) -> Option<DetectionResult> { None }
    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        if payload.is_empty() || !parse_openvpn(payload) { return None; }
        let is_std_port = ctx.dst_port == 1194 || ctx.src_port == 1194;
        Some(DetectionResult::new(Protocol::OpenVpn)
            .with_confidence(if is_std_port { Confidence::Dpi } else { Confidence::DpiPartial }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn msg(opcode: u8) -> Vec<u8> { let mut p = vec![opcode<<3|1]; p.extend(vec![0u8;13]); p }
    #[test] fn test_std_port() { let d=OpenVpnDetector::new(); let r=d.detect_with_context(&msg(7),&DetectContext{src_port:54321,dst_port:1194,is_http3_port:false}).unwrap(); assert_eq!(r.protocol,Protocol::OpenVpn); assert_eq!(r.confidence,Confidence::Dpi); }
    #[test] fn test_non_std_port() { let d=OpenVpnDetector::new(); let r=d.detect_with_context(&msg(7),&DetectContext{src_port:54321,dst_port:9999,is_http3_port:false}).unwrap(); assert_eq!(r.confidence,Confidence::DpiPartial); }
    #[test] fn test_reject() { let d=OpenVpnDetector::new(); assert!(d.detect_with_context(b"HTTP",&DetectContext{src_port:54321,dst_port:80,is_http3_port:false}).is_none()); }
}
