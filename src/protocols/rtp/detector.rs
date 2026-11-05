//! RTP/RTCP protocol detector for rDpi
//!
//! Detects RTP (Real-time Transport Protocol) and RTCP (RTP Control Protocol)
//! by parsing the 12-byte fixed header.

use crate::core::types::*;
use crate::protocols::ProtocolDetector;

use super::parser::parse_rtp_header;

/// Detector for RTP and RTCP protocols
pub struct RtpDetector;

impl Default for RtpDetector {
    fn default() -> Self {
        Self
    }
}

impl RtpDetector {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolDetector for RtpDetector {
    fn name(&self) -> &'static str {
        "rtp"
    }

    /// 首字节门：RTP/RTCP 头部 Version=2（0x80-0xBF）。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x80u8, 0xBFu8)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let header = parse_rtp_header(payload)?;

        let protocol = if header.is_rtcp {
            Protocol::Rtcp
        } else {
            Protocol::Rtp
        };

        let meta = RtpMetadata {
            ssrc: header.ssrc,
            payload_type: header.payload_type,
            sequence_number: header.sequence_number,
            timestamp: header.timestamp,
            ssrc_confirmed: false,
            is_rtcp: header.is_rtcp,
        };

        Some(
            DetectionResult::new(protocol)
                .with_confidence(Confidence::Dpi)
                .with_metadata(Metadata::Rtp(meta)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rtp_packet(pt: u8, seq: u16, ssrc: u32) -> Vec<u8> {
        let mut pkt = vec![0x80, pt];
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]);
        pkt.extend_from_slice(&ssrc.to_be_bytes());
        pkt
    }

    #[test]
    fn test_detect_rtp() {
        let detector = RtpDetector::new();
        let result = detector.detect(&make_rtp_packet(0, 1, 0x12345678)).unwrap();
        assert_eq!(result.protocol, Protocol::Rtp);
    }

    #[test]
    fn test_detect_rtcp() {
        let detector = RtpDetector::new();
        let result = detector
            .detect(&make_rtp_packet(200, 1, 0x12345678))
            .unwrap();
        assert_eq!(result.protocol, Protocol::Rtcp);
    }

    #[test]
    fn test_detect_rtp_empty() {
        let detector = RtpDetector::new();
        assert!(detector.detect(b"").is_none());
    }

    #[test]
    fn test_rtp_metadata() {
        let detector = RtpDetector::new();
        let pkt = make_rtp_packet(8, 42, 0xdeadbeef);
        let result = detector.detect(&pkt).unwrap();
        if let Metadata::Rtp(meta) = result.metadata {
            assert_eq!(meta.ssrc, 0xdeadbeef);
            assert_eq!(meta.payload_type, 8);
            assert_eq!(meta.sequence_number, 42);
            assert!(!meta.ssrc_confirmed);
        } else {
            panic!("Expected RTP metadata");
        }
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = RtpDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = make_rtp_packet(0, 1, 0x12345678);
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
