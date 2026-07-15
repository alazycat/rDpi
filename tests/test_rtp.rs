#![cfg(feature = "proto3")]

use rdpi::core::types::*;
use rdpi::protocols::ProtocolDetector;
use rdpi::protocols::rtp::RtpDetector;

fn rtp_packet(pt: u8, seq: u16, ssrc: u32) -> Vec<u8> {
    let mut pkt = vec![0x80, pt];
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]);
    pkt.extend_from_slice(&ssrc.to_be_bytes());
    pkt
}

#[test]
fn test_detect_rtp_audio() {
    let detector = RtpDetector::new();
    let result = detector.detect(&rtp_packet(0, 1, 0x11111111)).unwrap();
    assert_eq!(result.protocol, Protocol::Rtp);
}

#[test]
fn test_detect_rtp_video() {
    let detector = RtpDetector::new();
    let result = detector.detect(&rtp_packet(96, 100, 0x22222222)).unwrap();
    assert_eq!(result.protocol, Protocol::Rtp);
}

#[test]
fn test_detect_rtcp_sr() {
    let detector = RtpDetector::new();
    let result = detector.detect(&rtp_packet(200, 1, 0x33333333)).unwrap();
    assert_eq!(result.protocol, Protocol::Rtcp);
}

#[test]
fn test_detect_rtcp_bye() {
    let detector = RtpDetector::new();
    let result = detector.detect(&rtp_packet(203, 1, 0x44444444)).unwrap();
    assert_eq!(result.protocol, Protocol::Rtcp);
}

#[test]
fn test_rtp_rejects_non_rtp() {
    let detector = RtpDetector::new();
    assert!(detector.detect(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00").is_none());
}
