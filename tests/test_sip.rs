#![cfg(feature = "proto3")]

use rdpi::core::types::*;
use rdpi::protocols::ProtocolDetector;
use rdpi::protocols::sip::SipDetector;

#[test]
fn test_detect_sip_invite() {
    let detector = SipDetector::new();
    let pkt = b"INVITE sip:alice@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:bob@example.com>\r\nCSeq: 1 INVITE\r\n";
    let result = detector.detect(pkt).unwrap();
    assert_eq!(result.protocol, Protocol::Sip);
}

#[test]
fn test_detect_sip_methods() {
    let detector = SipDetector::new();
    for method in &["INVITE", "REGISTER", "BYE", "ACK", "CANCEL", "OPTIONS", "MESSAGE"] {
        let pkt = format!("{} sip:user@domain SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nCSeq: 1 {}\r\n", method, method);
        let result = detector.detect(pkt.as_bytes());
        assert!(result.is_some(), "Should detect SIP {}", method);
    }
}

#[test]
fn test_detect_sip_response_codes() {
    let detector = SipDetector::new();
    let pkt = b"SIP/2.0 180 Ringing\r\nVia: SIP/2.0/UDP 10.0.0.1\r\n";
    let result = detector.detect(pkt).unwrap();
    assert_eq!(result.protocol, Protocol::Sip);
}
