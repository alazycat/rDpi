#![cfg(feature = "proto3")]

use rdpi::core::types::*;
use rdpi::protocols::ProtocolDetector;
use rdpi::protocols::ftp::FtpDetector;

#[test]
fn test_detect_ftp_banner() {
    let detector = FtpDetector::new();
    let result = detector.detect(b"220 ProFTPD Server ready\r\n").unwrap();
    assert_eq!(result.protocol, Protocol::Ftp);
    if let Metadata::Ftp(meta) = result.metadata {
        assert!(!meta.is_client);
        assert_eq!(meta.response_code, Some(220));
    } else {
        panic!("Expected Ftp metadata");
    }
}

#[test]
fn test_detect_ftp_list() {
    let detector = FtpDetector::new();
    let result = detector.detect(b"LIST\r\n").unwrap();
    assert_eq!(result.protocol, Protocol::Ftp);
    if let Metadata::Ftp(meta) = result.metadata {
        assert!(meta.is_client);
        assert_eq!(meta.verb, Some("LIST".to_string()));
    } else {
        panic!("Expected Ftp metadata");
    }
}

#[test]
fn test_detect_ftp_various_responses() {
    let detector = FtpDetector::new();
    for code in &[220, 230, 331, 550] {
        let pkt = format!("{} Welcome\r\n", code);
        let result = detector.detect(pkt.as_bytes()).unwrap();
        assert_eq!(result.protocol, Protocol::Ftp);
    }
}

#[test]
fn test_detect_ftp_quits() {
    let detector = FtpDetector::new();
    assert!(detector.detect(b"HTTP/1.1 200 OK\r\n").is_none());
}
