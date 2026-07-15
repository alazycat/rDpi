#![cfg(feature = "ssh")]

use rdpi::protocols::ssh::{is_ssh_prefix, parse_ssh_version};

#[test]
fn test_is_ssh_prefix() {
    assert!(is_ssh_prefix(b'S')); // SSH-
    assert!(!is_ssh_prefix(b'H'));
    assert!(!is_ssh_prefix(b'G'));
}

#[test]
fn test_parse_ssh_version_openssh() {
    let data = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n";
    let result = parse_ssh_version(data);
    assert!(result.is_some());

    let info = result.unwrap();
    assert_eq!(info.protocol_version, "2.0");
    assert_eq!(
        info.software_version,
        Some("OpenSSH_8.9p1 Ubuntu-3".to_string())
    );
}

#[test]
fn test_parse_ssh_version_dropbear() {
    let data = b"SSH-2.0-dropbear_2022.83\r\n";
    let result = parse_ssh_version(data);
    assert!(result.is_some());

    let info = result.unwrap();
    assert_eq!(info.protocol_version, "2.0");
    assert_eq!(info.software_version, Some("dropbear_2022.83".to_string()));
}

#[test]
fn test_parse_ssh_version_libssh() {
    let data = b"SSH-2.0-libssh_0.10.5\r\n";
    let result = parse_ssh_version(data);
    assert!(result.is_some());

    let info = result.unwrap();
    assert_eq!(info.protocol_version, "2.0");
    assert_eq!(info.software_version, Some("libssh_0.10.5".to_string()));
}

#[test]
fn test_parse_ssh_version_legacy() {
    let data = b"SSH-1.99-OpenSSH_7.4\r\n";
    let result = parse_ssh_version(data);
    assert!(result.is_some());

    let info = result.unwrap();
    assert_eq!(info.protocol_version, "1.99");
    assert_eq!(info.software_version, Some("OpenSSH_7.4".to_string()));
}

#[test]
fn test_parse_ssh_version_no_software() {
    let data = b"SSH-2.0\r\n";
    let result = parse_ssh_version(data);
    assert!(result.is_some());

    let info = result.unwrap();
    assert_eq!(info.protocol_version, "2.0");
    assert_eq!(info.software_version, None);
}

#[test]
fn test_parse_ssh_version_invalid_version() {
    // SSH-1.0 is not valid (only 2.0 and 1.99)
    let data = b"SSH-1.0-xxx\r\n";
    let result = parse_ssh_version(data);
    assert!(result.is_none());
}

#[test]
fn test_parse_ssh_version_truncated() {
    let data = b"SSH-2.0";
    let result = parse_ssh_version(data);
    assert!(result.is_none());
}

#[test]
fn test_parse_ssh_version_no_prefix() {
    let data = b"GET / HTTP/1.1\r\n";
    let result = parse_ssh_version(data);
    assert!(result.is_none());
}

#[test]
fn test_parse_ssh_version_empty() {
    let data = b"";
    let result = parse_ssh_version(data);
    assert!(result.is_none());
}

// ============================================================
// SSH Detector Tests
// ============================================================

use rdpi::core::types::{Confidence, Metadata, Protocol};
use rdpi::protocols::ProtocolDetector;
use rdpi::protocols::ssh::SshDetector;

#[test]
fn test_ssh_detector_openssh() {
    let detector = SshDetector::new();
    let data = b"SSH-2.0-OpenSSH_8.9p1\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Ssh);
    assert_eq!(detection.confidence, Confidence::Dpi);

    if let Metadata::Ssh(meta) = detection.metadata {
        assert_eq!(meta.version, Some("2.0".to_string()));
        assert_eq!(meta.software, Some("OpenSSH_8.9p1".to_string()));
    } else {
        panic!("Expected Ssh metadata");
    }
}

#[test]
fn test_ssh_detector_dropbear() {
    let detector = SshDetector::new();
    let data = b"SSH-2.0-dropbear_2022.83\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Ssh);

    if let Metadata::Ssh(meta) = detection.metadata {
        assert_eq!(meta.software, Some("dropbear_2022.83".to_string()));
    } else {
        panic!("Expected Ssh metadata");
    }
}

#[test]
fn test_ssh_detector_legacy_version() {
    let detector = SshDetector::new();
    let data = b"SSH-1.99-OpenSSH_7.4\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    let detection = result.unwrap();
    assert_eq!(detection.protocol, Protocol::Ssh);

    if let Metadata::Ssh(meta) = detection.metadata {
        assert_eq!(meta.version, Some("1.99".to_string()));
    } else {
        panic!("Expected Ssh metadata");
    }
}

#[test]
fn test_ssh_detector_invalid_version() {
    let detector = SshDetector::new();
    let data = b"SSH-1.0-xxx\r\n";

    let result = detector.detect(data);
    assert!(result.is_none());
}

#[test]
fn test_ssh_detector_non_ssh() {
    let detector = SshDetector::new();

    // Non-SSH data
    let test_cases = vec![
        b"GET / HTTP/1.1\r\n".as_slice(),
        b"220 smtp.example.com ESMTP\r\n".as_slice(),
        b"\x16\x03\x03".as_slice(), // TLS
        b"".as_slice(),
    ];

    for data in test_cases {
        let result = detector.detect(data);
        assert!(
            result.is_none(),
            "Should not detect SSH in: {:?}",
            std::str::from_utf8(data)
        );
    }
}

#[test]
fn test_ssh_detector_no_software() {
    let detector = SshDetector::new();
    let data = b"SSH-2.0\r\n";

    let result = detector.detect(data);
    assert!(result.is_some());

    let detection = result.unwrap();
    if let Metadata::Ssh(meta) = detection.metadata {
        assert_eq!(meta.version, Some("2.0".to_string()));
        assert!(meta.software.is_none());
    } else {
        panic!("Expected Ssh metadata");
    }
}
