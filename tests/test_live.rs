#![cfg(feature = "live")]

use rdpi::live::{CaptureConfig, LiveError};

#[test]
fn capture_config_defaults() {
    let config = CaptureConfig::new("eth0");
    assert_eq!(config.device, "eth0");
    assert_eq!(config.filter, None);
    assert_eq!(config.snaplen, 65535);
    assert!(config.promisc);
    assert_eq!(config.timeout_ms, 100);
}

#[test]
fn capture_config_builder_overrides() {
    let config = CaptureConfig::new("wlan0")
        .filter("tcp port 443")
        .snaplen(9000)
        .promisc(false)
        .timeout_ms(250);
    assert_eq!(config.filter.as_deref(), Some("tcp port 443"));
    assert_eq!(config.snaplen, 9000);
    assert!(!config.promisc);
    assert_eq!(config.timeout_ms, 250);
}

#[test]
fn backend_unavailable_error_mentions_candidates() {
    let error = LiveError::BackendUnavailable {
        tried: vec!["wpcap.dll: not found".to_string()],
        message: "not found".to_string(),
    };
    let text = error.to_string();
    assert!(text.contains("wpcap.dll"));
    assert!(text.contains("Npcap"));
}
