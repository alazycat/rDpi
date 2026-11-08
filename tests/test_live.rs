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

#[test]
fn devices_return_list_or_backend_error() {
    match rdpi::live::devices() {
        Ok(devices) => {
            for device in devices {
                assert!(!device.name.is_empty());
            }
        }
        Err(LiveError::BackendUnavailable { .. }) => {}
        Err(error) => panic!("unexpected device enumeration error: {error}"),
    }
}

use rdpi::live::LiveCapture;

#[test]
fn open_empty_device_is_device_not_found() {
    match LiveCapture::open(CaptureConfig::new("")) {
        Err(LiveError::DeviceNotFound(name)) => assert!(name.is_empty()),
        Err(error) => panic!("unexpected error: {error:?}"),
        Ok(_) => panic!("unexpected success"),
    }
}

#[test]
fn open_unknown_device_reports_failure() {
    match LiveCapture::open(CaptureConfig::new("rdpi-definitely-not-a-device")) {
        Err(LiveError::OpenFailed { .. }) | Err(LiveError::BackendUnavailable { .. }) => {}
        Err(error) => panic!("unexpected error: {error:?}"),
        Ok(_) => panic!("unexpected success"),
    }
}

#[test]
fn signal_error_mentions_ctrl_c() {
    let error = LiveError::Signal("already installed".to_string());
    assert!(error.to_string().contains("Ctrl-C"));
}

#[test]
fn invalid_bpf_is_reported_when_backend_available() {
    let Ok(devices) = rdpi::live::devices() else {
        return;
    };
    let Some(device) = devices.into_iter().next() else {
        return;
    };

    let config = CaptureConfig::new(device.name).filter("this is not a bpf");
    match LiveCapture::open(config) {
        Err(LiveError::Filter { expression, .. }) => {
            assert_eq!(expression, "this is not a bpf");
        }
        // 权限不足等环境问题下无法走到过滤器编译，跳过。
        Err(LiveError::OpenFailed { .. }) | Err(LiveError::BackendUnavailable { .. }) => {}
        Err(error) => panic!("unexpected error: {error:?}"),
        Ok(_) => panic!("unexpected success"),
    }
}
