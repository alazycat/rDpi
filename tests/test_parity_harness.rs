//! P0 差分测试骨架：nDPI / rDpi 归一化流记录比较
//!
//! 依赖 `json` feature（serde/serde_json）。默认 features 下本测试不编译。
//! 真实语料生成方式见 `tests/parity/README.md`。

#![cfg(feature = "json")]

mod parity;

use parity::{NormalizedFlow, compare_flows};

fn flow(src: &str, src_port: u16, dst: &str, dst_port: u16) -> NormalizedFlow {
    NormalizedFlow {
        src_ip: src.into(),
        dst_ip: dst.into(),
        src_port,
        dst_port,
        transport: "tcp".into(),
        master_protocol: Some("TLS".into()),
        app_protocol: None,
        category: Some("Web".into()),
        breed: Some("Safe".into()),
        confidence: Some("DPI".into()),
        protocol_stack: vec!["TLS".into()],
        risk_mask: vec![],
    }
}

#[test]
fn identical_flows_match() {
    let expected = vec![flow("10.0.0.1", 12345, "10.0.0.2", 80)];
    let actual = expected.clone();

    let report = compare_flows(&expected, &actual);

    assert!(report.is_match(), "unexpected diff: {report:?}");
}

#[test]
fn reverse_direction_matches_canonical_key() {
    let expected = vec![flow("10.0.0.1", 12345, "10.0.0.2", 80)];
    let actual = vec![flow("10.0.0.2", 80, "10.0.0.1", 12345)];

    let report = compare_flows(&expected, &actual);

    assert!(report.is_match(), "unexpected diff: {report:?}");
}

#[test]
fn protocol_mismatch_is_reported() {
    let expected = vec![flow("10.0.0.1", 12345, "10.0.0.2", 80)];
    let mut actual = expected.clone();
    actual[0].master_protocol = Some("HTTP".into());

    let report = compare_flows(&expected, &actual);

    assert!(!report.is_match());
    assert_eq!(report.diffs.len(), 1);
    assert_eq!(report.diffs[0].field, "master_protocol");
    assert_eq!(report.diffs[0].expected, "TLS");
    assert_eq!(report.diffs[0].actual, "HTTP");
}

#[test]
fn missing_and_extra_flows_are_reported() {
    let expected = vec![flow("10.0.0.1", 12345, "10.0.0.2", 80)];
    let actual = vec![flow("10.0.0.3", 443, "10.0.0.4", 50000)];

    let report = compare_flows(&expected, &actual);

    assert!(!report.is_match());
    assert_eq!(report.missing.len(), 1);
    assert_eq!(report.extra.len(), 1);
}

#[test]
fn risk_mask_order_is_ignored() {
    let mut expected = vec![flow("10.0.0.1", 12345, "10.0.0.2", 80)];
    expected[0].risk_mask = vec!["TLS_MISSING_SNI".into(), "TLS_WEAK_CIPHER".into()];
    let mut actual = expected.clone();
    actual[0].risk_mask.reverse();

    let report = compare_flows(&expected, &actual);

    assert!(report.is_match(), "unexpected diff: {report:?}");
}

#[test]
fn protocol_stack_order_is_compared() {
    let mut expected = vec![flow("10.0.0.1", 12345, "10.0.0.2", 80)];
    expected[0].protocol_stack = vec!["TLS".into(), "HTTP".into()];
    let mut actual = expected.clone();
    actual[0].protocol_stack = vec!["HTTP".into(), "TLS".into()];

    let report = compare_flows(&expected, &actual);

    assert!(!report.is_match());
    assert_eq!(report.diffs[0].field, "protocol_stack");
}
