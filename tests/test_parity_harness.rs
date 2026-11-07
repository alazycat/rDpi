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

#[test]
fn ndpi_adapter_output_compares_with_rder_record() {
    // nDPI 真实输出（DNS 流，含 flow_risk 块）
    let ndpi_line = r#"{"src_ip":"192.168.1.1","dest_ip":"10.0.0.1","src_port":12345,"dst_port":53,"proto":"UDP","ndpi":{"confidence":{"6":"DPI"},"proto":"DNS","category":"Network","breed":"Acceptable","flow_risk":{"46":{"risk":"Unidirectional Traffic"}}}}"#;
    let expected = vec![NormalizedFlow::from_ndpi_json(ndpi_line).unwrap()];

    // rDpi 侧同一条流：反向五元组、小写名称、下划线风险名，
    // 验证双向规范键匹配与大小写/风险顺序归一化。
    let actual = vec![NormalizedFlow {
        src_ip: "10.0.0.1".into(),
        dst_ip: "192.168.1.1".into(),
        src_port: 53,
        dst_port: 12345,
        transport: "udp".into(),
        master_protocol: Some("Dns".into()),
        app_protocol: None,
        category: Some("Network".into()),
        breed: Some("Acceptable".into()),
        confidence: Some("Dpi".into()),
        protocol_stack: vec!["Dns".into()],
        risk_mask: vec!["Unidirectional_Traffic".into()],
    }];

    let report = compare_flows(&expected, &actual);
    assert!(report.is_match(), "unexpected diff: {report:?}");
}
