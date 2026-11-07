//! P0 差分链路：nDPI ndpiReader JSON → 归一化记录适配器测试
//!
//! 依赖 `json` feature。夹具取自 nDPI 5.0 `ndpiReader -K json` 的真实输出。

#![cfg(feature = "json")]

use rdpi::parity::{NormalizedFlow, parse_ndpi_jsonl};

/// 真实 ndpiReader 输出（单条 DNS 流，已裁剪与适配无关的统计块）
const NDPI_DNS_RECORD: &str = r#"{
  "src_ip":"192.168.1.1",
  "dest_ip":"10.0.0.1",
  "src_port":12345,
  "dst_port":53,
  "ip":4,
  "proto":"UDP",
  "ndpi":{
    "flow_risk":{
      "46":{"risk":"Unidirectional Traffic","severity":"Low",
            "risk_score":{"total":500,"client":430,"server":70}}
    },
    "confidence":{"6":"DPI"},
    "proto":"DNS",
    "proto_id":"5",
    "proto_by_ip":"Unknown",
    "proto_by_ip_id":0,
    "encrypted":0,
    "breed":"Acceptable",
    "category_id":14,
    "category":"Network",
    "hostname":"example.com",
    "domainame":"example.com"
  },
  "detection_completed":0,
  "check_extra_packets":0,
  "flow_id":0,
  "first_seen":1700000000.000,
  "last_seen":1700000000.000,
  "duration":0.000,
  "vlan_id":0,
  "bidirectional":0
}"#;

#[test]
fn parses_real_ndpi_reader_record() {
    let flow = NormalizedFlow::from_ndpi_json(NDPI_DNS_RECORD).unwrap();
    assert_eq!(flow.src_ip, "192.168.1.1");
    assert_eq!(flow.dst_ip, "10.0.0.1", "nDPI uses dest_ip");
    assert_eq!(flow.src_port, 12345);
    assert_eq!(flow.dst_port, 53);
    assert_eq!(flow.transport, "udp");
    assert_eq!(flow.master_protocol.as_deref(), Some("DNS"));
    assert_eq!(flow.app_protocol, None);
    assert_eq!(flow.category.as_deref(), Some("Network"));
    assert_eq!(flow.breed.as_deref(), Some("Acceptable"));
    assert_eq!(flow.confidence.as_deref(), Some("DPI"));
    assert_eq!(flow.protocol_stack, vec!["DNS".to_string()]);
    assert_eq!(
        flow.risk_mask,
        vec!["unidirectional_traffic".to_string()],
        "risk names are normalized to snake_case"
    );
}

#[test]
fn parses_master_and_app_protocol() {
    let json = r#"{
      "src_ip":"10.0.0.1","dest_ip":"10.0.0.2","src_port":50000,"dst_port":443,
      "proto":"TCP",
      "ndpi":{"proto":"TLS.YouTube","confidence":{"6":"DPI"},
              "category":"Media","breed":"Safe"}
    }"#;
    let flow = NormalizedFlow::from_ndpi_json(json).unwrap();
    assert_eq!(flow.transport, "tcp");
    assert_eq!(flow.master_protocol.as_deref(), Some("TLS"));
    assert_eq!(flow.app_protocol.as_deref(), Some("YouTube"));
    assert_eq!(
        flow.protocol_stack,
        vec!["TLS".to_string(), "YouTube".to_string()]
    );
}

#[test]
fn optional_fields_default_when_absent() {
    // ICMP：nDPI 省略端口；无风险块、无置信度块
    let json = r#"{
      "src_ip":"10.0.0.1","dest_ip":"10.0.0.2","proto":"ICMP",
      "ndpi":{"proto":"ICMP"}
    }"#;
    let flow = NormalizedFlow::from_ndpi_json(json).unwrap();
    assert_eq!(flow.src_port, 0);
    assert_eq!(flow.dst_port, 0);
    assert_eq!(flow.transport, "icmp");
    assert_eq!(flow.master_protocol.as_deref(), Some("ICMP"));
    assert_eq!(flow.confidence, None);
    assert!(flow.risk_mask.is_empty());
    assert_eq!(flow.category, None);
    assert_eq!(flow.breed, None);
}

#[test]
fn jsonl_parser_skips_blank_lines() {
    // ndpiReader 实际输出为单行一条记录；此处复刻其行格式
    let line = r#"{"src_ip":"192.168.1.1","dest_ip":"10.0.0.1","src_port":12345,"dst_port":53,"proto":"UDP","ndpi":{"confidence":{"6":"DPI"},"proto":"DNS","category":"Network","breed":"Acceptable"}}"#;
    let jsonl = format!("\n{line}\n\n{line}\n");
    let flows = parse_ndpi_jsonl(&jsonl).unwrap();
    assert_eq!(flows.len(), 2);
    assert_eq!(flows[0], flows[1]);
}

#[test]
fn malformed_line_is_error() {
    assert!(NormalizedFlow::from_ndpi_json("{not json").is_err());
    assert!(NormalizedFlow::from_ndpi_json(r#"{"src_ip":"10.0.0.1"}"#).is_err());
}
