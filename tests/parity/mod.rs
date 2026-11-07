//! P0 差分测试：归一化流记录与比较器
//!
//! nDPI 与 rDpi 的输出先归一化成 [`NormalizedFlow`]，再由
//! [`compare_flows`] 按双向规范五元组匹配并逐字段比较。
//!
//! 该模块只定义比较契约，不负责调用 nDPI/rDpi；真实语料生成见
//! `tests/parity/README.md`。

use std::collections::HashMap;

/// 归一化后的单条流记录（schema 定义在库内，供 CLI per-flow 输出复用）
pub use rdpi::parity::NormalizedFlow;

/// 单字段差异
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDiff {
    /// 规范五元组（人类可读）
    pub flow: String,
    /// 字段名
    pub field: &'static str,
    /// 期望值（nDPI）
    pub expected: String,
    /// 实际值（rDpi）
    pub actual: String,
}

/// 差分报告
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DiffReport {
    pub diffs: Vec<FlowDiff>,
    /// 期望存在、实际缺失的流
    pub missing: Vec<String>,
    /// 实际多出的流
    pub extra: Vec<String>,
}

impl DiffReport {
    /// 是否完全一致
    pub fn is_match(&self) -> bool {
        self.diffs.is_empty() && self.missing.is_empty() && self.extra.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CanonicalKey {
    a: String,
    b: String,
    transport: String,
}

impl CanonicalKey {
    fn label(&self) -> String {
        format!("{} <-> {} [{}]", self.a, self.b, self.transport)
    }
}

fn endpoint(ip: &str, port: u16) -> String {
    format!("{ip}:{port}")
}

fn canonical_key(flow: &NormalizedFlow) -> CanonicalKey {
    let src = endpoint(&flow.src_ip, flow.src_port);
    let dst = endpoint(&flow.dst_ip, flow.dst_port);
    let (a, b) = if src <= dst { (src, dst) } else { (dst, src) };
    CanonicalKey {
        a,
        b,
        transport: flow.transport.to_ascii_lowercase(),
    }
}

fn normalize_opt(value: &Option<String>) -> Option<String> {
    value.as_ref().map(|v| v.to_ascii_lowercase())
}

fn display_opt(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "<none>".to_string())
}

fn push_opt_diff(
    report: &mut DiffReport,
    flow: &str,
    field: &'static str,
    expected: &Option<String>,
    actual: &Option<String>,
) {
    if normalize_opt(expected) != normalize_opt(actual) {
        report.diffs.push(FlowDiff {
            flow: flow.to_string(),
            field,
            expected: display_opt(expected),
            actual: display_opt(actual),
        });
    }
}

fn normalize_list(values: &[String]) -> Vec<String> {
    values.iter().map(|v| v.to_ascii_lowercase()).collect()
}

fn normalized_risk_mask(values: &[String]) -> Vec<String> {
    let mut values = normalize_list(values);
    values.sort();
    values.dedup();
    values
}

/// nDPI 5.0 中 rDpi 不建模的流级启发式风险
///
/// 这些风险依赖 nDPI 内部指纹库（`malicious_fingerprint`）、IP/ASN 元数据
/// （`mismatching_protocol_with_server_ip_address`）、端到端流量统计
/// （`unidirectional_traffic`）、HTTP 解析器自有启发式（`malformed_packet`、
/// `tls_probably_not_carrying_https`、`http_susp_user_agent`——nDPI 对
/// 缺失/空 User-Agent 的 CONNECT/代理请求告警，rDpi 无此旗标）或端口启发式
/// （`known_proto_on_non_std_port`）。差分时从两侧集合中剔除，避免把
/// “未建模”误报为差异；其余风险要求两侧集合完全一致。
pub const NDPI_UNMODELED_RISKS: &[&str] = &[
    "malicious_fingerprint",
    "malformed_packet",
    "mismatching_protocol_with_server_ip_address",
    "tls_probably_not_carrying_https",
    "unidirectional_traffic",
    "known_proto_on_non_std_port",
    "http_susp_user_agent",
];

/// rDpi 与 nDPI 5.0 同语义风险的名称别名（风险名统一到右侧 nDPI 命名）
///
/// 仅列同语义不同名的映射；nDPI 端名称须真实存在于 golden 输出中。
pub const NDPI_RISK_ALIASES: &[(&str, &str)] = &[
    // rDpi RiskFlag::TlsMissingSni ↔ nDPI TLS 解析器 missing_sni_tls_extn
    ("tls_missing_sni", "missing_sni_tls_extn"),
    // rDpi RiskFlag::SmbInsecureVersion ↔ nDPI SMB 解析器 smb_insecure_ver
    ("smb_insecure_version", "smb_insecure_ver"),
];

/// 判断 `compare_flows` 报告中的两条 risk_mask 是否等价
///
/// 输入为 `FlowDiff` 里的逗号分隔字符串（风险名均为 snake_case，不含逗号）。
/// 名称先经 [`NDPI_RISK_ALIASES`] 归一，忽略 [`NDPI_UNMODELED_RISKS`] 后按
/// 大小写不敏感、顺序不敏感、去重比较。
pub fn risk_masks_equivalent(expected: &str, actual: &str) -> bool {
    fn canonical(name: &str) -> &str {
        for (from, to) in NDPI_RISK_ALIASES {
            if name.eq_ignore_ascii_case(from) || name.eq_ignore_ascii_case(to) {
                return to;
            }
        }
        name
    }

    fn normalized(value: &str) -> Vec<String> {
        let mut out: Vec<String> = value
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| canonical(name).to_ascii_lowercase())
            .filter(|name| !NDPI_UNMODELED_RISKS.contains(&name.as_str()))
            .collect();
        out.sort();
        out.dedup();
        out
    }
    normalized(expected) == normalized(actual)
}

/// 比较两组归一化流记录
///
/// 流按双向规范五元组匹配（与方向无关）；字段比较规则：
/// - 协议/应用/category/breed/confidence：大小写不敏感；
/// - protocol_stack：大小写不敏感且**顺序敏感**；
/// - risk_mask：大小写不敏感、顺序不敏感、去重。
pub fn compare_flows(expected: &[NormalizedFlow], actual: &[NormalizedFlow]) -> DiffReport {
    let mut expected_map: HashMap<CanonicalKey, &NormalizedFlow> = HashMap::new();
    let mut actual_map: HashMap<CanonicalKey, &NormalizedFlow> = HashMap::new();

    for flow in expected {
        expected_map.entry(canonical_key(flow)).or_insert(flow);
    }
    for flow in actual {
        actual_map.entry(canonical_key(flow)).or_insert(flow);
    }

    let mut report = DiffReport::default();

    for (key, expected_flow) in &expected_map {
        let Some(actual_flow) = actual_map.get(key) else {
            report.missing.push(key.label());
            continue;
        };
        let label = key.label();

        push_opt_diff(
            &mut report,
            &label,
            "master_protocol",
            &expected_flow.master_protocol,
            &actual_flow.master_protocol,
        );
        push_opt_diff(
            &mut report,
            &label,
            "app_protocol",
            &expected_flow.app_protocol,
            &actual_flow.app_protocol,
        );
        push_opt_diff(
            &mut report,
            &label,
            "category",
            &expected_flow.category,
            &actual_flow.category,
        );
        push_opt_diff(
            &mut report,
            &label,
            "breed",
            &expected_flow.breed,
            &actual_flow.breed,
        );
        push_opt_diff(
            &mut report,
            &label,
            "confidence",
            &expected_flow.confidence,
            &actual_flow.confidence,
        );

        let expected_stack = normalize_list(&expected_flow.protocol_stack);
        let actual_stack = normalize_list(&actual_flow.protocol_stack);
        if expected_stack != actual_stack {
            report.diffs.push(FlowDiff {
                flow: label.clone(),
                field: "protocol_stack",
                expected: expected_stack.join(","),
                actual: actual_stack.join(","),
            });
        }

        let expected_risks = normalized_risk_mask(&expected_flow.risk_mask);
        let actual_risks = normalized_risk_mask(&actual_flow.risk_mask);
        if expected_risks != actual_risks {
            report.diffs.push(FlowDiff {
                flow: label.clone(),
                field: "risk_mask",
                expected: expected_risks.join(","),
                actual: actual_risks.join(","),
            });
        }
    }

    for key in actual_map.keys() {
        if !expected_map.contains_key(key) {
            report.extra.push(key.label());
        }
    }

    report
}

#[cfg(test)]
mod risk_policy_tests {
    use super::risk_masks_equivalent;

    #[test]
    fn unmodeled_ndpi_risks_are_ignored() {
        assert!(risk_masks_equivalent(
            "missing_sni_tls_extn,malicious_fingerprint,tls_probably_not_carrying_https",
            "missing_sni_tls_extn"
        ));
        assert!(risk_masks_equivalent(
            "unsafe_protocol,clear_text_credentials,malicious_fingerprint",
            "clear_text_credentials,unsafe_protocol"
        ));
        // 两侧都出现未建模风险时同样忽略
        assert!(risk_masks_equivalent("unidirectional_traffic", ""));
    }

    #[test]
    fn modeled_risks_must_match_exactly() {
        assert!(!risk_masks_equivalent("unsafe_protocol", ""));
        assert!(!risk_masks_equivalent("", "obfuscated_traffic"));
        assert!(!risk_masks_equivalent(
            "missing_sni_tls_extn",
            "missing_sni_tls_extn,unsafe_protocol"
        ));
    }
}
