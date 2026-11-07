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
