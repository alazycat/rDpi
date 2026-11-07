//! P0 语料差分：rDpi per-flow 输出 vs nDPI 5.0 golden
//!
//! 语料与 golden 均由仓库内文件提供：
//! - `tests/parity/corpus/*.pcap`：自生成语料（`gen_corpus.py`）；
//! - `tests/parity/golden/*.ndpi.json`：同语料上的真实 ndpiReader 输出。
//!
//! 本测试断言 flow 集合与 master protocol 一致；category/breed/risk 的
//! 语义差异只在输出中报告，暂不判定失败（映射表是后续工作）。

#![cfg(all(feature = "pcap", feature = "json"))]

mod parity;

use parity::{NormalizedFlow, compare_flows, risk_masks_equivalent};
use rdpi::pcap::PcapProcessor;
use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn corpus_dir() -> PathBuf {
    manifest_dir().join("tests").join("parity").join("corpus")
}

fn golden_dir() -> PathBuf {
    manifest_dir().join("tests").join("parity").join("golden")
}

fn golden_for(pcap: &Path) -> PathBuf {
    let stem = pcap.file_stem().unwrap().to_string_lossy();
    golden_dir().join(format!("{stem}.ndpi.json"))
}

fn is_pcap(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("pcap" | "pcapng")
    )
}

/// 用库内 pcap 入口跑完整检测，导出归一化流记录
fn rder_flows(pcap: &Path) -> Vec<NormalizedFlow> {
    let mut iter = PcapProcessor::new()
        .process_file(pcap)
        .unwrap_or_else(|e| panic!("open {}: {e}", pcap.display()));
    for item in iter.by_ref() {
        item.unwrap_or_else(|e| panic!("process {}: {e}", pcap.display()));
    }
    iter.detector().normalized_flows()
}

#[test]
fn corpus_classification_matches_ndpi_golden() {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(corpus_dir())
        .expect("corpus directory")
        .map(|entry| entry.expect("corpus entry").path())
        .filter(|path| is_pcap(path))
        .collect();
    entries.sort();

    let mut failures = Vec::new();
    for pcap in &entries {
        let name = pcap.file_name().unwrap().to_string_lossy().to_string();
        let golden_path = golden_for(pcap);
        let golden_raw = std::fs::read_to_string(&golden_path).unwrap_or_else(|_| {
            panic!(
                "missing golden {} for {name}; regenerate with ndpiReader",
                golden_path.display()
            )
        });
        let expected: Vec<NormalizedFlow> = rdpi::parity::parse_ndpi_jsonl(&golden_raw)
            .unwrap_or_else(|e| panic!("parse golden {}: {e}", golden_path.display()));
        let actual = rder_flows(pcap);
        let report = compare_flows(&expected, &actual);

        let count_diff = |field: &str| {
            report
                .diffs
                .iter()
                .filter(|diff| diff.field == field)
                .count()
        };
        // 剔除 nDPI 专有启发式后仍不一致的风险差异数（门禁实际判定项）
        let risk_gate_diffs = report
            .diffs
            .iter()
            .filter(|diff| {
                diff.field == "risk_mask" && !risk_masks_equivalent(&diff.expected, &diff.actual)
            })
            .count();
        println!(
            "{name}: ndpi={} rder={} all_match={} master={} app={} category={} breed={} confidence={} risk={} risk_gate={}",
            expected.len(),
            actual.len(),
            report.is_match(),
            count_diff("master_protocol"),
            count_diff("app_protocol"),
            count_diff("category"),
            count_diff("breed"),
            count_diff("confidence"),
            count_diff("risk_mask"),
            risk_gate_diffs,
        );

        for missing in &report.missing {
            failures.push(format!("{name}: missing flow {missing}"));
        }
        for extra in &report.extra {
            failures.push(format!("{name}: extra flow {extra}"));
        }
        for diff in &report.diffs {
            match diff.field {
                // 已用真实 nDPI 5.0 验证的分类字段：语料上要求完全一致
                "master_protocol" | "category" | "breed" => {
                    failures.push(format!(
                        "{name}: {} expected {} actual {}",
                        diff.field, diff.expected, diff.actual
                    ));
                }
                // nDPI 仅按端口匹配或只完成部分 DPI、rDpi 通过载荷解析出
                // 更高置信度时视为通过
                "confidence"
                    if (diff.expected.eq_ignore_ascii_case("Match by port")
                        || diff.expected.eq_ignore_ascii_case("DPI (partial)"))
                        && diff.actual.eq_ignore_ascii_case("Dpi") => {}
                "confidence" => {
                    failures.push(format!(
                        "{name}: {} expected {} actual {}",
                        diff.field, diff.expected, diff.actual
                    ));
                }
                // nDPI 明确识别出 app 时，rDpi 不得漏识别或给出不同名称；
                // nDPI 无 app（如 DNS 查询）时允许 rDpi 更丰富。
                "app_protocol" if diff.expected != "<none>" => {
                    failures.push(format!(
                        "{name}: app_protocol expected {} actual {}",
                        diff.expected, diff.actual
                    ));
                }
                // 未启用 risk feature 时 rDpi 不产出风险，仅报告不判定
                "risk_mask" if !cfg!(feature = "risk") => {}
                // 剔除 nDPI 专有启发式后要求风险集合完全一致：
                // rDpi 不得漏报已建模风险，也不得产出 nDPI 未见的风险
                "risk_mask" if risk_masks_equivalent(&diff.expected, &diff.actual) => {}
                "risk_mask" => {
                    failures.push(format!(
                        "{name}: risk_mask expected {} actual {}",
                        diff.expected, diff.actual
                    ));
                }
                _ => {}
            }
        }
    }

    assert!(
        entries.len() >= 20,
        "corpus should contain at least 20 pcaps, found {}",
        entries.len()
    );
    assert!(
        failures.is_empty(),
        "parity failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn every_golden_file_has_corpus_pcap() {
    let mut goldens = 0usize;
    for entry in std::fs::read_dir(golden_dir()).expect("golden directory") {
        let path = entry.expect("golden entry").path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy();
        let stem = name
            .strip_suffix(".ndpi.json")
            .unwrap_or_else(|| panic!("unexpected golden file {name}"));
        let pcap = corpus_dir().join(format!("{stem}.pcap"));
        if !pcap.exists() {
            let pcapng = corpus_dir().join(format!("{stem}.pcapng"));
            assert!(pcapng.exists(), "golden {name} has no matching corpus pcap");
        }
        goldens += 1;
    }
    assert!(
        goldens >= 20,
        "expected at least 20 golden files, found {goldens}"
    );
}
