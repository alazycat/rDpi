//! rDpi CLI — 网络流量协议识别工具
//!
//! 从 pcap 文件读取流量，识别协议，输出流统计和协议汇总。
//!
//! 输出格式：
//! - `text`（默认）：人类可读汇总
//! - `csv`：协议计数表
//! - `json`：单 JSON 文档 `{summary, packets}`（`packets` 需 `-v`，收集于内存，
//!   超大 pcap 请改用 `jsonl`）
//! - `jsonl`：JSON Lines 流式输出（每行一个对象：packet/unknown/summary，
//!   零内存缓冲，适合大文件与管道消费）
//!
//! `json` / `jsonl` 需要 `--features json` 重建（该 feature 为库类型派生
//! `Serialize`）。

use clap::Parser;
use rdpi::DetectionResult;
use rdpi::pcap::PcapProcessor;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

/// rDpi — Rust Deep Packet Inspection CLI
#[derive(Parser)]
#[command(
    name = "rdpi",
    version = env!("CARGO_PKG_VERSION"),
    about = "Network traffic protocol identification tool"
)]
struct Cli {
    /// 输入的 pcap/pcapng 文件路径
    #[arg(short = 'i', long = "input", value_name = "FILE")]
    input: PathBuf,

    /// 输出格式（text / json / jsonl / csv）
    #[arg(short = 'o', long = "output", default_value = "text")]
    output: String,

    /// 显示每个包的检测结果（json 形态下加入 packets 数组 / jsonl 输出逐包行）
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // json/jsonl 依赖 json feature（库类型 Serialize 派生）；未启用时
    // json 降级为仅 summary 的手写兼容输出，jsonl 直接报错退出
    if (cli.output == "jsonl") && !cfg!(feature = "json") {
        eprintln!("error: output format 'jsonl' requires building with --features json");
        std::process::exit(2);
    }

    let start = Instant::now();
    let processor = PcapProcessor::new();
    let iter = processor.process_file(&cli.input)?;

    let mut protocol_counts: HashMap<String, u64> = HashMap::new();
    let mut total_packets = 0u64;
    let mut detected_packets = 0u64;
    // json 单文档模式的逐包收集（仅 verbose）
    #[cfg(feature = "json")]
    let mut packet_records: Vec<PacketRecord> = Vec::new();

    for item in iter {
        let maybe_result = item?; // Result<Option<(u64, DetectionResult)>>
        total_packets += 1;

        if let Some((ts, det)) = maybe_result {
            detected_packets += 1;
            let proto_name = format!("{:?}", det.protocol);
            *protocol_counts.entry(proto_name).or_insert(0) += 1;
            let _ = ts; // 非 verbose / 非 json 路径不消费时间戳

            if cli.verbose {
                #[cfg(feature = "json")]
                {
                    match cli.output.as_str() {
                        "jsonl" => {
                            let rec = PacketRecord::new(total_packets, ts, det);
                            println!("{}", serde_json::to_string(&rec)?);
                            continue;
                        }
                        "json" => {
                            packet_records.push(PacketRecord::new(total_packets, ts, det));
                            continue;
                        }
                        _ => {}
                    }
                }
                #[cfg(not(feature = "json"))]
                {
                    let _ = ts;
                }
                print_detection(total_packets, &det);
            }
        } else if cli.verbose {
            #[cfg(feature = "json")]
            if cli.output == "jsonl" {
                println!(
                    "{}",
                    serde_json::to_string(&UnknownRecord {
                        r#type: "unknown",
                        packet_no: total_packets,
                    })?
                );
                continue;
            }
            println!("[{:6}] UNKNOWN", total_packets);
        }
    }

    let elapsed = start.elapsed();

    match cli.output.as_str() {
        "json" => {
            #[cfg(feature = "json")]
            {
                let summary =
                    Summary::build(total_packets, detected_packets, &protocol_counts, elapsed);
                let doc = serde_json::json!({ "summary": summary, "packets": packet_records });
                println!("{}", serde_json::to_string_pretty(&doc)?);
            }
            #[cfg(not(feature = "json"))]
            print_json_summary(total_packets, detected_packets, &protocol_counts, elapsed);
        }
        "jsonl" => {
            #[cfg(feature = "json")]
            {
                let summary =
                    Summary::build(total_packets, detected_packets, &protocol_counts, elapsed);
                println!(
                    "{}",
                    serde_json::to_string(&JsonlLine {
                        r#type: "summary",
                        summary: &summary,
                    })?
                );
            }
        }
        "csv" => print_csv_summary(&protocol_counts),
        _ => print_text_summary(total_packets, detected_packets, &protocol_counts, elapsed),
    }

    Ok(())
}

/// 逐包检测记录（JSON 输出用）
///
/// `detection` 字段整体展开（flatten）：protocol / confidence / metadata /
/// category / breed / app_protocol / risks（feature=risk 时）。
#[cfg(feature = "json")]
#[derive(serde::Serialize)]
struct PacketRecord {
    /// 包序号（1-based）
    packet_no: u64,
    /// pcap 时间戳（微秒；SimplePacket 块为 0）
    timestamp_us: u64,
    /// 检测结果（flatten 展开）
    #[serde(flatten)]
    detection: DetectionResult,
}

#[cfg(feature = "json")]
impl PacketRecord {
    fn new(packet_no: u64, timestamp_us: u64, detection: DetectionResult) -> Self {
        Self {
            packet_no,
            timestamp_us,
            detection,
        }
    }
}

/// jsonl 未识别包占位行
#[cfg(feature = "json")]
#[derive(serde::Serialize)]
struct UnknownRecord {
    /// 行类型标记
    #[serde(rename = "type")]
    r#type: &'static str,
    /// 包序号
    packet_no: u64,
}

/// 检测汇总（JSON 输出用）
#[cfg(feature = "json")]
#[derive(serde::Serialize)]
struct Summary {
    total_packets: u64,
    detected_packets: u64,
    /// 识别率（0-1）
    detection_rate: f64,
    /// 处理耗时（秒）
    elapsed_seconds: f64,
    /// 吞吐（包/秒）
    throughput_pps: f64,
    /// 协议分布（按计数降序）
    protocols: Vec<ProtocolCount>,
}

#[cfg(feature = "json")]
#[derive(serde::Serialize)]
struct ProtocolCount {
    protocol: String,
    count: u64,
}

#[cfg(feature = "json")]
impl Summary {
    fn build(
        total: u64,
        detected: u64,
        counts: &HashMap<String, u64>,
        elapsed: std::time::Duration,
    ) -> Self {
        let secs = elapsed.as_secs_f64();
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        Summary {
            total_packets: total,
            detected_packets: detected,
            detection_rate: detected as f64 / total.max(1) as f64,
            elapsed_seconds: secs,
            throughput_pps: if secs > 0.0 { total as f64 / secs } else { 0.0 },
            protocols: sorted
                .into_iter()
                .map(|(p, c)| ProtocolCount {
                    protocol: p.clone(),
                    count: *c,
                })
                .collect(),
        }
    }
}

/// jsonl 逐行包装（附加 type 字段）
#[cfg(feature = "json")]
#[derive(serde::Serialize)]
struct JsonlLine<'a> {
    /// 行类型标记
    #[serde(rename = "type")]
    r#type: &'static str,
    /// 汇总内容（flatten 展开）
    #[serde(flatten)]
    summary: &'a Summary,
}

fn print_detection(pkt_num: u64, det: &DetectionResult) {
    let meta_str = match &det.metadata {
        rdpi::Metadata::Dns(dns) => dns.query_domain.as_deref().unwrap_or(""),
        rdpi::Metadata::Tls(tls) => tls.sni.as_deref().unwrap_or(""),
        // QUIC：优先 SNI，其次 ALPN（服务端方向只有 ALPN）
        rdpi::Metadata::Quic(quic) => quic
            .sni
            .as_deref()
            .unwrap_or(quic.alpn.as_deref().unwrap_or("")),
        rdpi::Metadata::Http(http) => http.host.as_deref().unwrap_or(""),
        rdpi::Metadata::Ssh(ssh) => ssh.software.as_deref().unwrap_or(""),
        // F37：DHCP/DHCPv6 主元数据即 JA4D/JA4D6 指纹
        rdpi::Metadata::Dhcp(d) => &d.ja4d,
        #[cfg(feature = "infra")]
        rdpi::Metadata::Dhcpv6(d) => &d.ja4d6,
        _ => "",
    };

    // F33：JA4T 客户端 TCP 指纹（来自流的初始 SYN 包）
    let ja4t_str = det
        .ja4t
        .as_deref()
        .map(|j| format!(" ja4t={}", j))
        .unwrap_or_default();

    // F34：JA4TS 服务端 TCP 指纹（来自服务端方向的 SYN-ACK 包）
    let ja4ts_str = det
        .ja4ts
        .as_deref()
        .map(|j| format!(" ja4ts={}", j))
        .unwrap_or_default();

    // F35：JA4L-S/C 时延指纹（半程时延µs_TTL）
    let ja4l_str = match (det.ja4ls.as_deref(), det.ja4lc.as_deref()) {
        (Some(s), Some(c)) => format!(" ja4ls={} ja4lc={}", s, c),
        (Some(s), None) => format!(" ja4ls={}", s),
        (None, Some(c)) => format!(" ja4lc={}", c),
        (None, None) => String::new(),
    };

    // F36：JA4SSH 会话指纹（最近完成的 200 载荷包窗口）
    let ja4ssh_str = det
        .ja4ssh
        .as_deref()
        .map(|j| format!(" ja4ssh={}", j))
        .unwrap_or_default();

    if meta_str.is_empty()
        && ja4t_str.is_empty()
        && ja4ts_str.is_empty()
        && ja4l_str.is_empty()
        && ja4ssh_str.is_empty()
    {
        println!("[{:6}] {:?} [{:?}]", pkt_num, det.protocol, det.confidence);
    } else {
        println!(
            "[{:6}] {:?} ({}{}{}{}{}) [{:?}]",
            pkt_num,
            det.protocol,
            meta_str,
            ja4t_str,
            ja4ts_str,
            ja4l_str,
            ja4ssh_str,
            det.confidence
        );
    }
}

fn print_text_summary(
    total: u64,
    detected: u64,
    counts: &HashMap<String, u64>,
    elapsed: std::time::Duration,
) {
    let secs = elapsed.as_secs_f64();
    let rate = if secs > 0.0 { total as f64 / secs } else { 0.0 };

    println!("\n=== rDpi Detection Summary ===");
    println!("  Total packets:   {}", total);
    println!(
        "  Detected:        {} ({:.1}%)",
        detected,
        (detected as f64 / total.max(1) as f64 * 100.0)
    );
    println!("  Elapsed:         {:.2}s", secs);
    println!("  Throughput:      {:.0} pkt/s", rate);

    if !counts.is_empty() {
        println!("\n  Protocol breakdown:");
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (proto, count) in &sorted {
            let pct = (**count as f64) / (detected.max(1) as f64) * 100.0;
            println!("    {:24} {:>8} ({:>5.1}%)", proto, count, pct);
        }
    }
}

/// 兼容输出：json feature 未启用时的手写 summary JSON（仅汇总，无逐包数据）
#[cfg(not(feature = "json"))]
fn print_json_summary(
    total: u64,
    detected: u64,
    counts: &HashMap<String, u64>,
    elapsed: std::time::Duration,
) {
    print!(
        "{{\n  \"total_packets\": {},\n  \"detected_packets\": {},\n",
        total, detected
    );
    print!(
        "  \"elapsed_seconds\": {:.4},\n  \"protocols\": {{",
        elapsed.as_secs_f64()
    );
    let mut first = true;
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (proto, count) in &sorted {
        if !first {
            println!(",");
        }
        first = false;
        print!("    \"{}\": {}", proto, count);
    }
    if !first {
        println!();
    }
    println!("  }}\n}}");
}

fn print_csv_summary(counts: &HashMap<String, u64>) {
    println!("protocol,count");
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (proto, count) in &sorted {
        println!("{},{}", proto, count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "json")]
    mod json_tests {
        use super::*;
        use rdpi::core::types::{Confidence, DnsMetadata, Metadata, Protocol};

        #[test]
        fn test_packet_record_serializes_full_detection() {
            let mut det =
                DetectionResult::new(Protocol::Dns).with_metadata(Metadata::Dns(DnsMetadata {
                    query_domain: Some("example.com".to_string()),
                    application: None,
                }));
            det.confidence = Confidence::Dpi;
            let rec = PacketRecord::new(1, 1700000000, det);
            let s = serde_json::to_string(&rec).unwrap();
            assert!(s.contains("\"packet_no\":1"));
            assert!(s.contains("\"timestamp_us\":1700000000"));
            assert!(s.contains("\"protocol\":\"Dns\""));
            assert!(s.contains("\"confidence\":\"Dpi\""));
            assert!(s.contains("\"query_domain\":\"example.com\""));
        }

        #[test]
        fn test_summary_build_sorted_and_rate() {
            let mut counts = HashMap::new();
            counts.insert("Quic".to_string(), 30u64);
            counts.insert("Dns".to_string(), 50u64);
            counts.insert("Http".to_string(), 50u64);
            let s = Summary::build(100, 130, &counts, std::time::Duration::from_millis(500));
            // 降序 + 同计数按名称升序：Dns, Http, Quic
            assert_eq!(s.protocols[0].protocol, "Dns");
            assert_eq!(s.protocols[1].protocol, "Http");
            assert_eq!(s.protocols[2].protocol, "Quic");
            assert!((s.detection_rate - 1.3).abs() < 1e-9);
            assert!((s.throughput_pps - 200.0).abs() < 1e-9);
        }

        #[test]
        fn test_jsonl_line_has_type_and_flat_summary() {
            let s = Summary::build(10, 10, &HashMap::new(), std::time::Duration::from_secs(1));
            let line = JsonlLine {
                r#type: "summary",
                summary: &s,
            };
            let out = serde_json::to_string(&line).unwrap();
            assert!(out.starts_with("{\"type\":\"summary\","));
            assert!(out.contains("\"total_packets\":10"));
        }

        #[test]
        fn test_unknown_record_shape() {
            let out = serde_json::to_string(&UnknownRecord {
                r#type: "unknown",
                packet_no: 7,
            })
            .unwrap();
            assert_eq!(out, r#"{"type":"unknown","packet_no":7}"#);
        }
    }
}
