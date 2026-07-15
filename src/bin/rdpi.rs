//! rDpi CLI — 网络流量协议识别工具
//!
//! 从 pcap 文件读取流量，识别协议，输出流统计和协议汇总。

use clap::Parser;
use rdpi::pcap::PcapProcessor;
use rdpi::DetectionResult;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

/// rDpi — Rust Deep Packet Inspection CLI
#[derive(Parser)]
#[command(name = "rdpi", version = "0.2.0", about = "Network traffic protocol identification tool")]
struct Cli {
    /// 输入的 pcap/pcapng 文件路径
    #[arg(short = 'i', long = "input", value_name = "FILE")]
    input: PathBuf,

    /// 输出格式（text / json / csv）
    #[arg(short = 'o', long = "output", default_value = "text")]
    output: String,

    /// 显示每个包的检测结果
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let start = Instant::now();
    let processor = PcapProcessor::new();
    let iter = processor.process_file(&cli.input)?;

    let mut protocol_counts: HashMap<String, u64> = HashMap::new();
    let mut total_packets = 0u64;
    let mut detected_packets = 0u64;

    for item in iter {
        let maybe_result = item?; // Result<Option<(u64, DetectionResult)>>
        total_packets += 1;

        if let Some((_ts, det)) = maybe_result {
            detected_packets += 1;
            let proto_name = format!("{:?}", det.protocol);
            *protocol_counts.entry(proto_name).or_insert(0) += 1;

            if cli.verbose {
                print_detection(total_packets, &det);
            }
        } else if cli.verbose {
            println!("[{:6}] UNKNOWN", total_packets);
        }
    }

    let elapsed = start.elapsed();

    match cli.output.as_str() {
        "json" => print_json_summary(total_packets, detected_packets, &protocol_counts, elapsed),
        "csv" => print_csv_summary(&protocol_counts),
        _ => print_text_summary(total_packets, detected_packets, &protocol_counts, elapsed),
    }

    Ok(())
}

fn print_detection(pkt_num: u64, det: &DetectionResult) {
    let meta_str = match &det.metadata {
        rdpi::Metadata::Dns(dns) => dns.query_domain.as_deref().unwrap_or(""),
        rdpi::Metadata::Tls(tls) => tls.sni.as_deref().unwrap_or(""),
        rdpi::Metadata::Http(http) => http.host.as_deref().unwrap_or(""),
        rdpi::Metadata::Ssh(ssh) => ssh.software.as_deref().unwrap_or(""),
        _ => "",
    };

    if meta_str.is_empty() {
        println!("[{:6}] {:?} [{:?}]", pkt_num, det.protocol, det.confidence);
    } else {
        println!("[{:6}] {:?} ({}) [{:?}]", pkt_num, det.protocol, meta_str, det.confidence);
    }
}

fn print_text_summary(total: u64, detected: u64, counts: &HashMap<String, u64>, elapsed: std::time::Duration) {
    let secs = elapsed.as_secs_f64();
    let rate = if secs > 0.0 { total as f64 / secs } else { 0.0 };

    println!("\n=== rDpi Detection Summary ===");
    println!("  Total packets:   {}", total);
    println!("  Detected:        {} ({:.1}%)", detected, (detected as f64 / total.max(1) as f64 * 100.0));
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

fn print_json_summary(total: u64, detected: u64, counts: &HashMap<String, u64>, elapsed: std::time::Duration) {
    print!("{{\n  \"total_packets\": {},\n  \"detected_packets\": {},\n", total, detected);
    print!("  \"elapsed_seconds\": {:.4},\n  \"protocols\": {{", elapsed.as_secs_f64());
    let mut first = true;
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (proto, count) in &sorted {
        if !first { println!(","); }
        first = false;
        print!("    \"{}\": {}", proto, count);
    }
    if !first { println!(); }
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
