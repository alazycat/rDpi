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
//! - `flows-jsonl`：JSON Lines per-flow 归一化记录（P0 差分链路；
//!   不含逐包/汇总行）
//!
//! `json` / `jsonl` / `flows-jsonl` 需要 `--features json` 重建（该 feature
//! 为库类型派生 `Serialize`）。

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
    /// 输入的 pcap/pcapng 文件路径或网卡名（路径存在时按文件处理）
    #[arg(
        short = 'i',
        long = "input",
        value_name = "FILE|IFACE",
        required_unless_present_any = ["iface", "list_ifaces"],
        conflicts_with = "iface"
    )]
    input: Option<String>,

    /// 显式指定实时抓包网卡（与 -i 互斥）
    #[arg(long = "iface", value_name = "NAME", conflicts_with = "input")]
    iface: Option<String>,

    /// 列出可抓包设备后退出
    #[arg(long = "list-ifaces", conflicts_with_all = ["input", "iface"])]
    list_ifaces: bool,

    /// BPF 过滤表达式（仅实时抓包）
    #[arg(short = 'f', long = "filter", value_name = "BPF")]
    filter: Option<String>,

    /// 捕获指定帧数后停止（仅实时抓包）
    #[arg(long = "count", value_name = "N")]
    count: Option<u64>,

    /// 运行指定秒数后停止（仅实时抓包）
    #[arg(long = "duration", value_name = "SECS")]
    duration: Option<u64>,

    /// 输出格式（text / json / jsonl / csv / flows-jsonl）
    #[arg(short = 'o', long = "output", default_value = "text")]
    output: String,

    /// 显示每个包的检测结果（json 形态下加入 packets 数组 / jsonl 输出逐包行）
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

use rdpi::Detector;
use std::path::Path;

/// 文件/实时两条路径共用的统计与输出。
struct OutputSink<'a> {
    output: &'a str,
    verbose: bool,
    total_packets: u64,
    detected_packets: u64,
    protocol_counts: HashMap<String, u64>,
    #[cfg(feature = "json")]
    packet_records: Vec<PacketRecord>,
}

impl<'a> OutputSink<'a> {
    fn new(output: &'a str, verbose: bool) -> Self {
        Self {
            output,
            verbose,
            total_packets: 0,
            detected_packets: 0,
            protocol_counts: HashMap::new(),
            #[cfg(feature = "json")]
            packet_records: Vec::new(),
        }
    }

    #[cfg(any(test, feature = "live"))]
    fn total(&self) -> u64 {
        self.total_packets
    }

    #[cfg(test)]
    fn detected(&self) -> u64 {
        self.detected_packets
    }

    #[cfg(test)]
    fn protocol_counts(&self) -> &HashMap<String, u64> {
        &self.protocol_counts
    }

    fn on_packet(
        &mut self,
        timestamp_us: u64,
        detection: Option<DetectionResult>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let packet_no = self.total_packets + 1;
        self.on_packet_numbered(packet_no, timestamp_us, detection)
    }

    /// 以抓包序号记录一个包。
    ///
    /// 多线程收集端按完成顺序到达，`packet_no` 由抓包线程按抓取顺序分配，
    /// 因此可能乱序；`json` 收尾时按该序号重排恢复抓包顺序。
    fn on_packet_numbered(
        &mut self,
        packet_no: u64,
        timestamp_us: u64,
        detection: Option<DetectionResult>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(feature = "json"))]
        let _ = timestamp_us;

        self.total_packets += 1;

        match detection {
            Some(detection) => {
                self.detected_packets += 1;
                *self
                    .protocol_counts
                    .entry(format!("{:?}", detection.protocol))
                    .or_insert(0) += 1;

                if !self.verbose || self.output == "flows-jsonl" {
                    return Ok(());
                }

                #[cfg(feature = "json")]
                match self.output {
                    "jsonl" => {
                        println!(
                            "{}",
                            serde_json::to_string(&PacketRecord::new(
                                packet_no,
                                timestamp_us,
                                detection
                            ))?
                        );
                        return Ok(());
                    }
                    "json" => {
                        self.packet_records.push(PacketRecord::new(
                            packet_no,
                            timestamp_us,
                            detection,
                        ));
                        return Ok(());
                    }
                    _ => {}
                }

                print_detection(packet_no, &detection);
            }
            None => {
                if !self.verbose || self.output == "flows-jsonl" {
                    return Ok(());
                }

                #[cfg(feature = "json")]
                if self.output == "jsonl" {
                    println!(
                        "{}",
                        serde_json::to_string(&UnknownRecord {
                            r#type: "unknown",
                            packet_no,
                        })?
                    );
                    return Ok(());
                }

                println!("[{:6}] UNKNOWN", packet_no);
            }
        }

        Ok(())
    }

    fn finish(
        &mut self,
        elapsed: std::time::Duration,
        detectors: &[Detector],
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(feature = "json"))]
        let _ = detectors;

        if self.output == "flows-jsonl" {
            #[cfg(feature = "json")]
            for flow in merged_normalized_flows(detectors) {
                println!("{}", serde_json::to_string(&flow)?);
            }
            return Ok(());
        }

        match self.output {
            "json" => {
                #[cfg(feature = "json")]
                {
                    // 多线程下逐包记录按完成顺序入列；收尾按抓包序号恢复顺序。
                    self.packet_records.sort_by_key(|record| record.packet_no);
                    let summary = Summary::build(
                        self.total_packets,
                        self.detected_packets,
                        &self.protocol_counts,
                        elapsed,
                    );
                    let doc = serde_json::json!({
                        "summary": summary,
                        "packets": &self.packet_records
                    });
                    println!("{}", serde_json::to_string_pretty(&doc)?);
                }
                #[cfg(not(feature = "json"))]
                print_json_summary(
                    self.total_packets,
                    self.detected_packets,
                    &self.protocol_counts,
                    elapsed,
                );
            }
            "jsonl" => {
                #[cfg(feature = "json")]
                {
                    let summary = Summary::build(
                        self.total_packets,
                        self.detected_packets,
                        &self.protocol_counts,
                        elapsed,
                    );
                    println!(
                        "{}",
                        serde_json::to_string(&JsonlLine {
                            r#type: "summary",
                            summary: &summary,
                        })?
                    );
                }
            }
            "csv" => print_csv_summary(&self.protocol_counts),
            _ => print_text_summary(
                self.total_packets,
                self.detected_packets,
                &self.protocol_counts,
                elapsed,
            ),
        }

        Ok(())
    }
}

/// 合并多个 worker 的归一化流并全局排序（`feature: json`）。
#[cfg(feature = "json")]
fn merged_normalized_flows(detectors: &[Detector]) -> Vec<rdpi::parity::NormalizedFlow> {
    let mut flows = Vec::new();
    for detector in detectors {
        flows.extend(detector.normalized_flows());
    }
    rdpi::parity::sort_normalized_flows(&mut flows);
    flows
}

fn run_file(path: &Path, output: &str, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let processor = PcapProcessor::new();
    let mut iter = processor.process_file(path)?;
    let mut sink = OutputSink::new(output, verbose);

    for item in iter.by_ref() {
        match item? {
            Some((timestamp_us, detection)) => {
                sink.on_packet(timestamp_us, Some(detection))?;
            }
            None => sink.on_packet(0, None)?,
        }
    }

    sink.finish(start.elapsed(), std::slice::from_ref(iter.detector()))?;
    Ok(())
}

/// CLI 输入来源。
#[derive(Debug, PartialEq, Eq)]
enum Source {
    File(PathBuf),
    Live(String),
    ListIfaces,
}

fn resolve_source(
    input: Option<&str>,
    iface: Option<&str>,
    list_ifaces: bool,
) -> Result<Source, String> {
    if list_ifaces {
        return Ok(Source::ListIfaces);
    }
    if let Some(iface) = iface {
        return Ok(Source::Live(iface.to_string()));
    }

    let input = input.ok_or_else(|| "missing -i/--input or --iface".to_string())?;
    let path = PathBuf::from(input);
    if path.is_file() {
        Ok(Source::File(path))
    } else {
        Ok(Source::Live(input.to_string()))
    }
}

fn validate_file_options(
    filter: Option<&str>,
    count: Option<u64>,
    duration: Option<u64>,
) -> Result<(), String> {
    if filter.is_some() {
        return Err("--filter requires a live capture interface".to_string());
    }
    if count.is_some() {
        return Err("--count requires a live capture interface".to_string());
    }
    if duration.is_some() {
        return Err("--duration requires a live capture interface".to_string());
    }
    Ok(())
}

#[cfg(feature = "live")]
fn run_live(
    device: String,
    filter: Option<String>,
    count: Option<u64>,
    duration: Option<u64>,
    output: &str,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use rdpi::live::{CaptureConfig, LinkType, LiveCapture};

    let mut config = CaptureConfig::new(device);
    if let Some(filter) = filter {
        config = config.filter(filter);
    }

    let mut capture = LiveCapture::open(config)?;
    let link_type = capture.link_type();
    let interrupt = match rdpi::live::InterruptFlag::install() {
        Ok(flag) => flag,
        Err(error) => {
            eprintln!("warning: failed to install Ctrl-C handler: {error}");
            rdpi::live::InterruptFlag::default()
        }
    };
    let mut detector = Detector::new();
    let mut sink = OutputSink::new(output, verbose);
    let start = Instant::now();
    let duration = duration.map(std::time::Duration::from_secs);

    loop {
        if interrupt.is_requested() {
            break;
        }
        if let Some(limit) = count
            && sink.total() >= limit
        {
            break;
        }
        if let Some(limit) = duration
            && start.elapsed() >= limit
        {
            break;
        }

        let Some(frame) = capture.next_frame()? else {
            continue;
        };
        let Some(l3) = link_type.l3_payload(&frame.data) else {
            // ARP/LLDP 等非 IP 帧计为未识别包，继续抓取。
            sink.on_packet(frame.timestamp_us, None)?;
            continue;
        };
        let detection = match link_type {
            LinkType::Ethernet => {
                detector.process_packet(&frame.data, frame.timestamp_us / 1000)?
            }
            _ => detector.process_ip_packet(l3, frame.timestamp_us / 1000)?,
        };
        sink.on_packet(frame.timestamp_us, detection)?;
    }

    if interrupt.is_requested() {
        eprintln!("interrupted");
    }
    sink.finish(start.elapsed(), std::slice::from_ref(&detector))?;
    Ok(())
}

#[cfg(not(feature = "live"))]
fn run_live(
    _device: String,
    _filter: Option<String>,
    _count: Option<u64>,
    _duration: Option<u64>,
    _output: &str,
    _verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("error: live capture requires building with --features \"pcap live\"");
    std::process::exit(2);
}

#[cfg(feature = "live")]
fn list_ifaces() -> Result<(), Box<dyn std::error::Error>> {
    let devices = rdpi::live::devices()?;
    if devices.is_empty() {
        println!("no capture devices found");
        return Ok(());
    }

    for device in devices {
        let mut flags = Vec::new();
        if device.is_loopback {
            flags.push("loopback");
        }
        if device.is_up {
            flags.push("up");
        }
        let flags = if flags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", flags.join(","))
        };

        match device.description.as_deref() {
            Some(description) if !description.is_empty() => {
                println!("{}{}  {}", device.name, flags, description);
            }
            _ => println!("{}{}", device.name, flags),
        }
    }

    Ok(())
}

#[cfg(not(feature = "live"))]
fn list_ifaces() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("error: live capture requires building with --features \"pcap live\"");
    std::process::exit(2);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // json/jsonl/flows-jsonl 依赖 json feature（库类型 Serialize 派生）；
    // 未启用时 json 降级为仅 summary 的手写兼容输出，其余直接报错退出
    if (cli.output == "jsonl" || cli.output == "flows-jsonl") && !cfg!(feature = "json") {
        eprintln!(
            "error: output format '{}' requires building with --features json",
            cli.output
        );
        std::process::exit(2);
    }

    let source = match resolve_source(cli.input.as_deref(), cli.iface.as_deref(), cli.list_ifaces) {
        Ok(source) => source,
        Err(message) => {
            eprintln!("error: {message}");
            std::process::exit(2);
        }
    };

    match source {
        Source::ListIfaces => list_ifaces(),
        Source::Live(device) => run_live(
            device,
            cli.filter,
            cli.count,
            cli.duration,
            &cli.output,
            cli.verbose,
        ),
        Source::File(path) => {
            if let Err(message) =
                validate_file_options(cli.filter.as_deref(), cli.count, cli.duration)
            {
                eprintln!("error: {message}");
                std::process::exit(2);
            }
            run_file(&path, &cli.output, cli.verbose)
        }
    }
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
        // DTLS：同 QUIC 的 SNI 优先、ALPN 回退
        rdpi::Metadata::Dtls(d) => d.sni.as_deref().unwrap_or(d.alpn.as_deref().unwrap_or("")),
        rdpi::Metadata::Http(http) => http.host.as_deref().unwrap_or(""),
        rdpi::Metadata::Ssh(ssh) => ssh.software.as_deref().unwrap_or(""),
        rdpi::Metadata::Smtp(smtp) => smtp
            .sender
            .as_deref()
            .or(smtp.recipient.as_deref())
            .or(smtp.hostname.as_deref())
            .unwrap_or(""),
        #[cfg(feature = "mail")]
        rdpi::Metadata::Pop3(p) => p.username.as_deref().unwrap_or(""),
        #[cfg(feature = "mail")]
        rdpi::Metadata::Imap(i) => i.username.as_deref().unwrap_or(""),
        // F44：FTP 元数据主展示为用户名，回退文件名
        #[cfg(feature = "proto3")]
        rdpi::Metadata::Ftp(ftp) => ftp
            .username
            .as_deref()
            .or(ftp.filename.as_deref())
            .unwrap_or(""),
        // F37：DHCP/DHCPv6 主元数据即 JA4D/JA4D6 指纹
        rdpi::Metadata::Dhcp(d) => &d.ja4d,
        #[cfg(feature = "infra")]
        rdpi::Metadata::Dhcpv6(d) => &d.ja4d6,
        #[cfg(feature = "smb")]
        rdpi::Metadata::NetBios(nb) => nb.name.as_deref().unwrap_or(""),
        #[cfg(feature = "smb")]
        rdpi::Metadata::Smb(_) => "",
        #[cfg(feature = "database")]
        rdpi::Metadata::Memcached(m) => m.command.as_deref().unwrap_or(""),
        #[cfg(feature = "database")]
        rdpi::Metadata::Elasticsearch(e) => match e.source {
            rdpi::ElasticsearchSource::Binary => "binary",
            rdpi::ElasticsearchSource::Http => "http",
        },
        #[cfg(feature = "messaging")]
        rdpi::Metadata::Amqp(a) => &a.version,
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

    #[test]
    fn output_sink_counts_packets() {
        use rdpi::core::types::Protocol;

        let mut sink = OutputSink::new("csv", false);
        sink.on_packet(0, Some(DetectionResult::new(Protocol::Tcp)))
            .unwrap();
        sink.on_packet(0, None).unwrap();

        assert_eq!(sink.total(), 2);
        assert_eq!(sink.detected(), 1);
        assert_eq!(sink.protocol_counts().get("Tcp"), Some(&1));
    }

    #[test]
    fn numbered_packets_keep_capture_order_numbers() {
        use rdpi::core::types::Protocol;

        let mut sink = OutputSink::new("csv", false);
        sink.on_packet_numbered(9, 0, Some(DetectionResult::new(Protocol::Tcp)))
            .unwrap();
        sink.on_packet_numbered(3, 0, None).unwrap();

        assert_eq!(sink.total(), 2);
        assert_eq!(sink.detected(), 1);
        assert_eq!(sink.protocol_counts().get("Tcp"), Some(&1));
    }

    #[test]
    fn resolve_existing_file() {
        assert_eq!(
            resolve_source(Some("Cargo.toml"), None, false).unwrap(),
            Source::File(PathBuf::from("Cargo.toml"))
        );
    }

    #[test]
    fn resolve_missing_path_as_live_device() {
        assert_eq!(
            resolve_source(Some("rdpi-no-such-iface"), None, false).unwrap(),
            Source::Live("rdpi-no-such-iface".to_string())
        );
    }

    #[test]
    fn explicit_iface_wins_over_input() {
        assert_eq!(
            resolve_source(Some("Cargo.toml"), Some("eth0"), false).unwrap(),
            Source::Live("eth0".to_string())
        );
    }

    #[test]
    fn list_ifaces_mode() {
        assert_eq!(
            resolve_source(None, None, true).unwrap(),
            Source::ListIfaces
        );
    }

    #[test]
    fn file_mode_rejects_live_options() {
        assert!(validate_file_options(Some("tcp"), None, None).is_err());
        assert!(validate_file_options(None, Some(1), None).is_err());
        assert!(validate_file_options(None, None, Some(1)).is_err());
        assert!(validate_file_options(None, None, None).is_ok());
    }

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
