//! 实时抓包并行管线：单抓包线程 + N 个检测 worker + 主线程收集。
//!
//! `-n 1` 不启动线程，走单线程循环（与 F47 行为一致）；`-n > 1` 时抓包线程
//! 只做链路层/IP 头轻量解析用于分片，完整解析与检测在各 worker 内完成。

use rdpi::live::{CaptureConfig, CapturedFrame, InterruptFlag, LinkType, LiveCapture, LiveError};
use rdpi::{DetectionResult, Detector};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use super::{MAX_THREADS, OutputSink};

/// 每个 worker 的有界队列容量（背压上限）。
const WORKER_QUEUE_CAPACITY: usize = 1024;
/// FNV-1a 64 位偏移基数。
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64 位质数。
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// 抓包线程投递给 worker 的一帧。
struct WorkItem {
    packet_no: u64,
    timestamp_us: u64,
    data: Vec<u8>,
}

/// 抓包线程的不可变运行参数。
struct CapturePlan {
    link_type: LinkType,
    threads: usize,
    count: Option<u64>,
    duration: Option<Duration>,
}

/// worker/抓包线程发给主线程收集器的事件。
///
/// `Packet` 携带完整检测结果；为避免每包一次 `Box` 分配，接受枚举变体较大
/// （收集端串行处理，事件生命周期短）。
#[allow(clippy::large_enum_variant)]
enum LiveEvent {
    Packet {
        packet_no: u64,
        timestamp_us: u64,
        detection: Option<DetectionResult>,
    },
    Fatal(String),
    Finished(Box<Detector>),
}

/// 抓包来源抽象：生产路径为 [`LiveCapture`]，测试注入合成帧。
trait FrameSource {
    fn next_frame(&mut self) -> Result<Option<CapturedFrame>, LiveError>;
    fn link_type(&self) -> LinkType;
}

impl FrameSource for LiveCapture {
    fn next_frame(&mut self) -> Result<Option<CapturedFrame>, LiveError> {
        LiveCapture::next_frame(self)
    }

    fn link_type(&self) -> LinkType {
        LiveCapture::link_type(self)
    }
}

/// CLI 实时抓包入口。
pub(super) fn run_live(
    device: String,
    filter: Option<String>,
    count: Option<u64>,
    duration: Option<u64>,
    output: &str,
    verbose: bool,
    threads: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = CaptureConfig::new(device);
    if let Some(filter) = filter {
        config = config.filter(filter);
    }
    let capture = LiveCapture::open(config)?;

    let interrupt = match InterruptFlag::install() {
        Ok(flag) => flag,
        Err(error) => {
            eprintln!("warning: failed to install Ctrl-C handler: {error}");
            InterruptFlag::default()
        }
    };

    let start = Instant::now();
    let mut sink = OutputSink::new(output, verbose);
    let detectors = run_source(
        capture,
        threads,
        count,
        duration.map(Duration::from_secs),
        &interrupt,
        &mut sink,
    )?;
    if interrupt.is_requested() {
        eprintln!("interrupted");
    }
    sink.finish(start.elapsed(), &detectors)?;
    Ok(())
}

/// 运行抓包管线并返回各 worker 的检测器（用于合并导出 flows）。
fn run_source<S: FrameSource + Send + 'static>(
    mut source: S,
    threads: usize,
    count: Option<u64>,
    duration: Option<Duration>,
    interrupt: &InterruptFlag,
    sink: &mut OutputSink<'_>,
) -> Result<Vec<Detector>, Box<dyn std::error::Error>> {
    if !(1..=MAX_THREADS).contains(&threads) {
        return Err(format!("--threads must be between 1 and {MAX_THREADS}").into());
    }

    let link_type = source.link_type();
    if threads == 1 {
        return run_single(&mut source, link_type, count, duration, interrupt, sink);
    }
    run_parallel(source, link_type, threads, count, duration, interrupt, sink)
}

/// `-n 1`：保留 F47 的单线程循环（输出顺序完全一致）。
fn run_single<S: FrameSource>(
    source: &mut S,
    link_type: LinkType,
    count: Option<u64>,
    duration: Option<Duration>,
    interrupt: &InterruptFlag,
    sink: &mut OutputSink<'_>,
) -> Result<Vec<Detector>, Box<dyn std::error::Error>> {
    let mut detector = Detector::new();
    let start = Instant::now();
    let mut read_packets = 0u64;

    loop {
        if interrupt.is_requested() {
            break;
        }
        if let Some(limit) = count
            && read_packets >= limit
        {
            break;
        }
        if let Some(limit) = duration
            && start.elapsed() >= limit
        {
            break;
        }

        let Some(frame) = source.next_frame()? else {
            continue;
        };
        read_packets += 1;

        let Some(l3) = link_type.l3_payload(&frame.data) else {
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

    Ok(vec![detector])
}

/// `-n > 1`：单抓包线程 + flow-hash worker + 主线程收集。
fn run_parallel<S: FrameSource + Send + 'static>(
    capture: S,
    link_type: LinkType,
    threads: usize,
    count: Option<u64>,
    duration: Option<Duration>,
    interrupt: &InterruptFlag,
    sink: &mut OutputSink<'_>,
) -> Result<Vec<Detector>, Box<dyn std::error::Error>> {
    let stop = Arc::new(AtomicBool::new(false));
    let (event_tx, event_rx) = mpsc::channel::<LiveEvent>();

    let mut workers = Vec::with_capacity(threads);
    let mut work_senders = Vec::with_capacity(threads);
    for index in 0..threads {
        let (sender, receiver) = mpsc::sync_channel::<WorkItem>(WORKER_QUEUE_CAPACITY);
        work_senders.push(sender);
        let worker_tx = event_tx.clone();
        let worker_stop = Arc::clone(&stop);
        match thread::Builder::new()
            .name(format!("rdpi-worker-{index}"))
            .spawn(move || worker_loop(receiver, worker_tx, worker_stop, link_type))
        {
            Ok(handle) => workers.push(handle),
            Err(error) => {
                stop.store(true, Ordering::SeqCst);
                drop(work_senders);
                for handle in workers {
                    let _ = handle.join();
                }
                return Err(format!("failed to spawn worker thread: {error}").into());
            }
        }
    }

    let capture_stop = Arc::clone(&stop);
    let capture_tx = event_tx.clone();
    let capture_interrupt = interrupt.clone();
    let plan = CapturePlan {
        link_type,
        threads,
        count,
        duration,
    };
    let capture_thread = thread::Builder::new()
        .name("rdpi-capture".to_string())
        .spawn(move || {
            capture_loop(
                capture,
                plan,
                &capture_interrupt,
                &capture_stop,
                work_senders,
                &capture_tx,
            );
        });

    let capture_thread = match capture_thread {
        Ok(handle) => handle,
        Err(error) => {
            stop.store(true, Ordering::SeqCst);
            drop(event_tx);
            for handle in workers {
                let _ = handle.join();
            }
            return Err(format!("failed to spawn capture thread: {error}").into());
        }
    };

    drop(event_tx);

    let mut detectors = Vec::with_capacity(threads);
    let mut fatal: Option<String> = None;
    let mut sink_error: Option<Box<dyn std::error::Error>> = None;
    for event in event_rx {
        match event {
            LiveEvent::Packet {
                packet_no,
                timestamp_us,
                detection,
            } => {
                if sink_error.is_none()
                    && let Err(error) = sink.on_packet_numbered(packet_no, timestamp_us, detection)
                {
                    stop.store(true, Ordering::SeqCst);
                    sink_error = Some(error);
                }
            }
            LiveEvent::Fatal(message) => {
                if fatal.is_none() {
                    fatal = Some(message);
                }
            }
            LiveEvent::Finished(detector) => detectors.push(*detector),
        }
    }

    let capture_panicked = capture_thread.join().is_err();
    let mut worker_panicked = false;
    for handle in workers {
        worker_panicked |= handle.join().is_err();
    }

    if capture_panicked {
        return Err(LiveError::Capture("capture thread panicked".to_string()).into());
    }
    if worker_panicked {
        return Err(LiveError::Capture("worker thread panicked".to_string()).into());
    }
    if let Some(error) = sink_error {
        return Err(error);
    }
    if let Some(message) = fatal {
        return Err(message.into());
    }

    Ok(detectors)
}

/// 抓包线程：读帧、按 flow hash 投递、非 IP 帧直接发事件。
fn capture_loop<S: FrameSource>(
    mut capture: S,
    plan: CapturePlan,
    interrupt: &InterruptFlag,
    stop: &AtomicBool,
    senders: Vec<SyncSender<WorkItem>>,
    event_tx: &Sender<LiveEvent>,
) {
    let start = Instant::now();
    let mut read_packets = 0u64;

    loop {
        if stop.load(Ordering::SeqCst) || interrupt.is_requested() {
            break;
        }
        if let Some(limit) = plan.count
            && read_packets >= limit
        {
            break;
        }
        if let Some(limit) = plan.duration
            && start.elapsed() >= limit
        {
            break;
        }

        let frame = match capture.next_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => continue,
            Err(error) => {
                stop.store(true, Ordering::SeqCst);
                let _ = event_tx.send(LiveEvent::Fatal(error.to_string()));
                break;
            }
        };
        read_packets += 1;

        match flow_shard(&frame.data, plan.link_type, plan.threads) {
            Some(shard) => {
                let item = WorkItem {
                    packet_no: read_packets,
                    timestamp_us: frame.timestamp_us,
                    data: frame.data,
                };
                if senders[shard].send(item).is_err() {
                    stop.store(true, Ordering::SeqCst);
                    break;
                }
            }
            None => {
                let packet = LiveEvent::Packet {
                    packet_no: read_packets,
                    timestamp_us: frame.timestamp_us,
                    detection: None,
                };
                if event_tx.send(packet).is_err() {
                    stop.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    }
}

/// worker：独占一个 `Detector`，排空队列后发送 `Finished`。
fn worker_loop(
    receiver: Receiver<WorkItem>,
    event_tx: Sender<LiveEvent>,
    stop: Arc<AtomicBool>,
    link_type: LinkType,
) {
    let mut detector = Detector::new();
    for item in receiver {
        let detection = match process_item(
            &mut detector,
            link_type,
            &item.data,
            item.timestamp_us / 1000,
        ) {
            Ok(detection) => detection,
            Err(error) => {
                stop.store(true, Ordering::SeqCst);
                let _ = event_tx.send(LiveEvent::Fatal(error.to_string()));
                break;
            }
        };
        if event_tx
            .send(LiveEvent::Packet {
                packet_no: item.packet_no,
                timestamp_us: item.timestamp_us,
                detection,
            })
            .is_err()
        {
            break;
        }
    }
    let _ = event_tx.send(LiveEvent::Finished(Box::new(detector)));
}

fn process_item(
    detector: &mut Detector,
    link_type: LinkType,
    data: &[u8],
    timestamp_ms: u64,
) -> Result<Option<DetectionResult>, rdpi::Error> {
    match link_type {
        LinkType::Ethernet => detector.process_packet(data, timestamp_ms),
        _ => match link_type.l3_payload(data) {
            Some(l3) => detector.process_ip_packet(l3, timestamp_ms),
            None => Ok(None),
        },
    }
}

/// 方向无关的流分片：返回 `[0, threads)` 或 `None`（非 IP/畸形）。
fn flow_shard(frame: &[u8], link_type: LinkType, threads: usize) -> Option<usize> {
    let l3 = link_type.l3_payload(frame)?;
    let hash = flow_hash(l3)?;
    Some((hash % threads as u64) as usize)
}

fn flow_hash(l3: &[u8]) -> Option<u64> {
    match l3.first()? >> 4 {
        4 => ipv4_hash(l3),
        6 => ipv6_hash(l3),
        _ => None,
    }
}

fn ipv4_hash(l3: &[u8]) -> Option<u64> {
    if l3.len() < 20 {
        return None;
    }
    let ihl = usize::from(l3[0] & 0x0f) * 4;
    if ihl < 20 || l3.len() < ihl {
        return None;
    }
    let protocol = l3[9];
    let fragment_offset = u16::from_be_bytes([l3[6], l3[7]]) & 0x1fff;
    let (src_port, dst_port) =
        if fragment_offset == 0 && matches!(protocol, 6 | 17) && l3.len() >= ihl + 4 {
            (
                u16::from_be_bytes([l3[ihl], l3[ihl + 1]]),
                u16::from_be_bytes([l3[ihl + 2], l3[ihl + 3]]),
            )
        } else {
            (0, 0)
        };
    Some(hash_endpoints(
        4,
        protocol,
        &l3[12..16],
        src_port,
        &l3[16..20],
        dst_port,
    ))
}

fn ipv6_hash(l3: &[u8]) -> Option<u64> {
    if l3.len() < 40 {
        return None;
    }
    let next_header = l3[6];
    // 扩展头场景不深解析：仅哈希地址与 Next Header（端口记 0）。
    let (src_port, dst_port) = if matches!(next_header, 6 | 17) && l3.len() >= 44 {
        (
            u16::from_be_bytes([l3[40], l3[41]]),
            u16::from_be_bytes([l3[42], l3[43]]),
        )
    } else {
        (0, 0)
    };
    Some(hash_endpoints(
        6,
        next_header,
        &l3[8..24],
        src_port,
        &l3[24..40],
        dst_port,
    ))
}

fn hash_endpoints(
    version: u8,
    protocol: u8,
    src: &[u8],
    src_port: u16,
    dst: &[u8],
    dst_port: u16,
) -> u64 {
    // 按（地址字节，端口）字典序规范化，保证 A→B 与 B→A 同 shard。
    let (a, a_port, b, b_port) = if (src, src_port) <= (dst, dst_port) {
        (src, src_port, dst, dst_port)
    } else {
        (dst, dst_port, src, src_port)
    };
    let mut hash = fnv1a(FNV_OFFSET, &[version, protocol]);
    hash = fnv1a(hash, a);
    hash = fnv1a(hash, &a_port.to_be_bytes());
    hash = fnv1a(hash, b);
    fnv1a(hash, &b_port.to_be_bytes())
}

fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::{FrameSource, flow_shard, run_source};
    use crate::OutputSink;
    #[cfg(feature = "json")]
    use rdpi::Detector;
    use rdpi::live::{CapturedFrame, InterruptFlag, LinkType, LiveCapture, LiveError};

    fn ipv4_udp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + 8 + payload.len();
        let mut packet = Vec::with_capacity(total_len);
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.push(64);
        packet.push(17);
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&src);
        packet.extend_from_slice(&dst);
        packet.extend_from_slice(&sport.to_be_bytes());
        packet.extend_from_slice(&dport.to_be_bytes());
        packet.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn eth_ipv4_udp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + 20 + 8 + payload.len());
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&ipv4_udp(src, sport, dst, dport, payload));
        frame
    }

    fn ipv6_udp(src: [u8; 16], sport: u16, dst: [u8; 16], dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src);
        packet[24..40].copy_from_slice(&dst);
        packet.extend_from_slice(&sport.to_be_bytes());
        packet.extend_from_slice(&dport.to_be_bytes());
        packet.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn dns_query(domain: &str) -> Vec<u8> {
        let mut query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        query
    }

    fn dns_response(domain: &str) -> Vec<u8> {
        let mut response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            response.push(label.len() as u8);
            response.extend_from_slice(label.as_bytes());
        }
        response.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 10, 0, 0, 2,
        ]);
        response
    }

    fn captured(data: Vec<u8>, timestamp_us: u64) -> CapturedFrame {
        CapturedFrame {
            original_len: data.len() as u32,
            data,
            timestamp_us,
        }
    }

    fn arp_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 28]);
        frame
    }

    struct FakeSource {
        frames: std::vec::IntoIter<CapturedFrame>,
        link_type: LinkType,
    }

    impl FrameSource for FakeSource {
        fn next_frame(&mut self) -> Result<Option<CapturedFrame>, LiveError> {
            Ok(self.frames.next())
        }

        fn link_type(&self) -> LinkType {
            self.link_type
        }
    }

    #[test]
    fn live_capture_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<LiveCapture>();
    }

    #[test]
    fn flow_shard_is_direction_independent_for_ipv4() {
        let forward = eth_ipv4_udp([10, 0, 0, 1], 40_000, [10, 0, 0, 2], 53, &[]);
        let reverse = eth_ipv4_udp([10, 0, 0, 2], 53, [10, 0, 0, 1], 40_000, &[]);
        assert_eq!(
            flow_shard(&forward, LinkType::Ethernet, 16),
            flow_shard(&reverse, LinkType::Ethernet, 16)
        );
    }

    #[test]
    fn flow_shard_is_direction_independent_for_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let forward = ipv6_udp(src, 40_000, dst, 53, &[]);
        let reverse = ipv6_udp(dst, 53, src, 40_000, &[]);
        assert_eq!(
            flow_shard(&forward, LinkType::RawIp, 16),
            flow_shard(&reverse, LinkType::RawIp, 16)
        );
    }

    #[test]
    fn flow_shard_ignores_non_ip_frames() {
        assert_eq!(flow_shard(&arp_frame(), LinkType::Ethernet, 4), None);
        assert_eq!(flow_shard(&[0u8; 8], LinkType::RawIp, 4), None);
    }

    #[test]
    fn flow_shard_spreads_flows_across_workers() {
        let mut shards = std::collections::HashSet::new();
        for last in 1..=64u8 {
            let frame = eth_ipv4_udp([10, 0, 0, last], 40_000, [10, 0, 0, 200], 53, &[]);
            shards.insert(flow_shard(&frame, LinkType::Ethernet, 4).unwrap());
        }
        assert!(shards.len() > 1, "all flows mapped to {shards:?}");
    }

    #[test]
    fn parallel_pipeline_merges_bidirectional_flow() {
        let frames = vec![
            captured(
                eth_ipv4_udp(
                    [10, 0, 0, 1],
                    40_000,
                    [10, 0, 0, 2],
                    53,
                    &dns_query("example.com"),
                ),
                1,
            ),
            captured(
                eth_ipv4_udp(
                    [10, 0, 0, 2],
                    53,
                    [10, 0, 0, 1],
                    40_000,
                    &dns_response("example.com"),
                ),
                2,
            ),
            captured(arp_frame(), 3),
        ];
        let source = FakeSource {
            frames: frames.into_iter(),
            link_type: LinkType::Ethernet,
        };
        let interrupt = InterruptFlag::default();
        let mut sink = OutputSink::new("csv", false);

        let detectors = run_source(source, 2, Some(3), None, &interrupt, &mut sink).unwrap();

        assert_eq!(sink.total(), 3);
        assert_eq!(sink.detected(), 2);
        assert_eq!(detectors.iter().map(|d| d.flow_count()).sum::<usize>(), 1);
    }

    #[test]
    fn parallel_pipeline_handles_sll_frames() {
        let mut frame = vec![0u8; 16];
        frame[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ipv4_udp(
            [10, 0, 0, 1],
            40_000,
            [10, 0, 0, 2],
            53,
            &dns_query("example.com"),
        ));
        let source = FakeSource {
            frames: vec![captured(frame, 1)].into_iter(),
            link_type: LinkType::LinuxSll,
        };
        let interrupt = InterruptFlag::default();
        let mut sink = OutputSink::new("csv", false);

        let detectors = run_source(source, 2, Some(1), None, &interrupt, &mut sink).unwrap();

        assert_eq!(sink.total(), 1);
        assert_eq!(sink.detected(), 1);
        assert_eq!(detectors.iter().map(|d| d.flow_count()).sum::<usize>(), 1);
    }

    #[cfg(feature = "json")]
    #[test]
    fn merged_flows_are_sorted_across_detectors() {
        let query = dns_query("example.com");
        let mut first = Detector::new();
        let mut second = Detector::new();
        first
            .process_packet(
                &eth_ipv4_udp([10, 0, 0, 1], 40_000, [10, 0, 0, 2], 53, &query),
                0,
            )
            .unwrap();
        second
            .process_packet(
                &eth_ipv4_udp([10, 0, 0, 3], 40_001, [10, 0, 0, 4], 53, &query),
                0,
            )
            .unwrap();

        let flows = crate::merged_normalized_flows(&[first, second]);
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].src_ip, "10.0.0.1");
        assert_eq!(flows[1].src_ip, "10.0.0.3");
    }
}
