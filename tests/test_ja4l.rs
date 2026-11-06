//! JA4L-S/C 时延指纹集成测试（F35，2026-11-06）
//!
//! 触发语义对齐 FoxIO 官方（zeek ja4l/main.zeek + python ja4.py + 官方博客）：
//! - JA4L-S = `{(B-A)/2}_{server_ttl}`：A=客户端 SYN 时戳，B=SYN-ACK 时戳
//!   （SYN/ACK 位测试），TTL 取 SYN-ACK 包；半程时延 = 总微秒整除 2
//! - JA4L-C = `{(C-B)/2}_{client_ttl}`：C=SYN-ACK 之后首个客户端包
//!   （纯 ACK 或数据均可，zeek 第二发起包语义），TTL 取 SYN 包
//! - 时戳经 [`Detector::detect_at`] 注入（离线回放传捕获时戳）；乱序/缺
//!   握手起点跳过，指纹保持 None

use rdpi::Detector;
use std::time::{Duration, SystemTime};

/// UNIX_EPOCH + 微秒偏移（测试用单调时戳）
fn ts(micros: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_micros(micros)
}

/// 构造完整以太网+IPv4+TCP 包（带 TTL 参数，风格对齐 test_ja4t.rs）
#[allow(clippy::too_many_arguments)]
fn build_tcp_packet(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    ttl: u8,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_hdr_len = 20usize;
    let total_len = 14 + 20 + tcp_hdr_len + payload.len();
    let mut pkt = Vec::with_capacity(total_len);

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);

    // IPv4 header (20 bytes)
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16 - 14).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(ttl);
    pkt.push(0x06); // protocol: TCP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);

    // TCP header
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
    pkt.push(0x50); // data offset 20
    pkt.push(flags);
    pkt.extend_from_slice(&8192u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer

    pkt.extend_from_slice(payload);
    pkt
}

const CLIENT: [u8; 4] = [192, 168, 1, 10];
const SERVER: [u8; 4] = [93, 184, 216, 34];
const CLIENT_TTL: u8 = 128;
const SERVER_TTL: u8 = 57;

/// 按源端口取流 JA4L-S 快照（克隆以终结借用，避免阻断后续 detect_at）
fn ja4ls_by_src_port(d: &Detector, port: u16) -> Option<String> {
    d.flows()
        .find(|(k, _)| k.src_port == port)
        .map(|(_, f)| f.ja4ls.clone())
        .flatten()
}

/// 按源端口取流 JA4L-C 快照
fn ja4lc_by_src_port(d: &Detector, port: u16) -> Option<String> {
    d.flows()
        .find(|(k, _)| k.src_port == port)
        .map(|(_, f)| f.ja4lc.clone())
        .flatten()
}

#[test]
fn test_ja4ls_and_ja4lc_handshake() {
    let mut d = Detector::new();

    // A：SYN（t=0，客户端 TTL=128）
    let syn = build_tcp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, 0x02, &[]);
    assert!(d.detect_at(&syn, ts(0)).unwrap().is_none());

    // B：SYN-ACK（t=10ms，服务端 TTL=57）→ JA4L-S = 10000/2 = 5000
    let syn_ack = build_tcp_packet(SERVER, 443, CLIENT, 54321, SERVER_TTL, 0x12, &[]);
    let r = d.detect_at(&syn_ack, ts(10_000)).unwrap();
    assert!(r.is_none() || r.unwrap().ja4ls.is_some());

    // ja4ls 落在服务端方向流（FlowKey 方向性：与客户端流分属两条）
    assert_eq!(
        ja4ls_by_src_port(&d, 443).as_deref(),
        Some("5000_57"),
        "JA4L-S = (B-A)/2 + '_' + {{SYN-ACK TTL}}"
    );
    assert!(
        ja4ls_by_src_port(&d, 54321).is_none(),
        "客户端流不携带 JA4L-S"
    );

    // C：客户端 ACK（t=30ms）→ JA4L-C = (30-10)ms/2 = 10000，TTL=128
    let ack = build_tcp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, 0x10, &[]);
    let r = d.detect_at(&ack, ts(30_000)).unwrap();
    assert!(r.is_none() || r.unwrap().ja4lc.is_some());

    assert_eq!(
        ja4lc_by_src_port(&d, 54321).as_deref(),
        Some("10000_128"),
        "JA4L-C = (C-B)/2 + '_' + {{SYN TTL}}"
    );
    assert!(
        ja4lc_by_src_port(&d, 443).is_none(),
        "服务端流不携带 JA4L-C"
    );
}

#[test]
fn test_ja4l_c_can_be_data_packet() {
    let mut d = Detector::new();
    // C 可以是带载荷的客户端数据包（zeek 第二发起包语义，不检查 flags/payload）
    let syn = build_tcp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, 0x02, &[]);
    d.detect_at(&syn, ts(0)).unwrap();
    let syn_ack = build_tcp_packet(SERVER, 443, CLIENT, 54321, SERVER_TTL, 0x12, &[]);
    d.detect_at(&syn_ack, ts(10_000)).unwrap();
    // 第三包：带 10 字节载荷的 PSH+ACK（t=14ms）→ (14-10)ms/2 = 2000
    let data = build_tcp_packet(
        CLIENT,
        54321,
        SERVER,
        443,
        CLIENT_TTL,
        0x18,
        &[0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5],
    );
    d.detect_at(&data, ts(14_000)).unwrap();

    assert_eq!(ja4lc_by_src_port(&d, 54321).as_deref(), Some("2000_128"));
}

#[test]
fn test_ja4l_first_synack_and_first_c_win() {
    let mut d = Detector::new();
    let syn = build_tcp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, 0x02, &[]);
    d.detect_at(&syn, ts(0)).unwrap();
    // SYN-ACK 重传：首个（t=10ms）定指纹，重传（t=40ms）不得覆盖
    let syn_ack = build_tcp_packet(SERVER, 443, CLIENT, 54321, SERVER_TTL, 0x12, &[]);
    d.detect_at(&syn_ack, ts(10_000)).unwrap();
    d.detect_at(&syn_ack, ts(40_000)).unwrap();
    // C：首个候选（t=50ms）定指纹，后续客户端包不得覆盖
    let ack1 = build_tcp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, 0x10, &[]);
    d.detect_at(&ack1, ts(50_000)).unwrap();
    let ack2 = build_tcp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, 0x10, &[]);
    d.detect_at(&ack2, ts(60_000)).unwrap();

    assert_eq!(
        ja4ls_by_src_port(&d, 443).as_deref(),
        Some("5000_57"),
        "重传 SYN-ACK 不得覆盖首个 JA4L-S"
    );
    assert_eq!(
        ja4lc_by_src_port(&d, 54321).as_deref(),
        Some("20000_128"),
        "(50-10)ms/2 = 20000；后续客户端包不得覆盖首个 JA4L-C"
    );
}

#[test]
fn test_ja4l_absent_without_handshake_start() {
    let mut d = Detector::new();
    // mid-stream：服务端 SYN-ACK 先到（客户端 SYN 未观测）→ 无 A，JA4L-S 跳过
    let syn_ack = build_tcp_packet(SERVER, 443, CLIENT, 54321, SERVER_TTL, 0x12, &[]);
    d.detect_at(&syn_ack, ts(10_000)).unwrap();
    assert!(
        ja4ls_by_src_port(&d, 443).is_none(),
        "缺握手起点不产出 JA4L-S"
    );

    // 客户端后续数据包：流无 A（syn_time None）→ 也不产出 JA4L-C
    let data = build_tcp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, 0x18, &[1, 2, 3]);
    d.detect_at(&data, ts(20_000)).unwrap();
    assert!(
        ja4lc_by_src_port(&d, 54321).is_none(),
        "缺握手起点不产出 JA4L-C"
    );
}

#[test]
fn test_ja4l_absent_without_synack() {
    let mut d = Detector::new();
    // 有 SYN 无 SYN-ACK（对端不回包/抓包截断）：JA4L-C 无 B 可用
    let syn = build_tcp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, 0x02, &[]);
    d.detect_at(&syn, ts(0)).unwrap();
    let ack = build_tcp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, 0x10, &[]);
    d.detect_at(&ack, ts(10_000)).unwrap();
    assert!(
        ja4lc_by_src_port(&d, 54321).is_none(),
        "无 SYN-ACK 不产出 JA4L-C"
    );
    assert!(ja4ls_by_src_port(&d, 54321).is_none());
}

#[test]
fn test_ja4l_skipped_on_backward_timestamp() {
    let mut d = Detector::new();
    // 乱序：SYN（t=100ms）后 SYN-ACK（t=40ms，时戳回退）→ duration_since 失败，跳过
    let syn = build_tcp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, 0x02, &[]);
    d.detect_at(&syn, ts(100_000)).unwrap();
    let syn_ack = build_tcp_packet(SERVER, 443, CLIENT, 54321, SERVER_TTL, 0x12, &[]);
    d.detect_at(&syn_ack, ts(40_000)).unwrap();
    assert!(
        ja4ls_by_src_port(&d, 443).is_none(),
        "时戳回退不产出 JA4L-S"
    );
}

#[test]
fn test_ja4l_udp_flow_untouched() {
    let mut d = Detector::new();
    // 非 TCP 流不参与 JA4L（构造最小 UDP 包）
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&34u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00]);
    pkt.extend_from_slice(&CLIENT);
    pkt.extend_from_slice(&SERVER);
    pkt.extend_from_slice(&5353u16.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&8u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[1, 2, 3, 4]);
    d.detect_at(&pkt, ts(0)).unwrap();
    assert!(ja4ls_by_src_port(&d, 5353).is_none());
    assert!(ja4lc_by_src_port(&d, 5353).is_none());
}
