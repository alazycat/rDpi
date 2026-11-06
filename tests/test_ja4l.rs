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
        .and_then(|(_, f)| f.ja4ls.clone())
}

/// 按源端口取流 JA4L-C 快照
fn ja4lc_by_src_port(d: &Detector, port: u16) -> Option<String> {
    d.flows()
        .find(|(k, _)| k.src_port == port)
        .and_then(|(_, f)| f.ja4lc.clone())
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

// ============================================================================
// QUIC 变体（F41，2026-11-06）：官方 zeek ja4l/main.zeek QUIC 事件语义
// ============================================================================

/// 构造完整以太网+IPv4+UDP 包（带 TTL 参数）
fn build_udp_packet(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 14 + 20 + 8 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16 - 14).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(ttl);
    pkt.push(0x11); // protocol: UDP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&(payload.len() as u16 + 8).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

/// QUIC v1 长包头载荷：首字节 fixed+long 位 + type 位 + version 0x00000001
/// + 哑 DCID 等字段（本观测只读首字节与 version）
fn quic_payload(first_byte: u8) -> Vec<u8> {
    let mut p = vec![first_byte, 0x00, 0x00, 0x00, 0x01];
    p.extend_from_slice(&[0xab; 16]);
    p
}

/// QUIC Initial（长包头 type = 0）载荷
fn quic_initial() -> Vec<u8> {
    quic_payload(0xc0)
}

/// QUIC Handshake（长包头 type = 2）载荷
fn quic_handshake() -> Vec<u8> {
    quic_payload(0xe0)
}

#[test]
fn test_ja4l_quic_handshake() {
    let mut d = Detector::new();

    // A'：客户端 Initial（t=0，客户端 TTL=128）
    let c_init = build_udp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, &quic_initial());
    d.detect_at(&c_init, ts(0)).unwrap();

    // 服务端 Initial（t=10ms，服务端 TTL=57）→ JA4L-S = 10000/2 = 5000，三段 _q
    let s_init = build_udp_packet(SERVER, 443, CLIENT, 54321, SERVER_TTL, &quic_initial());
    d.detect_at(&s_init, ts(10_000)).unwrap();
    assert_eq!(
        ja4ls_by_src_port(&d, 443).as_deref(),
        Some("5000_57_q"),
        "QUIC JA4L-S = (server_init - client_init)/2 + TTL + '_q'（官方三段格式）"
    );
    assert!(
        ja4ls_by_src_port(&d, 54321).is_none(),
        "客户端流不携带 JA4L-S"
    );

    // B'：服务端 Handshake（t=15ms）
    let s_hs = build_udp_packet(SERVER, 443, CLIENT, 54321, SERVER_TTL, &quic_handshake());
    d.detect_at(&s_hs, ts(15_000)).unwrap();

    // 客户端 Handshake（t=31ms）→ JA4L-C = (31-15)ms/2 = 8000，TTL 取客户端 Initial
    let c_hs = build_udp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, &quic_handshake());
    d.detect_at(&c_hs, ts(31_000)).unwrap();
    assert_eq!(
        ja4lc_by_src_port(&d, 54321).as_deref(),
        Some("8000_128_q"),
        "QUIC JA4L-C = (client_hs - server_hs)/2 + 客户端 Initial TTL + '_q'"
    );
    assert!(
        ja4lc_by_src_port(&d, 443).is_none(),
        "服务端流不携带 JA4L-C"
    );
}

#[test]
fn test_ja4l_quic_skipped_on_backward_timestamp() {
    let mut d = Detector::new();
    // 乱序：客户端 Initial（t=100ms）后服务端 Initial（t=40ms，时戳回退）
    let c_init = build_udp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, &quic_initial());
    d.detect_at(&c_init, ts(100_000)).unwrap();
    let s_init = build_udp_packet(SERVER, 443, CLIENT, 54321, SERVER_TTL, &quic_initial());
    d.detect_at(&s_init, ts(40_000)).unwrap();
    assert!(
        ja4ls_by_src_port(&d, 443).is_none(),
        "时戳回退不产出 QUIC JA4L-S"
    );
}

#[test]
fn test_ja4l_quic_midstream_skipped() {
    let mut d = Detector::new();
    // mid-stream：首包即服务端 Initial（缺客户端 A'）→ 不产出（zeek 对缺失
    // 时戳按 0 参与计算会产出巨值，此处按 F35 先例显式跳过）
    let s_init = build_udp_packet(SERVER, 443, CLIENT, 54321, SERVER_TTL, &quic_initial());
    d.detect_at(&s_init, ts(0)).unwrap();
    // 后续服务端 Handshake / 客户端 Handshake 同样不产出 JA4L-C
    let s_hs = build_udp_packet(SERVER, 443, CLIENT, 54321, SERVER_TTL, &quic_handshake());
    d.detect_at(&s_hs, ts(5_000)).unwrap();
    let c_hs = build_udp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, &quic_handshake());
    d.detect_at(&c_hs, ts(9_000)).unwrap();
    assert!(ja4ls_by_src_port(&d, 443).is_none());
    assert!(ja4lc_by_src_port(&d, 443).is_none());
    assert!(ja4lc_by_src_port(&d, 54321).is_none());
}

#[test]
fn test_ja4l_quic_non_v1_version_skipped() {
    let mut d = Detector::new();
    // 草稿版版本号（0xff000020）不追踪：服务端 Initial 到达时对端无 A'
    // → JA4L-S 不产出
    let mut draft = vec![0xc0, 0xff, 0x00, 0x00, 0x20];
    draft.extend_from_slice(&[0xab; 16]);
    let c_init = build_udp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, &draft);
    d.detect_at(&c_init, ts(0)).unwrap();
    let s_init = build_udp_packet(SERVER, 443, CLIENT, 54321, SERVER_TTL, &quic_initial());
    d.detect_at(&s_init, ts(10_000)).unwrap();
    assert!(ja4ls_by_src_port(&d, 443).is_none(), "非 v1 不产出 JA4L-S");
}

#[test]
fn test_ja4l_quic_malformed_and_ignored_types() {
    let mut d = Detector::new();
    // 短包（< 5 字节）与 0-RTT（type=1）/ 版本协商（type=3）长包头不参与
    let short = build_udp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, &[0xc0, 0x00, 0x00]);
    d.detect_at(&short, ts(0)).unwrap();
    let zero_rtt = build_udp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, &quic_payload(0xd0));
    d.detect_at(&zero_rtt, ts(1_000)).unwrap();
    // 非 v1 门控后 type=3 长包头同样落入忽略分支
    let vn = build_udp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, &quic_payload(0xf0));
    d.detect_at(&vn, ts(2_000)).unwrap();
    assert!(ja4ls_by_src_port(&d, 443).is_none());
    assert!(ja4lc_by_src_port(&d, 54321).is_none());
}

#[test]
fn test_ja4l_quic_retransmit_initial_keeps_first() {
    let mut d = Detector::new();
    // 客户端 Initial 重传不覆盖 A'（zeek 无守卫，此处每流一次故意收紧）：
    // 首个 Initial t=0，重传 t=2ms，服务端 Initial t=10ms → 仍按 0 起算
    let c_init = build_udp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, &quic_initial());
    d.detect_at(&c_init, ts(0)).unwrap();
    let c_retrans = build_udp_packet(CLIENT, 54321, SERVER, 443, CLIENT_TTL, &quic_initial());
    d.detect_at(&c_retrans, ts(2_000)).unwrap();
    let s_init = build_udp_packet(SERVER, 443, CLIENT, 54321, SERVER_TTL, &quic_initial());
    d.detect_at(&s_init, ts(10_000)).unwrap();
    assert_eq!(
        ja4ls_by_src_port(&d, 443).as_deref(),
        Some("5000_57_q"),
        "重传 Initial 不覆盖客户端 A' 时戳"
    );
}
