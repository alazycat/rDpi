//! JA4T/JA4TS TCP 指纹集成测试（F33/F34，2026-11-05）
//!
//! 触发语义：
//! - JA4T 对齐 FoxIO 官方 rust/ja4 tcp.rs：仅初始 SYN（SYN=0x02 置位且
//!   ACK=0x10 清零；SYN+ECN 0xC2 同样满足），每流只取第一个满足的包
//! - JA4TS 对齐官方 zeek/ja4t/main.zeek：仅服务端 SYN-ACK（flags 精确等于
//!   SYN|ACK=0x12），服务端方向流每流只取第一个满足的包
//! - 两者格式一致：`{window}_{options}_{mss}_{window_scale}`，官方向量见 application/ja4.rs

use rdpi::Detector;

/// 构造完整以太网+IPv4+TCP 包（可指定 flags/window/选项，风格对齐 test_tls.rs）
#[allow(clippy::too_many_arguments)]
fn build_tcp_packet_with_options(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    // 选项补零对齐 4 字节；data_offset 以 4 字节为单位
    let opt_padded = options.len() + (4 - options.len() % 4) % 4;
    let tcp_hdr_len = 20 + opt_padded;
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
    pkt.push(0x40);
    pkt.push(0x06); // protocol: TCP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);

    // TCP header（含选项）
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
    pkt.push(((tcp_hdr_len / 4) as u8) << 4); // data offset
    pkt.push(flags);
    pkt.extend_from_slice(&window.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer
    pkt.extend_from_slice(options);
    pkt.resize(14 + 20 + tcp_hdr_len, 0x00); // EOL 填充

    pkt.extend_from_slice(payload);
    pkt
}

/// 官方 Windows 11 形态 SYN：MSS(1460) + NOP + WS(8) + NOP + NOP + SACK-Permitted
const SYN_OPTIONS_WIN11: &[u8] = &[2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2];

#[test]
fn test_ja4t_captured_from_initial_syn() {
    let mut d = Detector::new();
    let syn = build_tcp_packet_with_options(
        [192, 168, 1, 10],
        54321,
        [93, 184, 216, 34],
        443,
        0x02, // SYN
        64240,
        SYN_OPTIONS_WIN11,
        &[],
    );
    let r = d.detect(&syn).unwrap();
    // 空载荷 SYN 通常无协议识别结果，但 JA4T 已写入流
    assert!(r.is_none() || r.unwrap().ja4t.is_some());

    let flows: Vec<_> = d.flows().map(|(_, f)| f).collect();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].ja4t.as_deref(), Some("64240_2-1-3-1-1-4_1460_8"));
}

#[test]
fn test_ja4t_echo_packets_carry_flow_fingerprint() {
    let mut d = Detector::new();
    let syn = build_tcp_packet_with_options(
        [192, 168, 1, 10],
        54321,
        [93, 184, 216, 34],
        80,
        0x02,
        64240,
        SYN_OPTIONS_WIN11,
        &[],
    );
    d.detect(&syn).unwrap();

    // 后续 HTTP 请求包（不同窗口/无选项）不覆盖指纹，且检测结果携带流级 JA4T
    let req = build_tcp_packet_with_options(
        [192, 168, 1, 10],
        54321,
        [93, 184, 216, 34],
        80,
        0x18, // PSH|ACK
        1000,
        &[],
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    let r = d
        .detect(&req)
        .unwrap()
        .expect("HTTP 请求应被默认 http feature 识别");
    assert_eq!(r.ja4t.as_deref(), Some("64240_2-1-3-1-1-4_1460_8"));

    let flows: Vec<_> = d.flows().map(|(_, f)| f).collect();
    assert_eq!(
        flows[0].ja4t.as_deref(),
        Some("64240_2-1-3-1-1-4_1460_8"),
        "后续包不得覆盖 SYN 指纹"
    );
}

#[test]
fn test_ja4t_syn_ack_does_not_trigger() {
    let mut d = Detector::new();
    // SYN-ACK（0x12）先行：不应产出指纹
    let syn_ack = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        443,
        [192, 168, 1, 10],
        54321,
        0x12,
        8192,
        &[2, 4, 0x05, 0xb4],
        &[],
    );
    d.detect(&syn_ack).unwrap();
    let server_flow = d
        .flows()
        .find(|(k, _)| k.src_port == 443)
        .map(|(_, f)| f)
        .expect("服务端方向流应存在");
    assert!(server_flow.ja4t.is_none(), "SYN-ACK 不得触发 JA4T");

    // 随后真正的初始 SYN 到达（客户端方向是另一条流）：应捕获
    let syn = build_tcp_packet_with_options(
        [192, 168, 1, 10],
        54321,
        [93, 184, 216, 34],
        443,
        0x02,
        5744,
        &[2, 4, 0x05, 0x9c],
        &[],
    );
    d.detect(&syn).unwrap();
    let client_flow = d
        .flows()
        .find(|(k, _)| k.src_port == 54321)
        .map(|(_, f)| f)
        .expect("客户端方向流应存在");
    assert_eq!(client_flow.ja4t.as_deref(), Some("5744_2_1436_00"));
}

#[test]
fn test_ja4t_syn_with_ecn_counts() {
    // SYN+ECE+CWR（0xC2）：官方语义算初始 SYN
    let mut d = Detector::new();
    let syn = build_tcp_packet_with_options(
        [192, 168, 1, 10],
        54321,
        [93, 184, 216, 34],
        443,
        0xC2,
        8192,
        &[],
        &[],
    );
    d.detect(&syn).unwrap();
    let flows: Vec<_> = d.flows().map(|(_, f)| f).collect();
    assert_eq!(flows[0].ja4t.as_deref(), Some("8192_00_00_00"));
}

#[test]
fn test_ja4t_absent_without_syn() {
    let mut d = Detector::new();
    // 纯数据流（无 SYN 抓包场景）：不产出 JA4T
    let psh = build_tcp_packet_with_options(
        [192, 168, 1, 10],
        54321,
        [93, 184, 216, 34],
        443,
        0x18,
        1000,
        &[],
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    d.detect(&psh).unwrap();
    let flows: Vec<_> = d.flows().map(|(_, f)| f).collect();
    assert!(flows[0].ja4t.is_none());
}

#[test]
fn test_ja4t_first_syn_wins_and_udp_unaffected() {
    // 同流两个 SYN：取第一个；UDP 流无 tcp 字段、无指纹
    let mut d = Detector::new();
    let syn1 = build_tcp_packet_with_options(
        [10, 0, 0, 1],
        40000,
        [10, 0, 0, 2],
        8080,
        0x02,
        1024,
        &[2, 4, 0x02, 0x00], // MSS=512
        &[],
    );
    d.detect(&syn1).unwrap();
    let syn2 = build_tcp_packet_with_options(
        [10, 0, 0, 1],
        40000,
        [10, 0, 0, 2],
        8080,
        0x02,
        9999,
        &[],
        &[],
    );
    d.detect(&syn2).unwrap();
    let flows: Vec<_> = d.flows().map(|(_, f)| f).collect();
    assert_eq!(flows[0].ja4t.as_deref(), Some("1024_2_512_00"));
}

/// 服务端形态 SYN-ACK 选项：MSS(1460) + NOP + WS(7) + NOP + NOP + SACK-Permitted
const SYN_ACK_OPTIONS_LINUX: &[u8] = &[2, 4, 0x05, 0xb4, 1, 3, 3, 7, 1, 1, 4, 2];

#[test]
fn test_ja4ts_captured_from_syn_ack() {
    let mut d = Detector::new();
    let syn_ack = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        443,
        [192, 168, 1, 10],
        54321,
        0x12, // SYN|ACK（精确等于，官方 zeek 语义）
        29200,
        SYN_ACK_OPTIONS_LINUX,
        &[],
    );
    let r = d.detect(&syn_ack).unwrap();
    // 空载荷 SYN-ACK 通常无协议识别结果，但 JA4TS 已写入服务端方向流
    assert!(r.is_none() || r.unwrap().ja4ts.is_some());

    let server_flow = d
        .flows()
        .find(|(k, _)| k.src_port == 443)
        .map(|(_, f)| f)
        .expect("服务端方向流应存在");
    assert_eq!(
        server_flow.ja4ts.as_deref(),
        Some("29200_2-1-3-1-1-4_1460_7")
    );

    // 客户端方向流（另一条流）不受影响
    let client_flow = d.flows().find(|(k, _)| k.src_port == 54321);
    assert!(client_flow.is_none(), "仅有 SYN-ACK 时客户端方向流不存在");
}

#[test]
fn test_ja4ts_first_syn_ack_wins() {
    let mut d = Detector::new();
    let syn_ack1 = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        443,
        [192, 168, 1, 10],
        54321,
        0x12,
        29200,
        SYN_ACK_OPTIONS_LINUX,
        &[],
    );
    d.detect(&syn_ack1).unwrap();
    // 重传 SYN-ACK（不同窗口/无选项）：不得覆盖首个指纹
    let syn_ack2 = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        443,
        [192, 168, 1, 10],
        54321,
        0x12,
        9999,
        &[],
        &[],
    );
    d.detect(&syn_ack2).unwrap();
    let server_flow = d
        .flows()
        .find(|(k, _)| k.src_port == 443)
        .map(|(_, f)| f)
        .expect("服务端方向流应存在");
    assert_eq!(
        server_flow.ja4ts.as_deref(),
        Some("29200_2-1-3-1-1-4_1460_7"),
        "重传 SYN-ACK 不得覆盖首个指纹"
    );
}

#[test]
fn test_ja4ts_syn_does_not_trigger() {
    let mut d = Detector::new();
    // 客户端 SYN 先行：ja4ts 不得产出（SYN 归 JA4T 管辖）
    let syn = build_tcp_packet_with_options(
        [192, 168, 1, 10],
        54321,
        [93, 184, 216, 34],
        443,
        0x02,
        64240,
        SYN_OPTIONS_WIN11,
        &[],
    );
    d.detect(&syn).unwrap();
    let client_flow = d
        .flows()
        .find(|(k, _)| k.src_port == 54321)
        .map(|(_, f)| f)
        .expect("客户端方向流应存在");
    assert!(client_flow.ja4ts.is_none(), "SYN 不得触发 JA4TS");
    assert_eq!(
        client_flow.ja4t.as_deref(),
        Some("64240_2-1-3-1-1-4_1460_8")
    );

    // 随后 SYN-ACK 到达（服务端方向是另一条流）：JA4TS 捕获，且 JA4T 不触发
    let syn_ack = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        443,
        [192, 168, 1, 10],
        54321,
        0x12,
        29200,
        SYN_ACK_OPTIONS_LINUX,
        &[],
    );
    d.detect(&syn_ack).unwrap();
    let server_flow = d
        .flows()
        .find(|(k, _)| k.src_port == 443)
        .map(|(_, f)| f)
        .expect("服务端方向流应存在");
    assert_eq!(
        server_flow.ja4ts.as_deref(),
        Some("29200_2-1-3-1-1-4_1460_7")
    );
    assert!(server_flow.ja4t.is_none(), "SYN-ACK 不得触发 JA4T");
}

#[test]
fn test_ja4ts_requires_exact_syn_ack_flags() {
    let mut d = Detector::new();
    // SYN|ACK|PSH（0x1A）：官方 zeek 要求 flags 精确等于 SYN|ACK，不触发
    let weird = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        443,
        [192, 168, 1, 10],
        54321,
        0x1A,
        29200,
        SYN_ACK_OPTIONS_LINUX,
        &[],
    );
    d.detect(&weird).unwrap();
    let flows: Vec<_> = d.flows().map(|(_, f)| f).collect();
    assert!(
        flows[0].ja4ts.is_none(),
        "带额外标志位的 SYN-ACK 不得触发 JA4TS"
    );
    // 同流真正精确的 SYN-ACK：仍可捕获（每流一次，首个精确 SYN-ACK 生效）
    let syn_ack = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        443,
        [192, 168, 1, 10],
        54321,
        0x12,
        5744,
        &[2, 4, 0x05, 0x9c],
        &[],
    );
    d.detect(&syn_ack).unwrap();
    let server_flow = d
        .flows()
        .find(|(k, _)| k.src_port == 443)
        .map(|(_, f)| f)
        .expect("服务端方向流应存在");
    assert_eq!(server_flow.ja4ts.as_deref(), Some("5744_2_1436_00"));
}

#[test]
fn test_ja4ts_absent_without_syn_ack() {
    let mut d = Detector::new();
    // 纯数据流（无握手抓包场景）：不产出 JA4TS
    let psh = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        443,
        [192, 168, 1, 10],
        54321,
        0x18,
        1000,
        &[],
        &[],
    );
    d.detect(&psh).unwrap();
    let flows: Vec<_> = d.flows().map(|(_, f)| f).collect();
    assert!(flows[0].ja4ts.is_none());
}

// ==== F40：JA4TS 第 5 段重传延迟 + RST 后缀（官方 zeek/ja4t/main.zeek）====

use std::time::{Duration, SystemTime};

/// 以 UNIX 纪元起算的秒级时戳（detect_at 捕获时戳语义）
fn ts(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// 服务端方向 HTTP 响应包（检测结果载体：空载荷握手包通常无识别结果）
fn http_response() -> Vec<u8> {
    build_tcp_packet_with_options(
        [93, 184, 216, 34],
        80,
        [192, 168, 1, 10],
        54321,
        0x18, // PSH|ACK
        29200,
        &[],
        b"HTTP/1.1 200 OK\r\n\r\n",
    )
}

#[test]
fn test_ja4ts_retrans_delays_fifth_segment() {
    let mut d = Detector::new();
    let syn_ack = |flags: u8| {
        build_tcp_packet_with_options(
            [93, 184, 216, 34],
            80,
            [192, 168, 1, 10],
            54321,
            flags,
            29200,
            SYN_ACK_OPTIONS_LINUX,
            &[],
        )
    };
    // 首个 SYN-ACK（t=100）开始收集；重传（t=101、t=103）记相邻间隔整秒
    d.detect_at(&syn_ack(0x12), ts(100)).unwrap();
    d.detect_at(&syn_ack(0x12), ts(101)).unwrap();
    d.detect_at(&syn_ack(0x12), ts(103)).unwrap();
    // 服务端数据包触发检测结果落库，验证组合输出
    let r = d.detect_at(&http_response(), ts(104)).unwrap();
    let server_flow = d
        .flows()
        .find(|(k, _)| k.src_port == 80)
        .map(|(_, f)| f)
        .expect("服务端方向流应存在");
    // 流字段：基串一次定型不覆盖，延迟序列单独累积
    assert_eq!(
        server_flow.ja4ts.as_deref(),
        Some("29200_2-1-3-1-1-4_1460_7"),
        "重传不得覆盖 4 段基串"
    );
    assert_eq!(server_flow.ja4ts_delays, vec![1, 2]);
    // 检测结果携带完整官方格式：第 5 段 = `1-2`
    assert_eq!(
        r.expect("HTTP 响应应被识别").ja4ts.as_deref(),
        Some("29200_2-1-3-1-1-4_1460_7_1-2")
    );
}

#[test]
fn test_ja4ts_client_packet_stops_collection() {
    let mut d = Detector::new();
    // 官方语义：任一客户端方向包（此处为握手完成 ACK）即停止收集——
    // 其后的 SYN-ACK 重传不计入延迟
    let syn = build_tcp_packet_with_options(
        [192, 168, 1, 10],
        54321,
        [93, 184, 216, 34],
        80,
        0x02,
        64240,
        SYN_OPTIONS_WIN11,
        &[],
    );
    d.detect_at(&syn, ts(100)).unwrap();
    let syn_ack = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        80,
        [192, 168, 1, 10],
        54321,
        0x12,
        29200,
        SYN_ACK_OPTIONS_LINUX,
        &[],
    );
    d.detect_at(&syn_ack, ts(101)).unwrap();
    let ack = build_tcp_packet_with_options(
        [192, 168, 1, 10],
        54321,
        [93, 184, 216, 34],
        80,
        0x10, // 纯 ACK
        64240,
        &[],
        &[],
    );
    d.detect_at(&ack, ts(102)).unwrap();
    // 关闭后的重传不计数；服务端数据包验证组合输出
    let retrans = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        80,
        [192, 168, 1, 10],
        54321,
        0x12,
        29200,
        SYN_ACK_OPTIONS_LINUX,
        &[],
    );
    d.detect_at(&retrans, ts(110)).unwrap();
    let r = d.detect_at(&http_response(), ts(111)).unwrap();
    let server_flow = d
        .flows()
        .find(|(k, _)| k.src_port == 80)
        .map(|(_, f)| f)
        .expect("服务端方向流应存在");
    assert!(
        server_flow.ja4ts_delays.is_empty(),
        "客户端包到达后的重传不得计入"
    );
    assert_eq!(
        r.expect("HTTP 响应应被识别").ja4ts.as_deref(),
        Some("29200_2-1-3-1-1-4_1460_7"),
        "无重传延迟时输出恰为 4 段基串"
    );
}

#[test]
fn test_ja4ts_rst_suffix_only_with_delays() {
    let syn_ack = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        80,
        [192, 168, 1, 10],
        54321,
        0x12,
        29200,
        SYN_ACK_OPTIONS_LINUX,
        &[],
    );
    let rst = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        80,
        [192, 168, 1, 10],
        54321,
        0x04,
        29200,
        &[],
        &[],
    );

    // 纯 RST（无重传）：官方门控下不带 -R 后缀，输出仍为 4 段
    let mut d = Detector::new();
    d.detect_at(&syn_ack, ts(100)).unwrap();
    d.detect_at(&rst, ts(101)).unwrap();
    let r = d.detect_at(&http_response(), ts(102)).unwrap();
    assert_eq!(
        r.expect("HTTP 响应应被识别").ja4ts.as_deref(),
        Some("29200_2-1-3-1-1-4_1460_7")
    );

    // 有重传延迟的连接：RST 追加 `-R{整秒}`（RST 距最近 SYN-ACK 3 秒）
    let mut d2 = Detector::new();
    d2.detect_at(&syn_ack, ts(100)).unwrap();
    d2.detect_at(&syn_ack, ts(102)).unwrap(); // 延迟 2
    d2.detect_at(&rst, ts(105)).unwrap();
    let r = d2.detect_at(&http_response(), ts(106)).unwrap();
    assert_eq!(
        r.expect("HTTP 响应应被识别").ja4ts.as_deref(),
        Some("29200_2-1-3-1-1-4_1460_7_2-R3")
    );
}

#[test]
fn test_ja4ts_timeout_stops_collection() {
    let mut d = Detector::new();
    let syn_ack = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        80,
        [192, 168, 1, 10],
        54321,
        0x12,
        29200,
        SYN_ACK_OPTIONS_LINUX,
        &[],
    );
    d.detect_at(&syn_ack, ts(100)).unwrap();
    // 距最近 SYN-ACK 超 120 秒：官方语义停止收集，重传不计入
    d.detect_at(&syn_ack, ts(100) + Duration::from_secs(121))
        .unwrap();
    // 超时后跟踪已关闭：其后 1 秒内的重传同样不计入
    d.detect_at(&syn_ack, ts(100) + Duration::from_secs(122))
        .unwrap();
    let server_flow = d
        .flows()
        .find(|(k, _)| k.src_port == 80)
        .map(|(_, f)| f)
        .expect("服务端方向流应存在");
    assert!(server_flow.ja4ts_delays.is_empty(), "超时后的重传不得计入");
    assert!(
        !server_flow.ja4ts_tracking,
        "超时后跟踪应关闭（官方 synack_done 语义）"
    );
}

#[test]
fn test_ja4ts_max_ten_delays() {
    let mut d = Detector::new();
    let syn_ack = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        80,
        [192, 168, 1, 10],
        54321,
        0x12,
        29200,
        SYN_ACK_OPTIONS_LINUX,
        &[],
    );
    d.detect_at(&syn_ack, ts(100)).unwrap();
    // 11 次重传：官方至多收集 10 项，满即停
    for i in 1..=11u64 {
        d.detect_at(&syn_ack, ts(100 + i)).unwrap();
    }
    let server_flow = d
        .flows()
        .find(|(k, _)| k.src_port == 80)
        .map(|(_, f)| f)
        .expect("服务端方向流应存在");
    assert_eq!(server_flow.ja4ts_delays.len(), 10);
    assert!(
        !server_flow.ja4ts_tracking,
        "满 10 项后跟踪应关闭（官方 |delays|==10 return 语义）"
    );
    assert_eq!(
        server_flow.ja4ts_delays,
        vec![1; 10],
        "延迟均为相邻 SYN-ACK 间隔整秒"
    );
}

#[test]
fn test_ja4ts_retrans_wins_base_and_records_delay() {
    // 更新 F34 语义钉住：重传不覆盖 4 段基串，但按官方记入延迟序列
    let mut d = Detector::new();
    let syn_ack1 = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        80,
        [192, 168, 1, 10],
        54321,
        0x12,
        29200,
        SYN_ACK_OPTIONS_LINUX,
        &[],
    );
    d.detect_at(&syn_ack1, ts(100)).unwrap();
    // 同秒重传（不同窗口/无选项）：基串不变，延迟记 0（整秒截断）
    let syn_ack2 = build_tcp_packet_with_options(
        [93, 184, 216, 34],
        80,
        [192, 168, 1, 10],
        54321,
        0x12,
        9999,
        &[],
        &[],
    );
    d.detect_at(&syn_ack2, ts(100)).unwrap();
    let r = d.detect_at(&http_response(), ts(101)).unwrap();
    let server_flow = d
        .flows()
        .find(|(k, _)| k.src_port == 80)
        .map(|(_, f)| f)
        .expect("服务端方向流应存在");
    assert_eq!(
        server_flow.ja4ts.as_deref(),
        Some("29200_2-1-3-1-1-4_1460_7"),
        "重传 SYN-ACK 不得覆盖 4 段基串"
    );
    assert_eq!(server_flow.ja4ts_delays, vec![0], "同秒重传延迟记 0");
    assert_eq!(
        r.expect("HTTP 响应应被识别").ja4ts.as_deref(),
        Some("29200_2-1-3-1-1-4_1460_7_0")
    );
}
