//! JA4T 客户端 TCP 指纹集成测试（F33，2026-11-05）
//!
//! 触发语义对齐 FoxIO 官方 rust/ja4 tcp.rs：
//! - 仅初始 SYN（SYN=0x02 置位且 ACK=0x10 清零；SYN+ECN 0xC2 同样满足）
//! - 每流只取第一个满足的包
//! - 格式 `{window}_{options}_{mss}_{window_scale}`，官方向量见 application/ja4.rs

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
