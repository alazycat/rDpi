//! JA4D/JA4D6 DHCP 指纹集成测试（F37，2026-11-06）
//!
//! 格式权威：FoxIO ja4 仓库 zeek/ja4d/main.zeek（v4）+ Wireshark packet-ja4.c
//! 插件（v6，官方 README "awaiting Zeek DHCPv6 support"），终版格式对齐
//! commit d21d63f9（终版）+ 11ae927f（v4 选项剔除 53/50/81）。
//!
//! 黄金向量来源：
//! - v4：wireshark/test/testdata/dhcp.pcapng.json（disco/offer/reqst/dpack）
//! - v6：wireshark/test/testdata/dhcpv6.pcap.json（solct/advrt/reqst/reply/relse）
//! - 博客样例：foxio.io/blog/ja4d-and-ja4d6-dhcp-fingerprinting
//!   （Android 16 Discover、Windows Request 带 FQDN、Pretender Advertise）

#![cfg(feature = "infra")]

use rdpi::Metadata;
use rdpi::protocols::ProtocolDetector;
use rdpi::protocols::dhcp::detect_dhcp;
use rdpi::protocols::dhcpv6::Dhcpv6Detector;

/// 构造 DHCPv4 报文：240 字节头 + magic cookie（内嵌）+ TLV 选项列表
fn build_v4(options: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut p = vec![0u8; 240];
    p[0] = 1; // opcode: BOOTREQUEST
    p[1] = 1; // htype: Ethernet
    p[2] = 6; // hlen
    p[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie
    for (code, val) in options {
        p.push(*code);
        p.push(val.len() as u8);
        p.extend_from_slice(val);
    }
    p
}

/// 构造 DHCPv6 报文：type + 事务 ID + TLV 选项列表（code/len 均 2 字节大端）
fn build_v6(msg_type: u8, options: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut v = vec![msg_type, 0x12, 0x34, 0x56];
    for (code, val) in options {
        v.extend_from_slice(&code.to_be_bytes());
        v.extend_from_slice(&(val.len() as u16).to_be_bytes());
        v.extend_from_slice(val);
    }
    v
}

/// 构造 DHCPv6 Relay 报文（type 12/13）：type + hop + link-address(16) +
/// peer-address(16) + TLV 选项列表（RFC 8415 §7.3，两种 Relay 同构 34 字节头）
fn build_v6_relay(msg_type: u8, options: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut v = vec![msg_type, 1];
    v.extend_from_slice(&[0u8; 32]); // link-address + peer-address
    for (code, val) in options {
        v.extend_from_slice(&code.to_be_bytes());
        v.extend_from_slice(&(val.len() as u16).to_be_bytes());
        v.extend_from_slice(val);
    }
    v
}

fn ja4d_of(pkt: &[u8]) -> String {
    let result = detect_dhcp(pkt).expect("应识别为 DHCP");
    assert_eq!(result.protocol, rdpi::Protocol::Dhcp);
    match &result.metadata {
        Metadata::Dhcp(m) => m.ja4d.clone(),
        _ => panic!("Expected Dhcp metadata"),
    }
}

fn ja4d6_of(pkt: &[u8]) -> String {
    let detector = Dhcpv6Detector::new();
    let result = detector.detect(pkt).expect("应识别为 DHCPv6");
    assert_eq!(result.protocol, rdpi::Protocol::Dhcpv6);
    match &result.metadata {
        Metadata::Dhcpv6(m) => m.ja4d6.clone(),
        _ => panic!("Expected Dhcpv6 metadata"),
    }
}

// ==== v4 黄金向量（wireshark dhcp.pcapng.json）====

#[test]
fn ja4d_v4_discover_golden() {
    // 官方向量：disco0000in_61-55_1-3-6-42
    // 选项序：53(Discover)、61(Client-ID)、50(Requested IP)、55(参数请求)
    // → 53/50 剔除，i 标志来自 50，选项列表 61-55
    let pkt = build_v4(&[
        (53, vec![1]),
        (61, vec![1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        (50, vec![10, 0, 0, 99]),
        (55, vec![1, 3, 6, 42]),
    ]);
    assert_eq!(ja4d_of(&pkt), "disco0000in_61-55_1-3-6-42");
}

#[test]
fn ja4d_v4_offer_golden() {
    // 官方向量：offer0000nn_1-58-59-51-54_00
    // 选项序：53(Offer)、1(子网掩码)、58(T1)、59(T2)、51(租期)、54(Server-ID)
    let pkt = build_v4(&[
        (53, vec![2]),
        (1, vec![255, 255, 255, 0]),
        (58, vec![0, 0, 27, 60]),
        (59, vec![0, 0, 47, 100]),
        (51, vec![0, 0, 83, 160]),
        (54, vec![10, 0, 0, 1]),
    ]);
    assert_eq!(ja4d_of(&pkt), "offer0000nn_1-58-59-51-54_00");
}

#[test]
fn ja4d_v4_request_golden() {
    // 官方向量：reqst0000in_61-54-55_1-3-6-42
    // 选项序：53(Request)、61、50、54、55 → 53/50 剔除，列表 61-54-55
    let pkt = build_v4(&[
        (53, vec![3]),
        (61, vec![1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        (50, vec![10, 0, 0, 99]),
        (54, vec![10, 0, 0, 1]),
        (55, vec![1, 3, 6, 42]),
    ]);
    assert_eq!(ja4d_of(&pkt), "reqst0000in_61-54-55_1-3-6-42");
}

#[test]
fn ja4d_v4_ack_golden() {
    // 官方向量：dpack0000nn_58-59-51-54-1_00
    let pkt = build_v4(&[
        (53, vec![5]),
        (58, vec![0, 0, 27, 60]),
        (59, vec![0, 0, 47, 100]),
        (51, vec![0, 0, 83, 160]),
        (54, vec![10, 0, 0, 1]),
        (1, vec![255, 255, 255, 0]),
    ]);
    assert_eq!(ja4d_of(&pkt), "dpack0000nn_58-59-51-54-1_00");
}

// ==== v4 博客样例向量（foxio.io JA4D 博客）====

#[test]
fn ja4d_v4_android_discover_blog() {
    // 博客样例：disco1500nn_61-57-60-12-55_1-3-6-15-26-28-51-58-59-43-114-108
    // 尺寸段来自 option 57 = 1500；57 出现在选项列表中（不同于 53/50/81 被剔除）
    let pkt = build_v4(&[
        (53, vec![1]),
        (61, vec![1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        (57, vec![0x05, 0xdc]), // 1500
        (60, b"android-dhcp-16".to_vec()),
        (12, vec![1, 2, 3, 4]),
        (55, vec![1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114, 108]),
    ]);
    assert_eq!(
        ja4d_of(&pkt),
        "disco1500nn_61-57-60-12-55_1-3-6-15-26-28-51-58-59-43-114-108"
    );
}

#[test]
fn ja4d_v4_windows_request_fqdn_blog() {
    // 博客样例：reqst0000id_61-12-60-55_1-3-6-15-31-33-43-44-46-47-119-121-249-252
    // i 标志来自 option 50（Requested IP）、d 标志来自 option 81（Client FQDN），
    // 50/81 自身被剔除出选项列表
    let pkt = build_v4(&[
        (53, vec![3]),
        (61, vec![1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        (12, vec![1, 2, 3, 4]),
        (60, b"MSFT 5.0".to_vec()),
        (50, vec![10, 0, 0, 99]),
        (
            55,
            vec![1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
        ),
        (81, vec![0, 0, 0, 0]),
    ]);
    assert_eq!(
        ja4d_of(&pkt),
        "reqst0000id_61-12-60-55_1-3-6-15-31-33-43-44-46-47-119-121-249-252"
    );
}

// ==== v4 边界 ====

#[test]
fn ja4d_v4_missing_msg_type_is_00000() {
    // 缺 option 53 → 首段 "00000"
    let pkt = build_v4(&[(55, vec![1, 3, 6]), (255, vec![])]);
    assert_eq!(ja4d_of(&pkt), "000000000nn_55_1-3-6");
}

#[test]
fn ja4d_v4_unknown_msg_type_numeric() {
    // 未知消息类型（19 无助记符）→ %05d
    let pkt = build_v4(&[(53, vec![19]), (255, vec![])]);
    assert_eq!(ja4d_of(&pkt), "000190000nn_00_00");
}

#[test]
fn ja4d_v4_max_msg_size_cap_9999() {
    // option 57 = 10000 越界 → 尺寸段 "9999"
    let pkt = build_v4(&[(53, vec![1]), (57, vec![0x27, 0x10])]);
    assert_eq!(ja4d_of(&pkt), "disco9999nn_57_00");
}

#[test]
fn ja4d_v4_empty_option_and_param_lists() {
    // 仅 option 53（+ End 补足最小包长）→ 两个列表段均为 "00"
    let pkt = build_v4(&[(53, vec![1]), (255, vec![])]);
    assert_eq!(ja4d_of(&pkt), "disco0000nn_00_00");
}

#[test]
fn ja4d_v4_end_option_terminates() {
    // option 255 终止遍历：其后的选项不参与指纹
    let pkt = build_v4(&[
        (53, vec![1]),
        (255, vec![]),
        (12, vec![1, 2, 3, 4]), // 255 之后，应被忽略
    ]);
    assert_eq!(ja4d_of(&pkt), "disco0000nn_00_00");
}

#[test]
fn ja4d_v4_pad_option_skipped() {
    // option 0（Pad，无长度字段）跳过 1 字节，不中断后续解析
    let pkt = build_v4(&[(53, vec![1]), (0, vec![]), (12, vec![1, 2, 3, 4])]);
    // 注意：Pad 的 push 会写入 code 0 后跟 len 0 两字节，等价于真实 Pad + 一个 0 字节
    assert_eq!(ja4d_of(&pkt), "disco0000nn_12_00");
}

#[test]
fn ja4d_v4_truncated_option_stops() {
    // 选项值越界截断：截断选项及其后内容不参与
    let mut pkt = build_v4(&[(53, vec![1]), (12, vec![1, 2])]);
    pkt.push(60); // code 60
    pkt.push(20); // 声称 20 字节，实际无值 → 截断停止
    assert_eq!(ja4d_of(&pkt), "disco0000nn_12_00");
}

// ==== v6 黄金向量（wireshark dhcpv6.pcap.json）====

#[test]
fn ja4d6_v6_solicit_golden() {
    // 官方向量：solct0014nn_1-6-8-25_23-24
    // 选项：1(Client-ID, DUID 14 字节)、6(ORO: 23,24)、8(Elapsed Time)、25(IA_NA)
    // v6 选项列表不剔除任何选项（含 1/6），尺寸段 = DUID 长度
    let pkt = build_v6(
        1,
        &[
            (
                1,
                vec![
                    0x00, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc,
                    0xdd,
                ],
            ), // 14B DUID-LLT
            (6, vec![0x00, 0x17, 0x00, 0x18]), // ORO: 23, 24
            (8, vec![0x00, 0x00]),
            (25, vec![0x11; 12]), // IA_NA
        ],
    );
    assert_eq!(ja4d6_of(&pkt), "solct0014nn_1-6-8-25_23-24");
}

#[test]
fn ja4d6_v6_advertise_golden() {
    // 官方向量：advrt0014nn_25-26-1-2_00
    let pkt = build_v6(
        2,
        &[
            (25, vec![0x11; 12]),
            (26, vec![0x22; 12]),
            (
                1,
                vec![
                    0x00, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc,
                    0xdd,
                ],
            ),
            (2, vec![0x33; 10]),
        ],
    );
    assert_eq!(ja4d6_of(&pkt), "advrt0014nn_25-26-1-2_00");
}

#[test]
fn ja4d6_v6_request_golden() {
    // 官方向量：reqst0014nn_1-2-6-8-25-26_23-24
    let pkt = build_v6(
        3,
        &[
            (
                1,
                vec![
                    0x00, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc,
                    0xdd,
                ],
            ),
            (2, vec![0x33; 10]),
            (6, vec![0x00, 0x17, 0x00, 0x18]),
            (8, vec![0x00, 0x00]),
            (25, vec![0x11; 12]),
            (26, vec![0x22; 12]),
        ],
    );
    assert_eq!(ja4d6_of(&pkt), "reqst0014nn_1-2-6-8-25-26_23-24");
}

#[test]
fn ja4d6_v6_reply_golden() {
    // 官方向量：reply0014nn_25-26-1-2_00
    let pkt = build_v6(
        7,
        &[
            (25, vec![0x11; 12]),
            (26, vec![0x22; 12]),
            (
                1,
                vec![
                    0x00, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc,
                    0xdd,
                ],
            ),
            (2, vec![0x33; 10]),
        ],
    );
    assert_eq!(ja4d6_of(&pkt), "reply0014nn_25-26-1-2_00");
}

#[test]
fn ja4d6_v6_release_golden() {
    // 官方向量：relse0014nn_1-2-6-8-25-26_23-24
    let pkt = build_v6(
        8,
        &[
            (
                1,
                vec![
                    0x00, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc,
                    0xdd,
                ],
            ),
            (2, vec![0x33; 10]),
            (6, vec![0x00, 0x17, 0x00, 0x18]),
            (8, vec![0x00, 0x00]),
            (25, vec![0x11; 12]),
            (26, vec![0x22; 12]),
        ],
    );
    assert_eq!(ja4d6_of(&pkt), "relse0014nn_1-2-6-8-25-26_23-24");
}

#[test]
fn ja4d6_v6_reply_status_golden() {
    // 官方向量：reply0014nn_1-2-13_00（option 13 = Status Code）
    let pkt = build_v6(
        7,
        &[
            (
                1,
                vec![
                    0x00, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc,
                    0xdd,
                ],
            ),
            (2, vec![0x33; 10]),
            (13, vec![0x00, 0x00]),
        ],
    );
    assert_eq!(ja4d6_of(&pkt), "reply0014nn_1-2-13_00");
}

// ==== v6 博客样例与边界 ====

#[test]
fn ja4d6_v6_pretender_advertise_blog() {
    // 博客样例（Pretender 工具）：advrt0018nn_1-2-23-3-5_00
    // DUID 长度 18（DUID-UUID）
    let pkt = build_v6(
        2,
        &[
            (1, vec![0x44; 18]),
            (2, vec![0x33; 10]),
            (23, vec![0xaa, 0xbb]),
            (3, vec![0x00, 0x01, 0x00, 0x00]),
            (5, vec![0x00, 0x00]),
        ],
    );
    assert_eq!(ja4d6_of(&pkt), "advrt0018nn_1-2-23-3-5_00");
}

#[test]
fn ja4d6_v6_duid_from_server_id_option() {
    // 无 Client-ID（option 1）时尺寸段取 Server Identifier（option 2）的 DUID 长度
    // （Wireshark dhcpv6.duid.bytes 覆盖两个字段）
    let pkt = build_v6(7, &[(2, vec![0x33; 10])]);
    assert_eq!(ja4d6_of(&pkt), "reply0010nn_2_00");
}

#[test]
fn ja4d6_v6_no_duid_0000() {
    // option 1/2 均缺失 → 尺寸段 "0000"
    let pkt = build_v6(7, &[(13, vec![0x00, 0x00])]);
    assert_eq!(ja4d6_of(&pkt), "reply0000nn_13_00");
}

#[test]
fn ja4d6_v6_iata_and_fqdn_flags() {
    // option 4（IA_TA）→ 'i'；option 39（Client FQDN）→ 'd'
    let pkt = build_v6(
        3,
        &[
            (1, vec![0x44; 14]),
            (4, vec![0x55; 12]),
            (39, vec![0x00, 0x03, 0x61, 0x62]),
        ],
    );
    assert_eq!(ja4d6_of(&pkt), "reqst0014id_1-4-39_00");
}

#[test]
fn ja4d6_v6_relay_reply_mnemonic() {
    // Relay-reply（type 13，合法类型号边界）：助记符 "rlayr"，
    // Relay 报文头 34 字节（RFC 8415 §7.3，两种 Relay 同构）
    let pkt = build_v6_relay(13, &[(1, vec![0x44; 15])]);
    assert_eq!(ja4d6_of(&pkt), "rlayr0015nn_1_00");
}

#[test]
fn ja4d6_v6_relay_forward_outer_options_only() {
    // Relay-forward（type 12）只解析最外层选项，不递归 option 9 内层报文
    // （risks.md F37 边界）
    let inner = build_v6(1, &[(1, vec![0x44; 14])]); // 内层 Solicit
    let pkt = build_v6_relay(
        12,
        &[
            (9, inner),            // Relay Message（内层不递归）
            (18, vec![0; 4]),      // Interface-ID
            (8, vec![0x00, 0x00]), // Elapsed Time
        ],
    );
    // option 9（Relay Message）出现在外层选项列表，内层 Solicit 选项不出现
    assert_eq!(ja4d6_of(&pkt), "rlayf0000nn_9-18-8_00");
}

#[test]
fn ja4d6_v6_truncated_option_stops() {
    // 选项值越界截断：截断选项及其后内容不参与
    let mut pkt = build_v6(1, &[(1, vec![0x44; 14])]);
    pkt.extend_from_slice(&[0x00, 0x08, 0x00, 0x20]); // option 8 声称 32 字节，无值
    assert_eq!(ja4d6_of(&pkt), "solct0014nn_1_00");
}
