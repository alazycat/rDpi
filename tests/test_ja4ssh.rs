//! JA4SSH 会话指纹集成测试（F36，2026-11-06）
//!
//! 触发语义（对齐官方 FoxIO zeek ja4ssh/main.zeek）：
//! - 门控：仅已定型为 SSH 的流参与，且连接自初始 SYN 起（mid-stream 不追踪）
//! - 累计：载荷包（payload > 0）长度入序列；纯 ACK（无载荷且 flags 精确
//!   等于 0x10）计数；其余包不计
//! - 窗口：双向载荷包合计 ≥ 200 产出指纹 `c{c众数}s{s众数}_c{c载荷包数}s{s载荷包数}_c{c纯ACK数}s{s纯ACK数}`
//!   并清零滚动；众数平局取较小值；SYN 发送端为客户端（zeek orig 语义）
//! - 定型当包（横幅包）不计入窗口（实现边界，见 risks.md F36）
//!
//! SSH 横幅触发依赖 ssh feature，整个文件在无 ssh feature 时为空。

#![cfg(feature = "ssh")]

use rdpi::Detector;

/// 构造完整以太网+IPv4+TCP 包（风格对齐 test_ja4t.rs）
fn build_tcp_packet(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_hdr_len = 20u16;
    let total_len = 14 + 20 + tcp_hdr_len as usize + payload.len();
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

    // TCP header (20 bytes)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
    pkt.push(0x50); // data offset 5
    pkt.push(flags);
    pkt.extend_from_slice(&64240u16.to_be_bytes()); // window
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer

    pkt.extend_from_slice(payload);
    pkt
}

const CLIENT: [u8; 4] = [192, 168, 1, 10];
const SERVER: [u8; 4] = [93, 184, 216, 34];
const CPORT: u16 = 54321;
const SPORT: u16 = 22;

/// 克隆快照辅助：按源端口取流级 ja4ssh（终结借用后再继续 detect）
fn ja4ssh_by_src_port(d: &Detector, port: u16) -> Option<String> {
    d.flows()
        .find(|(k, _)| k.src_port == port)
        .and_then(|(_, f)| f.ja4ssh.clone())
}

#[test]
fn test_ja4ssh_format_and_mode_tiebreak() {
    // 官方格式：c{mode}s{mode}_c{cnt}s{cnt}_c{ack}s{ack}
    assert_eq!(
        rdpi::application::compute_ja4ssh(&[100, 50, 100], &[200], 3, 1),
        "c100s200_c3s1_c3s1"
    );
    // 众数平局取较小值（zeek get_mode：freq == max && idx < mode）
    assert_eq!(
        rdpi::application::compute_ja4ssh(&[100, 50, 100, 50], &[], 0, 0),
        "c50s0_c4s0_c0s0"
    );
    // 空窗口众数记 0
    assert_eq!(
        rdpi::application::compute_ja4ssh(&[], &[], 7, 9),
        "c0s0_c0s0_c7s9"
    );
}

#[test]
fn test_ja4ssh_full_session_window() {
    let mut d = Detector::new();

    // 1. 客户端 SYN（记录 syn_time，门控 2 依据）
    let syn = build_tcp_packet(CLIENT, CPORT, SERVER, SPORT, 0x02, &[]);
    d.detect(&syn).unwrap();

    // 2. 双向横幅（定型 SSH；定型当包不计入窗口——实现边界）
    let c_banner = build_tcp_packet(
        CLIENT,
        CPORT,
        SERVER,
        SPORT,
        0x18,
        b"SSH-2.0-OpenSSH_9.6\r\n",
    );
    d.detect(&c_banner).unwrap();
    let s_banner = build_tcp_packet(
        SERVER,
        SPORT,
        CLIENT,
        CPORT,
        0x18,
        b"SSH-2.0-OpenSSH_9.2\r\n",
    );
    d.detect(&s_banner).unwrap();

    // 3. 客户端 3 个纯 ACK（计入 ack，不计入窗口载荷数）
    for _ in 0..3 {
        let ack = build_tcp_packet(CLIENT, CPORT, SERVER, SPORT, 0x10, &[]);
        d.detect(&ack).unwrap();
    }
    // 服务端 1 个纯 ACK
    let sack = build_tcp_packet(SERVER, SPORT, CLIENT, CPORT, 0x10, &[]);
    d.detect(&sack).unwrap();

    // 4. 客户端 97 个载荷包（100 字节）——未满窗口
    for i in 0..97 {
        let data = build_tcp_packet(CLIENT, CPORT, SERVER, SPORT, 0x18, &[0xAA; 100]);
        d.detect(&data).unwrap();
        if i < 96 {
            assert!(ja4ssh_by_src_port(&d, CPORT).is_none(), "窗口未满不产出");
        }
    }

    // 5. 服务端 102 个载荷包（200 字节）——合计 199，仍未满
    for _ in 0..102 {
        let data = build_tcp_packet(SERVER, SPORT, CLIENT, CPORT, 0x18, &[0xBB; 200]);
        d.detect(&data).unwrap();
    }
    assert!(
        ja4ssh_by_src_port(&d, CPORT).is_none() && ja4ssh_by_src_port(&d, SPORT).is_none(),
        "199 载荷包不产出"
    );

    // 6. 第 200 个载荷包（服务端方向到达）→ 窗口完成
    //    期望：c{100}s{200}_c{97}s{103}_c{3}s{1}（SYN 发送端为客户端）
    let data = build_tcp_packet(SERVER, SPORT, CLIENT, CPORT, 0x18, &[0xBB; 200]);
    d.detect(&data).unwrap();
    let expected = "c100s200_c97s103_c3s1";
    assert_eq!(
        ja4ssh_by_src_port(&d, SPORT),
        Some(expected.to_string()),
        "窗口在服务端方向包上完成，指纹仍按客户端在前归位"
    );
    assert_eq!(
        ja4ssh_by_src_port(&d, CPORT),
        Some(expected.to_string()),
        "指纹同步写两个方向流"
    );

    // 7. 后续客户端包回显携带流级指纹
    let data = build_tcp_packet(CLIENT, CPORT, SERVER, SPORT, 0x18, &[0xAA; 100]);
    let r = d.detect(&data).unwrap().expect("SSH 流回显结果");
    assert_eq!(r.ja4ssh.as_deref(), Some(expected));
}

#[test]
fn test_ja4ssh_window_rolls_and_overwrites() {
    let mut d = Detector::new();
    let syn = build_tcp_packet(CLIENT, CPORT, SERVER, SPORT, 0x02, &[]);
    d.detect(&syn).unwrap();
    let c_banner = build_tcp_packet(
        CLIENT,
        CPORT,
        SERVER,
        SPORT,
        0x18,
        b"SSH-2.0-OpenSSH_9.6\r\n",
    );
    d.detect(&c_banner).unwrap();
    // 服务端横幅：服务端方向流自此定型 SSH（否则服务端流要等 guess
    // giveup 才定型，前 ~20 包不计入窗口）
    let s_banner = build_tcp_packet(
        SERVER,
        SPORT,
        CLIENT,
        CPORT,
        0x18,
        b"SSH-2.0-OpenSSH_9.2\r\n",
    );
    d.detect(&s_banner).unwrap();

    // 第一窗口：100+100 载荷包（长度 100/200）
    for _ in 0..100 {
        d.detect(&build_tcp_packet(
            CLIENT,
            CPORT,
            SERVER,
            SPORT,
            0x18,
            &[0xAA; 100],
        ))
        .unwrap();
        d.detect(&build_tcp_packet(
            SERVER,
            SPORT,
            CLIENT,
            CPORT,
            0x18,
            &[0xBB; 200],
        ))
        .unwrap();
    }
    assert_eq!(
        ja4ssh_by_src_port(&d, CPORT),
        Some("c100s200_c100s100_c0s0".to_string())
    );

    // 第二窗口：计数已清零，新长度 300/400 再满 200 → 覆盖为最新窗口指纹
    for _ in 0..100 {
        d.detect(&build_tcp_packet(
            CLIENT,
            CPORT,
            SERVER,
            SPORT,
            0x18,
            &vec![0xAA; 300],
        ))
        .unwrap();
        d.detect(&build_tcp_packet(
            SERVER,
            SPORT,
            CLIENT,
            CPORT,
            0x18,
            &vec![0xBB; 400],
        ))
        .unwrap();
    }
    assert_eq!(
        ja4ssh_by_src_port(&d, CPORT),
        Some("c300s400_c100s100_c0s0".to_string()),
        "滚动窗口产出最新指纹并覆盖"
    );
}

#[test]
fn test_ja4ssh_not_counted_for_non_ssh_flow() {
    let mut d = Detector::new();
    let syn = build_tcp_packet(CLIENT, CPORT, SERVER, 80, 0x02, &[]);
    d.detect(&syn).unwrap();
    // HTTP 流（非 SSH）：205 个载荷包也不产出
    for _ in 0..205 {
        d.detect(&build_tcp_packet(
            CLIENT,
            CPORT,
            SERVER,
            80,
            0x18,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ))
        .unwrap();
    }
    assert!(ja4ssh_by_src_port(&d, CPORT).is_none(), "非 SSH 流不产出");
}

#[test]
fn test_ja4ssh_mid_stream_skipped() {
    let mut d = Detector::new();
    // 无 SYN（mid-stream 抓包）：横幅直接开始
    let c_banner = build_tcp_packet(
        CLIENT,
        CPORT,
        SERVER,
        SPORT,
        0x18,
        b"SSH-2.0-OpenSSH_9.6\r\n",
    );
    d.detect(&c_banner).unwrap();
    // 205 个载荷包：zeek 仅跟踪自 SYN 起的连接，此处同样不产出
    for _ in 0..205 {
        d.detect(&build_tcp_packet(
            CLIENT,
            CPORT,
            SERVER,
            SPORT,
            0x18,
            &[0xAA; 100],
        ))
        .unwrap();
        d.detect(&build_tcp_packet(
            SERVER,
            SPORT,
            CLIENT,
            CPORT,
            0x18,
            &[0xBB; 200],
        ))
        .unwrap();
    }
    assert!(
        ja4ssh_by_src_port(&d, CPORT).is_none(),
        "mid-stream 会话不追踪"
    );
}

#[test]
fn test_ja4ssh_bare_syn_fin_not_counted() {
    let mut d = Detector::new();
    let syn = build_tcp_packet(CLIENT, CPORT, SERVER, SPORT, 0x02, &[]);
    d.detect(&syn).unwrap();
    let c_banner = build_tcp_packet(
        CLIENT,
        CPORT,
        SERVER,
        SPORT,
        0x18,
        b"SSH-2.0-OpenSSH_9.6\r\n",
    );
    d.detect(&c_banner).unwrap();
    let s_banner = build_tcp_packet(
        SERVER,
        SPORT,
        CLIENT,
        CPORT,
        0x18,
        b"SSH-2.0-OpenSSH_9.2\r\n",
    );
    d.detect(&s_banner).unwrap();

    // 裸 FIN（0x11）与裸 SYN 重传（0x02）既非载荷也非纯 ACK，不计数
    d.detect(&build_tcp_packet(CLIENT, CPORT, SERVER, SPORT, 0x11, &[]))
        .unwrap();
    d.detect(&build_tcp_packet(CLIENT, CPORT, SERVER, SPORT, 0x02, &[]))
        .unwrap();

    // 若被误计为载荷则窗口不会在第 200 包完成——此处双向各 100 载荷包，
    // 加上被误计的 2 个会提前/错位；用精确计数验证窗口恰好在第 200 载荷包完成
    for _ in 0..100 {
        d.detect(&build_tcp_packet(
            CLIENT,
            CPORT,
            SERVER,
            SPORT,
            0x18,
            &[0xAA; 100],
        ))
        .unwrap();
    }
    // 99 个后仍差 1（200 - 100 - 99）
    for _ in 0..99 {
        d.detect(&build_tcp_packet(
            SERVER,
            SPORT,
            CLIENT,
            CPORT,
            0x18,
            &[0xBB; 200],
        ))
        .unwrap();
    }
    assert!(ja4ssh_by_src_port(&d, CPORT).is_none(), "差 1 包不产出");
    d.detect(&build_tcp_packet(
        SERVER,
        SPORT,
        CLIENT,
        CPORT,
        0x18,
        &[0xBB; 200],
    ))
    .unwrap();
    assert_eq!(
        ja4ssh_by_src_port(&d, CPORT),
        Some("c100s200_c100s100_c0s0".to_string()),
        "裸 SYN/FIN 不占用窗口计数"
    );
}
