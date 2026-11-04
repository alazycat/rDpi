//! 关键业务规则钉住测试（legacy-takeover 第四步产出）
//!
//! 目的：把 docs/architecture/risks.md 与 docs/business/tls-sni-application.md 中
//! 「代码明确实现」的规则用可执行断言钉死。
//!
//! 分两类：
//! - B 类（不变量）：预期全绿。破坏即回归。
//! - A 类（探针）：钉住**当前实际行为**。若行为与风险清单中的"期望行为"不一致，
//!   相应断言旁注释了修复时应反转的方向（F1/F3/R4/P9）。
//!
//! 证据规则：每条测试引用源码行号；发现行为变化时先更新文档再改断言。

use rdpi::Detector;
use rdpi::core::types::*;

// ============================================================================
// 辅助：以太网帧构造（与 tests/test_guess.rs 同一模式，IP 可参数化）
// ============================================================================

fn build_tcp_packet_ip(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 14 + 20 + 20 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&((total_len - 14) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(0x40);
    pkt.push(0x06); // TCP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.push(0x50);
    pkt.push(0x00);
    pkt.extend_from_slice(&[0xff, 0xff]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

fn build_udp_packet_ip(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 14 + 20 + 8 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&((total_len - 14) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(0x40);
    pkt.push(0x11); // UDP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&((payload.len() as u16) + 8).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

/// 构造 TLS ClientHello 帧
///
/// record_version: 记录层版本字节，如 [0x03,0x03]（TLS 1.2）、[0x03,0x01]（TLS 1.0）
/// with_supported_versions: 是否带 supported_versions 扩展（0x002b → TLS 1.3）
fn build_client_hello(
    sni: Option<&str>,
    record_version: [u8; 2],
    with_supported_versions: bool,
) -> Vec<u8> {
    // --- SNI 扩展 ---
    let mut sni_ext_body: Vec<u8> = Vec::new();
    if let Some(name) = sni {
        let name_b = name.as_bytes();
        let list_len = (name_b.len() + 3) as u16;
        sni_ext_body.extend_from_slice(&list_len.to_be_bytes());
        sni_ext_body.push(0x00); // hostname type
        sni_ext_body.extend_from_slice(&(name_b.len() as u16).to_be_bytes());
        sni_ext_body.extend_from_slice(name_b);
    }
    let mut sni_ext: Vec<u8> = vec![0x00, 0x00]; // ext type SNI
    if sni.is_some() {
        sni_ext.extend_from_slice(&(sni_ext_body.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&sni_ext_body);
    }

    // --- supported_versions 扩展 ---
    let mut sv_ext: Vec<u8> = Vec::new();
    if with_supported_versions {
        sv_ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    }

    // --- extensions block ---
    let mut ext_bytes = Vec::new();
    ext_bytes.extend_from_slice(&sni_ext);
    ext_bytes.extend_from_slice(&sv_ext);
    let mut ext_block = (ext_bytes.len() as u16).to_be_bytes().to_vec();
    ext_block.extend_from_slice(&ext_bytes);

    // --- handshake body ---
    let mut hs = Vec::new();
    hs.extend_from_slice(&[0x03, 0x03]); // client version (legacy TLS 1.2)
    hs.extend_from_slice(&[0u8; 32]); // random
    hs.push(0x00); // session id len = 0
    hs.extend_from_slice(&[0x00, 0x02]); // cipher suites len
    hs.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    hs.push(0x01); // compression len
    hs.push(0x00);
    hs.extend_from_slice(&ext_block);

    // --- record ---
    let mut payload = vec![0x16];
    payload.extend_from_slice(&record_version);
    let record_len = (4 + hs.len()) as u16;
    payload.extend_from_slice(&record_len.to_be_bytes());
    payload.push(0x01); // handshake type ClientHello
    payload.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
    payload.extend_from_slice(&hs);
    payload
}

/// 构造合法 DNS 查询 payload（example.com A 记录）
fn build_dns_query_payload() -> Vec<u8> {
    let mut p = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    p.extend_from_slice(b"\x07example\x03com\x00");
    p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    p
}

/// 构造 TLS Certificate 记录 payload（证书体为占位假 DER）
fn build_certificate_record_payload() -> Vec<u8> {
    let mut p = vec![0x16, 0x03, 0x03, 0x00, 0x0c]; // record header, len=12
    p.extend_from_slice(&[0x0b, 0x00, 0x00, 0x08]); // handshake Certificate, len=8
    p.extend_from_slice(&[0x00, 0x00, 0x05]); // cert list len = 5
    p.extend_from_slice(&[0x00, 0x00, 0x02]); // cert len = 2
    p.extend_from_slice(&[0x30, 0x82]); // 假 DER 开头
    p
}

/// 构造可被 parse_certificate 真实解析的 TLS Certificate 记录
/// （仿 src/protocols/tls/certificate.rs 测试构造器：极简 X.509-like DER，UTF8String CN）
fn build_tls_certificate_record(subject_cn: &str) -> Vec<u8> {
    fn append_dn(data: &mut Vec<u8>, cn: &str) {
        let mut attr = vec![0x06, 0x03, 0x55, 0x04, 0x03]; // OID commonName
        attr.push(0x0c); // UTF8String
        attr.push(cn.len() as u8);
        attr.extend_from_slice(cn.as_bytes());
        let mut set = vec![0x30, attr.len() as u8];
        set.extend_from_slice(&attr);
        let mut dn = vec![0x31, set.len() as u8];
        dn.extend_from_slice(&set);
        data.push(0x30);
        data.push(dn.len() as u8);
        data.extend_from_slice(&dn);
    }

    let mut inner = Vec::new();
    inner.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]); // version [0] v3
    inner.extend_from_slice(&[0x02, 0x01, 0x01]); // serialNumber 1
    inner.extend_from_slice(&[
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    ]); // signature SEQ
    append_dn(&mut inner, "Test CA"); // issuer
    inner.extend_from_slice(&[
        0x30, 0x1e, 0x17, 0x0d, b'2', b'4', b'0', b'3', b'0', b'9', b'1', b'2', b'0', b'0', b'0',
        b'0', b'Z', 0x17, 0x0d, b'2', b'5', b'0', b'3', b'0', b'9', b'1', b'2', b'0', b'0', b'0',
        b'0', b'Z',
    ]); // validity UTCTime ×2
    append_dn(&mut inner, subject_cn); // subject

    let mut tbs = vec![0x30, 0x00];
    tbs.extend_from_slice(&inner);
    tbs[1] = (tbs.len() - 2) as u8;

    let mut cert = vec![0x30, 0x00];
    cert.extend_from_slice(&tbs);
    cert[1] = (cert.len() - 2) as u8;

    let mut msg = vec![0x16, 0x03, 0x03]; // record header
    msg.extend_from_slice(&((cert.len() as u16) + 10).to_be_bytes());
    msg.push(0x0b); // handshake Certificate
    msg.extend_from_slice(&[0x00, 0x00, (cert.len() + 3) as u8]);
    msg.extend_from_slice(&[0x00, 0x00, cert.len() as u8]); // list len
    msg.extend_from_slice(&[0x00, 0x00, cert.len() as u8]); // cert len
    msg.extend_from_slice(&cert);
    msg
}

const NOISE: &[u8] = &[0x00u8; 8]; // 无协议特征 payload

// ============================================================================
// B 类：关键不变量（预期全绿）
// ============================================================================

/// B1: DNS 查询 → Protocol::Dns + Confidence::Dpi + 域名提取
/// 证据：protocols/mod.rs:235-236（DNS 注册）；dns detector payload 驱动
#[test]
fn b1_dns_query_detected_with_domain() {
    let mut d = Detector::new();
    let pkt = build_udp_packet_ip(
        [10, 0, 0, 1],
        [8, 8, 8, 8],
        5353,
        53,
        &build_dns_query_payload(),
    );
    let r = d.detect(&pkt).unwrap().expect("DNS query must be detected");
    assert_eq!(r.protocol, Protocol::Dns);
    assert_eq!(r.confidence, Confidence::Dpi);
    match r.metadata {
        Metadata::Dns(m) => assert_eq!(m.query_domain.as_deref(), Some("example.com")),
        other => panic!("expected DNS metadata, got {:?}", other),
    }
}

/// B2: HTTP GET → Protocol::Http + Dpi + Host 提取
/// 证据：protocols/mod.rs:233-234（HTTP 注册，位于 TLS/DNS 之后）
#[test]
fn b2_http_get_detected_with_host() {
    let mut d = Detector::new();
    let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let pkt = build_tcp_packet_ip([10, 0, 0, 1], [93, 184, 216, 34], 12345, 80, payload);
    let r = d.detect(&pkt).unwrap().expect("HTTP GET must be detected");
    assert_eq!(r.protocol, Protocol::Http);
    assert_eq!(r.confidence, Confidence::Dpi);
    match r.metadata {
        Metadata::Http(m) => assert_eq!(m.host.as_deref(), Some("example.com")),
        other => panic!("expected HTTP metadata, got {:?}", other),
    }
}

/// B3: TLS ClientHello → Tls + Dpi + SNI + 应用识别 + JA4
/// 证据：tls/mod.rs:52-62；application/mod.rs:18-21；trie.rs:28-31
#[test]
fn b3_tls_sni_application_ja4() {
    let mut d = Detector::new();
    let payload = build_client_hello(Some("www.youtube.com"), [0x03, 0x03], false);
    let pkt = build_tcp_packet_ip([10, 0, 0, 1], [93, 184, 216, 34], 12345, 443, &payload);
    let r = d
        .detect(&pkt)
        .unwrap()
        .expect("ClientHello must be detected");
    assert_eq!(r.protocol, Protocol::Tls);
    assert_eq!(r.confidence, Confidence::Dpi);
    match r.metadata {
        Metadata::Tls(m) => {
            assert_eq!(m.sni.as_deref(), Some("www.youtube.com"));
            assert_eq!(m.application, Some(Application::YouTube));
            assert!(m.ja4.is_some(), "JA4 must be computed when version present");
        }
        other => panic!("expected TLS metadata, got {:?}", other),
    }
}

/// B4 (ADR-0004): 流协议一次定型；回显包携带已有元数据（F7 已修复，2026-11-04）
/// 修复前：lib.rs 回显分支不带 metadata，无条件写回把 flow.metadata 抹成 Some(Metadata::None)，
///         risk 处理器从第二包起失效。
/// 修复后：回显结果携带 flow.metadata，长流元数据持久，risk 逐包生效（见 a6）。
#[test]
fn b4_protocol_locked_and_metadata_overwritten() {
    let mut d = Detector::new();
    let http = build_tcp_packet_ip(
        [10, 0, 0, 1],
        [93, 184, 216, 34],
        12345,
        80,
        b"GET / HTTP/1.1\r\nHost: first.com\r\n\r\n",
    );
    let r1 = d.detect(&http).unwrap().expect("first packet HTTP");
    assert_eq!(r1.protocol, Protocol::Http);
    assert!(
        matches!(r1.metadata, Metadata::Http(_)),
        "first packet carries metadata"
    );

    let tls_like = build_tcp_packet_ip(
        [10, 0, 0, 1],
        [93, 184, 216, 34],
        12345,
        80,
        &build_client_hello(Some("second.com"), [0x03, 0x03], false),
    );
    let r2 = d.detect(&tls_like).unwrap().expect("echo result");
    assert_eq!(
        r2.protocol,
        Protocol::Http,
        "protocol must stay locked to HTTP"
    );
    assert!(
        matches!(&r2.metadata, Metadata::Http(m) if m.host.as_deref() == Some("first.com")),
        "F7 fixed: echo carries preserved metadata (not re-detected, so still first.com)"
    );

    let flow = d.flows().next().unwrap().1;
    assert!(
        matches!(&flow.metadata, Some(Metadata::Http(m)) if m.host.as_deref() == Some("first.com")),
        "F7 fixed: flow.metadata persists across packets"
    );
}

/// B5 (Giveup-TCP): 前 19 包纯 DPI，第 20 包触发端口猜测
/// 证据：lib.rs:80（DEFAULT_TCP_GIVEUP=20）、lib.rs:243(+1)、lib.rs:275（< 阈值走 DPI）
#[test]
fn b5_tcp_giveup_boundary() {
    let mut d = Detector::new();
    for _ in 0..19 {
        let pkt = build_tcp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 55555, 22, NOISE);
        assert!(
            d.detect(&pkt).unwrap().is_none(),
            "packet <20 must stay undetected (DPI phase)"
        );
    }
    let pkt = build_tcp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 55555, 22, NOISE);
    let r = d
        .detect(&pkt)
        .unwrap()
        .expect("packet 20 must trigger port guess");
    assert_eq!(r.protocol, Protocol::Ssh, "port 22 → SSH by port map");
    assert_eq!(r.confidence, Confidence::MatchByPort);
}

/// B6 (Giveup-UDP): UDP 阈值 5——第 4 包 None，第 5 包端口猜测
/// 证据：lib.rs:81（DEFAULT_UDP_GIVEUP=5）
#[test]
fn b6_udp_giveup_boundary() {
    let mut d = Detector::new();
    for _ in 0..4 {
        let pkt = build_udp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 55555, 53, NOISE);
        assert!(
            d.detect(&pkt).unwrap().is_none(),
            "packet <5 must stay undetected"
        );
    }
    let pkt = build_udp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 55555, 53, NOISE);
    let r = d
        .detect(&pkt)
        .unwrap()
        .expect("packet 5 must trigger port guess");
    assert_eq!(r.protocol, Protocol::Dns);
    assert_eq!(r.confidence, Confidence::MatchByPort);
}

/// B7 (label 边界): 反向 Trie 大小写敏感——大写 SNI 不命中（现状）
/// 证据：trie.rs:28-31（rev 后逐字符匹配，无归一化）；application/mod.rs:18-21
#[test]
fn b7_trie_is_case_sensitive() {
    assert_eq!(
        rdpi::application::identify("www.youtube.com"),
        Some(Application::YouTube)
    );
    assert_eq!(
        rdpi::application::identify("WWW.YOUTUBE.COM"),
        None,
        "current impl is case-sensitive"
    );
    assert_eq!(
        rdpi::application::identify("notyoutube.com"),
        None,
        "label boundary must block prefix tricks"
    );
}

// ============================================================================
// A 类：探针（钉住当前实际行为；修复对应风险时须反转断言并更新文档）
// ============================================================================

/// A1 (P7/F1): 真实格式 TLS 1.0 ClientHello 的 version 字符串带 "TLS " 前缀
/// 现状断言：version == "TLS 1.0"（tls/parser.rs:327-330）。
/// F1：risk/processors/tls.rs:72 比较 "1.0"（无前缀）→ ObsoleteVersion 永不触发（见 a1_risk）。
#[test]
fn a1_tls10_version_string_format() {
    let mut d = Detector::new();
    let payload = build_client_hello(Some("legacy.example.com"), [0x03, 0x01], false);
    let pkt = build_tcp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 54321, 443, &payload);
    let r = d
        .detect(&pkt)
        .unwrap()
        .expect("TLS 1.0 ClientHello must be detected");
    match r.metadata {
        Metadata::Tls(m) => {
            assert_eq!(
                m.version.as_deref(),
                Some("TLS 1.0"),
                "parser emits 'TLS 1.0' (F1 evidence)"
            );
        }
        other => panic!("expected TLS metadata, got {:?}", other),
    }
}

/// A1-risk (P7/F1): TlsObsoleteVersion 对真实 "TLS 1.0" 流量触发（F1 已修复，钉住正确行为）
/// 修复：risk/processors/tls.rs:73 现在匹配解析器真实产出格式 "TLS 1.0"/"TLS 1.1"。
/// 若版本字符串格式再变，此断言失败即是集成断裂的警报。
#[cfg(feature = "risk")]
#[test]
fn a1_risk_obsolete_version_fires_on_tls10() {
    use rdpi::risk::types::RiskFlag;
    let mut d = Detector::new();
    let payload = build_client_hello(Some("legacy.example.com"), [0x03, 0x01], false);
    let pkt = build_tcp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 54321, 443, &payload);
    d.detect(&pkt).unwrap().expect("detected");
    let flow = d.flows().next().expect("flow exists");
    let has_obsolete = flow
        .1
        .risks
        .iter()
        .any(|r| r.flag == RiskFlag::TlsObsoleteVersion);
    assert!(
        has_obsolete,
        "TLS 1.0 ClientHello must be flagged as obsolete (F1 fixed)"
    );
}

/// A2 (P6/F3): 证书帧在流识别后到达（同方向同流）→ 协议保持 TLS；F3 修复后（2026-11-04）
/// 证书字段在回显路径一次性富化（lib.rs enrich_tls_cert），SNI 等既有元数据保持。
/// 证据：lib.rs:327-331 回显分支调用 enrich_tls_cert；字段填充后不再重复解析。
/// 注意：FlowKey 含方向——对向包（sport/dst_port 互换）会创建新流，本测试特意用同方向。
#[test]
fn a2_certificate_in_later_packet_is_ignored() {
    let mut d = Detector::new();
    let ch = build_tcp_packet_ip(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        54321,
        443,
        &build_client_hello(Some("api.example.com"), [0x03, 0x03], false),
    );
    let r1 = d.detect(&ch).unwrap().expect("ClientHello detected");
    assert_eq!(r1.protocol, Protocol::Tls);
    assert!(
        matches!(&r1.metadata, Metadata::Tls(m) if m.cert_subject.is_none()),
        "ClientHello packet carries no cert yet"
    );

    // 同方向同流：证书帧从客户端侧继续发出（模拟同向 TCP 段）
    let cert = build_tcp_packet_ip(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        54321,
        443,
        &build_tls_certificate_record("api.example.com"),
    );
    let r2 = d.detect(&cert).unwrap().expect("echo result");
    assert_eq!(
        r2.protocol,
        Protocol::Tls,
        "flow stays TLS (same-direction packet)"
    );
    // F3 修复：证书字段富化 + SNI 等既有元数据保持
    assert!(
        matches!(&r2.metadata, Metadata::Tls(m)
            if m.sni.as_deref() == Some("api.example.com")
                && m.cert_subject.as_deref() == Some("api.example.com")),
        "F3 fixed: echo enriches cert fields while preserving SNI"
    );
    let flow = d.flows().next().unwrap().1;
    assert!(
        matches!(&flow.metadata, Some(Metadata::Tls(m)) if m.cert_subject.is_some()),
        "F3 fixed: flow.metadata carries certificate"
    );
}

/// A3 (P8): 连体 ClientHello+Certificate 单包 → SNI 可解析，证书仍不可解析（现状）
/// 证据：certificate.rs:26-27 is_certificate_message 检查 data[5]，连体时该字节是 ClientHello(0x01)。
#[test]
fn a3_combined_clienthello_certificate_cert_not_parsed() {
    let mut d = Detector::new();
    let mut payload = build_client_hello(Some("combined.example.com"), [0x03, 0x03], false);
    payload.extend_from_slice(&build_certificate_record_payload());
    let pkt = build_tcp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 54321, 443, &payload);
    let r = d
        .detect(&pkt)
        .unwrap()
        .expect("combined payload detected as TLS");
    match r.metadata {
        Metadata::Tls(m) => {
            assert_eq!(m.sni.as_deref(), Some("combined.example.com"));
            assert!(
                m.cert_subject.is_none(),
                "P8: cert in same packet after ClientHello is not parsed"
            );
        }
        other => panic!("expected TLS metadata, got {:?}", other),
    }
}

/// A4 (R4)：猜测引擎 IP 匹配支持双向（已修复，2026-11-04）
/// 构造：src=8.8.8.8（IP 表 → Dns，core/guess/ip.rs:93），dst=10.0.0.1，dst_port=9999（端口表无此项）。
/// 服务端在 src 方向（server→client 包），lib.rs:293-296 将两方向 IP 均交给猜测引擎，
/// guess/mod.rs match_ip 先试 dst 再试 src → 命中 Dns(MatchByIp)。
#[test]
fn a4_guess_ip_match_uses_src_ip() {
    let mut d = Detector::new();
    for _ in 0..19 {
        let pkt = build_tcp_packet_ip([8, 8, 8, 8], [10, 0, 0, 1], 40000, 9999, NOISE);
        assert!(d.detect(&pkt).unwrap().is_none());
    }
    let pkt = build_tcp_packet_ip([8, 8, 8, 8], [10, 0, 0, 1], 40000, 9999, NOISE);
    let r = d.detect(&pkt).unwrap().expect("packet 20 triggers guess");
    assert_eq!(
        r.protocol,
        Protocol::Dns,
        "R4: server IP 8.8.8.8 on src side must match"
    );
    assert_eq!(r.confidence, Confidence::MatchByIp);
}

/// A4b (R4)：反向包（client→server，dst=8.8.8.8）修复后回归钉住
/// 构造：src=10.0.0.1:40000 → dst=8.8.8.8:9999。修复前 lib.rs:291 只取 src_ip=10.0.0.1
/// → 漏判；修复后 guess/mod.rs match_ip 两方向尝试 → 命中 Dns(MatchByIp)。
#[test]
fn a4b_guess_ip_reverse_direction_matches_known_server() {
    let mut d = Detector::new();
    for _ in 0..19 {
        let pkt = build_tcp_packet_ip([10, 0, 0, 1], [8, 8, 8, 8], 40000, 9999, NOISE);
        assert!(d.detect(&pkt).unwrap().is_none());
    }
    let pkt = build_tcp_packet_ip([10, 0, 0, 1], [8, 8, 8, 8], 40000, 9999, NOISE);
    let r = d.detect(&pkt).unwrap().expect("packet 20 triggers guess");
    assert_eq!(
        r.protocol,
        Protocol::Dns,
        "R4: server IP 8.8.8.8 on dst side must match"
    );
    assert_eq!(r.confidence, Confidence::MatchByIp);
}

/// A5 (P10): version 不可得（record 版本 0x0300 且无 supported_versions）→ version 与 JA4 均为 None
/// 证据：tls/mod.rs:59-62（ja4 = info.version.map(...)）；parser.rs:93（supported_version 优先，回退 record）；parser.rs:325-333（0x0300 → None）
#[test]
fn a5_no_version_means_no_ja4() {
    let mut d = Detector::new();
    let payload = build_client_hello(Some("nover.example.com"), [0x03, 0x00], false);
    let pkt = build_tcp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 54321, 443, &payload);
    let r = d
        .detect(&pkt)
        .unwrap()
        .expect("SNI still present → detected");
    match r.metadata {
        Metadata::Tls(m) => {
            assert_eq!(m.version, None);
            assert_eq!(m.ja4, None, "JA4 must be None when version unknown");
        }
        other => panic!("expected TLS metadata, got {:?}", other),
    }
}

/// A6 (P9/F7/risk): 风险结果累计行为（现状钉住）
/// F7 已修复（2026-11-04）：回显包携带 flow.metadata（lib.rs:316-328），
/// 元数据不再被抹，risk 处理器逐包生效 → missing_sni == 3（P9 原断言恢复）。
#[cfg(feature = "risk")]
#[test]
fn a6_risks_accumulate_per_packet() {
    use rdpi::risk::types::RiskFlag;
    let mut d = Detector::new();
    // 无 SNI 的 ClientHello × 3 包（同一流）
    let payload = build_client_hello(None, [0x03, 0x03], false);
    for _ in 0..3 {
        let pkt = build_tcp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 54321, 443, &payload);
        let r = d.detect(&pkt).unwrap().expect("TLS detected/echoed");
        assert_eq!(r.protocol, Protocol::Tls);
    }
    let flow = d.flows().next().unwrap().1;
    let missing_sni = flow
        .risks
        .iter()
        .filter(|r| r.flag == RiskFlag::TlsMissingSni)
        .count();
    assert_eq!(
        missing_sni, 3,
        "F7 fixed: metadata persists, risk processors run per packet (1→3)"
    );
}

/// R5（risk）：expire_flows 的 analyze 窗口与 FlowTable 真实超时一致（已修复，2026-11-04）
/// 修复前 lib.rs:370-373 硬编码 120s——with_config 自定义 timeout < 120s 时流被清前
/// analyze_flow 不跑、> 120s 时重复分析。修复后取 flow_table.timeout()（flow.rs:176）。
/// 本测试钉住：timeout=1s 的自定义配置下，静默 1.2s 后 expire_flows 过期该流。
#[cfg(feature = "risk")]
#[test]
fn r5_expire_window_uses_configured_timeout() {
    let mut d = Detector::with_config(100, 1); // timeout = 1s（≠ 硬编码 120s）
    let pkt = build_tcp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 54321, 443, NOISE);
    d.detect(&pkt).unwrap();
    assert_eq!(d.flow_count(), 1);

    std::thread::sleep(std::time::Duration::from_millis(1200));
    let expired = d.expire_flows();
    assert_eq!(
        expired.len(),
        1,
        "R5: flow must expire per configured 1s timeout (not hardcoded 120s)"
    );
    assert_eq!(d.flow_count(), 0);
}

/// 风险出口（drain_risks，2026-11-04 新增）：flow.risks 逐包累积可被收割并清空。
/// 此前 flow.risks 只能经 flows() 间接读取且无界增长（a6）；drain 后清空。
#[cfg(feature = "risk")]
#[test]
fn risk_exit_drain_collects_and_clears_flow_risks() {
    use rdpi::risk::types::RiskFlag;
    let mut d = Detector::new();
    let payload = build_client_hello(None, [0x03, 0x03], false);
    for _ in 0..2 {
        let pkt = build_tcp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 54321, 443, &payload);
        d.detect(&pkt).unwrap();
    }
    let drained = d.drain_risks();
    assert_eq!(drained.len(), 2, "two packets → two accumulated risks");
    assert_eq!(
        drained[0].0, drained[1].0,
        "both risks keyed by the same flow"
    );
    assert!(drained[0].1.flag == RiskFlag::TlsMissingSni);

    // 收割后清空：流仍在，但 flow.risks 已空；二次 drain 无残留
    assert_eq!(d.flow_count(), 1);
    let flow = d.flows().next().unwrap().1;
    assert!(flow.risks.is_empty(), "drain must clear flow.risks");
    assert!(
        d.drain_risks().is_empty(),
        "second drain returns nothing new"
    );
}

/// 风险出口（drain_risks）：过期流 analyze_flow 结果不再被丢弃。
/// 修复前：① register 只注册 packet 侧（risk/mod.rs），flow_processors 恒空；
/// ② lib.rs `let _risks = ...` 丢弃 → 流级风险（ProbingAttempt 等）永不产出。
#[cfg(feature = "risk")]
#[test]
fn risk_exit_expired_flow_level_risks_reachable() {
    use rdpi::risk::types::RiskFlag;
    let mut d = Detector::with_config(100, 1); // 1s 过期
    // 单个 UDP 包打到未知端口：无协议识别、无响应 → 探测特征
    // payload 用不可打印字节——短可打印文本（如 b"xy"）会被 whois 等认领，
    // 协议非 None 后 behavioral 不产出探测风险
    let pkt = build_udp_packet_ip([10, 0, 0, 9], [10, 0, 0, 3], 54321, 9999, &[0xAA; 4]);
    d.detect(&pkt).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1200));
    let expired = d.expire_flows();
    assert_eq!(expired.len(), 1);

    let drained = d.drain_risks();
    assert!(
        drained
            .iter()
            .any(|(k, r)| *k == expired[0] && r.flag == RiskFlag::ProbingAttempt),
        "expire-time analyze_flow results must surface via drain_risks"
    );
    assert!(d.drain_risks().is_empty(), "no duplicate after drain");
}

/// 风险出口（set_risk_callback，观察者模式）：逐包风险产生即推送。
#[cfg(feature = "risk")]
#[test]
fn risk_exit_callback_pushes_packet_risks() {
    use rdpi::risk::types::RiskFlag;
    use std::sync::{Arc, Mutex};
    let mut d = Detector::new();
    let events: Arc<Mutex<Vec<(rdpi::core::types::FlowKey, RiskFlag)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    d.set_risk_callback(move |k, r| sink.lock().unwrap().push((k, r.flag)));

    let payload = build_client_hello(None, [0x03, 0x03], false);
    for _ in 0..2 {
        let pkt = build_tcp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 54321, 443, &payload);
        d.detect(&pkt).unwrap();
    }
    let got = events.lock().unwrap();
    assert_eq!(got.len(), 2, "each packet's risk pushed immediately");
    assert!(got.iter().all(|(_, f)| *f == RiskFlag::TlsMissingSni));
    assert_eq!(got[0].0, got[1].0, "same flow key for both events");
}

/// 风险出口（set_risk_callback）：流级风险（过期时 analyze_flow）推送。
/// 回调是观察者——drain_risks 拉取路径不受影响，两通道收到同一事件。
#[cfg(feature = "risk")]
#[test]
fn risk_exit_callback_pushes_flow_level_risks() {
    use rdpi::risk::types::RiskFlag;
    use std::sync::{Arc, Mutex};
    let mut d = Detector::with_config(100, 1);
    let events: Arc<Mutex<Vec<(rdpi::core::types::FlowKey, RiskFlag)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    d.set_risk_callback(move |k, r| sink.lock().unwrap().push((k, r.flag)));

    let pkt = build_udp_packet_ip([10, 0, 0, 9], [10, 0, 0, 3], 54321, 9999, &[0xAA; 4]);
    d.detect(&pkt).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1200));
    let expired = d.expire_flows();
    assert_eq!(expired.len(), 1);

    let got = events.lock().unwrap();
    // 单包未识别流同时命中两条流级风险（behavioral.rs：packets<=3 单向 + packets<=2 探测）
    assert_eq!(
        got.len(),
        2,
        "UnidirectionalTraffic + ProbingAttempt pushed at expire"
    );
    assert!(
        got.iter().all(|(k, _)| *k == expired[0]),
        "all keyed by expired flow"
    );
    assert!(got.iter().any(|(_, f)| *f == RiskFlag::ProbingAttempt));
    assert!(
        got.iter()
            .any(|(_, f)| *f == RiskFlag::UnidirectionalTraffic)
    );

    // 观察者不影响拉取路径：drain_risks 仍返回该事件
    assert!(
        d.drain_risks()
            .iter()
            .any(|(_, r)| r.flag == RiskFlag::ProbingAttempt)
    );
}

/// 补充 (F6) — 已修复（2026-11-04）：纯 Certificate 记录的单包流不再被误报为 Dns。
/// 修复：dns/detector.rs 增加问题区可行性校验（每条 question ≥5 字节）+ qname
/// 非空可打印校验——假 Certificate 帧的 TLS 长度字段被误读为 qdcount=3083 → 拒绝。
#[test]
fn a7_pure_certificate_record_misdetected_as_dns() {
    let mut d = Detector::new();
    let pkt = build_tcp_packet_ip(
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        443,
        54321,
        &build_certificate_record_payload(),
    );
    let r = d.detect(&pkt).unwrap();
    assert!(
        r.is_none(),
        "F6 fixed: non-DNS binary payload must not be detected as DNS"
    );
}

/// A8 (F9/vpn) — 已修复（2026-11-04）：HTTP 文本不再被 OpenVpn 误报。
/// 修复：openvpn/parser.rs 对可打印 ASCII 占比 ≥ 90% 的 payload 直接拒绝
/// （真实控制消息 bytes 1-8 为随机 session_id，可打印占比极低）。
/// 注册顺序未动（openvpn mod.rs:232 仍早于 http mod.rs:234，R11）。
#[cfg(feature = "vpn")]
#[test]
fn a8_http_text_not_misdetected_as_openvpn() {
    let mut d = Detector::new();
    let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let pkt = build_tcp_packet_ip([10, 0, 0, 1], [93, 184, 216, 34], 12345, 80, payload);
    let r = d.detect(&pkt).unwrap().expect("HTTP GET must be detected");
    assert_eq!(
        r.protocol,
        Protocol::Http,
        "F9 fixed: HTTP text must be Http, not OpenVpn"
    );
    assert_ne!(r.protocol, Protocol::OpenVpn);
}

/// P3 (R6)：sni_contains 规则首包命中（已修复，2026-11-04）
/// 修复前：规则分支仅在 flow.protocol.is_none() 时进入（lib.rs:255-276），此时
/// flow.metadata 必为 None → RuleContext.sni 恒 None → sni_contains 规则永不命中。
/// 修复后：SNI 回退从当前包 payload 提取（protocols::tls::extract_sni，rule+tls
/// feature 同时启用；lib.rs:266-267）→ 规则先于 DPI 命中（CustomRule）。
#[cfg(feature = "rule")]
#[test]
fn p3_sni_rule_never_fires_on_first_packet() {
    use rdpi::rule::{Rule, RuleCondition};
    let mut d = Detector::with_rules(vec![Rule {
        id: "flag-evil".into(),
        protocol: Protocol::Http, // 标志性协议：区分规则命中 vs DPI 命中
        condition: RuleCondition {
            sni_contains: Some("evil.example.com".into()),
            ..Default::default()
        },
        metadata: None,
    }]);
    let payload = build_client_hello(Some("evil.example.com"), [0x03, 0x03], false);
    let pkt = build_tcp_packet_ip([10, 0, 0, 1], [10, 0, 0, 2], 54321, 443, &payload);
    let r = d
        .detect(&pkt)
        .unwrap()
        .expect("packet must produce a result");
    assert_eq!(
        r.protocol,
        Protocol::Http,
        "R6 fixed: sni_contains rule must fire on first packet (rule > DPI)"
    );
    assert_eq!(r.confidence, Confidence::CustomRule);
}
