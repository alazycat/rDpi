//! DTLS 识别 + d 前缀 JA4/JA4S 测试（F38，2026-11-06）
//!
//! 权威规格：FoxIO technical_details/JA4.md（proto 首字符 d、DTLS 版本映射
//! d1/d2/d3）；JA4S 哈希段输入与 TCP/QUIC 同源（golden 已交叉验证）。

#![cfg(feature = "dtls")]

use rdpi::core::types::{Application, Metadata, Protocol};
use rdpi::protocols::ProtocolDetector;
use rdpi::protocols::dtls::DtlsDetector;

/// 构造 DTLS 握手记录（单片段、epoch 0）
fn dtls_handshake(record_version: u16, msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x16); // handshake content_type
    out.extend_from_slice(&record_version.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00]); // epoch
    out.extend_from_slice(&[0x00; 6]); // sequence_number
    let rec_len = 12 + body.len();
    out.extend_from_slice(&(rec_len as u16).to_be_bytes());
    out.push(msg_type);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // length
    out.extend_from_slice(&[0x00, 0x00]); // message_seq
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_offset
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // fragment_length
    out.extend_from_slice(body);
    out
}

/// 单个扩展编码
fn ext(ext_type: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// SNI 扩展值
fn sni_ext_value(sni: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes()); // list length
    v.push(0x00); // hostname type
    v.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    v.extend_from_slice(sni.as_bytes());
    v
}

/// ALPN 扩展值（单协议）
fn alpn_ext_value(alpn: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&((alpn.len() + 1) as u16).to_be_bytes()); // list length
    v.push(alpn.len() as u8);
    v.extend_from_slice(alpn.as_bytes());
    v
}

/// 构造 ClientHello 消息体
///
/// `cookie`：None = DTLS 1.3 布局（无 cookie 字段）；Some(None) = DTLS 1.2
/// 空 cookie；Some(Some(bytes)) = DTLS 1.2 带 cookie（HVR 往返后的重传 CH）。
/// `supported_version`：Some(v) 时带 supported_versions 扩展。
fn client_hello_body(
    client_version: u16,
    sni: &str,
    supported_version: Option<u16>,
    cookie: Option<Option<&[u8]>>,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&client_version.to_be_bytes());
    b.extend_from_slice(&[0x42; 32]); // random
    b.push(0x00); // session_id 空
    if let Some(c) = cookie {
        match c {
            Some(data) => {
                b.push(data.len() as u8);
                b.extend_from_slice(data);
            }
            None => b.push(0x00),
        }
    }
    // cipher_suites：2 个
    b.extend_from_slice(&4u16.to_be_bytes());
    b.extend_from_slice(&0x1302u16.to_be_bytes());
    b.extend_from_slice(&0x1301u16.to_be_bytes());
    // compression：null
    b.push(0x01);
    b.push(0x00);
    // extensions（先建列表再写总长）
    let mut exts = Vec::new();
    exts.extend_from_slice(&ext(0x0000, &sni_ext_value(sni)));
    if let Some(v) = supported_version {
        // ClientHello 中 supported_versions 为 1B 列表长 + 2B×N
        let mut sv = vec![0x02];
        sv.extend_from_slice(&v.to_be_bytes());
        exts.extend_from_slice(&ext(0x002b, &sv));
    }
    b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    b.extend_from_slice(&exts);
    b
}

/// 构造 ServerHello 消息体（扩展顺序 [0x002b, 0x0010] 对齐 JA4S golden 输入）
fn server_hello_body(
    legacy_version: u16,
    supported_version: Option<u16>,
    alpn: Option<&str>,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&legacy_version.to_be_bytes());
    b.extend_from_slice(&[0x99; 32]); // random
    b.push(0x00); // legacy_session_id_echo 空
    b.extend_from_slice(&0x1302u16.to_be_bytes()); // 选定 cipher
    b.push(0x01);
    b.push(0x00); // compression
    let mut exts = Vec::new();
    if let Some(v) = supported_version {
        // ServerHello 中 supported_versions 为单个 2B 版本值
        exts.extend_from_slice(&ext(0x002b, &v.to_be_bytes()));
    }
    if let Some(a) = alpn {
        exts.extend_from_slice(&ext(0x0010, &alpn_ext_value(a)));
    }
    b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    b.extend_from_slice(&exts);
    b
}

/// DTLS 1.3 ClientHello：SNI + 应用识别 + 版本取 supported_versions（0xfefc）
#[test]
fn test_dtls13_client_hello() {
    let detector = DtlsDetector::new();
    let body = client_hello_body(0xfefd, "www.youtube.com", Some(0xfefc), None);
    let pkt = dtls_handshake(0xfefd, 1, &body);

    let result = detector.detect(&pkt).expect("应识别为 DTLS");
    assert_eq!(result.protocol, Protocol::Dtls);
    if let Metadata::Dtls(meta) = result.metadata {
        assert_eq!(meta.sni.as_deref(), Some("www.youtube.com"));
        assert_eq!(meta.version.as_deref(), Some("DTLS 1.3"));
        assert_eq!(meta.application, Some(Application::YouTube));
        // 客户端 JA4 占位格式："DTLS 1.3" 落入 tls10 桶（已知局限，risks.md F38）
        let ja4 = meta.ja4.as_deref().expect("应携带 JA4");
        assert!(ja4.starts_with("tls10."), "{}", ja4);
        assert_eq!(ja4.len(), 38, "{}", ja4);
        assert!(meta.ja4s.is_none(), "客户端流不携带 JA4S");
    } else {
        panic!("Expected Dtls metadata");
    }
}

/// DTLS 1.2 ClientHello（空 legacy cookie）：布局剥离后 SNI 可提取，版本 "DTLS 1.2"
#[test]
fn test_dtls12_client_hello_empty_cookie() {
    let detector = DtlsDetector::new();
    let body = client_hello_body(0xfefd, "example.org", None, Some(None));
    let pkt = dtls_handshake(0xfefd, 1, &body);

    let result = detector.detect(&pkt).expect("应识别为 DTLS");
    if let Metadata::Dtls(meta) = result.metadata {
        assert_eq!(meta.sni.as_deref(), Some("example.org"));
        assert_eq!(meta.version.as_deref(), Some("DTLS 1.2"));
    } else {
        panic!("Expected Dtls metadata");
    }
}

/// DTLS 1.2 ClientHello（HVR 往返后带非空 cookie）：cookie 向量剥离后可解析
#[test]
fn test_dtls12_client_hello_with_cookie() {
    let detector = DtlsDetector::new();
    let body = client_hello_body(0xfefd, "example.net", None, Some(Some(&[0xab; 4])));
    let pkt = dtls_handshake(0xfefd, 1, &body);

    let result = detector.detect(&pkt).expect("应识别为 DTLS");
    if let Metadata::Dtls(meta) = result.metadata {
        assert_eq!(meta.sni.as_deref(), Some("example.net"));
        assert_eq!(meta.version.as_deref(), Some("DTLS 1.2"));
    } else {
        panic!("Expected Dtls metadata");
    }
}

/// DTLS 1.3 ServerHello：JA4S golden 向量（proto 'd' + 版本段 "d3" = "dd3"，
/// JA4.md 字面语义，Wireshark packet-ja4.c `case 'd'` 印证；哈希段与 TCP/QUIC
/// 同输入已交叉验证）：legacy 0xfefd + supported_versions 0xfefc + cipher
/// 0x1302 + 扩展 [0x002b, 0x0010] + ALPN "h2" → dd302h2_1302_60694de2240d
#[test]
fn test_dtls13_server_hello_ja4s() {
    let detector = DtlsDetector::new();
    let body = server_hello_body(0xfefd, Some(0xfefc), Some("h2"));
    let pkt = dtls_handshake(0xfefd, 2, &body);

    let result = detector.detect(&pkt).expect("应识别为 DTLS");
    if let Metadata::Dtls(meta) = result.metadata {
        assert_eq!(meta.ja4s.as_deref(), Some("dd302h2_1302_60694de2240d"));
        assert_eq!(meta.version.as_deref(), Some("DTLS 1.3"));
        assert_eq!(meta.alpn.as_deref(), Some("h2"));
        assert!(meta.sni.is_none(), "ServerHello 无 SNI");
    } else {
        panic!("Expected Dtls metadata");
    }
}

/// DTLS 1.2 ServerHello（无 supported_versions）：legacy 0xfefd → 版本段 "d2"
/// → JA4S 首段 "dd2"
#[test]
fn test_dtls12_server_hello_ja4s() {
    let detector = DtlsDetector::new();
    let body = server_hello_body(0xfefd, None, None);
    let pkt = dtls_handshake(0xfefd, 2, &body);

    let result = detector.detect(&pkt).expect("应识别为 DTLS");
    if let Metadata::Dtls(meta) = result.metadata {
        let ja4s = meta.ja4s.as_deref().expect("应携带 JA4S");
        assert!(ja4s.starts_with("dd20000_1302_"), "{}", ja4s);
        assert_eq!(meta.version.as_deref(), Some("DTLS 1.2"));
    } else {
        panic!("Expected Dtls metadata");
    }
}

/// HelloVerifyRequest（msg_type 3）不定型——避免服务端流在 ServerHello
/// 到达前提前定型丢元数据
#[test]
fn test_hello_verify_request_not_detected() {
    let detector = DtlsDetector::new();
    let mut body = vec![0xfe, 0xfd]; // HVR 内 DTLS 版本 0xfefd
    body.push(0x04); // cookie 向量长度
    body.extend_from_slice(&[0x11; 4]);
    let pkt = dtls_handshake(0xfefd, 3, &body);
    assert!(detector.detect(&pkt).is_none());
}

/// 分片握手消息（fragment_length ≠ length）不解析
#[test]
fn test_fragmented_handshake_skipped() {
    let detector = DtlsDetector::new();
    let body = client_hello_body(0xfefd, "www.youtube.com", Some(0xfefc), None);
    let mut pkt = dtls_handshake(0xfefd, 1, &body);
    // 把 fragment_length（offset 22..25）改小，模拟分片
    pkt[22] = 0x00;
    pkt[23] = 0x00;
    pkt[24] = 0x10;
    assert!(detector.detect(&pkt).is_none());
}

/// epoch ≠ 0（加密记录）不解析
#[test]
fn test_encrypted_epoch_skipped() {
    let detector = DtlsDetector::new();
    let body = client_hello_body(0xfefd, "www.youtube.com", Some(0xfefc), None);
    let mut pkt = dtls_handshake(0xfefd, 1, &body);
    pkt[4] = 0x01; // epoch 低字节置 1
    assert!(detector.detect(&pkt).is_none());
}

/// TLS over TCP 记录（legacy_record_version 0x0303）不是 DTLS
#[test]
fn test_tls_record_not_dtls() {
    let detector = DtlsDetector::new();
    let body = client_hello_body(0x0303, "www.youtube.com", Some(0x0304), None);
    let pkt = dtls_handshake(0x0303, 1, &body);
    assert!(detector.detect(&pkt).is_none());
}

/// 畸形/截断输入返回 None（不 panic）
#[test]
fn test_malformed_inputs() {
    let detector = DtlsDetector::new();
    assert!(detector.detect(&[]).is_none());
    assert!(detector.detect(&[0x16, 0xfe]).is_none());
    // 声明长度超过实际载荷
    let body = client_hello_body(0xfefd, "a.com", None, None);
    let mut pkt = dtls_handshake(0xfefd, 1, &body);
    pkt.truncate(pkt.len() - 5);
    assert!(detector.detect(&pkt).is_none());
}

/// 构造完整以太网+IPv4+UDP 包（Detector 全链路用）
fn build_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 14 + 20 + 8 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    // Ethernet
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0x11; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    // IPv4
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x40, 17, 0x00, 0x00]); // proto=UDP
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    // UDP
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(payload);
    pkt
}

/// Detector 全链路：UDP 载荷上的 DTLS ClientHello 识别为 Protocol::Dtls
#[test]
fn test_detector_full_stack_dtls() {
    let mut detector = rdpi::Detector::new();
    let body = client_hello_body(0xfefd, "www.youtube.com", Some(0xfefc), None);
    let frame = build_udp_packet(54321, 443, &dtls_handshake(0xfefd, 1, &body));

    let result = detector.detect(&frame).unwrap().unwrap();
    assert_eq!(result.protocol, Protocol::Dtls);
    if let Metadata::Dtls(meta) = result.metadata {
        assert_eq!(meta.sni.as_deref(), Some("www.youtube.com"));
        assert_eq!(meta.version.as_deref(), Some("DTLS 1.3"));
    } else {
        panic!("Expected Dtls metadata");
    }
}
