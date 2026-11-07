# 阶段 1 收尾 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 补齐 DoH/DoT/DoQ、HTTP CONNECT/Proxy 子分类，并把 FTP 升级为有状态会话，使首批 A+B 协议覆盖闭环。

**Architecture:** 在现有 TLS/QUIC/HTTP detector 内做协议子分类，不新增 detector、不改 Registry 注册顺序；FTP 复用 F43 的 `process()` + `DissectorState` + `monitoring` 框架。Parity 导出层把新协议映射为 nDPI 5.0 的 `TLS.DoH_DoT` / `QUIC.DoH_DoT` / `HTTP_Connect` / `HTTP_Proxy`。

**Tech Stack:** Rust 1.88 / edition 2024；现有 `ProtocolDetector` trait、`DissectorState`、`Flow`、`parity` 模块；测试用 `cargo test`；语料用 `tests/parity/gen_corpus.py` + WSL ndpiReader 5.0。

## Global Constraints

- edition 2024，`rust-version = "1.88"`（`Cargo.toml` 已声明）。
- 不新增外部依赖。
- 中文 doc 注释为主，公开 API 保持现有风格。
- 禁止修改 Registry 注册顺序（顺序 = 优先级语义）。
- 首字节门契约（F29）：修改 detector 判定逻辑时必须同步维护 `first_byte_gate()` 并保留门覆盖样本测试；本计划不改 FTP 的 `first_byte_gate()`。
- 不引入分配密集的热路径逻辑；有状态路径复用现有 `Vec<u8>` 缓冲模式。
- 提交信息不加任何 AI 署名/Co-Authored-By；只提交源码、测试、项目文档，不提交 `.claude/` 或 `docs/superpowers/`。
- 每个任务结束运行相关测试并提交；最终门禁：
  `cargo fmt --all -- --check`、
  `cargo clippy --all-features --all-targets -- -D warnings`、
  `cargo test`、
  `cargo test --all-features`。

---

### Task 1: 协议枚举与规则名称映射

**Files:**
- Modify: `src/core/types.rs:272-382`（`Protocol` 枚举）
- Modify: `src/core/types.rs:1095-1278`（`category()` / `breed()`）
- Modify: `src/rule/parser.rs:25-70`（`RuleFile::into_rules`）
- Test: `tests/test_types.rs`（追加测试）
- Test: `tests/test_rule.rs`（追加测试）

**Interfaces:**
- Consumes: 无。
- Produces: `Protocol::Doh`、`Protocol::Dot`、`Protocol::Doq`、`Protocol::HttpConnect`、`Protocol::HttpProxy`；`Protocol::category()` 对 DoH/DoT/DoQ 返回 `Dns`，对 `HttpConnect`/`HttpProxy` 返回 `Web`；`breed()` 全部返回 `Acceptable`；规则 JSON 支持 `doh`/`dot`/`doq`/`http_connect`/`http_proxy`。

- [ ] **Step 1: Write the failing tests**

在 `tests/test_types.rs` 末尾追加：

```rust
#[test]
fn test_new_protocol_classification() {
    use rdpi::core::types::{Protocol, ProtocolBreed, ProtocolCategory};

    for protocol in [Protocol::Doh, Protocol::Dot, Protocol::Doq] {
        assert_eq!(protocol.category(), ProtocolCategory::Dns);
        assert_eq!(protocol.breed(), ProtocolBreed::Acceptable);
    }
    for protocol in [Protocol::HttpConnect, Protocol::HttpProxy] {
        assert_eq!(protocol.category(), ProtocolCategory::Web);
        assert_eq!(protocol.breed(), ProtocolBreed::Acceptable);
    }
}
```

在 `tests/test_rule.rs` 末尾追加：

```rust
#[test]
fn test_rule_parser_new_protocol_names() {
    let json = r#"{
        "rules": [
            {"id": "doh", "protocol": "doh", "condition": {"dst_port": 443}},
            {"id": "dot", "protocol": "dot", "condition": {"dst_port": 853}},
            {"id": "doq", "protocol": "doq", "condition": {"dst_port": 784}},
            {"id": "connect", "protocol": "http_connect", "condition": {"dst_port": 8080}},
            {"id": "proxy", "protocol": "http_proxy", "condition": {"dst_port": 3128}}
        ]
    }"#;
    let engine = RuleEngine::from_json(json).unwrap();

    let cases = [
        (443, Protocol::Doh),
        (853, Protocol::Dot),
        (784, Protocol::Doq),
        (8080, Protocol::HttpConnect),
        (3128, Protocol::HttpProxy),
    ];
    for (dst_port, expected) in cases {
        let ctx = RuleContext {
            src_port: 12345,
            dst_port,
            sni: None,
            payload: Vec::new(),
        };
        let result = engine.match_rule(&ctx).expect("rule should match");
        assert_eq!(result.protocol, expected);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test --test test_types test_new_protocol_classification
cargo test --features rule --test test_rule test_rule_parser_new_protocol_names
```

Expected: 编译失败，错误包含 `no variant named 'Doh'`（`Protocol::Doh` 不存在）。

- [ ] **Step 3: Add enum variants and classification arms**

在 `src/core/types.rs` 的 `Protocol` 枚举中，`Http` 后加入：

```rust
    Http,
    /// HTTP CONNECT 隧道（feature: http）
    HttpConnect,
    /// HTTP 正向代理（绝对 URI，feature: http）
    HttpProxy,
    Tls,
```

在 `Http3` 后加入：

```rust
    Http3,
    /// DNS over HTTPS（RFC 8484，feature: tls）
    Doh,
    /// DNS over TLS（RFC 7858，feature: tls）
    Dot,
    /// DNS over QUIC（RFC 9250，feature: quic）
    Doq,
    /// DTLS（RFC 6347/9147，feature: dtls，F38）
    Dtls,
```

在 `category()` 中修改 Web 与 DNS 分支：

```rust
            // Web
            Protocol::Http | Protocol::HttpConnect | Protocol::HttpProxy => ProtocolCategory::Web,
            #[cfg(feature = "proto3")]
            Protocol::Http2 | Protocol::WebSocket => ProtocolCategory::Web,
```

```rust
            // DNS
            Protocol::Dns | Protocol::Doh | Protocol::Dot | Protocol::Doq => {
                ProtocolCategory::Dns
            }
```

在 `breed()` 的 `Acceptable` 分支加入新协议：

```rust
            Protocol::Mysql
            | Protocol::Postgresql
            | Protocol::Redis
            | Protocol::Mongodb
            | Protocol::Snmp
            | Protocol::Modbus
            | Protocol::Doh
            | Protocol::Dot
            | Protocol::Doq
            | Protocol::HttpConnect
            | Protocol::HttpProxy => ProtocolBreed::Acceptable,
```

在 `src/rule/parser.rs` 的 `match entry.protocol.to_lowercase().as_str()` 中，`"http"` 后加入：

```rust
                    "http" => Protocol::Http,
                    "http_connect" | "httpconnect" => Protocol::HttpConnect,
                    "http_proxy" | "httpproxy" => Protocol::HttpProxy,
                    "doh" => Protocol::Doh,
                    "dot" => Protocol::Dot,
                    "doq" => Protocol::Doq,
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test --test test_types
cargo test --features rule --test test_rule
cargo test
```

Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/core/types.rs src/rule/parser.rs tests/test_types.rs tests/test_rule.rs
git commit -m "Add protocol variants for DoH/DoT/DoQ and HTTP proxy"
```

---

### Task 2: TLS DoH/DoT 子分类

**Files:**
- Create: `src/protocols/tls/doh.rs`
- Modify: `src/protocols/tls/mod.rs:1-230`（imports、`mod doh`、`detect`、`detect_with_context`、`process`）
- Test: `src/protocols/tls/mod.rs` 的 `mod tests`

**Interfaces:**
- Consumes: `Protocol::Doh` / `Protocol::Dot`（Task 1）。
- Produces: `doh::is_doh_resolver(host: &str) -> bool`；`TlsDetector::detect` 在 ALPN `dot` / DoH SNI 时返回 `Dot`/`Doh`；`detect_with_context` 在 TCP 853 端口把 `Tls` 升级为 `Dot`（`DpiPartial`）。

- [ ] **Step 1: Write the failing tests**

在 `src/protocols/tls/mod.rs` 的 `#[cfg(test)] mod tests` 中追加测试辅助函数与用例（放在现有 `test_first_byte_gate_covers_valid_sample` 之后）：

```rust
    /// 构造带 SNI/ALPN 扩展的最小 ClientHello 记录
    fn make_client_hello_with_alpn(sni: Option<&str>, alpn: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(host) = sni {
            let name = host.as_bytes();
            let list_len = name.len() + 3;
            let ext_len = name.len() + 5;
            extensions.extend_from_slice(&[0x00, 0x00]);
            extensions.extend_from_slice(&(ext_len as u16).to_be_bytes());
            extensions.extend_from_slice(&(list_len as u16).to_be_bytes());
            extensions.push(0x00);
            extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
            extensions.extend_from_slice(name);
        }
        if let Some(protocol) = alpn {
            let mut list = vec![protocol.len() as u8];
            list.extend_from_slice(protocol.as_bytes());
            extensions.extend_from_slice(&[0x00, 0x10]);
            extensions.extend_from_slice(&((list.len() + 2) as u16).to_be_bytes());
            extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&list);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// 构造带 ALPN 扩展的最小 ServerHello 记录
    fn make_server_hello_with_alpn(alpn: &str) -> Vec<u8> {
        let mut list = vec![alpn.len() as u8];
        list.extend_from_slice(alpn.as_bytes());
        let mut extensions = vec![0x00, 0x10];
        extensions.extend_from_slice(&((list.len() + 2) as u16).to_be_bytes());
        extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&list);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x22u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![0x02];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn test_tls_alpn_dot_classified_as_dot() {
        let detector = TlsDetector::new();
        let record = make_client_hello_with_alpn(Some("example.com"), Some("dot"));
        let result = detector.detect(&record).unwrap();
        assert_eq!(result.protocol, Protocol::Dot);
    }

    #[test]
    fn test_tls_doh_resolver_sni_classified_as_doh() {
        let detector = TlsDetector::new();
        let record = make_client_hello_with_alpn(Some("dns.google"), Some("h2"));
        let result = detector.detect(&record).unwrap();
        assert_eq!(result.protocol, Protocol::Doh);
    }

    #[test]
    fn test_tls_normal_sni_stays_tls() {
        let detector = TlsDetector::new();
        let record = make_client_hello_with_alpn(Some("example.com"), Some("h2"));
        let result = detector.detect(&record).unwrap();
        assert_eq!(result.protocol, Protocol::Tls);
    }

    #[test]
    fn test_tls_server_hello_alpn_dot_classified_as_dot() {
        let detector = TlsDetector::new();
        let record = make_server_hello_with_alpn("dot");
        let result = detector.detect(&record).unwrap();
        assert_eq!(result.protocol, Protocol::Dot);
    }

    #[test]
    fn test_tls_dot_port_fallback_is_partial() {
        use crate::core::types::{Confidence, DetectContext};
        use crate::protocols::ProtocolDetector;

        let detector = TlsDetector::new();
        let record = make_client_hello_with_alpn(Some("example.com"), Some("h2"));
        let ctx = DetectContext {
            src_port: 50000,
            dst_port: 853,
            is_http3_port: false,
        };
        let result = detector.detect_with_context(&record, &ctx).unwrap();
        assert_eq!(result.protocol, Protocol::Dot);
        assert_eq!(result.confidence, Confidence::DpiPartial);
    }

    #[test]
    fn test_tls_dot_alpn_wins_over_doh_sni() {
        let detector = TlsDetector::new();
        let record = make_client_hello_with_alpn(Some("dns.google"), Some("dot"));
        let result = detector.detect(&record).unwrap();
        assert_eq!(result.protocol, Protocol::Dot);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test --lib protocols::tls::tests::test_tls_alpn_dot_classified_as_dot
```

Expected: FAIL，`Protocol::Dot` 存在但 TLS detector 返回 `Protocol::Tls`（断言失败），或 `detect_with_context` 未实现导致端口回退断言失败。

- [ ] **Step 3: Create `src/protocols/tls/doh.rs`**

```rust
//! DoH 解析器域名表（RFC 8484）
//!
//! nDPI 5.0 通过 TLS SNI 命中已知 DoH 解析器域名来识别 DoH/DoT。
//! 本模块维护公开解析器域名表，匹配语义为“全等或子域后缀”。

/// 已知 DoH 解析器域名（公开解析器文档整理）
const DOH_RESOLVERS: &[&str] = &[
    "dns.google",
    "dns.google.com",
    "mozilla.cloudflare-dns.com",
    "cloudflare-dns.com",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "doh.opendns.com",
    "doh.powerdns.org",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
    "doh.libredns.gr",
    "dns.dns-over-https.com",
    "doh.dns.sb",
    "dns.mullvad.net",
    "doh.mullvad.net",
];

/// 判断 SNI/host 是否命中已知 DoH 解析器域名
pub(crate) fn is_doh_resolver(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return false;
    }
    let host_bytes = host.as_bytes();
    DOH_RESOLVERS.iter().any(|resolver| {
        let resolver_bytes = resolver.as_bytes();
        host_bytes.eq_ignore_ascii_case(resolver_bytes)
            || (host_bytes.len() > resolver_bytes.len()
                && host_bytes[host_bytes.len() - resolver_bytes.len() - 1] == b'.'
                && host_bytes[host_bytes.len() - resolver_bytes.len()..]
                    .eq_ignore_ascii_case(resolver_bytes))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_subdomain_and_case() {
        assert!(is_doh_resolver("dns.google"));
        assert!(is_doh_resolver("DNS.GOOGLE"));
        assert!(is_doh_resolver("resolver.dns.google"));
        assert!(is_doh_resolver("mozilla.cloudflare-dns.com"));
        assert!(is_doh_resolver("dns.google."));
    }

    #[test]
    fn rejects_lookalikes_and_empty() {
        assert!(!is_doh_resolver("notdns.google"));
        assert!(!is_doh_resolver("dns.google.example.com"));
        assert!(!is_doh_resolver("example.com"));
        assert!(!is_doh_resolver(""));
    }
}
```

- [ ] **Step 4: Wire DoH/DoT into the TLS detector**

在 `src/protocols/tls/mod.rs` 顶部：

```rust
mod certificate;
mod doh;
mod parser;
```

把 imports 改为：

```rust
use crate::core::types::{
    Confidence, DetectContext, DetectionResult, Direction, DissectorOutcome, DissectorState,
    Metadata, Protocol, TlsDissectorState, TlsMetadata,
};
```

在 `TlsDetector` 的 `impl` 前加入两个辅助函数：

```rust
/// 按 ALPN/SNI 选择 TLS 子协议
fn select_tls_protocol(tls_meta: &TlsMetadata) -> Protocol {
    if tls_meta
        .alpn
        .as_deref()
        .is_some_and(|alpn| alpn.eq_ignore_ascii_case("dot"))
    {
        return Protocol::Dot;
    }
    if tls_meta
        .sni
        .as_deref()
        .is_some_and(doh::is_doh_resolver)
    {
        return Protocol::Doh;
    }
    Protocol::Tls
}

/// 无 ALPN/SNI 信号时，TCP 853 端口回退为 DoT（DpiPartial）
fn apply_dot_port_hint(mut result: DetectionResult, ctx: &DetectContext) -> DetectionResult {
    if result.protocol == Protocol::Tls && (ctx.src_port == 853 || ctx.dst_port == 853) {
        result.protocol = Protocol::Dot;
        result.category = Protocol::Dot.category();
        result.breed = Protocol::Dot.breed();
        result.confidence = Confidence::DpiPartial;
    }
    result
}
```

在 `process()` 的 `Classified` 返回处：

```rust
                if let Some(result) = process_handshake(self, handshake_buffer) {
                    record_buffer.clear();
                    handshake_buffer.clear();
                    return Some(DissectorOutcome::Classified(apply_dot_port_hint(result, ctx)));
                }
```

在 `detect()` 的最终返回处（`if tls_meta... { return None; }` 之后）：

```rust
        let protocol = select_tls_protocol(&tls_meta);
        Some(
            DetectionResult::new(protocol)
                .with_metadata(Metadata::Tls(tls_meta))
                .with_confidence(Confidence::Dpi),
        )
```

在 `impl ProtocolDetector for TlsDetector` 中新增（放在 `process` 之后）：

```rust
    fn detect_with_context(
        &self,
        payload: &[u8],
        ctx: &DetectContext,
    ) -> Option<DetectionResult> {
        let result = self.detect(payload)?;
        Some(apply_dot_port_hint(result, ctx))
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run:

```bash
cargo test --lib protocols::tls
cargo test
```

Expected: 全部 PASS。

- [ ] **Step 6: Commit**

```bash
git add src/protocols/tls/doh.rs src/protocols/tls/mod.rs
git commit -m "Classify DoH and DoT in the TLS detector"
```

---

### Task 3: QUIC DoQ 子分类

**Files:**
- Modify: `src/protocols/quic/mod.rs:100-230`（`select_quic_protocol`、`detect`、`detect_with_context`）
- Test: `src/protocols/quic/mod.rs` 的 `mod tests`

**Interfaces:**
- Consumes: `Protocol::Doq`（Task 1）。
- Produces: `select_quic_protocol(alpn: Option<&str>, is_http3_port: bool, is_standard_version: bool) -> (Protocol, Confidence)`；QUIC detector 在 ALPN 以 `doq` 开头时返回 `Protocol::Doq`。

- [ ] **Step 1: Write the failing tests**

在 `src/protocols/quic/mod.rs` 的 `mod tests` 中追加：

```rust
    #[test]
    fn test_select_quic_protocol_doq() {
        assert_eq!(
            select_quic_protocol(Some("doq"), false, true),
            (Protocol::Doq, Confidence::Dpi)
        );
        assert_eq!(
            select_quic_protocol(Some("doq-i00"), false, false),
            (Protocol::Doq, Confidence::Dpi)
        );
    }

    #[test]
    fn test_select_quic_protocol_http3_and_quic() {
        assert_eq!(
            select_quic_protocol(Some("h3"), true, true),
            (Protocol::Http3, Confidence::DpiPartial)
        );
        assert_eq!(
            select_quic_protocol(Some("h3"), false, true),
            (Protocol::Quic, Confidence::Dpi)
        );
        assert_eq!(
            select_quic_protocol(None, true, false),
            (Protocol::Quic, Confidence::Dpi)
        );
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test --features quic --lib protocols::quic::tests::test_select_quic_protocol_doq
```

Expected: 编译失败，`cannot find function 'select_quic_protocol'`。

- [ ] **Step 3: Implement `select_quic_protocol` and use it**

在 `src/protocols/quic/mod.rs` 的 `QuicDetector` impl 之前加入：

```rust
/// 根据 ALPN 与端口上下文选择 QUIC 子协议
fn select_quic_protocol(
    alpn: Option<&str>,
    is_http3_port: bool,
    is_standard_version: bool,
) -> (Protocol, Confidence) {
    if alpn.is_some_and(|alpn| alpn.starts_with("doq")) {
        return (Protocol::Doq, Confidence::Dpi);
    }
    if is_http3_port && is_standard_version {
        (Protocol::Http3, Confidence::DpiPartial)
    } else {
        (Protocol::Quic, Confidence::Dpi)
    }
}
```

在 `detect()` 中，**构建 `QuicMetadata` 之前**计算协议（`alpn` 随后会被 move 进 metadata）：

```rust
        let is_standard_version = matches!(info.version, QUIC_VERSION_1 | QUIC_VERSION_2);
        let (protocol, confidence) =
            select_quic_protocol(alpn.as_deref(), false, is_standard_version);

        let metadata = QuicMetadata {
            sni,
            version: Some(format!("{:08x}", info.version)),
            destination_connection_id: Some(info.dcid),
            application,
            alpn,
            ja4,
            ja4s,
            transport_parameters,
        };

        Some(
            DetectionResult::new(protocol)
                .with_metadata(Metadata::Quic(metadata))
                .with_confidence(confidence),
        )
```

在 `detect_with_context()` 中，同样在构建 metadata 之前计算：

```rust
        let is_standard_version = matches!(info.version, QUIC_VERSION_1 | QUIC_VERSION_2);
        let (protocol, confidence) =
            select_quic_protocol(alpn.as_deref(), ctx.is_http3_port, is_standard_version);

        let metadata = QuicMetadata {
            sni,
            version: Some(format!("{:08x}", info.version)),
            destination_connection_id: Some(info.dcid),
            application,
            alpn,
            ja4,
            ja4s,
            transport_parameters,
        };

        Some(
            DetectionResult::new(protocol)
                .with_metadata(Metadata::Quic(metadata))
                .with_confidence(confidence),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test --features quic --lib protocols::quic
cargo test --all-features
```

Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/protocols/quic/mod.rs
git commit -m "Classify DNS-over-QUIC by ALPN"
```

---

### Task 4: HTTP CONNECT / Proxy 子分类

**Files:**
- Modify: `src/protocols/http/detector.rs:108-170`（`detect` 请求分支）
- Test: `src/protocols/http/detector.rs` 的 `mod tests`

**Interfaces:**
- Consumes: `Protocol::HttpConnect` / `Protocol::HttpProxy`（Task 1）。
- Produces: `HttpDetector::detect` 对 `CONNECT` 方法返回 `HttpConnect`，对绝对 URI `http://` 返回 `HttpProxy`，普通请求仍返回 `Http`。

- [ ] **Step 1: Write the failing tests**

在 `src/protocols/http/detector.rs` 的 `mod tests` 中追加：

```rust
    #[test]
    fn test_detect_http_connect() {
        let detector = HttpDetector::new();
        let result = detector
            .detect(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        assert_eq!(result.protocol, Protocol::HttpConnect);
    }

    #[test]
    fn test_detect_http_proxy_absolute_uri() {
        let detector = HttpDetector::new();
        let result = detector
            .detect(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        assert_eq!(result.protocol, Protocol::HttpProxy);
    }

    #[test]
    fn test_detect_http_proxy_case_insensitive_scheme() {
        let detector = HttpDetector::new();
        let result = detector
            .detect(b"GET HTTP://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        assert_eq!(result.protocol, Protocol::HttpProxy);
    }

    #[test]
    fn test_detect_normal_http_stays_http() {
        let detector = HttpDetector::new();
        let result = detector
            .detect(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        assert_eq!(result.protocol, Protocol::Http);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test --lib protocols::http::tests::test_detect_http_connect
```

Expected: FAIL，当前返回 `Protocol::Http`，断言 `HttpConnect` 失败。

- [ ] **Step 3: Implement the classification**

在 `HttpDetector::detect` 的请求分支中，`parse_request_line` 成功后、构造 metadata 前加入：

```rust
            let protocol = if req.method.eq_ignore_ascii_case("CONNECT") {
                Protocol::HttpConnect
            } else if req
                .path
                .as_bytes()
                .get(..7)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
            {
                Protocol::HttpProxy
            } else {
                Protocol::Http
            };
```

把该分支的返回改为：

```rust
            return Some(
                DetectionResult::new(protocol)
                    .with_metadata(metadata)
                    .with_confidence(Confidence::Dpi),
            );
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test --lib protocols::http
cargo test
```

Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/protocols/http/detector.rs
git commit -m "Classify HTTP CONNECT and forward proxy requests"
```

---

### Task 5: FTP 有状态会话

**Files:**
- Modify: `src/core/types.rs:115-185`（`FtpDissectorState`、`DissectorState::Ftp`）
- Modify: `src/core/types.rs:1793-1798`（`FtpMetadata` 字段）
- Modify: `src/protocols/ftp/parser.rs`（`complete_line_end`）
- Modify: `src/protocols/ftp/detector.rs:1-312`（`process`、常量、构造点、测试）
- Modify: `src/protocols/http/detector.rs:67-85`（`DissectorState::Ftp` match 分支）
- Modify: `src/lib.rs:943-953`（`flow.monitoring`）
- Modify: `src/lib.rs:652-700`（`merge_detected_metadata`）
- Modify: `src/bin/rdpi.rs:270-290`（FTP 元数据显示）

**Interfaces:**
- Consumes: `Protocol::Ftp`、`Metadata::Ftp`、`DissectorState`、`Direction`、`DetectContext`。
- Produces: `FtpDissectorState { buffer, username, filename }`；`DissectorState::Ftp`；`FtpMetadata.username` / `FtpMetadata.filename`；`FtpDetector::process()` 支持跨段行重组与多命令元数据。

- [ ] **Step 1: Write the failing tests**

在 `src/protocols/ftp/detector.rs` 的 `mod tests` 中追加（复用现有 `ctx_with`）：

```rust
    // ---- F44: FTP 有状态会话 ----

    #[test]
    fn test_process_reassembles_split_banner() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(50000, 21);

        let first = detector
            .process(&mut state, b"220 FTP ser", Direction::Reverse, &ctx)
            .unwrap();
        assert!(matches!(first, DissectorOutcome::Continue));

        let second = detector
            .process(&mut state, b"ver ready\r\n", Direction::Reverse, &ctx)
            .unwrap();
        match second {
            DissectorOutcome::Classified(result) => {
                assert_eq!(result.protocol, Protocol::Ftp);
            }
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn test_process_extracts_username_across_segments() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(50000, 21);

        detector
            .process(&mut state, b"220 FTP ready\r\n", Direction::Reverse, &ctx)
            .unwrap();
        detector
            .process(&mut state, b"US", Direction::Forward, &ctx)
            .unwrap();
        let result = detector
            .process(&mut state, b"ER alice\r\n", Direction::Forward, &ctx)
            .unwrap();

        match result {
            DissectorOutcome::Classified(result) => match result.metadata {
                Metadata::Ftp(meta) => {
                    assert_eq!(meta.username.as_deref(), Some("alice"));
                }
                other => panic!("expected Ftp metadata, got {other:?}"),
            },
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn test_process_extracts_filename_for_retr_and_stor() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(50000, 21);
        detector
            .process(&mut state, b"220 FTP ready\r\n", Direction::Reverse, &ctx)
            .unwrap();

        let result = detector
            .process(&mut state, b"RETR report.pdf\r\n", Direction::Forward, &ctx)
            .unwrap();
        match result {
            DissectorOutcome::Classified(result) => match result.metadata {
                Metadata::Ftp(meta) => assert_eq!(meta.filename.as_deref(), Some("report.pdf")),
                other => panic!("expected Ftp metadata, got {other:?}"),
            },
            other => panic!("expected Classified, got {other:?}"),
        }

        let result = detector
            .process(&mut state, b"STOR upload.bin\r\n", Direction::Forward, &ctx)
            .unwrap();
        match result {
            DissectorOutcome::Classified(result) => match result.metadata {
                Metadata::Ftp(meta) => assert_eq!(meta.filename.as_deref(), Some("report.pdf")),
                other => panic!("expected Ftp metadata, got {other:?}"),
            },
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn test_process_multiple_commands_in_one_segment() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(50000, 21);
        detector
            .process(&mut state, b"220 FTP ready\r\n", Direction::Reverse, &ctx)
            .unwrap();

        let result = detector
            .process(
                &mut state,
                b"USER bob\r\nRETR notes.txt\r\n",
                Direction::Forward,
                &ctx,
            )
            .unwrap();
        match result {
            DissectorOutcome::Classified(result) => match result.metadata {
                Metadata::Ftp(meta) => {
                    assert_eq!(meta.username.as_deref(), Some("bob"));
                    assert_eq!(meta.filename.as_deref(), Some("notes.txt"));
                }
                other => panic!("expected Ftp metadata, got {other:?}"),
            },
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn test_process_does_not_take_over_on_smtp_port() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(12345, 25);
        assert!(
            detector
                .process(
                    &mut state,
                    b"220 mail.example.com ESMTP\r\n",
                    Direction::Reverse,
                    &ctx
                )
                .is_none()
        );
        assert_eq!(state, DissectorState::None);
    }

    #[test]
    fn test_process_gives_up_when_first_line_is_not_ftp() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(12345, 21);
        let outcome = detector
            .process(&mut state, b"6xx not-an-ftp-line\r\n", Direction::Reverse, &ctx)
            .unwrap();
        assert!(matches!(outcome, DissectorOutcome::GiveUp));
    }

    #[test]
    fn test_process_buffer_overflow_gives_up() {
        let detector = FtpDetector::new();
        let mut state = DissectorState::None;
        let ctx = ctx_with(12345, 21);
        let payload = vec![b'2'; FTP_LINE_MAX_BYTES + 1];
        let outcome = detector
            .process(&mut state, &payload, Direction::Reverse, &ctx)
            .unwrap();
        assert!(matches!(outcome, DissectorOutcome::GiveUp));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test --features proto3 --lib protocols::ftp::tests::test_process_reassembles_split_banner
```

Expected: 编译失败，`DissectorState::Ftp` / `FtpDissectorState` 不存在（或 `process` 未实现）。

- [ ] **Step 3: Add FTP state and metadata fields**

在 `src/core/types.rs` 的 `WebSocketDissectorState` 之后加入：

```rust
/// FTP 有状态 dissector 的 per-flow 状态
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FtpDissectorState {
    /// 跨包累积的行字节
    pub buffer: Vec<u8>,
    /// 已提取的用户名（USER 命令，首个非空值）
    pub username: Option<String>,
    /// 已提取的文件名（RETR/STOR 命令，首个非空值）
    pub filename: Option<String>,
}
```

在 `DissectorState` 枚举中 `WebSocket` 后加入：

```rust
    /// FTP 行跨段重组
    Ftp(FtpDissectorState),
```

把 `FtpMetadata` 改为：

```rust
#[cfg(feature = "proto3")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct FtpMetadata {
    pub is_client: bool,
    pub verb: Option<String>,
    pub argument: Option<String>,
    pub response_code: Option<u16>,
    /// 已提取的用户名（USER 命令，首个非空值）
    pub username: Option<String>,
    /// 已提取的文件名（RETR/STOR 命令，首个非空值）
    pub filename: Option<String>,
}
```

- [ ] **Step 4: Add `complete_line_end` to the FTP parser**

在 `src/protocols/ftp/parser.rs` 的 `is_ftp_command_prefix` 之后加入：

```rust
/// 返回缓冲区中首个完整行（含 `\n`）的结束位置（不含端点）
pub fn complete_line_end(buffer: &[u8]) -> Option<usize> {
    buffer.iter().position(|&byte| byte == b'\n').map(|pos| pos + 1)
}
```

- [ ] **Step 5: Implement `FtpDetector::process` and update constructors**

在 `src/protocols/ftp/detector.rs` 顶部 imports 中加入 `Direction`、`DissectorOutcome`、`DissectorState`、`FtpDissectorState`（当前 `use crate::core::types::*;` 已覆盖，确认即可），并加入：

```rust
/// FTP 行缓冲上限（RFC 959 命令/响应 ≤ 512 字节，留足余量）
const FTP_LINE_MAX_BYTES: usize = 4096;

/// 判断首字节是否可能为 FTP 数字响应（200–600）
fn is_ftp_response_start(byte: u8) -> bool {
    (b'2'..=b'6').contains(&byte)
}
```

在 `impl ProtocolDetector for FtpDetector` 中 `detect` 之后加入：

```rust
    /// 有状态逐包处理：FTP 命令/响应行可能跨 TCP 段
    ///
    /// 仅服务端数字响应前缀（2–6）且非 SMTP 端口时接管；FTP 为 server-first
    /// 协议，正常抓包从 banner 开始。接管后进入 monitoring，后续 USER /
    /// RETR / STOR 命令持续富化 username/filename。
    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        _direction: Direction,
        ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        let was_none = matches!(state, DissectorState::None);
        match state {
            DissectorState::None => {
                if payload.is_empty()
                    || !is_ftp_response_start(payload[0])
                    || is_smtp_port(ctx.src_port)
                    || is_smtp_port(ctx.dst_port)
                {
                    return None;
                }
                *state = DissectorState::Ftp(FtpDissectorState::default());
            }
            DissectorState::Ftp(_) => {}
            _ => return None,
        }
        let DissectorState::Ftp(ftp) = state else {
            return None;
        };

        if ftp.buffer.len() + payload.len() > FTP_LINE_MAX_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        ftp.buffer.extend_from_slice(payload);

        let pending = std::mem::take(&mut ftp.buffer);
        let mut start = 0;
        let mut first_complete_line = was_none;
        let mut last_metadata = None;

        while let Some(end_rel) = super::parser::complete_line_end(&pending[start..]) {
            let end = start + end_rel;
            let line = &pending[start..end];
            start = end;

            match self.detect(line) {
                Some(result) => {
                    if let Metadata::Ftp(ref meta) = result.metadata {
                        if meta.is_client {
                            match meta.verb.as_deref() {
                                Some("USER") => {
                                    if ftp.username.is_none() {
                                        ftp.username = meta.argument.clone();
                                    }
                                }
                                Some("RETR" | "STOR") => {
                                    if ftp.filename.is_none() {
                                        ftp.filename = meta.argument.clone();
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    let mut metadata = match result.metadata {
                        Metadata::Ftp(meta) => meta,
                        _ => unreachable!("FTP detector always returns Ftp metadata"),
                    };
                    metadata.username = ftp.username.clone();
                    metadata.filename = ftp.filename.clone();
                    last_metadata = Some(metadata);
                }
                None => {
                    if first_complete_line {
                        return Some(DissectorOutcome::GiveUp);
                    }
                }
            }
            first_complete_line = false;
        }

        ftp.buffer.extend_from_slice(&pending[start..]);

        last_metadata.map(|metadata| {
            DissectorOutcome::Classified(
                DetectionResult::new(Protocol::Ftp).with_metadata(Metadata::Ftp(metadata)),
            )
        })
        .or(Some(DissectorOutcome::Continue))
    }
```

在 `detect()` 的两个 `FtpMetadata` 构造点补字段：

```rust
            let meta = Metadata::Ftp(FtpMetadata {
                is_client: false,
                verb: None,
                argument: None,
                response_code: Some(resp.code),
                username: None,
                filename: None,
            });
```

```rust
            let meta = Metadata::Ftp(FtpMetadata {
                is_client: true,
                verb: Some(cmd.verb),
                argument: cmd.argument,
                response_code: None,
                username: None,
                filename: None,
            });
```

- [ ] **Step 6: Wire monitoring and metadata merge**

在 `src/lib.rs` 的 `flow.monitoring` 匹配中加入 `DissectorState::Ftp(_)`：

```rust
                    flow.monitoring = matches!(
                        flow.dissector_state,
                        DissectorState::Tls(_)
                            | DissectorState::Smtp(_)
                            | DissectorState::Pop3(_)
                            | DissectorState::Imap(_)
                            | DissectorState::Ftp(_)
                    );
```

在 `merge_detected_metadata` 的 `Some(other)` 之前加入：

```rust
            #[cfg(feature = "proto3")]
            Some(Metadata::Ftp(mut old)) => {
                if let Metadata::Ftp(new) = detected.metadata.clone() {
                    if new.username.is_some() {
                        old.username = new.username;
                    }
                    if new.filename.is_some() {
                        old.filename = new.filename;
                    }
                    if new.verb.is_some() {
                        old.verb = new.verb;
                    }
                    if new.argument.is_some() {
                        old.argument = new.argument;
                    }
                    if new.response_code.is_some() {
                        old.response_code = new.response_code;
                    }
                    old.is_client = new.is_client;
                }
                flow.metadata = Some(Metadata::Ftp(old.clone()));
                detected.metadata = Metadata::Ftp(old);
            }
```

在 `src/protocols/http/detector.rs` 的 `process()` 显式 match 中，把 `DissectorState::Ftp(_)` 加入 `return None` 的分支：

```rust
            DissectorState::Ssh(_)
            | DissectorState::DnsTcp(_)
            | DissectorState::Tls(_)
            | DissectorState::Http2(_)
            | DissectorState::Smtp(_)
            | DissectorState::Pop3(_)
            | DissectorState::Imap(_)
            | DissectorState::WebSocket(_)
            | DissectorState::Ftp(_) => {
                return None;
            }
```

在 `src/bin/rdpi.rs` 的 `print_detection` 元数据 match 中，`Smtp` 分支后加入：

```rust
        #[cfg(feature = "proto3")]
        rdpi::Metadata::Ftp(ftp) => ftp
            .username
            .as_deref()
            .or(ftp.filename.as_deref())
            .unwrap_or(""),
```

- [ ] **Step 7: Run tests to verify they pass**

Run:

```bash
cargo test --features proto3 --lib protocols::ftp
cargo test --features proto3
cargo test
cargo test --all-features
```

Expected: 全部 PASS。

- [ ] **Step 8: Commit**

```bash
git add src/core/types.rs src/protocols/ftp/parser.rs src/protocols/ftp/detector.rs src/protocols/http/detector.rs src/lib.rs src/bin/rdpi.rs
git commit -m "Add stateful FTP sessions with username and filename metadata"
```

---

### Task 6: Parity 导出映射

**Files:**
- Modify: `src/parity.rs:43-99`（`from_flow`）
- Modify: `src/parity.rs:168-245`（`protocol_name`、`ndpi_compat_classification`）
- Test: `tests/test_flow_export.rs`

**Interfaces:**
- Consumes: `Protocol::Doh`/`Dot`/`Doq`/`HttpConnect`/`HttpProxy`（Task 1）。
- Produces: `NormalizedFlow::from_flow` 对 DoH/DoT 导出 `TLS` + `DoH_DoT`，DoQ 导出 `QUIC` + `DoH_DoT`，HTTP CONNECT/Proxy 导出 `HTTP_Connect`/`HTTP_Proxy`；category/breed 对齐 nDPI（Network/Acceptable、Web/Acceptable）。

- [ ] **Step 1: Write the failing tests**

在 `tests/test_flow_export.rs` 末尾追加：

```rust
fn flow_with_protocol(protocol: Protocol) -> Flow {
    let mut flow = Flow::new(key());
    flow.protocol = Some(protocol);
    flow.protocol_stack.push(protocol);
    flow
}

#[test]
fn doh_and_dot_export_as_tls_doh_dot() {
    for protocol in [Protocol::Doh, Protocol::Dot] {
        let normalized = NormalizedFlow::from_flow(&flow_with_protocol(protocol));
        assert_eq!(normalized.master_protocol.as_deref(), Some("TLS"));
        assert_eq!(normalized.app_protocol.as_deref(), Some("DoH_DoT"));
        assert_eq!(
            normalized.protocol_stack,
            vec!["TLS".to_string(), "DoH_DoT".to_string()]
        );
        assert_eq!(normalized.category.as_deref(), Some("Network"));
        assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
    }
}

#[test]
fn doq_exports_as_quic_doh_dot() {
    let normalized = NormalizedFlow::from_flow(&flow_with_protocol(Protocol::Doq));
    assert_eq!(normalized.master_protocol.as_deref(), Some("QUIC"));
    assert_eq!(normalized.app_protocol.as_deref(), Some("DoH_DoT"));
    assert_eq!(
        normalized.protocol_stack,
        vec!["QUIC".to_string(), "DoH_DoT".to_string()]
    );
    assert_eq!(normalized.category.as_deref(), Some("Network"));
    assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
}

#[test]
fn http_connect_and_proxy_export_as_single_protocol() {
    let cases = [
        (Protocol::HttpConnect, "HTTP_Connect"),
        (Protocol::HttpProxy, "HTTP_Proxy"),
    ];
    for (protocol, name) in cases {
        let normalized = NormalizedFlow::from_flow(&flow_with_protocol(protocol));
        assert_eq!(normalized.master_protocol.as_deref(), Some(name));
        assert_eq!(normalized.app_protocol, None);
        assert_eq!(normalized.protocol_stack, vec![name.to_string()]);
        assert_eq!(normalized.category.as_deref(), Some("Web"));
        assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test --features json --test test_flow_export doh_and_dot_export_as_tls_doh_dot
```

Expected: FAIL，`master_protocol` 当前为 `"Doh"` / `"Dot"`，不是 `"TLS"`。

- [ ] **Step 3: Implement the special mappings**

在 `src/parity.rs` 的 `from_flow` 中，把原来的：

```rust
        let master_protocol = flow.protocol.map(protocol_name);
        let application = flow
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.application());
        let app_protocol = application.map(ndpi_compat_app_name);
        let (category, breed) = match flow.protocol {
            Some(protocol) => {
                let (category, breed) = ndpi_compat_classification(protocol, application);
                (Some(category), Some(breed))
            }
            None => (None, None),
        };
        let confidence = flow.confidence.map(|confidence| format!("{confidence:?}"));
        let protocol_stack = flow.protocol_stack.iter().map(protocol_name).collect();
```

替换为：

```rust
        let application = flow
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.application());
        let (master_protocol, app_protocol, protocol_stack) = match flow.protocol {
            Some(Protocol::Doh | Protocol::Dot) => (
                Some("TLS".to_string()),
                Some("DoH_DoT".to_string()),
                vec!["TLS".to_string(), "DoH_DoT".to_string()],
            ),
            Some(Protocol::Doq) => (
                Some("QUIC".to_string()),
                Some("DoH_DoT".to_string()),
                vec!["QUIC".to_string(), "DoH_DoT".to_string()],
            ),
            Some(Protocol::HttpConnect) => (
                Some("HTTP_Connect".to_string()),
                None,
                vec!["HTTP_Connect".to_string()],
            ),
            Some(Protocol::HttpProxy) => (
                Some("HTTP_Proxy".to_string()),
                None,
                vec!["HTTP_Proxy".to_string()],
            ),
            Some(protocol) => (
                Some(protocol_name(protocol)),
                application.map(ndpi_compat_app_name),
                flow.protocol_stack.iter().map(protocol_name).collect(),
            ),
            None => (
                None,
                None,
                flow.protocol_stack.iter().map(protocol_name).collect(),
            ),
        };
        let (category, breed) = match flow.protocol {
            Some(protocol) => {
                let (category, breed) = ndpi_compat_classification(protocol, application);
                (Some(category), Some(breed))
            }
            None => (None, None),
        };
        let confidence = flow.confidence.map(|confidence| format!("{confidence:?}"));
```

在 `protocol_name` 中加入：

```rust
        Protocol::HttpConnect => "HTTP_Connect".to_string(),
        Protocol::HttpProxy => "HTTP_Proxy".to_string(),
```

在 `ndpi_compat_classification` 的 `Protocol::Dns` 分支之后加入：

```rust
        Protocol::Doh | Protocol::Dot | Protocol::Doq => {
            ("Network".to_string(), "Acceptable".to_string())
        }
        Protocol::HttpConnect | Protocol::HttpProxy => {
            ("Web".to_string(), "Acceptable".to_string())
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test --features json --test test_flow_export
cargo test --all-features --test test_parity_harness
```

Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/parity.rs tests/test_flow_export.rs
git commit -m "Map DoH/DoT/DoQ and HTTP proxy protocols to nDPI names"
```

---

### Task 7: 语料扩展与 golden 差分

**Files:**
- Modify: `tests/parity/gen_corpus.py:100-210`（TLS/HTTP builders）
- Modify: `tests/parity/gen_corpus.py:465-510`（`CORPUS`）
- Create: `tests/parity/corpus/tls_dot.pcap`、`tls_doh_sni.pcap`、`http_connect.pcap`、`http_proxy.pcap`、`ftp_split_session.pcap`
- Create: `tests/parity/golden/*.ndpi.json`（对应 5 个新语料）
- Test: `tests/test_parity_corpus.rs`

**Interfaces:**
- Consumes: Task 2/3/4/5/6 的分类与 parity 映射。
- Produces: 5 个新 pcap + nDPI golden，现有 corpus runner 自动纳入。

- [ ] **Step 1: Extend the corpus generator**

把 `tests/parity/gen_corpus.py` 的 `tls_client_hello` 改为支持 ALPN：

```python
def tls_client_hello(sni="example.com", alpn=None):
    if sni is None:
        sni_ext = b""
    else:
        name = sni.encode()
        list_len = len(name) + 3
        ext_len = len(name) + 5
        sni_ext = (
            bytes([0x00, 0x00])
            + struct.pack(">H", ext_len)
            + struct.pack(">H", list_len)
            + bytes([0x00])
            + struct.pack(">H", len(name))
            + name
        )
    versions_ext = bytes([0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04])
    alpn_ext = b""
    if alpn is not None:
        proto = alpn.encode()
        alpn_list = bytes([len(proto)]) + proto
        alpn_ext = (
            bytes([0x00, 0x10])
            + struct.pack(">H", len(alpn_list) + 2)
            + struct.pack(">H", len(alpn_list))
            + alpn_list
        )
    extensions = (
        struct.pack(">H", len(sni_ext) + len(versions_ext) + len(alpn_ext))
        + sni_ext
        + versions_ext
        + alpn_ext
    )

    body = (
        bytes([0x03, 0x03])
        + bytes([0x11] * 32)
        + bytes([0x00])
        + struct.pack(">H", 2)
        + bytes([0x13, 0x01])
        + bytes([0x01, 0x00])
        + extensions
    )
    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16, 0x03, 0x01]) + struct.pack(">H", len(handshake)) + handshake
```

把 `build_tls_client_hello` 改为支持端口/ALPN：

```python
def build_tls_client_hello(sni="example.com", alpn=None, sport=443, cport=50001):
    client, server = [192, 168, 1, 1], [10, 0, 0, 1]
    hello = tls_client_hello(sni, alpn)
    cseq, sseq = 2000, 6000
    return [
        (BASE_TS + 0, frame(client, server, 6, tcp(cport, sport, cseq, 0, 0x02))),
        (
            BASE_TS + 10_000,
            frame(server, client, 6, tcp(sport, cport, sseq, cseq + 1, 0x12)),
        ),
        (
            BASE_TS + 20_000,
            frame(client, server, 6, tcp(cport, sport, cseq + 1, sseq + 1, 0x10)),
        ),
        (
            BASE_TS + 30_000,
            frame(
                client,
                server,
                6,
                tcp(cport, sport, cseq + 1, sseq + 1, 0x18, hello),
            ),
        ),
    ]
```

在 `build_ftp` 之后加入：

```python
def build_tls_dot():
    return build_tls_client_hello("dns.google", alpn="dot", sport=853, cport=50005)


def build_tls_doh_sni():
    return build_tls_client_hello("dns.google", sport=443, cport=50006)


def build_http_connect():
    return tcp_session(
        CLIENT,
        SERVER,
        50007,
        8080,
        [
            ("c", b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            ("s", b"HTTP/1.1 200 Connection established\r\n\r\n"),
        ],
    )


def build_http_proxy():
    return tcp_session(
        CLIENT,
        SERVER,
        50008,
        8080,
        [
            ("c", b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            ("s", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"),
        ],
    )


def build_ftp_split_session():
    return tcp_session(
        CLIENT,
        SERVER,
        50009,
        21,
        [
            ("s", b"220 (vsFTPd 3.0.5)\r\n"),
            ("c", b"USER ali"),
            ("c", b"ce\r\n"),
            ("s", b"331 Please specify the password.\r\n"),
            ("c", b"RETR rep"),
            ("c", b"ort.pdf\r\n"),
            ("s", b"150 Opening BINARY mode data connection.\r\n"),
        ],
    )
```

在 `CORPUS` 字典中加入：

```python
    "tls_dot": build_tls_dot,
    "tls_doh_sni": build_tls_doh_sni,
    "http_connect": build_http_connect,
    "http_proxy": build_http_proxy,
    "ftp_split_session": build_ftp_split_session,
```

- [ ] **Step 2: Regenerate corpus**

Run:

```bash
python -I tests/parity/gen_corpus.py
```

Expected: `tests/parity/corpus/` 下新增 5 个 pcap；已有文件内容不变（确定性生成）。

- [ ] **Step 3: Generate nDPI golden with WSL ndpiReader 5.0**

Run:

```bash
wsl.exe bash -lc 'cd /mnt/d/rust_code/rDpi && for n in tls_dot tls_doh_sni http_connect http_proxy ftp_split_session; do /mnt/d/c_code/nDPI-5.0/build/example/ndpiReader -i tests/parity/corpus/$n.pcap -k tests/parity/golden/$n.ndpi.json -K json; done'
```

Expected: `tests/parity/golden/` 下新增 5 个 `.ndpi.json`。

- [ ] **Step 4: Inspect nDPI protocol names**

Run:

```bash
python -I - <<'PY'
import json, pathlib
for name in ["tls_dot", "tls_doh_sni", "http_connect", "http_proxy", "ftp_split_session"]:
    path = pathlib.Path("tests/parity/golden") / f"{name}.ndpi.json"
    for line in path.read_text().splitlines():
        if line.strip():
            record = json.loads(line)
            print(name, "->", record["ndpi"].get("proto"))
            break
PY
```

Expected:

```text
tls_dot -> TLS.DoH_DoT
tls_doh_sni -> TLS.DoH_DoT
http_connect -> HTTP_Connect
http_proxy -> HTTP_Proxy
ftp_split_session -> FTP_CONTROL
```

若输出与预期不符，先按实际输出修正 Task 6 的映射（例如 `HTTP.Connect` 需在 `split_ndpi_protocol` 后调整 `from_flow` 分支），再继续。

- [ ] **Step 5: Run the corpus test**

Run:

```bash
cargo test --all-features --test test_parity_corpus -- --nocapture
```

Expected: 全部 PASS；新用例的 `master/app/category/breed/confidence/risk_gate` 差异为 0。

- [ ] **Step 6: Commit**

```bash
git add tests/parity/gen_corpus.py tests/parity/corpus tests/parity/golden
git commit -m "Add parity corpus cases for DoH/DoT/DoQ and HTTP proxy"
```

---

### Task 8: 文档回写与最终门禁

**Files:**
- Modify: `AGENTS.md:31-55`（F44 条目、测试计数）
- Modify: `AGENTS.md:112`（F 表新增 F44 行）
- Modify: `docs/architecture/modules.md:45-55`（tls/quic/http/ftp 模块说明）
- Modify: `docs/architecture/risks.md`（追加 F44 章节）
- Modify: `docs/architecture/ndpi-pure-rust-plan.md:266-365`（§9 进度与待办）
- Modify: `docs/architecture/protocol-coverage-plan.md`（缺口表与下一步）

**Interfaces:**
- Consumes: 全部实现与测试。
- Produces: 项目认知库与路线图与代码一致。

- [ ] **Step 1: Run the full gate and record counts**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo test
cargo test --all-features
cargo test --features risk
```

Expected: 全部 PASS；记录三项测试的实际用例数（默认 / all-features / risk）。

- [ ] **Step 2: Update `AGENTS.md`**

在关键机制列表（F43 条目之后）加入：

```markdown
- **DoH/DoT/DoQ 子分类 + HTTP CONNECT/Proxy + FTP 有状态会话（F44，2026-11-07）**：不新增 detector——TLS detector 在解析 `TlsMetadata` 后按优先级选协议（ALPN `dot` → `Dot`，SNI 命中 DoH 解析器表 → `Doh`，否则 `Tls`），无 ALPN/SNI 时 TCP 853 端口回退为 `Dot`（`DpiPartial`）；QUIC detector 在 Initial 解出 ALPN 后 `starts_with("doq")` → `Doq`，否则沿用 `Http3`/`Quic`；HTTP detector 按请求方法 `CONNECT` → `HttpConnect`、绝对 URI `http://` → `HttpProxy`。FTP 推广 F43 的 `process()`/`DissectorState` 框架：仅服务端数字响应前缀（2–6）且非 SMTP 端口接管，跨段行重组，`USER` 提取 username、`RETR`/`STOR` 提取 filename，进入 monitoring 持续富化。parity 导出：DoH/DoT → `TLS.DoH_DoT`，DoQ → `QUIC.DoH_DoT`，HTTP CONNECT/Proxy → `HTTP_Connect`/`HTTP_Proxy`；category/breed 对齐 Network/Acceptable、Web/Acceptable。
```

在常用命令的三行测试计数中，替换为 Step 1 记录的实际数字。

在 F 表末尾加入 F44 行：

```markdown
| F44 | 阶段 1 收尾：DoH/DoT/DoQ 子分类 + HTTP CONNECT/Proxy + FTP 有状态会话；TLS ALPN/SNI/853 端口、QUIC ALPN、HTTP 方法/绝对 URI、FTP server-first 行重组 | 中 | ✅ 已完成 2026-11-07（5 个 Protocol 变体 + 5 个语料 golden；默认 / all-features / risk 全绿，详见 risks.md F44） |
```

- [ ] **Step 3: Update `docs/architecture/modules.md`**

把 `tls`、`quic`、`http`、`ftp` 行改为：

```markdown
| tls | tls（DoH/DoT 子分类：ALPN dot / DoH SNI 表 / TCP 853 回退） |
| quic | quic（DoQ 子分类：ALPN starts_with("doq")；crypto.rs Initial 解密 + parser.rs） |
| http | http（HTTP CONNECT / 绝对 URI 代理子分类） |
| proto3 | ftp（F44 有状态跨段行重组 + USER/RETR/STOR 元数据）, sip, rtp, http2（HPACK 元数据，2026-11-05）, websocket（F43，2026-11-06：有状态升级握手重组）, rtmp, socks |
```

（保留原有未涉及的模块描述。）

- [ ] **Step 4: Append F44 section to `docs/architecture/risks.md`**

```markdown
## F44【中】阶段 1 收尾：DoH/DoT/DoQ + HTTP CONNECT/Proxy + FTP 有状态会话（2026-11-07，新功能开发）—— ✅ 已完成

- **背景**：阶段 1（A+B 首批）缺口为 DoH/DoT/DoQ 与 HTTP CONNECT/Proxy；F43 已推广有状态框架但 FTP 仍为无状态单包 detector。
- **实现**：
  - `Protocol` 新增 `Doh`/`Dot`/`Doq`/`HttpConnect`/`HttpProxy`，category/breed 分别为 Dns/Acceptable、Web/Acceptable；规则 JSON 支持对应名称。
  - TLS：`select_tls_protocol` 按 ALPN `dot` → `Dot`、SNI 命中 `doh::is_doh_resolver` → `Doh`、否则 `Tls`；`apply_dot_port_hint` 在 TCP 853 端口把 `Tls` 升级为 `Dot`（`DpiPartial`），有状态 `process` 与无状态 `detect_with_context` 共用。
  - QUIC：`select_quic_protocol` 在 ALPN 以 `doq` 开头时返回 `Doq`（`Dpi`），优先于 HTTP/3 端口逻辑。
  - HTTP：请求方法 `CONNECT` → `HttpConnect`，请求目标以 `http://` 开头 → `HttpProxy`。
  - FTP：`FtpDissectorState{buffer, username, filename}`；仅服务端数字响应前缀（2–6）且非 SMTP 端口接管；跨段行重组；`USER`/`RETR`/`STOR` 提取元数据；`flow.monitoring` 与 `merge_detected_metadata` 支持持续富化。
  - parity：DoH/DoT → `TLS.DoH_DoT`，DoQ → `QUIC.DoH_DoT`，HTTP CONNECT/Proxy → `HTTP_Connect`/`HTTP_Proxy`；5 个新语料与 golden 纳入差分门禁。
- **已知边界**：
  1. DoH 仅靠 SNI 域名表，不识别明文 HTTP `application/dns-message`；无 SNI 的 DoH 漏判（nDPI 还可经证书 SAN 命中）。
  2. DoT 仅端口 853 时置信度为 `DpiPartial`；ALPN `dot` 才是 `Dpi`。
  3. DoQ 依赖 QUIC Initial 解密（`tls` feature）；mid-stream 无 Initial 不分类；ALPN 前缀 `doq` 与 nDPI 一致，`doqfoo` 也会命中。
  4. HTTP CONNECT 不提取 authority/host；HTTP Proxy 仅识别 `http://` 绝对 URI。
  5. FTP 仅 server-first 接管；mid-stream 客户端先发的流保持无状态；username/filename 只保留首个非空值；不保存密码、不建模数据通道/PASV、不支持 FTPS。
  6. 单 flow 仍只允许一个活跃 `DissectorState`。
- **测试**：默认 / all-features / risk 三配置全绿；新增 5 个 pcap + golden 差分用例；fmt/clippy 干净。
```

- [ ] **Step 5: Update the roadmap docs**

在 `docs/architecture/ndpi-pure-rust-plan.md` §8 第 5 条后追加：

```markdown
6. ~~A 组缺口 DoH/DoT/DoQ、HTTP CONNECT/Proxy~~、~~FTP 有状态会话~~ 已完成（F44，2026-11-07）；下一步进入阶段 2（企业协议补齐）。
```

在 §9 的“待办”中删除已完成的 P1 项（SMTP/IMAP/POP3/FTP 多包会话、WebSocket 升级），并注明：

```markdown
- **P1**：全部首批 A 组协议已完成；FTP 有状态会话已由 F44 兑现。剩余：P1 边界项（QUIC 流级风险接入、HTTP/2 CONTINUATION、TLS 大证书、TCP FIN/RST、多活跃状态机）。
```

在 `docs/architecture/protocol-coverage-plan.md` 的 §1 表格后补充：

```markdown
补充：DoH/DoT/DoQ 由 TLS/QUIC detector 子分类产出，HTTP CONNECT/Proxy 由 HTTP detector 子分类产出（F44）；detector 数量不变。
```

并把 §4 P0 表中的 DoH/DoT/DoQ、HTTP CONNECT/Proxy 标记为已覆盖（在“价值”列后加 `✅ F44`）。

- [ ] **Step 6: Run the full gate again**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo test
cargo test --all-features
cargo test --features risk
```

Expected: 全部 PASS。

- [ ] **Step 7: Commit**

```bash
git add AGENTS.md docs/architecture
git commit -m "Document phase 1 closeout protocol additions"
```

---

## Self-Review

- **Spec coverage:** Protocol model → Task 1；DoH/DoT → Task 2；DoQ → Task 3；HTTP CONNECT/Proxy → Task 4；FTP → Task 5；parity → Task 6；corpus → Task 7；docs → Task 8。设计文档 §1-§12 均有对应任务。
- **Placeholder scan:** 已检查；无 TBD/TODO；测试计数在 Task 8 以“运行并记录实际数字”落实。
- **Type consistency:** `FtpDissectorState` 字段名 `buffer`/`username`/`filename`；`FtpMetadata` 字段 `username`/`filename`；`select_quic_protocol` 签名与调用一致；`apply_dot_port_hint` 参数顺序一致；parity 映射名称在 Task 6 与 Task 7 的预期一致。
