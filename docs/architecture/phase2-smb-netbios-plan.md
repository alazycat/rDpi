# 阶段 2 第一批 Implementation Plan：NetBIOS + SMBv1/v2/v3

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增 `smb` feature，实现 NetBIOS（NBNS/NBDS/NBSS）与 SMBv1/v2/3 识别、基础元数据、SMBv1 风险与 nDPI 兼容导出。

**Architecture:** `netbios` 与 `smb` 两个独立模块各一个 detector；SMB detector 按 NBSS 签名选择 `Smb1`/`Smb23`，并用 `process()` 做头部重组与 SMB1 Negotiate 跳过；NetBIOS detector 处理 UDP 137/138 与 TCP 139，TCP 139 复用 `process()` 做会话请求头部重组。

**Tech Stack:** Rust 1.88 / edition 2024；现有 `ProtocolDetector`、`DissectorState`、`Flow`、`parity`、`risk` 模块；`tests/parity/gen_corpus.py` + WSL ndpiReader 5.0。

## Global Constraints

- edition 2024，`rust-version = "1.88"`。
- 不新增外部依赖。
- 中文 doc 注释为主；公开 API 保持现有风格。
- 禁止修改 Registry 现有注册顺序（顺序 = 优先级语义）；本计划只在 SSH 之后、FTP 之前插入 `smb` 块。
- 首字节门契约（F29）：SMB 声明 `0x00` 门并保留覆盖样本测试；NetBIOS 声明 `None`（首字节任意）。
- 不引入分配密集热路径逻辑；有状态路径复用 `Vec<u8>` 缓冲模式。
- 提交信息不加 AI 署名/Co-Authored-By；只提交源码、测试、项目文档。
- 最终门禁：
  `cargo fmt --all -- --check`、
  `cargo clippy --all-features --all-targets -- -D warnings`、
  `cargo test`、
  `cargo test --features smb`、
  `cargo test --all-features`、
  `cargo test --features "risk smb"`。

---

### Task 1: `smb` feature + 协议/元数据/状态枚举 + 规则名称

**Files:**
- Modify: `Cargo.toml`（`[features]`）
- Modify: `src/core/types.rs`（`Protocol`、`Metadata`、元数据结构、`DissectorState`）
- Modify: `src/rule/parser.rs`
- Test: `tests/test_types.rs`
- Test: `tests/test_rule.rs`

**Interfaces:**
- Consumes: 无。
- Produces: `feature = "smb"`；`Protocol::NetBios`/`Smb1`/`Smb23`；`Metadata::NetBios`/`Smb`；`NetBiosService`、`NetBiosMetadata`、`SmbMetadata`；`DissectorState::NetBios`/`Smb`；规则名 `netbios`/`smb1`/`smb23`。

- [ ] **Step 1: Write the failing tests**

在 `tests/test_types.rs` 末尾追加：

```rust
#[cfg(feature = "smb")]
#[test]
fn test_smb_protocol_classification() {
    use rdpi::core::types::{Protocol, ProtocolBreed, ProtocolCategory};

    assert_eq!(Protocol::NetBios.category(), ProtocolCategory::Infrastructure);
    assert_eq!(Protocol::NetBios.breed(), ProtocolBreed::Acceptable);
    assert_eq!(Protocol::Smb1.category(), ProtocolCategory::FileTransfer);
    assert_eq!(Protocol::Smb1.breed(), ProtocolBreed::Dangerous);
    assert_eq!(Protocol::Smb23.category(), ProtocolCategory::FileTransfer);
    assert_eq!(Protocol::Smb23.breed(), ProtocolBreed::Acceptable);
}
```

在 `tests/test_rule.rs` 末尾追加：

```rust
#[cfg(feature = "smb")]
#[test]
fn test_rule_parser_smb_protocol_names() {
    let json = r#"{
        "rules": [
            {"id": "netbios", "protocol": "netbios", "condition": {"dst_port": 137}},
            {"id": "smb1", "protocol": "smb1", "condition": {"dst_port": 445}},
            {"id": "smb23", "protocol": "smb23", "condition": {"dst_port": 446}}
        ]
    }"#;
    let engine = RuleEngine::from_json(json).unwrap();

    let cases = [
        (137, Protocol::NetBios),
        (445, Protocol::Smb1),
        (446, Protocol::Smb23),
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
cargo test --features smb --test test_types test_smb_protocol_classification
cargo test --features "rule smb" --test test_rule test_rule_parser_smb_protocol_names
```

Expected: 编译失败，`no variant named 'NetBios'`。

- [ ] **Step 3: Add the `smb` feature**

在 `Cargo.toml` 的 `[features]` 中 `storage = []` 后加入：

```toml
smb = []       # SMBv1/v2/v3 + NetBIOS
```

- [ ] **Step 4: Add protocol variants and matches**

在 `src/core/types.rs` 的 `Protocol` 枚举中：

- `Dns` 后加入：

```rust
    #[cfg(feature = "smb")]
    NetBios,
```

- `Ftp` 后加入：

```rust
    #[cfg(feature = "smb")]
    Smb1,
    #[cfg(feature = "smb")]
    Smb23,
```

在 `Protocol::category()` 的 DNS 分支后加入：

```rust
            #[cfg(feature = "smb")]
            Protocol::NetBios => ProtocolCategory::Infrastructure,
```

在 FileTransfer 分支（`Protocol::Ftp` 附近）后加入：

```rust
            #[cfg(feature = "smb")]
            Protocol::Smb1 | Protocol::Smb23 => ProtocolCategory::FileTransfer,
```

在 `Protocol::breed()` 的 final `Tcp | Udp | Icmp | Other` arm 之前加入：

```rust
            #[cfg(feature = "smb")]
            Protocol::NetBios | Protocol::Smb23 => ProtocolBreed::Acceptable,
            #[cfg(feature = "smb")]
            Protocol::Smb1 => ProtocolBreed::Dangerous,
```

在 `Metadata` 枚举末尾（`Kerberos` 之后）加入：

```rust
    /// NetBIOS 元数据 (feature: smb)
    #[cfg(feature = "smb")]
    NetBios(NetBiosMetadata),
    /// SMB 元数据 (feature: smb)
    #[cfg(feature = "smb")]
    Smb(SmbMetadata),
```

在 `FtpMetadata` 定义之后加入：

```rust
#[cfg(feature = "smb")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetBiosService {
    NameService,
    DatagramService,
    SessionService,
}

#[cfg(feature = "smb")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct NetBiosMetadata {
    /// 服务类型（NBNS / NBDS / NBSS）
    pub service: NetBiosService,
    /// 解码后的 NetBIOS 名称
    pub name: Option<String>,
    /// NBNS 名称第 16 字节后缀
    pub suffix: Option<u8>,
}

#[cfg(feature = "smb")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct SmbMetadata {
    /// SMB1 command（u8 扩展为 u16）或 SMB2 command（u16 LE）
    pub command: Option<u16>,
    /// NT status（SMB1 @9..13 / SMB2 @12..16，LE）
    pub status: Option<u32>,
}
```

在 `FtpDissectorState` 之后加入：

```rust
/// NetBIOS TCP 139 会话请求头部重组状态
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetBiosDissectorState {
    pub buffer: Vec<u8>,
}

/// SMB TCP 445 头部重组 + SMB1 Negotiate 跳过状态
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmbDissectorState {
    pub buffer: Vec<u8>,
}
```

在 `DissectorState` 枚举的 `Ftp` 之后加入：

```rust
    /// NetBIOS TCP 139 头部重组
    NetBios(NetBiosDissectorState),
    /// SMB TCP 445 头部重组
    Smb(SmbDissectorState),
```

- [ ] **Step 5: Add rule name mappings**

在 `src/rule/parser.rs` 的 `match entry.protocol.to_lowercase().as_str()` 中，`_ => Protocol::Other(0)` 之前加入：

```rust
                    #[cfg(feature = "smb")]
                    "netbios" => Protocol::NetBios,
                    #[cfg(feature = "smb")]
                    "smb1" => Protocol::Smb1,
                    #[cfg(feature = "smb")]
                    "smb23" => Protocol::Smb23,
```

- [ ] **Step 6: Run tests to verify they pass**

Run:

```bash
cargo test --features smb --test test_types
cargo test --features "rule smb" --test test_rule
cargo test --all-features
```

Expected: 全部 PASS。

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml src/core/types.rs src/rule/parser.rs tests/test_types.rs tests/test_rule.rs
git commit -m "Add smb feature and NetBIOS/SMB protocol model"
```

---

### Task 2: NetBIOS parser（NBNS/NBDS/NBSS）

**Files:**
- Create: `src/protocols/netbios/parser.rs`
- Create: `src/protocols/netbios/mod.rs`
- Modify: `src/protocols/mod.rs`（`#[cfg(feature = "smb")] pub mod netbios;`）
- Test: `src/protocols/netbios/parser.rs` 的 `mod tests`

**Interfaces:**
- Consumes: `NetBiosService`（Task 1）。
- Produces:
  - `pub(crate) struct NetBiosParsed { service: NetBiosService, name: Option<String>, suffix: Option<u8> }`
  - `pub(crate) fn parse_nbns(&[u8]) -> Option<NetBiosParsed>`
  - `pub(crate) fn parse_nbds(&[u8]) -> Option<NetBiosParsed>`
  - `pub(crate) fn parse_nbss(&[u8]) -> Option<NetBiosParsed>`
  - `pub(crate) fn parse_nbss_session_message(&[u8]) -> Option<NetBiosParsed>`

- [ ] **Step 1: Write the failing parser tests**

创建 `src/protocols/netbios/parser.rs`，包含以下测试（实现留空会导致编译失败或测试失败）：

```rust
//! NetBIOS parsers (NBNS/NBDS/NBSS).

use crate::core::types::NetBiosService;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetBiosParsed {
    pub service: NetBiosService,
    pub name: Option<String>,
    pub suffix: Option<u8>,
}

fn trim_name(bytes: &[u8]) -> Option<String> {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0 || byte == b' ')
        .unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&bytes[..end]).ok().map(str::to_string)
}

fn decode_nbns_name(encoded: &[u8]) -> Option<[u8; 16]> {
    if encoded.len() != 32 {
        return None;
    }
    let mut decoded = [0u8; 16];
    for (index, pair) in encoded.chunks_exact(2).enumerate() {
        let hi = pair[0].checked_sub(b'A')?;
        let lo = pair[1].checked_sub(b'A')?;
        if hi > 15 || lo > 15 {
            return None;
        }
        decoded[index] = (hi << 4) | lo;
    }
    Some(decoded)
}

pub(crate) fn parse_nbns(payload: &[u8]) -> Option<NetBiosParsed> {
    if payload.len() < 50 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let nscount = u16::from_be_bytes([payload[8], payload[9]]);
    let arcount = u16::from_be_bytes([payload[10], payload[11]]);
    let query = qdcount == 1 && ancount == 0 && nscount == 0 && arcount <= 1;
    let response = ancount >= 1 && qdcount <= 1 && nscount == 0;
    if !query && !response {
        return None;
    }
    if payload[12] != 0x20 {
        return None;
    }
    let decoded = decode_nbns_name(&payload[13..45])?;
    if payload[45] != 0x00 {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[46], payload[47]]);
    let qclass = u16::from_be_bytes([payload[48], payload[49]]);
    if !matches!(qtype, 0x0020 | 0x0002) || qclass != 0x0001 {
        return None;
    }
    Some(NetBiosParsed {
        service: NetBiosService::NameService,
        name: trim_name(&decoded[..15]),
        suffix: Some(decoded[15]),
    })
}

pub(crate) fn parse_nbds(payload: &[u8]) -> Option<NetBiosParsed> {
    if payload.len() < 46 {
        return None;
    }
    if !(0x10..=0x16).contains(&payload[0]) {
        return None;
    }
    let dgm_len = u16::from_be_bytes([payload[10], payload[11]]) as usize;
    if dgm_len != payload.len() - 14 {
        return None;
    }
    Some(NetBiosParsed {
        service: NetBiosService::DatagramService,
        name: trim_name(&payload[14..30]),
        suffix: None,
    })
}

pub(crate) fn parse_nbss(payload: &[u8]) -> Option<NetBiosParsed> {
    if payload.len() < 37 || payload[0] != 0x81 {
        return None;
    }
    let length = u16::from_be_bytes([payload[2], payload[3]]) & 0x3FFF;
    if length < 33 {
        return None;
    }
    Some(NetBiosParsed {
        service: NetBiosService::SessionService,
        name: trim_name(&payload[4..20]),
        suffix: None,
    })
}

pub(crate) fn parse_nbss_session_message(payload: &[u8]) -> Option<NetBiosParsed> {
    if payload.len() < 8 || payload[0] != 0x00 {
        return None;
    }
    let signature = &payload[4..8];
    if signature != &b"\xFFSMB"[..] && signature != &b"\xFESMB"[..] {
        return None;
    }
    Some(NetBiosParsed {
        service: NetBiosService::SessionService,
        name: None,
        suffix: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_name(name: &str, suffix: u8) -> Vec<u8> {
        let mut padded = name.as_bytes().iter().copied().take(15).collect::<Vec<_>>();
        padded.resize(15, b' ');
        padded.push(suffix);
        let mut out = Vec::with_capacity(32);
        for byte in padded {
            out.push(b'A' + (byte >> 4));
            out.push(b'A' + (byte & 0x0F));
        }
        out
    }

    fn nbns_query() -> Vec<u8> {
        let mut payload = vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        payload.push(0x20);
        payload.extend(encode_name("SERVER", 0x20));
        payload.push(0x00);
        payload.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
        payload
    }

    fn nbds_datagram() -> Vec<u8> {
        let mut payload = vec![0x10, 0x00, 0x12, 0x34, 192, 168, 1, 1, 0x00, 0x8A];
        let body_len = 16 + 16 + 13;
        payload.extend_from_slice(&(body_len as u16).to_be_bytes());
        payload.extend_from_slice(&[0x00, 0x00]);
        payload.extend_from_slice(b"SERVER          ");
        payload.extend_from_slice(b"CLIENT          ");
        payload.extend_from_slice(b"hello netbios");
        payload
    }

    fn nbss_session_request() -> Vec<u8> {
        let mut payload = vec![0x81, 0x00, 0x00, 0x44];
        payload.extend_from_slice(b"SERVER          ");
        payload.extend_from_slice(b"CLIENT          ");
        payload.extend_from_slice(&[0x20]);
        payload.extend_from_slice(&[0x00; 35]);
        payload
    }

    #[test]
    fn parses_nbns_query() {
        let parsed = parse_nbns(&nbns_query()).unwrap();
        assert_eq!(parsed.service, NetBiosService::NameService);
        assert_eq!(parsed.name.as_deref(), Some("SERVER"));
        assert_eq!(parsed.suffix, Some(0x20));
    }

    #[test]
    fn rejects_malformed_nbns() {
        assert!(parse_nbns(b"").is_none());
        let mut payload = nbns_query();
        payload[13] = b'Z'; // 非 'A'..='P'
        assert!(parse_nbns(&payload).is_none());
        let mut payload = nbns_query();
        payload[4] = 0;
        payload[5] = 2; // qdcount=2
        assert!(parse_nbns(&payload).is_none());
    }

    #[test]
    fn parses_nbds_datagram() {
        let parsed = parse_nbds(&nbds_datagram()).unwrap();
        assert_eq!(parsed.service, NetBiosService::DatagramService);
        assert_eq!(parsed.name.as_deref(), Some("SERVER"));
        assert_eq!(parsed.suffix, None);
    }

    #[test]
    fn rejects_nbds_length_mismatch() {
        let mut payload = nbds_datagram();
        payload[10] = 0xFF;
        assert!(parse_nbds(&payload).is_none());
    }

    #[test]
    fn parses_nbss_session_request() {
        let payload = nbss_session_request();
        assert_eq!(payload.len(), 72);
        let parsed = parse_nbss(&payload).unwrap();
        assert_eq!(parsed.service, NetBiosService::SessionService);
        assert_eq!(parsed.name.as_deref(), Some("SERVER"));
    }

    #[test]
    fn parses_nbss_session_message_with_smb() {
        let payload = [0x00, 0x00, 0x00, 0x20, 0xFF, b'S', b'M', b'B'];
        let parsed = parse_nbss_session_message(&payload).unwrap();
        assert_eq!(parsed.service, NetBiosService::SessionService);
        assert!(parsed.name.is_none());
        assert!(parse_nbss_session_message(&[0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00]).is_none());
    }
}
```

创建 `src/protocols/netbios/mod.rs`：

```rust
//! NetBIOS protocol module (feature: smb)

mod parser;
```

在 `src/protocols/mod.rs` 的 `pub mod nfs;` 附近加入：

```rust
#[cfg(feature = "smb")]
pub mod netbios;
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test --features smb --lib protocols::netbios::parser::tests
```

Expected: 编译失败（`NetBiosService` / parser 未定义），或测试断言失败。

- [ ] **Step 3: Implement parser code**

按 Step 1 中的代码完整实现（`parse_nbns` / `parse_nbds` / `parse_nbss` / `parse_nbss_session_message` / `trim_name` / `decode_nbns_name`）。注意 `NetBiosService` 来自 `crate::core::types`（Task 1）。

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test --features smb --lib protocols::netbios::parser::tests
cargo test --features smb
```

Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/protocols/netbios/parser.rs src/protocols/netbios/mod.rs src/protocols/mod.rs
git commit -m "Add NetBIOS NBNS/NBDS/NBSS parsers"
```

---

### Task 3: NetBIOS detector（无状态 + TCP 139 有状态）

**Files:**
- Create: `src/protocols/netbios/detector.rs`
- Modify: `src/protocols/netbios/mod.rs`
- Test: `src/protocols/netbios/detector.rs` 的 `mod tests`

**Interfaces:**
- Consumes: `NetBiosParsed` + parser functions（Task 2）；`DissectorState::NetBios`（Task 1）。
- Produces: `NetBiosDetector`（实现 `ProtocolDetector`），在端口 137/138/139 上产出 `Protocol::NetBios`。

- [ ] **Step 1: Write the failing detector tests**

在 `src/protocols/netbios/detector.rs` 中创建测试（实现留空）：

```rust
use super::parser::{self, NetBiosParsed};
use crate::core::types::*;
use crate::protocols::ProtocolDetector;

const NETBIOS_MAX_BUFFER_BYTES: usize = 4096;

pub struct NetBiosDetector;

impl Default for NetBiosDetector {
    fn default() -> Self {
        Self
    }
}

impl NetBiosDetector {
    pub fn new() -> Self {
        Self
    }
}

fn result_from(parsed: NetBiosParsed) -> DetectionResult {
    DetectionResult::new(Protocol::NetBios).with_metadata(Metadata::NetBios(NetBiosMetadata {
        service: parsed.service,
        name: parsed.name,
        suffix: parsed.suffix,
    }))
}

fn parse_any(payload: &[u8]) -> Option<NetBiosParsed> {
    parser::parse_nbns(payload)
        .or_else(|| parser::parse_nbds(payload))
        .or_else(|| parser::parse_nbss(payload))
        .or_else(|| parser::parse_nbss_session_message(payload))
}

impl ProtocolDetector for NetBiosDetector {
    fn name(&self) -> &'static str {
        "netbios"
    }

    /// 首字节任意：NBNS transaction ID、NBDS type、NBSS type 均不固定。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        None
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        parse_any(payload).map(result_from)
    }

    fn detect_with_context(
        &self,
        payload: &[u8],
        ctx: &DetectContext,
    ) -> Option<DetectionResult> {
        let parsed = if ctx.src_port == 137 || ctx.dst_port == 137 {
            parser::parse_nbns(payload)
        } else if ctx.src_port == 138 || ctx.dst_port == 138 {
            parser::parse_nbds(payload)
        } else if ctx.src_port == 139 || ctx.dst_port == 139 {
            parser::parse_nbss(payload)
                .or_else(|| parser::parse_nbss_session_message(payload))
        } else {
            None
        }?;
        Some(result_from(parsed))
    }

    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        _direction: Direction,
        ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        if ctx.src_port != 139 && ctx.dst_port != 139 {
            return None;
        }
        match state {
            DissectorState::None => {
                if payload.is_empty() {
                    return None;
                }
                if payload[0] != 0x81 && payload[0] != 0x00 {
                    return None;
                }
                *state = DissectorState::NetBios(NetBiosDissectorState::default());
            }
            DissectorState::NetBios(_) => {}
            _ => return None,
        }
        let DissectorState::NetBios(nb) = state else {
            return None;
        };
        if nb.buffer.len() + payload.len() > NETBIOS_MAX_BUFFER_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        nb.buffer.extend_from_slice(payload);

        let parsed = match nb.buffer[0] {
            0x81 => {
                if nb.buffer.len() < 37 {
                    return Some(DissectorOutcome::Continue);
                }
                parser::parse_nbss(&nb.buffer)
            }
            0x00 => {
                if nb.buffer.len() < 8 {
                    return Some(DissectorOutcome::Continue);
                }
                parser::parse_nbss_session_message(&nb.buffer)
            }
            _ => None,
        };

        match parsed {
            Some(parsed) => {
                nb.buffer.clear();
                Some(DissectorOutcome::Classified(result_from(parsed)))
            }
            None => Some(DissectorOutcome::GiveUp),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(src_port: u16, dst_port: u16) -> DetectContext {
        DetectContext {
            src_port,
            dst_port,
            is_http3_port: false,
        }
    }

    fn nbns_query() -> Vec<u8> {
        let mut name_bytes = b"SERVER".to_vec();
        name_bytes.resize(15, b' ');
        name_bytes.push(0x20);
        let mut name = Vec::new();
        for byte in name_bytes {
            name.push(b'A' + (byte >> 4));
            name.push(b'A' + (byte & 0x0F));
        }
        let mut payload = vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        payload.push(0x20);
        payload.extend(name);
        payload.push(0x00);
        payload.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
        payload
    }

    fn nbss_request() -> Vec<u8> {
        let mut payload = vec![0x81, 0x00, 0x00, 0x44];
        payload.extend_from_slice(b"SERVER          ");
        payload.extend_from_slice(b"CLIENT          ");
        payload.push(0x20);
        payload.extend_from_slice(&[0x00; 35]);
        payload
    }

    #[test]
    fn detects_nbns_on_137() {
        let detector = NetBiosDetector::new();
        let result = detector
            .detect_with_context(&nbns_query(), &ctx(50010, 137))
            .unwrap();
        assert_eq!(result.protocol, Protocol::NetBios);
        match result.metadata {
            Metadata::NetBios(meta) => {
                assert_eq!(meta.service, NetBiosService::NameService);
                assert_eq!(meta.name.as_deref(), Some("SERVER"));
                assert_eq!(meta.suffix, Some(0x20));
            }
            other => panic!("expected NetBios metadata, got {other:?}"),
        }
    }

    #[test]
    fn ignores_nbns_on_other_port() {
        let detector = NetBiosDetector::new();
        assert!(detector
            .detect_with_context(&nbns_query(), &ctx(50010, 53))
            .is_none());
    }

    #[test]
    fn detects_nbss_on_139() {
        let detector = NetBiosDetector::new();
        let result = detector
            .detect_with_context(&nbss_request(), &ctx(50000, 139))
            .unwrap();
        assert_eq!(result.protocol, Protocol::NetBios);
        match result.metadata {
            Metadata::NetBios(meta) => {
                assert_eq!(meta.service, NetBiosService::SessionService);
                assert_eq!(meta.name.as_deref(), Some("SERVER"));
            }
            other => panic!("expected NetBios metadata, got {other:?}"),
        }
    }

    #[test]
    fn process_reassembles_split_nbss_request() {
        let detector = NetBiosDetector::new();
        let mut state = DissectorState::None;
        let c = ctx(50000, 139);
        let payload = nbss_request();

        let first = detector
            .process(&mut state, &payload[..4], Direction::Forward, &c)
            .unwrap();
        assert!(matches!(first, DissectorOutcome::Continue));

        let second = detector
            .process(&mut state, &payload[4..], Direction::Forward, &c)
            .unwrap();
        match second {
            DissectorOutcome::Classified(result) => {
                assert_eq!(result.protocol, Protocol::NetBios);
            }
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn process_ignores_non_139_port() {
        let detector = NetBiosDetector::new();
        let mut state = DissectorState::None;
        assert!(detector
            .process(
                &mut state,
                &nbss_request(),
                Direction::Forward,
                &ctx(50000, 445)
            )
            .is_none());
        assert_eq!(state, DissectorState::None);
    }

    #[test]
    fn process_gives_up_on_unknown_type() {
        let detector = NetBiosDetector::new();
        let mut state = DissectorState::None;
        detector
            .process(
                &mut state,
                &[0x00, 0x00, 0x00, 0x20],
                Direction::Forward,
                &ctx(50000, 139),
            )
            .unwrap();
        let outcome = detector
            .process(
                &mut state,
                b"XXXX",
                Direction::Forward,
                &ctx(50000, 139),
            )
            .unwrap();
        assert!(matches!(outcome, DissectorOutcome::GiveUp));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test --features smb --lib protocols::netbios::detector::tests
```

Expected: 编译失败（`NetBiosDetector` / `DissectorState::NetBios` 未接入），或断言失败。

- [ ] **Step 3: Wire the detector module**

把 `src/protocols/netbios/mod.rs` 改为：

```rust
//! NetBIOS protocol module (feature: smb)

mod detector;
mod parser;

pub use detector::NetBiosDetector;
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test --features smb --lib protocols::netbios
cargo test --features smb
```

Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/protocols/netbios/detector.rs src/protocols/netbios/mod.rs
git commit -m "Add NetBIOS detector with TCP 139 reassembly"
```

---

### Task 4: SMB parser（NBSS / SMB1 / SMB2）

**Files:**
- Create: `src/protocols/smb/parser.rs`
- Create: `src/protocols/smb/mod.rs`
- Modify: `src/protocols/mod.rs`（`#[cfg(feature = "smb")] pub mod smb;`）
- Test: `src/protocols/smb/parser.rs` 的 `mod tests`

**Interfaces:**
- Consumes: 无（`SmbVersion`/`SmbHeader` 为模块内部类型）。
- Produces:
  - `pub(crate) enum SmbVersion { V1, V23 }`
  - `pub(crate) struct SmbHeader { version, command: Option<u16>, status: Option<u32> }`
  - `pub(crate) fn parse_nbss_length(&[u8]) -> Option<usize>`
  - `pub(crate) fn parse_smb(&[u8]) -> Option<SmbHeader>`
  - `pub(crate) fn is_smb1_trans(&[u8]) -> bool`

- [ ] **Step 1: Write the failing parser tests**

创建 `src/protocols/smb/parser.rs`：

```rust
//! SMB parsers (NBSS + SMB1/SMB2 headers).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SmbVersion {
    V1,
    V23,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SmbHeader {
    pub version: SmbVersion,
    pub command: Option<u16>,
    pub status: Option<u32>,
}

pub(crate) fn parse_nbss_length(payload: &[u8]) -> Option<usize> {
    if payload.len() < 4 || payload[0] != 0x00 {
        return None;
    }
    let length = ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | payload[3] as usize;
    if length < 4 {
        return None;
    }
    Some(length)
}

pub(crate) fn parse_smb(payload: &[u8]) -> Option<SmbHeader> {
    parse_nbss_length(payload)?;
    if payload.len() < 8 {
        return None;
    }
    let signature = &payload[4..8];
    if signature == &b"\xFFSMB"[..] {
        let command = payload.get(8).copied()? as u16;
        let status = payload.get(9..13).map(|bytes| {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        });
        Some(SmbHeader {
            version: SmbVersion::V1,
            command: Some(command),
            status,
        })
    } else if signature == &b"\xFESMB"[..] {
        let status = payload.get(12..16).map(|bytes| {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        });
        let command = payload
            .get(16..18)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
        Some(SmbHeader {
            version: SmbVersion::V23,
            command,
            status,
        })
    } else {
        None
    }
}

pub(crate) fn is_smb1_trans(payload: &[u8]) -> bool {
    parse_smb(payload).is_some_and(|header| {
        header.version == SmbVersion::V1 && header.command == Some(0x25)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nbss(payload: &[u8]) -> Vec<u8> {
        let length = payload.len();
        let mut out = vec![0x00, (length >> 16) as u8, (length >> 8) as u8, length as u8];
        out.extend_from_slice(payload);
        out
    }

    fn smb1(command: u8) -> Vec<u8> {
        let mut smb = b"\xFFSMB".to_vec();
        smb.push(command);
        smb.extend_from_slice(&0u32.to_le_bytes());
        smb.resize(32, 0);
        nbss(&smb)
    }

    fn smb2(command: u16) -> Vec<u8> {
        let mut smb = b"\xFESMB".to_vec();
        smb.extend_from_slice(&64u16.to_le_bytes());
        smb.extend_from_slice(&1u16.to_le_bytes());
        smb.extend_from_slice(&0u32.to_le_bytes());
        smb.extend_from_slice(&command.to_le_bytes());
        smb.resize(64, 0);
        nbss(&smb)
    }

    #[test]
    fn parses_smb1() {
        let payload = smb1(0x73);
        let header = parse_smb(&payload).unwrap();
        assert_eq!(header.version, SmbVersion::V1);
        assert_eq!(header.command, Some(0x73));
    }

    #[test]
    fn parses_smb23() {
        let payload = smb2(0x0000);
        let header = parse_smb(&payload).unwrap();
        assert_eq!(header.version, SmbVersion::V23);
        assert_eq!(header.command, Some(0x0000));
        assert_eq!(header.status, Some(0));
    }

    #[test]
    fn rejects_unknown_signature() {
        let payload = nbss(b"XXXX");
        assert!(parse_smb(&payload).is_none());
    }

    #[test]
    fn detects_smb1_trans() {
        assert!(is_smb1_trans(&smb1(0x25)));
        assert!(!is_smb1_trans(&smb1(0x73)));
        assert!(!is_smb1_trans(&smb2(0x0000)));
    }
}
```

创建 `src/protocols/smb/mod.rs`：

```rust
//! SMB protocol module (feature: smb)

pub(crate) mod parser;
```

在 `src/protocols/mod.rs` 的 `pub mod netbios;` 后加入：

```rust
#[cfg(feature = "smb")]
pub mod smb;
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test --features smb --lib protocols::smb::parser::tests
```

Expected: 编译失败或测试失败。

- [ ] **Step 3: Implement parser code**

按 Step 1 中的代码完整实现。

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test --features smb --lib protocols::smb
cargo test --features smb
```

Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/protocols/smb/parser.rs src/protocols/smb/mod.rs src/protocols/mod.rs
git commit -m "Add SMB NBSS/SMB1/SMB2 header parsers"
```

---

### Task 5: SMB detector（无状态 + 有状态 Negotiate 跳过/头部重组）

**Files:**
- Create: `src/protocols/smb/detector.rs`
- Modify: `src/protocols/smb/mod.rs`
- Test: `src/protocols/smb/detector.rs` 的 `mod tests`

**Interfaces:**
- Consumes: `parse_nbss_length` / `parse_smb` / `SmbHeader` / `SmbVersion`（Task 4）；`DissectorState::Smb`（Task 1）。
- Produces: `SmbDetector`（实现 `ProtocolDetector`），端口 445 上产出 `Smb1`/`Smb23`。

- [ ] **Step 1: Write the failing detector tests**

创建 `src/protocols/smb/detector.rs`：

```rust
use super::parser::{self, SmbHeader, SmbVersion};
use crate::core::types::*;
use crate::protocols::ProtocolDetector;

const SMB_MAX_BUFFER_BYTES: usize = 64 * 1024;

pub struct SmbDetector;

impl Default for SmbDetector {
    fn default() -> Self {
        Self
    }
}

impl SmbDetector {
    pub fn new() -> Self {
        Self
    }
}

fn result_from(header: SmbHeader) -> DetectionResult {
    let protocol = match header.version {
        SmbVersion::V1 => Protocol::Smb1,
        SmbVersion::V23 => Protocol::Smb23,
    };
    DetectionResult::new(protocol).with_metadata(Metadata::Smb(SmbMetadata {
        command: header.command,
        status: header.status,
    }))
}

fn is_negotiate(header: &SmbHeader) -> bool {
    header.version == SmbVersion::V1 && header.command == Some(0x72)
}

impl ProtocolDetector for SmbDetector {
    fn name(&self) -> &'static str {
        "smb"
    }

    /// 首字节门：NBSS session message type 恒为 0x00。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x00u8, 0x00u8)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let message_len = parser::parse_nbss_length(payload)?;
        if message_len + 4 < payload.len() {
            return None;
        }
        let header = parser::parse_smb(payload)?;
        if is_negotiate(&header) {
            return None;
        }
        Some(result_from(header))
    }

    fn detect_with_context(
        &self,
        payload: &[u8],
        ctx: &DetectContext,
    ) -> Option<DetectionResult> {
        if ctx.src_port != 445 && ctx.dst_port != 445 {
            return None;
        }
        self.detect(payload)
    }

    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        _direction: Direction,
        ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        if ctx.src_port != 445 && ctx.dst_port != 445 {
            return None;
        }
        match state {
            DissectorState::None => {
                if payload.first() != Some(&0x00) {
                    return None;
                }
                *state = DissectorState::Smb(SmbDissectorState::default());
            }
            DissectorState::Smb(_) => {}
            _ => return None,
        }
        let DissectorState::Smb(smb) = state else {
            return None;
        };
        if smb.buffer.len() + payload.len() > SMB_MAX_BUFFER_BYTES {
            return Some(DissectorOutcome::GiveUp);
        }
        smb.buffer.extend_from_slice(payload);

        loop {
            let message_len = match parser::parse_nbss_length(&smb.buffer) {
                Some(length) => length,
                None => {
                    if smb.buffer.len() < 4 {
                        return Some(DissectorOutcome::Continue);
                    }
                    return Some(DissectorOutcome::GiveUp);
                }
            };
            if smb.buffer.len() < 8 {
                return Some(DissectorOutcome::Continue);
            }
            let is_v1 = &smb.buffer[4..8] == &b"\xFFSMB"[..];
            if is_v1 && smb.buffer.len() < 9 {
                return Some(DissectorOutcome::Continue);
            }

            let available = smb.buffer.len().min(4 + message_len);
            let header = match parser::parse_smb(&smb.buffer[..available]) {
                Some(header) => header,
                None => return Some(DissectorOutcome::GiveUp),
            };

            if is_negotiate(&header) {
                if smb.buffer.len() < 4 + message_len {
                    return Some(DissectorOutcome::Continue);
                }
                smb.buffer.drain(..4 + message_len);
                if smb.buffer.is_empty() {
                    return Some(DissectorOutcome::Continue);
                }
                continue;
            }

            smb.buffer.clear();
            return Some(DissectorOutcome::Classified(result_from(header)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(src_port: u16, dst_port: u16) -> DetectContext {
        DetectContext {
            src_port,
            dst_port,
            is_http3_port: false,
        }
    }

    fn nbss(payload: &[u8]) -> Vec<u8> {
        let length = payload.len();
        let mut out = vec![0x00, (length >> 16) as u8, (length >> 8) as u8, length as u8];
        out.extend_from_slice(payload);
        out
    }

    fn smb1(command: u8) -> Vec<u8> {
        let mut smb = b"\xFFSMB".to_vec();
        smb.push(command);
        smb.extend_from_slice(&0u32.to_le_bytes());
        smb.resize(32, 0);
        nbss(&smb)
    }

    fn smb2(command: u16) -> Vec<u8> {
        let mut smb = b"\xFESMB".to_vec();
        smb.extend_from_slice(&64u16.to_le_bytes());
        smb.extend_from_slice(&1u16.to_le_bytes());
        smb.extend_from_slice(&0u32.to_le_bytes());
        smb.extend_from_slice(&command.to_le_bytes());
        smb.resize(64, 0);
        nbss(&smb)
    }

    #[test]
    fn detects_smb1_session_setup() {
        let detector = SmbDetector::new();
        let result = detector
            .detect_with_context(&smb1(0x73), &ctx(50000, 445))
            .unwrap();
        assert_eq!(result.protocol, Protocol::Smb1);
        match result.metadata {
            Metadata::Smb(meta) => assert_eq!(meta.command, Some(0x73)),
            other => panic!("expected Smb metadata, got {other:?}"),
        }
    }

    #[test]
    fn detects_smb23_negotiate() {
        let detector = SmbDetector::new();
        let result = detector
            .detect_with_context(&smb2(0x0000), &ctx(50000, 445))
            .unwrap();
        assert_eq!(result.protocol, Protocol::Smb23);
    }

    #[test]
    fn stateless_skips_smb1_negotiate() {
        let detector = SmbDetector::new();
        assert!(detector
            .detect_with_context(&smb1(0x72), &ctx(50000, 445))
            .is_none());
    }

    #[test]
    fn ignores_non_445_port() {
        let detector = SmbDetector::new();
        assert!(detector
            .detect_with_context(&smb1(0x73), &ctx(50000, 139))
            .is_none());
    }

    #[test]
    fn process_skips_negotiate_then_classifies_setup() {
        let detector = SmbDetector::new();
        let mut state = DissectorState::None;
        let c = ctx(50000, 445);

        let outcome = detector
            .process(&mut state, &smb1(0x72), Direction::Forward, &c)
            .unwrap();
        assert!(matches!(outcome, DissectorOutcome::Continue));

        let outcome = detector
            .process(&mut state, &smb1(0x73), Direction::Forward, &c)
            .unwrap();
        match outcome {
            DissectorOutcome::Classified(result) => {
                assert_eq!(result.protocol, Protocol::Smb1);
            }
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn process_reassembles_split_header() {
        let detector = SmbDetector::new();
        let mut state = DissectorState::None;
        let c = ctx(50000, 445);
        let payload = smb2(0x0000);

        let outcome = detector
            .process(&mut state, &payload[..2], Direction::Forward, &c)
            .unwrap();
        assert!(matches!(outcome, DissectorOutcome::Continue));

        let outcome = detector
            .process(&mut state, &payload[2..], Direction::Forward, &c)
            .unwrap();
        match outcome {
            DissectorOutcome::Classified(result) => {
                assert_eq!(result.protocol, Protocol::Smb23);
            }
            other => panic!("expected Classified, got {other:?}"),
        }
    }

    #[test]
    fn process_gives_up_on_unknown_signature() {
        let detector = SmbDetector::new();
        let mut state = DissectorState::None;
        let c = ctx(50000, 445);
        let payload = nbss(b"XXXXXXXX");
        let outcome = detector
            .process(&mut state, &payload, Direction::Forward, &c)
            .unwrap();
        assert!(matches!(outcome, DissectorOutcome::GiveUp));
    }

    #[test]
    fn first_byte_gate_covers_valid_sample() {
        use crate::protocols::ProtocolDetector;
        let detector = SmbDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = smb1(0x73);
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test --features smb --lib protocols::smb::detector::tests
```

Expected: 编译失败或测试失败。

- [ ] **Step 3: Wire the detector module**

把 `src/protocols/smb/mod.rs` 改为：

```rust
//! SMB protocol module (feature: smb)

mod detector;
pub(crate) mod parser;

pub use detector::SmbDetector;
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
cargo test --features smb --lib protocols::smb
cargo test --features smb
```

Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/protocols/smb/detector.rs src/protocols/smb/mod.rs
git commit -m "Add SMB detector with negotiate skipping and header reassembly"
```

---

### Task 6: 注册、HTTP match、CLI 集成

**Files:**
- Modify: `src/protocols/mod.rs`（`register_defaults`）
- Modify: `src/protocols/http/detector.rs`（`DissectorState` match）
- Modify: `src/bin/rdpi.rs`（`print_detection`）
- Test: 现有 `cargo test --features smb` + 新增注册冒烟测试

**Interfaces:**
- Consumes: `NetBiosDetector` / `SmbDetector`（Task 3/5）。
- Produces: `smb` feature 下两个 detector 出现在默认 Registry；CLI 显示 NetBIOS 名称。

- [ ] **Step 1: Write the failing integration test**

在 `src/protocols/mod.rs` 的 `mod gate_tests` 之外新增测试模块（文件末尾）：

```rust
#[cfg(all(test, feature = "smb"))]
mod smb_registry_tests {
    use super::*;

    #[test]
    fn test_smb_detectors_registered() {
        // 子模块可访问 `Registry.detectors` 私有字段（同文件、后代模块）
        let registry = Registry::default();
        let names: Vec<&str> = registry
            .detectors
            .iter()
            .map(|entry| entry.detector.name())
            .collect();
        assert!(names.contains(&"netbios"), "netbios detector must be registered");
        assert!(names.contains(&"smb"), "smb detector must be registered");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test --features smb --lib protocols::smb_registry_tests
```

Expected: FAIL（`netbios`/`smb` 未注册）。

- [ ] **Step 3: Register the detectors**

在 `src/protocols/mod.rs` 的 `register_defaults` 中，`ssh::register(_registry);` 之后、`ftp::register(_registry);` 之前加入：

```rust
    #[cfg(feature = "smb")]
    {
        netbios::register(_registry);
        smb::register(_registry);
    }
```

把 `register_defaults` 顶部注释更新为：

```rust
/// 注册顺序：QUIC → DTLS → TLS → SSH → (NetBIOS → SMB) → FTP → ...（按特异性递减）
```

在 `src/protocols/netbios/mod.rs` 末尾加入：

```rust
use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(NetBiosDetector::new()));
}
```

在 `src/protocols/smb/mod.rs` 末尾加入：

```rust
use crate::protocols::Registry;

pub fn register(registry: &mut Registry) {
    registry.register(Box::new(SmbDetector::new()));
}
```

- [ ] **Step 4: Add HTTP match arms**

在 `src/protocols/http/detector.rs` 的显式 `DissectorState` match 中，`DissectorState::Ftp(_)` 后加入：

```rust
            | DissectorState::NetBios(_)
            | DissectorState::Smb(_) => {
                return None;
            }
```

- [ ] **Step 5: Add CLI display**

在 `src/bin/rdpi.rs` 的 `print_detection` 元数据 match 中，`Smtp` 分支后加入：

```rust
        #[cfg(feature = "smb")]
        rdpi::Metadata::NetBios(nb) => nb.name.as_deref().unwrap_or(""),
        #[cfg(feature = "smb")]
        rdpi::Metadata::Smb(_) => "",
```

- [ ] **Step 6: Run tests to verify they pass**

Run:

```bash
cargo test --features smb
cargo test --all-features
```

Expected: 全部 PASS。

- [ ] **Step 7: Commit**

```bash
git add src/protocols/mod.rs src/protocols/netbios/mod.rs src/protocols/smb/mod.rs src/protocols/http/detector.rs src/bin/rdpi.rs
git commit -m "Register NetBIOS and SMB detectors"
```

---

### Task 7: SMBv1 风险 + Parity 映射

**Files:**
- Modify: `src/risk/types.rs`（`RiskFlag`）
- Create: `src/risk/processors/smb.rs`
- Modify: `src/risk/processors/mod.rs`
- Modify: `src/parity.rs`（`from_flow`、`protocol_name`、`ndpi_compat_classification`、`ndpi_compat_risk_name`）
- Modify: `tests/parity/mod.rs`（`NDPI_RISK_ALIASES`）
- Test: `src/risk/types.rs`、`src/risk/processors/smb.rs`、`tests/test_flow_export.rs`

**Interfaces:**
- Consumes: `Protocol::Smb1`/`Smb23`（Task 1）、`crate::protocols::smb::parser::is_smb1_trans`（Task 4）。
- Produces: `RiskFlag::SmbInsecureVersion`；`SmbRiskProcessor`；parity master/app/stack 与 category/breed；风险名别名。

- [ ] **Step 1: Write the failing tests**

在 `src/risk/types.rs` 的 `mod tests` 中追加：

```rust
    #[test]
    fn test_smb_insecure_version_metadata() {
        assert_eq!(
            RiskFlag::SmbInsecureVersion.default_severity(),
            RiskSeverity::High
        );
        assert_eq!(RiskFlag::SmbInsecureVersion.name(), "smb_insecure_version");
    }
```

在 `src/risk/processors/smb.rs` 中创建（实现留空）：

```rust
//! SMB risk processor (`feature: smb`)
//!
//! SMBv1 是已知不安全版本（WannaCry/EternalBlue）；nDPI 5.0 以
//! `NDPI_SMB_INSECURE_VERSION`（HIGH）报告。

use crate::core::flow::Flow;
use crate::core::types::Protocol;
use crate::parser::ParsedPacket;
use crate::protocols::smb::parser;
use crate::risk::RiskProcessor;
use crate::risk::types::{RiskFlag, RiskResult, RiskSeverity};

pub struct SmbRiskProcessor;

impl SmbRiskProcessor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SmbRiskProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskProcessor for SmbRiskProcessor {
    fn name(&self) -> &'static str {
        "smb_risk"
    }

    fn analyze_packet(&self, parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
        if flow.protocol != Some(Protocol::Smb1) {
            return Vec::new();
        }
        if parser::is_smb1_trans(&parsed.payload) {
            return Vec::new();
        }
        if flow
            .risks
            .iter()
            .any(|risk| risk.flag == RiskFlag::SmbInsecureVersion)
        {
            return Vec::new();
        }
        vec![RiskResult::new(
            RiskFlag::SmbInsecureVersion,
            RiskSeverity::High,
            "SMBv1 is insecure and vulnerable to known exploits",
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{FlowKey, TransportProto};

    fn flow(protocol: Protocol) -> Flow {
        let mut flow = Flow::new(FlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 50000,
            dst_port: 445,
            transport: TransportProto::Tcp,
        });
        flow.protocol = Some(protocol);
        flow
    }

    fn parsed(payload: &[u8]) -> ParsedPacket {
        ParsedPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 50000,
            dst_port: 445,
            transport: TransportProto::Tcp,
            payload: payload.to_vec(),
            tcp: None,
            ttl: 0,
        }
    }

    fn smb1(command: u8) -> Vec<u8> {
        let mut smb = b"\xFFSMB".to_vec();
        smb.push(command);
        smb.extend_from_slice(&0u32.to_le_bytes());
        smb.resize(32, 0);
        let length = smb.len();
        let mut out = vec![0x00, (length >> 16) as u8, (length >> 8) as u8, length as u8];
        out.extend_from_slice(&smb);
        out
    }

    #[test]
    fn smb1_flow_reports_insecure_version() {
        let processor = SmbRiskProcessor::new();
        let risks = processor.analyze_packet(&parsed(&smb1(0x73)), &flow(Protocol::Smb1));
        assert!(risks
            .iter()
            .any(|risk| risk.flag == RiskFlag::SmbInsecureVersion));
    }

    #[test]
    fn smb23_flow_does_not_report() {
        let processor = SmbRiskProcessor::new();
        let risks = processor.analyze_packet(&parsed(&smb1(0x73)), &flow(Protocol::Smb23));
        assert!(risks.is_empty());
    }

    #[test]
    fn smb1_trans_does_not_report() {
        let processor = SmbRiskProcessor::new();
        let risks = processor.analyze_packet(&parsed(&smb1(0x25)), &flow(Protocol::Smb1));
        assert!(risks.is_empty());
    }

    #[test]
    fn existing_risk_is_not_duplicated() {
        let processor = SmbRiskProcessor::new();
        let mut flow = flow(Protocol::Smb1);
        flow.risks.push(RiskResult::new(
            RiskFlag::SmbInsecureVersion,
            RiskSeverity::High,
            "existing",
        ));
        let risks = processor.analyze_packet(&parsed(&smb1(0x73)), &flow);
        assert!(risks.is_empty());
    }
}
```

在 `tests/test_flow_export.rs` 末尾追加：

```rust
#[cfg(feature = "smb")]
fn flow_with_smb_protocol(protocol: Protocol) -> Flow {
    let mut flow = Flow::new(key());
    flow.protocol = Some(protocol);
    flow.protocol_stack.push(protocol);
    flow
}

#[cfg(feature = "smb")]
#[test]
fn netbios_exports_as_single_protocol() {
    let normalized = NormalizedFlow::from_flow(&flow_with_smb_protocol(Protocol::NetBios));
    assert_eq!(normalized.master_protocol.as_deref(), Some("NetBIOS"));
    assert_eq!(normalized.app_protocol, None);
    assert_eq!(normalized.protocol_stack, vec!["NetBIOS".to_string()]);
    assert_eq!(normalized.category.as_deref(), Some("System"));
    assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
}

#[cfg(feature = "smb")]
#[test]
fn smb_exports_master_and_netbios_app() {
    let cases = [
        (Protocol::Smb1, "SMBv1", "Dangerous"),
        (Protocol::Smb23, "SMBv23", "Acceptable"),
    ];
    for (protocol, name, breed) in cases {
        let normalized = NormalizedFlow::from_flow(&flow_with_smb_protocol(protocol));
        assert_eq!(normalized.master_protocol.as_deref(), Some(name));
        assert_eq!(normalized.app_protocol.as_deref(), Some("NetBIOS"));
        assert_eq!(
            normalized.protocol_stack,
            vec![name.to_string(), "NetBIOS".to_string()]
        );
        assert_eq!(normalized.category.as_deref(), Some("System"));
        assert_eq!(normalized.breed.as_deref(), Some(breed));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test --features "risk smb" --lib risk::types::tests::test_smb_insecure_version_metadata
cargo test --features "risk smb" --lib risk::processors::smb::tests
cargo test --features "json smb" --test test_flow_export netbios_exports_as_single_protocol
```

Expected: 编译失败（`RiskFlag::SmbInsecureVersion` / `SmbRiskProcessor` 未定义）或断言失败。

- [ ] **Step 3: Add the risk flag**

在 `src/risk/types.rs` 的 `RiskFlag` 枚举末尾（`UnknownProtocol` 后）加入：

```rust
    /// SMBv1 为已知不安全版本（WannaCry/EternalBlue 等）
    SmbInsecureVersion,
```

在 `default_severity()` 中 `UnknownProtocol` 前加入：

```rust
            RiskFlag::SmbInsecureVersion => RiskSeverity::High,
```

在 `name()` 中 `UnknownProtocol` 前加入：

```rust
            RiskFlag::SmbInsecureVersion => "smb_insecure_version",
```

- [ ] **Step 4: Register the risk processor**

在 `src/risk/processors/mod.rs` 顶部加入：

```rust
#[cfg(feature = "smb")]
pub mod smb;
```

在 `register_defaults` 中 `ftp` 注册之后加入：

```rust
    // SMBv1 风险随 smb feature 注册
    #[cfg(feature = "smb")]
    registry.register(Box::new(smb::SmbRiskProcessor::new()));
```

更新 `test_register_defaults` 的 expected：

```rust
        let expected = 5
            + usize::from(cfg!(feature = "quic"))
            + usize::from(cfg!(feature = "proto3"))
            + usize::from(cfg!(feature = "smb"));
```

- [ ] **Step 5: Add parity mappings**

在 `src/parity.rs` 的 `from_flow` 特殊映射 match 中，`Protocol::HttpProxy` 分支之后加入：

```rust
            #[cfg(feature = "smb")]
            Some(Protocol::NetBios) => (
                Some("NetBIOS".to_string()),
                None,
                vec!["NetBIOS".to_string()],
            ),
            #[cfg(feature = "smb")]
            Some(Protocol::Smb1) => (
                Some("SMBv1".to_string()),
                Some("NetBIOS".to_string()),
                vec!["SMBv1".to_string(), "NetBIOS".to_string()],
            ),
            #[cfg(feature = "smb")]
            Some(Protocol::Smb23) => (
                Some("SMBv23".to_string()),
                Some("NetBIOS".to_string()),
                vec!["SMBv23".to_string(), "NetBIOS".to_string()],
            ),
```

在 `protocol_name` 中加入：

```rust
        #[cfg(feature = "smb")]
        Protocol::NetBios => "NetBIOS".to_string(),
        #[cfg(feature = "smb")]
        Protocol::Smb1 => "SMBv1".to_string(),
        #[cfg(feature = "smb")]
        Protocol::Smb23 => "SMBv23".to_string(),
```

在 `ndpi_compat_classification` 中加入：

```rust
        #[cfg(feature = "smb")]
        Protocol::NetBios | Protocol::Smb23 => {
            ("System".to_string(), "Acceptable".to_string())
        }
        #[cfg(feature = "smb")]
        Protocol::Smb1 => ("System".to_string(), "Dangerous".to_string()),
```

在 `ndpi_compat_risk_name` 中加入：

```rust
        "smb_insecure_version" => "smb_insecure_ver",
```

在 `tests/parity/mod.rs` 的 `NDPI_RISK_ALIASES` 中加入：

```rust
    ("smb_insecure_version", "smb_insecure_ver"),
```

- [ ] **Step 6: Run tests to verify they pass**

Run:

```bash
cargo test --features "risk smb" --lib risk::types::tests::test_smb_insecure_version_metadata
cargo test --features "risk smb" --lib risk::processors::smb::tests
cargo test --features "json smb" --test test_flow_export
cargo test --all-features --test test_parity_harness
```

Expected: 全部 PASS。

- [ ] **Step 7: Commit**

```bash
git add src/risk/types.rs src/risk/processors/smb.rs src/risk/processors/mod.rs src/parity.rs tests/parity/mod.rs tests/test_flow_export.rs
git commit -m "Add SMBv1 risk and nDPI parity mapping"
```

---

### Task 8: 语料扩展与 golden 差分

**Files:**
- Modify: `tests/parity/gen_corpus.py`
- Modify: `tests/parity/gen_golden.sh`
- Create: `tests/parity/corpus/netbios_nbns.pcap`、`netbios_nbds.pcap`、`netbios_nbss.pcap`、`smb1_session_setup.pcap`、`smb1_negotiate_then_setup.pcap`、`smb23_negotiate.pcap`
- Create: `tests/parity/golden/*.ndpi.json`
- Test: `tests/test_parity_corpus.rs`

**Interfaces:**
- Consumes: Task 2-7 的检测与 parity 映射。
- Produces: 6 个新 pcap + golden，现有 corpus runner 自动纳入。

- [ ] **Step 1: Add corpus builders**

在 `tests/parity/gen_corpus.py` 的 `build_ftp_transfer` 之后加入：

```python
def _netbios_encode_name(name, suffix):
    padded = name.encode()[:15].ljust(15, b" ") + bytes([suffix])
    encoded = bytearray()
    for byte in padded:
        encoded.append(ord("A") + (byte >> 4))
        encoded.append(ord("A") + (byte & 0x0F))
    return bytes(encoded)


def build_netbios_nbns():
    encoded = _netbios_encode_name("SERVER", 0x20)
    payload = (
        struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
        + bytes([0x20])
        + encoded
        + b"\x00"
        + struct.pack(">HH", 0x0020, 0x0001)
    )
    return [udp_pair(CLIENT, SERVER, 50010, 137, payload, b"")[0]]


def build_netbios_nbds():
    source_name = b"SERVER".ljust(16, b" ")
    dest_name = b"CLIENT".ljust(16, b" ")
    data = b"hello netbios"
    body = source_name + dest_name + data
    payload = (
        bytes([0x10, 0x00])
        + struct.pack(">H", 0x1234)
        + bytes(CLIENT)
        + struct.pack(">H", 138)
        + struct.pack(">H", len(body))
        + struct.pack(">H", 0)
        + body
    )
    return [udp_pair(CLIENT, SERVER, 50011, 138, payload, b"")[0]]


def build_netbios_nbss():
    payload = (
        bytes([0x81, 0x00])
        + struct.pack(">H", 68)
        + b"SERVER".ljust(16, b" ")
        + b"CLIENT".ljust(16, b" ")
        + b"\x20"
        + bytes(35)
    )
    return tcp_session(
        CLIENT,
        SERVER,
        50012,
        139,
        [
            ("c", payload),
            ("s", bytes([0x82, 0x00, 0x00, 0x00])),
        ],
    )


def _smb1_header(command):
    header = (
        b"\xFFSMB"
        + bytes([command])
        + struct.pack("<I", 0)
        + b"\x18"
        + struct.pack("<H", 1)
        + struct.pack(">H", 0)
        + bytes(8)
        + bytes(2)
        + struct.pack("<HHHH", 0, 0, 0, 0)
    )
    return header


def build_smb1_session_setup():
    smb = _smb1_header(0x73) + bytes(16)
    payload = bytes([0x00]) + struct.pack(">I", len(smb))[1:] + smb
    return tcp_session(CLIENT, SERVER, 50013, 445, [("c", payload)])


def build_smb1_negotiate_then_setup():
    negotiate = _smb1_header(0x72) + bytes(16)
    setup = _smb1_header(0x73) + bytes(16)
    negotiate_payload = bytes([0x00]) + struct.pack(">I", len(negotiate))[1:] + negotiate
    setup_payload = bytes([0x00]) + struct.pack(">I", len(setup))[1:] + setup
    return tcp_session(
        CLIENT,
        SERVER,
        50014,
        445,
        [("c", negotiate_payload), ("c", setup_payload)],
    )


def _smb2_header(command=0):
    header = (
        b"\xFESMB"
        + struct.pack("<H", 64)
        + struct.pack("<H", 1)
        + struct.pack("<I", 0)
        + struct.pack("<H", command)
        + struct.pack("<H", 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", 0)
        + bytes(16)
    )
    return header


def build_smb23_negotiate():
    smb = _smb2_header(0x0000) + bytes(16)
    payload = bytes([0x00]) + struct.pack(">I", len(smb))[1:] + smb
    return tcp_session(CLIENT, SERVER, 50015, 445, [("c", payload)])
```

在 `CORPUS` 字典中 `ftp_transfer` 后加入：

```python
    # F45 NetBIOS + SMB
    "netbios_nbns": build_netbios_nbns,
    "netbios_nbds": build_netbios_nbds,
    "netbios_nbss": build_netbios_nbss,
    "smb1_session_setup": build_smb1_session_setup,
    "smb1_negotiate_then_setup": build_smb1_negotiate_then_setup,
    "smb23_negotiate": build_smb23_negotiate,
```

- [ ] **Step 2: Regenerate corpus**

Run:

```bash
python -I tests/parity/gen_corpus.py
```

Expected: `tests/parity/corpus/` 下新增 6 个 pcap；已有文件内容不变。

- [ ] **Step 3: Extend and run the golden script**

把 `tests/parity/gen_golden.sh` 的 for 列表改为：

```bash
for n in http_connect http_proxy doh_resolver dot_alpn dot_port ftp_transfer \
         netbios_nbns netbios_nbds netbios_nbss \
         smb1_session_setup smb1_negotiate_then_setup smb23_negotiate; do
```

Run:

```bash
wsl.exe bash tests/parity/gen_golden.sh
```

Expected: `tests/parity/golden/` 下新增 6 个 `.ndpi.json`。

- [ ] **Step 4: Inspect nDPI protocol names**

Run:

```bash
python -I - <<'PY'
import json, pathlib
for name in ["netbios_nbns", "netbios_nbds", "netbios_nbss",
             "smb1_session_setup", "smb1_negotiate_then_setup", "smb23_negotiate"]:
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
netbios_nbns -> NetBIOS
netbios_nbds -> NetBIOS
netbios_nbss -> NetBIOS
smb1_session_setup -> SMBv1.NetBIOS
smb1_negotiate_then_setup -> SMBv1.NetBIOS
smb23_negotiate -> SMBv23.NetBIOS
```

若输出与预期不符，先按真实 golden 修正 Task 7 的 `from_flow` 映射，再继续。

- [ ] **Step 5: Run the corpus test**

Run:

```bash
cargo test --all-features --test test_parity_corpus -- --nocapture
```

Expected: 全部 PASS；新用例的 master/app/category/breed/confidence/risk_gate 差异为 0。

- [ ] **Step 6: Commit**

```bash
git add tests/parity/gen_corpus.py tests/parity/gen_golden.sh tests/parity/corpus tests/parity/golden
git commit -m "Add NetBIOS and SMB parity corpus and goldens"
```

---

### Task 9: 文档回写与最终门禁

**Files:**
- Modify: `AGENTS.md`
- Modify: `docs/architecture/modules.md`
- Modify: `docs/architecture/risks.md`
- Modify: `docs/architecture/ndpi-pure-rust-plan.md`
- Modify: `docs/architecture/protocol-coverage-plan.md`
- Modify: `README.md`（如包含 feature 列表）

**Interfaces:**
- Consumes: 全部实现与测试。
- Produces: 项目认知库与路线图与代码一致。

- [ ] **Step 1: Run the full gate and record counts**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo test
cargo test --features smb
cargo test --all-features
cargo test --features "risk smb"
```

Expected: 全部 PASS；记录三组测试（默认 / all-features / risk+smb）的实际用例数。

- [ ] **Step 2: Update `AGENTS.md`**

在关键机制列表（F44 条目之后）加入：

```markdown
- **NetBIOS + SMBv1/v2/v3（F45，2026-11-07）**：新增 `smb` feature 与 `NetBios`/`Smb1`/`Smb23` 协议变体（category Infrastructure/FileTransfer，breed Acceptable/Dangerous/Acceptable）。NetBIOS detector：NBNS（UDP 137，12B 头 + first-level 名称解码 + qtype/qclass 校验）、NBDS（UDP 138，msg_type 0x10-0x16 + dgm_length 校验）、NBSS（TCP 139，session request 0x81 + called/calling name；0x00 + SMB 签名按 NetBIOS Session 处理）；TCP 139 用 `process()` 做头部重组（4096B）。SMB detector：仅 TCP 445，NBSS 4B + `0xFFSMB`/`0xFESMB` 签名；SMB1 跳过 Negotiate（0x72），SMB2/3 首个头部即分类；`process()` 处理 split header 与同段多 NBSS 消息（64 KiB 上限）。Risk：`SmbInsecureVersion`（HIGH，对齐 nDPI `smb_insecure_ver`，Trans 0x25 例外）。Parity：NetBIOS → NetBIOS；SMB → `SMBv1.NetBIOS`/`SMBv23.NetBIOS`（category System，breed Dangerous/Acceptable）。
```

在常用命令的测试计数三行中，替换为 Step 1 记录的实际数字。

在 F 表末尾加入：

```markdown
| F45 | 阶段 2 第一批：NetBIOS（NBNS/NBDS/NBSS）+ SMBv1/v2/v3（NBSS/SMB1/SMB2、Negotiate 跳过、头部重组）+ SmbInsecureVersion 风险；新增 `smb` feature | 中 | ✅ 已完成 2026-11-07（默认 / smb / all-features / risk+smb 全绿，详见 risks.md F45） |
```

- [ ] **Step 3: Update `docs/architecture/modules.md`**

在 feature 表末尾加入：

```markdown
| smb | netbios（NBNS/NBDS/NBSS）, smb（NBSS + SMB1/SMB2/3 头部） |
```

- [ ] **Step 4: Append F45 section to `docs/architecture/risks.md`**

```markdown
## F45【中】NetBIOS + SMBv1/v2/v3（2026-11-07，新功能开发）—— ✅ 已完成

- **背景**：阶段 2 企业协议 Wave 1B 首批缺口；nDPI 5.0 协议 ID 为 NETBIOS(10)、SMBV1(16)、SMBV23(41)。
- **实现**：
  - `smb` feature + `Protocol` 变体 `NetBios`/`Smb1`/`Smb23` + `Metadata::NetBios`/`Smb` + `DissectorState::NetBios`/`Smb`。
  - NetBIOS：UDP 137 NBNS（12B 头、first-level 名称解码、qtype/qclass）、UDP 138 NBDS（msg_type 0x10-0x16、dgm_length）、TCP 139 NBSS（0x81 session request、0x00 + SMB 签名）；TCP 139 有状态头部重组。
  - SMB：TCP 445，NBSS 4B + `0xFFSMB`/`0xFESMB`；SMB1 Negotiate（0x72）跳过；SMB2/3 首个头部分类；有状态 split-header 与同段多消息处理。
  - 风险：`RiskFlag::SmbInsecureVersion`（High）+ `SmbRiskProcessor`（Trans 0x25 例外，已报告不重复）。
  - Parity：NetBIOS → `NetBIOS`；SMB → `SMBv1.NetBIOS` / `SMBv23.NetBIOS`；category `System`；breed `Dangerous`/`Acceptable`；风险名 `smb_insecure_ver`。
  - 注册顺序：SSH 之后、FTP 之前（端口门控 137/138/139/445，无重叠）。
- **测试**：默认 / `smb` / all-features / `risk smb` 全绿；新增 6 个 pcap + golden 差分；fmt/clippy 干净。
- **已知边界**：
  1. SMB over TCP 139 保持 `NetBios`（与 nDPI 一致）；SMB over QUIC 不识别。
  2. SMB1 Negotiate-only 流不分类（nDPI 同）。
  3. SMB 元数据仅 command/status；不解析 dialect/server/OS/签名/加密。
  4. NetBIOS 名称只取首个问题/会话请求/source name；不递归 NBDS relay。
  5. NBDS 不校验 source_ip == IPv4 源地址（detector 无 IP 上下文；nDPI 会校验）。
  6. 头部重组上限：SMB 64 KiB、NetBIOS 4 KiB。
  7. 单 flow 仍只允许一个活跃 `DissectorState`。
```

- [ ] **Step 5: Update roadmap docs**

在 `docs/architecture/ndpi-pure-rust-plan.md` 的进度章节追加：

```markdown
- **阶段 2 Wave 1B 首批（F45，2026-11-07）**：NetBIOS（NBNS/NBDS/NBSS）与 SMBv1/v2/v3（NBSS/SMB1/SMB2 + Negotiate 跳过 + 头部重组）完成；`smb` feature 覆盖两者；SMBv1 风险与 nDPI 兼容导出已接入。
```

在“待办”中把 NetBIOS/SMB 从阶段 2 首批缺口移除，并注明下一批：MSSQL/TDS、Memcached、Elasticsearch、Kafka、AMQP。

在 `docs/architecture/protocol-coverage-plan.md` 中把 SMBv1/v2/v3、NetBIOS 标记为已覆盖（§1/§4），并在“下一步”注明阶段 2 第二批。

在 `README.md` 的 feature 列表（若存在）加入 `smb`。

- [ ] **Step 6: Run the full gate again**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo test
cargo test --features smb
cargo test --all-features
cargo test --features "risk smb"
```

Expected: 全部 PASS。

- [ ] **Step 7: Commit**

```bash
git add AGENTS.md README.md docs/architecture
git commit -m "Document NetBIOS and SMB support"
```

---

## Self-Review

- **Spec coverage:** 协议模型/feature → Task 1；NetBIOS parser/detector/有状态 → Task 2/3；SMB parser/detector/有状态 → Task 4/5；注册/HTTP/CLI → Task 6；风险/parity → Task 7；语料/golden → Task 8；文档/门禁 → Task 9。
- **Placeholder scan:** 无 TBD/TODO；Task 6 的注册冒烟测试给出两种实现路径（字段可见/私有），实施时按当前代码选择其一；测试计数在 Task 9 以“运行并记录实际数字”落实。
- **Type consistency:** `NetBiosParsed` 字段、`SmbVersion`/`SmbHeader`、`NetBiosDissectorState`/`SmbDissectorState`、`RiskFlag::SmbInsecureVersion`、parity 名称在任务间一致；`parse_nbss_session_message` 与 `parse_smb` 的签名在 Task 2/4 定义、Task 3/5 使用一致。
