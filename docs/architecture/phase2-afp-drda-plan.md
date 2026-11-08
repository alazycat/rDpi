# AFP + DRDA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 在 `storage` feature 下新增 AFP（DSI）识别，在 `database` feature 下新增 DRDA（IBM DB2）识别，并补齐元数据、端口回退、规则名、parity、CLI 与语料差分。

**Architecture:** 两个无状态 detector，与 F49/F50 同构。AFP 严格校验 16 字节 DSI 头并对 >128 字节载荷拒绝；DRDA 严格校验 10 字节 DSS/DDM 头并精确消费多消息。跨段识别复用现有 `tcp_prefix` 前缀补齐能力，不新增 `DissectorState`。

**Tech Stack:** Rust 2024（`rust-version = 1.88`）、现有 `thiserror`/`serde`（json feature）、cargo test / fmt / clippy、Python 3 语料生成、WSL ndpiReader 5.0 golden。

## Global Constraints

- 不新增 Cargo feature 或第三方依赖；AFP 复用 `storage`，DRDA 复用 `database`。
- 新协议变体与所有引用分支必须带对应 `#[cfg(feature = "...")]`。
- 禁止修改既有 detector 的相对注册顺序；只允许在对应 feature 块内追加。
- 首字节门契约（AGENTS.md 禁止事项 #6）：声明门后，门区间外的 payload 必须返回 `None`。
- 中文 doc 注释为主；解析失败返回 `None`，不 panic。
- 热路径不引入分配密集逻辑；命中定制时仅在需要时分配。
- 提交信息不得包含任何 AI 署名（用户规则）；提交只包含代码与项目文档。
- 全量门禁：`cargo fmt --all -- --check`、`cargo clippy --all-features --all-targets -D warnings`、`cargo test`、`cargo test --features "storage database"`、`cargo test --all-features`。
- 设计依据：`docs/architecture/phase2-afp-drda-design.md`；nDPI 源码 `D:\c_code\nDPI-5.0`；golden 工具 `/mnt/d/c_code/nDPI-5.0/build/example/ndpiReader`。

---

### Task 1: Protocol 与元数据脚手架

**Files:**
- Modify: `src/core/types.rs`（`Protocol` 枚举、`Metadata` 枚举、元数据结构、`category()`、`breed()`）
- Test: `tests/test_types.rs`

**Interfaces:**
- Produces: `Protocol::Afp`、`Protocol::Drda`；`AfpMetadata { flags: u8, command: u8, request_id: u16, length: u32 }`；`DrdaMetadata { message_count: u16, message_length: u16 }`；`Metadata::Afp`、`Metadata::Drda`。

- [x] **Step 1: 写失败测试**

在 `tests/test_types.rs` 追加：

```rust
#[cfg(feature = "storage")]
#[test]
fn test_afp_classification() {
    assert_eq!(Protocol::Afp.category(), ProtocolCategory::FileTransfer);
    assert_eq!(Protocol::Afp.breed(), ProtocolBreed::Acceptable);
}

#[cfg(feature = "database")]
#[test]
fn test_drda_classification() {
    assert_eq!(Protocol::Drda.category(), ProtocolCategory::Database);
    assert_eq!(Protocol::Drda.breed(), ProtocolBreed::Acceptable);
}
```

- [x] **Step 2: 运行测试确认失败**

Run: `cargo test --features "storage database" --test test_types -v`

Expected: 编译失败，提示 `no variant named Afp` / `Drda`。

- [x] **Step 3: 实现类型**

在 `src/core/types.rs` 的 `Protocol::Cassandra` 变体之后追加：

```rust
    /// Apple Filing Protocol（feature: storage，F51）
    #[cfg(feature = "storage")]
    Afp,
    /// DRDA（IBM DB2 分布式关系数据库架构，feature: database，F51）
    #[cfg(feature = "database")]
    Drda,
```

在 `Metadata` 枚举的 `Cassandra(CassandraMetadata)` 之后追加：

```rust
    /// AFP DSI 元数据 (feature: storage, F51)
    #[cfg(feature = "storage")]
    Afp(AfpMetadata),
    /// DRDA 元数据 (feature: database, F51)
    #[cfg(feature = "database")]
    Drda(DrdaMetadata),
```

在 `CassandraMetadata` 定义之后追加：

```rust
/// AFP DSI 元数据 (feature: storage, F51)
#[cfg(feature = "storage")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AfpMetadata {
    /// DSI 标志（0=请求，1=响应）
    pub flags: u8,
    /// DSI 命令（1..=8）
    pub command: u8,
    /// 请求 ID
    pub request_id: u16,
    /// 声明数据长度（命中时载荷至少包含 16+length 字节）
    pub length: u32,
}

/// DRDA 元数据 (feature: database, F51)
#[cfg(feature = "database")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrdaMetadata {
    /// 本载荷中的 DRDA 消息数
    pub message_count: u16,
    /// 首条消息的总长度
    pub message_length: u16,
}
```

在 `category()` 的 `Protocol::Oracle | Protocol::Cassandra => ProtocolCategory::Database,` 之后追加：

```rust
            #[cfg(feature = "database")]
            Protocol::Drda => ProtocolCategory::Database,
```

在 `category()` 的 FileTransfer 分组中追加：

```rust
            #[cfg(feature = "storage")]
            Protocol::Afp => ProtocolCategory::FileTransfer,
```

在 `breed()` 的 `Protocol::Oracle | Protocol::Cassandra => ProtocolBreed::Acceptable,` 之后追加：

```rust
            #[cfg(feature = "storage")]
            Protocol::Afp => ProtocolBreed::Acceptable,
            #[cfg(feature = "database")]
            Protocol::Drda => ProtocolBreed::Acceptable,
```

- [x] **Step 4: 运行测试确认通过**

Run: `cargo test --features "storage database" --test test_types test_afp_classification test_drda_classification -v`

Expected: 2 个测试 PASS。

- [x] **Step 5: 提交**

```bash
git add src/core/types.rs tests/test_types.rs
git commit -m "Add AFP and DRDA protocol types"
```

---

### Task 2: AFP 解析器

**Files:**
- Create: `src/protocols/afp/parser.rs`
- Create: `src/protocols/afp/mod.rs`（本任务只声明 `parser`）
- Modify: `src/protocols/mod.rs`（模块声明）

**Interfaces:**
- Produces: `pub const AFP_DSI_HEADER_LEN: usize = 16`；`pub const AFP_MAX_DETECT_LEN: usize = 128`；`pub struct AfpParsed { pub flags: u8, pub command: u8, pub request_id: u16, pub length: u32 }`；`pub fn parse_afp_dsi(payload: &[u8]) -> Option<AfpParsed>`。

- [x] **Step 1: 写失败测试与桩实现**

创建 `src/protocols/afp/parser.rs`：

```rust
//! AFP DSI 报文头解析（与 nDPI 5.0 `afp.c` 判定一致）

/// DSI 报文头固定长度
pub const AFP_DSI_HEADER_LEN: usize = 16;
/// 与 nDPI 一致：>128 字节的载荷不单独作为 AFP 定型依据
pub const AFP_MAX_DETECT_LEN: usize = 128;

/// AFP DSI 报文头解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AfpParsed {
    pub flags: u8,
    pub command: u8,
    pub request_id: u16,
    pub length: u32,
}

/// 解析 AFP DSI 报文头
pub fn parse_afp_dsi(_payload: &[u8]) -> Option<AfpParsed> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dsi(flags: u8, command: u8, request_id: u16, length: u32, body: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(flags);
        packet.push(command);
        packet.extend_from_slice(&request_id.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(body);
        packet
    }

    #[test]
    fn test_parse_request_header_only() {
        let parsed = parse_afp_dsi(&dsi(0, 1, 1, 0, b"")).unwrap();
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.command, 1);
        assert_eq!(parsed.request_id, 1);
        assert_eq!(parsed.length, 0);
    }

    #[test]
    fn test_parse_response_with_body() {
        let parsed = parse_afp_dsi(&dsi(1, 2, 7, 4, b"body")).unwrap();
        assert_eq!(parsed.flags, 1);
        assert_eq!(parsed.command, 2);
        assert_eq!(parsed.request_id, 7);
        assert_eq!(parsed.length, 4);
    }

    #[test]
    fn test_all_commands_hit() {
        for command in 1..=8u8 {
            assert!(
                parse_afp_dsi(&dsi(0, command, 1, 0, b"")).is_some(),
                "command {command} 应命中"
            );
        }
    }

    #[test]
    fn test_reject_short_payload() {
        assert!(parse_afp_dsi(&[0u8; 15]).is_none());
    }

    #[test]
    fn test_reject_large_payload() {
        let payload = dsi(0, 1, 1, 113, &[0u8; 113]);
        assert_eq!(payload.len(), 129);
        assert!(parse_afp_dsi(&payload).is_none());
    }

    #[test]
    fn test_reject_bad_flags() {
        assert!(parse_afp_dsi(&dsi(2, 1, 1, 0, b"")).is_none());
    }

    #[test]
    fn test_reject_bad_command() {
        assert!(parse_afp_dsi(&dsi(0, 0, 1, 0, b"")).is_none());
        assert!(parse_afp_dsi(&dsi(0, 9, 1, 0, b"")).is_none());
    }

    #[test]
    fn test_reject_nonzero_reserved() {
        let mut payload = dsi(0, 1, 1, 0, b"");
        payload[12] = 1;
        assert!(parse_afp_dsi(&payload).is_none());
    }

    #[test]
    fn test_reject_body_shorter_than_length() {
        assert!(parse_afp_dsi(&dsi(0, 1, 1, 5, b"body")).is_none());
    }
}
```

创建 `src/protocols/afp/mod.rs`：

```rust
//! Apple Filing Protocol detection module for rDpi

pub mod parser;
```

在 `src/protocols/mod.rs` 的 `pub mod amqp;` 之前插入：

```rust
#[cfg(feature = "storage")]
pub mod afp;
```

- [x] **Step 2: 运行测试确认失败**

Run: `cargo test --features storage afp::parser -v`

Expected: 9 个测试失败（桩实现返回 `None`）。

- [x] **Step 3: 实现解析器**

将 `parse_afp_dsi` 替换为：

```rust
/// 解析 AFP DSI 报文头
///
/// 命中条件（nDPI 5.0 `afp.c`）：
/// - 载荷长度 16..=128；
/// - `flags <= 1`；
/// - `command ∈ 1..=8`；
/// - `reserved == 0`；
/// - 载荷至少包含 `16 + length` 字节。
pub fn parse_afp_dsi(payload: &[u8]) -> Option<AfpParsed> {
    if payload.len() < AFP_DSI_HEADER_LEN || payload.len() > AFP_MAX_DETECT_LEN {
        return None;
    }
    let flags = payload[0];
    if flags > 1 {
        return None;
    }
    let command = payload[1];
    if !(1..=8).contains(&command) {
        return None;
    }
    let request_id = u16::from_be_bytes([payload[2], payload[3]]);
    let length = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let reserved = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
    if reserved != 0 {
        return None;
    }
    let end = AFP_DSI_HEADER_LEN.checked_add(length as usize)?;
    if payload.len() < end {
        return None;
    }
    Some(AfpParsed {
        flags,
        command,
        request_id,
        length,
    })
}
```

- [x] **Step 4: 运行测试确认通过**

Run: `cargo test --features storage afp::parser -v`

Expected: PASS（9 个测试）。

- [x] **Step 5: 提交**

```bash
git add src/protocols/afp/parser.rs src/protocols/afp/mod.rs src/protocols/mod.rs
git commit -m "Add AFP DSI parser"
```

---

### Task 3: AFP detector、注册与入口测试

**Files:**
- Create: `src/protocols/afp/detector.rs`
- Modify: `src/protocols/afp/mod.rs`
- Modify: `src/protocols/mod.rs`（注册）
- Create: `tests/test_afp_drda.rs`（本任务先写 AFP 用例）

**Interfaces:**
- Consumes: `parse_afp_dsi`、`AfpParsed`（Task 2）。
- Produces: `AfpDetector`；`afp::register(&mut Registry)`。

- [x] **Step 1: 写 detector 与测试**

创建 `src/protocols/afp/detector.rs`：

```rust
//! Apple Filing Protocol detector for rDpi

use crate::core::types::{
    AfpMetadata, Confidence, DetectContext, DetectionResult, Metadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::parse_afp_dsi;

/// AFP DSI protocol detector
pub struct AfpDetector {
    _private: (),
}

impl AfpDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for AfpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for AfpDetector {
    fn name(&self) -> &'static str {
        "afp"
    }

    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x00, 0x01)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_afp_dsi(payload)?;
        Some(
            DetectionResult::new(Protocol::Afp)
                .with_metadata(Metadata::Afp(AfpMetadata {
                    flags: parsed.flags,
                    command: parsed.command,
                    request_id: parsed.request_id,
                    length: parsed.length,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }

    fn detect_with_context(&self, payload: &[u8], _ctx: &DetectContext) -> Option<DetectionResult> {
        // 与 nDPI 一致：AFP detector 不检查端口，548 仅用于回退猜测。
        self.detect(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dsi(flags: u8, command: u8, request_id: u16, length: u32, body: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(flags);
        packet.push(command);
        packet.extend_from_slice(&request_id.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(body);
        packet
    }

    fn ctx(src_port: u16, dst_port: u16) -> DetectContext {
        DetectContext {
            src_port,
            dst_port,
            is_http3_port: false,
        }
    }

    #[test]
    fn test_detect_request() {
        let detector = AfpDetector::new();
        let result = detector.detect(&dsi(0, 1, 3, 0, b"")).unwrap();
        assert_eq!(result.protocol, Protocol::Afp);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Afp(meta) => {
                assert_eq!(meta.flags, 0);
                assert_eq!(meta.command, 1);
                assert_eq!(meta.request_id, 3);
                assert_eq!(meta.length, 0);
            }
            _ => panic!("expected AFP metadata"),
        }
    }

    #[test]
    fn test_reject_http() {
        let detector = AfpDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_detect_is_port_independent() {
        let detector = AfpDetector::new();
        let payload = dsi(0, 1, 1, 0, b"");
        assert!(
            detector
                .detect_with_context(&payload, &ctx(50000, 9999))
                .is_some()
        );
        assert!(
            detector
                .detect_with_context(&payload, &ctx(50000, 548))
                .is_some()
        );
    }

    #[test]
    fn test_first_byte_gate_covers_valid_samples() {
        let detector = AfpDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        for flags in [0u8, 1] {
            let sample = dsi(flags, 1, 1, 0, b"");
            assert!(
                gate.iter()
                    .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
                "门区间不覆盖合法样本首字节 0x{:02X}",
                sample[0]
            );
        }
        for byte in [2u8, 0xFF, b'G'] {
            assert!(!gate.iter().any(|&(lo, hi)| byte >= lo && byte <= hi));
        }
    }
}
```

将 `src/protocols/afp/mod.rs` 替换为：

```rust
//! Apple Filing Protocol detection module for rDpi
//!
//! 识别 16 字节 DSI 头（AFP over TCP/UDP 548）。

mod detector;
pub mod parser;

pub use detector::AfpDetector;
pub use parser::{AFP_DSI_HEADER_LEN, AFP_MAX_DETECT_LEN, AfpParsed, parse_afp_dsi};

use crate::protocols::Registry;

/// Register AFP detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(AfpDetector::new()));
}
```

在 `src/protocols/mod.rs` 的 `http::register(_registry);` 之后、`dns::register(_registry);` 之前插入（header-only DSI 会被 DNS detector 误判为 Dns，必须先于 DNS；影响面见设计文档 §5.2）：

```rust
    #[cfg(feature = "storage")]
    afp::register(_registry);
```

- [x] **Step 2: 运行模块测试**

Run: `cargo test --features storage afp -v`

Expected: PASS（parser 9 + detector 4）。

- [x] **Step 3: 写入口跨段测试**

创建 `tests/test_afp_drda.rs`：

```rust
//! F51：AFP/DRDA 经双向入口的跨段识别

#![cfg(any(feature = "storage", feature = "database"))]

use rdpi::Detector;

const CLIENT: [u8; 4] = [192, 168, 1, 1];
const SERVER: [u8; 4] = [10, 0, 0, 1];
const BASE_TS_MS: u64 = 1_700_000_000_000;

fn eth_ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + 20 + l4.len());
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.push(64);
    frame.push(proto);
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(l4);
    frame
}

fn tcp(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend_from_slice(&sport.to_be_bytes());
    segment.extend_from_slice(&dport.to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&ack.to_be_bytes());
    segment.push(0x50);
    segment.push(flags);
    segment.extend_from_slice(&0xffffu16.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes());
    segment.extend_from_slice(payload);
    segment
}

fn client_session(client_port: u16, server_port: u16, segments: &[&[u8]]) -> Vec<Vec<u8>> {
    let cseq = 1000u32;
    let sseq = 5000u32;
    let mut frames = vec![
        eth_ipv4(
            CLIENT,
            SERVER,
            6,
            &tcp(client_port, server_port, cseq, 0, 0x02, b""),
        ),
        eth_ipv4(
            SERVER,
            CLIENT,
            6,
            &tcp(server_port, client_port, sseq, cseq + 1, 0x12, b""),
        ),
        eth_ipv4(
            CLIENT,
            SERVER,
            6,
            &tcp(client_port, server_port, cseq + 1, sseq + 1, 0x10, b""),
        ),
    ];
    let mut offset = 0u32;
    for segment in segments {
        frames.push(eth_ipv4(
            CLIENT,
            SERVER,
            6,
            &tcp(
                client_port,
                server_port,
                cseq + 1 + offset,
                sseq + 1,
                0x18,
                segment,
            ),
        ));
        offset += segment.len() as u32;
    }
    frames
}

fn detect(frames: &[Vec<u8>]) -> Option<rdpi::Protocol> {
    let mut detector = Detector::new();
    let mut last = None;
    for (index, frame) in frames.iter().enumerate() {
        if let Some(result) = detector
            .process_packet(frame, BASE_TS_MS + index as u64 * 10)
            .unwrap()
        {
            last = Some(result.protocol);
        }
    }
    last
}

#[cfg(feature = "storage")]
#[test]
fn afp_dsi_split_across_segments_is_detected() {
    let payload = [
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let frames = client_session(50040, 548, &[&payload[..8], &payload[8..]]);
    assert_eq!(detect(&frames), Some(rdpi::Protocol::Afp));
}
```

- [x] **Step 4: 运行入口测试**

Run: `cargo test --features storage --test test_afp_drda -v`

Expected: PASS（1 个用例）。

- [x] **Step 5: 提交**

```bash
git add src/protocols/afp/ src/protocols/mod.rs tests/test_afp_drda.rs
git commit -m "Add AFP detector"
```

---

### Task 4: DRDA 解析器

**Files:**
- Create: `src/protocols/drda/parser.rs`
- Create: `src/protocols/drda/mod.rs`（本任务只声明 `parser`）
- Modify: `src/protocols/mod.rs`（模块声明）

**Interfaces:**
- Produces:
  - `pub const DRDA_HEADER_LEN: usize = 10`
  - `pub const DRDA_MAGIC: u8 = 0xD0`
  - `pub struct DrdaParsed { pub message_count: u16, pub message_length: u16 }`
  - `pub fn parse_drda(payload: &[u8]) -> Option<DrdaParsed>`

- [x] **Step 1: 写失败测试与桩实现**

创建 `src/protocols/drda/parser.rs`：

```rust
//! DRDA 消息头解析（与 nDPI 5.0 `drda.c` 判定一致）

/// DSS/DDM 消息头固定长度
pub const DRDA_HEADER_LEN: usize = 10;
/// DSS 魔数
pub const DRDA_MAGIC: u8 = 0xD0;

/// DRDA 载荷解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrdaParsed {
    /// 本载荷中的消息数
    pub message_count: u16,
    /// 首条消息的总长度
    pub message_length: u16,
}

/// 解析 DRDA 载荷（单条或多条严格串联消息）
pub fn parse_drda(_payload: &[u8]) -> Option<DrdaParsed> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(length2: u16, body: &[u8]) -> Vec<u8> {
        let length = length2 + 6;
        let mut message = Vec::new();
        message.extend_from_slice(&length.to_be_bytes());
        message.push(DRDA_MAGIC);
        message.push(0x41);
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&length2.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(body);
        message
    }

    #[test]
    fn test_parse_single_message() {
        let payload = message(10, &[0u8; 6]);
        assert_eq!(payload.len(), 16);
        let parsed = parse_drda(&payload).unwrap();
        assert_eq!(parsed.message_count, 1);
        assert_eq!(parsed.message_length, 16);
    }

    #[test]
    fn test_parse_two_messages() {
        let mut payload = message(10, &[0u8; 6]);
        payload.extend_from_slice(&message(10, &[0u8; 6]));
        let parsed = parse_drda(&payload).unwrap();
        assert_eq!(parsed.message_count, 2);
        assert_eq!(parsed.message_length, 16);
    }

    #[test]
    fn test_reject_short_payload() {
        assert!(parse_drda(&[0u8; 9]).is_none());
    }

    #[test]
    fn test_reject_wrong_magic() {
        let mut payload = message(10, &[0u8; 6]);
        payload[2] = 0xD1;
        assert!(parse_drda(&payload).is_none());
    }

    #[test]
    fn test_reject_length_mismatch() {
        let mut payload = message(10, &[0u8; 6]);
        payload[0..2].copy_from_slice(&17u16.to_be_bytes());
        assert!(parse_drda(&payload).is_none());
    }

    #[test]
    fn test_reject_too_short_message() {
        // length=9, length2=3 -> 3+6=9，但 length < 10
        let mut payload = Vec::new();
        payload.extend_from_slice(&9u16.to_be_bytes());
        payload.push(DRDA_MAGIC);
        payload.push(0x41);
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&3u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(payload.len(), 10);
        assert!(parse_drda(&payload).is_none());
    }

    #[test]
    fn test_reject_declared_length_beyond_payload() {
        let mut payload = message(10, &[0u8; 6]);
        payload.truncate(12);
        assert!(parse_drda(&payload).is_none());
    }

    #[test]
    fn test_reject_trailing_partial_header() {
        let mut payload = message(10, &[0u8; 6]);
        payload.extend_from_slice(&[0u8; 5]);
        assert!(parse_drda(&payload).is_none());
    }

    #[test]
    fn test_reject_second_message_bad_magic() {
        let mut payload = message(10, &[0u8; 6]);
        let mut second = message(10, &[0u8; 6]);
        second[2] = 0x00;
        payload.extend_from_slice(&second);
        assert!(parse_drda(&payload).is_none());
    }
}
```

创建 `src/protocols/drda/mod.rs`：

```rust
//! DRDA protocol detection module for rDpi

pub mod parser;
```

在 `src/protocols/mod.rs` 的 `pub mod dns;` 之前插入：

```rust
#[cfg(feature = "database")]
pub mod drda;
```

- [x] **Step 2: 运行测试确认失败**

Run: `cargo test --features database drda::parser -v`

Expected: 9 个测试失败（桩实现返回 `None`）。

- [x] **Step 3: 实现解析器**

将 `parse_drda` 替换为：

```rust
/// 解析 DRDA 载荷（单条或多条严格串联消息）
///
/// 每条消息头（10 字节，网络序）：
/// - `length == length2 + 6`；
/// - `length >= 10`；
/// - `magic == 0xD0`；
/// - 消息长度不得超出载荷；所有消息必须精确消费完载荷。
pub fn parse_drda(payload: &[u8]) -> Option<DrdaParsed> {
    if payload.len() < DRDA_HEADER_LEN {
        return None;
    }
    let mut offset = 0usize;
    let mut message_count = 0u16;
    let mut first_length = 0u16;
    while offset < payload.len() {
        if payload.len() - offset < DRDA_HEADER_LEN {
            return None;
        }
        let length = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let length2 = u16::from_be_bytes([payload[offset + 6], payload[offset + 7]]);
        if payload[offset + 2] != DRDA_MAGIC
            || (length as usize) < DRDA_HEADER_LEN
            || length as usize != length2 as usize + 6
        {
            return None;
        }
        let end = offset.checked_add(length as usize)?;
        if end > payload.len() {
            return None;
        }
        if message_count == 0 {
            first_length = length;
        }
        message_count = message_count.saturating_add(1);
        offset = end;
    }
    Some(DrdaParsed {
        message_count,
        message_length: first_length,
    })
}
```

- [x] **Step 4: 运行测试确认通过**

Run: `cargo test --features database drda::parser -v`

Expected: PASS（9 个测试）。

- [x] **Step 5: 提交**

```bash
git add src/protocols/drda/parser.rs src/protocols/drda/mod.rs src/protocols/mod.rs
git commit -m "Add DRDA parser"
```

---

### Task 5: DRDA detector、注册与入口测试

**Files:**
- Create: `src/protocols/drda/detector.rs`
- Modify: `src/protocols/drda/mod.rs`
- Modify: `src/protocols/mod.rs`（注册）
- Modify: `tests/test_afp_drda.rs`（追加 DRDA 用例）

**Interfaces:**
- Consumes: `parse_drda`、`DrdaParsed`（Task 4）。
- Produces: `DrdaDetector`；`drda::register(&mut Registry)`。

- [x] **Step 1: 写 detector 与测试**

创建 `src/protocols/drda/detector.rs`：

```rust
//! DRDA protocol detector for rDpi

use crate::core::types::{Confidence, DetectionResult, DrdaMetadata, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_drda;

/// DRDA protocol detector
pub struct DrdaDetector {
    _private: (),
}

impl DrdaDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for DrdaDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for DrdaDetector {
    fn name(&self) -> &'static str {
        "drda"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_drda(payload)?;
        Some(
            DetectionResult::new(Protocol::Drda)
                .with_metadata(Metadata::Drda(DrdaMetadata {
                    message_count: parsed.message_count,
                    message_length: parsed.message_length,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&16u16.to_be_bytes());
        message.push(0xD0);
        message.push(0x41);
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&10u16.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&[0u8; 6]);
        message
    }

    #[test]
    fn test_detect_single_message() {
        let detector = DrdaDetector::new();
        let result = detector.detect(&message()).unwrap();
        assert_eq!(result.protocol, Protocol::Drda);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Drda(meta) => {
                assert_eq!(meta.message_count, 1);
                assert_eq!(meta.message_length, 16);
            }
            _ => panic!("expected DRDA metadata"),
        }
    }

    #[test]
    fn test_reject_http() {
        let detector = DrdaDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_first_byte_gate_is_none() {
        let detector = DrdaDetector::new();
        assert!(detector.first_byte_gate().is_none());
    }
}
```

将 `src/protocols/drda/mod.rs` 替换为：

```rust
//! DRDA protocol detection module for rDpi
//!
//! 识别 IBM DB2 DRDA 的 DSS/DDM 消息头（无默认端口）。

mod detector;
pub mod parser;

pub use detector::DrdaDetector;
pub use parser::{DRDA_HEADER_LEN, DRDA_MAGIC, DrdaParsed, parse_drda};

use crate::protocols::Registry;

/// Register DRDA detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(DrdaDetector::new()));
}
```

在 `src/protocols/mod.rs` 的 `oracle::register(_registry);` 之后追加：

```rust
    #[cfg(feature = "database")]
    drda::register(_registry);
```

- [x] **Step 2: 运行模块测试**

Run: `cargo test --features database drda -v`

Expected: PASS（parser 9 + detector 3）。

- [x] **Step 3: 追加 DRDA 入口测试**

在 `tests/test_afp_drda.rs` 末尾追加：

```rust
#[cfg(feature = "database")]
#[test]
fn drda_message_split_across_segments_is_detected() {
    let payload = [
        0x00, 0x10, 0xD0, 0x41, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let frames = client_session(50041, 50000, &[&payload[..8], &payload[8..]]);
    assert_eq!(detect(&frames), Some(rdpi::Protocol::Drda));
}
```

- [x] **Step 4: 运行入口测试**

Run: `cargo test --features database --test test_afp_drda -v`

Expected: PASS（1 个用例）。

- [x] **Step 5: 提交**

```bash
git add src/protocols/drda/ src/protocols/mod.rs tests/test_afp_drda.rs
git commit -m "Add DRDA detector"
```

---

### Task 6: 端口回退、规则名、parity、CLI 与计数

**Files:**
- Modify: `src/core/guess/port.rs`
- Modify: `src/rule/parser.rs`
- Modify: `src/parity.rs`
- Modify: `src/bin/rdpi.rs`
- Modify: `tests/test_integration.rs`
- Modify: `tests/test_rule.rs`
- Modify: `tests/parity_export.rs`

**Interfaces:**
- Consumes: `Protocol::Afp`、`Protocol::Drda`、`AfpMetadata`、`DrdaMetadata`。
- Produces: 548→Afp 端口回退；`afp`/`drda` 规则名；AFP `DataTransfer/Acceptable`、DRDA `Database/Acceptable` parity；CLI 元数据展示。

- [x] **Step 1: 写失败测试**

在 `src/core/guess/port.rs` 的 tests 模块末尾追加：

```rust
    #[cfg(feature = "storage")]
    #[test]
    fn test_afp_port() {
        assert_eq!(match_port(548).unwrap().protocol, Protocol::Afp);
        assert_eq!(match_port(548).unwrap().confidence, Confidence::MatchByPort);
    }

    #[cfg(feature = "database")]
    #[test]
    fn test_drda_has_no_port_fallback() {
        assert!(match_port(50000).is_none());
    }
```

在 `tests/test_rule.rs` 末尾追加：

```rust
#[cfg(feature = "storage")]
#[test]
fn test_rule_parser_afp_protocol_name() {
    let json = r#"{
        "rules": [
            {"id": "afp", "protocol": "afp", "condition": {"dst_port": 548}}
        ]
    }"#;
    let engine = RuleEngine::from_json(json).unwrap();
    let ctx = RuleContext {
        src_port: 12345,
        dst_port: 548,
        sni: None,
        payload: Vec::new(),
    };
    let result = engine.match_rule(&ctx).expect("rule should match");
    assert_eq!(result.protocol, Protocol::Afp);
}

#[cfg(feature = "database")]
#[test]
fn test_rule_parser_drda_protocol_name() {
    let json = r#"{
        "rules": [
            {"id": "drda", "protocol": "drda", "condition": {"dst_port": 50000}}
        ]
    }"#;
    let engine = RuleEngine::from_json(json).unwrap();
    let ctx = RuleContext {
        src_port: 12345,
        dst_port: 50000,
        sni: None,
        payload: Vec::new(),
    };
    let result = engine.match_rule(&ctx).expect("rule should match");
    assert_eq!(result.protocol, Protocol::Drda);
}
```

在 `tests/parity_export.rs` 末尾追加：

```rust
#[cfg(feature = "storage")]
#[test]
fn test_protocol_name_afp() {
    let flow = flow_with_protocol(Protocol::Afp);
    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.master_protocol.as_deref(), Some("AFP"));
    assert_eq!(normalized.app_protocol, None);
    assert_eq!(normalized.category.as_deref(), Some("DataTransfer"));
    assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
}

#[cfg(feature = "database")]
#[test]
fn test_protocol_name_drda() {
    let flow = flow_with_protocol(Protocol::Drda);
    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.master_protocol.as_deref(), Some("DRDA"));
    assert_eq!(normalized.app_protocol, None);
    assert_eq!(normalized.category.as_deref(), Some("Database"));
    assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
}
```

将 `tests/test_integration.rs` 的计数改为：

```rust
        #[cfg(feature = "database")]
        {
            count += 10; // MySQL + PostgreSQL + Redis + MongoDB + Memcached + Elasticsearch（F46）+ MSSQL（F49）+ Oracle/Cassandra（F50）+ DRDA（F51）
        }
```

```rust
        #[cfg(feature = "storage")]
        {
            count += 2; // NFS + AFP（F51）
        }
```

- [x] **Step 2: 运行测试确认失败**

Run: `cargo test --features "storage database rule json" --test test_rule test_rule_parser_afp_protocol_name test_rule_parser_drda_protocol_name -v`

Expected: 失败（规则名未映射）。

Run: `cargo test --features "storage database" --test test_integration test_registry_default_detector_count -v`

Expected: FAIL（实际 detector 数比期望少 2）。

- [x] **Step 3: 实现集成**

在 `src/core/guess/port.rs` 的 `PORT_MAP` 末尾（Kafka 之前或之后均可，保持按端口升序可读性）追加：

```rust
    #[cfg(feature = "storage")]
    (548u16, &[Protocol::Afp]),
```

在 `src/rule/parser.rs` 的 `"cassandra"` 映射之后追加：

```rust
                    #[cfg(feature = "storage")]
                    "afp" => Protocol::Afp,
                    #[cfg(feature = "database")]
                    "drda" => Protocol::Drda,
```

在 `src/parity.rs` 的 `protocol_name` 中追加：

```rust
        #[cfg(feature = "storage")]
        Protocol::Afp => "AFP".to_string(),
        #[cfg(feature = "database")]
        Protocol::Drda => "DRDA".to_string(),
```

在 `src/parity.rs` 的 `ndpi_compat_classification` 中追加：

```rust
        // F51（nDPI 5.0 源码核对）：AFP 归 DataTransfer/Acceptable，
        // DRDA 归 Database/Acceptable
        #[cfg(feature = "storage")]
        Protocol::Afp => ("DataTransfer".to_string(), "Acceptable".to_string()),
        #[cfg(feature = "database")]
        Protocol::Drda => ("Database".to_string(), "Acceptable".to_string()),
```

在 `src/bin/rdpi.rs` 的 `formatted_meta` match 中，Cassandra 分支之后追加：

```rust
        #[cfg(feature = "storage")]
        rdpi::Metadata::Afp(a) => Some(format!(
            "flags={} command={} request={} length={}",
            a.flags, a.command, a.request_id, a.length
        )),
        #[cfg(feature = "database")]
        rdpi::Metadata::Drda(d) => Some(format!(
            "messages={} length={}",
            d.message_count, d.message_length
        )),
```

- [x] **Step 4: 运行测试确认通过**

Run: `cargo test --features "storage database rule json" --test test_rule test_rule_parser_afp_protocol_name test_rule_parser_drda_protocol_name -v`

Expected: PASS（2 个）。

Run: `cargo test --features "storage database" --test test_integration test_registry_default_detector_count -v`

Expected: PASS。

Run: `cargo test --features "storage database json" --test parity_export test_protocol_name_afp test_protocol_name_drda -v`

Expected: PASS（2 个）。

Run: `cargo test --features "storage database" --lib core::guess::port -v`

Expected: PASS。

- [x] **Step 5: 提交**

```bash
git add src/core/guess/port.rs src/rule/parser.rs src/parity.rs src/bin/rdpi.rs tests/test_integration.rs tests/test_rule.rs tests/parity_export.rs
git commit -m "Integrate AFP and DRDA detection"
```

---

### Task 7: 语料、golden 与差分门禁

**Files:**
- Modify: `tests/parity/gen_corpus.py`
- Modify: `tests/parity/gen_golden.sh`
- Create: `tests/parity/corpus/afp_dsi.pcap`
- Create: `tests/parity/corpus/drda_message.pcap`
- Create: `tests/parity/golden/afp_dsi.ndpi.json`
- Create: `tests/parity/golden/drda_message.ndpi.json`

**Interfaces:**
- Consumes: detector 已注册（Task 3/Task 5）。
- Produces: 2 个 pcap 与对应 nDPI 5.0 golden。

- [x] **Step 1: 添加语料 builder**

在 `tests/parity/gen_corpus.py` 的 `build_cassandra_startup` 之后追加：

```python
def afp_dsi(flags, command, request_id):
    """构造 AFP DSI 报文头（16 字节，无 body）。"""
    return struct.pack(">BBHIII", flags, command, request_id, 0, 0, 0)


def build_afp_dsi():
    """AFP DSI（TCP 548）：请求 flags=0，响应 flags=1。"""
    request = afp_dsi(0, 1, 1)
    response = afp_dsi(1, 1, 1)
    return tcp_session(CLIENT, SERVER, 50023, 548, [("c", request), ("s", response)])


def build_drda_message():
    """DRDA 单消息（TCP 50000）：length=16, magic=0xD0, length2=10。"""
    message = struct.pack(">HBBHHH", 16, 0xD0, 0x41, 0, 10, 0) + bytes(6)
    return tcp_session(CLIENT, SERVER, 50024, 50000, [("c", message)])
```

在 `CORPUS` 字典的 `"cassandra_startup": build_cassandra_startup,` 之后追加：

```python
    # F51：AFP DSI 与 DRDA 单消息
    "afp_dsi": build_afp_dsi,
    "drda_message": build_drda_message,
```

- [x] **Step 2: 生成语料**

Run: `python -I tests/parity/gen_corpus.py`

Expected: 输出包含 `wrote .../afp_dsi.pcap`、`drda_message.pcap`。

- [x] **Step 3: 扩展 golden 生成脚本**

将 `tests/parity/gen_golden.sh` 的循环列表末尾追加：

```bash
afp_dsi drda_message
```

完整循环行示例：

```bash
for n in http_connect http_proxy doh_resolver dot_alpn dot_port ftp_transfer nbns_registration nbds_datagram nbss_session_request smb1_session_setup smb23_session_setup smb_echo memcached_session elasticsearch_binary amqp_frame mssql_tds_prelogin kafka_metadata_request oracle_connect cassandra_internode cassandra_startup afp_dsi drda_message; do
```

- [x] **Step 4: 生成 golden**

Run: `MSYS_NO_PATHCONV=1 wsl.exe bash /mnt/d/rust_code/rDpi/tests/parity/gen_golden.sh`

Expected: 输出 `DONE`，两个 `.ndpi.json` 生成。

- [x] **Step 5: 核对 golden 输出**

Run:

```bash
python -I - <<'PY'
import json
from pathlib import Path
for name in ("afp_dsi", "drda_message"):
    path = Path("tests/parity/golden") / f"{name}.ndpi.json"
    text = path.read_text()
    decoder = json.JSONDecoder()
    index = 0
    while index < len(text):
        while index < len(text) and text[index] in " \r\n\t":
            index += 1
        if index >= len(text):
            break
        obj, index = decoder.raw_decode(text, index)
        ndpi = obj.get("ndpi", {})
        print(name, "|", ndpi.get("proto"), "|", ndpi.get("category"),
              "|", ndpi.get("breed"), "|", ndpi.get("confidence"))
PY
```

Expected:

```text
afp_dsi | AFP | DataTransfer | Acceptable | {'6': 'DPI'}
drda_message | DRDA | Database | Acceptable | {'6': 'DPI'}
```

若输出与预期不符，先修正 §6 的 parity 映射或语料构造，再继续。

- [x] **Step 6: 运行差分门禁**

Run: `cargo test --all-features --test test_parity_corpus -v`

Expected: PASS。

- [x] **Step 7: 提交**

```bash
git add tests/parity/gen_corpus.py tests/parity/gen_golden.sh tests/parity/corpus/ tests/parity/golden/
git commit -m "Add AFP and DRDA parity corpus"
```

---

### Task 8: 文档回写与全量门禁

**Files:**
- Modify: `AGENTS.md`
- Modify: `docs/architecture/modules.md`
- Modify: `docs/architecture/risks.md`
- Modify: `docs/architecture/ndpi-pure-rust-plan.md`
- Modify: `docs/architecture/protocol-coverage-plan.md`
- Modify memory: `C:\Users\jin\.claude\projects\D--rust-code-rDpi\memory\project_roadmap.md`

**Interfaces:**
- Consumes: 前 7 个任务的全部实现与测试结果。
- Produces: 项目文档与路线图状态同步。

- [x] **Step 1: 更新 AGENTS.md §2 功能条目**

在 F50 条目之后追加：

```markdown
- **AFP + DRDA 识别（F51，2026-11-08）**：阶段 2 第五批（`docs/architecture/phase2-afp-drda-design.md`）——`storage` feature 新增 `Protocol::Afp` + `AfpMetadata{flags,command,request_id,length}`，`database` feature 新增 `Protocol::Drda` + `DrdaMetadata{message_count,message_length}`，无新增 `DissectorState`。AFP detector 严格校验 16 字节 DSI 头（flags<=1、command 1..=8、reserved=0、payload>=16+length），>128 字节载荷不判定；首字节门 `[(0,1)]`；detect 不检查端口，548 仅端口回退。DRDA detector 严格校验 10 字节 DSS/DDM 头（length==length2+6、magic==0xD0、length>=10）并精确消费多消息；首字节门 None；无端口回退。注册：AFP 在 storage 块 nfs 之后；DRDA 在 database 块 oracle 之后。规则名 `afp`/`drda`；parity AFP→DataTransfer/Acceptable、DRDA→Database/Acceptable；语料 +2 pcap + 真实 golden 差分全绿。
```

- [x] **Step 2: 更新 AGENTS.md §3 测试基线**

运行以下命令并记录实际数字：

```bash
cargo test
cargo test --features "storage database"
cargo test --all-features
```

把 §3 中对应行的测试数与日期更新为实测值；在 `cargo test --features database` 行之后新增：

```markdown
cargo test --features "storage database"  # <实测数> 测试全绿（F51 AFP/DRDA 模块 + 语料差分）
```

- [x] **Step 3: 更新 AGENTS.md §6 已知问题索引**

在 F50 行之后追加：

```markdown
| F51 | AFP + DRDA 识别：AFP 16 字节 DSI 头 + >128 字节拒绝；DRDA 10 字节 DSS/DDM 头 + 多消息精确消费；端口回退/规则名/parity/CLI 接入；语料 +2 pcap + 真实 golden 差分 | 中 | ✅ 已完成 2026-11-08（DRDA 多消息与 nDPI 循环差异等边界见 risks.md F51） |
```

- [x] **Step 4: 更新 modules.md**

在 `storage` 行追加 AFP，在 `database` 行追加 DRDA：

```markdown
| storage | nfs, afp（F51，2026-11-08：DSI 16 字节头 + flags/command/reserved 校验） |
```

```markdown
，drda（F51，2026-11-08：DSS/DDM 10 字节头 + 多消息精确消费）
```

- [x] **Step 5: 更新 risks.md**

在 F50 小节之后追加：

```markdown
## F51【中】AFP + DRDA 识别（2026-11-08，新功能开发）—— ✅ 已完成

- **背景**：阶段 2 第五批（`docs/architecture/phase2-afp-drda-design.md`、`docs/architecture/phase2-afp-drda-plan.md`）。收尾 Wave 1B 的 AFP，并补齐数据库缺口 DRDA。
- **实现**：
  - **枚举与元数据**（[core/types.rs](file:///d:/rust_code/rDpi/src/core/types.rs)）：`storage` 新增 `Protocol::Afp` + `AfpMetadata{flags,command,request_id,length}`；`database` 新增 `Protocol::Drda` + `DrdaMetadata{message_count,message_length}`；无新增 `DissectorState`。
  - **AFP 模块**（[src/protocols/afp/](file:///d:/rust_code/rDpi/src/protocols/afp/)）：16 字节 DSI 头；`flags<=1`、`command∈1..=8`、`reserved==0`、`payload.len()>=16+length`；`payload.len()>128` 不判定；首字节门 `[(0,1)]`；detect 不检查端口。
  - **DRDA 模块**（[src/protocols/drda/](file:///d:/rust_code/rDpi/src/protocols/drda/)）：10 字节 DSS/DDM 头；`length==length2+6`、`length>=10`、`magic==0xD0`；多消息精确消费完载荷；首字节门 None；无端口回退。
  - **注册**（[protocols/mod.rs](file:///d:/rust_code/rDpi/src/protocols/mod.rs)）：AFP 在 storage 块 nfs 之后；DRDA 在 database 块 oracle 之后；未改变既有 detector 相对顺序。
  - **集成**：端口回退 548→Afp；规则名 `afp`/`drda`；parity AFP→DataTransfer/Acceptable（内部 FileTransfer，显式映射）、DRDA→Database/Acceptable；CLI 展示 DSI 头字段与 DRDA 消息数/长度。
- **Golden 差分（真实 nDPI 5.0 验证）**：`afp_dsi` → DPI `AFP`（DataTransfer/Acceptable）；`drda_message` → DPI `DRDA`（Database/Acceptable）。
- **已知边界**：① AFP 仅识别 DSI 头，不解析命令体/卷名/文件路径；② AFP >128 字节大数据块不判定（与 nDPI 一致），首包即大数据块时后续不会重新识别；③ mDNS AFP 广告不识别；④ DRDA 不解析 DDM 命令码/SQL/参数；⑤ DRDA 多消息采用严格精确消费，nDPI 循环上界在部分长度组合下不消费最后一条消息，两者可能不一致（parity 只用单消息）；⑥ DRDA 无端口回退、不区分请求/响应方向；⑦ 检测不感知传输层（既有 detector 通病），UDP 上相同结构会命中。
```

- [x] **Step 6: 更新路线图与覆盖清单**

`docs/architecture/ndpi-pure-rust-plan.md`：

- 将第 134 行的 `AFP` 改为 `AFP（✅ F51）`；
- 在 §9 的 F50 条目之后追加：

```markdown
- **P2 Wave 1B 子批次 D：AFP + DRDA（F51，2026-11-08）**
  - AFP：16 字节 DSI 头严格校验（flags/command/reserved/长度下界）+ >128 字节载荷拒绝；首字节门 `[(0,1)]`；548 端口回退；
  - DRDA：10 字节 DSS/DDM 头（length==length2+6、magic=0xD0）+ 多消息精确消费；首字节门 None；无端口回退；
  - 规则名、parity、CLI 接入；语料 +2 pcap + 真实 ndpiReader 5.0 golden 差分全绿。
```

`docs/architecture/protocol-coverage-plan.md`：

- 第 62 行缺口列去掉 AFP（SMB/AFP 均已覆盖）；
- 第 63 行缺口列改为 `ClickHouse 缺失（DRDA 已于 F51 补齐）`；
- 第 123 行 AFP 行尾追加 `（✅ F51 完成，2026-11-08）`；
- 第 283 行把 `AFP、NATS` 改为 `AFP（✅ F51 完成）、NATS`，并在数据库段追加 `DRDA（✅ F51 完成）`。

- [x] **Step 7: 更新路线图记忆**

把 `C:\Users\jin\.claude\projects\D--rust-code-rDpi\memory\project_roadmap.md` 的近期里程碑追加：

```markdown
- F51（2026-11-08）：AFP + DRDA（DSI 16 字节头、DRDA DSS/DDM 头 + 多消息、端口回退/规则名/parity/CLI、语料 +2 golden 差分）
```

并把“下一步候选”中的 `P2 Wave 1B 剩余企业协议：AFP（Oracle/Cassandra 已于 F50 完成）` 改为：

```markdown
- P2 Wave 1B 已完成（AFP/DRDA 于 F51 收尾）；下一波候选：Wave 2 流媒体、数据驱动应用识别、风险对等、P1 边界补齐
```

- [x] **Step 8: 全量门禁**

Run:

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -D warnings
cargo test
cargo test --features "storage database"
cargo test --all-features
```

Expected: 全部通过，clippy 0 警告。若 fmt 产生改动，单独提交：

```bash
git add -u
git commit -m "Apply rustfmt"
```

- [x] **Step 9: 提交文档**

```bash
git add AGENTS.md docs/architecture/modules.md docs/architecture/risks.md docs/architecture/ndpi-pure-rust-plan.md docs/architecture/protocol-coverage-plan.md docs/architecture/phase2-afp-drda-design.md docs/architecture/phase2-afp-drda-plan.md
git commit -m "Document AFP and DRDA support"
```

---

## 自检记录

- **Spec 覆盖**：设计文档 §2（类型/feature）→ Task 1；§3（AFP）→ Task 2/3；§4（DRDA）→ Task 4/5；§5（集成）→ Task 6；§6（parity）→ Task 6；§7（语料）→ Task 7；§8（文件清单）→ 全部任务；§9（测试）→ 各任务测试步骤；§10（边界）→ Task 8 risks.md；§11（实施顺序）→ 任务顺序一致。
- **占位符检查**：无 TBD/TODO；测试数与 AGENTS.md 计数在 Task 8 以实测值回写（测量步骤明确）。
- **类型一致性**：`AfpMetadata`/`DrdaMetadata` 在 Task 1 定义，Task 3/5/6 使用一致；`parse_afp_dsi`/`parse_drda` 签名在 Task 2/4 定义，后续任务引用一致。
