# Oracle + Cassandra Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 在 `database` feature 下新增 Oracle（TNS）与 Cassandra（CQL）识别、元数据、端口回退、规则名、parity 导出、CLI 展示与语料差分。

**Architecture:** 两个无状态 detector，与 F49 MSSQL/Kafka 同构。Oracle 严格校验 TNS Connect 8 字节头并在 `detect_with_context` 要求 1521 端口；Cassandra 识别 19 字节 internode magic（不限端口）与严格解析的 CQL STARTUP 帧。逐包入口复用现有 `tcp_prefix` 前缀补齐能力，不新增 `DissectorState`。

**Tech Stack:** Rust 2024（`rust-version = 1.88`）、现有 `thiserror`/`serde`（json feature）、cargo test / fmt / clippy、Python 3 语料生成、WSL ndpiReader 5.0 golden。

## Global Constraints

- 不新增 Cargo feature 或第三方依赖；复用 `database`。
- 新协议变体与所有引用分支必须带 `#[cfg(feature = "database")]`。
- 禁止修改既有 detector 的相对注册顺序；只允许在 database 块内追加。
- 首字节门契约（AGENTS.md 禁止事项 #6）：声明门后，门区间外的 payload 必须返回 `None`。
- 中文 doc 注释为主；解析失败返回 `None`，不 panic。
- 热路径不引入分配密集逻辑；`String` 仅在命中定型时分配。
- 提交信息不得包含任何 AI 署名（用户规则）；提交只包含代码与项目文档。
- 全量门禁：`cargo fmt --all -- --check`、`cargo clippy --all-features --all-targets -D warnings`、`cargo test`、`cargo test --features database`、`cargo test --all-features`。
- 设计依据：`docs/architecture/phase2-oracle-cassandra-design.md`；nDPI 源码 `D:\c_code\nDPI-5.0`；golden 工具 `/mnt/d/c_code/nDPI-5.0/build/example/ndpiReader`。

---

### Task 1: Protocol 与元数据脚手架

**Files:**
- Modify: `src/core/types.rs`（`Protocol` 枚举、`Metadata` 枚举、元数据结构、`category()`、`breed()`）
- Test: `tests/test_types.rs:326-339`

**Interfaces:**
- Produces: `Protocol::Oracle`、`Protocol::Cassandra`；`OracleMetadata { packet_length: u16, packet_type: u8 }`；`CassandraSource::{Internode, Cql}`；`CassandraMetadata { source, version, stream_id, opcode, cql_version }`；`Metadata::Oracle`、`Metadata::Cassandra`。

- [x] **Step 1: 写失败测试**

在 `tests/test_types.rs` 的 `test_database_protocol_classification_new` 末尾（F49 两行之后）追加：

```rust
    // F50
    assert_eq!(Protocol::Oracle.category(), ProtocolCategory::Database);
    assert_eq!(Protocol::Oracle.breed(), ProtocolBreed::Acceptable);
    assert_eq!(Protocol::Cassandra.category(), ProtocolCategory::Database);
    assert_eq!(Protocol::Cassandra.breed(), ProtocolBreed::Acceptable);
```

- [x] **Step 2: 运行测试确认失败**

Run: `cargo test --features database --test test_types test_database_protocol_classification_new -v`

Expected: 编译失败，提示 `no variant named Oracle` / `Cassandra`。

- [x] **Step 3: 实现类型**

在 `src/core/types.rs` 的 `Protocol::Mssql` 变体之后追加：

```rust
    /// Oracle TNS 协议（feature: database，F50）
    #[cfg(feature = "database")]
    Oracle,
    /// Apache Cassandra CQL 协议（feature: database，F50）
    #[cfg(feature = "database")]
    Cassandra,
```

在 `Metadata` 枚举的 `Mssql(MssqlMetadata)` 之后追加：

```rust
    /// Oracle TNS 元数据 (feature: database, F50)
    #[cfg(feature = "database")]
    Oracle(OracleMetadata),
    /// Cassandra 元数据 (feature: database, F50)
    #[cfg(feature = "database")]
    Cassandra(CassandraMetadata),
```

在 `MssqlMetadata` 定义之后追加：

```rust
/// Oracle TNS Connect 元数据 (feature: database, F50)
#[cfg(feature = "database")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OracleMetadata {
    /// TNS 包长度（命中时等于载荷长度）
    pub packet_length: u16,
    /// TNS 包类型（当前只接受 1 = Connect）
    pub packet_type: u8,
}

/// Cassandra 识别来源 (feature: database, F50)
#[cfg(feature = "database")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CassandraSource {
    /// 19 字节 internode 握手 magic
    #[default]
    Internode,
    /// CQL STARTUP 帧
    Cql,
}

/// Cassandra 元数据 (feature: database, F50)
#[cfg(feature = "database")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CassandraMetadata {
    /// 识别来源
    pub source: CassandraSource,
    /// CQL 协议版本（0x02..=0x05；internode 为 None）
    pub version: Option<u8>,
    /// CQL stream id（internode 为 None）
    pub stream_id: Option<u16>,
    /// CQL opcode（STARTUP = 0x01；internode 为 None）
    pub opcode: Option<u8>,
    /// STARTUP string map 中的 CQL_VERSION 值（如 "3.0.0"）
    pub cql_version: Option<String>,
}
```

在 `category()` 的 `Protocol::Mssql => ProtocolCategory::Database,` 之后追加：

```rust
            // F50 数据库协议
            #[cfg(feature = "database")]
            Protocol::Oracle | Protocol::Cassandra => ProtocolCategory::Database,
```

在 `breed()` 的 `Protocol::Mssql => ProtocolBreed::Acceptable,` 之后追加：

```rust
            #[cfg(feature = "database")]
            Protocol::Oracle | Protocol::Cassandra => ProtocolBreed::Acceptable,
```

- [x] **Step 4: 运行测试确认通过**

Run: `cargo test --features database --test test_types test_database_protocol_classification_new -v`

Expected: PASS。

- [x] **Step 5: 提交**

```bash
git add src/core/types.rs tests/test_types.rs
git commit -m "Add Oracle and Cassandra protocol types"
```

---

### Task 2: Oracle 解析器

**Files:**
- Create: `src/protocols/oracle/parser.rs`
- Create: `src/protocols/oracle/mod.rs`（本任务只声明 `parser`）
- Modify: `src/protocols/mod.rs`（模块声明）

**Interfaces:**
- Produces: `pub const ORACLE_CONNECT_HEADER_LEN: usize = 8`；`pub struct OracleParsed { pub packet_length: u16, pub packet_type: u8 }`；`pub fn parse_oracle_connect(payload: &[u8]) -> Option<OracleParsed>`。

- [x] **Step 1: 写失败测试与桩实现**

创建 `src/protocols/oracle/parser.rs`：

```rust
//! Oracle TNS Connect 报文头解析（与 nDPI 5.0 `oracle.c` 判定一致）

/// TNS Connect 报文头固定长度
pub const ORACLE_CONNECT_HEADER_LEN: usize = 8;

/// TNS Connect 报文头解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleParsed {
    /// TNS 包长度（命中时等于载荷长度）
    pub packet_length: u16,
    /// TNS 包类型（1 = Connect）
    pub packet_type: u8,
}

/// 解析 TNS Connect 报文头
pub fn parse_oracle_connect(_payload: &[u8]) -> Option<OracleParsed> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect(body: &[u8]) -> Vec<u8> {
        let total = (ORACLE_CONNECT_HEADER_LEN + body.len()) as u16;
        let mut packet = Vec::new();
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.push(0x01);
        packet.push(0x00);
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(body);
        packet
    }

    #[test]
    fn test_parse_connect_header_only() {
        let parsed = parse_oracle_connect(&connect(b"")).unwrap();
        assert_eq!(parsed.packet_length, 8);
        assert_eq!(parsed.packet_type, 1);
    }

    #[test]
    fn test_parse_connect_with_body() {
        let parsed = parse_oracle_connect(&connect(b"\x01\x02\x03\x04")).unwrap();
        assert_eq!(parsed.packet_length, 12);
    }

    #[test]
    fn test_reject_short_payload() {
        assert!(parse_oracle_connect(&[0x00, 0x08, 0x00]).is_none());
    }

    #[test]
    fn test_reject_length_mismatch() {
        let mut payload = connect(b"");
        payload[0..2].copy_from_slice(&9u16.to_be_bytes());
        assert!(parse_oracle_connect(&payload).is_none());
    }

    #[test]
    fn test_reject_nonzero_packet_checksum() {
        let mut payload = connect(b"");
        payload[2] = 1;
        assert!(parse_oracle_connect(&payload).is_none());
    }

    #[test]
    fn test_reject_non_connect_type() {
        let mut payload = connect(b"");
        payload[4] = 2;
        assert!(parse_oracle_connect(&payload).is_none());
    }

    #[test]
    fn test_reject_nonzero_reserved() {
        let mut payload = connect(b"");
        payload[5] = 1;
        assert!(parse_oracle_connect(&payload).is_none());
    }

    #[test]
    fn test_reject_nonzero_header_checksum() {
        let mut payload = connect(b"");
        payload[7] = 1;
        assert!(parse_oracle_connect(&payload).is_none());
    }
}
```

创建 `src/protocols/oracle/mod.rs`：

```rust
//! Oracle TNS protocol detection module for rDpi

pub mod parser;
```

在 `src/protocols/mod.rs` 的 `pub mod mssql;` 之后追加：

```rust
#[cfg(feature = "database")]
pub mod oracle;
```

- [x] **Step 2: 运行测试确认失败**

Run: `cargo test --features database oracle::parser -v`

Expected: 8 个测试失败（桩实现返回 `None`）。

- [x] **Step 3: 实现解析器**

将 `parse_oracle_connect` 替换为：

```rust
/// 解析 TNS Connect 报文头
///
/// 命中条件（nDPI 5.0 `oracle.c`）：
/// - 载荷长度 ≥ 8；
/// - `packet_length` 等于载荷总长度；
/// - 包校验和、保留字段、头校验和均为 0；
/// - 包类型为 1（Connect）。
pub fn parse_oracle_connect(payload: &[u8]) -> Option<OracleParsed> {
    if payload.len() < ORACLE_CONNECT_HEADER_LEN {
        return None;
    }
    let packet_length = u16::from_be_bytes([payload[0], payload[1]]);
    if packet_length as usize != payload.len() {
        return None;
    }
    if payload[2] != 0 || payload[3] != 0 {
        return None;
    }
    if payload[4] != 0x01 {
        return None;
    }
    if payload[5] != 0 || payload[6] != 0 || payload[7] != 0 {
        return None;
    }
    Some(OracleParsed {
        packet_length,
        packet_type: payload[4],
    })
}
```

- [x] **Step 4: 运行测试确认通过**

Run: `cargo test --features database oracle::parser -v`

Expected: PASS（8 个测试）。

- [x] **Step 5: 提交**

```bash
git add src/protocols/oracle/parser.rs src/protocols/oracle/mod.rs src/protocols/mod.rs
git commit -m "Add Oracle TNS parser"
```

---

### Task 3: Oracle detector、注册与入口测试

**Files:**
- Create: `src/protocols/oracle/detector.rs`
- Modify: `src/protocols/oracle/mod.rs`
- Modify: `src/protocols/mod.rs`（注册）
- Create: `tests/test_oracle_cassandra.rs`（本任务先写 Oracle 用例）

**Interfaces:**
- Consumes: `parse_oracle_connect`、`OracleParsed`（Task 2）。
- Produces: `OracleDetector`；`oracle::register(&mut Registry)`。

- [x] **Step 1: 写 detector 与测试**

创建 `src/protocols/oracle/detector.rs`：

```rust
//! Oracle TNS protocol detector for rDpi

use crate::core::types::{
    Confidence, DetectContext, DetectionResult, Metadata, OracleMetadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::parse_oracle_connect;

/// Oracle TNS 默认端口
const ORACLE_PORT: u16 = 1521;

/// Oracle TNS protocol detector
pub struct OracleDetector {
    _private: (),
}

impl OracleDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for OracleDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for OracleDetector {
    fn name(&self) -> &'static str {
        "oracle"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_oracle_connect(payload)?;
        Some(
            DetectionResult::new(Protocol::Oracle)
                .with_metadata(Metadata::Oracle(OracleMetadata {
                    packet_length: parsed.packet_length,
                    packet_type: parsed.packet_type,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }

    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        if ctx.src_port != ORACLE_PORT && ctx.dst_port != ORACLE_PORT {
            return None;
        }
        self.detect(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect(body: &[u8]) -> Vec<u8> {
        let total = (8 + body.len()) as u16;
        let mut packet = Vec::new();
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.push(0x01);
        packet.push(0x00);
        packet.extend_from_slice(&[0, 0]);
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
    fn test_detect_connect() {
        let detector = OracleDetector::new();
        let result = detector.detect(&connect(b"\x00\x00")).unwrap();
        assert_eq!(result.protocol, Protocol::Oracle);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Oracle(meta) => {
                assert_eq!(meta.packet_length, 10);
                assert_eq!(meta.packet_type, 1);
            }
            _ => panic!("expected Oracle metadata"),
        }
    }

    #[test]
    fn test_reject_http() {
        let detector = OracleDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_detect_with_context_requires_port_1521() {
        let detector = OracleDetector::new();
        let payload = connect(b"");
        assert!(
            detector
                .detect_with_context(&payload, &ctx(50000, 1521))
                .is_some()
        );
        assert!(
            detector
                .detect_with_context(&payload, &ctx(1521, 50000))
                .is_some()
        );
        assert!(
            detector
                .detect_with_context(&payload, &ctx(50000, 1522))
                .is_none()
        );
    }

    #[test]
    fn test_first_byte_gate_is_none() {
        let detector = OracleDetector::new();
        assert!(detector.first_byte_gate().is_none());
    }
}
```

将 `src/protocols/oracle/mod.rs` 替换为：

```rust
//! Oracle TNS protocol detection module for rDpi
//!
//! 识别 TCP 1521 上的 TNS Connect 报文头（8 字节）。

mod detector;
pub mod parser;

pub use detector::OracleDetector;
pub use parser::{ORACLE_CONNECT_HEADER_LEN, OracleParsed, parse_oracle_connect};

use crate::protocols::Registry;

/// Register Oracle detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(OracleDetector::new()));
}
```

在 `src/protocols/mod.rs` 的 `mssql::register(_registry);` 之后追加：

```rust
    #[cfg(feature = "database")]
    oracle::register(_registry);
```

- [x] **Step 2: 运行模块测试**

Run: `cargo test --features database oracle -v`

Expected: PASS（parser 8 + detector 4）。

- [x] **Step 3: 写入口跨段测试**

创建 `tests/test_oracle_cassandra.rs`：

```rust
//! F50：Oracle/Cassandra 经双向入口的跨段识别

#![cfg(feature = "database")]

use rdpi::{Detector, Protocol};

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

/// 三次握手 + 客户端按 `segments` 顺序发送的多个 TCP 段
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

fn detect(frames: &[Vec<u8>]) -> Option<Protocol> {
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

#[test]
fn oracle_connect_split_across_segments_is_detected() {
    let payload = [0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    let frames = client_session(50030, 1521, &[&payload[..4], &payload[4..]]);
    assert_eq!(detect(&frames), Some(Protocol::Oracle));
}
```

- [x] **Step 4: 运行入口测试**

Run: `cargo test --features database --test test_oracle_cassandra -v`

Expected: PASS（1 个用例）。

- [x] **Step 5: 提交**

```bash
git add src/protocols/oracle/ src/protocols/mod.rs tests/test_oracle_cassandra.rs
git commit -m "Add Oracle detector"
```

---

### Task 4: Cassandra 解析器

**Files:**
- Create: `src/protocols/cassandra/parser.rs`
- Create: `src/protocols/cassandra/mod.rs`（本任务只声明 `parser`）
- Modify: `src/protocols/mod.rs`（模块声明）

**Interfaces:**
- Produces:
  - `CASSANDRA_INTERNODE_MAGIC: u32 = 0xCA55_2DFA`
  - `CASSANDRA_INTERNODE_LEN: usize = 19`
  - `CQL_STARTUP_HEADER_LEN: usize = 9`
  - `enum CassandraParsed { Internode, Cql(CassandraStartupParsed) }`
  - `struct CassandraStartupParsed { version: u8, stream_id: u16, opcode: u8, cql_version: String }`
  - `fn parse_cassandra(payload: &[u8]) -> Option<CassandraParsed>`
  - `fn parse_cassandra_startup(payload: &[u8]) -> Option<CassandraStartupParsed>`

- [x] **Step 1: 写失败测试与桩实现**

创建 `src/protocols/cassandra/parser.rs`：

```rust
//! Cassandra CQL 解析（internode magic + STARTUP 帧）

/// internode 通信 magic
pub const CASSANDRA_INTERNODE_MAGIC: u32 = 0xCA55_2DFA;
/// internode 通信报文长度
pub const CASSANDRA_INTERNODE_LEN: usize = 19;
/// CQL 请求头固定长度
pub const CQL_STARTUP_HEADER_LEN: usize = 9;
/// STARTUP opcode
pub const CQL_OPCODE_STARTUP: u8 = 0x01;
/// string map 条目数上限
const CQL_MAX_MAP_ENTRIES: usize = 64;

/// Cassandra 解析结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CassandraParsed {
    /// internode 握手 magic
    Internode,
    /// CQL STARTUP 帧
    Cql(CassandraStartupParsed),
}

/// CQL STARTUP 帧解析结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CassandraStartupParsed {
    pub version: u8,
    pub stream_id: u16,
    pub opcode: u8,
    pub cql_version: String,
}

/// 解析 Cassandra 载荷
pub fn parse_cassandra(_payload: &[u8]) -> Option<CassandraParsed> {
    None
}

/// 解析 CQL STARTUP 帧
pub fn parse_cassandra_startup(_payload: &[u8]) -> Option<CassandraStartupParsed> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn internode() -> Vec<u8> {
        let mut payload = CASSANDRA_INTERNODE_MAGIC.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0u8; 15]);
        payload
    }

    fn startup(version: u8, cql_version: &str, extra: &[(&str, &str)]) -> Vec<u8> {
        let mut entries: Vec<(&str, &str)> = vec![("CQL_VERSION", cql_version)];
        entries.extend_from_slice(extra);
        let mut body = Vec::new();
        body.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for (key, value) in entries {
            body.extend_from_slice(&(key.len() as u16).to_be_bytes());
            body.extend_from_slice(key.as_bytes());
            body.extend_from_slice(&(value.len() as u16).to_be_bytes());
            body.extend_from_slice(value.as_bytes());
        }
        let mut frame = vec![version, 0x00, 0x00, 0x01, CQL_OPCODE_STARTUP];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn test_internode_magic() {
        assert_eq!(
            parse_cassandra(&internode()),
            Some(CassandraParsed::Internode)
        );
    }

    #[test]
    fn test_reject_internode_wrong_length() {
        let mut payload = internode();
        payload.pop();
        assert!(parse_cassandra(&payload).is_none());
        payload.extend_from_slice(&[0, 0]);
        assert!(parse_cassandra(&payload).is_none());
    }

    #[test]
    fn test_reject_internode_wrong_magic() {
        let mut payload = internode();
        payload[0] = 0;
        assert!(parse_cassandra(&payload).is_none());
    }

    #[test]
    fn test_startup_v4() {
        let parsed = parse_cassandra_startup(&startup(0x04, "3.0.0", &[])).unwrap();
        assert_eq!(parsed.version, 0x04);
        assert_eq!(parsed.stream_id, 1);
        assert_eq!(parsed.opcode, CQL_OPCODE_STARTUP);
        assert_eq!(parsed.cql_version, "3.0.0");
    }

    #[test]
    fn test_startup_versions_v2_to_v5() {
        for version in [0x02u8, 0x03, 0x04, 0x05] {
            assert!(
                parse_cassandra_startup(&startup(version, "3.0.0", &[])).is_some(),
                "version 0x{version:02X} 应命中"
            );
        }
    }

    #[test]
    fn test_startup_multiple_entries() {
        let parsed = parse_cassandra_startup(&startup(
            0x04,
            "3.4.5",
            &[("DRIVER_NAME", "DataStax"), ("DRIVER_VERSION", "1.0")],
        ))
        .unwrap();
        assert_eq!(parsed.cql_version, "3.4.5");
    }

    #[test]
    fn test_reject_missing_cql_version() {
        let body = {
            let mut body = Vec::new();
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&9u16.to_be_bytes());
            body.extend_from_slice(b"COMPRESS");
            body.extend_from_slice(&0u16.to_be_bytes());
            body
        };
        let mut frame = vec![0x04, 0x00, 0x00, 0x01, CQL_OPCODE_STARTUP];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_truncated_map() {
        let mut frame = startup(0x04, "3.0.0", &[]);
        frame.pop();
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_zero_entries() {
        let mut frame = vec![0x04, 0x00, 0x00, 0x01, CQL_OPCODE_STARTUP];
        frame.extend_from_slice(&2u32.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_non_printable_key() {
        let body = {
            let mut body = Vec::new();
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&2u16.to_be_bytes());
            body.extend_from_slice(&[0x01, 0x02]);
            body.extend_from_slice(&2u16.to_be_bytes());
            body.extend_from_slice(b"v1");
            body
        };
        let mut frame = vec![0x04, 0x00, 0x00, 0x01, CQL_OPCODE_STARTUP];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_non_printable_cql_version_value() {
        let body = {
            let mut body = Vec::new();
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&11u16.to_be_bytes());
            body.extend_from_slice(b"CQL_VERSION");
            body.extend_from_slice(&2u16.to_be_bytes());
            body.extend_from_slice(&[0x01, 0x02]);
            body
        };
        let mut frame = vec![0x04, 0x00, 0x00, 0x01, CQL_OPCODE_STARTUP];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_non_startup_opcode() {
        let mut frame = startup(0x04, "3.0.0", &[]);
        frame[4] = 0x05;
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_invalid_versions() {
        for version in [0x01u8, 0x06, 0x80, 0x83] {
            assert!(
                parse_cassandra_startup(&startup(version, "3.0.0", &[])).is_none(),
                "version 0x{version:02X} 应拒绝"
            );
        }
    }

    #[test]
    fn test_reject_length_mismatch() {
        let mut frame = startup(0x04, "3.0.0", &[]);
        frame.extend_from_slice(&[0x00]);
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_invalid_flags() {
        let mut frame = startup(0x04, "3.0.0", &[]);
        frame[1] = 0x20;
        assert!(parse_cassandra_startup(&frame).is_none());
    }

    #[test]
    fn test_reject_short_payload() {
        assert!(parse_cassandra_startup(&[0x04, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_parse_cassandra_prefers_startup() {
        let parsed = parse_cassandra(&startup(0x04, "3.0.0", &[])).unwrap();
        assert!(matches!(parsed, CassandraParsed::Cql(_)));
    }
}
```

创建 `src/protocols/cassandra/mod.rs`：

```rust
//! Apache Cassandra CQL protocol detection module for rDpi

pub mod parser;
```

在 `src/protocols/mod.rs` 的 `pub mod oracle;` 之后追加：

```rust
#[cfg(feature = "database")]
pub mod cassandra;
```

- [x] **Step 2: 运行测试确认失败**

Run: `cargo test --features database cassandra::parser -v`

Expected: 17 个测试失败（桩实现返回 `None`）。

- [x] **Step 3: 实现解析器**

将 `parse_cassandra` 与 `parse_cassandra_startup` 替换为：

```rust
/// 解析 Cassandra 载荷：先尝试 internode magic，再尝试 CQL STARTUP
pub fn parse_cassandra(payload: &[u8]) -> Option<CassandraParsed> {
    if payload.len() == CASSANDRA_INTERNODE_LEN
        && u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
            == CASSANDRA_INTERNODE_MAGIC
    {
        return Some(CassandraParsed::Internode);
    }
    parse_cassandra_startup(payload).map(CassandraParsed::Cql)
}

/// 解析 CQL STARTUP 帧
///
/// 命中条件：
/// - 版本 0x02..=0x05（请求方向）；
/// - flags 仅低 5 位有定义；
/// - opcode 为 STARTUP（0x01）；
/// - 长度字段精确等于 `payload.len() - 9`；
/// - body 是完整 string map（条目数 1..=64，恰好消费完），且包含 `CQL_VERSION`。
pub fn parse_cassandra_startup(payload: &[u8]) -> Option<CassandraStartupParsed> {
    if payload.len() < CQL_STARTUP_HEADER_LEN {
        return None;
    }
    let version = payload[0];
    if !(0x02..=0x05).contains(&version) {
        return None;
    }
    if payload[1] & 0xE0 != 0 {
        return None;
    }
    let stream_id = u16::from_be_bytes([payload[2], payload[3]]);
    let opcode = payload[4];
    if opcode != CQL_OPCODE_STARTUP {
        return None;
    }
    let body_len = u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]) as usize;
    if body_len != payload.len() - CQL_STARTUP_HEADER_LEN {
        return None;
    }
    let cql_version = parse_cql_version(&payload[CQL_STARTUP_HEADER_LEN..])?;
    Some(CassandraStartupParsed {
        version,
        stream_id,
        opcode,
        cql_version,
    })
}

fn parse_cql_version(body: &[u8]) -> Option<String> {
    let count = read_u16(body, &mut 0)? as usize;
    if count == 0 || count > CQL_MAX_MAP_ENTRIES {
        return None;
    }
    let mut offset = 2usize;
    let mut cql_version = None;
    for _ in 0..count {
        let key_len = read_u16(body, &mut offset)? as usize;
        let key_end = offset.checked_add(key_len)?;
        let key = body.get(offset..key_end)?;
        offset = key_end;
        if !key.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            return None;
        }
        let value_len = read_u16(body, &mut offset)? as usize;
        let value_end = offset.checked_add(value_len)?;
        let value = body.get(offset..value_end)?;
        offset = value_end;
        if key == b"CQL_VERSION".as_slice() {
            if !value.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
                return None;
            }
            cql_version = Some(String::from_utf8_lossy(value).into_owned());
        }
    }
    if offset != body.len() {
        return None;
    }
    cql_version
}

fn read_u16(buffer: &[u8], offset: &mut usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = buffer.get(*offset..end)?;
    *offset = end;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}
```

- [x] **Step 4: 运行测试确认通过**

Run: `cargo test --features database cassandra::parser -v`

Expected: PASS（17 个测试）。

- [x] **Step 5: 提交**

```bash
git add src/protocols/cassandra/parser.rs src/protocols/cassandra/mod.rs src/protocols/mod.rs
git commit -m "Add Cassandra CQL parser"
```

---

### Task 5: Cassandra detector、注册与入口测试

**Files:**
- Create: `src/protocols/cassandra/detector.rs`
- Modify: `src/protocols/cassandra/mod.rs`
- Modify: `src/protocols/mod.rs`（注册）
- Modify: `tests/test_oracle_cassandra.rs`（追加 Cassandra 用例）

**Interfaces:**
- Consumes: `parse_cassandra`、`CassandraParsed`（Task 4）。
- Produces: `CassandraDetector`；`cassandra::register(&mut Registry)`。

- [x] **Step 1: 写 detector 与测试**

创建 `src/protocols/cassandra/detector.rs`：

```rust
//! Apache Cassandra CQL protocol detector for rDpi

use crate::core::types::{
    CassandraMetadata, CassandraSource, Confidence, DetectionResult, Metadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::{CassandraParsed, parse_cassandra};

/// Apache Cassandra protocol detector
pub struct CassandraDetector {
    _private: (),
}

impl CassandraDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for CassandraDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for CassandraDetector {
    fn name(&self) -> &'static str {
        "cassandra"
    }

    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x02, 0x05), (0xCA, 0xCA)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_cassandra(payload)?;
        let metadata = match parsed {
            CassandraParsed::Internode => CassandraMetadata {
                source: CassandraSource::Internode,
                ..Default::default()
            },
            CassandraParsed::Cql(startup) => CassandraMetadata {
                source: CassandraSource::Cql,
                version: Some(startup.version),
                stream_id: Some(startup.stream_id),
                opcode: Some(startup.opcode),
                cql_version: Some(startup.cql_version),
            },
        };
        Some(
            DetectionResult::new(Protocol::Cassandra)
                .with_metadata(Metadata::Cassandra(metadata))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn internode() -> Vec<u8> {
        let mut payload = vec![0xCA, 0x55, 0x2D, 0xFA];
        payload.extend_from_slice(&[0u8; 15]);
        payload
    }

    fn startup(cql_version: &str) -> Vec<u8> {
        let key = b"CQL_VERSION";
        let value = cql_version.as_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&(key.len() as u16).to_be_bytes());
        body.extend_from_slice(key);
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value);
        let mut frame = vec![0x04, 0x00, 0x00, 0x01, 0x01];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn test_detect_internode() {
        let detector = CassandraDetector::new();
        let result = detector.detect(&internode()).unwrap();
        assert_eq!(result.protocol, Protocol::Cassandra);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Cassandra(meta) => {
                assert_eq!(meta.source, CassandraSource::Internode);
                assert_eq!(meta.version, None);
                assert_eq!(meta.cql_version, None);
            }
            _ => panic!("expected Cassandra metadata"),
        }
    }

    #[test]
    fn test_detect_startup() {
        let detector = CassandraDetector::new();
        let result = detector.detect(&startup("3.0.0")).unwrap();
        match result.metadata {
            Metadata::Cassandra(meta) => {
                assert_eq!(meta.source, CassandraSource::Cql);
                assert_eq!(meta.version, Some(0x04));
                assert_eq!(meta.stream_id, Some(1));
                assert_eq!(meta.opcode, Some(0x01));
                assert_eq!(meta.cql_version.as_deref(), Some("3.0.0"));
            }
            _ => panic!("expected Cassandra metadata"),
        }
    }

    #[test]
    fn test_reject_http() {
        let detector = CassandraDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_samples() {
        let detector = CassandraDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let samples = [internode(), startup("3.0.0")];
        for payload in &samples {
            assert!(
                gate.iter()
                    .any(|&(lo, hi)| payload[0] >= lo && payload[0] <= hi),
                "门区间不覆盖合法样本首字节 0x{:02X}",
                payload[0]
            );
        }
        for byte in [0u8, 0x01, 0x06, 0x80, 0xCB] {
            assert!(!gate.iter().any(|&(lo, hi)| byte >= lo && byte <= hi));
        }
    }
}
```

将 `src/protocols/cassandra/mod.rs` 替换为：

```rust
//! Apache Cassandra CQL protocol detection module for rDpi
//!
//! 识别 19 字节 internode magic 与 CQL STARTUP 帧。

mod detector;
pub mod parser;

pub use detector::CassandraDetector;
pub use parser::{
    CASSANDRA_INTERNODE_LEN, CASSANDRA_INTERNODE_MAGIC, CQL_OPCODE_STARTUP,
    CQL_STARTUP_HEADER_LEN, CassandraParsed, CassandraStartupParsed, parse_cassandra,
    parse_cassandra_startup,
};

use crate::protocols::Registry;

/// Register Cassandra detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(CassandraDetector::new()));
}
```

在 `src/protocols/mod.rs` 的 `register_defaults` 最前面、`quic::register(_registry);` 之前插入（internode magic 首字节 `0xCA` 与 QUIC 长包头门冲突，必须先于 QUIC）：

```rust
    #[cfg(feature = "database")]
    cassandra::register(_registry);
```

同时在注册处写明影响面注释：Cassandra 门仅 `{0x02..=0x05, 0xCA}`，真实 QUIC 短包头为 `0x40..=0x7F`、长包头 `0xC0..=0xFF`，只有 `0xCA` 落入 Cassandra 门且需 19 字节精确 magic 或严格 STARTUP，不会抢占真实 QUIC。

- [x] **Step 2: 运行模块测试**

Run: `cargo test --features database cassandra -v`

Expected: PASS（parser 17 + detector 4）。

- [x] **Step 3: 追加 Cassandra 入口测试**

在 `tests/test_oracle_cassandra.rs` 末尾追加：

```rust
fn cql_startup(cql_version: &str) -> Vec<u8> {
    let key = b"CQL_VERSION";
    let value = cql_version.as_bytes();
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&(key.len() as u16).to_be_bytes());
    body.extend_from_slice(key);
    body.extend_from_slice(&(value.len() as u16).to_be_bytes());
    body.extend_from_slice(value);
    let mut frame = vec![0x04, 0x00, 0x00, 0x01, 0x01];
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

#[test]
fn cassandra_startup_split_across_segments_is_detected() {
    let payload = cql_startup("3.0.0");
    let split = payload.len() / 2;
    let frames = client_session(50031, 9042, &[&payload[..split], &payload[split..]]);
    assert_eq!(detect(&frames), Some(Protocol::Cassandra));
}

#[test]
fn cassandra_internode_is_port_independent() {
    let mut payload = vec![0xCA, 0x55, 0x2D, 0xFA];
    payload.extend_from_slice(&[0u8; 15]);
    let frames = client_session(50032, 9999, &[&payload]);
    assert_eq!(detect(&frames), Some(Protocol::Cassandra));
}
```

- [x] **Step 4: 运行入口测试**

Run: `cargo test --features database --test test_oracle_cassandra -v`

Expected: PASS（3 个用例）。

- [x] **Step 5: 提交**

```bash
git add src/protocols/cassandra/ src/protocols/mod.rs tests/test_oracle_cassandra.rs
git commit -m "Add Cassandra detector"
```

---

### Task 6: 端口回退、规则名、parity、CLI 与计数

**Files:**
- Modify: `src/core/guess/port.rs`
- Modify: `src/rule/parser.rs`
- Modify: `src/parity.rs`
- Modify: `src/bin/rdpi.rs`
- Modify: `tests/test_integration.rs:206-209`
- Modify: `tests/test_rule.rs`
- Modify: `tests/parity_export.rs`

**Interfaces:**
- Consumes: `Protocol::Oracle`、`Protocol::Cassandra`、`CassandraSource`。
- Produces: 1521/7000/9042 端口回退；`oracle`/`cassandra` 规则名；`Database/Acceptable` parity 映射；CLI 元数据展示。

- [x] **Step 1: 写失败测试**

在 `src/core/guess/port.rs` 的 tests 模块末尾追加：

```rust
    #[cfg(feature = "database")]
    #[test]
    fn test_oracle_cassandra_ports() {
        assert_eq!(match_port(1521).unwrap().protocol, Protocol::Oracle);
        assert_eq!(match_port(7000).unwrap().protocol, Protocol::Cassandra);
        assert_eq!(match_port(9042).unwrap().protocol, Protocol::Cassandra);
        assert_eq!(
            match_port(9042).unwrap().confidence,
            Confidence::MatchByPort
        );
    }
```

在 `tests/test_rule.rs` 末尾追加：

```rust
#[cfg(feature = "database")]
#[test]
fn test_rule_parser_oracle_cassandra_protocol_names() {
    let json = r#"{
        "rules": [
            {"id": "oracle", "protocol": "oracle", "condition": {"dst_port": 1521}},
            {"id": "cassandra", "protocol": "cassandra", "condition": {"dst_port": 9042}}
        ]
    }"#;
    let engine = RuleEngine::from_json(json).unwrap();

    for (dst_port, expected) in [
        (1521u16, Protocol::Oracle),
        (9042, Protocol::Cassandra),
    ] {
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

在 `tests/parity_export.rs` 末尾追加：

```rust
#[cfg(feature = "database")]
#[test]
fn test_protocol_name_oracle_cassandra() {
    for (protocol, name) in [
        (Protocol::Oracle, "Oracle"),
        (Protocol::Cassandra, "Cassandra"),
    ] {
        let flow = flow_with_protocol(protocol);
        let normalized = NormalizedFlow::from_flow(&flow);
        assert_eq!(normalized.master_protocol.as_deref(), Some(name));
        assert_eq!(normalized.app_protocol, None);
        assert_eq!(normalized.category.as_deref(), Some("Database"));
        assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
    }
}
```

将 `tests/test_integration.rs` 的 database 计数改为：

```rust
        #[cfg(feature = "database")]
        {
            count += 9; // MySQL + PostgreSQL + Redis + MongoDB + Memcached + Elasticsearch（F46）+ MSSQL（F49）+ Oracle/Cassandra（F50）
        }
```

- [x] **Step 2: 运行测试确认失败**

Run: `cargo test --features database --test test_rule test_rule_parser_oracle_cassandra_protocol_names -v`

Expected: 编译失败或断言失败（`Protocol::Oracle` 规则名未映射）。

Run: `cargo test --features database --test test_integration test_registry_default_detector_count -v`

Expected: FAIL（实际 detector 数比期望少 2）。

- [x] **Step 3: 实现集成**

在 `src/core/guess/port.rs` 的 `PORT_MAP` 中，`Mssql` 1434 条目之后追加：

```rust
    #[cfg(feature = "database")]
    (1521u16, &[Protocol::Oracle]),
    #[cfg(feature = "database")]
    (7000u16, &[Protocol::Cassandra]),
    #[cfg(feature = "database")]
    (9042u16, &[Protocol::Cassandra]),
```

在 `src/rule/parser.rs` 的 mssql 名称映射之后追加：

```rust
                    #[cfg(feature = "database")]
                    "oracle" => Protocol::Oracle,
                    #[cfg(feature = "database")]
                    "cassandra" => Protocol::Cassandra,
```

在 `src/parity.rs` 的 `Protocol::Mssql` 映射之后追加：

```rust
        // F50（nDPI 5.0 源码核对）：Oracle/Cassandra 均归 Database/Acceptable
        #[cfg(feature = "database")]
        Protocol::Oracle | Protocol::Cassandra => {
            ("Database".to_string(), "Acceptable".to_string())
        }
```

在 `src/bin/rdpi.rs` 的 `formatted_meta` match 中，`Metadata::Kafka` 分支之后追加：

```rust
        #[cfg(feature = "database")]
        rdpi::Metadata::Oracle(o) => Some(format!(
            "length={} type={}",
            o.packet_length, o.packet_type
        )),
        #[cfg(feature = "database")]
        rdpi::Metadata::Cassandra(c) => Some(match c.source {
            rdpi::CassandraSource::Internode => "source=internode".to_string(),
            rdpi::CassandraSource::Cql => format!(
                "source=cql version=0x{:02X} stream={} cql_version={}",
                c.version.unwrap_or(0),
                c.stream_id.unwrap_or(0),
                c.cql_version.as_deref().unwrap_or("")
            ),
        }),
```

- [x] **Step 4: 运行测试确认通过**

Run: `cargo test --features database --test test_rule test_rule_parser_oracle_cassandra_protocol_names -v`

Expected: PASS。

Run: `cargo test --features database --test test_integration test_registry_default_detector_count -v`

Expected: PASS。

Run: `cargo test --features database --test parity_export test_protocol_name_oracle_cassandra -v`

Expected: PASS。

Run: `cargo test --features database --lib core::guess::port -v`

Expected: PASS。

- [x] **Step 5: 提交**

```bash
git add src/core/guess/port.rs src/rule/parser.rs src/parity.rs src/bin/rdpi.rs tests/test_integration.rs tests/test_rule.rs tests/parity_export.rs
git commit -m "Integrate Oracle and Cassandra detection"
```

---

### Task 7: 语料、golden 与差分门禁

**Files:**
- Modify: `tests/parity/gen_corpus.py`
- Modify: `tests/parity/gen_golden.sh`
- Create: `tests/parity/corpus/oracle_connect.pcap`
- Create: `tests/parity/corpus/cassandra_internode.pcap`
- Create: `tests/parity/corpus/cassandra_startup.pcap`
- Create: `tests/parity/golden/oracle_connect.ndpi.json`
- Create: `tests/parity/golden/cassandra_internode.ndpi.json`
- Create: `tests/parity/golden/cassandra_startup.ndpi.json`

**Interfaces:**
- Consumes: detector 已注册（Task 3/Task 5）。
- Produces: 3 个 pcap 与对应 nDPI 5.0 golden。

- [x] **Step 1: 添加语料 builder**

在 `tests/parity/gen_corpus.py` 的 `build_kafka_metadata_request` 之后追加：

```python
def tns_packet(packet_type, body=b""):
    """构造 TNS 报文（8 字节头：长度/包校验和/类型/保留/头校验和）。"""
    total = 8 + len(body)
    return struct.pack(">HHBBH", total, 0, packet_type, 0, 0) + body


def build_oracle_connect():
    """Oracle TNS Connect（TCP 1521）：type=1，长度精确等于载荷长度。"""
    request = tns_packet(1)
    response = tns_packet(2, b"\x00\x00\x00\x00")
    return tcp_session(CLIENT, SERVER, 50020, 1521, [("c", request), ("s", response)])


def build_cassandra_internode():
    """Cassandra internode magic（TCP 7000）：19 字节 0xCA552DFA + 15 字节。"""
    payload = struct.pack(">I", 0xCA552DFA) + bytes(15)
    return tcp_session(CLIENT, SERVER, 50021, 7000, [("c", payload)])


def cql_startup_frame(cql_version="3.0.0"):
    """构造 CQL v4 STARTUP 帧（9 字节头 + CQL_VERSION string map）。"""
    key = b"CQL_VERSION"
    value = cql_version.encode()
    body = (
        struct.pack(">H", 1)
        + struct.pack(">H", len(key))
        + key
        + struct.pack(">H", len(value))
        + value
    )
    return bytes([0x04, 0x00]) + struct.pack(">H", 1) + bytes([0x01]) + struct.pack(">I", len(body)) + body


def build_cassandra_startup():
    """Cassandra CQL STARTUP（TCP 9042）：nDPI 走 Match by port，rDpi 为 Dpi。"""
    return tcp_session(CLIENT, SERVER, 50022, 9042, [("c", cql_startup_frame())])
```

在 `CORPUS` 字典的 `"kafka_metadata_request": build_kafka_metadata_request,` 之后追加：

```python
    # F50：Oracle TNS Connect 与 Cassandra internode/STARTUP
    "oracle_connect": build_oracle_connect,
    "cassandra_internode": build_cassandra_internode,
    "cassandra_startup": build_cassandra_startup,
```

- [x] **Step 2: 生成语料**

Run: `python -I tests/parity/gen_corpus.py`

Expected: 输出包含 `wrote .../oracle_connect.pcap`、`cassandra_internode.pcap`、`cassandra_startup.pcap`。

- [x] **Step 3: 扩展 golden 生成脚本**

将 `tests/parity/gen_golden.sh` 的循环列表末尾追加：

```bash
oracle_connect cassandra_internode cassandra_startup
```

完整循环行示例：

```bash
for n in http_connect http_proxy doh_resolver dot_alpn dot_port ftp_transfer nbns_registration nbds_datagram nbss_session_request smb1_session_setup smb23_session_setup smb_echo memcached_session elasticsearch_binary amqp_frame mssql_tds_prelogin kafka_metadata_request oracle_connect cassandra_internode cassandra_startup; do
```

- [x] **Step 4: 生成 golden**

Run: `MSYS_NO_PATHCONV=1 wsl.exe bash /mnt/d/rust_code/rDpi/tests/parity/gen_golden.sh`

Expected: 输出 `DONE`，三个 `.ndpi.json` 生成。

- [x] **Step 5: 核对 golden 输出**

Run:

```bash
python -I - <<'PY'
import json
from pathlib import Path
for name in ("oracle_connect", "cassandra_internode", "cassandra_startup"):
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
oracle_connect | Oracle | Database | Acceptable | {'6': 'DPI'}
cassandra_internode | Cassandra | Database | Acceptable | {'6': 'DPI'}
cassandra_startup | Cassandra | Database | Acceptable | {'1': 'Match by port'}
```

若输出与预期不符，先修正 §6 的 parity 映射或语料构造，再继续。

- [x] **Step 6: 运行差分门禁**

Run: `cargo test --all-features --test test_parity_corpus -v`

Expected: PASS。Cassandra STARTUP 的 confidence 差异按 Match by port → Dpi 升级放行；风险差异沿用既有 nDPI 专有启发式剔除策略。

- [x] **Step 7: 提交**

```bash
git add tests/parity/gen_corpus.py tests/parity/gen_golden.sh tests/parity/corpus/ tests/parity/golden/
git commit -m "Add Oracle and Cassandra parity corpus"
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

在 F49 条目之后追加：

```markdown
- **Oracle + Cassandra 识别（F50，2026-11-08）**：阶段 2 第四批（`docs/architecture/phase2-oracle-cassandra-design.md`）——`database` feature 新增 `Protocol::Oracle` + `OracleMetadata{packet_length,packet_type}` 与 `Protocol::Cassandra` + `CassandraMetadata{source,version,stream_id,opcode,cql_version}`，无新增 `DissectorState`。Oracle detector 严格校验 TNS Connect 8 字节头（长度精确相等、包/头校验和为 0、type=1、reserved=0），`detect_with_context` 要求任一端 1521 端口，首字节门 None；Cassandra detector 识别 19 字节 internode magic（`0xCA552DFA`，不限端口）与严格 CQL STARTUP 帧（版本 0x02..=0x05、opcode=0x01、长度精确相等、string map 含 CQL_VERSION），首字节门 `[(2,5),(0xCA,0xCA)]`。注册于 database 块 mssql 之后、elasticsearch 之前；端口回退 1521/7000/9042；规则名 `oracle`/`cassandra`；parity Oracle/Cassandra→Database/Acceptable；语料 +3 pcap + 真实 golden 差分全绿。
```

- [x] **Step 2: 更新 AGENTS.md §3 测试基线**

运行以下命令并记录实际数字：

```bash
cargo test
cargo test --features database
cargo test --all-features
```

把 §3 中对应行的测试数与日期更新为实测值；在 `cargo test --features "database messaging"` 行之后新增：

```markdown
cargo test --features database       # <实测数> 测试全绿（F50 Oracle/Cassandra 模块 + 语料差分）
```

- [x] **Step 3: 更新 AGENTS.md §6 已知问题索引**

在 F49 行之后追加：

```markdown
| F50 | Oracle + Cassandra 识别：Oracle TNS Connect 8 字节头 + 1521 端口门控；Cassandra internode magic + 严格 CQL STARTUP 解析；端口回退/规则名/parity/CLI 接入；语料 +3 pcap + 真实 golden 差分 | 中 | ✅ 已完成 2026-11-08（弱启发式不兼容等边界见 risks.md F50） |
```

- [x] **Step 4: 更新 modules.md**

把 `database` 行的 mssql 条目之后追加：

```markdown
，oracle（F50，2026-11-08：TNS Connect 8 字节头 + 1521 端口门控），cassandra（F50，2026-11-08：internode magic + 严格 CQL STARTUP）
```

- [x] **Step 5: 更新 risks.md**

在 F49 小节之后追加：

```markdown
## F50【中】Oracle + Cassandra 识别（2026-11-08，新功能开发）—— ✅ 已完成

- **枚举与元数据**（[core/types.rs](file:///d:/rust_code/rDpi/src/core/types.rs)）：`database` 新增 `Protocol::Oracle` + `OracleMetadata{packet_length,packet_type}`、`Protocol::Cassandra` + `CassandraMetadata{source,version,stream_id,opcode,cql_version}`；无新增 `DissectorState`。
- **Oracle 模块**（[src/protocols/oracle/](file:///d:/rust_code/rDpi/src/protocols/oracle/)）：TNS Connect 8 字节头；`packet_length==payload.len()`、包校验和/保留字段/头校验和为 0、`packet_type==1`；`detect_with_context` 要求任一端 1521 端口；首字节门 `None`。
- **Cassandra 模块**（[src/protocols/cassandra/](file:///d:/rust_code/rDpi/src/protocols/cassandra/)）：19 字节 internode magic `0xCA552DFA`（不限端口）；CQL STARTUP 严格解析（版本 0x02..=0x05、flags 高 3 位为 0、opcode=0x01、长度精确等于 `payload.len()-9`、string map 条目 1..=64 且恰好消费完、含 `CQL_VERSION` 且值为可打印 ASCII）；首字节门 `[(2,5),(0xCA,0xCA)]`。
- **注册**（[protocols/mod.rs](file:///d:/rust_code/rDpi/src/protocols/mod.rs)）：Oracle/Cassandra 在 database 块 mssql 之后、Elasticsearch 之前；未改变既有 detector 相对顺序。
- **集成**：端口回退 1521→Oracle、7000/9042→Cassandra；规则名 `oracle`/`cassandra`；parity Oracle/Cassandra→Database/Acceptable；CLI 展示 TNS 头字段与 Cassandra 来源/版本/stream/CQL_VERSION。
- **Golden 差分（真实 nDPI 5.0 验证）**：`oracle_connect` → DPI `Oracle`（Database/Acceptable）；`cassandra_internode` → DPI `Cassandra`（Database/Acceptable）；`cassandra_startup` @9042 → `Cassandra`/Match by port，rDpi Dpi 升级放行。
- **已知边界**：① Oracle 仅识别 TNS Connect 且仅 1521 端口，不解析 Connect 体；② Cassandra 仅 internode magic + STARTUP 请求，OPTIONS/QUERY/响应/mid-stream 不识别；③ 单报文语义，多帧粘连不识别（与 nDPI 一致）；④ 跨段拆分在 rDpi TCP 前缀补齐后可识别（超集，单测覆盖）；⑤ 不实现 nDPI 的 `CQL_VERSION` 尾部弱启发式（`len-20`、载荷 > 60）；⑥ 不实现 nDPI 的 `packet_counter`/方向计数放弃阈值（严格解析已消除误报）；⑦ 加密变体（TCPS、7042/9043 TLS）不解析。
```

- [x] **Step 6: 更新路线图与覆盖清单**

`docs/architecture/ndpi-pure-rust-plan.md`：

- 将第 134 行的 `Oracle、Cassandra` 改为 `Oracle（✅ F50）、Cassandra（✅ F50）`；
- 在 §9 的 F49 条目之后追加：

```markdown
- **P2 Wave 1B 子批次 C：Oracle + Cassandra（F50，2026-11-08）**
  - Oracle：TNS Connect 8 字节头严格校验 + 1521 端口门控；首字节门 `None`；
  - Cassandra：19 字节 internode magic + 严格 CQL STARTUP 帧解析；首字节门 `[(2,5),(0xCA,0xCA)]`；
  - 端口回退、规则名、parity、CLI 接入；语料 +3 pcap + 真实 ndpiReader 5.0 golden 差分全绿。
```

`docs/architecture/protocol-coverage-plan.md`：

- 第 63 行缺口列改为 `ClickHouse、DRDA 缺失`（MSSQL/Oracle/Cassandra/Memcached/Elasticsearch 均已覆盖）；
- 第 85/86 行 Oracle/Cassandra 行尾追加 `（✅ F50 完成，2026-11-08）`；
- 第 283 行把 `AFP、Oracle、Cassandra` 改为 `AFP（Oracle ✅ F50、Cassandra ✅ F50）`。

- [x] **Step 7: 更新路线图记忆**

把 `C:\Users\jin\.claude\projects\D--rust-code-rDpi\memory\project_roadmap.md` 的近期里程碑追加：

```markdown
- F50（2026-11-08）：Oracle + Cassandra（TNS Connect 1521 端口门控、internode magic、严格 CQL STARTUP、端口回退/规则名/parity/CLI、语料 +3 golden 差分）
```

并把“下一步候选”中的“P2 Wave 1B 剩余企业协议：AFP、Oracle、Cassandra”改为：

```markdown
- P2 Wave 1B 剩余企业协议：AFP（Oracle/Cassandra 已于 F50 完成）
```

- [x] **Step 8: 全量门禁**

Run:

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -D warnings
cargo test
cargo test --features database
cargo test --all-features
```

Expected: 全部通过，clippy 0 警告。若 fmt 产生改动，单独提交：

```bash
git add -u
git commit -m "Apply rustfmt"
```

- [x] **Step 9: 提交文档**

```bash
git add AGENTS.md docs/architecture/modules.md docs/architecture/risks.md docs/architecture/ndpi-pure-rust-plan.md docs/architecture/protocol-coverage-plan.md docs/architecture/phase2-oracle-cassandra-design.md docs/architecture/phase2-oracle-cassandra-plan.md
git commit -m "Document Oracle and Cassandra support"
```

---

## 自检记录

- **Spec 覆盖**：设计文档 §2（类型/feature）→ Task 1；§3（Oracle）→ Task 2/3；§4（Cassandra）→ Task 4/5；§5（集成）→ Task 6；§6（parity）→ Task 6；§7（语料）→ Task 7；§8（文件清单）→ 全部任务；§9（测试）→ 各任务测试步骤；§10（边界）→ Task 8 risks.md；§11（实施顺序）→ 任务顺序一致。
- **占位符检查**：无 TBD/TODO；测试数与 AGENTS.md 计数在 Task 8 以实测值回写（测量步骤明确）。
- **类型一致性**：`OracleMetadata`/`CassandraMetadata`/`CassandraSource` 在 Task 1 定义，Task 3/5/6 使用一致；`parse_oracle_connect`/`parse_cassandra`/`parse_cassandra_startup` 签名在 Task 2/4 定义，后续任务引用一致。
