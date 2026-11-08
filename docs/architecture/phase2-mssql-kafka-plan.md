# MSSQL/TDS + Kafka Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 rDpi 新增 MSSQL/TDS 与 Apache Kafka 的无状态协议识别，对齐 nDPI 5.0 检测语义，并通过真实 ndpiReader golden 差分。

**Architecture:** 复用 `database` / `messaging` feature，各新增一个 `detector.rs` + `parser.rs` + `mod.rs` 模块；`detect()` 严格校验 nDPI 5.0 的单报文条件，`detect_with_context()` 仅用于 MSSQL 的端口 102 排除。不新增 `DissectorState`。新增 `Protocol`/`Metadata` 变体、端口回退、规则名、parity 导出与 CLI 展示。

**Tech Stack:** Rust 2024（rust-version 1.88）、现有手写解析器、`cargo test`、`tests/parity` 自生成 pcap + nDPI 5.0 golden。

## Global Constraints

- Rust edition 2024，`rust-version = "1.88"`；不新增任何依赖。
- 核心保持纯 Rust；不引入 C/C++ 依赖。
- `Protocol::Mssql` 与 `MssqlMetadata` 只在 `feature = "database"` 下存在；`Protocol::Kafka` 与 `KafkaMetadata` 只在 `feature = "messaging"` 下存在。所有引用处必须带相同的 `#[cfg]`。
- 注册顺序只允许追加，不改变既有 detector 相对顺序（AGENTS.md 禁止事项 #1）。
- 首字节门契约（F29）：`first_byte_gate()` 声明必须覆盖全部合法命中载荷的首字节；MSSQL 为 `[(1,8),(14,18)]`，Kafka 为 `None`。
- 热路径 miss 不分配内存；`KafkaMetadata.client_id` 只在命中定型时分配一次。
- 中文 doc 注释为主；公开 API 带文档注释。
- 每次 commit 信息**不带** `Co-Authored-By`（用户偏好）。
- 语料生成必须确定性；golden 使用 WSL 中 nDPI 5.0 构建的 `/mnt/d/c_code/nDPI-5.0/build/example/ndpiReader`。
- 所有测试/门禁必须在 Windows Git Bash + WSL 环境下可复现。

---

### Task 1: Protocol 模型与分类骨架

**Files:**
- Modify: `src/core/types.rs`（Protocol 枚举 ~359-372；Metadata 枚举 ~553-563；Metadata 结构体 ~1858-1875；`category()` ~1208-1216；`breed()` ~1320-1323）
- Test: `tests/test_types.rs`（现有 `test_database_protocol_classification_new` / `test_messaging_protocol_classification_new` ~326-345）

**Interfaces:**
- Produces: `Protocol::Mssql`, `Protocol::Kafka`, `MssqlMetadata`, `KafkaMetadata`, `Metadata::Mssql`, `Metadata::Kafka`；`Protocol::Mssql.category() == ProtocolCategory::Database`、`Protocol::Kafka.category() == ProtocolCategory::Messaging`，两者 `breed() == ProtocolBreed::Acceptable`。

- [ ] **Step 1: 写失败测试**

在 `tests/test_types.rs` 的两个现有测试中追加断言：

```rust
#[cfg(feature = "database")]
#[test]
fn test_database_protocol_classification_new() {
    assert_eq!(Protocol::Memcached.category(), ProtocolCategory::Database);
    assert_eq!(
        Protocol::Elasticsearch.category(),
        ProtocolCategory::Database
    );
    assert_eq!(Protocol::Memcached.breed(), ProtocolBreed::Acceptable);
    assert_eq!(Protocol::Elasticsearch.breed(), ProtocolBreed::Acceptable);
    // F49
    assert_eq!(Protocol::Mssql.category(), ProtocolCategory::Database);
    assert_eq!(Protocol::Mssql.breed(), ProtocolBreed::Acceptable);
}

#[cfg(feature = "messaging")]
#[test]
fn test_messaging_protocol_classification_new() {
    assert_eq!(Protocol::Amqp.category(), ProtocolCategory::Messaging);
    assert_eq!(Protocol::Amqp.breed(), ProtocolBreed::Acceptable);
    // F49
    assert_eq!(Protocol::Kafka.category(), ProtocolCategory::Messaging);
    assert_eq!(Protocol::Kafka.breed(), ProtocolBreed::Acceptable);
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features "database messaging" --test test_types protocol_classification_new`
Expected: 编译失败，`no variant or associated item named 'Mssql' found for enum 'Protocol'`（Kafka 同理）。

- [ ] **Step 3: 添加 Protocol 变体**

在 `src/core/types.rs` 的 `Protocol` 枚举中，`Mongodb,` 之后插入：

```rust
    /// MSSQL/TDS 协议（feature: database，F49）
    #[cfg(feature = "database")]
    Mssql,
```

在 `Amqp,` 之后插入：

```rust
    /// Apache Kafka 协议（feature: messaging，F49）
    #[cfg(feature = "messaging")]
    Kafka,
```

- [ ] **Step 4: 添加 Metadata 枚举变体**

在 `Metadata` 枚举的 `Mongodb(MongodbMetadata),` 之后插入：

```rust
    /// MSSQL/TDS 元数据 (feature: database, F49)
    #[cfg(feature = "database")]
    Mssql(MssqlMetadata),
```

在 `Amqp(AmqpMetadata),` 之后插入：

```rust
    /// Kafka 元数据 (feature: messaging, F49)
    #[cfg(feature = "messaging")]
    Kafka(KafkaMetadata),
```

- [ ] **Step 5: 添加 Metadata 结构体**

在 `ElasticsearchMetadata` 定义之后、`AmqpMetadata` 定义之前插入：

```rust
/// MSSQL/TDS 元数据 (feature: database, F49)
#[cfg(feature = "database")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MssqlMetadata {
    /// TDS 报文类型（1..=8 或 14..=18）
    pub packet_type: u8,
    /// TDS 状态位（0x00/0x01/0x02/0x04/0x08/0x09/0x10）
    pub status: u8,
    /// TDS 声明长度（命中时等于报文字节数）
    pub length: u16,
    /// SPID / channel
    pub channel: u16,
    /// 报文序号（类型 1..=8 时要求 > 0）
    pub packet_id: u8,
}
```

在 `AmqpMetadata` 定义之后、`MqttMetadata` 定义之前插入：

```rust
/// Kafka 请求元数据 (feature: messaging, F49)
#[cfg(feature = "messaging")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KafkaMetadata {
    /// Kafka API key（< 75）
    pub api_key: u16,
    /// Kafka API version（< 16）
    pub api_version: u16,
    /// 请求 correlation id
    pub correlation_id: u32,
    /// 客户端 ID（可打印 ASCII，可为空字符串）
    pub client_id: String,
}
```

- [ ] **Step 6: 添加 category/breed 分支**

`impl Protocol { pub fn category(...) }` 的 F46 database 分支之后插入：

```rust
            #[cfg(feature = "database")]
            Protocol::Mssql => ProtocolCategory::Database,
```

F46 messaging 分支之后插入：

```rust
            #[cfg(feature = "messaging")]
            Protocol::Kafka => ProtocolCategory::Messaging,
```

`pub fn breed(...)` 的 F46 database 分支之后插入：

```rust
            #[cfg(feature = "database")]
            Protocol::Mssql => ProtocolBreed::Acceptable,
```

F46 messaging 分支之后插入：

```rust
            #[cfg(feature = "messaging")]
            Protocol::Kafka => ProtocolBreed::Acceptable,
```

- [ ] **Step 7: 运行测试确认通过**

Run: `cargo test --features "database messaging" --test test_types protocol_classification_new`
Expected: PASS（2 passed）。

- [ ] **Step 8: Commit**

```bash
git add src/core/types.rs tests/test_types.rs
git commit -m "Add MSSQL and Kafka protocol model"
```

---

### Task 2: MSSQL/TDS 模块与注册

**Files:**
- Create: `src/protocols/mssql/parser.rs`
- Create: `src/protocols/mssql/detector.rs`
- Create: `src/protocols/mssql/mod.rs`
- Modify: `src/protocols/mod.rs`（模块声明 ~31-36；database 注册块 ~335-347）
- Modify: `tests/test_integration.rs`（detector 计数 ~206-213）

**Interfaces:**
- Produces: `pub struct MssqlParsed { packet_type: u8, status: u8, length: u16, channel: u16, packet_id: u8 }`；`pub fn parse_mssql_tds(payload: &[u8]) -> Option<MssqlParsed>`；`pub struct MssqlDetector`；`pub fn mssql::register(registry: &mut Registry)`。
- Consumes: Task 1 的 `Protocol::Mssql` / `Metadata::Mssql` / `MssqlMetadata`。

- [ ] **Step 1: 创建带失败测试的 parser 桩**

创建 `src/protocols/mssql/parser.rs`，先放入完整测试与返回 `None` 的桩：

```rust
//! MSSQL/TDS 报文头解析（与 nDPI 5.0 `mssql_tds.c` 判定一致）

/// TDS 报文头固定长度
pub const MSSQL_TDS_HEADER_LEN: usize = 8;

/// TDS 报文头解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MssqlParsed {
    pub packet_type: u8,
    pub status: u8,
    pub length: u16,
    pub channel: u16,
    pub packet_id: u8,
}

/// 解析 TDS 报文头
pub fn parse_mssql_tds(_payload: &[u8]) -> Option<MssqlParsed> {
    None // TDD 桩：Step 4 实现
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tds(packet_type: u8, status: u8, packet_id: u8, window: u8, body: &[u8]) -> Vec<u8> {
        let total = (MSSQL_TDS_HEADER_LEN + body.len()) as u16;
        let mut packet = vec![packet_type, status];
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.push(packet_id);
        packet.push(window);
        packet.extend_from_slice(body);
        packet
    }

    #[test]
    fn test_parse_prelogin() {
        let parsed = parse_mssql_tds(&tds(0x12, 0x01, 1, 0, b"body")).unwrap();
        assert_eq!(parsed.packet_type, 0x12);
        assert_eq!(parsed.status, 0x01);
        assert_eq!(parsed.length, 12);
        assert_eq!(parsed.channel, 0);
        assert_eq!(parsed.packet_id, 1);
    }

    #[test]
    fn test_reject_sql_batch_with_zero_packet_id() {
        assert!(parse_mssql_tds(&tds(1, 0x01, 0, 0, b"body")).is_none());
    }

    #[test]
    fn test_reject_unknown_type() {
        for packet_type in [0u8, 9, 13, 19] {
            assert!(parse_mssql_tds(&tds(packet_type, 0x01, 1, 0, b"body")).is_none());
        }
    }

    #[test]
    fn test_reject_bad_status() {
        for status in [0x03u8, 0x05, 0x20, 0xff] {
            assert!(parse_mssql_tds(&tds(1, status, 1, 0, b"body")).is_none());
        }
    }

    #[test]
    fn test_reject_length_mismatch() {
        let mut payload = tds(1, 0x01, 1, 0, b"body");
        payload[2..4].copy_from_slice(&9u16.to_be_bytes());
        assert!(parse_mssql_tds(&payload).is_none());
    }

    #[test]
    fn test_reject_nonzero_window() {
        assert!(parse_mssql_tds(&tds(1, 0x01, 1, 1, b"body")).is_none());
    }

    #[test]
    fn test_reject_short_payload() {
        assert!(parse_mssql_tds(&[0x12, 0x01, 0x00]).is_none());
    }
}
```

- [ ] **Step 2: 创建带失败测试的 detector 桩**

创建 `src/protocols/mssql/detector.rs`：

```rust
//! MSSQL/TDS protocol detector for rDpi

use crate::core::types::{
    Confidence, DetectContext, DetectionResult, Metadata, MssqlMetadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::parse_mssql_tds;

/// TPKT over ISO 8072 使用的 TCP 端口（nDPI 排除，避免与 TDS 头混淆）
const TPKT_PORT: u16 = 102;

/// MSSQL/TDS protocol detector
pub struct MssqlDetector {
    _private: (),
}

impl MssqlDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for MssqlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for MssqlDetector {
    fn name(&self) -> &'static str {
        "mssql"
    }

    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(1, 8), (14, 18)])
    }

    fn detect(&self, _payload: &[u8]) -> Option<DetectionResult> {
        None // TDD 桩：Step 5 实现
    }

    fn detect_with_context(&self, _payload: &[u8], _ctx: &DetectContext) -> Option<DetectionResult> {
        None // TDD 桩：Step 5 实现
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tds(packet_type: u8, status: u8, packet_id: u8, window: u8, body: &[u8]) -> Vec<u8> {
        let total = (8 + body.len()) as u16;
        let mut packet = vec![packet_type, status];
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.push(packet_id);
        packet.push(window);
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
    fn test_detect_prelogin() {
        let detector = MssqlDetector::new();
        let payload = tds(0x12, 0x01, 1, 0, &[0x00, 0x00, 0x1a, 0x00]);
        let result = detector.detect(&payload).unwrap();
        assert_eq!(result.protocol, Protocol::Mssql);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Mssql(meta) => {
                assert_eq!(meta.packet_type, 0x12);
                assert_eq!(meta.status, 0x01);
                assert_eq!(meta.length, 12);
                assert_eq!(meta.channel, 0);
                assert_eq!(meta.packet_id, 1);
            }
            _ => panic!("expected Mssql metadata"),
        }
    }

    #[test]
    fn test_detect_sql_batch_and_reply() {
        let detector = MssqlDetector::new();
        for packet_type in [1u8, 2, 4, 7] {
            let payload = tds(packet_type, 0x01, 1, 0, b"query");
            assert_eq!(detector.detect(&payload).unwrap().protocol, Protocol::Mssql);
        }
    }

    #[test]
    fn test_detect_transaction_manager_types() {
        let detector = MssqlDetector::new();
        for packet_type in [14u8, 15, 16, 17, 18] {
            let payload = tds(packet_type, 0x01, 0, 0, b"body");
            assert_eq!(detector.detect(&payload).unwrap().protocol, Protocol::Mssql);
        }
    }

    #[test]
    fn test_reject_http() {
        let detector = MssqlDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_detect_with_context_excludes_tpkt_port() {
        let detector = MssqlDetector::new();
        let payload = tds(0x12, 0x01, 1, 0, b"body");
        assert!(
            detector
                .detect_with_context(&payload, &ctx(50000, 102))
                .is_none()
        );
        assert!(
            detector
                .detect_with_context(&payload, &ctx(102, 50000))
                .is_none()
        );
        assert!(
            detector
                .detect_with_context(&payload, &ctx(50000, 1433))
                .is_some()
        );
    }

    #[test]
    fn test_first_byte_gate_covers_valid_types() {
        let detector = MssqlDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        for packet_type in [1u8, 2, 3, 4, 5, 6, 7, 8, 14, 15, 16, 17, 18] {
            let payload = tds(packet_type, 0x01, 1, 0, b"body");
            assert!(
                gate.iter()
                    .any(|&(lo, hi)| payload[0] >= lo && payload[0] <= hi),
                "门区间不覆盖合法样本首字节 0x{:02X}",
                payload[0]
            );
        }
        for byte in [0u8, 9, 13, 19, b'G'] {
            assert!(!gate.iter().any(|&(lo, hi)| byte >= lo && byte <= hi));
        }
    }
}
```

- [ ] **Step 3: 创建 mod.rs 并接入注册**

创建 `src/protocols/mssql/mod.rs`：

```rust
//! MSSQL/TDS protocol detection module for rDpi
//!
//! 识别 TDS 报文头（8 字节）并提取类型/状态/长度/通道/报文序号。

mod detector;
mod parser;

pub use detector::MssqlDetector;
pub use parser::{MSSQL_TDS_HEADER_LEN, MssqlParsed, parse_mssql_tds};

use crate::protocols::Registry;

/// Register MSSQL/TDS detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(MssqlDetector::new()));
}
```

在 `src/protocols/mod.rs` 的模块声明区（`pub mod mysql;` 之前）插入：

```rust
#[cfg(feature = "database")]
pub mod mssql;
```

在 `register_defaults` 的 database 块中，`redis::register(_registry);` 之后、`elasticsearch::register(_registry);` 之前插入：

```rust
    #[cfg(feature = "database")]
    mssql::register(_registry);
```

在 `tests/test_integration.rs` 的 `#[cfg(feature = "database")]` 计数块中，把 `count += 6;` 改为 `count += 7;`，注释改为：

```rust
            count += 7; // MySQL + PostgreSQL + Redis + MongoDB + Memcached + Elasticsearch（F46）+ MSSQL（F49）
```

- [ ] **Step 4: 运行测试确认失败**

Run: `cargo test --features database protocols::mssql`
Expected: FAIL（parser/detector 桩返回 `None`，断言 `unwrap()` panic）。

- [ ] **Step 5: 实现 parser 与 detector**

把 `src/protocols/mssql/parser.rs` 的桩函数替换为：

```rust
pub fn parse_mssql_tds(payload: &[u8]) -> Option<MssqlParsed> {
    if payload.len() < MSSQL_TDS_HEADER_LEN {
        return None;
    }
    let packet_type = payload[0];
    let status = payload[1];
    let length = u16::from_be_bytes([payload[2], payload[3]]);
    let channel = u16::from_be_bytes([payload[4], payload[5]]);
    let packet_id = payload[6];
    let window = payload[7];

    if length as usize != payload.len() || window != 0 {
        return None;
    }
    let type_ok =
        (packet_id > 0 && (1..=8).contains(&packet_type)) || (14..=18).contains(&packet_type);
    let status_ok = matches!(status, 0x00 | 0x01 | 0x02 | 0x04 | 0x08 | 0x09 | 0x10);
    if !type_ok || !status_ok {
        return None;
    }
    Some(MssqlParsed {
        packet_type,
        status,
        length,
        channel,
        packet_id,
    })
}
```

把 `src/protocols/mssql/detector.rs` 的两个桩方法替换为：

```rust
    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_mssql_tds(payload)?;
        Some(
            DetectionResult::new(Protocol::Mssql)
                .with_metadata(Metadata::Mssql(MssqlMetadata {
                    packet_type: parsed.packet_type,
                    status: parsed.status,
                    length: parsed.length,
                    channel: parsed.channel,
                    packet_id: parsed.packet_id,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }

    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        if ctx.src_port == TPKT_PORT || ctx.dst_port == TPKT_PORT {
            return None;
        }
        self.detect(payload)
    }
```

- [ ] **Step 6: 运行测试确认通过**

Run: `cargo test --features database protocols::mssql`
Expected: PASS（parser 7 + detector 6 个测试全部通过）。

- [ ] **Step 7: Commit**

```bash
git add src/protocols/mssql src/protocols/mod.rs tests/test_integration.rs
git commit -m "Add MSSQL/TDS detector"
```

---

### Task 3: Kafka 模块与注册

**Files:**
- Create: `src/protocols/kafka/parser.rs`
- Create: `src/protocols/kafka/detector.rs`
- Create: `src/protocols/kafka/mod.rs`
- Modify: `src/protocols/mod.rs`（模块声明 ~25-30；messaging 注册块 ~347-348）
- Modify: `tests/test_integration.rs`（messaging 计数 ~210-213）

**Interfaces:**
- Produces: `pub struct KafkaParsed { api_key: u16, api_version: u16, correlation_id: u32, client_id: String }`；`pub fn parse_kafka_request(payload: &[u8]) -> Option<KafkaParsed>`；`pub struct KafkaDetector`；`pub fn kafka::register(registry: &mut Registry)`。
- Consumes: Task 1 的 `Protocol::Kafka` / `Metadata::Kafka` / `KafkaMetadata`。

- [ ] **Step 1: 创建带失败测试的 parser 桩**

创建 `src/protocols/kafka/parser.rs`：

```rust
//! Kafka 请求头解析（与 nDPI 5.0 `kafka.c` 判定一致）

const KAFKA_MIN_LEN: usize = 8;
const KAFKA_MIN_REQUEST_LEN: usize = 14;
const KAFKA_MAX_API_KEY: u16 = 75;
const KAFKA_MAX_API_VERSION: u16 = 16;

/// Kafka 请求头解析结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaParsed {
    pub api_key: u16,
    pub api_version: u16,
    pub correlation_id: u32,
    pub client_id: String,
}

/// 解析 Kafka 请求头
pub fn parse_kafka_request(_payload: &[u8]) -> Option<KafkaParsed> {
    None // TDD 桩：Step 4 实现
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(api_key: u16, api_version: u16, correlation_id: u32, client_id: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&api_key.to_be_bytes());
        body.extend_from_slice(&api_version.to_be_bytes());
        body.extend_from_slice(&correlation_id.to_be_bytes());
        body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        body.extend_from_slice(client_id);
        let mut payload = (body.len() as u32).to_be_bytes().to_vec();
        payload.extend_from_slice(&body);
        payload
    }

    #[test]
    fn test_parse_request() {
        let parsed = parse_kafka_request(&request(3, 1, 42, b"rdpi-test")).unwrap();
        assert_eq!(parsed.api_key, 3);
        assert_eq!(parsed.api_version, 1);
        assert_eq!(parsed.correlation_id, 42);
        assert_eq!(parsed.client_id, "rdpi-test");
    }

    #[test]
    fn test_parse_empty_client_id() {
        assert!(parse_kafka_request(&request(0, 0, 1, b"")).is_some());
    }

    #[test]
    fn test_reject_length_mismatch() {
        let mut payload = request(3, 1, 1, b"rdpi");
        payload[0..4].copy_from_slice(&999u32.to_be_bytes());
        assert!(parse_kafka_request(&payload).is_none());
    }

    #[test]
    fn test_reject_api_key_too_large() {
        assert!(parse_kafka_request(&request(75, 1, 1, b"rdpi")).is_none());
    }

    #[test]
    fn test_reject_api_version_too_large() {
        assert!(parse_kafka_request(&request(3, 16, 1, b"rdpi")).is_none());
    }

    #[test]
    fn test_reject_client_id_overflow() {
        let mut payload = request(3, 1, 1, b"rdpi");
        payload[12..14].copy_from_slice(&1000u16.to_be_bytes());
        assert!(parse_kafka_request(&payload).is_none());
    }

    #[test]
    fn test_reject_non_printable_client_id() {
        assert!(parse_kafka_request(&request(3, 1, 1, b"rd\x1fpi")).is_none());
        assert!(parse_kafka_request(&request(3, 1, 1, b"rd\x7fpi")).is_none());
    }

    #[test]
    fn test_reject_short_payload() {
        assert!(parse_kafka_request(&[0u8; 7]).is_none());
    }
}
```

- [ ] **Step 2: 创建带失败测试的 detector 桩**

创建 `src/protocols/kafka/detector.rs`：

```rust
//! Kafka protocol detector for rDpi

use crate::core::types::{Confidence, DetectionResult, KafkaMetadata, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_kafka_request;

/// Kafka protocol detector
pub struct KafkaDetector {
    _private: (),
}

impl KafkaDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for KafkaDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for KafkaDetector {
    fn name(&self) -> &'static str {
        "kafka"
    }

    fn detect(&self, _payload: &[u8]) -> Option<DetectionResult> {
        None // TDD 桩：Step 5 实现
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(api_key: u16, api_version: u16, correlation_id: u32, client_id: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&api_key.to_be_bytes());
        body.extend_from_slice(&api_version.to_be_bytes());
        body.extend_from_slice(&correlation_id.to_be_bytes());
        body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        body.extend_from_slice(client_id);
        let mut payload = (body.len() as u32).to_be_bytes().to_vec();
        payload.extend_from_slice(&body);
        payload
    }

    #[test]
    fn test_detect_request() {
        let detector = KafkaDetector::new();
        let payload = request(3, 1, 42, b"rdpi-test");
        let result = detector.detect(&payload).unwrap();
        assert_eq!(result.protocol, Protocol::Kafka);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Kafka(meta) => {
                assert_eq!(meta.api_key, 3);
                assert_eq!(meta.api_version, 1);
                assert_eq!(meta.correlation_id, 42);
                assert_eq!(meta.client_id, "rdpi-test");
            }
            _ => panic!("expected Kafka metadata"),
        }
    }

    #[test]
    fn test_reject_response_shape() {
        // 响应：长度前缀 + correlation id，无客户端 ID 段；12 < 14 应拒绝
        let detector = KafkaDetector::new();
        let payload = vec![0, 0, 0, 8, 0, 0, 0, 1];
        assert!(detector.detect(&payload).is_none());
    }

    #[test]
    fn test_reject_http() {
        let detector = KafkaDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_has_no_first_byte_gate() {
        let detector = KafkaDetector::new();
        assert!(detector.first_byte_gate().is_none());
    }
}
```

- [ ] **Step 3: 创建 mod.rs 并接入注册**

创建 `src/protocols/kafka/mod.rs`：

```rust
//! Apache Kafka protocol detection module for rDpi
//!
//! 识别长度前缀自洽的 Kafka 请求头并提取 API key/version/correlation/client_id。

mod detector;
mod parser;

pub use detector::KafkaDetector;
pub use parser::{KafkaParsed, parse_kafka_request};

use crate::protocols::Registry;

/// Register Kafka detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(KafkaDetector::new()));
}
```

在 `src/protocols/mod.rs` 的模块声明区（`pub mod kerberos;` 之前）插入：

```rust
#[cfg(feature = "messaging")]
pub mod kafka;
```

在 `register_defaults` 的 messaging 块中，`amqp::register(_registry);` 之后插入：

```rust
    #[cfg(feature = "messaging")]
    kafka::register(_registry);
```

在 `tests/test_integration.rs` 的 `#[cfg(feature = "messaging")]` 计数块中，把 `count += 1;` 改为 `count += 2;`，注释改为：

```rust
            count += 2; // AMQP（F46）+ Kafka（F49）
```

- [ ] **Step 4: 运行测试确认失败**

Run: `cargo test --features messaging protocols::kafka`
Expected: FAIL（parser/detector 桩返回 `None`，断言 `unwrap()` panic）。

- [ ] **Step 5: 实现 parser 与 detector**

把 `src/protocols/kafka/parser.rs` 的桩函数替换为：

```rust
pub fn parse_kafka_request(payload: &[u8]) -> Option<KafkaParsed> {
    if payload.len() < KAFKA_MIN_LEN {
        return None;
    }
    let declared = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if declared != payload.len() - 4 {
        return None;
    }
    let api_key = u16::from_be_bytes([payload[4], payload[5]]);
    let api_version = u16::from_be_bytes([payload[6], payload[7]]);
    if api_key >= KAFKA_MAX_API_KEY || api_version >= KAFKA_MAX_API_VERSION {
        return None;
    }
    if payload.len() < KAFKA_MIN_REQUEST_LEN {
        return None;
    }
    let client_id_len = u16::from_be_bytes([payload[12], payload[13]]) as usize;
    let end = KAFKA_MIN_REQUEST_LEN.checked_add(client_id_len)?;
    if end > payload.len() {
        return None;
    }
    let client_id_bytes = &payload[KAFKA_MIN_REQUEST_LEN..end];
    if !client_id_bytes.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    let correlation_id = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    Some(KafkaParsed {
        api_key,
        api_version,
        correlation_id,
        client_id: String::from_utf8_lossy(client_id_bytes).into_owned(),
    })
}
```

把 `src/protocols/kafka/detector.rs` 的桩方法替换为：

```rust
    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_kafka_request(payload)?;
        Some(
            DetectionResult::new(Protocol::Kafka)
                .with_metadata(Metadata::Kafka(KafkaMetadata {
                    api_key: parsed.api_key,
                    api_version: parsed.api_version,
                    correlation_id: parsed.correlation_id,
                    client_id: parsed.client_id,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }
```

- [ ] **Step 6: 运行测试确认通过**

Run: `cargo test --features messaging protocols::kafka`
Expected: PASS（parser 8 + detector 4 个测试全部通过）。

- [ ] **Step 7: Commit**

```bash
git add src/protocols/kafka src/protocols/mod.rs tests/test_integration.rs
git commit -m "Add Kafka detector"
```

---

### Task 4: 端口回退、规则名、parity 与 CLI

**Files:**
- Modify: `src/core/guess/port.rs`（`PORT_MAP` 末尾 + 测试）
- Modify: `src/rule/parser.rs`（协议名 match ~51-59）
- Modify: `src/parity.rs`（`protocol_name` ~205-232；`ndpi_compat_classification` ~337-345）
- Modify: `src/bin/rdpi.rs`（`print_detection` 元数据 ~587-635）
- Test: `tests/test_rule.rs`（F46 测试之后）
- Test: `tests/parity_export.rs`（F46 测试之后）

**Interfaces:**
- Consumes: Task 1-3 的类型、detector 与注册。
- Produces: `match_port(1433/1434/9092)` 返回 `MatchByPort`；规则名 `mssql`/`mssql_tds`/`kafka`；parity 名称 `MsSQL-TDS` 与分类 `Database/Acceptable`、`RPC/Acceptable`。

- [ ] **Step 1: 写失败测试**

在 `src/core/guess/port.rs` 的测试模块末尾追加：

```rust
    #[cfg(feature = "database")]
    #[test]
    fn test_mssql_ports() {
        assert_eq!(match_port(1433).unwrap().protocol, Protocol::Mssql);
        assert_eq!(match_port(1434).unwrap().protocol, Protocol::Mssql);
        assert_eq!(match_port(1433).unwrap().confidence, Confidence::MatchByPort);
    }

    #[cfg(feature = "messaging")]
    #[test]
    fn test_kafka_port() {
        assert_eq!(match_port(9092).unwrap().protocol, Protocol::Kafka);
        assert_eq!(match_port(9092).unwrap().confidence, Confidence::MatchByPort);
    }
```

在 `tests/test_rule.rs` 末尾追加：

```rust
#[cfg(feature = "database")]
#[test]
fn test_rule_parser_mssql_protocol_names() {
    let json = r#"{
        "rules": [
            {"id": "mssql", "protocol": "mssql", "condition": {"dst_port": 1433}},
            {"id": "mssql_tds", "protocol": "mssql_tds", "condition": {"dst_port": 1434}}
        ]
    }"#;
    let engine = RuleEngine::from_json(json).unwrap();

    for dst_port in [1433u16, 1434] {
        let ctx = RuleContext {
            src_port: 12345,
            dst_port,
            sni: None,
            payload: Vec::new(),
        };
        let result = engine.match_rule(&ctx).expect("rule should match");
        assert_eq!(result.protocol, Protocol::Mssql);
    }
}

#[cfg(feature = "messaging")]
#[test]
fn test_rule_parser_kafka_protocol_name() {
    let json = r#"{
        "rules": [
            {"id": "kafka", "protocol": "kafka", "condition": {"dst_port": 9092}}
        ]
    }"#;
    let engine = RuleEngine::from_json(json).unwrap();
    let ctx = RuleContext {
        src_port: 12345,
        dst_port: 9092,
        sni: None,
        payload: Vec::new(),
    };
    let result = engine.match_rule(&ctx).expect("rule should match");
    assert_eq!(result.protocol, Protocol::Kafka);
}
```

> 说明：上面的 MSSQL 规则测试对 `mssql` 与 `mssql_tds` 两个名称各建一条规则，端口 1433/1434 分别匹配；`expected` 仅用于保持用例表结构，断言协议均为 `Mssql`。

在 `tests/parity_export.rs` 末尾追加：

```rust
#[cfg(feature = "database")]
#[test]
fn test_protocol_name_mssql() {
    let flow = flow_with_protocol(Protocol::Mssql);
    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.master_protocol.as_deref(), Some("MsSQL-TDS"));
    assert_eq!(normalized.app_protocol, None);
    assert_eq!(normalized.category.as_deref(), Some("Database"));
    assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
}

#[cfg(feature = "messaging")]
#[test]
fn test_protocol_name_kafka() {
    let flow = flow_with_protocol(Protocol::Kafka);
    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.master_protocol.as_deref(), Some("Kafka"));
    assert_eq!(normalized.app_protocol, None);
    assert_eq!(normalized.category.as_deref(), Some("RPC"));
    assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features "database messaging" --lib guess::port`
Expected: FAIL（1433/1434/9092 未映射，`unwrap()` panic）。

Run: `cargo test --features "database messaging" --test test_rule rule_parser_mssql`
Expected: FAIL（`mssql` 落入 `_ => Protocol::Other(0)`）。

Run: `cargo test --features "database messaging" --test parity_export protocol_name_mssql`
Expected: FAIL（master 为 `Mssql` 而非 `MsSQL-TDS`）。

- [ ] **Step 3: 添加端口回退**

在 `src/core/guess/port.rs` 的 `PORT_MAP` 末尾（`];` 之前）插入：

```rust
    #[cfg(feature = "database")]
    (1433u16, &[Protocol::Mssql]),
    #[cfg(feature = "database")]
    (1434u16, &[Protocol::Mssql]),
    #[cfg(feature = "messaging")]
    (9092u16, &[Protocol::Kafka]),
```

- [ ] **Step 4: 添加规则名**

在 `src/rule/parser.rs` 的协议名 match 中，`"redis" => Protocol::Redis,` 之后插入：

```rust
                    #[cfg(feature = "database")]
                    "mssql" | "mssql_tds" => Protocol::Mssql,
```

在 `"amqp" => Protocol::Amqp,` 之后插入：

```rust
                    #[cfg(feature = "messaging")]
                    "kafka" => Protocol::Kafka,
```

- [ ] **Step 5: 添加 parity 映射**

在 `src/parity.rs` 的 `protocol_name()` 中，`Protocol::Amqp => "AMQP".to_string(),` 之后插入：

```rust
        #[cfg(feature = "database")]
        Protocol::Mssql => "MsSQL-TDS".to_string(),
```

在 `ndpi_compat_classification()` 中，`Protocol::Amqp => ("RPC".to_string(), "Acceptable".to_string()),` 之后插入：

```rust
        #[cfg(feature = "database")]
        Protocol::Mssql => ("Database".to_string(), "Acceptable".to_string()),
        #[cfg(feature = "messaging")]
        Protocol::Kafka => ("RPC".to_string(), "Acceptable".to_string()),
```

- [ ] **Step 6: CLI 元数据显示**

在 `src/bin/rdpi.rs` 的 `print_detection` 中，把：

```rust
    let meta_str = match &det.metadata {
```

改为：

```rust
    // F49：MSSQL/Kafka 需要格式化字段组合；其余协议保持零分配 &str 路径。
    let formatted_meta: Option<String> = match &det.metadata {
        #[cfg(feature = "database")]
        rdpi::Metadata::Mssql(m) => Some(format!(
            "type={} status=0x{:02X} length={} channel={} packet_id={}",
            m.packet_type, m.status, m.length, m.channel, m.packet_id
        )),
        #[cfg(feature = "messaging")]
        rdpi::Metadata::Kafka(k) => Some(format!(
            "api_key={} version={} client_id={}",
            k.api_key, k.api_version, k.client_id
        )),
        _ => None,
    };

    let borrowed_meta = match &det.metadata {
```

并在 `borrowed_meta` 的 match 结束 `};` 之后插入：

```rust
    let meta_str = formatted_meta.as_deref().unwrap_or(borrowed_meta);
```

- [ ] **Step 7: 运行测试确认通过**

Run: `cargo test --features "database messaging" --lib guess::port`
Expected: PASS。

Run: `cargo test --features "database messaging" --test test_rule rule_parser_`
Expected: PASS（含 F46 与 F49 的规则名用例）。

Run: `cargo test --features "database messaging" --test parity_export`
Expected: PASS（含既有 F44/F45/F46 用例）。

- [ ] **Step 8: 编译检查 CLI**

Run: `cargo build --features "pcap database messaging"`
Expected: 编译成功。

- [ ] **Step 9: Commit**

```bash
git add src/core/guess/port.rs src/rule/parser.rs src/parity.rs src/bin/rdpi.rs tests/test_rule.rs tests/parity_export.rs
git commit -m "Integrate MSSQL and Kafka detection"
```

---

### Task 5: 语料、golden 与差分

**Files:**
- Modify: `tests/parity/gen_corpus.py`（`CORPUS` ~最后 30 行；builder 函数区 ~424-458）
- Modify: `tests/parity/gen_golden.sh`
- Create: `tests/parity/corpus/mssql_tds_prelogin.pcap`
- Create: `tests/parity/corpus/kafka_metadata_request.pcap`
- Create: `tests/parity/golden/mssql_tds_prelogin.ndpi.json`
- Create: `tests/parity/golden/kafka_metadata_request.ndpi.json`

**Interfaces:**
- Consumes: Task 2/3 的 detector；Task 4 的 parity 映射。
- Produces: 两个新语料及 nDPI 5.0 golden，差分测试自动发现。

- [ ] **Step 1: 添加语料 builder**

在 `tests/parity/gen_corpus.py` 的 `build_amqp_frame()` 之后插入：

```python
def tds_packet(packet_type, status, body, channel=0, packet_id=1, window=0):
    """构造 TDS 报文（8 字节头 + body；length 恒等于总长度）。"""
    total = 8 + len(body)
    return (
        struct.pack(">BBHHBB", packet_type, status, total, channel, packet_id, window)
        + body
    )


def build_mssql_tds_prelogin():
    """MSSQL/TDS PreLogin（TCP 1433）：type=0x12, status=0x01, packet_id=1, window=0。"""
    prelogin_body = bytes.fromhex(
        "00001a00060100200001020021000103002200040400260001ff"
    )
    request = tds_packet(0x12, 0x01, prelogin_body)
    response = tds_packet(0x04, 0x01, b"\x04\x00\x00\x00\x00\x00")
    return tcp_session(
        CLIENT, SERVER, 50018, 1433, [("c", request), ("s", response)]
    )


def kafka_request(api_key, api_version, correlation_id, client_id):
    """构造 Kafka 请求：BE u32 长度前缀 + API key/version + correlation + client_id。"""
    client = client_id.encode()
    body = (
        struct.pack(">HHIH", api_key, api_version, correlation_id, len(client))
        + client
    )
    return struct.pack(">I", len(body)) + body


def build_kafka_metadata_request():
    """Kafka Metadata 请求（TCP 9092）：api_key=3, version=1, client_id=rdpi-test。"""
    return tcp_session(
        CLIENT,
        SERVER,
        50019,
        9092,
        [("c", kafka_request(3, 1, 1, "rdpi-test"))],
    )
```

在 `CORPUS` 字典的 F46 条目之后（`"amqp_frame": build_amqp_frame,` 之后）插入：

```python
    # F49：MSSQL/TDS 与 Kafka
    "mssql_tds_prelogin": build_mssql_tds_prelogin,
    "kafka_metadata_request": build_kafka_metadata_request,
```

- [ ] **Step 2: 重新生成语料**

Run: `python -I tests/parity/gen_corpus.py`
Expected: 打印 61 个 `wrote ...`；`git status --short tests/parity/corpus` 只显示两个新文件（既有语料确定性不变）。

- [ ] **Step 3: 生成 golden**

在 `tests/parity/gen_golden.sh` 的 `for n in ...; do` 列表末尾加入 `mssql_tds_prelogin kafka_metadata_request`：

```bash
for n in http_connect http_proxy doh_resolver dot_alpn dot_port ftp_transfer nbns_registration nbds_datagram nbss_session_request smb1_session_setup smb23_session_setup smb_echo memcached_session elasticsearch_binary amqp_frame mssql_tds_prelogin kafka_metadata_request; do
```

Run (WSL): `wsl -e bash -lc 'bash /mnt/d/rust_code/rDpi/tests/parity/gen_golden.sh'`
Expected: 输出 `DONE`；`tests/parity/golden/mssql_tds_prelogin.ndpi.json` 与 `kafka_metadata_request.ndpi.json` 已生成；`git status --short tests/parity/golden` 只显示两个新文件。

- [ ] **Step 4: 人工核对 golden**

Run: `cat tests/parity/golden/mssql_tds_prelogin.ndpi.json`
Expected: 包含 `"proto":"MsSQL-TDS"`、`"category":"Database"`、`"breed":"Acceptable"`。

Run: `cat tests/parity/golden/kafka_metadata_request.ndpi.json`
Expected: 包含 `"proto":"Kafka"`、`"category":"RPC"`、`"breed":"Acceptable"`。

若名称/分类与预期不符：先按真实输出修正 Task 4 的 parity 映射，再重跑本步。

- [ ] **Step 5: 运行差分测试**

Run: `cargo test --all-features --test test_parity_corpus`
Expected: PASS（61 个语料，无失败、无 pending golden）。

- [ ] **Step 6: Commit**

```bash
git add tests/parity/gen_corpus.py tests/parity/gen_golden.sh tests/parity/corpus tests/parity/golden
git commit -m "Add MSSQL and Kafka parity corpus"
```

---

### Task 6: 文档回写与全量门禁

**Files:**
- Modify: `AGENTS.md`（§2 关键机制；§6 已知问题索引表）
- Modify: `docs/architecture/modules.md`（§4 协议 × Feature 对照表 ~54-55）
- Modify: `docs/architecture/risks.md`（F48 之后新增 F49 段）
- Modify: `docs/architecture/ndpi-pure-rust-plan.md`（§3 B 组清单；§9 已完成）
- Modify: `docs/architecture/protocol-coverage-plan.md`（§4 P0 表；§10.2）

**Interfaces:**
- Consumes: Task 1-5 的全部实现与测试结果。

- [ ] **Step 1: 更新 AGENTS.md §2**

在 F48 条目之后插入：

```markdown
- **MSSQL/TDS + Kafka 识别（F49，2026-11-08）**：阶段 2 第三批（`docs/architecture/phase2-mssql-kafka-design.md`）——`database` feature 新增 `Protocol::Mssql` + `MssqlMetadata{packet_type,status,length,channel,packet_id}`，`messaging` feature 新增 `Protocol::Kafka` + `KafkaMetadata{api_key,api_version,correlation_id,client_id}`；MSSQL detector 严格校验 TDS 8 字节头（type 1..=8 要求 packet_id>0 或 type 14..=18、status 白名单、length==载荷长度、window==0），`detect_with_context` 任一端 102 端口排除 TPKT，首字节门 `[(1,8),(14,18)]`；Kafka detector 校验 BE u32 长度前缀自洽、api_key<75、api_version<16、client_id 长度自洽且全可打印 ASCII，首字节门 `None`；两者均为无状态 detector，不新增 `DissectorState`；注册位置：MSSQL 在 database 块 redis 之后、Kafka 在 messaging 块 amqp 之后；端口回退 1433/1434/9092；parity `MsSQL-TDS`→Database/Acceptable、`Kafka`→RPC/Acceptable。
```

- [ ] **Step 2: 更新 AGENTS.md §6**

在表格 F46 行之后插入：

```markdown
| F49 | MSSQL/TDS + Kafka 识别：database 复用 + messaging 复用；TDS 8 字节头严格校验（长度/窗口/类型/状态，102 端口排除 TPKT）；Kafka 请求长度前缀 + client_id 校验；端口回退/规则名/parity/CLI 接入；语料 +2 pcap + 真实 golden 差分 | 中 | ✅ 已完成 2026-11-08（跨段/粘连单报文语义等边界见 risks.md F49） |
```

- [ ] **Step 3: 更新 modules.md 协议×Feature 表**

把 database 行改为：

```markdown
| database | mysql, postgresql, redis, mongodb, memcached, elasticsearch（F46），mssql（F49，2026-11-08：TDS 8 字节头严格校验 + 102 端口 TPKT 排除） |
```

把 messaging 行改为：

```markdown
| messaging | amqp（F46），kafka（F49，2026-11-08：长度前缀 + api_key/version + 可打印 client_id） |
```

- [ ] **Step 4: 更新 risks.md**

在 F48 段之后新增：

```markdown
## F49【中】MSSQL/TDS + Kafka 识别（2026-11-08，新功能开发）—— ✅ 已完成

- **背景**：阶段 2 第三批（`docs/architecture/phase2-mssql-kafka-design.md`、`docs/architecture/phase2-mssql-kafka-plan.md`）。子批次 B：企业数据库与消息管道缺口。
- **实现**：
  - **枚举与元数据**（[core/types.rs](file:///d:/rust_code/rDpi/src/core/types.rs)）：`database` 新增 `Protocol::Mssql` + `MssqlMetadata{packet_type,status,length,channel,packet_id}`；`messaging` 新增 `Protocol::Kafka` + `KafkaMetadata{api_key,api_version,correlation_id,client_id}`；无新增 `DissectorState`。
  - **MSSQL 模块**（[src/protocols/mssql/](file:///d:/rust_code/rDpi/src/protocols/mssql/)）：TDS 8 字节头；`length==payload.len()`、`window==0`、`packet_id>0 && type∈1..=8` 或 `type∈14..=18`、`status∈{0,1,2,4,8,9,10}`；`detect_with_context` 任一端端口 102 排除 TPKT；首字节门 `[(1,8),(14,18)]`。
  - **Kafka 模块**（[src/protocols/kafka/](file:///d:/rust_code/rDpi/src/protocols/kafka/)）：BE u32 长度前缀 `== payload.len()-4`、`api_key<75`、`api_version<16`、载荷 ≥14、`client_id_len+14<=payload.len()`、client_id 全为 `0x20..=0x7e`；只识别请求；首字节门 `None`。
  - **注册**（[protocols/mod.rs](file:///d:/rust_code/rDpi/src/protocols/mod.rs)）：MSSQL 在 database 块 redis 之后、Elasticsearch 之前；Kafka 在 messaging 块 amqp 之后；未改变既有 detector 相对顺序。
  - **集成**：端口回退 1433/1434→Mssql、9092→Kafka；规则名 `mssql`/`mssql_tds`/`kafka`；parity `MsSQL-TDS`→Database/Acceptable、`Kafka`→RPC/Acceptable；CLI 展示 TDS 头字段与 Kafka 请求字段。
- **Golden 差分（真实 nDPI 5.0 验证）**：`mssql_tds_prelogin` → DPI `MsSQL-TDS`（Database/Acceptable）；`kafka_metadata_request` → DPI `Kafka`（RPC/Acceptable）；跨段拆分与非标端口变体不进入 parity 语料。
- **已知边界**：① 单报文语义，多消息粘连不识别（与 nDPI 一致）；② 跨段拆分在 rDpi TCP 前缀补齐后可识别（超集，单测覆盖）；③ MSSQL 端口 102 双向排除（比 nDPI 的 dest-only 严格）；④ Kafka 只识别请求、null client_id（0xFFFF）不识别；⑤ api_key≥75/api_version≥16 不识别（与 nDPI 5.0 固定上限一致）；⑥ 加密变体（Kafka TLS 9093、MSSQL 加密会话）不解析。
```

- [ ] **Step 5: 更新路线图与覆盖清单**

`docs/architecture/ndpi-pure-rust-plan.md` §3 的 B 组清单中，把 `MSSQL、Oracle ... Kafka、AMQP（✅ F46）` 更新为：

```markdown
- **B. 企业协议**：SMB、NetBIOS（✅ 已于 F45 完成，2026-11-07）、LDAP、Kerberos、RDP、NFS、MSSQL（✅ F49）、Oracle、Cassandra、Memcached（✅ F46）、Elasticsearch（✅ F46）、Kafka（✅ F49）、AMQP（✅ F46）等；
```

在 §9 “已完成”末尾追加：

```markdown
- **P2 Wave 1B 子批次 B：MSSQL/TDS + Kafka（F49，2026-11-08）**
  - MSSQL/TDS：TDS 8 字节头严格校验（类型/状态/长度/窗口），102 端口 TPKT 双向排除，首字节门 `[(1,8),(14,18)]`；
  - Kafka：长度前缀自洽 + api_key/version 上限 + 可打印 client_id，仅识别请求；
  - 端口回退、规则名、parity、CLI 接入；语料 +2 pcap + 真实 ndpiReader 5.0 golden 差分全绿；
  - 无新增 `DissectorState`（无状态单报文语义）。
```

`docs/architecture/protocol-coverage-plan.md` §4 P0 表中，把 MSSQL 与 Kafka 行改为：

```markdown
| MSSQL / TDS | 数据库 | 企业数据库 | 中 |（✅ F49 完成，2026-11-08）
| Kafka | 消息 | 数据管道 | 中 |（✅ F49 完成，2026-11-08）
```

§10.2 阶段 2 清单更新为：

```markdown
- SMBv1/v2/v3、NetBIOS（✅ F45 完成）、Memcached（✅ F46 完成）、Elasticsearch（✅ F46 完成）、AMQP（✅ F46 完成）、MSSQL/TDS（✅ F49 完成）、Kafka（✅ F49 完成）、AFP、Oracle、Cassandra、NATS、STOMP、OpenWire。
```

- [ ] **Step 6: 运行全量门禁**

Run: `cargo fmt --all -- --check`
Expected: 无输出（exit 0）。若检查失败，先运行 `cargo fmt --all`，再重新运行本命令确认通过。

Run: `cargo test`
Expected: 全部通过。

Run: `cargo test --features "database messaging"`
Expected: 全部通过（含新增模块与规则/parity 测试）。

Run: `cargo test --all-features`
Expected: 全部通过（含 61 个语料差分；既有 ignored 用例保持 ignored）。

Run: `cargo clippy --all-features --all-targets -- -D warnings`
Expected: 0 警告。

- [ ] **Step 7: Commit**

```bash
git add AGENTS.md docs/architecture/modules.md docs/architecture/risks.md docs/architecture/ndpi-pure-rust-plan.md docs/architecture/protocol-coverage-plan.md
git commit -m "Document MSSQL and Kafka support"
```

---

## 自审记录

- **Spec coverage**：设计 §2 协议模型→Task 1；§3 MSSQL→Task 2；§4 Kafka→Task 3；§5 集成→Task 4；§6 parity→Task 4；§7 语料/golden→Task 5；§8 文件清单→Task 1-6；§9 测试→各任务 + Task 6；§10 边界→Task 6 文档；§11 实施顺序→Task 顺序；§12 风险→实现中的校验与边界测试。
- **Placeholder scan**：无 TBD/TODO；每个代码步骤含完整代码与命令。
- **Type consistency**：`MssqlParsed` / `KafkaParsed` 字段、`MssqlMetadata` / `KafkaMetadata` 字段、`parse_mssql_tds` / `parse_kafka_request` 签名在各任务间一致。
