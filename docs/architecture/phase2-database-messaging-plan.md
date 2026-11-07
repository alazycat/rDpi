# 阶段 2 第二批实施计划：Memcached、Elasticsearch、AMQP

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 按已确认设计实现 Memcached、Elasticsearch、AMQP 三个协议的识别、元数据、parity 映射与语料差分。

**Architecture:** Memcached/Elasticsearch 挂现有 `database` feature，AMQP 挂新增 `messaging` feature；三个 detector 各自独立模块（`mod.rs`/`parser.rs`/`detector.rs`），Memcached 使用 `DissectorState` 做跨包命中计数，Elasticsearch 在二进制 detector 之外由 HTTP detector 响应分支补充 `X-elastic-product` 子分类，AMQP 做无状态帧头校验。

**Tech Stack:** Rust 2024、现有 `ProtocolDetector`/`Registry`/`DissectorState` 框架、`tests/parity` pcap + ndpiReader 5.0 golden。

## Global Constraints

- 所有新协议变体/metadata 必须带 `#[cfg(feature = "...")]`；`DissectorState` 变体与状态结构保持无条件（沿 Ftp/NetBios/SMB 先例）。
- 不得修改既有 detector 相对注册顺序；只允许在 `database` 块末尾追加、在 `database` 块之后新增 `messaging` 注册。
- 不引入新依赖；不新增风险旗标/风险处理器。
- `first_byte_gate()` 必须遵守 F29 契约（声明区间必须覆盖全部可命中 payload 的首字节）。
- 项目文档使用中文；提交信息不得包含任何 AI 署名或 `Co-Authored-By`。
- 每次提交只包含本任务相关文件。
- 行为基线以真实 ndpiReader 5.0 golden 为准；若与本计划假设不一致，先修正实现/映射并在提交说明中记录。

---

## 文件结构

| 文件 | 职责 |
|---|---|
| `Cargo.toml` | 新增 `messaging` feature |
| `src/core/types.rs` | Protocol/Metadata/DissectorState 变体与状态结构 |
| `src/protocols/memcached/{mod,parser,detector}.rs` | 26 签名解析 + UDP 头 + 有状态计数 |
| `src/protocols/elasticsearch/{mod,parser,detector}.rs` | 二进制 `ES` 解析 + HTTP 响应头辅助 |
| `src/protocols/amqp/{mod,parser,detector}.rs` | 0-9-1 帧头 + 协议头解析 |
| `src/protocols/mod.rs` | 模块声明与注册 |
| `src/protocols/http/detector.rs` | Elasticsearch 响应头子分类、Memcached 状态 match 分支 |
| `src/rule/parser.rs` | 规则协议名 |
| `src/parity.rs` | nDPI 兼容名称/分类 |
| `src/bin/rdpi.rs` | CLI 元数据显示 |
| `tests/test_types.rs`、`tests/test_rule.rs`、`tests/parity_export.rs` | 模型/规则/parity 测试 |
| `tests/parity/gen_corpus.py`、`gen_golden.sh`、`corpus/`、`golden/` | 语料与 golden |
| `AGENTS.md`、`docs/architecture/*.md` | F46 文档回写 |

---

### Task 1: Feature 与协议模型

**Files:**
- Modify: `Cargo.toml:34`
- Modify: `src/core/types.rs`（Protocol 枚举、category/breed、Metadata、状态结构、DissectorState）
- Test: `tests/test_types.rs`（文件末尾追加）

**Interfaces:**
- Produces: `Protocol::Memcached` / `Protocol::Elasticsearch`（cfg database）、`Protocol::Amqp`（cfg messaging）；`Metadata::Memcached/Elasticsearch/Amqp`；`ElasticsearchSource`；`MemcachedDissectorState`；`DissectorState::Memcached`。

- [ ] **Step 1: 写失败测试**

在 `tests/test_types.rs` 末尾追加：

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
    assert_eq!(
        Protocol::Elasticsearch.breed(),
        ProtocolBreed::Acceptable
    );
}

#[cfg(feature = "messaging")]
#[test]
fn test_messaging_protocol_classification_new() {
    assert_eq!(Protocol::Amqp.category(), ProtocolCategory::Messaging);
    assert_eq!(Protocol::Amqp.breed(), ProtocolBreed::Acceptable);
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features "database messaging" --test test_types`
Expected: 编译失败，报 `no variant or associated item named 'Memcached' found for enum 'Protocol'`。

- [ ] **Step 3: 实现模型**

`Cargo.toml` 在 `database = []` 之后加入：

```toml
messaging = []  # AMQP
```

`src/core/types.rs` 的 `Protocol` 枚举，在 `Mongodb,` 之后加入：

```rust
    /// Memcached 文本缓存协议（feature: database，F46）
    #[cfg(feature = "database")]
    Memcached,
    /// Elasticsearch 二进制传输协议（feature: database，F46）
    #[cfg(feature = "database")]
    Elasticsearch,
    /// AMQP 0-9-1/1.0 消息队列协议（feature: messaging，F46）
    #[cfg(feature = "messaging")]
    Amqp,
```

`Protocol::category()` 的 Database 分支之后加入：

```rust
            // F46 数据库/消息协议
            #[cfg(feature = "database")]
            Protocol::Memcached | Protocol::Elasticsearch => ProtocolCategory::Database,
            #[cfg(feature = "messaging")]
            Protocol::Amqp => ProtocolCategory::Messaging,
```

`Protocol::breed()` 的 `Smb1 => Dangerous` 之后、最终 Unrated 分支之前加入：

```rust
            #[cfg(feature = "database")]
            Protocol::Memcached | Protocol::Elasticsearch => ProtocolBreed::Acceptable,
            #[cfg(feature = "messaging")]
            Protocol::Amqp => ProtocolBreed::Acceptable,
```

`Metadata` 枚举的 `Mongodb(MongodbMetadata),` 之后加入：

```rust
    /// Memcached 元数据 (feature: database, F46)
    #[cfg(feature = "database")]
    Memcached(MemcachedMetadata),
    /// Elasticsearch 元数据 (feature: database, F46)
    #[cfg(feature = "database")]
    Elasticsearch(ElasticsearchMetadata),
    /// AMQP 元数据 (feature: messaging, F46)
    #[cfg(feature = "messaging")]
    Amqp(AmqpMetadata),
```

`RedisMetadata` 结构体之后加入：

```rust
/// Memcached 元数据 (feature: database, F46)
#[cfg(feature = "database")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default)]
pub struct MemcachedMetadata {
    /// 请求命令（小写，如 "get"）或响应状态（如 "END"/"STORED"）
    pub command: Option<String>,
    /// 是否为服务端响应
    pub is_response: bool,
}

/// Elasticsearch 识别来源 (feature: database, F46)
#[cfg(feature = "database")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ElasticsearchSource {
    /// 二进制 `ES` 协议
    #[default]
    Binary,
    /// HTTP 响应头 `X-elastic-product`
    Http,
}

/// Elasticsearch 元数据 (feature: database, F46)
#[cfg(feature = "database")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default)]
pub struct ElasticsearchMetadata {
    /// 二进制协议头中的 BE u32 长度；HTTP 路径为 None
    pub message_length: Option<u32>,
    /// 识别来源
    pub source: ElasticsearchSource,
}

/// AMQP 元数据 (feature: messaging, F46)
#[cfg(feature = "messaging")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default)]
pub struct AmqpMetadata {
    /// 协议版本："0-9-1" 或 "1.0"
    pub version: String,
    /// 帧类型 0..=3；协议头识别时为 None
    pub frame_type: Option<u8>,
    /// 通道号
    pub channel: Option<u16>,
    /// 0-9-1 class id
    pub class_id: Option<u16>,
    /// 0-9-1 method id
    pub method: Option<u16>,
}
```

`SmbDissectorState` 之后加入：

```rust
/// Memcached TCP 命中计数状态
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemcachedDissectorState {
    /// 已匹配报文数（每包最多 +1，对齐 nDPI 的 matches）
    pub matches: u8,
    /// 已检查载荷包数（对齐 nDPI 的 packet_counter > 5 放弃）
    pub packets: u8,
}
```

`DissectorState` 枚举的 `Smb(SmbDissectorState),` 之后加入：

```rust
    /// Memcached TCP 命中计数
    Memcached(MemcachedDissectorState),
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --features "database messaging" --test test_types`
Expected: 全部通过。

- [ ] **Step 5: 格式化并提交**

```bash
cargo fmt --all
git add Cargo.toml src/core/types.rs tests/test_types.rs
git commit -m "Add database and messaging protocol model"
```

---

### Task 2: 规则协议名称

**Files:**
- Modify: `src/rule/parser.rs:53`
- Test: `tests/test_rule.rs`（末尾追加）

**Interfaces:**
- Consumes: Task 1 的 `Protocol::{Memcached,Elasticsearch,Amqp}`。
- Produces: 规则名 `memcached` / `elasticsearch` / `amqp`。

- [ ] **Step 1: 写失败测试**

在 `tests/test_rule.rs` 末尾追加：

```rust
#[cfg(feature = "database")]
#[test]
fn test_rule_parser_database_protocol_names() {
    let json = r#"{
        "rules": [
            {"id": "memcached", "protocol": "memcached", "condition": {"dst_port": 11211}},
            {"id": "elasticsearch", "protocol": "elasticsearch", "condition": {"dst_port": 9200}}
        ]
    }"#;
    let engine = RuleEngine::from_json(json).unwrap();

    let cases = [
        (11211, Protocol::Memcached),
        (9200, Protocol::Elasticsearch),
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

#[cfg(feature = "messaging")]
#[test]
fn test_rule_parser_amqp_protocol_name() {
    let json = r#"{
        "rules": [
            {"id": "amqp", "protocol": "amqp", "condition": {"dst_port": 5672}}
        ]
    }"#;
    let engine = RuleEngine::from_json(json).unwrap();
    let ctx = RuleContext {
        src_port: 12345,
        dst_port: 5672,
        sni: None,
        payload: Vec::new(),
    };
    let result = engine.match_rule(&ctx).expect("rule should match");
    assert_eq!(result.protocol, Protocol::Amqp);
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features "rule database messaging" --test test_rule`
Expected: 测试失败，两个规则的 `protocol` 均为 `Protocol::Other(0)`。

- [ ] **Step 3: 实现映射**

`src/rule/parser.rs` 的 `"redis" => Protocol::Redis,` 之后加入：

```rust
                    #[cfg(feature = "database")]
                    "memcached" => Protocol::Memcached,
                    #[cfg(feature = "database")]
                    "elasticsearch" => Protocol::Elasticsearch,
                    #[cfg(feature = "messaging")]
                    "amqp" => Protocol::Amqp,
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --features "rule database messaging" --test test_rule`
Expected: 全部通过。

- [ ] **Step 5: 提交**

```bash
cargo fmt --all
git add src/rule/parser.rs tests/test_rule.rs
git commit -m "Add database and messaging rule protocol names"
```

---

### Task 3: Memcached 解析器

**Files:**
- Create: `src/protocols/memcached/parser.rs`
- Create: `src/protocols/memcached/mod.rs`（先只声明 parser，detector 在 Task 4 接入）
- Modify: `src/protocols/mod.rs`（模块声明）

**Interfaces:**
- Produces:
  - `pub struct MemcachedParsed { pub token: &'static str, pub is_response: bool }`
  - `pub fn parse_memcached(&[u8]) -> Option<MemcachedParsed>`
  - `pub fn parse_memcached_udp(&[u8]) -> Option<MemcachedParsed>`
  - `pub const MEMCACHED_UDP_HEADER_LEN: usize = 8;`
  - `protocols::memcached` 模块声明

- [ ] **Step 1: 写失败测试**

创建 `src/protocols/memcached/parser.rs`，先只写测试与签名占位：

```rust
//! Memcached 文本协议解析（与 nDPI 5.0 `memcached.c` 签名表一致）

pub const MEMCACHED_UDP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemcachedParsed {
    pub token: &'static str,
    pub is_response: bool,
}

pub fn parse_memcached(_payload: &[u8]) -> Option<MemcachedParsed> {
    None
}

pub fn parse_memcached_udp(_payload: &[u8]) -> Option<MemcachedParsed> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commands() {
        let cases: &[(&[u8], &str)] = &[
            (b"set k 0 0 1\r\nx\r\n", "set"),
            (b"add k 0 0 1\r\n", "add"),
            (b"replace k 0 0 1\r\n", "replace"),
            (b"append k 0 0 1\r\n", "append"),
            (b"prepend k 0 0 1\r\n", "prepend"),
            (b"cas k 0 0 1 1\r\n", "cas"),
            (b"get foo\r\n", "get"),
            (b"gets foo\r\n", "gets"),
            (b"delete foo\r\n", "delete"),
            (b"incr foo 1\r\n", "incr"),
            (b"decr foo 1\r\n", "decr"),
            (b"touch foo 10\r\n", "touch"),
            (b"gat 10 foo\r\n", "gat"),
            (b"gats 10 foo\r\n", "gats"),
            (b"stats\r\n", "stats"),
        ];
        for (payload, token) in cases {
            let parsed = parse_memcached(payload).expect("command should match");
            assert_eq!(parsed.token, *token);
            assert!(!parsed.is_response);
        }
    }

    #[test]
    fn test_responses() {
        let cases: &[(&[u8], &str)] = &[
            (b"ERROR\r\n", "ERROR"),
            (b"CLIENT_ERROR bad command\r\n", "CLIENT_ERROR"),
            (b"SERVER_ERROR out of memory\r\n", "SERVER_ERROR"),
            (b"STORED\r\n", "STORED"),
            (b"NOT_STORED\r\n", "NOT_STORED"),
            (b"EXISTS\r\n", "EXISTS"),
            (b"NOT_FOUND\r\n", "NOT_FOUND"),
            (b"END\r\n", "END"),
            (b"DELETED\r\n", "DELETED"),
            (b"TOUCHED\r\n", "TOUCHED"),
            (b"STAT pid 1234\r\n", "STAT"),
        ];
        for (payload, token) in cases {
            let parsed = parse_memcached(payload).expect("response should match");
            assert_eq!(parsed.token, *token);
            assert!(parsed.is_response);
        }
    }

    #[test]
    fn test_rejects_case_mismatch_and_partial_prefixes() {
        assert!(parse_memcached(b"SET k 0 0 1\r\n").is_none());
        assert!(parse_memcached(b"end\r\n").is_none());
        assert!(parse_memcached(b"getaway\r\n").is_none());
        assert!(parse_memcached(b"GET / HTTP/1.1\r\n").is_none());
    }

    fn udp_payload(body: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x12, 0x34, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00];
        payload.extend_from_slice(body);
        payload
    }

    #[test]
    fn test_udp_header_and_command() {
        let payload = udp_payload(b"get foo\r\n");
        let parsed = parse_memcached_udp(&payload).expect("udp command should match");
        assert_eq!(parsed.token, "get");
        assert!(!parsed.is_response);
    }

    #[test]
    fn test_udp_rejects_bad_header() {
        let mut reserved = udp_payload(b"get foo\r\n");
        reserved[7] = 1;
        assert!(parse_memcached_udp(&reserved).is_none());

        let mut total = udp_payload(b"get foo\r\n");
        total[4] = 0;
        total[5] = 0;
        assert!(parse_memcached_udp(&total).is_none());

        let short = udp_payload(b"END\r\n");
        assert!(parse_memcached_udp(&short[..short.len() - 1]).is_none());
    }
}
```

创建 `src/protocols/memcached/mod.rs`（本任务先只导出 parser）：

```rust
mod parser;

pub use parser::{parse_memcached, parse_memcached_udp, MemcachedParsed};
```

在 `src/protocols/mod.rs` 的 `mongodb` 声明之后加入：

```rust
#[cfg(feature = "database")]
pub mod memcached;
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features database memcached::parser`
Expected: `test_commands`/`test_responses`/`test_udp_header_and_command` 失败（返回 None）。

- [ ] **Step 3: 实现解析器**

保留文件末尾的 `#[cfg(test)] mod tests`，将测试模块之前的内容替换为：

```rust
/// TCP 最少签名长度（`END\r\n`）
const MEMCACHED_MIN_LEN: usize = 5;

/// UDP 最少载荷（8 字节头 + 5 字节签名）
const MEMCACHED_MIN_UDP_LEN: usize = MEMCACHED_UDP_HEADER_LEN + MEMCACHED_MIN_LEN;

/// 命令签名（小写、带尾随空格；`stats` 与 nDPI 一致不带空格）
const COMMANDS: &[(&[u8], &str)] = &[
    (b"set ", "set"),
    (b"add ", "add"),
    (b"replace ", "replace"),
    (b"append ", "append"),
    (b"prepend ", "prepend"),
    (b"cas ", "cas"),
    (b"get ", "get"),
    (b"gets ", "gets"),
    (b"delete ", "delete"),
    (b"incr ", "incr"),
    (b"decr ", "decr"),
    (b"touch ", "touch"),
    (b"gat ", "gat"),
    (b"gats ", "gats"),
    (b"stats", "stats"),
];

/// 响应签名
const RESPONSES: &[(&[u8], &str)] = &[
    (b"ERROR\r\n", "ERROR"),
    (b"CLIENT_ERROR ", "CLIENT_ERROR"),
    (b"SERVER_ERROR ", "SERVER_ERROR"),
    (b"STORED\r\n", "STORED"),
    (b"NOT_STORED\r\n", "NOT_STORED"),
    (b"EXISTS\r\n", "EXISTS"),
    (b"NOT_FOUND\r\n", "NOT_FOUND"),
    (b"END\r\n", "END"),
    (b"DELETED\r\n", "DELETED"),
    (b"TOUCHED\r\n", "TOUCHED"),
    (b"STAT ", "STAT"),
];

fn match_prefix(
    payload: &[u8],
    table: &[(&[u8], &str)],
    is_response: bool,
) -> Option<MemcachedParsed> {
    table.iter().find_map(|(prefix, token)| {
        payload.starts_with(prefix).then_some(MemcachedParsed {
            token,
            is_response,
        })
    })
}

/// 解析 TCP 载荷起始处的 Memcached 命令或响应
pub fn parse_memcached(payload: &[u8]) -> Option<MemcachedParsed> {
    match_prefix(payload, COMMANDS, false).or_else(|| match_prefix(payload, RESPONSES, true))
}

/// 解析 UDP 载荷：8 字节请求头 + 命令/响应
pub fn parse_memcached_udp(payload: &[u8]) -> Option<MemcachedParsed> {
    if payload.len() < MEMCACHED_MIN_UDP_LEN {
        return None;
    }
    // nDPI：total datagrams 不得为 0，reserved 必须为 0
    let total_datagrams = u16::from_be_bytes([payload[4], payload[5]]);
    let reserved = u16::from_be_bytes([payload[6], payload[7]]);
    if total_datagrams == 0 || reserved != 0 {
        return None;
    }
    parse_memcached(&payload[MEMCACHED_UDP_HEADER_LEN..])
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --features database memcached::parser`
Expected: 5 个测试全部通过。

- [ ] **Step 5: 提交**

```bash
cargo fmt --all
git add src/protocols/memcached src/protocols/mod.rs
git commit -m "Add Memcached signature parser"
```

---

### Task 4: Memcached Detector 与注册

**Files:**
- Create: `src/protocols/memcached/detector.rs`
- Create: `src/protocols/memcached/mod.rs`
- Modify: `src/protocols/mod.rs`（模块声明、注册、注册测试）

**Interfaces:**
- Consumes: Task 3 的 `parse_memcached` / `parse_memcached_udp`；Task 1 的 `MemcachedMetadata` / `MemcachedDissectorState`。
- Produces: `MemcachedDetector`；`memcached::register(&mut Registry)`。

- [ ] **Step 1: 写失败测试**

创建 `src/protocols/memcached/detector.rs`：

```rust
//! Memcached 协议 detector（TCP 有状态计数 + UDP 单包）

use crate::core::types::{
    Confidence, DetectContext, DetectionResult, Direction, DissectorOutcome, DissectorState,
    MemcachedDissectorState, MemcachedMetadata, Metadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::{parse_memcached, parse_memcached_udp, MemcachedParsed};

const MEMCACHED_PORT: u16 = 11211;
const MEMCACHED_MIN_MATCH: u8 = 2;
const MEMCACHED_MAX_PACKETS: u8 = 5;

pub struct MemcachedDetector {
    _private: (),
}

impl MemcachedDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }

    fn result(parsed: MemcachedParsed) -> DetectionResult {
        DetectionResult::new(Protocol::Memcached)
            .with_metadata(Metadata::Memcached(MemcachedMetadata {
                command: Some(parsed.token.to_string()),
                is_response: parsed.is_response,
            }))
            .with_confidence(Confidence::Dpi)
    }
}

impl Default for MemcachedDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for MemcachedDetector {
    fn name(&self) -> &'static str {
        "memcached"
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        parse_memcached(payload).map(Self::result)
    }

    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        if ctx.src_port != MEMCACHED_PORT && ctx.dst_port != MEMCACHED_PORT {
            return None;
        }
        parse_memcached(payload)
            .or_else(|| parse_memcached_udp(payload))
            .map(Self::result)
    }

    fn process(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        _direction: Direction,
        ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        let first_match = match state {
            DissectorState::None => {
                let parsed = parse_memcached(payload)?;
                *state = DissectorState::Memcached(MemcachedDissectorState::default());
                Some(parsed)
            }
            DissectorState::Memcached(_) => None,
            _ => return None,
        };
        let DissectorState::Memcached(memcached) = state else {
            return None;
        };
        memcached.packets = memcached.packets.saturating_add(1);

        let parsed = match first_match {
            Some(parsed) => Some(parsed),
            None => parse_memcached(payload),
        };
        if let Some(parsed) = parsed {
            memcached.matches = memcached.matches.saturating_add(1);
            let required = if ctx.src_port == MEMCACHED_PORT || ctx.dst_port == MEMCACHED_PORT {
                1
            } else {
                MEMCACHED_MIN_MATCH
            };
            if memcached.matches >= required {
                return Some(DissectorOutcome::Classified(Self::result(parsed)));
            }
        }
        if memcached.packets > MEMCACHED_MAX_PACKETS {
            return Some(DissectorOutcome::GiveUp);
        }
        Some(DissectorOutcome::Continue)
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

    fn udp_payload(body: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x12, 0x34, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00];
        payload.extend_from_slice(body);
        payload
    }

    #[test]
    fn test_detect_text_command() {
        let detector = MemcachedDetector::new();
        let result = detector.detect(b"get foo\r\n").unwrap();
        assert_eq!(result.protocol, Protocol::Memcached);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Memcached(meta) => {
                assert_eq!(meta.command.as_deref(), Some("get"));
                assert!(!meta.is_response);
            }
            _ => panic!("expected Memcached metadata"),
        }
    }

    #[test]
    fn test_detect_udp_on_standard_port() {
        let detector = MemcachedDetector::new();
        let payload = udp_payload(b"get foo\r\n");
        let result = detector
            .detect_with_context(&payload, &ctx(40000, 11211))
            .unwrap();
        assert_eq!(result.protocol, Protocol::Memcached);
    }

    #[test]
    fn test_detect_with_context_requires_port() {
        let detector = MemcachedDetector::new();
        let payload = udp_payload(b"get foo\r\n");
        assert!(
            detector
                .detect_with_context(&payload, &ctx(40000, 9999))
                .is_none()
        );
    }

    #[test]
    fn test_process_standard_port_single_match() {
        let detector = MemcachedDetector::new();
        let mut state = DissectorState::None;
        let outcome = detector.process(
            &mut state,
            b"delete foo\r\n",
            Direction::Forward,
            &ctx(40000, 11211),
        );
        assert!(matches!(
            outcome,
            Some(DissectorOutcome::Classified(_))
        ));
    }

    #[test]
    fn test_process_nonstandard_port_requires_two_matches() {
        let detector = MemcachedDetector::new();
        let mut state = DissectorState::None;
        let first = detector.process(
            &mut state,
            b"get foo\r\n",
            Direction::Forward,
            &ctx(40000, 9999),
        );
        assert!(matches!(first, Some(DissectorOutcome::Continue)));

        let second = detector.process(
            &mut state,
            b"DELETED\r\n",
            Direction::Reverse,
            &ctx(40000, 9999),
        );
        assert!(matches!(
            second,
            Some(DissectorOutcome::Classified(_))
        ));
    }

    #[test]
    fn test_process_does_not_take_over_without_match() {
        let detector = MemcachedDetector::new();
        let mut state = DissectorState::None;
        let outcome = detector.process(
            &mut state,
            b"GET / HTTP/1.1\r\n",
            Direction::Forward,
            &ctx(40000, 9999),
        );
        assert!(outcome.is_none());
        assert_eq!(state, DissectorState::None);
    }

    #[test]
    fn test_process_gives_up_after_six_packets() {
        let detector = MemcachedDetector::new();
        let mut state = DissectorState::None;
        let first = detector.process(
            &mut state,
            b"get foo\r\n",
            Direction::Forward,
            &ctx(40000, 9999),
        );
        assert!(matches!(first, Some(DissectorOutcome::Continue)));

        for _ in 0..4 {
            let outcome = detector.process(
                &mut state,
                b"PING\r\n",
                Direction::Forward,
                &ctx(40000, 9999),
            );
            assert!(matches!(outcome, Some(DissectorOutcome::Continue)));
        }

        let last = detector.process(
            &mut state,
            b"PING\r\n",
            Direction::Forward,
            &ctx(40000, 9999),
        );
        assert!(matches!(last, Some(DissectorOutcome::GiveUp)));
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features database memcached`
Expected: 编译失败，`src/protocols/memcached/mod.rs` 尚未声明 `mod detector`，`MemcachedDetector` 不可用。

- [ ] **Step 3: 接入模块并注册**

把 `src/protocols/memcached/mod.rs` 替换为：

```rust
//! Memcached protocol detection module for rDpi
//!
//! 支持 nDPI 5.0 的文本命令/响应签名（TCP 11211 或非标端口 2 次匹配）
//! 与 UDP 请求头（仅 11211）。

mod detector;
mod parser;

pub use detector::MemcachedDetector;
pub use parser::{parse_memcached, parse_memcached_udp, MemcachedParsed};

use crate::protocols::Registry;

/// Register Memcached detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(MemcachedDetector::new()));
}
```

`src/protocols/mod.rs` 模块声明（`mongodb` 之后）加入：

```rust
#[cfg(feature = "database")]
pub mod memcached;
```

`register_defaults` 的 `redis::register(_registry);` 之后加入：

```rust
    #[cfg(feature = "database")]
    memcached::register(_registry);
```

在同文件末尾追加注册冒烟测试：

```rust
#[cfg(all(test, feature = "database"))]
mod database_registry_tests {
    use super::*;

    #[test]
    fn test_memcached_detector_registered() {
        let registry = Registry::default();
        let names: Vec<&str> = registry
            .detectors
            .iter()
            .map(|entry| entry.detector.name())
            .collect();
        assert!(
            names.contains(&"memcached"),
            "memcached detector must be registered"
        );
    }
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --features database memcached`
Expected: 11 个 Memcached 测试全部通过（含 parser 5 个、detector 6 个）；注册测试通过。

- [ ] **Step 5: 提交**

```bash
cargo fmt --all
git add src/protocols/memcached src/protocols/mod.rs
git commit -m "Add Memcached detector and registration"
```

---

### Task 5: Elasticsearch 解析器

**Files:**
- Create: `src/protocols/elasticsearch/parser.rs`
- Create: `src/protocols/elasticsearch/mod.rs`（先只声明 parser，detector 在 Task 6 接入）
- Modify: `src/protocols/mod.rs`（模块声明）

**Interfaces:**
- Produces:
  - `pub fn parse_elasticsearch(&[u8]) -> Option<u32>`
  - `pub fn is_elasticsearch_http_response(&[u8]) -> bool`
  - `protocols::elasticsearch` 模块声明

- [ ] **Step 1: 写失败测试**

创建 `src/protocols/elasticsearch/parser.rs`：

```rust
//! Elasticsearch 二进制协议与 HTTP 响应头识别

const ELASTICSEARCH_HEADER_LEN: usize = 6;

pub fn parse_elasticsearch(_payload: &[u8]) -> Option<u32> {
    None
}

pub fn is_elasticsearch_http_response(_payload: &[u8]) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_valid() {
        assert_eq!(parse_elasticsearch(b"ES\x00\x00\x00\x05hello"), Some(5));
    }

    #[test]
    fn test_binary_zero_length() {
        assert_eq!(parse_elasticsearch(b"ES\x00\x00\x00\x00"), Some(0));
    }

    #[test]
    fn test_binary_truncated() {
        assert_eq!(parse_elasticsearch(b"ES\x00\x00\x00\x06hello"), None);
    }

    #[test]
    fn test_binary_wrong_magic() {
        assert_eq!(parse_elasticsearch(b"EX\x00\x00\x00\x00"), None);
    }

    #[test]
    fn test_binary_short() {
        assert_eq!(parse_elasticsearch(b"ES\x00"), None);
    }

    #[test]
    fn test_http_response_header() {
        assert!(is_elasticsearch_http_response(
            b"HTTP/1.1 200 OK\r\nX-elastic-product: Elasticsearch\r\n\r\n{}"
        ));
    }

    #[test]
    fn test_http_response_header_case_insensitive() {
        assert!(is_elasticsearch_http_response(
            b"HTTP/1.1 200 OK\r\nx-elastic-product:   elasticsearch  \r\n\r\n"
        ));
    }

    #[test]
    fn test_http_response_header_wrong_value() {
        assert!(!is_elasticsearch_http_response(
            b"HTTP/1.1 200 OK\r\nX-elastic-product: OpenSearch\r\n\r\n"
        ));
    }

    #[test]
    fn test_http_body_header_not_scanned() {
        assert!(!is_elasticsearch_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nX-elastic-product: Elasticsearch\r\n"
        ));
    }

    #[test]
    fn test_http_request_not_matched() {
        assert!(!is_elasticsearch_http_response(
            b"GET / HTTP/1.1\r\nX-elastic-product: Elasticsearch\r\n\r\n"
        ));
    }
}
```

创建 `src/protocols/elasticsearch/mod.rs`（本任务先只导出 parser）：

```rust
mod parser;

pub use parser::{is_elasticsearch_http_response, parse_elasticsearch};
```

在 `src/protocols/mod.rs` 的 `dns` 声明之后加入：

```rust
#[cfg(feature = "database")]
pub mod elasticsearch;
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features database elasticsearch::parser`
Expected: 有效二进制与 HTTP 头测试失败（返回 None/false）。

- [ ] **Step 3: 实现解析器**

保留文件末尾的 `#[cfg(test)] mod tests`，将测试模块之前的内容替换为：

```rust
//! Elasticsearch 二进制协议与 HTTP 响应头识别

const ELASTICSEARCH_HEADER_LEN: usize = 6;

/// 解析二进制 `ES` + BE u32 长度头，返回消息长度
///
/// 与 nDPI 5.0 `elastic_search.c` 一致：载荷 ≥ 6 字节、magic 为 `ES`、
/// 载荷长度 ≥ `message_length + 6`（允许头部后跟完整消息体）。
pub fn parse_elasticsearch(payload: &[u8]) -> Option<u32> {
    if payload.len() < ELASTICSEARCH_HEADER_LEN || !payload.starts_with(b"ES") {
        return None;
    }
    let message_length = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
    if payload.len() < message_length as usize + ELASTICSEARCH_HEADER_LEN {
        return None;
    }
    Some(message_length)
}

/// 是否为带 `X-elastic-product: Elasticsearch` 的 HTTP 响应
///
/// 只扫描头部区域（到 `\r\n\r\n` 为止），名称与值大小写不敏感。
pub fn is_elasticsearch_http_response(payload: &[u8]) -> bool {
    if !payload.starts_with(b"HTTP/1.") {
        return false;
    }
    let headers_end = payload
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(payload.len());
    let headers = &payload[..headers_end];
    let Some(first_line_end) = find_crlf(headers) else {
        return false;
    };
    let mut offset = first_line_end + 2;
    while offset < headers.len() {
        let line_end = find_crlf(&headers[offset..])
            .map(|index| offset + index)
            .unwrap_or(headers.len());
        let line = &headers[offset..line_end];
        if let Some(colon) = line.iter().position(|&byte| byte == b':') {
            let (name, value) = line.split_at(colon);
            if trim_ascii(name).eq_ignore_ascii_case(b"x-elastic-product")
                && trim_ascii(&value[1..]).eq_ignore_ascii_case(b"Elasticsearch")
            {
                return true;
            }
        }
        offset = line_end.saturating_add(2);
    }
    false
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if !first.is_ascii_whitespace() {
            break;
        }
        bytes = rest;
    }
    while let Some((last, rest)) = bytes.split_last() {
        if !last.is_ascii_whitespace() {
            break;
        }
        bytes = rest;
    }
    bytes
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --features database elasticsearch::parser`
Expected: 10 个测试全部通过。

- [ ] **Step 5: 提交**

```bash
cargo fmt --all
git add src/protocols/elasticsearch src/protocols/mod.rs
git commit -m "Add Elasticsearch binary and HTTP response parser"
```

---

### Task 6: Elasticsearch Detector、注册与 HTTP 接入

**Files:**
- Create: `src/protocols/elasticsearch/detector.rs`
- Create: `src/protocols/elasticsearch/mod.rs`
- Modify: `src/protocols/mod.rs`（模块声明、注册、注册测试）
- Modify: `src/protocols/http/detector.rs`（响应分支 + Memcached 状态 arm + 测试）

**Interfaces:**
- Consumes: Task 5 的 `parse_elasticsearch` / `is_elasticsearch_http_response`；Task 1 的 `ElasticsearchMetadata` / `ElasticsearchSource`。
- Produces: `ElasticsearchDetector`；`elasticsearch::register(&mut Registry)`；HTTP 响应分类为 `Protocol::Elasticsearch`。

- [ ] **Step 1: 写失败测试**

创建 `src/protocols/elasticsearch/detector.rs`：

```rust
//! Elasticsearch 二进制协议 detector

use crate::core::types::{
    Confidence, DetectionResult, ElasticsearchMetadata, ElasticsearchSource, Metadata, Protocol,
};
use crate::protocols::ProtocolDetector;

use super::parser::parse_elasticsearch;

pub struct ElasticsearchDetector {
    _private: (),
}

impl ElasticsearchDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for ElasticsearchDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for ElasticsearchDetector {
    fn name(&self) -> &'static str {
        "elasticsearch"
    }

    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(b'E', b'E')])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let message_length = parse_elasticsearch(payload)?;
        Some(
            DetectionResult::new(Protocol::Elasticsearch)
                .with_metadata(Metadata::Elasticsearch(ElasticsearchMetadata {
                    message_length: Some(message_length),
                    source: ElasticsearchSource::Binary,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_binary() {
        let detector = ElasticsearchDetector::new();
        let result = detector.detect(b"ES\x00\x00\x00\x05hello").unwrap();
        assert_eq!(result.protocol, Protocol::Elasticsearch);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Elasticsearch(meta) => {
                assert_eq!(meta.message_length, Some(5));
                assert_eq!(meta.source, ElasticsearchSource::Binary);
            }
            _ => panic!("expected Elasticsearch metadata"),
        }
    }

    #[test]
    fn test_detect_rejects_non_es_payload() {
        let detector = ElasticsearchDetector::new();
        assert!(detector.detect(b"EX\x00\x00\x00\x00").is_none());
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_sample() {
        let detector = ElasticsearchDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        let sample = b"ES\x00\x00\x00\x00";
        assert!(
            gate.iter()
                .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
            "门区间不覆盖合法样本首字节 0x{:02X}",
            sample[0]
        );
        assert!(!gate.iter().any(|&(lo, hi)| b'G' >= lo && b'G' <= hi));
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features database elasticsearch`
Expected: 编译失败，`src/protocols/elasticsearch/mod.rs` 尚未声明 `mod detector`，`ElasticsearchDetector` 不可用。

- [ ] **Step 3: 接入模块、注册并接入 HTTP**

把 `src/protocols/elasticsearch/mod.rs` 替换为：

```rust
//! Elasticsearch protocol detection module for rDpi
//!
//! 二进制 `ES` + BE u32 长度（对齐 nDPI 5.0），并由 HTTP detector 通过
//! `X-elastic-product: Elasticsearch` 响应头补充 HTTP 子分类。

mod detector;
mod parser;

pub use detector::ElasticsearchDetector;
pub use parser::{is_elasticsearch_http_response, parse_elasticsearch};

use crate::protocols::Registry;

/// Register Elasticsearch detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(ElasticsearchDetector::new()));
}
```

`src/protocols/mod.rs` 模块声明（`dns` 之后或 database 区域）加入：

```rust
#[cfg(feature = "database")]
pub mod elasticsearch;
```

`register_defaults` 的 `redis::register(_registry);` 之后、`memcached::register` 之前加入：

```rust
    #[cfg(feature = "database")]
    elasticsearch::register(_registry);
```

在同文件的 `database_registry_tests` 中追加：

```rust
    #[test]
    fn test_elasticsearch_detector_registered() {
        let registry = Registry::default();
        let names: Vec<&str> = registry
            .detectors
            .iter()
            .map(|entry| entry.detector.name())
            .collect();
        assert!(
            names.contains(&"elasticsearch"),
            "elasticsearch detector must be registered"
        );
    }
```

`src/protocols/http/detector.rs` 响应分支替换为：

```rust
        // Layer 2: Try parsing as HTTP response
        if let Some(_resp) = parse_response_line(payload) {
            // F46：Elasticsearch 响应头子分类（nDPI 5.0 无此路径，纯 rDpi 超集）
            #[cfg(feature = "database")]
            if crate::protocols::elasticsearch::is_elasticsearch_http_response(payload) {
                let metadata = Metadata::Elasticsearch(ElasticsearchMetadata {
                    message_length: None,
                    source: ElasticsearchSource::Http,
                });
                return Some(
                    DetectionResult::new(Protocol::Elasticsearch)
                        .with_metadata(metadata)
                        .with_confidence(Confidence::Dpi),
                );
            }

            // Layer 3: For responses, we just detect protocol (status code is in response line)
            let metadata = Metadata::Http(HttpMetadata {
                host: None,
                method: None,
                path: None,
                application: None,
                ja4h: None,
            });

            return Some(
                DetectionResult::new(Protocol::Http)
                    .with_metadata(metadata)
                    .with_confidence(Confidence::Dpi),
            );
        }
```

`HttpDetector::process()` 的显式状态 match 中：

```rust
            | DissectorState::NetBios(_)
            | DissectorState::Smb(_) => {
```

改为：

```rust
            | DissectorState::NetBios(_)
            | DissectorState::Smb(_)
            | DissectorState::Memcached(_) => {
```

在 `http/detector.rs` 的 `tests` 模块末尾追加：

```rust
    #[cfg(feature = "database")]
    #[test]
    fn test_detect_elasticsearch_response() {
        let detector = HttpDetector::new();
        let result = detector
            .detect(
                b"HTTP/1.1 200 OK\r\nX-elastic-product: Elasticsearch\r\nContent-Type: application/json\r\n\r\n{}",
            )
            .unwrap();
        assert_eq!(result.protocol, Protocol::Elasticsearch);
        match result.metadata {
            Metadata::Elasticsearch(meta) => {
                assert_eq!(meta.source, ElasticsearchSource::Http);
                assert_eq!(meta.message_length, None);
            }
            _ => panic!("expected Elasticsearch metadata"),
        }
    }

    #[cfg(feature = "database")]
    #[test]
    fn test_detect_normal_response_stays_http() {
        let detector = HttpDetector::new();
        let result = detector
            .detect(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok")
            .unwrap();
        assert_eq!(result.protocol, Protocol::Http);
    }
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --features "database http" elasticsearch`
Run: `cargo test --features "database http" http::detector`
Expected: 全部通过。

- [ ] **Step 5: 提交**

```bash
cargo fmt --all
git add src/protocols/elasticsearch src/protocols/mod.rs src/protocols/http/detector.rs
git commit -m "Add Elasticsearch detector and HTTP response classification"
```

---

### Task 7: AMQP 解析器

**Files:**
- Create: `src/protocols/amqp/parser.rs`
- Create: `src/protocols/amqp/mod.rs`（先只声明 parser，detector 在 Task 8 接入）
- Modify: `src/protocols/mod.rs`（模块声明）

**Interfaces:**
- Produces:
  - `pub struct AmqpParsed { pub version: &'static str, pub frame_type: Option<u8>, pub channel: Option<u16>, pub class_id: Option<u16>, pub method: Option<u16> }`
  - `pub fn parse_amqp(&[u8]) -> Option<AmqpParsed>`
  - `protocols::amqp` 模块声明

- [ ] **Step 1: 写失败测试**

创建 `src/protocols/amqp/parser.rs`：

```rust
//! AMQP 0-9-1 帧头与 1.0 协议头解析（与 nDPI 5.0 `amqp.c` 判定一致）

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmqpParsed {
    pub version: &'static str,
    pub frame_type: Option<u8>,
    pub channel: Option<u16>,
    pub class_id: Option<u16>,
    pub method: Option<u16>,
}

pub fn parse_amqp(_payload: &[u8]) -> Option<AmqpParsed> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method_frame(method: u16) -> Vec<u8> {
        vec![
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x04,
            0x00,
            0x0A,
            (method >> 8) as u8,
            method as u8,
            0xCE,
        ]
    }

    #[test]
    fn test_valid_method_frame() {
        let parsed = parse_amqp(&method_frame(10)).expect("frame should match");
        assert_eq!(parsed.version, "0-9-1");
        assert_eq!(parsed.frame_type, Some(1));
        assert_eq!(parsed.channel, Some(0));
        assert_eq!(parsed.class_id, Some(10));
        assert_eq!(parsed.method, Some(10));
    }

    #[test]
    fn test_protocol_headers() {
        let parsed = parse_amqp(b"AMQP\x00\x00\x09\x01").expect("0-9-1 header");
        assert_eq!(parsed.version, "0-9-1");
        assert_eq!(parsed.frame_type, None);
        assert_eq!(parsed.channel, None);
        assert_eq!(parsed.class_id, None);
        assert_eq!(parsed.method, None);

        let parsed = parse_amqp(b"AMQP\x00\x01\x00\x00").expect("1.0 header");
        assert_eq!(parsed.version, "1.0");
        assert_eq!(parsed.frame_type, None);
    }

    #[test]
    fn test_rejects_bad_frame_type() {
        let mut payload = method_frame(10);
        payload[0] = 0x04;
        assert!(parse_amqp(&payload).is_none());
    }

    #[test]
    fn test_rejects_bad_class() {
        let mut payload = method_frame(10);
        payload[7] = 0x00;
        payload[8] = 0x09;
        assert!(parse_amqp(&payload).is_none());

        let mut payload = method_frame(10);
        payload[7] = 0x00;
        payload[8] = 0x6F;
        assert!(parse_amqp(&payload).is_none());
    }

    #[test]
    fn test_rejects_bad_method() {
        let mut payload = method_frame(121);
        payload[9] = 0x00;
        payload[10] = 0x79;
        assert!(parse_amqp(&payload).is_none());
    }

    #[test]
    fn test_rejects_large_frame_length() {
        let mut payload = method_frame(10);
        payload[3..7].copy_from_slice(&32768u32.to_be_bytes());
        assert!(parse_amqp(&payload).is_none());
    }

    #[test]
    fn test_rejects_payload_longer_than_frame() {
        let mut payload = method_frame(10);
        payload.extend_from_slice(&[0u8; 16]);
        assert!(parse_amqp(&payload).is_none());
    }

    #[test]
    fn test_rejects_short_payload() {
        let payload = method_frame(10);
        assert!(parse_amqp(&payload[..11]).is_none());
    }
}
```

创建 `src/protocols/amqp/mod.rs`（本任务先只导出 parser）：

```rust
mod parser;

pub use parser::{parse_amqp, AmqpParsed};
```

在 `src/protocols/mod.rs` 文件顶部 `bgp` 声明之前加入：

```rust
#[cfg(feature = "messaging")]
pub mod amqp;
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features messaging amqp::parser`
Expected: `test_valid_method_frame` / `test_protocol_headers` 失败。

- [ ] **Step 3: 实现解析器**

保留文件末尾的 `#[cfg(test)] mod tests`，将测试模块之前的内容替换为：

```rust
//! AMQP 0-9-1 帧头与 1.0 协议头解析（与 nDPI 5.0 `amqp.c` 判定一致）

/// 0-9-1 协议头
pub const AMQP_091_PROTOCOL_HEADER: &[u8] = b"AMQP\x00\x00\x09\x01";
/// 1.0 协议头
pub const AMQP_10_PROTOCOL_HEADER: &[u8] = b"AMQP\x00\x01\x00\x00";

const AMQP_FRAME_HEADER_LEN: usize = 11;
const AMQP_MAX_FRAME_LEN: u32 = 32768;
const AMQP_CLASS_MIN: u16 = 10;
const AMQP_CLASS_MAX: u16 = 110;
const AMQP_METHOD_MAX: u16 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmqpParsed {
    pub version: &'static str,
    pub frame_type: Option<u8>,
    pub channel: Option<u16>,
    pub class_id: Option<u16>,
    pub method: Option<u16>,
}

/// 解析 AMQP 协议头或 0-9-1 帧头
pub fn parse_amqp(payload: &[u8]) -> Option<AmqpParsed> {
    if payload.starts_with(AMQP_091_PROTOCOL_HEADER) {
        return Some(AmqpParsed {
            version: "0-9-1",
            frame_type: None,
            channel: None,
            class_id: None,
            method: None,
        });
    }
    if payload.starts_with(AMQP_10_PROTOCOL_HEADER) {
        return Some(AmqpParsed {
            version: "1.0",
            frame_type: None,
            channel: None,
            class_id: None,
            method: None,
        });
    }
    if payload.len() <= AMQP_FRAME_HEADER_LEN {
        return None;
    }
    let frame_type = payload[0];
    if frame_type > 3 {
        return None;
    }
    let length = u32::from_be_bytes([payload[3], payload[4], payload[5], payload[6]]);
    if length >= AMQP_MAX_FRAME_LEN || length as usize + 8 < payload.len() {
        return None;
    }
    let class_id = u16::from_be_bytes([payload[7], payload[8]]);
    if !(AMQP_CLASS_MIN..=AMQP_CLASS_MAX).contains(&class_id) {
        return None;
    }
    let method = u16::from_be_bytes([payload[9], payload[10]]);
    if method > AMQP_METHOD_MAX {
        return None;
    }
    Some(AmqpParsed {
        version: "0-9-1",
        frame_type: Some(frame_type),
        channel: Some(u16::from_be_bytes([payload[1], payload[2]])),
        class_id: Some(class_id),
        method: Some(method),
    })
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --features messaging amqp::parser`
Expected: 8 个测试全部通过。

- [ ] **Step 5: 提交**

```bash
cargo fmt --all
git add src/protocols/amqp src/protocols/mod.rs
git commit -m "Add AMQP frame and protocol header parser"
```

---

### Task 8: AMQP Detector 与注册

**Files:**
- Create: `src/protocols/amqp/detector.rs`
- Create: `src/protocols/amqp/mod.rs`
- Modify: `src/protocols/mod.rs`（模块声明、注册、注册测试）

**Interfaces:**
- Consumes: Task 7 的 `parse_amqp`；Task 1 的 `AmqpMetadata`。
- Produces: `AmqpDetector`；`amqp::register(&mut Registry)`。

- [ ] **Step 1: 写失败测试**

创建 `src/protocols/amqp/detector.rs`：

```rust
//! AMQP 协议 detector（0-9-1 帧头 + 协议头）

use crate::core::types::{AmqpMetadata, Confidence, DetectionResult, Metadata, Protocol};
use crate::protocols::ProtocolDetector;

use super::parser::parse_amqp;

pub struct AmqpDetector {
    _private: (),
}

impl AmqpDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for AmqpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector for AmqpDetector {
    fn name(&self) -> &'static str {
        "amqp"
    }

    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        Some(&[(0x00, 0x03), (0x41, 0x41)])
    }

    fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        let parsed = parse_amqp(payload)?;
        Some(
            DetectionResult::new(Protocol::Amqp)
                .with_metadata(Metadata::Amqp(AmqpMetadata {
                    version: parsed.version.to_string(),
                    frame_type: parsed.frame_type,
                    channel: parsed.channel,
                    class_id: parsed.class_id,
                    method: parsed.method,
                }))
                .with_confidence(Confidence::Dpi),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method_frame() -> [u8; 12] {
        [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0A, 0x00, 0x0A, 0xCE]
    }

    #[test]
    fn test_detect_method_frame() {
        let detector = AmqpDetector::new();
        let result = detector.detect(&method_frame()).unwrap();
        assert_eq!(result.protocol, Protocol::Amqp);
        assert_eq!(result.confidence, Confidence::Dpi);
        match result.metadata {
            Metadata::Amqp(meta) => {
                assert_eq!(meta.version, "0-9-1");
                assert_eq!(meta.frame_type, Some(1));
                assert_eq!(meta.channel, Some(0));
                assert_eq!(meta.class_id, Some(10));
                assert_eq!(meta.method, Some(10));
            }
            _ => panic!("expected AMQP metadata"),
        }
    }

    #[test]
    fn test_detect_amqp_10_header() {
        let detector = AmqpDetector::new();
        let result = detector.detect(b"AMQP\x00\x01\x00\x00").unwrap();
        assert_eq!(result.protocol, Protocol::Amqp);
        match result.metadata {
            Metadata::Amqp(meta) => {
                assert_eq!(meta.version, "1.0");
                assert_eq!(meta.frame_type, None);
            }
            _ => panic!("expected AMQP metadata"),
        }
    }

    #[test]
    fn test_detect_rejects_garbage() {
        let detector = AmqpDetector::new();
        assert!(detector.detect(b"GET / HTTP/1.1\r\n").is_none());
        assert!(detector.detect(&[0x05; 12]).is_none());
    }

    #[test]
    fn test_first_byte_gate_covers_valid_samples() {
        let detector = AmqpDetector::new();
        let gate = detector.first_byte_gate().expect("detector 应声明首字节门");
        for sample in [&method_frame()[..], &b"AMQP\x00\x00\x09\x01"[..]] {
            assert!(
                gate.iter()
                    .any(|&(lo, hi)| sample[0] >= lo && sample[0] <= hi),
                "门区间不覆盖合法样本首字节 0x{:02X}",
                sample[0]
            );
        }
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features messaging amqp`
Expected: 编译失败，`src/protocols/amqp/mod.rs` 尚未声明 `mod detector`，`AmqpDetector` 不可用。

- [ ] **Step 3: 接入模块并注册**

把 `src/protocols/amqp/mod.rs` 替换为：

```rust
//! AMQP protocol detection module for rDpi
//!
//! 识别 0-9-1 方法/头/体/心跳帧头与 0-9-1/1.0 协议头。

mod detector;
mod parser;

pub use detector::AmqpDetector;
pub use parser::{parse_amqp, AmqpParsed};

use crate::protocols::Registry;

/// Register AMQP detector with the protocol registry
pub fn register(registry: &mut Registry) {
    registry.register(Box::new(AmqpDetector::new()));
}
```

`src/protocols/mod.rs` 模块声明（文件顶部 `bgp` 之前）加入：

```rust
#[cfg(feature = "messaging")]
pub mod amqp;
```

`register_defaults` 的 `memcached::register(_registry);` 之后加入：

```rust
    #[cfg(feature = "messaging")]
    amqp::register(_registry);
```

在同文件末尾追加：

```rust
#[cfg(all(test, feature = "messaging"))]
mod messaging_registry_tests {
    use super::*;

    #[test]
    fn test_amqp_detector_registered() {
        let registry = Registry::default();
        let names: Vec<&str> = registry
            .detectors
            .iter()
            .map(|entry| entry.detector.name())
            .collect();
        assert!(names.contains(&"amqp"), "amqp detector must be registered");
    }
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --features messaging amqp`
Expected: 4 个 detector 测试 + 8 个 parser 测试全部通过；注册测试通过。

- [ ] **Step 5: 提交**

```bash
cargo fmt --all
git add src/protocols/amqp src/protocols/mod.rs
git commit -m "Add AMQP detector and registration"
```

---

### Task 9: Parity 导出映射

**Files:**
- Modify: `src/parity.rs`（`protocol_name`、`ndpi_compat_classification`）
- Test: `tests/parity_export.rs`（末尾追加）

**Interfaces:**
- Consumes: Task 1 的三个协议变体。
- Produces: nDPI 兼容 master/category/breed：Memcached→Memcached/Network、Elasticsearch→Elasticsearch/System、Amqp→AMQP/RPC。

- [ ] **Step 1: 写失败测试**

在 `tests/parity_export.rs` 末尾追加：

```rust
#[cfg(feature = "database")]
#[test]
fn test_protocol_name_memcached_elasticsearch() {
    let flow = flow_with_protocol(Protocol::Memcached);
    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.master_protocol.as_deref(), Some("Memcached"));
    assert_eq!(normalized.category.as_deref(), Some("Network"));
    assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));

    let flow = flow_with_protocol(Protocol::Elasticsearch);
    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.master_protocol.as_deref(), Some("Elasticsearch"));
    assert_eq!(normalized.category.as_deref(), Some("System"));
    assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
}

#[cfg(feature = "messaging")]
#[test]
fn test_protocol_name_amqp() {
    let flow = flow_with_protocol(Protocol::Amqp);
    let normalized = NormalizedFlow::from_flow(&flow);
    assert_eq!(normalized.master_protocol.as_deref(), Some("AMQP"));
    assert_eq!(normalized.category.as_deref(), Some("RPC"));
    assert_eq!(normalized.breed.as_deref(), Some("Acceptable"));
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features "json database messaging" --test parity_export`
Expected: `Memcached` category 为 `Database`（期望 Network）、`Amqp` master 为 `Amqp`（期望 AMQP）等断言失败。

- [ ] **Step 3: 实现映射**

`src/parity.rs` 的 `protocol_name` 中，`Protocol::Smb23 => "SMBv23"` 之后加入：

```rust
        #[cfg(feature = "messaging")]
        Protocol::Amqp => "AMQP".to_string(),
```

`ndpi_compat_classification` 的 MySQL/PostgreSQL 分支之后加入：

```rust
        // F46（nDPI 5.0 源码核对）：Memcached 归 Network/Acceptable，
        // Elasticsearch 归 System/Acceptable，AMQP 归 RPC/Acceptable
        #[cfg(feature = "database")]
        Protocol::Memcached => ("Network".to_string(), "Acceptable".to_string()),
        #[cfg(feature = "database")]
        Protocol::Elasticsearch => ("System".to_string(), "Acceptable".to_string()),
        #[cfg(feature = "messaging")]
        Protocol::Amqp => ("RPC".to_string(), "Acceptable".to_string()),
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --features "json database messaging" --test parity_export`
Expected: 全部通过。

- [ ] **Step 5: 提交**

```bash
cargo fmt --all
git add src/parity.rs tests/parity_export.rs
git commit -m "Map database and messaging protocols to nDPI parity names"
```

---

### Task 10: CLI 元数据显示

**Files:**
- Modify: `src/bin/rdpi.rs:300`（`print_detection` 的 metadata match）

**Interfaces:**
- Consumes: Task 1 的三个 metadata 类型、`ElasticsearchSource`。

- [ ] **Step 1: 实现显示分支**

在 `rdpi::Metadata::Smb(_) => "",` 之前加入：

```rust
        #[cfg(feature = "database")]
        rdpi::Metadata::Memcached(m) => m.command.as_deref().unwrap_or(""),
        #[cfg(feature = "database")]
        rdpi::Metadata::Elasticsearch(e) => match e.source {
            rdpi::ElasticsearchSource::Binary => "binary",
            rdpi::ElasticsearchSource::Http => "http",
        },
        #[cfg(feature = "messaging")]
        rdpi::Metadata::Amqp(a) => &a.version,
```

- [ ] **Step 2: 编译验证**

Run: `cargo check --features "pcap json database messaging"`
Expected: 编译通过，无警告。

- [ ] **Step 3: 提交**

```bash
cargo fmt --all
git add src/bin/rdpi.rs
git commit -m "Show Memcached, Elasticsearch and AMQP metadata in CLI"
```

---

### Task 11: 语料与真实 golden

**Files:**
- Modify: `tests/parity/gen_corpus.py`
- Modify: `tests/parity/gen_golden.sh`
- Create: `tests/parity/corpus/{memcached_session,elasticsearch_binary,amqp_frame}.pcap`
- Create: `tests/parity/golden/{memcached_session,elasticsearch_binary,amqp_frame}.ndpi.json`

**Interfaces:**
- Consumes: 全部 detector。
- Produces: 3 个新语料 + golden，差分门禁全绿。

- [ ] **Step 1: 添加语料构造器**

在 `tests/parity/gen_corpus.py` 的 `build_redis` 之后加入：

```python
def build_memcached_session():
    """Memcached 文本命令/响应（TCP 11211，nDPI 两次匹配后 DPI）。"""
    return tcp_session(
        CLIENT,
        SERVER,
        50015,
        11211,
        [("c", b"delete foo\r\n"), ("s", b"DELETED\r\n")],
    )


def build_elasticsearch_binary():
    """Elasticsearch 二进制 `ES` + BE u32 长度（TCP 9200）。"""
    request = b"ES" + struct.pack(">I", 5) + b"hello"
    response = b"ES" + struct.pack(">I", 3) + b"ack"
    return tcp_session(
        CLIENT,
        SERVER,
        50016,
        9200,
        [("c", request), ("s", response)],
    )


def build_amqp_frame():
    """AMQP 0-9-1 方法帧（type=1, channel=0, class=10, method=10/11）。"""
    request = bytes(
        [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0A, 0x00, 0x0A, 0xCE]
    )
    response = bytes(
        [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0A, 0x00, 0x0B, 0xCE]
    )
    return tcp_session(
        CLIENT, SERVER, 50017, 5672, [("c", request), ("s", response)]
    )
```

在 `CORPUS` 字典的 `"redis_ping": build_redis,` 之后加入：

```python
    # F46：Memcached / Elasticsearch 二进制 / AMQP 0-9-1
    "memcached_session": build_memcached_session,
    "elasticsearch_binary": build_elasticsearch_binary,
    "amqp_frame": build_amqp_frame,
```

- [ ] **Step 2: 生成 pcap**

Run: `python -I tests/parity/gen_corpus.py`
Expected: 输出包含 `wrote .../memcached_session.pcap`、`wrote .../elasticsearch_binary.pcap`、`wrote .../amqp_frame.pcap`。

- [ ] **Step 3: 生成 golden**

将 `tests/parity/gen_golden.sh` 的 for 列表末尾加入 `memcached_session elasticsearch_binary amqp_frame`，然后运行：

Run: `wsl.exe bash -lc "cd /mnt/d/rust_code/rDpi && bash tests/parity/gen_golden.sh"`
Expected: 输出 `DONE`，三个 golden 文件存在。

- [ ] **Step 4: 核对 golden 内容**

Run: `cat tests/parity/golden/memcached_session.ndpi.json`
Expected: `"proto":"Memcached"`、`"category":"Network"`、`"breed":"Acceptable"`。

Run: `cat tests/parity/golden/elasticsearch_binary.ndpi.json`
Expected: `"proto":"Elasticsearch"`、`"category":"System"`、`"breed":"Acceptable"`。

Run: `cat tests/parity/golden/amqp_frame.ndpi.json`
Expected: `"proto":"AMQP"`、`"category":"RPC"`、`"breed":"Acceptable"`。

若与预期不一致，以真实 golden 为准修正 detector/parity 映射，并在提交说明中记录差异。

- [ ] **Step 5: 运行差分门禁**

Run: `cargo test --all-features --test test_parity_corpus`
Expected: 全部通过；新语料的 master/category/breed/confidence/risk gate 无失败。

- [ ] **Step 6: 提交**

```bash
git add tests/parity/gen_corpus.py tests/parity/gen_golden.sh tests/parity/corpus tests/parity/golden
git commit -m "Add database and messaging corpus with real nDPI golden"
```

---

### Task 12: 文档回写与全量门禁

**Files:**
- Modify: `AGENTS.md`
- Modify: `docs/architecture/modules.md`
- Modify: `docs/architecture/risks.md`
- Modify: `docs/architecture/ndpi-pure-rust-plan.md`
- Modify: `docs/architecture/protocol-coverage-plan.md`

**Interfaces:**
- Consumes: 前 11 个任务的实现与实测结果。

- [ ] **Step 1: 更新 AGENTS.md**

在 F45 条目之后、F29 条目之前加入：

```markdown
- **Memcached + Elasticsearch + AMQP 识别（F46，2026-11-07）**：阶段 2 第二批子批次 A（`docs/architecture/phase2-database-messaging-design.md`）——`database` feature 新增 `Protocol::Memcached/Elasticsearch` + `MemcachedMetadata{command,is_response}`/`ElasticsearchMetadata{message_length,source}`；新 `messaging` feature：`Protocol::Amqp` + `AmqpMetadata{version,frame_type,channel,class_id,method}`；`DissectorState::Memcached` 命中计数（端口 11211 单包定型 / 非标端口 2 次匹配 / >5 包 GiveUp）；Memcached 26 签名 + UDP 8 字节头；Elasticsearch 二进制 `ES`+BE u32 + HTTP `X-elastic-product` 响应头子分类（rDpi 超集，仅响应先到）；AMQP 0-9-1 帧头 + 1.0 协议头；注册于 Redis 后 SMTP 前；parity：Memcached Network/Acceptable、Elasticsearch System/Acceptable、AMQP RPC/Acceptable（`Amqp` 显式映射 "AMQP"）；语料 +3 pcap + WSL golden 差分全绿。
```

在状态表 F45 行之后加入：

```markdown
| F46 | Memcached + Elasticsearch + AMQP 识别：database 复用 + 新 messaging feature；Memcached 有状态匹配计数、Elasticsearch 二进制/HTTP 双路径、AMQP 0-9-1/1.0；parity 三协议分类映射；语料 +3 pcap 差分全绿 | 中 | ✅ 已完成 2026-11-07（HTTP-ES 仅响应先到、AMQP 1.0 仅协议头等边界见 risks.md F46） |
```

把“常用命令”中 `cargo test --all-features` 的测试数替换为本次实测值，并增加一行：

```bash
cargo test --features "database messaging"  # F46 Memcached/Elasticsearch/AMQP 模块测试
```

- [ ] **Step 2: 更新 modules.md**

`database` 行改为：

```markdown
| database | mysql, postgresql, redis, mongodb, memcached, elasticsearch（F46，2026-11-07：Memcached 26 签名 + UDP 头 + 有状态匹配计数；Elasticsearch 二进制 `ES` + HTTP `X-elastic-product`） |
| messaging | amqp（F46，2026-11-07：0-9-1 帧头 + 1.0 协议头） |
```

- [ ] **Step 3: 更新 risks.md**

在 F45 章节之后新增：

```markdown
## F46【中】Memcached + Elasticsearch + AMQP 识别（2026-11-07，新功能开发）—— ✅ 已完成

- **背景**：阶段 2 第二批子批次 A（`docs/architecture/phase2-database-messaging-design.md`）。数据库/消息协议缺口中的首批可独立验收协议。
- **实现**：
  - **枚举与规则**（core/types.rs）：`database` 复用（Memcached/Elasticsearch）、新 `messaging` feature（Amqp）；`MemcachedMetadata{command,is_response}`、`ElasticsearchSource{Binary,Http}` + `ElasticsearchMetadata{message_length,source}`、`AmqpMetadata{version,frame_type,channel,class_id,method}`；`MemcachedDissectorState{matches,packets}` + `DissectorState::Memcached`；rule 名 `memcached`/`elasticsearch`/`amqp`。
  - **Memcached 模块**：parser 26 签名（15 命令 + 11 响应，大小写敏感、仅载荷起始）+ UDP 8 字节头（reserved=0、total≠0）；detector TCP `process()` 标准端口 11211 单次匹配、非标端口 2 次匹配、>5 包 GiveUp；UDP 仅 11211 单包；`first_byte_gate=None`。
  - **Elasticsearch 模块**：二进制 `ES` + BE u32 长度（payload ≥ length+6）；HTTP detector 响应分支扫描 `X-elastic-product: Elasticsearch`（名称/值大小写不敏感，仅头部区域）；请求先到的流保持 Http。
  - **AMQP 模块**：0-9-1 帧头（ptype≤3、length<32768、length+8≥payload、class 10..=110、method≤120）+ 0-9-1/1.0 协议头；`first_byte_gate=Some([(0x00,0x03),(0x41,0x41)])`。
  - **注册**：database 块末尾 elasticsearch→memcached；messaging 块紧随其后 amqp；均位于 HTTP 之前。
  - **parity**：protocol_name 仅 Amqp 需显式 "AMQP"；classification Memcached→Network、Elasticsearch→System、Amqp→RPC，均 Acceptable。
- **Golden 差分（真实 nDPI 5.0 验证）**：`memcached_session` 两次匹配 → DPI Memcached；`elasticsearch_binary` 首包 DPI Elasticsearch；`amqp_frame` 首包 DPI AMQP。HTTP-ES 与 AMQP 1.0 因 nDPI 5.0 无对应识别，不进入 parity 语料（单测覆盖）。
- **测试**：默认 / database+messaging / all-features / clippy 全绿（具体数字以本次门禁输出为准）。
- **已知边界**：① Memcached 签名必须位于载荷起始，跨段命令不重组；② 不支持二进制协议/meta 命令；③ HTTP-ES 仅响应先到；④ AMQP 1.0 仅协议头；⑤ AMQP 多帧载荷只看首帧；⑥ 0-9-1 帧检测为与 nDPI 相同的启发式，不保证完整帧合法。
```

- [ ] **Step 4: 更新路线图与覆盖表**

`docs/architecture/ndpi-pure-rust-plan.md` 的 B 组列表中，把 `Memcached、Elasticsearch、Kafka、AMQP` 改为：

```markdown
Memcached（✅ F46）、Elasticsearch（✅ F46）、Kafka、AMQP（✅ F46）
```

`docs/architecture/protocol-coverage-plan.md` §10.2 的协议列表改为：

```markdown
- SMBv1/v2/v3、NetBIOS（✅ F45 完成）、Memcached（✅ F46 完成）、Elasticsearch（✅ F46 完成）、AMQP（✅ F46 完成）、AFP、MSSQL/TDS、Oracle、Cassandra、Kafka、NATS、STOMP、OpenWire。
```

- [ ] **Step 5: 运行全量门禁**

```bash
cargo test
cargo test --features "database messaging"
cargo test --all-features
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
```

Expected: 全部通过，clippy 0 警告。

- [ ] **Step 6: 提交**

```bash
git add AGENTS.md docs/architecture
git commit -m "Update docs for database and messaging protocol support"
```

---

## 验收清单

- [ ] `cargo test` 默认 features 全绿（新增测试均被 feature gate 排除）。
- [ ] `cargo test --features "database messaging"` 全绿。
- [ ] `cargo test --all-features` 全绿。
- [ ] `cargo fmt --all -- --check` 无输出。
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` 0 警告。
- [ ] 3 个新 pcap 与真实 nDPI 5.0 golden 差分通过。
- [ ] HTTP-ES 与 AMQP 1.0 单测覆盖，且未进入 parity 语料。
- [ ] 文档 F46 条目、模块表、风险边界、路线图均已回写。
