# 阶段 2 第二批设计：Memcached、Elasticsearch、AMQP

> 生成时间：2026-11-07
> 状态：设计已确认，待实现
> 关联文档：
> - [nDPI 纯 Rust 实现方案](ndpi-pure-rust-plan.md)（阶段 2：数据库/消息协议 Wave）
> - [协议/应用覆盖候选清单](protocol-coverage-plan.md)（§10.2 阶段 2）
> - [阶段 2 第一批设计：NetBIOS + SMBv1/v2/v3](phase2-smb-netbios-design.md)（有状态框架与 parity 先例）
> - [风险与已知问题](risks.md)（F45 feature/状态/parity 先例）
> - [AGENTS.md](../../AGENTS.md)（F45 及测试基线）

---

## 1. 背景与目标

阶段 2 第一批已完成 NetBIOS/SMB（F45）。本批进入数据库/消息协议缺口，按可独立验收的粒度拆为两个子批次：

- **子批次 A（本文档）**：Memcached、Elasticsearch、AMQP；
- 子批次 B（后续设计）：MSSQL/TDS、Kafka。

本轮目标：

1. 复用现有 `database` feature 承载 Memcached/Elasticsearch，新增 `messaging` feature 承载 AMQP；
2. 与 nDPI 5.0 协议粒度对齐，新增 `Memcached`、`Elasticsearch`、`Amqp` 三个 `Protocol` 变体；
3. 对齐 nDPI 5.0 检测依据：
   - Memcached：TCP/UDP 11211，命令/响应前缀 + 2 次匹配阈值；
   - Elasticsearch：二进制 `ES` + BE u32 长度；
   - AMQP：0-9-1 帧头（ptype/长度/class/method 约束）；
4. 在不改变 nDPI 语义的前提下提供两个已确认的超集能力：
   - Elasticsearch HTTP 响应头 `X-elastic-product: Elasticsearch` 子分类；
   - AMQP 1.0 8 字节协议头识别；
5. 提取基础元数据（命令/消息长度/帧字段）；
6. 加入语料 + 真实 ndpiReader 5.0 golden 差分。

**Parity 语料约束（实现前已核实 nDPI 5.0 源码）**：

- `elastic_search.c` 只识别二进制 `ES` 格式，没有 HTTP 头检测。HTTP-ES 若进入 parity 语料，nDPI golden 会报 `HTTP`，master 差分必然失败；
- `amqp.c` 只识别 0-9-1 帧头，不识别 1.0 协议头。1.0 语料同理不能进入 parity 语料。

因此 HTTP-ES 与 AMQP 1.0 只做单元测试，不进入 `tests/parity/corpus/`。

---

## 2. 协议模型与 Feature

### 2.1 Protocol 变体

| 变体 | feature | 内部 category | breed | 产出位置 |
|---|---|---|---|---|
| `Memcached` | `database` | `ProtocolCategory::Database` | `ProtocolBreed::Acceptable` | Memcached detector |
| `Elasticsearch` | `database` | `ProtocolCategory::Database` | `ProtocolBreed::Acceptable` | Elasticsearch detector / HTTP detector |
| `Amqp` | `messaging` | `ProtocolCategory::Messaging` | `ProtocolBreed::Acceptable` | AMQP detector |

三个变体均使用 `#[cfg(feature = "...")]`，与 F45 的 `NetBios`/`Smb1`/`Smb23` 一致。所有引用这些变体的 match 分支（`category()` / `breed()` / 规则名称 / parity 映射 / CLI）都必须带相同的 cfg 包裹。

### 2.2 Feature 与模块

- `Cargo.toml`：新增 `messaging = []`（`database` 已存在，不新增 feature）；
- `src/protocols/memcached/`：`mod.rs` + `detector.rs` + `parser.rs`；
- `src/protocols/elasticsearch/`：`mod.rs` + `detector.rs` + `parser.rs`；
- `src/protocols/amqp/`：`mod.rs` + `detector.rs` + `parser.rs`；
- `src/protocols/mod.rs`：模块声明 + `register_defaults` 注册。

### 2.3 Metadata

```rust
#[cfg(feature = "database")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default)]
pub struct MemcachedMetadata {
    /// 请求命令（小写，如 "get"）或响应状态（如 "END"/"STORED"）
    pub command: Option<String>,
    /// 是否为服务端响应
    pub is_response: bool,
}

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

#[cfg(feature = "database")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default)]
pub struct ElasticsearchMetadata {
    /// 二进制协议头中的 BE u32 长度；HTTP 路径为 None
    pub message_length: Option<u32>,
    /// 识别来源
    pub source: ElasticsearchSource,
}

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

`Metadata` 枚举新增三个条件变体：

```rust
#[cfg(feature = "database")]
Memcached(MemcachedMetadata),
#[cfg(feature = "database")]
Elasticsearch(ElasticsearchMetadata),
#[cfg(feature = "messaging")]
Amqp(AmqpMetadata),
```

### 2.4 DissectorState

按现有 Ftp/NetBios/SMB 先例，**状态结构与状态变体保持无条件**（只有 metadata 与 protocol 变体受 feature 控制）：

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemcachedDissectorState {
    /// 已匹配报文数（每包最多 +1，对齐 nDPI 的 matches）
    pub matches: u8,
    /// 已检查载荷包数（对齐 nDPI 的 packet_counter > 5 放弃）
    pub packets: u8,
}
```

`DissectorState` 新增：

```rust
/// Memcached TCP 命中计数
Memcached(MemcachedDissectorState),
```

### 2.5 规则名称

`src/rule/parser.rs` 新增：

```rust
#[cfg(feature = "database")]
"memcached" => Protocol::Memcached,
#[cfg(feature = "database")]
"elasticsearch" => Protocol::Elasticsearch,
#[cfg(feature = "messaging")]
"amqp" => Protocol::Amqp,
```

---

## 3. Memcached Detector

### 3.1 签名表

与 nDPI `memcached.c` 完全一致的 26 个前缀签名，只在载荷起始处匹配（大小写敏感）：

| 类别 | 签名 |
|---|---|
| 命令（15） | `set ` `add ` `replace ` `append ` `prepend ` `cas ` `get ` `gets ` `delete ` `incr ` `decr ` `touch ` `gat ` `gats ` `stats` |
| 响应（11） | `ERROR\r\n` `CLIENT_ERROR ` `SERVER_ERROR ` `STORED\r\n` `NOT_STORED\r\n` `EXISTS\r\n` `NOT_FOUND\r\n` `END\r\n` `DELETED\r\n` `TOUCHED\r\n` `STAT ` |

解析输出：

```rust
pub struct MemcachedParsed {
    /// 请求命令（小写）或响应状态（大写）
    pub token: &'static str,
    pub is_response: bool,
}
```

`get ` 与 `gets `、`gat ` 与 `gats ` 的前缀关系天然由“命令带尾随空格”区分；`stats` 不带尾随空格，与 nDPI 一致（`statsfoo` 也会命中）。

### 3.2 UDP

仅端口 11211（任一端），载荷长度 ≥ 13（8 字节头 + `END\r\n`），并满足 nDPI 的头部约束：

- `payload[6..8] == 0`（reserved 必须为 0）；
- `payload[4..6] != 0`（total datagrams 不得为 0）；
- 命令/响应签名从偏移 8 开始匹配。

### 3.3 有状态 `process()`

| 场景 | 判定 | 结果 |
|---|---|---|
| TCP 端口 11211，首包命中 | 1 次匹配 | `Classified` |
| TCP 非标端口，首包命中 | 第 1 次匹配 | `Continue` |
| TCP 非标端口，已接管后再次命中 | 第 2 次匹配 | `Classified` |
| 首包未命中 | 不接管 | `None` |
| 已接管后 `packets > 5` 且未达标 | nDPI 放弃阈值 | `GiveUp` |

实现要点：

- 只在 `DissectorState::None` 时用首包签名尝试接管；其他状态（含其他协议）返回 `None`；
- 接管后每个包 `packets += 1`，命中时 `matches += 1`；
- 标准端口阈值 1，非标端口阈值 2；
- `GiveUp` 由上层清空状态并回退无状态/端口猜测；
- 返回 `Classified` 时附带当前包的 `MemcachedMetadata`。

### 3.4 `detect()` / `detect_with_context()`

- `detect()`：直接调用文本签名解析，命中返回 `Protocol::Memcached` + `Confidence::Dpi`。供库用户与单测直接使用；
- `detect_with_context()`：仅当任一端端口为 11211 时生效；先尝试文本签名（覆盖直连 TCP 11211 的库调用），再尝试 UDP 解析；
- Pipeline 中 TCP 首包会先进入 `process()`，因此不会出现“非标端口单包即定型”的路径。

### 3.5 首字节门

`first_byte_gate() = None`：UDP 头部首字节任意，命令/响应又是大小写混合，无法给出有意义的窄区间；声明宽区间没有收益。

---

## 4. Elasticsearch Detector

### 4.1 二进制路径

与 `elastic_search.c` 一致：

1. `payload.len() >= 6`；
2. `payload[0..2] == b"ES"`；
3. `message_length = u32::from_be_bytes(payload[2..6])`；
4. `payload.len() >= message_length as usize + 6`；
5. 命中 → `Protocol::Elasticsearch`，`source = Binary`，`message_length = Some(...)`，`Confidence::Dpi`。

`first_byte_gate() = Some(&[(0x45u8, 0x45u8)])`（`'E'`）。

### 4.2 HTTP 路径

新增 `src/protocols/elasticsearch/parser.rs::is_elasticsearch_http_response(payload) -> bool`：

- 只扫描响应头部区域（到 `\r\n\r\n` 为止）；
- 跳过状态行，逐行按 `:` 拆分；
- 头部名与值均大小写不敏感；
- 名称等于 `x-elastic-product` 且值等于 `Elasticsearch`（去两侧空白）时命中；
- 使用字节级扫描，不要求整个载荷是合法 UTF-8。

### 4.3 HTTP detector 集成

`src/protocols/http/detector.rs` 的响应分支：

```rust
#[cfg(feature = "database")]
let protocol = if crate::protocols::elasticsearch::is_elasticsearch_http_response(payload) {
    Protocol::Elasticsearch
} else {
    Protocol::Http
};
#[cfg(not(feature = "database"))]
let protocol = Protocol::Http;
```

命中时 metadata 为 `Metadata::Elasticsearch(ElasticsearchMetadata { message_length: None, source: Http })`；未命中保持 `Metadata::Http`。请求分支不变。

同时，`HttpDetector::process()` 中显式的 `DissectorState` 穷尽 match 需要增加：

```rust
| DissectorState::Memcached(_) => return None,
```

### 4.4 边界

- 只在“该流首个可见载荷是响应”时生效（抓包从中途开始、服务端先发包）；请求先到的流已定型为 `Http`，响应不会触发重分类；
- 不做 REST 路径启发式（`/_search`、`/_bulk` 等），避免与普通 HTTP 误报；
- 二进制格式只按 nDPI 的首消息规则识别，不解析后续消息体；
- HTTP 路径依赖 `http` feature；仅启用 `database` 而不启用 `http` 时不存在该路径。

---

## 5. AMQP Detector

### 5.1 0-9-1 帧头

与 `amqp.c` 一致：

1. `payload.len() > 11`；
2. `ptype = payload[0]`，要求 `<= 3`；
3. `length = BE u32 payload[3..7]`，要求 `length < 32768`；
4. `length as usize + 8 >= payload.len()`（允许帧跨 TCP 段）；
5. `class_id = BE u16 payload[7..9]`，要求 `10..=110`；
6. `method = BE u16 payload[9..11]`，要求 `<= 120`；
7. `channel = BE u16 payload[1..3]`；
8. 命中 → `Protocol::Amqp`，`version = "0-9-1"`，`Confidence::Dpi`。

### 5.2 协议头

两个 8 字节常量精确匹配：

- `b"AMQP\x00\x00\x09\x01"` → 0-9-1；
- `b"AMQP\x00\x01\x00\x00"` → 1.0。

协议头识别时 `frame_type/channel/class_id/method` 均为 `None`。1.0 只识别协议头，不解析 1.0 帧（nDPI 5.0 亦不支持）。

### 5.3 首字节门

`first_byte_gate() = Some(&[(0x00u8, 0x03u8), (0x41u8, 0x41u8)])`：

- 0-9-1 帧首字节为 ptype（0..=3）；
- 协议头首字节为 `'A'`（0x41）。

---

## 6. 注册与集成

### 6.1 模块声明

`src/protocols/mod.rs`：

```rust
#[cfg(feature = "messaging")]
pub mod amqp;
#[cfg(feature = "database")]
pub mod elasticsearch;
#[cfg(feature = "database")]
pub mod memcached;
```

### 6.2 注册顺序

在现有 `database` 块末尾追加（保持 MySQL/PostgreSQL/Redis 相对顺序不变）：

```rust
#[cfg(feature = "database")]
elasticsearch::register(_registry);
#[cfg(feature = "database")]
memcached::register(_registry);
#[cfg(feature = "messaging")]
amqp::register(_registry);
```

位置在 `redis` 之后、`smtp` 之前，仍先于 HTTP/DNS。三个 detector 的首字节门互斥性：

- Elasticsearch 门仅 `'E'`；
- AMQP 门为 `0x00..0x03` 与 `'A'`；
- Memcached 无门。

与现有 detector 无首字节冲突，注册顺序对结果无影响。

### 6.3 CLI

`src/bin/rdpi.rs` 的元数据显示新增：

- `Metadata::Memcached(m)` → `command`；
- `Metadata::Elasticsearch(e)` → `"binary"` / `"http"`；
- `Metadata::Amqp(a)` → `version`。

各分支带对应 `#[cfg(feature = "...")]`。

---

## 7. Parity 导出

`src/parity.rs`：

| rDpi 协议 | master | app | category | breed |
|---|---|---|---|---|
| `Memcached` | `Memcached` | — | `Network` | `Acceptable` |
| `Elasticsearch` | `Elasticsearch` | — | `System` | `Acceptable` |
| `Amqp` | `AMQP` | — | `RPC` | `Acceptable` |

- `protocol_name`：`Memcached` / `Elasticsearch` 的 Debug 输出已与 nDPI 一致；只新增 `Protocol::Amqp => "AMQP"`；
- `ndpi_compat_classification` 新增三条映射（内部 category 与 nDPI 不同，必须显式覆盖）；
- 无 app 层协议，`app_protocol = None`；
- 不新增风险映射。

nDPI 协议 ID 供参考：Memcached 40、AMQP 192、Elasticsearch 330。分类/名称均已用源码核对，语料 golden 生成后以真实输出为准。

---

## 8. 文件改动清单

| 文件 | 改动 |
|---|---|
| `Cargo.toml` | 新增 `messaging = []` |
| `src/core/types.rs` | 3 个 `Protocol` 变体；3 个 metadata 类型；`ElasticsearchSource`；`MemcachedDissectorState`；`DissectorState::Memcached`；category/breed 分支 |
| `src/protocols/memcached/` | 新建：`mod.rs`、`detector.rs`、`parser.rs` |
| `src/protocols/elasticsearch/` | 新建：`mod.rs`、`detector.rs`、`parser.rs`（含 HTTP 头辅助函数） |
| `src/protocols/amqp/` | 新建：`mod.rs`、`detector.rs`、`parser.rs` |
| `src/protocols/mod.rs` | 模块声明 + 注册 |
| `src/protocols/http/detector.rs` | ES 响应头子分类；`DissectorState::Memcached` match 分支 |
| `src/rule/parser.rs` | 3 个协议名称映射 |
| `src/parity.rs` | master/category/breed 映射 |
| `src/bin/rdpi.rs` | 元数据显示 |
| `tests/parity/gen_corpus.py` | 3 个语料用例 |
| `tests/parity/gen_golden.sh` | 3 个 golden 生成项 |
| `tests/parity/corpus/`、`tests/parity/golden/` | 新语料与 ndpiReader 5.0 golden |
| `AGENTS.md`、`docs/architecture/*.md` | F46 记录与状态更新 |

---

## 9. 测试与语料

### 9.1 单元测试

**Memcached**

- 15 个命令 + 11 个响应签名逐一命中；
- 大写 `SET `、`END\r\n` 小写、`getaway` 等负样本；
- UDP 头部：reserved 非零、total 为 0、长度不足、命令偏移正确；
- 标准端口首包 → `Classified`；非标端口首包 → `Continue`、第二包 → `Classified`；
- 首包不命中 → `None`；
- 接管后 6 个包仍未达标 → `GiveUp`；
- 元数据 `command` / `is_response` 正确。

**Elasticsearch**

- 二进制有效包（长度恰好匹配、长度小于可用字节）；
- 短包、错误 magic、声明长度超过载荷 → `None`；
- HTTP 头：名称/值大小写、值前后空白、头在响应中部、值不匹配、请求中不命中、头部结束后的 body 不参与扫描；
- HTTP detector：带 `X-elastic-product` 的响应 → `Elasticsearch`；普通响应 → `Http`；
- `first_byte_gate` 覆盖 `'E'` 且拒绝其他字节。

**AMQP**

- 合法 0-9-1 方法帧（ptype=1、channel/class/method 元数据）；
- ptype > 3、class < 10、class > 110、method > 120、length ≥ 32768、`length + 8 < payload_len` → `None`；
- 0-9-1 与 1.0 协议头；
- `first_byte_gate` 覆盖 `0x00..0x03` 与 `'A'`。

**回归**

- `rule` 名称映射；
- parity `from_flow` 的 master/category/breed；
- `Protocol::category()` / `breed()` 在 default / `database` / `messaging` / all-features 下均可编译。

### 9.2 语料 + golden

扩展 `tests/parity/gen_corpus.py`：

1. `memcached_session.pcap`：TCP 11211，客户端 `delete foo\r\n`，服务端 `DELETED\r\n`。nDPI 两包各匹配一次 → `DPI`；
2. `elasticsearch_binary.pcap`：TCP 9200，双向各一个 `ES` 消息，例如请求 `ES\x00\x00\x00\x05hello`（11 字节），响应同格式不同内容。nDPI 首包即 DPI；
3. `amqp_frame.pcap`：TCP 5672，双向各一个 0-9-1 方法帧，例如
   `01 0000 00000004 000A 000A CE`（12 字节，class 10 / method 10）。

用 WSL 中的 ndpiReader 5.0 生成 golden；若真实输出与映射预期不一致，先修正映射再提交。

**不进入 parity 语料**：

- Elasticsearch HTTP（nDPI 报 `HTTP`）；
- AMQP 1.0 协议头（nDPI 无法识别）。

两者由单元测试覆盖。

### 9.3 门禁

```bash
cargo test
cargo test --features "database messaging"
cargo test --all-features
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
```

验收：

- 新增单测全部通过；
- 3 个新语料在 master/category/breed/confidence/risk gate 上一致；
- 现有 56 个语料与全部存量测试无回归。

---

## 10. 文档更新

- `AGENTS.md`：新增 F46 条目（实现摘要、测试基线、模块说明）；
- `docs/architecture/modules.md`：memcached/elasticsearch/amqp 模块说明；
- `docs/architecture/risks.md`：F46 实现细节与超集边界；
- `docs/architecture/ndpi-pure-rust-plan.md`：标记数据库/消息协议子批次 A 完成；
- `docs/architecture/protocol-coverage-plan.md`：更新缺口表与“下一步”。

---

## 11. 已知边界

**Memcached**

- 签名必须位于载荷起始处；跨 TCP 段的命令不重组（nDPI 同）；
- 不支持二进制 Memcached 协议、meta 命令（`mg`/`ms` 等）、SASL；
- 标准端口单包定型是对 nDPI 2 次匹配的保守放宽，用于对齐 rDpi 已有的“端口 + 载荷即定型”模式；
- UDP 只在 11211 识别，且要求 8 字节头 reserved=0、total≠0。

**Elasticsearch**

- 二进制格式只覆盖 nDPI 的 `ES` + 长度首消息规则；
- HTTP 只在响应先到时识别，请求先到的流不升级；
- 不解析 REST 路径、不解析响应体、不做 gzip/压缩处理。

**AMQP**

- 0-9-1 检测为启发式帧头校验（与 nDPI 相同），不保证完整帧合法性；
- 1.0 只识别协议头，不识别 1.0 帧；
- 不解析 SASL、不处理 5671 TLS；
- 多帧载荷只看起始帧。

**Parity**

- HTTP-ES 与 AMQP 1.0 无 nDPI 对应输出，不进入语料；
- Memcached 单包语料的 nDPI golden 可能是 `Match by port`，差分门禁允许升级为 `Dpi`。

---

## 12. 实施顺序

1. `messaging` feature + 三个 `Protocol` 变体 + category/breed + 规则名称（先让新变体可编译）；
2. Memcached 解析器 + 状态 + detector + 注册 + 单测；
3. Elasticsearch 二进制解析/detector + HTTP 头辅助函数 + HTTP detector 接入 + 单测；
4. AMQP 解析器/detector + 注册 + 单测；
5. parity 映射 + 单测；
6. 语料生成 + WSL golden + 差分门禁；
7. 文档回写、全量门禁、提交。

---

## 13. 风险与注意事项

| 风险 | 应对 |
|---|---|
| Memcached UDP 头部校验在 TCP 流上误命中 | Pipeline 中 TCP 首包先由 `process()` 处理；`detect_with_context` 先文本后 UDP，且 UDP 解析要求 reserved/total 约束 |
| 非标端口 2 次匹配导致慢识别 | 仅非标端口；命中 2 包即定型，超过 5 包放弃，与 nDPI 一致 |
| `stats` 前缀过宽 | 与 nDPI 相同；只在载荷起始处匹配，误报面可控 |
| HTTP-ES 只在响应先到时生效 | 已确认为本批边界；不引入 REST 路径启发式 |
| AMQP 1.0 协议头与 0-9-1 混淆 | 两个 8 字节常量精确匹配，互斥 |
| 新增 `Protocol` 变体导致 match 不穷尽 | 编译期暴露；`category()`/`breed()`/规则/parity/CLI 逐处补齐 |
| `DissectorState` 新增变体影响 HTTP 显式 match | 在 `http/detector.rs` 增加 `Memcached(_) => return None` |
| parity golden 与 nDPI 版本差异 | 用本地 ndpiReader 5.0 生成，映射以真实输出为准 |
| 超集能力影响既有语料 | HTTP-ES 只在响应头出现时改变协议；AMQP 1.0 只在精确常量出现时命中；既有语料不含这些特征 |
