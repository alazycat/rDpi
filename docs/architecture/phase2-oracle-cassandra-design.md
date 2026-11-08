# 阶段 2 第四批设计：Oracle 与 Cassandra

> 生成时间：2026-11-08
> 状态：设计已确认，待实现
> 关联文档：
> - [nDPI 纯 Rust 实现方案](ndpi-pure-rust-plan.md)（阶段 2 Wave 1B）
> - [协议/应用覆盖候选清单](protocol-coverage-plan.md)（§4 P0）
> - [阶段 2 第三批设计：MSSQL/TDS 与 Kafka](phase2-mssql-kafka-design.md)（无状态 detector 先例）
> - [AGENTS.md](../../AGENTS.md)（F49 检测/元数据/parity 模式与测试基线）

---

## 1. 背景与目标

阶段 2 第三批（F49）已完成 MSSQL/TDS 与 Kafka。本批补齐 P0 清单中剩余的两个数据库协议：**Oracle（TNS）与 Cassandra（CQL）**，复用现有 `database` feature。

本轮目标：

1. 新增 `Oracle`、`Cassandra` 两个 `Protocol` 变体，复用 `database` feature；
2. 对齐 nDPI 5.0 的核心检测依据：
   - Oracle：TCP 1521 上的 TNS Connect 8 字节头（`oracle.c`）；
   - Cassandra：19 字节 internode magic（`cassandra.c`）；
3. 在 nDPI 实际行为之外提供已确认的超集能力：
   - Cassandra 严格解析 CQL STARTUP 帧（版本/opcode/长度/string map/CQL_VERSION），使标准 STARTUP 可直接 Dpi 定型；
4. 提取基础元数据（Oracle 包头字段、Cassandra 来源/版本/stream/CQL_VERSION）；
5. 加入语料 + 真实 ndpiReader 5.0 golden 差分；
6. 补齐端口回退、规则名称、parity 导出与 CLI 展示。

**nDPI 5.0 源码核对（2026-11-08，`D:\c_code\nDPI-5.0`）**：

- `src/lib/protocols/oracle.c`：仅当 `dport == 1521 || sport == 1521` 时检测；载荷 ≥ 8 字节；`BE u16(payload[0..2]) == payload_packet_len`；`payload[2] == 0 && payload[3] == 0`（包校验和）；`payload[4] == 0x01`（Connect）；`payload[5] == 0`（保留）；`payload[6] == 0 && payload[7] == 0`（头校验和）。注释明确说明“the logic is quite weak”，因此只在默认端口检测。
- `src/lib/protocols/cassandra.c`：
  - 19 字节载荷且 `BE u32(payload[0..4]) == 0xCA552DFA` → Cassandra（internode 通信），不依赖端口；
  - 否则若载荷 < 9 字节或 `packet_counter >= 8` 或首字节校验失败 → 放弃；
  - 首字节校验调用 `ndpi_validate_cassandra_response` / `ndpi_validate_cassandra_request`，两函数返回 `1`/`-1`，取逻辑非后恒为 `0`，**该分支在 nDPI 5.0 中实际不生效**（首字节不被校验）；
  - 单方向报文计数 > 2 → 放弃；
  - `payload_packet_len > 60` 且 `payload[len-20..len-9] == "CQL_VERSION"` → Cassandra（弱启发式）。
- `src/include/ndpi_protocol_ids.h`：Oracle ID 167；Cassandra ID 264。
- `src/lib/ndpi_main.c`：Oracle 名称 `Oracle`、category `DATABASE`、breed `ACCEPTABLE`、TCP 端口 1521；Cassandra 名称 `Cassandra`、category `DATABASE`、breed `ACCEPTABLE`、TCP 端口 7000/9042。

**真实 ndpiReader 5.0 探针（2026-11-08，WSL 本地构建 `nDPI 5.0.0`）**：

| 探针 | nDPI 5.0 输出 |
|---|---|
| Oracle Connect @1521 | `Oracle` / DPI / Database-Acceptable |
| Oracle Connect @1522 | `Unknown` / Unspecified-Unrated |
| Cassandra internode magic @7000 / 9042 / 9999 | `Cassandra` / DPI（不限端口） |
| 标准 31 字节 CQL STARTUP @9042 | `Cassandra` / **Match by port**（nDPI 的 >60 字节门槛不满足） |
| 80 字节载荷、`CQL_VERSION` 位于 `len-20` @9042 | `Cassandra` / DPI（弱启发式） |

结论：Oracle 必须端口门控；Cassandra 的 internode magic 可精确对齐，CQL 业务流在 nDPI 中只能靠端口回退或弱启发式，rDpi 的严格 STARTUP 解析是明确的超集能力。

---

## 2. 协议模型与 Feature

### 2.1 Protocol 变体

| 变体 | feature | 内部 category | breed | 产出位置 |
|---|---|---|---|---|
| `Oracle` | `database` | `ProtocolCategory::Database` | `ProtocolBreed::Acceptable` | Oracle detector |
| `Cassandra` | `database` | `ProtocolCategory::Database` | `ProtocolBreed::Acceptable` | Cassandra detector |

两个变体均带 `#[cfg(feature = "database")]`，与 F46/F49 的变体一致。所有引用这些变体的 match 分支（`category()` / `breed()` / 规则名称 / parity 映射 / CLI / 端口回退）都必须带相同的 cfg 包裹。

### 2.2 Feature 与模块

- `Cargo.toml`：**不新增 feature**（`database` 已存在）；
- `src/protocols/oracle/`：`mod.rs` + `detector.rs` + `parser.rs`；
- `src/protocols/cassandra/`：`mod.rs` + `detector.rs` + `parser.rs`；
- `src/protocols/mod.rs`：模块声明 + `register_defaults` 注册。

### 2.3 Metadata

```rust
#[cfg(feature = "database")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OracleMetadata {
    /// TNS 包长度（命中时等于载荷长度）
    pub packet_length: u16,
    /// TNS 包类型（当前只接受 1 = Connect）
    pub packet_type: u8,
}

/// Cassandra 识别来源
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

`Metadata` 枚举新增两个条件变体：

```rust
#[cfg(feature = "database")]
Oracle(OracleMetadata),
#[cfg(feature = "database")]
Cassandra(CassandraMetadata),
```

### 2.4 DissectorState

**不新增变体**。两种协议均为无状态 detector：

- Oracle 严格校验单报文 8 字节头；
- Cassandra 的 internode magic 与 STARTUP 帧均为单消息语义，严格解析不需要跨包状态；
- rDpi 的双向入口把每方向 TCP 起始字节累积为 `tcp_prefix`（上限 2 KiB）后交给无状态检测，因此跨 TCP 段拆分的单消息在前缀补齐后仍可识别（相对 nDPI 的小超集，见 §10）。

---

## 3. Oracle Detector

### 3.1 TNS Connect 报文头

| 偏移 | 字段 | 类型 | 校验 |
|---:|---|---|---|
| 0..2 | `packet_length` | BE u16 | `as usize == payload.len()` |
| 2..4 | `packet_checksum` | u16 | `== 0x0000` |
| 4 | `packet_type` | u8 | `== 0x01`（Connect） |
| 5 | `reserved` | u8 | `== 0x00` |
| 6..8 | `header_checksum` | u16 | `== 0x0000` |

### 3.2 检测逻辑

```rust
pub fn parse_oracle_connect(payload: &[u8]) -> Option<OracleParsed> {
    if payload.len() < 8 {
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

### 3.3 端口门控

nDPI 只在 1521 端口检测。`detect_with_context()` 要求任一端端口为 1521：

```rust
fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
    if ctx.src_port != ORACLE_PORT && ctx.dst_port != ORACLE_PORT {
        return None;
    }
    self.detect(payload)
}
```

`detect()` 保留仅载荷校验，供库内单测与无端口上下文场景使用；rDpi 的主检测路径（`detect_with_ports` / `process_packet`）始终携带端口，因此生产路径与 nDPI 的端口门控一致。

### 3.4 首字节门

`first_byte_gate() = None`：首字节是包长度高字节，合法载荷长度可达 64 KiB，没有有意义的窄区间；该 detector 不参与 miss 路径预筛。

### 3.5 检测结果

```rust
DetectionResult::new(Protocol::Oracle)
    .with_metadata(Metadata::Oracle(OracleMetadata { packet_length, packet_type }))
    .with_confidence(Confidence::Dpi)
```

---

## 4. Cassandra Detector

### 4.1 Internode magic

```rust
pub const CASSANDRA_INTERNODE_MAGIC: u32 = 0xCA55_2DFA;
pub const CASSANDRA_INTERNODE_LEN: usize = 19;
```

命中条件与 nDPI 完全一致：`payload.len() == 19 && BE u32(payload[0..4]) == 0xCA55_2DFA`。不要求端口。

### 4.2 CQL STARTUP 帧

CQL 二进制协议请求头固定 9 字节（网络序）：

| 偏移 | 字段 | 类型 | 校验 |
|---:|---|---|---|
| 0 | `version` | u8 | `0x02..=0x05`（请求方向；STARTUP 只发请求） |
| 1 | `flags` | u8 | `flags & 0xE0 == 0`（仅低 5 位有定义） |
| 2..4 | `stream_id` | BE u16 | 无约束（元数据） |
| 4 | `opcode` | u8 | `== 0x01`（STARTUP） |
| 5..9 | `length` | BE u32 | `as usize == payload.len() - 9` |
| 9.. | `body` | string map | 严格解析且必须消费完 body |

string map 布局：`BE u16` 条目数 `n`（`1..=64`），随后 `n` 组 `BE u16 key_len + key + BE u16 value_len + value`。键必须是可打印 ASCII（`0x20..=0x7e`，CQL 选项名均为 ASCII）；值只做边界校验，但 `CQL_VERSION` 的值必须是可打印 ASCII。必须包含键 `CQL_VERSION`，其值写入 `cql_version`。除 `CQL_VERSION` 外的自定义选项值允许任意字节，避免误伤合法客户端。

```rust
pub struct CassandraStartupParsed {
    pub version: u8,
    pub stream_id: u16,
    pub opcode: u8,
    pub cql_version: String,
}

pub fn parse_cassandra_startup(payload: &[u8]) -> Option<CassandraStartupParsed> { /* 严格解析 */ }
```

### 4.3 检测逻辑

`detect()` 先尝试 internode magic，再尝试 STARTUP：

```rust
pub fn parse_cassandra(payload: &[u8]) -> Option<CassandraParsed> {
    if payload.len() == CASSANDRA_INTERNODE_LEN
        && u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
            == CASSANDRA_INTERNODE_MAGIC
    {
        return Some(CassandraParsed::Internode);
    }
    parse_cassandra_startup(payload).map(CassandraParsed::Cql)
}
```

### 4.4 首字节门

```rust
fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
    Some(&[(0x02, 0x05), (0xCA, 0xCA)])
}
```

`0x02..=0x05` 覆盖 CQL v2–v5 请求版本；`0xCA` 覆盖 internode magic。两者之外的 payload 在 miss 热路径直接跳过本 detector。

### 4.5 与 nDPI 5.0 的故意差异

- nDPI 的 “载荷 > 60 字节且 `CQL_VERSION` 位于 `len-20`” 弱启发式**不实现**；
- nDPI 的 `packet_counter < 8`、单方向计数 > 2 放弃逻辑**不实现**（严格解析已消除误报；rDpi 对 STARTUP 的识别面更宽）；
- 标准 STARTUP 在 nDPI 中只能靠 9042 端口回退（Match by port），rDpi 产出 Dpi；parity 门禁按现有规则允许该升级；
- 弱启发式命中的合成流量（合法 STARTUP 之外的 `CQL_VERSION` 尾部）rDpi 不识别，不进入 parity 语料。

---

## 5. 注册与集成

### 5.1 模块声明

`src/protocols/mod.rs`：

```rust
#[cfg(feature = "database")]
pub mod cassandra;
#[cfg(feature = "database")]
pub mod oracle;
```

### 5.2 注册顺序与影响面

Oracle 在现有 `database` 块 `mssql::register` 之后、`elasticsearch::register` 之前插入：

```rust
#[cfg(feature = "database")]
oracle::register(_registry);
```

Cassandra 必须注册在 `register_defaults` 的最前面、**QUIC 之前**：

```rust
#[cfg(feature = "database")]
cassandra::register(_registry);
#[cfg(feature = "quic")]
quic::register(_registry);
```

**影响面复述（AGENTS.md 禁止事项 #1）**：

- Cassandra internode magic 首字节 `0xCA` 落在 QUIC 长包头门 `0x80..=0xFF` 内，且版本字段 `0x552DFA00` 会被 QUIC 的 `detect_other_long_header` 当作未知版本长包头；若 Cassandra 注册在 QUIC 之后，真实 internode 流量会被误判为 `Quic`（语料差分已复现）；
- Cassandra 门仅 `{0x02..=0x05, 0xCA}`：真实 QUIC 短包头首字节为 `0x40..=0x7F`（固定位），长包头为 `0xC0..=0xFF`，其中只有 `0xCA` 可能落入 Cassandra 门；`0xCA` 进一步要求 19 字节精确 internode magic（QUIC 中不可能出现）或严格 CQL STARTUP（版本 `0x02..=0x05`），因此不会抢占真实 QUIC；
- 该调整把 Cassandra 从 database 块移到最前，既有 detector 之间的相对顺序不变，仅 Cassandra 与 QUIC 的相对顺序改变；
- Oracle 首字节门为 `None`，但 `detect_with_context` 要求 1521 端口；管线中 `detect_with_ports` 先经过既有 MySQL/PostgreSQL/Redis/MSSQL 等更严格的包头校验，Oracle 的弱头在这些 detector 之后执行，端口约束进一步收窄命中面；
- Cassandra 首字节门与 MongoDB（长度前缀）、MySQL（3 字节长度）、PostgreSQL（u32 长度）、MSSQL（TDS 类型 1..=8/14..=18）等既有 detector 的特征字节不构成有效冲突；严格长度相等 + STARTUP 结构校验保证互斥。

### 5.3 端口回退

`src/core/guess/port.rs` 的 `PORT_MAP` 增加（带 cfg）：

```rust
#[cfg(feature = "database")]
(1521u16, &[Protocol::Oracle]),
#[cfg(feature = "database")]
(7000u16, &[Protocol::Cassandra]),
#[cfg(feature = "database")]
(9042u16, &[Protocol::Cassandra]),
```

对齐 nDPI 默认端口；置信度为 `MatchByPort`（DPI 失败后才使用）。

### 5.4 规则名称

`src/rule/parser.rs`：

```rust
#[cfg(feature = "database")]
"oracle" => Protocol::Oracle,
#[cfg(feature = "database")]
"cassandra" => Protocol::Cassandra,
```

### 5.5 CLI

`src/bin/rdpi.rs` 的元数据显示新增：

- `Metadata::Oracle(o)` → `length={} type={}`；
- `Metadata::Cassandra(c)`：
  - Internode → `source=internode`；
  - Cql → `source=cql version=0x{:02X} stream={} cql_version={}`。

各分支带 `#[cfg(feature = "database")]`。

---

## 6. Parity 导出

`src/parity.rs`：

| rDpi 协议 | protocol_name（master） | app | category | breed |
|---|---|---|---|---|
| `Oracle` | `Oracle`（Debug 默认即一致） | — | `Database` | `Acceptable` |
| `Cassandra` | `Cassandra`（Debug 默认即一致） | — | `Database` | `Acceptable` |

- `protocol_name` 无需新增覆盖；
- `ndpi_compat_classification` 显式新增：`Oracle | Cassandra → ("Database","Acceptable")`（内部 category/breed 已一致，显式条目用于防回归）；
- 两者均无 app 层协议，`app_protocol = None`；
- 不新增风险映射。

nDPI 协议 ID 供参考：Oracle 167、Cassandra 264。名称/分类已用真实 ndpiReader 5.0 输出验证（§1）。

---

## 7. 语料与 golden

扩展 `tests/parity/gen_corpus.py`：

1. `oracle_connect.pcap`：TCP 1521 三次握手后，客户端发送 TNS Connect（`length=8, checksum=0, type=1, reserved=0, header_checksum=0`，载荷 `00 08 00 00 01 00 00 00`）；服务端发送 Accept（type=2）回复。nDPI 首包即 DPI；
2. `cassandra_internode.pcap`：TCP 7000 三次握手后，客户端发送 19 字节 internode magic（`CA 55 2D FA` + 15 字节）。nDPI 首包即 DPI；
3. `cassandra_startup.pcap`：TCP 9042 三次握手后，客户端发送标准 CQL v4 STARTUP（`version=0x04, flags=0, stream=1, opcode=0x01, body="CQL_VERSION" -> "3.0.0"`，共 31 字节）。nDPI golden 为 `Match by port`，rDpi 为 Dpi，差分门禁按既有规则放行。

用 `tests/parity/gen_golden.sh`（`/mnt/d/c_code/nDPI-5.0/build/example/ndpiReader`）生成 golden；若真实输出与 §6 映射不一致，先修正映射再提交。

**不进入 parity 语料**：

- Cassandra 弱启发式变量（`CQL_VERSION` 位于 `len-20`、载荷 > 60 且无合法 STARTUP 结构）：nDPI 报 Cassandra/Dpi，rDpi 不识别，必然失败；
- 非标端口变体：Oracle @1522（nDPI 报 Unknown，rDpi 因端口门控同样 Unknown，可以入语料但没有增量价值）；Cassandra internode 非标端口已由 @7000 覆盖端口无关性；
- 跨段拆分变体：nDPI 单报文语义在首段即可能排除，golden 与 rDpi 前缀补齐后的识别结果不一致；跨段能力由库内单测覆盖（§10）。

---

## 8. 文件改动清单

| 文件 | 改动 |
|---|---|
| `src/core/types.rs` | 2 个 `Protocol` 变体；2 个 metadata 类型；`CassandraSource`；`Metadata` 2 个条件变体；category/breed 分支 |
| `src/protocols/oracle/` | 新建：`mod.rs`、`detector.rs`、`parser.rs` |
| `src/protocols/cassandra/` | 新建：`mod.rs`、`detector.rs`、`parser.rs` |
| `src/protocols/mod.rs` | 模块声明 + 注册 |
| `src/core/guess/port.rs` | 1521/7000/9042 端口回退 + 单测 |
| `src/rule/parser.rs` | 2 个协议名称映射 + 单测 |
| `src/parity.rs` | category/breed 映射 + 单测 |
| `src/bin/rdpi.rs` | 元数据显示 |
| `tests/test_integration.rs` | database detector 计数 7 → 9 |
| `tests/test_oracle_cassandra.rs` | 新建跨段/入口集成测试 |
| `tests/parity/gen_corpus.py` | 3 个语料 builder + `CORPUS` 条目 |
| `tests/parity/gen_golden.sh` | 3 个 golden 生成项 |
| `tests/parity/corpus/`、`tests/parity/golden/` | 新语料与 ndpiReader 5.0 golden |
| `AGENTS.md`、`docs/architecture/*.md` | F50 记录与状态更新 |

`Cargo.toml` 不变。

---

## 9. 测试与验收

### 9.1 单元测试

**Oracle**

- 8 字节 Connect 头命中；带 body 的 Connect（长度 > 8，长度字段一致）命中；
- 载荷 < 8 → `None`；长度字段大于/小于载荷 → `None`；
- `packet_checksum` 非零、`packet_type != 1`、`reserved != 0`、`header_checksum` 非零 → `None`；
- `detect_with_context`：任一端 1521 → 命中；1522 → `None`；
- 负样本：HTTP 请求、TDS 头、随机二进制；
- `first_byte_gate` 为 `None`。

**Cassandra**

- 19 字节 internode magic 命中（来源 Internode，版本/stream 等为 None）；
- 长度 18/20、magic 错误 → `None`；
- CQL v2/v3/v4/v5 STARTUP（单/多 string map 条目，CQL_VERSION 值不同）命中，元数据字段正确；
- 缺 `CQL_VERSION`、map 截断、条目数 0 或 > 64、key 非可打印 ASCII、`CQL_VERSION` 值非可打印 ASCII → `None`；
- 版本 `0x01`/`0x80`/`0x83`/`0x06` → `None`；opcode 非 `0x01` → `None`；
- 长度字段不等于 `payload.len() - 9`（含多帧粘连）→ `None`；
- 负样本：HTTP 请求、MSSQL TDS 头、Kafka 请求、随机二进制；
- `first_byte_gate` 覆盖 `0x02..=0x05` 与 `0xCA`，拒绝其他字节。

**回归**

- 规则名称映射（`oracle`/`cassandra`）；
- parity `protocol_name` / `ndpi_compat_classification`；
- 端口回退（1521/7000/9042）；
- `Protocol::category()` / `breed()` 在 default / `database` / all-features 下均可编译；
- detector 计数（database +2）。

**跨段超集（库内，不进入 parity）**

- 将 Oracle Connect / Cassandra internode magic / CQL STARTUP 从中间拆成两个 TCP 段，经 `Detector::process_packet` 处理后仍识别为对应协议。

### 9.2 语料 + golden 门禁

```bash
python -I tests/parity/gen_corpus.py
# WSL：
bash tests/parity/gen_golden.sh
```

验收：

- 新增 3 个语料在 master/category/breed/confidence/risk gate 上一致（Cassandra STARTUP 的 Match by port → Dpi 升级放行）；
- 现有语料与全部存量测试无回归。

### 9.3 全量门禁

```bash
cargo test
cargo test --features "database"
cargo test --all-features
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -D warnings
```

---

## 10. 已知边界

**Oracle**

- 仅识别 TNS Connect（type=1）；Accept/Refuse、Data、Redirect 等报文不识别（与 nDPI 一致）；
- 仅在任一端端口为 1521 时识别；非标端口不识别（端口回退也只覆盖 1521）；
- 不解析 Connect 体内的 TNS 版本、SDU、服务名等字段；
- TLS 包装的 TNS（TCPS）不识别；
- 跨 TCP 段拆分的 8 字节头在前缀补齐后可识别（相对 nDPI 的超集）；
- 多个 TNS 报文粘连在同一 TCP 段时不识别（长度字段失配，与 nDPI 一致）。

**Cassandra**

- 只识别 internode magic 与 STARTUP 请求；OPTIONS/QUERY 等其他请求、服务端响应、mid-stream 抓包不识别；
- STARTUP 必须恰好是方向起始的单个完整帧；多帧粘连不识别（长度失配）；
- 跨 TCP 段拆分的 STARTUP 在前缀补齐后可识别（相对 nDPI 的超集）；但若首段前缀先被低特异性 detector（如 DHCPv6：`0x04` + 长度 >= 10）定型，流会被永久定型，无法再升级为 Cassandra——这是既有逐包 pipeline 的通用限制，不由本 detector 控制；库内跨段测试选择 9 字节 CQL 头边界以避开该冲突；
- 不解析 STARTUP 之外的 CQL 消息体；
- 不实现 nDPI 的弱启发式（`CQL_VERSION` 尾部位置），该类流量 rDpi 不识别；
- 不实现 nDPI 的 `packet_counter` / 方向计数放弃阈值（严格解析已消除误报）。

**Parity**

- Cassandra 弱启发式变量不进入语料；
- 标准 STARTUP 语料使用 9042 端口，nDPI golden 为 Match by port，按既有规则允许 rDpi Dpi 升级；
- 合成流可能触发 nDPI 的 `Malicious Fingerprint` 风险，沿用现有门禁剔除策略。

---

## 11. 实施顺序

1. `src/core/types.rs`：两个 `Protocol` 变体 + metadata 类型 + `Metadata` 变体 + category/breed（先让新变体可编译）；
2. Oracle parser + detector + 注册 + 单测；
3. Cassandra parser + detector + 注册 + 单测；
4. 端口回退 + 规则名称 + parity 映射 + CLI + detector 计数 + 对应单测；
5. 语料生成 + WSL golden + 差分门禁；
6. 文档回写（AGENTS.md F50、modules.md、risks.md、路线图、覆盖清单）、全量门禁、提交。

---

## 12. 风险与注意事项

| 风险 | 应对 |
|---|---|
| Oracle 签名弱，任意流量误报 | `detect_with_context` 强制 1521 端口；要求长度精确相等 + 三处校验和为 0；注册在既有数据库 detector 之后 |
| Oracle 直连 `detect()` 无端口门控 | 主检测路径始终使用 `detect_with_ports`；文档标注 `detect()` 为弱校验入口 |
| Cassandra 首字节门与既有协议冲突 | 门仅 `0x02..=0x05` 与 `0xCA`；STARTUP 结构校验（版本/opcode/长度/string map）保证互斥 |
| CQL STARTUP 解析分配 `String` | 仅在命中定型时分配一次；符合热路径零分配约束 |
| 长度字段失配导致跨段/粘连漏报 | 与 nDPI 单报文语义一致；前缀补齐后可恢复，单测覆盖 |
| 与 nDPI 弱启发式不一致 | 明确登记为故意超集/差异；语料不包含该变量 |
| 新 `Protocol` 变体导致 match 不穷尽 | 编译期暴露；category/breed/规则/parity/CLI/端口表逐处补齐 |
| 注册顺序影响既有 detector | Cassandra 前置到 QUIC 之前（internode magic 与 QUIC 长包头冲突）；其余相对顺序不变，影响面已在 §5.2 复述 |
| 端口回退把 7000/9042/1521 的非目标流量猜成新协议 | 仅 DPI 失败后的 `MatchByPort`，与 nDPI 默认端口表一致；不参与 DPI 定型 |
