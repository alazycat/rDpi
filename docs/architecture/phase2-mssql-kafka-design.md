# 阶段 2 第三批设计：MSSQL/TDS 与 Kafka

> 生成时间：2026-11-08
> 状态：设计已确认，待实现
> 关联文档：
> - [nDPI 纯 Rust 实现方案](ndpi-pure-rust-plan.md)（阶段 2 Wave 1B）
> - [协议/应用覆盖候选清单](protocol-coverage-plan.md)（§10.2 阶段 2）
> - [阶段 2 第二批设计：Memcached、Elasticsearch、AMQP](phase2-database-messaging-design.md)（子批次 A 先例）
> - [AGENTS.md](../../AGENTS.md)（F46 检测/元数据/parity 模式与测试基线）

---

## 1. 背景与目标

阶段 2 第二批子批次 A（F46）已完成 Memcached、Elasticsearch、AMQP。本批为子批次 B：**MSSQL/TDS 与 Kafka**，补齐企业数据库与消息管道缺口。

本轮目标：

1. 复用现有 `database` feature 承载 MSSQL/TDS，复用 `messaging` feature 承载 Kafka；
2. 新增 `Mssql`、`Kafka` 两个 `Protocol` 变体；
3. 严格对齐 nDPI 5.0 检测依据：
   - MSSQL/TDS：8 字节 TDS 报文头 + 长度/窗口/类型/状态约束（`mssql_tds.c`）；
   - Kafka：BE u32 长度前缀 + API key/version + 可打印 client_id（`kafka.c`）；
4. 提取基础元数据（TDS 头字段、Kafka 请求头字段）；
5. 加入语料 + 真实 ndpiReader 5.0 golden 差分；
6. 补齐端口回退、规则名称、parity 导出与 CLI 展示。

**nDPI 5.0 源码核对（2026-11-08，`D:\c_code\nDPI-5.0`）**：

- `src/lib/protocols/mssql_tds.c`：报文载荷 < 8 字节或 TCP 目的端口 102 时排除；TDS 头需满足 `number > 0 && type ∈ 1..=8` 或 `type ∈ 14..=18`，`status ∈ {0x00,0x01,0x02,0x04,0x08,0x09,0x10}`，`length == payload_packet_len`，`window == 0x00`；
- `src/lib/protocols/kafka.c`：载荷长度 ≥ 8；`BE u32(payload[0..4]) == payload_len - 4`；请求分支要求 `api_key < 75`、`api_version < 16`、载荷 ≥ 14、`client_id_len + 14 <= payload_len`、client_id 全部为可打印 ASCII（`ndpi_isprint`：`0x20..=0x7e`）；
- `src/lib/ndpi_main.c`：MSSQL 名称 `MsSQL-TDS`、category `DATABASE`、breed `ACCEPTABLE`、默认 TCP 端口 1433/1434；Kafka 名称 `Kafka`、category `RPC`、breed `ACCEPTABLE`、默认 TCP 端口 9092。

**真实 ndpiReader 5.0 探针（2026-11-08）**：自构造的 PreLogin / Metadata 请求 pcap 输出为：

- `"proto":"MsSQL-TDS"`、`"proto_id":"114"`、`"category":"Database"`、`"breed":"Acceptable"`、`"confidence":{"6":"DPI"}`；
- `"proto":"Kafka"`、`"proto_id":"377"`、`"category":"RPC"`、`"breed":"Acceptable"`、`"confidence":{"6":"DPI"}`；
- Kafka 在非标端口（19092）仍由 DPI 定型，说明检测本身不依赖端口；
- 合成流可能附带 nDPI 专有启发式风险 `Malicious Fingerprint`，沿用现有语料门禁的剔除策略。

---

## 2. 协议模型与 Feature

### 2.1 Protocol 变体

| 变体 | feature | 内部 category | breed | 产出位置 |
|---|---|---|---|---|
| `Mssql` | `database` | `ProtocolCategory::Database` | `ProtocolBreed::Acceptable` | MSSQL/TDS detector |
| `Kafka` | `messaging` | `ProtocolCategory::Messaging` | `ProtocolBreed::Acceptable` | Kafka detector |

两个变体均带 `#[cfg(feature = "...")]`，与 F46 的 `Memcached`/`Elasticsearch`/`Amqp` 一致。所有引用这些变体的 match 分支（`category()` / `breed()` / 规则名称 / parity 映射 / CLI / 端口回退）都必须带相同的 cfg 包裹。

### 2.2 Feature 与模块

- `Cargo.toml`：**不新增 feature**（`database`、`messaging` 均已存在）；
- `src/protocols/mssql/`：`mod.rs` + `detector.rs` + `parser.rs`；
- `src/protocols/kafka/`：`mod.rs` + `detector.rs` + `parser.rs`；
- `src/protocols/mod.rs`：模块声明 + `register_defaults` 注册。

### 2.3 Metadata

```rust
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

`Metadata` 枚举新增两个条件变体：

```rust
#[cfg(feature = "database")]
Mssql(MssqlMetadata),
#[cfg(feature = "messaging")]
Kafka(KafkaMetadata),
```

### 2.4 DissectorState

**不新增变体**。两种协议均为无状态 detector，严格遵循 nDPI 的单报文语义：

- `detect()` 直接解析当前检测载荷；
- rDpi 的双向入口把每方向 TCP 起始字节累积为 `tcp_prefix`（上限 2 KiB）后交给无状态检测，因此跨 TCP 段拆分的单个消息在前缀补齐后仍可识别（相对 nDPI 的小超集，见 §10）；
- 多个消息粘连在同一 TCP 段时不识别，与 nDPI 一致。

---

## 3. MSSQL/TDS Detector

### 3.1 TDS 报文头

TDS 头固定 8 字节（网络序）：

| 偏移 | 字段 | 类型 | 校验 |
|---:|---|---|---|
| 0 | `type` | u8 | `(packet_id > 0 && 1..=8) || 14..=18` |
| 1 | `status` | u8 | `∈ {0x00,0x01,0x02,0x04,0x08,0x09,0x10}` |
| 2..4 | `length` | BE u16 | `length as usize == payload.len()` |
| 4..6 | `channel` | BE u16 | 无约束（元数据） |
| 6 | `packet_id` | u8 | 类型 1..=8 时 > 0 |
| 7 | `window` | u8 | `== 0x00` |

### 3.2 检测逻辑

```rust
pub fn parse_mssql_tds(payload: &[u8]) -> Option<MssqlParsed> {
    if payload.len() < 8 {
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
    let type_ok = (packet_id > 0 && (1..=8).contains(&packet_type))
        || (14..=18).contains(&packet_type);
    let status_ok = matches!(status, 0x00 | 0x01 | 0x02 | 0x04 | 0x08 | 0x09 | 0x10);
    if !type_ok || !status_ok {
        return None;
    }
    Some(MssqlParsed { packet_type, status, length, channel, packet_id })
}
```

### 3.3 端口 102 排除

`detect_with_context()` 在调用解析前检查端口：

```rust
if ctx.src_port == 102 || ctx.dst_port == 102 {
    return None;
}
```

TPKT（ISO 8072 over TCP 102）头部与 TDS 头高度相似，nDPI 只排除 `dest == 102`。rDpi 双向流入口不区分客户端/服务端方向，任一端口为 102 即排除（比 nDPI 严格，避免两个方向的 TPKT 误报）。

### 3.4 首字节门

```rust
fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
    Some(&[(1, 8), (14, 18)])
}
```

合法 TDS 类型的首字节只可能落在两个区间；其他字节在 miss 热路径直接跳过本 detector。

### 3.5 检测结果

命中返回：

```rust
DetectionResult::new(Protocol::Mssql)
    .with_metadata(Metadata::Mssql(MssqlMetadata { ... }))
    .with_confidence(Confidence::Dpi)
```

---

## 4. Kafka Detector

### 4.1 请求报文布局

Kafka 请求（网络序）：

| 偏移 | 字段 | 类型 | 校验 |
|---:|---|---|---|
| 0..4 | `length` | BE u32 | `== payload.len() - 4` |
| 4..6 | `api_key` | BE u16 | `< 75` |
| 6..8 | `api_version` | BE u16 | `< 16` |
| 8..12 | `correlation_id` | BE u32 | 无约束（元数据） |
| 12..14 | `client_id_len` | BE u16 | `client_id_len + 14 <= payload.len()` |
| 14.. | `client_id` | bytes | 全部 ∈ `0x20..=0x7e` |

### 4.2 检测逻辑

```rust
pub fn parse_kafka_request(payload: &[u8]) -> Option<KafkaParsed> {
    if payload.len() < 8 {
        return None;
    }
    let declared = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if declared != payload.len() - 4 {
        return None;
    }
    let api_key = u16::from_be_bytes([payload[4], payload[5]]);
    let api_version = u16::from_be_bytes([payload[6], payload[7]]);
    if api_key >= 75 || api_version >= 16 || payload.len() < 14 {
        return None;
    }
    let client_id_len = u16::from_be_bytes([payload[12], payload[13]]) as usize;
    let end = 14usize.checked_add(client_id_len)?;
    if end > payload.len() {
        return None;
    }
    let client_id = &payload[14..end];
    if !client_id.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    let correlation_id = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    Some(KafkaParsed {
        api_key,
        api_version,
        correlation_id,
        client_id: String::from_utf8_lossy(client_id).into_owned(),
    })
}
```

说明：

- 与 nDPI 一致，只识别**请求**；响应没有 client_id 字符串段，通常不满足校验；
- `client_id_len == 0` 合法（空字符串）；`0xFFFF`（Kafka nullable string 的 null）会超出载荷约束，不识别（与 nDPI 一致）；
- 可打印性判定严格使用 `0x20..=0x7e`，对齐 `ndpi_isprint`。

### 4.3 首字节门

`first_byte_gate() = None`：长度前缀高字节没有有意义的窄区间（合法消息长度可达 2^32-1），声明宽区间没有收益。该 detector 不参与 miss 路径预筛。

### 4.4 端口

检测本身不依赖端口（与 nDPI 一致）；仅在 `PORT_MAP` 增加 9092 的**回退猜测**（DPI 失败后使用）。

---

## 5. 注册与集成

### 5.1 模块声明

`src/protocols/mod.rs`：

```rust
#[cfg(feature = "database")]
pub mod mssql;
#[cfg(feature = "messaging")]
pub mod kafka;
```

### 5.2 注册顺序与影响面

在现有 `database` 块 `redis::register` 之后、`elasticsearch::register` 之前插入：

```rust
#[cfg(feature = "database")]
mssql::register(_registry);
```

在现有 `messaging` 块 `amqp::register` 之后插入：

```rust
#[cfg(feature = "messaging")]
kafka::register(_registry);
```

**影响面复述（AGENTS.md 禁止事项 #1）**：只新增两个 detector，未改变任何既有 detector 的相对顺序。

- MSSQL 首字节门为 `{1..=8, 14..=18}`，与 Redis（首字节文本）、Elasticsearch（`'E'`）、Memcached（文本）、MySQL/PostgreSQL/MongoDB 的特征字节不重叠；注册在 `redis` 之后不影响这些 detector 的命中；
- Kafka 无首字节门，注册在 `amqp` 之后；AMQP 的严格帧头/协议头校验先执行，Kafka 的长度前缀校验后执行，两者互斥（AMQP 首字节只允许 `0x00..=0x03` 或 `'A'`，Kafka 命中要求长度前缀与载荷长度精确相等，合成语料与真实流量中无交集）；
- Kafka 对任意二进制流都有一次解析成本，但校验在长度前缀不等时立即返回，热路径成本为一次 u32 读取与比较。

### 5.3 端口回退

`src/core/guess/port.rs` 的 `PORT_MAP` 增加（带 cfg）：

```rust
#[cfg(feature = "database")]
(1433u16, &[Protocol::Mssql]),
#[cfg(feature = "database")]
(1434u16, &[Protocol::Mssql]),
#[cfg(feature = "messaging")]
(9092u16, &[Protocol::Kafka]),
```

对齐 nDPI 默认端口；置信度为 `MatchByPort`（DPI 失败后才使用）。nDPI 5.0 的默认端口表把 1433/1434 都列在 MSSQL 的 TCP 端口集合中；rDpi 的端口回退不区分传输层，该映射只表达“该端口通常属于 MSSQL”，与 nDPI 默认端口表一致。MSSQL detector 本身仅处理 TCP 载荷。

### 5.4 规则名称

`src/rule/parser.rs`：

```rust
#[cfg(feature = "database")]
"mssql" | "mssql_tds" => Protocol::Mssql,
#[cfg(feature = "messaging")]
"kafka" => Protocol::Kafka,
```

### 5.5 CLI

`src/bin/rdpi.rs` 的元数据显示新增：

- `Metadata::Mssql(m)` → `type={} status={}`（可选追加 `length`/`channel`）；
- `Metadata::Kafka(k)` → `api_key={} version={} client_id={}`。

各分支带对应 `#[cfg(feature = "...")]`。

---

## 6. Parity 导出

`src/parity.rs`：

| rDpi 协议 | protocol_name（master） | app | category | breed |
|---|---|---|---|---|
| `Mssql` | `MsSQL-TDS` | — | `Database` | `Acceptable` |
| `Kafka` | `Kafka`（Debug 默认即一致） | — | `RPC` | `Acceptable` |

- `protocol_name` 只新增 `Protocol::Mssql => "MsSQL-TDS"`；Kafka 的 Debug 输出已与 nDPI 一致；
- `ndpi_compat_classification` 新增：`Mssql → ("Database","Acceptable")`、`Kafka → ("RPC","Acceptable")`；
- 两者均无 app 层协议，`app_protocol = None`；
- 不新增风险映射。

nDPI 协议 ID 供参考：MSSQL_TDS 114、APACHE_KAFKA 377。名称/分类已用真实 ndpiReader 5.0 输出验证（§1）。

---

## 7. 语料与 golden

扩展 `tests/parity/gen_corpus.py`：

1. `mssql_tds_prelogin.pcap`：TCP 1433 三次握手后，客户端发送 TDS PreLogin（`type=0x12, status=0x01, length=报文长度, channel=0, packet_id=1, window=0`），服务端发送 Reply（`type=0x04, status=0x01, packet_id=1, window=0`）。nDPI 首包即 DPI；
2. `kafka_metadata_request.pcap`：TCP 9092 三次握手后，客户端发送 Metadata 请求（`api_key=3, api_version=1, correlation_id=1, client_id="rdpi-test"`）。nDPI 首包即 DPI。

用 `tests/parity/gen_golden.sh`（`/mnt/d/c_code/nDPI-5.0/build/example/ndpiReader`）生成 golden；若真实输出与 §6 映射不一致，先修正映射再提交。

**不进入 parity 语料**：

- 跨段拆分变体：nDPI 单报文语义在首段即排除 detector，golden 会报 `TCP`，与 rDpi 前缀补齐后的识别结果不一致；跨段能力由库内单测覆盖（§10）；
- 非标端口变体：`proto_by_ip`/`Known Proto on Non Std Port` 会引入额外风险，差分噪声大于收益；非标端口能力由单测覆盖。

---

## 8. 文件改动清单

| 文件 | 改动 |
|---|---|
| `src/core/types.rs` | 2 个 `Protocol` 变体；2 个 metadata 类型；`Metadata` 2 个条件变体；category/breed 分支 |
| `src/protocols/mssql/` | 新建：`mod.rs`、`detector.rs`、`parser.rs` |
| `src/protocols/kafka/` | 新建：`mod.rs`、`detector.rs`、`parser.rs` |
| `src/protocols/mod.rs` | 模块声明 + 注册 |
| `src/core/guess/port.rs` | 1433/1434/9092 端口回退 |
| `src/rule/parser.rs` | 3 个协议名称映射 |
| `src/parity.rs` | protocol_name + category/breed 映射 |
| `src/bin/rdpi.rs` | 元数据显示 |
| `tests/parity/gen_corpus.py` | 2 个语料 builder + `CORPUS` 条目 |
| `tests/parity/gen_golden.sh` | 2 个 golden 生成项 |
| `tests/parity/corpus/`、`tests/parity/golden/` | 新语料与 ndpiReader 5.0 golden |
| `tests/parity_export.rs` | protocol_name / classification 单测 |
| `tests/test_rule.rs` | 规则名映射单测 |
| `tests/test_types.rs` | category/breed 单测（如现有结构需要） |
| `AGENTS.md`、`docs/architecture/*.md` | F49 记录与状态更新 |

`Cargo.toml` 不变。

---

## 9. 测试与验收

### 9.1 单元测试

**MSSQL**

- 合法类型：1（SQL Batch）、2（RPC）、4（Reply）、7、14、18（PreLogin）逐一命中；
- 类型 1..=8 且 `packet_id == 0` → `None`；类型 9..=13 → `None`；
- 非法 status（如 `0x03`、`0x20`）→ `None`；
- `length` 大于/小于载荷 → `None`；
- `window != 0` → `None`；载荷 < 8 字节 → `None`；
- `detect_with_context`：src/dst 任一端 102 → `None`；1433 端口正常命中；
- 负样本：HTTP 请求、SMB NBSS 头、随机二进制；
- `first_byte_gate` 覆盖全部合法样本首字节，且拒绝 `0x09`/`0x13`/ASCII。

**Kafka**

- 合法 Metadata/Produce 请求（不同 api_key/version/client_id 长度，含空 client_id）；
- 长度前缀与载荷不符（多 1/少 1）→ `None`；
- `api_key >= 75`、`api_version >= 16` → `None`；
- `client_id_len` 超出载荷 → `None`；
- client_id 含 `0x1f`/`0x7f`/非 ASCII → `None`；
- 载荷 8..13 字节 → `None`；
- 负样本：HTTP 请求、MSSQL TDS 头、随机二进制；
- 元数据字段（api_key/api_version/correlation_id/client_id）正确。

**回归**

- 规则名称映射（`mssql`/`mssql_tds`/`kafka`）；
- parity `protocol_name`/`ndpi_compat_classification`；
- 端口回退（1433/1434/9092）；
- `Protocol::category()` / `breed()` 在 default / `database` / `messaging` / all-features 下均可编译。

**跨段超集（库内，不进入 parity）**

- 将 TDS PreLogin / Kafka 请求从中间拆成两个 TCP 段，经 `Detector::process_packet` 处理后仍识别为对应协议。

### 9.2 语料 + golden 门禁

```bash
python -I tests/parity/gen_corpus.py
# WSL：
bash tests/parity/gen_golden.sh
```

验收：

- 新增 2 个语料在 master/app/category/breed/confidence/risk gate 上一致；
- 现有 59 个语料与全部存量测试无回归（新增后共 61 个）。

### 9.3 全量门禁

```bash
cargo test
cargo test --features "database messaging"
cargo test --all-features
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -D warnings
```

---

## 10. 已知边界

**MSSQL**

- 单报文语义：`length` 必须精确等于当前检测载荷长度；多个 TDS 报文粘连在同一 TCP 段时不识别（与 nDPI 一致）；跨段拆分在 rDpi 前缀补齐后可识别（相对 nDPI 的超集）；
- 端口 102 双向排除，比 nDPI 的 `dest == 102` 更严格；
- 不解析 TDS 消息体（登录、SQL 批处理、RPC 参数），只产出头部元数据；
- 加密/TLS 包装的 TDS 不识别；
- 类型 14..=18 不要求 `packet_id > 0`（与 nDPI 的布尔表达式完全一致）。

**Kafka**

- 只识别请求；响应、SASL 握手前的原始字节、TLS（9093）流量不识别；
- null client_id（长度 0xFFFF）不识别（与 nDPI 一致）；
- `api_key >= 75` 或 `api_version >= 16` 的新版 API 不识别（与 nDPI 5.0 的固定上限一致，后续按需放宽）；
- 多消息粘连/跨段拆分同 MSSQL 的单报文语义；
- 不解析请求体（topic、partition、record batch）。

**Parity**

- 跨段拆分与非标端口变体不进入语料（§7）；
- 合成流可能触发 nDPI 的 `Malicious Fingerprint` 风险，沿用现有门禁剔除策略。

---

## 11. 实施顺序

1. `src/core/types.rs`：两个 `Protocol` 变体 + metadata 类型 + `Metadata` 变体 + category/breed（先让新变体可编译）；
2. MSSQL parser + detector + 注册 + 单测；
3. Kafka parser + detector + 注册 + 单测；
4. 端口回退 + 规则名称 + parity 映射 + CLI + 对应单测；
5. 语料生成 + WSL golden + 差分门禁；
6. 文档回写（AGENTS.md F49、modules.md、risks.md、路线图、覆盖清单）、全量门禁、提交。

---

## 12. 风险与注意事项

| 风险 | 应对 |
|---|---|
| TPKT（端口 102）与 TDS 头混淆 | `detect_with_context` 任一端 102 排除；首字节门再收窄 |
| MSSQL 长度字段跨段时失配 | 与 nDPI 一致；前缀补齐后可恢复，单测覆盖 |
| Kafka 长度前缀校验对任意二进制流产生一次解析成本 | 首步只做 u32 比较，成本极低；无分配 |
| Kafka 旧版 API 上限（75/16）误拒新流量 | 与 nDPI 5.0 对齐；边界登记，后续按需提升 |
| `client_id` 字符串分配 | 仅在命中定型时分配一次；符合热路径零分配约束 |
| 新 `Protocol` 变体导致 match 不穷尽 | 编译期暴露；category/breed/规则/parity/CLI/端口表逐处补齐 |
| parity golden 与 nDPI 版本差异 | 用本地 ndpiReader 5.0 生成；名称/分类已用探针验证 |
| 注册顺序影响既有 detector | 仅追加、不改变既有相对顺序；影响面已在 §5.2 复述 |
| 1434 端口回退把 UDP 流量猜成 MSSQL | 仅 DPI 失败后的 `MatchByPort`，与 nDPI 默认端口表一致；不参与 DPI 定型 |
