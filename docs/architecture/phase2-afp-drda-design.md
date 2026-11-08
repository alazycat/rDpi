# 阶段 2 第五批设计：AFP 与 DRDA

> 生成时间：2026-11-08
> 状态：设计已确认，待实现
> 关联文档：
> - [nDPI 纯 Rust 实现方案](ndpi-pure-rust-plan.md)（阶段 2 Wave 1B 收尾）
> - [协议/应用覆盖候选清单](protocol-coverage-plan.md)（§4 P0/P1）
> - [阶段 2 第四批设计：Oracle 与 Cassandra](phase2-oracle-cassandra-design.md)（无状态 detector 先例）
> - [AGENTS.md](../../AGENTS.md)（F50 检测/元数据/parity 模式与测试基线）

---

## 1. 背景与目标

阶段 2 第四批（F50）已完成 Oracle 与 Cassandra。本批收尾 Wave 1B 的文件共享缺口 **AFP**，并补齐数据库缺口 **DRDA**（IBM DB2 分布式关系数据库架构）。

本轮目标：

1. 复用现有 `storage` feature 承载 AFP，复用 `database` feature 承载 DRDA；
2. 新增 `Afp`、`Drda` 两个 `Protocol` 变体；
3. 严格对齐 nDPI 5.0 检测依据：
   - AFP：16 字节 DSI 头（`afp.c`）；
   - DRDA：10 字节 DSS/DDM 头 + 多消息串联校验（`drda.c`）；
4. 提取基础元数据（AFP 命令/请求号/长度、DRDA 消息数/首消息长度）；
5. 加入语料 + 真实 ndpiReader 5.0 golden 差分；
6. 补齐端口回退、规则名称、parity 导出与 CLI 展示。

**nDPI 5.0 源码核对（2026-11-08，`D:\c_code\nDPI-5.0`）**：

- `src/lib/protocols/afp.c`：载荷 ≥ 16 字节；载荷 > 128 字节时不判定（`packet_counter > 5` 才放弃，避免把大数据块当作 AFP 证据）；否则要求 `flags <= 1`、`command ∈ 1..=8`、`reserved == 0`、`payload_len >= 16 + BE u32(length)`。
- `src/lib/protocols/drda.c`：载荷 ≥ 10 字节；首条消息要求 `BE u16(length) == BE u16(length2) + 6` 且 `magic == 0xD0`；载荷长度大于首消息时逐条校验后续消息并要求精确消费；不检查端口。
- `src/include/ndpi_protocol_ids.h`：AFP ID 97；DRDA ID 227。
- `src/lib/ndpi_main.c`：AFP 名称 `AFP`、category `DATA_TRANSFER`、breed `ACCEPTABLE`、TCP/UDP 端口 548；DRDA 名称 `DRDA`、category `DATABASE`、breed `ACCEPTABLE`、无默认端口。

**真实 ndpiReader 5.0 探针（2026-11-08，WSL 本地构建 `nDPI 5.0.0`）**：

| 探针 | nDPI 5.0 输出 |
|---|---|
| AFP DSI @548 | `AFP` / DPI / DataTransfer-Acceptable |
| AFP DSI @549（非标端口） | `AFP` / DPI（检测本身不限端口） |
| DRDA 单消息 @50000 | `DRDA` / DPI / Database-Acceptable |

---

## 2. 协议模型与 Feature

### 2.1 Protocol 变体

| 变体 | feature | 内部 category | breed | 产出位置 |
|---|---|---|---|---|
| `Afp` | `storage` | `ProtocolCategory::FileTransfer` | `ProtocolBreed::Acceptable` | AFP detector |
| `Drda` | `database` | `ProtocolCategory::Database` | `ProtocolBreed::Acceptable` | DRDA detector |

两个变体均带对应 `#[cfg(feature = "...")]`。所有引用这些变体的 match 分支（`category()` / `breed()` / 规则名称 / parity 映射 / CLI / 端口回退）都必须带相同的 cfg 包裹。

### 2.2 Feature 与模块

- `Cargo.toml`：**不新增 feature**；更新 `storage` 注释为 `NFS + AFP`；
- `src/protocols/afp/`：`mod.rs` + `detector.rs` + `parser.rs`；
- `src/protocols/drda/`：`mod.rs` + `detector.rs` + `parser.rs`；
- `src/protocols/mod.rs`：模块声明 + `register_defaults` 注册。

### 2.3 Metadata

```rust
/// AFP DSI 元数据（feature: storage, F51）
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

/// DRDA 元数据（feature: database, F51）
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

`Metadata` 枚举新增两个条件变体：

```rust
#[cfg(feature = "storage")]
Afp(AfpMetadata),
#[cfg(feature = "database")]
Drda(DrdaMetadata),
```

### 2.4 DissectorState

**不新增变体**。两种协议均为无状态 detector：

- AFP 校验单报文 DSI 头；跨 TCP 段拆分的头由 `tcp_prefix` 补齐后识别；
- DRDA 校验单报文内的完整消息序列；跨段拆分同样由前缀补齐。

---

## 3. AFP Detector

### 3.1 DSI 报文头

DSI 头固定 16 字节（网络序）：

| 偏移 | 字段 | 类型 | 校验 |
|---:|---|---|---|
| 0 | `flags` | u8 | `<= 1` |
| 1 | `command` | u8 | `1..=8` |
| 2..4 | `request_id` | BE u16 | 无约束（元数据） |
| 4..8 | `data_offset` | BE u32 | 无约束（不解析） |
| 8..12 | `length` | BE u32 | `payload.len() >= 16 + length` |
| 12..16 | `reserved` | BE u32 | `== 0` |

### 3.2 检测逻辑

```rust
pub const AFP_DSI_HEADER_LEN: usize = 16;
/// 与 nDPI 一致：>128 字节的载荷不单独作为 AFP 定型依据
pub const AFP_MAX_DETECT_LEN: usize = 128;

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

### 3.3 首字节门

```rust
fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
    Some(&[(0x00, 0x01)])
}
```

`flags` 只能是 0 或 1，门区间与解析约束一致。

### 3.4 端口

nDPI 的 detector 不检查端口，只把 548 列为默认端口。rDpi 同样不在 `detect_with_context` 中做端口门控；仅在 `PORT_MAP` 增加 548 的**回退猜测**（DPI 失败后使用）。

### 3.5 检测结果

```rust
DetectionResult::new(Protocol::Afp)
    .with_metadata(Metadata::Afp(AfpMetadata { flags, command, request_id, length }))
    .with_confidence(Confidence::Dpi)
```

---

## 4. DRDA Detector

### 4.1 消息头

每条 DRDA 消息以 10 字节 DSS/DDM 头开始（网络序）：

| 偏移 | 字段 | 类型 | 校验 |
|---:|---|---|---|
| 0..2 | `length` | BE u16 | `== length2 + 6` 且 `>= 10` |
| 2 | `magic` | u8 | `== 0xD0` |
| 3 | `format` | u8 | 无约束（不解析） |
| 4..6 | `correl_id` | BE u16 | 无约束 |
| 6..8 | `length2` | BE u16 | 见 `length` |
| 8..10 | `code_point` | BE u16 | 无约束 |

### 4.2 检测逻辑

```rust
pub const DRDA_HEADER_LEN: usize = 10;
pub const DRDA_MAGIC: u8 = 0xD0;

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

与 nDPI 的差异：nDPI 的循环上界为 `count + 10 < payload_len`，在某些长度组合下不会消费最后一条消息；rDpi 采用更严格的“精确消费全部载荷”语义。单消息语料与 nDPI 完全一致，多消息由库内单测覆盖（不进入 parity 语料）。

### 4.3 首字节门

`first_byte_gate() = None`：首字节是消息长度高字节，合法值范围覆盖整个 `u8`，没有有意义的窄区间。

### 4.4 端口

nDPI 的 DRDA 没有默认端口。rDpi **不增加端口回退**，只通过载荷 DPI 识别；这是与 nDPI 默认端口表一致的行为。

### 4.5 检测结果

```rust
DetectionResult::new(Protocol::Drda)
    .with_metadata(Metadata::Drda(DrdaMetadata { message_count, message_length }))
    .with_confidence(Confidence::Dpi)
```

---

## 5. 注册与集成

### 5.1 模块声明

`src/protocols/mod.rs`：

```rust
#[cfg(feature = "storage")]
pub mod afp;
#[cfg(feature = "database")]
pub mod drda;
```

### 5.2 注册顺序与影响面

- AFP **注册在 DNS 之前**（`http::register` 之后、`dns::register` 之前）：

```rust
#[cfg(feature = "http")]
http::register(_registry);
#[cfg(feature = "storage")]
afp::register(_registry);
#[cfg(feature = "dns")]
dns::register(_registry);
```

原因：header-only DSI（16 字节，`flags=0/1`、其余字段为 0）会被 DNS detector 误判为 `Dns`（DNS 只校验 qd/opcode，不校验 payload 尾部多余字节；语料差分已复现）。AFP 门仅 `{0x00,0x01}` 且要求完整 DSI 结构，真实 DNS 问题区从偏移 12 开始，非零 qname 字节使 `reserved != 0`，不会落入 AFP。

- DRDA 在现有 `database` 块 `oracle::register` 之后、`elasticsearch::register` 之前：

```rust
#[cfg(feature = "database")]
oracle::register(_registry);
#[cfg(feature = "database")]
drda::register(_registry);
```

**影响面复述（AGENTS.md 禁止事项 #1）**：新增两个 detector；AFP 与 DNS 的相对顺序改变（AFP 前置），其余既有 detector 相对顺序不变。

- AFP 首字节门 `{0x00,0x01}`，要求 16 字节 DSI 头（flags/command/reserved/长度下界）。它与 MySQL（3 字节长度 + 序号）、PostgreSQL/MongoDB（u32 长度）、MSSQL（TDS 类型 1..=8）存在理论上的首字节交集；这些 database detector 在 registry 中仍早于 AFP，只有它们拒绝后才轮到 AFP，因此不会抢占其流量；
- AFP 前置 DNS 的影响：真实 DNS 查询/响应的问题区从偏移 12 开始，qname 字节非零使 DSI `reserved` 字段不为 0；DNS over TCP 在端口 53 由有状态 dissector 先行接管；因此 AFP 不会抢占正常 DNS 流量；
- DRDA 首字节门为 `None`，但 10 字节头的 `length == length2+6 && magic==0xD0` 约束很强；注册在 database 块内 MySQL/PostgreSQL/Redis/MongoDB/MSSQL/Oracle 之后，既有长度校验先执行，DRDA 后执行，互不抢占；
- 两个 detector 均不改变既有相对顺序。

### 5.3 端口回退

`src/core/guess/port.rs` 的 `PORT_MAP` 增加（带 cfg）：

```rust
#[cfg(feature = "storage")]
(548u16, &[Protocol::Afp]),
```

DRDA 不增加端口回退（nDPI 无默认端口）。

### 5.4 规则名称

`src/rule/parser.rs`：

```rust
#[cfg(feature = "storage")]
"afp" => Protocol::Afp,
#[cfg(feature = "database")]
"drda" => Protocol::Drda,
```

### 5.5 CLI

`src/bin/rdpi.rs` 的元数据显示新增：

- `Metadata::Afp(a)` → `flags={} command={} request={} length={}`；
- `Metadata::Drda(d)` → `messages={} length={}`。

各分支带对应 `#[cfg(feature = "...")]`。

---

## 6. Parity 导出

`src/parity.rs`：

| rDpi 协议 | protocol_name（master） | app | category | breed |
|---|---|---|---|---|
| `Afp` | `AFP` | — | `DataTransfer` | `Acceptable` |
| `Drda` | `DRDA` | — | `Database` | `Acceptable` |

- `protocol_name`：`Afp`/`Drda` 的 Debug 输出与 nDPI 仅大小写不同（比较器大小写不敏感），仍显式映射为 `AFP`/`DRDA` 以锁定输出；
- `ndpi_compat_classification` 新增：`Afp → ("DataTransfer","Acceptable")`（内部 FileTransfer 与 nDPI 不同，必须显式覆盖）、`Drda → ("Database","Acceptable")`；
- 两者均无 app 层协议，`app_protocol = None`；
- 不新增风险映射。

nDPI 协议 ID 供参考：AFP 97、DRDA 227。名称/分类已用真实 ndpiReader 5.0 输出验证（§1）。

---

## 7. 语料与 golden

扩展 `tests/parity/gen_corpus.py`：

1. `afp_dsi.pcap`：TCP 548 三次握手后，客户端发送 DSI 请求（`flags=0, command=1, request_id=1, data_offset=0, length=0, reserved=0`，16 字节）；服务端发送 DSI 响应（`flags=1, command=1`，16 字节）。nDPI 首包即 DPI；
2. `drda_message.pcap`：TCP 50000 三次握手后，客户端发送 16 字节 DRDA 单消息（`length=16, magic=0xD0, format=0x41, correl_id=0, length2=10, code_point=0` + 6 字节填充）。nDPI 首包即 DPI。

用 `tests/parity/gen_golden.sh`（`/mnt/d/c_code/nDPI-5.0/build/example/ndpiReader`）生成 golden；若真实输出与 §6 映射不一致，先修正映射再提交。

**不进入 parity 语料**：

- AFP 非标端口变体：nDPI 同样 DPI，但无增量价值；
- AFP >128 字节大数据块：nDPI 不判定，rDpi 同样不判定，无法形成有效差分；
- DRDA 多消息串联：nDPI 循环在部分长度组合下行为不同，避免 golden 噪声；由库内单测覆盖；
- 跨段拆分变体：nDPI 单报文语义在首段即可能排除，golden 与 rDpi 前缀补齐后的识别结果不一致；跨段能力由库内单测覆盖（§10）。

---

## 8. 文件改动清单

| 文件 | 改动 |
|---|---|
| `Cargo.toml` | `storage` 注释更新（NFS + AFP），无新 feature |
| `src/core/types.rs` | 2 个 `Protocol` 变体；2 个 metadata 类型；`Metadata` 2 个条件变体；category/breed 分支 |
| `src/protocols/afp/` | 新建：`mod.rs`、`detector.rs`、`parser.rs` |
| `src/protocols/drda/` | 新建：`mod.rs`、`detector.rs`、`parser.rs` |
| `src/protocols/mod.rs` | 模块声明 + 注册 |
| `src/core/guess/port.rs` | 548 端口回退 + 单测 |
| `src/rule/parser.rs` | 2 个协议名称映射 + 单测 |
| `src/parity.rs` | protocol_name + category/breed 映射 + 单测 |
| `src/bin/rdpi.rs` | 元数据显示 |
| `tests/test_integration.rs` | storage 1→2、database 9→10 |
| `tests/test_afp_drda.rs` | 新建跨段/入口集成测试 |
| `tests/parity/gen_corpus.py` | 2 个语料 builder + `CORPUS` 条目 |
| `tests/parity/gen_golden.sh` | 2 个 golden 生成项 |
| `tests/parity/corpus/`、`tests/parity/golden/` | 新语料与 ndpiReader 5.0 golden |
| `AGENTS.md`、`docs/architecture/*.md` | F51 记录与状态更新 |

---

## 9. 测试与验收

### 9.1 单元测试

**AFP**

- 16 字节 DSI 请求/响应命中；带 body（长度 > 0 且载荷足够）命中；
- 载荷 < 16 → `None`；载荷 > 128 → `None`；
- `flags > 1`、`command == 0`、`command == 9`、`reserved != 0` → `None`；
- `payload.len() < 16 + length` → `None`；
- 负样本：HTTP 请求、TDS 头、MySQL 头、随机二进制；
- `first_byte_gate` 覆盖 0x00/0x01，拒绝其他字节。

**DRDA**

- 单条 16 字节消息命中；多条严格串联命中（消息长度 > 10，避免 nDPI 循环怪癖）；
- 载荷 < 10 → `None`；magic 错误 → `None`；`length != length2+6` → `None`；`length < 10` → `None`；
- 消息声明长度超过载荷 → `None`；尾随不足 10 字节残片 → `None`；
- 负样本：HTTP 请求、TDS 头、Kafka 请求、随机二进制；
- `first_byte_gate` 为 `None`。

**回归**

- 规则名称映射（`afp`/`drda`）；
- parity `protocol_name` / `ndpi_compat_classification`；
- 端口回退 548→Afp；50000 不产生 DRDA 端口回退；
- `Protocol::category()` / `breed()` 在 default / `storage` / `database` / all-features 下均可编译；
- detector 计数（storage +1、database +1）。

**跨段超集（库内，不进入 parity）**

- 将 AFP DSI 头与 DRDA 消息从中间拆成两个 TCP 段，经 `Detector::process_packet` 处理后仍识别为对应协议。

### 9.2 语料 + golden 门禁

```bash
python -I tests/parity/gen_corpus.py
# WSL：
bash tests/parity/gen_golden.sh
```

验收：

- 新增 2 个语料在 master/app/category/breed/confidence/risk gate 上一致；
- 现有语料与全部存量测试无回归。

### 9.3 全量门禁

```bash
cargo test
cargo test --features "storage database"
cargo test --all-features
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -D warnings
```

---

## 10. 已知边界

**AFP**

- 仅识别 DSI 头，不解析 AFP 命令体、卷名、文件路径等；
- 载荷 > 128 字节的报文不判定（与 nDPI 一致：避免把大数据块当作 AFP 证据）；若首包即为大数据块，rDpi 不会在后续前缀中重新识别（前缀只会增长）；
- mDNS/Bonjour 的 AFP 服务广告不识别；
- 检测本身不限端口（与 nDPI 一致），548 仅作为回退猜测；
- 跨 TCP 段拆分的 ≤128 字节 DSI 消息在前缀补齐后可识别（相对 nDPI 的超集）。

**DRDA**

- 不解析 DDM 命令码、SQL 语句、参数等；
- 多消息串联采用“精确消费全部载荷”的严格语义；nDPI 的循环上界在部分长度组合下不会消费最后一条消息，两者可能不一致（parity 只用单消息）；
- 无端口回退（nDPI 无默认端口）；
- 不区分 DRDA 请求/响应方向；
- 检测不感知传输层（既有 detector 通病），UDP 上出现相同结构会命中。

**Parity**

- AFP 非标端口、>128 字节大数据块、DRDA 多消息不进入语料；
- 合成流可能触发 nDPI 的 `Malicious Fingerprint` 风险，沿用现有门禁剔除策略。

---

## 11. 实施顺序

1. `src/core/types.rs`：两个 `Protocol` 变体 + metadata 类型 + `Metadata` 变体 + category/breed（先让新变体可编译）；
2. AFP parser + detector + 注册 + 单测；
3. DRDA parser + detector + 注册 + 单测；
4. 端口回退 + 规则名称 + parity 映射 + CLI + detector 计数 + 对应单测；
5. 语料生成 + WSL golden + 差分门禁；
6. 文档回写（AGENTS.md F51、modules.md、risks.md、路线图、覆盖清单）、全量门禁、提交。

---

## 12. 风险与注意事项

| 风险 | 应对 |
|---|---|
| AFP 与 MySQL/PostgreSQL/MSSQL 首字节交集 | AFP 在 storage 块末尾、既有 detector 之后执行；16 字节头 + reserved=0 + 长度下界收缩命中面 |
| AFP 大数据块误判 | `payload.len() > 128` 直接拒绝（对齐 nDPI） |
| DRDA 多消息循环与 nDPI 不一致 | 采用严格精确消费；parity 只用单消息；边界登记 |
| DRDA 无首字节门带来额外解析成本 | 仅读取 10 字节头并在 magic/length 不符时立即返回；无分配 |
| 新 `Protocol` 变体导致 match 不穷尽 | 编译期暴露；category/breed/规则/parity/CLI/端口表逐处补齐 |
| 注册顺序影响既有 detector | AFP 前置到 DNS 之前（header-only DSI 与 DNS 误报冲突）；其余相对顺序不变，影响面已在 §5.2 复述 |
| 548 端口回退把非 AFP 流量猜成 AFP | 仅 DPI 失败后的 `MatchByPort`，与 nDPI 默认端口表一致 |
