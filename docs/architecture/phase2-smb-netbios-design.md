# 阶段 2 第一批设计：NetBIOS + SMBv1/v2/v3

> 生成时间：2026-11-07
> 状态：设计已确认，待实现
> 关联文档：
> - [nDPI 纯 Rust 实现方案](ndpi-pure-rust-plan.md)（阶段 2：企业协议 Wave 1B）
> - [协议/应用覆盖候选清单](protocol-coverage-plan.md)（§10.2 阶段 2）
> - [风险与已知问题](risks.md)（F44 子分类与有状态框架先例）
> - [AGENTS.md](../../AGENTS.md)（F44 及测试基线）

---

## 1. 背景与目标

阶段 1（A 组 Web/Cloud + B 组已有企业协议）已由 F44 收尾。阶段 2 的 Wave 1B 首批缺口是 **NetBIOS** 与 **SMBv1/v2/v3**——Windows 内网文件共享与发现的核心协议，当前 `src/protocols/` 中均不存在。

nDPI 5.0 的行为基线：

- 协议 ID：`NETBIOS`(10)、`SMBV1`(16)、`SMBV23`(41)
- 分类：NetBIOS → `System/OS` + Acceptable；SMBv1 → `System/OS` + **Dangerous**；SMBv23 → `System/OS` + Acceptable
- 检测位置：
  - NetBIOS：UDP 137（NBNS）、UDP 138（NBDS）、TCP 139（NBSS session request）
  - SMB：**仅 TCP 445**；NBSS 4 字节长度头 + `0xFFSMB`（v1）/`0xFE SMB`（v2/3）
  - SMBv1 会跳过 Negotiate（command `0x72`），等待后续非 Negotiate 包
- SMBv1 风险：`NDPI_SMB_INSECURE_VERSION`（HIGH，客户端问责）

本轮目标：

1. 新增 `smb` feature，同时启用 NetBIOS 与 SMB 两个模块；
2. 与 nDPI 协议粒度对齐：`NetBios`、`Smb1`、`Smb23` 三个 `Protocol` 变体；
3. 提取基础元数据：NetBIOS 服务类型/名称/suffix；SMB command/status；
4. 处理 TCP 首段头部拆分（NetBIOS 139 / SMB 445 的头部重组）；
5. SMBv1 产出 `SmbInsecureVersion` 风险；
6. Parity 导出与 nDPI 5.0 输出对齐，并加入语料 + golden 差分。

---

## 2. 协议模型与 Feature

### 2.1 Protocol 变体

| 变体 | 内部 category | breed | 产出 |
|---|---|---|---|
| `NetBios` | `ProtocolCategory::Infrastructure` | `ProtocolBreed::Acceptable` | NetBIOS detector |
| `Smb1` | `ProtocolCategory::FileTransfer` | `ProtocolBreed::Dangerous` | SMB detector（`0xFFSMB`） |
| `Smb23` | `ProtocolCategory::FileTransfer` | `ProtocolBreed::Acceptable` | SMB detector（`0xFESMB`） |

均使用 `#[cfg(feature = "smb")]`，与现有 `Ftp`/`Nfs` 的 optional protocol 模式一致。所有引用这些变体的 match 分支（`category()` / `breed()` / 规则名称 / parity 映射 / 风险处理器）都必须用 `#[cfg(feature = "smb")]` 包裹；`DissectorState` 的状态变体保持无条件（沿用 `Ftp` 先例）。

### 2.2 Feature 与模块

- `Cargo.toml`：新增 `smb = []`
- `src/protocols/netbios/`：`mod.rs` + `detector.rs` + `parser.rs`
- `src/protocols/smb/`：`mod.rs` + `detector.rs` + `parser.rs`
- `src/protocols/mod.rs`：
  ```rust
  #[cfg(feature = "smb")]
  pub mod netbios;
  #[cfg(feature = "smb")]
  pub mod smb;
  ```

### 2.3 Metadata

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
    pub service: NetBiosService,
    /// 解码后的 NetBIOS 名称（NBNS 问题名 / NBDS source name / NBSS called name）
    pub name: Option<String>,
    /// NBNS 名称第 16 字节后缀（0x00 workstation、0x20 file server 等）
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

`Metadata` 枚举新增 `NetBios(NetBiosMetadata)` 与 `Smb(SmbMetadata)`（cfg smb）。`Metadata::application()` 的 `_ => None` 已覆盖新变体，无需修改。

### 2.4 DissectorState

沿用 F43/F44 的“状态结构无条件、协议变体 cfg”模式：

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetBiosDissectorState {
    pub buffer: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmbDissectorState {
    pub buffer: Vec<u8>,
}

pub enum DissectorState {
    // ... 现有变体 ...
    /// NetBIOS TCP 139 会话请求头部重组
    NetBios(NetBiosDissectorState),
    /// SMB TCP 445 头部重组 + SMB1 Negotiate 跳过
    Smb(SmbDissectorState),
}
```

`DissectorState` 的显式 match（`src/protocols/http/detector.rs`）增加 `NetBios(_)` / `Smb(_) => return None`。

### 2.5 规则名称

`src/rule/parser.rs` 增加：`netbios`、`smb1`、`smb23`（均 `#[cfg(feature = "smb")]`）。未知名称仍回退 `Protocol::Other(0)`。

---

## 3. NetBIOS Detector

### 3.1 UDP 137 — NBNS 名称服务

报文结构（RFC 1002）：

```text
0..2   transaction_id
2..4   flags
4..6   qdcount
6..8   ancount
8..10  nscount
10..12 arcount
12..   question name (first-level encoded)
```

问题名格式：

```text
0x20 + 32 个 'A'..='P' 编码字符 + 0x00 + QTYPE(2) + QCLASS(2)
```

校验（端口 137，任一端）：

- `payload.len() >= 50`
- 计数合理：查询 `qdcount == 1 && ancount == 0 && nscount == 0 && arcount <= 1`；响应 `ancount >= 1`
- `payload[12] == 0x20`
- 32 个编码字符均 ∈ `'A'..='P'`，`payload[45] == 0x00`
- QTYPE ∈ {`0x0020`, `0x0002`}，QCLASS == `0x0001`

名称解码：

- 每两个字符还原一个字节：`((hi - b'A') << 4) | (lo - b'A')`，共 16 字节
- `suffix = decoded[15]`
- `name = decoded[..15]` 去除尾部空格/`0x00` 后的 ASCII 字符串

元数据：`service = NameService`、`name`、`suffix`。

### 3.2 UDP 138 — NBDS 数据报服务

报文结构（RFC 1002）：

```text
0      msg_type (0x10..=0x16)
1      flags
2..4   dgm_id
4..8   source_ip
8..10  source_port
10..12 dgm_length
12..14 packet_offset
14..30 source_name (16 bytes)
30..46 dest_name   (16 bytes)
46..   data
```

校验（端口 138，任一端）：

- `payload.len() >= 46`
- `msg_type ∈ 0x10..=0x16`
- `dgm_length == payload.len() - 14`（与 nDPI 判据一致）

元数据：`service = DatagramService`、`name = source_name`（ASCII，去除尾部空格/`0x00`）、`suffix = None`。

**与 nDPI 的差异**：nDPI 还校验 `source_ip` 字段等于 IPv4 源地址；rDpi detector 只拿得到 payload + 端口，不暴露 IP，因此不做该校验。字段仍保留在报文里，不影响识别。登记为边界。

### 3.3 TCP 139 — NBSS 会话服务

NBSS 4 字节头：

```text
0      type
1      flags
2..4   length（14-bit；高 2 位为 flags）
```

类型：

| type | 含义 | 处理 |
|---|---|---|
| `0x00` | session message | 若 payload[4..8] 为 `\xFFSMB`/`\xFESMB` → NetBIOS Session（不升级 SMB） |
| `0x81` | session request | 解析 called name / calling name |
| `0x82`-`0x85` | 响应/keepalive | 不单独分类（信息量不足） |

Session request（type `0x81`）：

```text
4..20    called name  (16 bytes, ASCII)
20..36   calling name (16 bytes, ASCII)
36..     session request data
```

校验：

- `length >= 33`（两个名称 + 至少 1 字节 session request data）
- `payload.len() >= 37`（4 + 16 + 16 + 1）

元数据：`service = SessionService`、`name = called name`（去除尾部空格/`0x00`）、`suffix = None`。

### 3.4 有状态 `process()`

仅 TCP 139：

- 端口门控：任一端不是 139 → `None`
- `state == None`：payload[0] 为 `0x81` 或 `0x00` 才接管；否则 `None`
- 缓冲上限 `NETBIOS_MAX_BUFFER_BYTES = 4096`
- type `0x81`：缓冲至至少 37 字节后分类；首段不足 → `Continue`
- type `0x00`：缓冲至 8 字节；若 payload[4..8] 为 SMB 签名 → 分类；否则 `GiveUp`
- 其他类型 → `GiveUp`

UDP 137/138 走无状态 `detect_with_context`，没有 `process`（lib 只对 TCP 调用有状态路径）。

### 3.5 首字节门

`first_byte_gate() = None`（NBNS transaction ID 任意，NBDS type 0x10–0x16，NBSS type 0x81/0x00）。按 F29 契约，`None` 表示显式声明首字节任意；端口门控在 `detect_with_context` 内完成。更新 AGENTS.md 中“首字节任意”的 detector 列表。

---

## 4. SMB Detector

### 4.1 报文与签名

仅 TCP 445（任一端）。payload 起始为 NBSS 4 字节头：

```text
0      type（必须 0x00）
1..4   length（24-bit，big-endian）
4..8   签名
```

签名：

- `0xFF 0x53 0x4D 0x42`（`\xFFSMB`）→ SMB1
- `0xFE 0x53 0x4D 0x42`（`\xFE SMB`）→ SMBv2/3

### 4.2 分类规则

**SMB2/3**

- 拿到 8 字节签名即可分类为 `Smb23`
- 元数据需要 18 字节：status `LE u32 @ payload[12..16]`、command `LE u16 @ payload[16..18]`
- 不足 18 字节时元数据为 `None`，仍可分类

**SMB1**

- 需要 9 字节读取 command `payload[8]`
- `command != 0x72`（Negotiate）→ `Smb1`
- `command == 0x72` → **跳过该 NBSS 消息**，等待后续非 Negotiate 消息（与 nDPI 一致）
- 元数据需要 13 字节：status `LE u32 @ payload[9..13]`、command 扩展为 u16

**未知签名** → `None`（无状态）/ `GiveUp`（有状态）。

### 4.3 有状态 `process()`

- 端口门控：任一端不是 445 → `None`
- `state == None`：payload[0] == 0x00 才接管；否则 `None`
- 缓冲上限 `SMB_MAX_BUFFER_BYTES = 64 * 1024`
- 循环处理缓冲中的 NBSS 消息：
  1. 不足 4 字节 → `Continue`
  2. 解析 type/length；type != 0x00 或 length == 0 或 length > 16 MiB → `GiveUp`
  3. 不足 8 字节签名 → `Continue`
  4. 签名 SMB2/3：不足 18 字节 → `Continue`；否则分类 `Smb23`（带元数据）
  5. 签名 SMB1：不足 9 字节 → `Continue`
     - command != 0x72：不足 13 字节 → `Continue`；否则分类 `Smb1`
     - command == 0x72：需要完整消息 `4 + length` 字节；不足 → `Continue`；足够则丢弃该消息并继续循环，等待下一个 NBSS 消息
  6. 其他签名 → `GiveUp`
- 同一 TCP 段内可包含多条 NBSS 消息；Negotiate 后紧跟 Session Setup 时同一调用即可分类

### 4.4 无状态 `detect` / `detect_with_context`

- `detect` 按 4.2 规则在单包内分类；SMB1 Negotiate 返回 `None`
- `detect_with_context` 先做 445 端口门控，再调用 `detect`
- 首字节门：`Some(&[(0x00, 0x00)])`；保留门覆盖样本测试

### 4.5 分类后行为

- SMB2/3 与 SMB1 均不进入 `flow.monitoring`（元数据为单消息级，无持续富化需求）
- 分类后缓冲清空；后续包不再处理（lib 在 classified + !monitoring 时直接回显）

---

## 5. Risk：SMBv1 insecure version

### 5.1 RiskFlag

```rust
/// SMBv1 为已知不安全版本（WannaCry/EternalBlue 等）
SmbInsecureVersion,
```

- `default_severity()` → `RiskSeverity::High`
- `name()` → `"smb_insecure_version"`

### 5.2 Processor

新增 `src/risk/processors/smb.rs`：

- `#[cfg(feature = "smb")]` 编译与注册
- `analyze_packet`：
  - `flow.protocol == Some(Protocol::Smb1)` 且 `flow.risks` 尚无该 flag
  - 当前包为 SMB1 `Trans` 命令（command `0x25`）时跳过（对齐 nDPI 的广播发现例外）
  - 产出 `RiskResult::new(RiskFlag::SmbInsecureVersion, RiskSeverity::High, "SMBv1 is insecure and vulnerable to known exploits")`
- `src/risk/processors/mod.rs`：`#[cfg(feature = "smb")] pub mod smb;` + 注册；更新处理器数量测试

### 5.3 Parity

- `src/parity.rs` `ndpi_compat_risk_name`：`smb_insecure_version` → `smb_insecure_ver`
- `tests/parity/mod.rs` `NDPI_RISK_ALIASES` 增加同一对别名

---

## 6. Parity 导出

`NormalizedFlow::from_flow` 特殊映射：

| rDpi 协议 | master | app | protocol_stack |
|---|---|---|---|
| `NetBios` | `NetBIOS` | — | `["NetBIOS"]` |
| `Smb1` | `SMBv1` | `NetBIOS` | `["SMBv1","NetBIOS"]` |
| `Smb23` | `SMBv23` | `NetBIOS` | `["SMBv23","NetBIOS"]` |

- `protocol_name`：`NetBios → "NetBIOS"`、`Smb1 → "SMBv1"`、`Smb23 → "SMBv23"`（cfg smb）
- `ndpi_compat_classification`（cfg smb）：
  - `NetBios | Smb23 → ("System", "Acceptable")`
  - `Smb1 → ("System", "Dangerous")`
- `from_flow` 对 `Smb1`/`Smb23` 固定 `app_protocol = Some("NetBIOS")`，覆盖 `metadata.application()`（新 metadata 返回 None，仍显式处理以表达 nDPI 的 master/app 语义）

---

## 7. 注册与集成

### 7.1 注册顺序

`register_defaults` 在 SSH 之后、FTP 之前插入：

```rust
#[cfg(feature = "ssh")]
ssh::register(_registry);
#[cfg(feature = "smb")]
{
    netbios::register(_registry);
    smb::register(_registry);
}
#[cfg(feature = "proto3")]
ftp::register(_registry);
```

理由：

- 两者均为端口门控 + 头部校验的高特异性 detector（137/138/139/445）
- 与现有 detector 无端口重叠
- 放在文件传输族（FTP）之前，符合特异性递减的注册约定
- 更新 `register_defaults` 顶部注册顺序注释

### 7.2 显式 match

- `src/protocols/http/detector.rs` 的 `DissectorState` 显式 match 增加 `NetBios(_)` / `Smb(_) => return None`
- 其他 detector 使用 `_ => return None`，无需改动

### 7.3 CLI

`src/bin/rdpi.rs` `print_detection`：

- `Metadata::NetBios(nb)`：显示 `nb.name`
- `Metadata::Smb(_)`：无主元数据（显示协议名即可；command/status 留待后续 CLI 增强）

---

## 8. 测试与语料

### 8.1 单元测试

**NetBIOS**
- NBNS：合法 query（flags=0，qdcount=1）→ NetBios + NameService + 解码名称/suffix；非法名称编码/计数 → None；响应（ancount=1）→ NetBios
- NBDS：合法 datagram（type 0x10，dgm_length 匹配）→ NetBios + DatagramService + source name；长度不匹配 → None
- NBSS：72 字节 session request（type 0x81，length 68）→ NetBios + SessionService + called name；type 0x00 + SMB 签名 → NetBios；type 0x82 → None
- 有状态：split session request（首段 4 字节、次段补齐）；错误 type → GiveUp
- 端口门控：137/138 之外 UDP 不接管；139 之外 TCP 不接管
- 首字节门：`None` 契约

**SMB**
- SMB1 Session Setup（command 0x73）→ Smb1 + command/status
- SMB1 Negotiate（0x72）→ 无状态 None；有状态 Continue；后续 Setup → Classified Smb1
- 同一段内 Negotiate + Setup → Classified Smb1
- SMB2 NEGOTIATE（`0xFE SMB`，command 0）→ Smb23 + command/status
- split header（首段 2 字节，次段补齐）→ 有状态 Classified
- 错误签名 / 非 445 端口 → None
- 首字节门覆盖样本测试

**Risk**
- Smb1 流 → SmbInsecureVersion（High）
- Smb23 流 → 无风险
- SMB1 Trans（0x25）→ 不产出风险
- 同一流重复包不重复产出

**Parity**
- NetBios → master NetBIOS、app None、stack [NetBIOS]、System/Acceptable
- Smb1 → master SMBv1、app NetBIOS、stack [SMBv1, NetBIOS]、System/Dangerous
- Smb23 → master SMBv23、app NetBIOS、stack [SMBv23, NetBIOS]、System/Acceptable
- 风险名映射 `smb_insecure_version` → `smb_insecure_ver`

### 8.2 语料 + golden

新增：

| 语料 | 内容 | nDPI 预期 |
|---|---|---|
| `netbios_nbns.pcap` | UDP 137 NBNS 名称查询（50 字节） | NetBIOS |
| `netbios_nbds.pcap` | UDP 138 NBDS 数据报（msg_type 0x10，source_ip 匹配） | NetBIOS |
| `netbios_nbss.pcap` | TCP 139 72 字节 session request | NetBIOS |
| `smb1_session_setup.pcap` | TCP 445，SMB1 Session Setup（0x73） | SMBv1.NetBIOS |
| `smb1_negotiate_then_setup.pcap` | 先 SMB1 Negotiate（0x72）后 Session Setup | SMBv1.NetBIOS |
| `smb23_negotiate.pcap` | TCP 445，SMB2 NEGOTIATE | SMBv23.NetBIOS |

- 用 WSL ndpiReader 5.0 生成 golden（`tests/parity/gen_golden.sh` 现有流程）
- split-header 场景只进单测，不进 golden（nDPI 不做跨段重组，避免必然差分）
- 语料 runner 自动纳入；若 nDPI 输出与预期不符，先修正 parity 映射再提交

### 8.3 门禁

```bash
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo test
cargo test --features smb
cargo test --all-features
cargo test --features "risk smb"
```

---

## 9. 文档更新

- `AGENTS.md`：新增 F45 条目（实现摘要、测试计数、模块说明）；更新“首字节任意”列表
- `docs/architecture/modules.md`：新增 `smb` feature 行（netbios + smb）
- `docs/architecture/risks.md`：F45 实现细节与已知边界
- `docs/architecture/ndpi-pure-rust-plan.md`：阶段 2 Wave 1B 进度
- `docs/architecture/protocol-coverage-plan.md`：SMB/NetBIOS 标记为已覆盖
- `README.md`：feature 列表如包含 `proto3`/`infra` 等，补充 `smb`

---

## 10. 已知边界

1. **SMB over TCP 139 保持 NetBios**（与 nDPI 一致，不升级为 SMB）；SMB over QUIC 不识别。
2. **SMB1 Negotiate-only 流不分类**（nDPI 同）；SMB2/3 首个头部即分类。
3. SMB 元数据仅 command/status；不解析 dialect、server name、OS、签名/加密状态。
4. NetBIOS 名称只取首个问题/会话请求/source name；不递归 NBDS relay、不解析多问题。
5. NBDS 不校验 `source_ip == IPv4 源地址`（detector 无 IP 上下文；nDPI 会校验）。
6. NBNS/NBDS 校验为启发式，私有/厂商扩展消息类型可能漏判。
7. 头部重组上限：SMB 64 KiB、NetBIOS 4 KiB；超限 GiveUp 回退。
8. 不分析 SMB3 加密消息；仅初始明文头部可分类。
9. 单 flow 仍只允许一个活跃 `DissectorState`。
10. 语料中的 NBNS/NBDS/session request 为手工构造的最小合法报文，不代表真实厂商变体。

---

## 11. 实施顺序

1. `smb` feature + `Protocol`/`Metadata`/`DissectorState` 变体 + 规则名称
2. `netbios` parser（NBNS/NBDS/NBSS 名称解码）+ detector（无状态 + TCP 139 有状态）+ 单测
3. `smb` parser（NBSS/SMB1/SMB2 头）+ detector（无状态 + 有状态 Negotiate 跳过/头部重组）+ 单测
4. 注册、HTTP match、CLI
5. `SmbInsecureVersion` 风险 flag/processor + parity 名称映射 + 单测
6. Parity 导出特殊映射 + 单测
7. 语料生成 + golden 差分
8. 文档回写、全量门禁、提交

---

## 12. 风险与注意事项

| 风险 | 应对 |
|---|---|
| NetBIOS 首字节任意导致误报 | 端口门控 + 严格 NBNS/NBDS/NBSS 结构校验；注册在 SSH 之后，仍按当前顺序运行 |
| SMB1 Negotiate 跳过导致流长期未分类 | 与 nDPI 对齐；有状态 `Continue` 保留缓冲，后续包可升级；流超时后由 giveup/guess 处理 |
| SMB 大消息缓冲 | 只等到解析所需头部（SMB2 18B / SMB1 13B）；Negotiate 需完整消息但上限 64 KiB |
| 子分类影响现有语料 | 新 detector 端口门控 137/138/139/445，不影响现有 44+ 语料流 |
| nDPI 输出 master/app 不是预期格式 | 语料生成后先 inspect `ndpi.proto`，按真实 golden 修正 `from_flow` |
| RiskFlag 增加导致 match 不穷尽 | 编译期暴露；更新 `default_severity`/`name` 与 parity 映射 |
| `smb` feature 未进 CI | CI 使用 `--all-features`，自动覆盖；本地补 `--features smb` 与 `"risk smb"` |
