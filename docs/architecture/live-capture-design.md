# Live Capture 垂直切片设计

> 生成时间：2026-11-07
> 状态：设计已确认，待实现
> 关联文档：
> - [nDPI 纯 Rust 实现方案](ndpi-pure-rust-plan.md)（§4 P4：部署形态与工具链）
> - [nDPI 对比与替换路线（历史版）](ndpi-comparison-and-roadmap.md)（§3.4 P3：live capture / CLI）
> - [AGENTS.md](../../AGENTS.md)（现有 CLI、pcap 回放与测试基线）
> - [风险与已知问题](risks.md)

---

## 1. 背景与目标

rDpi 目前只能回放 pcap/pcapng 文件（`PcapProcessor` + `src/bin/rdpi.rs`），不具备实时抓包能力。nDPI 类比路线中的部署能力（P4）要求：

- `-i device` 实时抓包；
- BPF 过滤；
- 与离线回放一致的协议识别、流统计和输出格式；
- 核心 crate 保持纯 Rust，live capture 作为可选适配层。

本设计交付 **Live Capture 垂直切片的第一个可独立验收版本**：单线程、单网卡、以太网帧、复用现有检测/输出链路。多线程、任意链路层、优雅信号处理不在本切片范围内。

### 1.1 已确认的决策

| 决策点 | 选择 | 理由 |
|---|---|---|
| 抓包后端 | 动态加载 pcap（`libloading`） | 本机只有 Npcap 运行时、没有 Npcap SDK；动态加载无需编译期 `wpcap.lib`，Linux/macOS 同样可用 |
| 代码布局 | 同 crate 可选 feature `live` | 改动最小；默认构建不引入 `libloading`，核心仍零 C 构建依赖 |
| 交付范围 | 库 API + CLI | 库用户可嵌入采集；CLI 复用现有输出与差分链路 |
| CLI 入口 | `-i` 自动区分文件/网卡，另加 `--iface` | 兼容现有 `-i FILE`；接近 ndpiReader 习惯；`--iface` 消除同名歧义 |

### 1.2 非目标（本切片不做）

- 多线程抓包与 flow 分片（后续子项目）；
- Linux `any` 接口 / `DLT_LINUX_SLL`、`DLT_RAW`、回环非以太网链路；
- Ctrl-C 优雅停机与运行中统计；
- pcap 注入、离线 pcap 写入、BPF 编译缓存；
- 网卡地址列表（IPv4/IPv6/netmask）；
- 抓包缓冲区大小、immediate mode、TPACKET_V3 等高级调优；
- Windows 服务化、DPDK、eBPF。

---

## 2. Feature 与模块布局

### 2.1 Cargo

```toml
[dependencies]
libloading = { version = "0.8", optional = true }

[features]
live = ["dep:libloading"]  # 实时抓包适配层（动态加载 Npcap/libpcap）
```

- `live` 不进入 `default`；默认 `cargo build` / `cargo test` 行为不变。
- `libloading` 是纯 Rust 依赖，不引入 C 编译期依赖。
- CLI 二进制维持 `required-features = ["pcap"]`；实时抓包需同时启用 `live`：

```text
cargo run --features "pcap live" --bin rdpi -- --list-ifaces
```

`[[example]] name = "live_capture"` 声明 `required-features = ["live"]`，避免默认构建编译示例。

### 2.2 文件结构

| 文件 | 职责 |
|---|---|
| `src/live/mod.rs` | 公共 API：`CaptureConfig`、`Device`、`CapturedFrame`、`LiveCapture`、`LiveError`、`devices()` |
| `src/live/ffi.rs` | 动态库加载、函数指针表、`#[repr(C)]` 结构、RAII 句柄 |
| `src/lib.rs` | `#[cfg(feature = "live")] pub mod live;` |
| `src/bin/rdpi.rs` | 新增 CLI 参数、来源解析、实时抓包循环、输出复用 |
| `examples/live_capture.rs` | 手工验证示例 |
| `tests/test_live.rs` | feature-gated 单元/集成测试（文件级 `#![cfg(feature = "live")]`） |
| `README.md`、`AGENTS.md` | 文档回写 |

---

## 3. 公共 API

### 3.1 类型

~~~rust
/// 抓包配置
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// pcap 设备名（`devices()` 返回的 `Device::name`）
    pub device: String,
    /// BPF 过滤表达式；None 表示不过滤
    pub filter: Option<String>,
    /// 快照长度，默认 65535
    pub snaplen: i32,
    /// 混杂模式，默认 true
    pub promisc: bool,
    /// 读超时（毫秒），默认 100；仅影响 `next_frame` 的无包返回频率
    pub timeout_ms: i32,
}

impl CaptureConfig {
    pub fn new(device: impl Into<String>) -> Self;
    pub fn filter(self, expression: impl Into<String>) -> Self;
    pub fn snaplen(self, snaplen: i32) -> Self;
    pub fn promisc(self, promisc: bool) -> Self;
    pub fn timeout_ms(self, timeout_ms: i32) -> Self;
}

/// 可抓包设备
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// 传给 `CaptureConfig::new` 的设备名（Windows: `\Device\NPF_{GUID}`）
    pub name: String,
    /// 描述（Windows 为 "Ethernet" / "Wi-Fi" 等；可能为 None）
    pub description: Option<String>,
    pub is_loopback: bool,
    pub is_up: bool,
}

/// 一帧以太网数据
#[derive(Debug, Clone)]
pub struct CapturedFrame {
    /// 帧字节（长度 = caplen，不超过 snaplen）
    pub data: Vec<u8>,
    /// 抓包时间戳（微秒）
    pub timestamp_us: u64,
    /// 原始线上长度（可能大于 data.len()，表示被 snaplen 截断）
    pub original_len: u32,
}

/// 实时抓包迭代器
pub struct LiveCapture { /* pcap 句柄 + 元数据 */ }

impl LiveCapture {
    /// 打开设备并应用 BPF；失败时不保留半初始化状态
    pub fn open(config: CaptureConfig) -> Result<Self, LiveError>;

    /// 读取下一帧；返回 Ok(None) 表示读超时（未捕获到包）
    pub fn next_frame(&mut self) -> Result<Option<CapturedFrame>, LiveError>;

    /// pcap 链路层类型（应为 1 = DLT_EN10MB）
    pub fn datalink(&self) -> i32;

    /// 底层 pcap 版本字符串，便于诊断（`pcap_lib_version` 缺失时为 None）
    pub fn backend_version(&self) -> Option<String>;
}

/// Iterator 语义：跳过读超时，持续产出帧，直到错误或 `pcap_next_ex` 返回 -2
impl Iterator for LiveCapture {
    type Item = Result<CapturedFrame, LiveError>;
}

/// 列出设备；库缺失时返回 `LiveError::BackendUnavailable`
pub fn devices() -> Result<Vec<Device>, LiveError>;
~~~

### 3.2 线程与生命周期

- `LiveCapture` 含裸 pcap 句柄，天然 `!Send + !Sync`；每个线程必须独立 `open`。
- `live` 模块不引入全局可变状态；动态库符号表加载成功后用 `OnceLock` 缓存，加载失败不写入缓存（后续调用可重试）。
- `CapturedFrame` 拥有数据副本；pcap 返回的指针只在下次 `pcap_next_ex` 前有效，必须在 `next_frame` 内复制。

### 3.3 错误模型

~~~rust
#[derive(Debug, thiserror::Error)]
pub enum LiveError {
    #[error("pcap backend not found (tried: {tried:?}); install Npcap or libpcap")]
    BackendUnavailable { tried: Vec<String>, message: String },

    #[error("capture device not found: {0}")]
    DeviceNotFound(String),

    #[error("failed to open device '{device}': {message}")]
    OpenFailed { device: String, message: String },

    #[error("invalid BPF filter '{expression}': {message}")]
    Filter { expression: String, message: String },

    #[error("unsupported data link type {0}; only Ethernet (DLT_EN10MB=1) is supported")]
    UnsupportedDatalink(i32),

    #[error("capture error: {0}")]
    Capture(String),
}
~~~

错误消息保持英文，与现有库/CLI 错误风格一致；文档和 README 用中文解释处理办法。

---

## 4. FFI 后端

### 4.1 动态库候选

按顺序尝试，命中即停止：

| 平台 | 候选 |
|---|---|
| Windows | `wpcap.dll`（默认搜索路径含 System32）、`C:\Windows\System32\Npcap\wpcap.dll`、`C:\Program Files\Npcap\wpcap.dll` |
| Linux | `libpcap.so.1`、`libpcap.so.0.8`、`libpcap.so` |
| macOS | `libpcap.dylib`、`/usr/lib/libpcap.A.dylib` |

加载失败时聚合所有尝试路径与 `libloading` 错误文本，返回 `BackendUnavailable`。

### 4.2 符号表

只声明必需函数，全部为 cdecl：

| 符号 | 用途 |
|---|---|
| `pcap_findalldevs` / `pcap_freealldevs` | 枚举设备 |
| `pcap_open_live` | 打开设备（snaplen/promisc/timeout） |
| `pcap_compile` / `pcap_freecode` / `pcap_setfilter` | BPF 编译与应用 |
| `pcap_next_ex` | 读取下一帧（区分包/超时/错误/结束） |
| `pcap_datalink` | 链路层校验 |
| `pcap_geterr` | 错误文本 |
| `pcap_close` | 释放句柄 |
| `pcap_lib_version` | 诊断信息（可选符号，缺失时 `backend_version` 返回 None） |

`pcap_lib_version` 按可选处理；其余缺失视为后端不可用。`pcap_compile` 固定传 `optimize = 1`、`netmask = 0xFFFF_FFFF`（`PCAP_NETMASK_UNKNOWN`）；错误缓冲区按 `PCAP_ERRBUF_SIZE = 256` 分配。

### 4.3 C 结构布局

~~~rust
#[repr(C)]
struct PcapPkthdr {
    ts: Timeval,
    caplen: u32,
    len: u32,
}

// Windows 的 long 为 32 位；64 位 Unix 的 time_t/suseconds_t 为 64 位
#[cfg(any(windows, target_pointer_width = "32"))]
#[repr(C)]
struct Timeval { tv_sec: i32, tv_usec: i32 }

#[cfg(all(not(windows), target_pointer_width = "64"))]
#[repr(C)]
struct Timeval { tv_sec: i64, tv_usec: i64 }

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut c_void,
    flags: u32,
}

#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *mut c_void,
}
~~~

- `pcap_t` 作为不透明类型处理（`#[repr(C)] struct PcapT { _private: [u8; 0] }`）。
- 时间戳换算：`tv_sec as u64 * 1_000_000 + tv_usec as u64`；负数或溢出按 0 处理。
- 设备 flags：`0x1` = loopback，`0x2` = up，`0x4` = running（running 不单独暴露）。
- 描述/名称为空指针时转 `None`；非 UTF-8 用 `from_utf8_lossy`。

### 4.4 RAII 与 unsafe 边界

所有 `unsafe` 只出现在 `src/live/ffi.rs`；`src/live/mod.rs` 及 CLI 不写 `unsafe`。

- `PcapHandle`：`Drop` 调 `pcap_close`；`open_live` 返回空指针时读取 errbuf 转 `OpenFailed`。
- `DeviceList`：`Drop` 调 `pcap_freealldevs`；遍历结束后方可释放。
- `BpfProgramGuard`：`pcap_compile` 成功后保证 `pcap_freecode`；`pcap_setfilter` 失败时仍释放。
- 每次调用 `pcap_geterr` 后立即复制为 `String`，不保存指针。
- `pcap_next_ex` 返回 1 时校验 `header`/`data` 非空、`caplen <= snaplen`，再 `slice::from_raw_parts` 复制。
- `pcap_next_ex` 返回 -2 时 Iterator 结束；返回 -1 时读取 `pcap_geterr` 转 `Capture` 错误。
- 不在信号处理器中调用任何 pcap 函数（本切片无信号处理）。

### 4.5 链路层约束

- 打开顺序固定为：`pcap_open_live` → `pcap_datalink` 校验 → BPF 编译/应用；链路层不支持时不编译过滤器。
- `pcap_open_live` 后立即调用 `pcap_datalink`；不等于 `1`（DLT_EN10MB）时关闭句柄并返回 `UnsupportedDatalink`。
- 典型触发场景：Linux `any` 返回 `DLT_LINUX_SLL`（113）。错误消息提示“改用具体网卡”；README 同样说明。

---

## 5. CLI 行为

### 5.1 参数

`Cli::input` 由现有 `PathBuf` 改为 `Option<String>`，以支持网卡名与 `--iface` 二选一；文件来源仍按路径处理。

| 参数 | 类型 | 说明 |
|---|---|---|
| `-i, --input <FILE\|IFACE>` | 可选 | `is_file()` 为真 → pcap 回放；否则 → 实时网卡 |
| `--iface <NAME>` | 可选 | 显式网卡；与 `-i` 互斥（clap `conflicts_with`） |
| `--list-ifaces` | flag | 列出设备后退出；不需要 `-i`/`--iface` |
| `-f, --filter <BPF>` | 可选 | BPF 表达式；仅实时模式有效，文件模式报错 |
| `--count <N>` | 可选 | 捕获 N 帧后停止并输出汇总 |
| `--duration <SECS>` | 可选 | 运行指定秒数后停止并输出汇总 |
| `-o, --output` | 沿用 | text / json / jsonl / csv / flows-jsonl |
| `-v, --verbose` | 沿用 | 逐包输出 |

约束：

- `-i` 与 `--iface` 至少提供一个，除非使用 `--list-ifaces`（clap `required_unless_present_any`）。
- `--list-ifaces` 与 `-i`/`--iface` 同时出现时报错。
- `--count` 与 `--duration` 可同时使用，任一满足即停止。
- 未启用 `live` feature 时，解析到实时来源或使用 `--list-ifaces`/`-f` 直接给出构建提示：

```text
error: live capture requires building with --features "pcap live"
```

### 5.2 来源解析

~~~text
--list-ifaces           → 列设备，退出
--iface NAME            → 实时
-i PATH 且 PATH.is_file() → pcap 文件
-i NAME 且非文件          → 实时
其余                     → clap 错误
~~~

- 目录路径不视为 pcap 文件；按网卡名处理，打开失败时错误信息中同时给出该字符串。
- `--filter/--count/--duration` 与文件来源组合时返回用法错误（退出码 2），不静默忽略。

### 5.3 实时循环

1. `devices()`（仅在 `--list-ifaces` 时）或直接 `LiveCapture::open(CaptureConfig)`。
2. 循环调用 `next_frame()`：
   - `Ok(Some(frame))`：`timestamp_ms = frame.timestamp_us / 1000`，调用 `Detector::process_packet(&frame.data, timestamp_ms)`；
   - `Ok(None)`：检查 `--duration` 是否到期，继续；
   - `Err(e)`：打印错误并返回非零退出码。
3. 每帧递增 `total_packets`；检测结果非空时更新 `detected_packets` 与协议计数。
4. `--count` 达到后停止；`--duration` 在每次循环（含读超时）检查，误差不超过 `timeout_ms`。
5. 结束后按现有输出格式输出汇总；`flows-jsonl` 输出 `detector.normalized_flows()`（需 `json` feature）。

### 5.4 输出复用

现有文件路径的统计变量与输出分支需要抽取，避免实时路径复制一份：

- 新增内部 `RunStats`（total/detected/protocol_counts/packet_records）与 `record_packet()`；
- 新增 `emit_summary(output, stats, elapsed)` 与 `emit_flows_jsonl(detector)`；
- 文件路径与实时路径共用上述函数；文件路径的现有输出语义、排序、字段保持不变；
- `PcapIterator` 继续持有 `Detector`；实时路径直接创建 `Detector`，结束后调用同一组输出函数。

### 5.5 `--list-ifaces` 输出

纯文本，每行一个设备：

```text
\Device\NPF_{...}  [up]  Intel(R) Wi-Fi 6E AX211
\Device\NPF_{...}  [loopback,up]  Npcap Loopback Adapter
```

无设备时输出 `no capture devices found` 并以退出码 0 结束；后端缺失返回非零并打印安装提示。

---

## 6. 测试策略

### 6.1 不依赖真实抓包

CI 不保证安装 libpcap/Npcap，测试必须能在“后端不可用”环境中通过：

| 测试 | 断言 |
|---|---|
| `CaptureConfig` 默认值 | snaplen=65535、promisc=true、timeout_ms=100 |
| builder 链式设置 | 各字段按调用顺序覆盖 |
| `devices()` 容错 | `Ok(list)` 或 `Err(BackendUnavailable)`，不 panic |
| 来源解析 | 在 `src/bin/rdpi.rs` 内用 `#[cfg(test)]` 单测覆盖：文件路径 → 文件；不存在路径 → 实时；`--iface` 优先 |
| 错误 Display | 各变体包含设备名/表达式/链路层数字 |
| `Timeval` 布局 | `size_of::<Timeval>()` 在 64 位为 16，32 位/Windows 为 8 |
| Iterator 结束语义 | v1 不引入可注入的假后端；`-2 → None` 只在手工验证中覆盖，不写依赖真实抓包的单测 |

### 6.2 依赖后端的测试（本机手工）

- `--list-ifaces` 返回至少一个设备；
- `open` 不存在的设备名 → `DeviceNotFound`/`OpenFailed`；
- 非法 BPF（如 `tcp port not-a-number`）→ `Filter`；
- `-i <网卡> --count 200 -o jsonl -v` 能识别真实流量；
- `-f "tcp port 443"` 只产出匹配流量；
- `--duration 5` 在空闲链路上也能按时停止并输出汇总。

这些不进入 CI；`examples/live_capture.rs` 作为可重复手工脚本。

### 6.3 编译与 lint

- `cargo check --features live`（无需 pcap 运行时/开发包）；
- `cargo clippy --all-features --all-targets -- -D warnings`；
- 默认 features 与全 features 测试保持全绿；
- 现有 pcap 回放、parity 语料、CLI 输出测试不得回归。

---

## 7. 文档与安全说明

### 7.1 README

- Feature 表新增 `live`：实时抓包适配层（动态加载 Npcap/libpcap）。
- 新增“实时抓包”小节：

```bash
cargo run --features "pcap live" --bin rdpi -- --list-ifaces
cargo run --features "pcap live" --bin rdpi -- -i <iface> -f "tcp port 443" --duration 10
```

- 说明平台依赖：
  - Windows 需安装 Npcap 运行时；若安装时勾选“仅管理员访问 Npcap 驱动”，需在管理员终端运行；
  - Linux 需安装 libpcap 运行时，抓包需 root 或 `CAP_NET_RAW`；
  - macOS 使用系统自带 libpcap。
- 说明仅支持以太网链路层；Linux `any` 不支持。

### 7.2 架构文档与 AGENTS.md

- 本文档记录设计与边界；
- AGENTS.md 增加 F47 条目：live capture 实现、动态库候选、错误模型、CLI 行为、测试基线；
- `docs/architecture/ndpi-pure-rust-plan.md` §4 P4 与 §9 实施进展回写完成项。

### 7.3 安全

- 抓包内容属于敏感数据；CLI 默认只在内存中处理，不落盘。
- 动态加载按固定候选路径/库名，不接受用户提供的任意库路径（避免 DLL 劫持面扩大）。
- `wpcap.dll` 从系统路径或 Npcap 安装目录加载；不调用 `AddDllDirectory` 等改变搜索路径的 API。
- 所有来自 pcap 的长度/指针在使用前校验；不信任 `caplen`/`len`。

---

## 8. 验收标准

- [ ] `--list-ifaces` 在 Windows 本机列出网卡；无后端时有清晰错误与安装提示。
- [ ] `rdpi -i <网卡> --count 200 -o jsonl -v` 实时识别流量并输出逐包记录。
- [ ] `rdpi -i <网卡> -f "tcp port 443" --duration 10 -o text` 按 BPF 过滤并按时停止。
- [ ] `rdpi -i <pcap 文件>` 行为与改动前完全一致；现有测试全部通过。
- [ ] 默认构建与 `cargo test --all-features` 不需要 Npcap SDK / libpcap 开发包。
- [ ] `LiveCapture` 公共 API 有 rustdoc；`examples/live_capture.rs` 可运行。
- [ ] README、AGENTS.md、路线图文档完成回写。

---

## 9. 风险与后续扩展

| 风险 | 影响 | 应对 |
|---|---|---|
| `timeval` 平台布局错误 | 时间戳错乱、JA4L 等时延指纹失真 | 按平台/位宽定义 + 尺寸单测；`process_packet` 只用毫秒，误差可观察但不会崩溃 |
| pcap 符号版本差异 | 后端加载失败 | 只用长期稳定符号；`pcap_lib_version` 可选；错误信息列出缺失符号 |
| Linux `any` 被拒 | 用户以为功能坏了 | `UnsupportedDatalink` 提示改用具体网卡；README 明确 |
| Npcap 权限不足 | 打开失败 | 原样透出 `pcap_geterr`；README 说明管理员/Npcap 驱动访问选项 |
| 每帧 `Vec` 复制 | 高吞吐下分配压力 | v1 可接受；后续加回调式 `capture_with` 或复用缓冲区 |
| 无 Ctrl-C 优雅停机 | 交互式使用时无汇总 | `--duration`/`--count` 可预期停止；后续子项目引入信号处理 |
| 循环链路/虚拟网卡 | 非以太网帧被拒 | 明确报错；后续支持 SLL/RAW 与链路层适配 |

### 后续增量（不在本切片）

1. 多线程：按 flow hash 分片，每线程独立 `LiveCapture` + `Detector`，统计聚合；CLI `-n`。
2. 信号处理：Ctrl-C 优雅停止，打印汇总并输出 flows。
3. 链路层扩展：DLT_LINUX_SLL/SLL2、DLT_RAW；`any` 设备支持。
4. 零拷贝/缓冲复用 API；抓包缓冲区、immediate mode。
5. 设备地址列表、友好名称解析（description → name）。
6. ndpiReader 风格参数补齐：`-a`、`-B`、`-T/-U`、`--cfg` 等。

---

## 10. 决策记录

- **为什么不用 `pcap` crate**：Windows 编译期需要 Npcap SDK 的 `wpcap.lib`，本机只有运行时；`libloading` 动态加载对 CI 与用户更友好，且保持“默认构建无 C 依赖”。
- **为什么不做独立 crate**：当前仓库单 crate，feature 已能满足“默认不引入”的边界；若后续多线程/多平台适配膨胀，再拆 `rdpi-live`。
- **为什么只支持以太网帧**：检测核心与 pcap 回放都按以太网帧工作；SLL/RAW 需要新的链路层适配层，属于独立设计。
- **为什么先不做 Ctrl-C**：信号处理涉及平台 FFI 与退出时序，容易把垂直切片膨胀；`--count`/`--duration` 已能覆盖脚本化验收。
