# 实时抓包 v2 设计：多线程、优雅停机与链路层扩展

> 生成时间：2026-11-08
> 状态：设计已确认，待实施
> 前序切片：F47（[live-capture-design.md](live-capture-design.md)、[live-capture-plan.md](live-capture-plan.md)）
> 关联文档：[ndpi-pure-rust-plan.md](ndpi-pure-rust-plan.md)（P4）、[risks.md](risks.md)

---

## 0. 背景与目标

F47 交付了 live capture 垂直切片：运行时动态加载 Npcap/libpcap、以太网帧读取、CLI `-i/--iface/--list-ifaces/-f/--count/--duration`。设计文档登记的后续增量为：

1. 多线程：按 flow hash 分片，CLI `-n`；
2. 信号处理：Ctrl-C 优雅停止并输出汇总；
3. 链路层扩展：DLT_LINUX_SLL/SLL2、DLT_RAW，支持 Linux `any` 设备。

本设计一次覆盖上述三项，目标是把 live capture 从“垂直切片”做到“生产可用”：

- 单抓包线程 + N 个检测 worker，同一流始终落在同一 worker；
- 首次 Ctrl-C 优雅收尾（排空已入队帧、输出汇总），第二次立即退出；
- `-i any` 与 RAW 接口可直接识别，无需伪造以太网头；
- `-n 1`（默认）保持 F47 行为与输出顺序完全不变。

---

## 1. 已确认的决策

| 问题 | 决策 | 影响 |
|---|---|---|
| 多线程适用范围 | **仅实时抓包**，默认 `-n 1` | pcap 文件回放路径不动；单线程行为零变化 |
| 多线程输出语义 | `-v` 逐包行按完成顺序（可能乱序）；汇总与 `flows-jsonl` 确定性 | 收集端串行化输出，文档注明顺序差异 |
| Ctrl-C 语义 | 首次优雅停止并输出汇总（exit 0）；第二次立即退出（exit 130） | 依赖信号处理器计数 |
| 信号实现 | 新增 `ctrlc = "3"`，仅 `live` feature 启用 | 不扩大仓库 unsafe 面；新增一个轻量纯 Rust 依赖 |
| 并行架构 | 单抓包线程 + flow-hash 分发 + 主线程收集 | 单 pcap 句柄，跨平台可靠；有界队列提供背压 |
| 链路层适配 | 新增 `LinkType` 剥离链路头 + `Detector::process_ip_packet` L3 入口 | 不伪造以太网头，不污染帧语义与字节统计 |

---

## 2. 公共 API

### 2.1 `live::LinkType`

```rust
/// 支持的链路层类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// DLT_EN10MB (1)
    Ethernet,
    /// DLT_LINUX_SLL (113)
    LinuxSll,
    /// DLT_LINUX_SLL2 (276)
    LinuxSll2,
    /// DLT_RAW (12) / DLT_IPV4 (228) / DLT_IPV6 (229)
    RawIp,
}

impl LinkType {
    /// 从 `pcap_datalink` 值映射；不支持时返回 `None`。
    pub fn from_datalink(datalink: i32) -> Option<Self>;

    /// 剥离链路层头，返回 IPv4/IPv6 起始切片；非 IP 或截断返回 `None`。
    pub fn l3_payload<'a>(&self, frame: &'a [u8]) -> Option<&'a [u8]>;
}
```

DLT 解析规则：

| DLT | 值 | 布局 |
|---|---:|---|
| `DLT_EN10MB` | 1 | 14B 以太网头；EtherType 位于 offset 12；VLAN/QinQ/0x9100 标签栈上限 4 |
| `DLT_LINUX_SLL` | 113 | 16B 头；协议字段位于 offset 14；`l3` 从 offset 16 开始 |
| `DLT_LINUX_SLL2` | 276 | 20B 头；协议字段位于 offset 0；`l3` 从 offset 20 开始 |
| `DLT_RAW` | 12 | 无链路头；首半字节必须为 4 或 6 |
| `DLT_IPV4` / `DLT_IPV6` | 228 / 229 | 按 `RawIp` 处理，由首半字节校验版本 |

- SLL/SLL2 的协议字段为 VLAN TPID 时，继续剥离 4 字节 VLAN 标签（上限 4），与以太网路径一致。
- 以太网与 SLL/SLL2 仅在协议字段为 `0x0800`/`0x86dd` 时返回 `Some`；ARP、LLDP、未知协议均返回 `None`。RAW 仅按首半字节判定。
- `LiveCapture::open` 接受上述 DLT；其他 DLT 返回 `LiveError::UnsupportedDatalink`，错误文本列出支持项。
- `LiveCapture::datalink() -> i32` 保留；新增 `LiveCapture::link_type() -> LinkType`。

### 2.2 `live::InterruptFlag`

```rust
/// 跨平台 Ctrl-C 中断标志（仅 live feature）。
pub struct InterruptFlag { /* requested: Arc<AtomicBool>, signals: Arc<AtomicU8> */ }

impl InterruptFlag {
    /// 安装进程级 Ctrl-C 处理器；重复安装返回错误。
    pub fn install() -> Result<Self, LiveError>;

    /// 是否已收到第一次 Ctrl-C。
    pub fn is_requested(&self) -> bool;
}

impl Default for InterruptFlag { /* 永不置位，用于处理器安装失败时降级 */ }
```

- 处理器逻辑：第一次收到信号置位 `requested`；第二次调用 `std::process::exit(130)`。
- `ctrlc::set_handler` 的闭包运行在独立线程，调用 `exit` 安全。
- 只处理 SIGINT（Windows 为 Ctrl-C/Ctrl-Break）；Unix 不处理 SIGTERM。
- 新增 `LiveError::Signal(String)` 变体。

### 2.3 `Detector::process_ip_packet`

```rust
impl Detector {
    /// 处理 L3 包（IPv4/IPv6 头起始，不含链路层头），使用内置流表。
    pub fn process_ip_packet(
        &mut self,
        packet: &[u8],
        timestamp_ms: u64,
    ) -> crate::error::Result<Option<DetectionResult>>;
}
```

- 内部重构：

```text
process_packet(frame, ts)
  └─ parse_packet → process_parsed_with_table(parsed, frame.len(), ts)

process_ip_packet(l3, ts)
  └─ parse_l3_packet → process_parsed_with_table(parsed, l3.len(), ts)
```

- `process_parsed_with_table` 承担流表 `take`/`put`、双向归并、有状态 dissector、规则/风险/JA4 全链路。
- 字节统计：以太网路径按整帧长度计；L3 路径按 IP 包长度计，rustdoc 明确说明（`flows-jsonl` 不含字节字段，不受影响）。

### 2.4 `parity::sort_normalized_flows`

```rust
/// 按“信息量优先 + 端点字典序”排序归一化流记录。
pub fn sort_normalized_flows(flows: &mut [NormalizedFlow]);
```

`Detector::normalized_flows` 与 CLI 多线程收尾共用该函数，保证单/多线程导出顺序同构。

---

## 3. 多线程管线

### 3.1 数据流

```text
LiveCapture（rdpi-capture 线程）
  │  raw frame + timestamp_us + packet_no
  ├─ flow_shard(frame, link_type) —— 方向无关五元组哈希
  │      ├─ Some(shard) → SyncSender<WorkItem>（容量 1024，阻塞背压）
  │      └─ None        → LiveEvent::Packet { detection: None }
  ▼
Worker 0..N-1（rdpi-worker-<i>，各自独占 Detector）
  └─ LiveEvent::Packet / LiveEvent::Fatal / LiveEvent::Finished(Box<Detector>)
  ▼
主线程收集器（独占 OutputSink）
  └─ 合并统计；收尾合并各 Detector 的 flows 后统一排序输出
```

### 3.2 组件

```rust
const WORKER_QUEUE_CAPACITY: usize = 1024;
const MAX_THREADS: usize = 64;

struct WorkItem {
    packet_no: u64,
    timestamp_us: u64,
    data: Vec<u8>,
}

enum LiveEvent {
    Packet {
        packet_no: u64,
        timestamp_us: u64,
        detection: Option<DetectionResult>,
    },
    Fatal(String),
    Finished(Box<Detector>),
}
```

- `-n == 1` 不启动任何线程，走 F47 现有循环。
- `-n > 1`：抓包线程读帧；IP 帧按 shard 投递，非 IP/畸形帧直接发 `Packet { detection: None }`；每个 worker 独占一个 `Detector`。
- worker 处理：Ethernet 走 `process_packet`（保留 VLAN/IP-in-IP 语义），SLL/SLL2/RAW 先 `l3_payload` 再 `process_ip_packet`。
- 主线程持有 `OutputSink`，逐事件调用 `on_packet`；`Fatal` 记录首个错误并置停止标志；`Finished` 收集 Detector。
- 通道关闭后 join 全部线程（捕获 panic），再调用 `OutputSink::finish(elapsed, &detectors)`。

### 3.3 flow_shard

- 输入为原始帧；先用 `LinkType::l3_payload` 取 L3 切片（零分配）。
- IPv4：读取源/目的地址、协议与（当协议为 TCP/UDP 且首片时）端口；IPv6：读取源/目的地址与 Next Header，直接 TCP/UDP 时读端口；扩展头场景仅哈希地址与 Next Header。
- 规范化端点：按（地址字节，端口）字典序排序后再哈希，保证 A→B 与 B→A 得到同一 shard。
- 哈希算法：FNV-1a 64 位（确定性、无随机种子），`shard = hash % threads`。
- 非 IP、截断或首半字节非法返回 `None`。

### 3.4 生命周期与停止条件

- 停止条件：`--count` 达到读到的帧数（含非 IP）、`--duration` 到期、Ctrl-C、fatal 错误、任一发送通道断开。
- 抓包线程与每个 worker 各持有一个 event sender（抓包线程用于非 IP 帧与 fatal）；抓包线程退出后丢弃全部 frame sender；worker 排空队列后发送 `Finished` 并退出；全部线程退出、event sender 全部丢弃后，主线程收集循环结束。
- 已入队帧不丢；`--count` 语义与 F47 一致（按读取的帧计数）。
- 有界队列容量 1024/worker，提供背压，避免抓包快于检测时内存无界增长。

---

## 4. 链路层适配

### 4.1 CLI 分派

```text
let Some(l3) = link_type.l3_payload(&frame.data) else {
    sink.on_packet(timestamp_us, None);   // 非 IP 帧
    continue;
};
let detection = match link_type {
    LinkType::Ethernet => detector.process_packet(&frame.data, timestamp_us / 1000)?,
    _ => detector.process_ip_packet(l3, timestamp_us / 1000)?,
};
```

- 删除 CLI 中重复的 `is_ip_ethernet_frame`，统一由 `LinkType::l3_payload` 判定。
- 实现复用：`parser` 暴露 `pub(crate) fn ethernet_l3_payload(data) -> Result<(&[u8], u16)>`，避免再复制一份 VLAN 扫描逻辑。
- Linux `any` 设备由 libpcap 返回 SLL/SLL2，无需特判；BPF 过滤器由 libpcap 按链路类型编译，语义不变。
- Windows Npcap 无 `any` 设备；`--list-ifaces` 行为不变。

### 4.2 示例与文档

`examples/live_capture.rs` 按 `capture.link_type()` 选择入口，保证 `-i any` 下示例仍可运行。

---

## 5. CLI 与信号

### 5.1 参数

```text
-n, --threads <N>     实时抓包 worker 线程数（默认 1，范围 1..=64）
```

- `-n 1`：现有单线程循环，输出顺序与 F47 完全一致。
- `-n 0` 或 `> 64`：参数错误，exit 2。
- pcap 文件模式：`validate_file_options` 增加 `threads != 1` 即报错（`--threads requires a live capture interface`）。
- `-f/--count/--duration/-v/-o` 语义不变。

### 5.2 Ctrl-C

- `Source::Live` 启动时调用 `InterruptFlag::install()`；失败打印 `warning: failed to install Ctrl-C handler: ...`，降级为 `InterruptFlag::default()` 并继续抓包。
- 第一次 Ctrl-C：置位停止标志；抓包线程在 ≤ 一个 `timeout_ms`（默认 100ms）内退出，worker 排空队列，正常输出汇总，exit 0；stderr 打印一行 `interrupted` 提示（不污染 stdout）。
- 第二次 Ctrl-C：handler 直接 `std::process::exit(130)`。
- `--count` / `--duration` / Ctrl-C 取最先触发者。

### 5.3 输出合并

- `OutputSink::finish` 签名改为 `&mut self, elapsed, detectors: &[Detector]`：
  - `flows-jsonl`：拼接各 worker 的 `normalized_flows()`，调用 `sort_normalized_flows` 全局排序。
  - `json`（`-v` 的 `packets`）：收尾按 `packet_no` 升序重排，恢复抓包顺序。
  - `jsonl`/`text`：逐包行按完成顺序输出；汇总计数天然合并；文档注明 `-n > 1` 时逐包行可能乱序。
- `packet_no` 在抓包线程分配（1-based，含非 IP 帧），不依赖 worker 本地计数。

---

## 6. 错误处理

| 场景 | 行为 |
|---|---|
| `next_frame()` 返回错误 | 抓包线程发 `Fatal`、置停止标志，主线程排空后返回错误（不输出半截汇总） |
| worker `process_*` 返回错误 | 发 `Fatal`、置停止标志；该 worker 退出，其他 worker 在抓包停止后排空 |
| worker panic | 其 event sender 丢弃；抓包线程发送失败后停止；主线程 join 得到 panic，返回 `LiveError::Capture("worker thread panicked")` |
| 抓包线程 panic | frame sender 全部丢弃；worker 正常结束；主线程 join 得到 panic 并返回错误 |
| 通道发送失败 | 按 fatal 处理并停止抓包 |
| Ctrl-C 处理器安装失败 | 警告后降级继续 |

- 单线程路径保持 F47 语义：`?` 直接中止。
- 线程用 `thread::Builder` 命名：`rdpi-capture`、`rdpi-worker-<i>`。
- 退出码：参数错误 exit 2；运行期错误由 `main` 返回 `Err`（Rust 运行时 exit 1）；优雅停止 exit 0；第二次 Ctrl-C exit 130。

---

## 7. 测试策略

### 7.1 单元测试

- `src/live/link.rs`：
  - Ethernet/IPv4/IPv6/VLAN/QinQ；
  - SLL 与 SLL2 的最小合法帧、截断帧、非 IP 协议；
  - SLL 下 VLAN 标签栈偏移；
  - RAW 首半字节 4/6 与非法 0x0；
  - `from_datalink` 映射与未知 DLT。
- `src/bin/rdpi/live_runner.rs`：
  - `flow_shard` 双向对称、IPv6、非 IP 返回 `None`、分布不退化；
  - 合成以太网帧向量驱动 `-n 2` 管线，校验总包数、识别数、flow 合并与排序。
- `src/parity.rs`：`sort_normalized_flows` 排序语义。
- `src/live/signal.rs`：`InterruptFlag::is_requested` 在手工置位后为真；测试不安装进程级处理器。

### 7.2 集成测试

- `tests/test_process_ip_packet.rs`：
  - 同一 IP 包分别走 `process_packet`（前置 14B 以太网头）与 `process_ip_packet`，协议、流数、双向计数一致；
  - TCP/UDP/ICMP 覆盖；畸形 L3 返回错误。

### 7.3 回归与静态检查

```bash
cargo fmt --check
cargo test
cargo test --all-features
cargo test --features live
cargo clippy --all-features --all-targets -- -D warnings
cargo build --features "pcap live"
```

### 7.4 手工验收

Windows 本机：

```bash
cargo run --features "pcap live" --bin rdpi -- --list-ifaces
cargo run --features "pcap live" --bin rdpi -- -i '<网卡>' -n 4 --count 200 -o jsonl -v
cargo run --features "pcap live" --bin rdpi -- -i '<网卡>' -n 4 --duration 10 -o text
cargo run --features "pcap live" --example live_capture -- '<网卡>' 20
```

- 运行中第一次 Ctrl-C：输出汇总、exit 0；第二次 Ctrl-C：exit 130。
- `-n 1` 输出与 F47 一致。

Linux/WSL：

```bash
cargo run --features "pcap live" --bin rdpi -- -i any --count 200 -o text
cargo run --features "pcap live" --bin rdpi -- -i any -f "tcp port 443" --duration 10 -o jsonl -v
```

- SLL/SLL2 路径能识别协议；BPF 过滤生效。

---

## 8. 文档与进度回写

- 新增本文档；实施计划另存 `docs/architecture/live-capture-v2-plan.md`。
- 更新 `live-capture-design.md` §9 的“后续增量”，标注已由 v2 兑现。
- README：live capture 章节补 `-n`、Ctrl-C、`any`/SLL/RAW。
- AGENTS.md：新增 F48 条目与常用命令。
- `ndpi-pure-rust-plan.md`：P4 进展与待办。
- `risks.md`：登记本文 §9 的边界。

---

## 9. 风险与边界

| 边界 | 说明 |
|---|---|
| 抓包线程单点 | 单 pcap 句柄 + 单读线程是吞吐上限；PF_RING/DPDK/内核 fanout 不在本期 |
| `-v` 输出顺序 | `-n > 1` 时逐包行按完成顺序，可能乱序；`json` 的 `packets` 收尾重排，`flows-jsonl` 确定性排序 |
| 流表容量 | 每个 worker 默认 10000 条，总量约 10000 × N；本期不提供每 worker 容量参数 |
| 流分片均衡 | FNV-1a 五元组哈希；极端流量分布可能倾斜，本期不做动态再平衡 |
| SIGTERM | `ctrlc` 只处理 SIGINT；Unix 下 SIGTERM 不触发优雅停止 |
| DLT_RAW 平台差异 | 支持值 12；OpenBSD 的 DLT_RAW 差异不在本期 |
| Windows `any` | Npcap 不提供 `any` 设备，保持现状 |
| 非 IP 帧 | 计入 `--count` 与总包数，识别数为 0，与 F47 一致 |
| 多线程解析 | 抓包线程只做链路/IP 头轻量解析用于分片；完整解析与检测在 worker |

---

## 10. 范围外

- pcap 文件回放的并行化；
- 每 worker 流表容量/超时配置；
- 零拷贝/缓冲复用 API、抓包缓冲区与 immediate mode；
- PF_RING/DPDK/内核 fanout；
- ndpiReader 风格参数补齐（`-a`、`-B`、`-T/-U`、`--cfg`）；
- 设备友好名称解析与地址列表。

---

## 11. 决策记录

- **为什么单抓包线程 + 分发**：libpcap/Npcap 无法可移植地用 BPF 表达 flow-hash 分片；多句柄打开同一设备在 Npcap 上行为不可靠。单句柄 + 有界通道是跨平台最稳妥的方案。
- **为什么 `-n 1` 保留独立路径**：默认行为、输出顺序与性能特征零变化，降低回归面。
- **为什么主线程做收集器**：`OutputSink` 无需并发改造，汇总与 flow 合并天然串行；逐包输出不会行内交错。
- **为什么新增 `process_ip_packet` 而不是伪造以太网头**：伪造 L2 会污染字节统计与语义；L3 入口与 `process_l3_packet` 的既有模型一致。
- **为什么用 ctrlc crate**：跨平台且成熟，避免把信号 FFI 引入仓库；`unsafe` 仍仅限 `src/live/ffi.rs`。
- **为什么不在本期并行化 pcap 回放**：回放路径不是当前瓶颈，且保序/分片设计成本高；先完成 live 收尾。
