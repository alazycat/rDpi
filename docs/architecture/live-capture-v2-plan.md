# 实时抓包 v2 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 兑现 F47 登记的三项后续增量：实时抓包多线程（`-n`）、Ctrl-C 优雅停机、SLL/SLL2/RAW 链路层与 L3 检测入口。

**Architecture:** 单抓包线程读帧并按方向无关五元组哈希分发给 N 个 worker，每个 worker 独占一个 `Detector`，主线程串行收集事件并独占 `OutputSink`；`-n 1` 保留 F47 单线程路径。新增 `LinkType` 剥离链路层头，非以太网链路走新的 `Detector::process_ip_packet` L3 入口，不伪造以太网头。`ctrlc`（仅 `live` feature）提供第一次优雅停止、第二次强退的信号语义。

**Tech Stack:** Rust 2024（MSRV 1.88）、`ctrlc = "3"`（optional）、std `mpsc`/`thread`/`AtomicBool`、现有 `Detector`/`OutputSink`/clap/serde。

## Global Constraints

- 不新增除 `ctrlc = "3"` 之外的依赖；`ctrlc` 必须为 optional，且只由 `live` feature 启用。
- `unsafe` 只允许出现在 `src/live/ffi.rs`；新增的 `unsafe impl Send for CaptureHandle` 也只放在该文件。
- 多线程仅适用于实时抓包；pcap 文件回放路径（`run_file`）除 `OutputSink::finish` 签名适配外不得改变行为。
- `-n 1`（默认）必须保持 F47 的输出内容与顺序完全一致；`-n` 范围为 `1..=64`，越界按参数错误 exit 2。
- 第一次 Ctrl-C：排空已入队帧、输出汇总、exit 0；第二次 Ctrl-C：exit 130。Unix 不处理 SIGTERM。
- `-n > 1` 时 `-v` 逐包行按完成顺序（可能乱序）；`json` 的 `packets` 收尾按 `packet_no` 升序重排；`flows-jsonl` 跨 worker 全局排序，保持确定性。
- `--count` 语义与 F47 一致：按抓包线程读取的帧数计（含非 IP 帧）。
- 项目文档使用中文；提交信息不得包含任何 AI 署名或 `Co-Authored-By`；不得提交 `.claude/` 与 `docs/superpowers/`。
- 每个任务提交前运行 `cargo fmt`；最终门禁用 `cargo fmt --check`。
- 每次提交只包含本任务相关文件；不得修改 detector 注册顺序。
- 默认 features、`--all-features`、`--features live` 测试必须全绿；测试不得依赖本机安装 libpcap/Npcap。
- 既有 pcap 回放输出（text/json/jsonl/csv/flows-jsonl）语义保持不变。

---

## 文件结构

| 文件 | 职责 | 创建/修改 |
|---|---|---|
| `src/lib.rs` | `Detector::process_ip_packet` L3 入口；抽取共用流表主体 | 修改 |
| `tests/test_process_ip_packet.rs` | L3 入口与以太网入口一致性/双向聚合测试 | 创建 |
| `src/parser/mod.rs` | `ethernet_l3_payload` 复用 helper | 修改 |
| `src/live/link.rs` | `LinkType` 与 `l3_payload`（Ethernet/SLL/SLL2/RAW） | 创建 |
| `src/live/signal.rs` | `InterruptFlag` 与 `ctrlc` 安装 | 创建 |
| `src/live/ffi.rs` | 接受 SLL/SLL2/RAW DLT；存储 `link_type`；`unsafe impl Send` | 修改 |
| `src/live/mod.rs` | 导出 `LinkType`/`InterruptFlag`；`LiveCapture::link_type`；`LiveError::Signal` | 修改 |
| `src/parity.rs` | `sort_normalized_flows` 公共排序函数 | 修改 |
| `src/bin/rdpi.rs` | CLI `-n/--threads`、`OutputSink` 序号/合并、实时入口委托 | 修改 |
| `src/bin/rdpi/live_runner.rs` | 单抓包线程 + flow-hash worker + 主线程收集 | 创建 |
| `examples/live_capture.rs` | 按 `link_type()` 选择以太网/L3 入口 | 修改 |
| `README.md` | 实时抓包能力、`-n`、Ctrl-C、链路层说明 | 修改 |
| `AGENTS.md` | F48 认知条目与命令 | 修改 |
| `docs/architecture/ndpi-pure-rust-plan.md` | P4 进展回写 | 修改 |
| `docs/architecture/risks.md` | F48 边界登记 | 修改 |
| `docs/architecture/live-capture-design.md` | §9 后续增量标记已兑现 | 修改 |
| `docs/architecture/live-capture-v2-design.md` | 状态改为已实施 | 修改 |
| `Cargo.toml` / `Cargo.lock` | `ctrlc` 可选依赖、`live` feature 扩展 | 修改 |

---

### Task 1: Detector L3 入口

**Files:**
- Modify: `src/lib.rs:745-769`
- Test: `tests/test_process_ip_packet.rs`

**Interfaces:**
- Consumes: 现有 `parser::parse_packet`、`parser::parse_l3_packet`、`process_parsed_l3_packet`。
- Produces: `Detector::process_ip_packet(&mut self, packet: &[u8], timestamp_ms: u64) -> crate::error::Result<Option<DetectionResult>>`；私有 `Detector::process_parsed_with_table(&mut self, parsed: &crate::parser::ParsedPacket, byte_len: usize, timestamp_ms: u64) -> crate::error::Result<Option<DetectionResult>>`。

- [ ] **Step 1: 写失败测试**

创建 `tests/test_process_ip_packet.rs`：

```rust
//! `Detector::process_ip_packet`：L3（IPv4/IPv6 头起始）入口。
//!
//! 锁定与 `process_packet` 的一致性：同一 IP 包分别走以太网入口与 L3 入口，
//! 协议、流数、双向计数一致；字节统计口径不同（以太网含链路头）。

use rdpi::Detector;

const CLIENT: [u8; 4] = [192, 168, 1, 1];
const SERVER: [u8; 4] = [10, 0, 0, 1];

fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
    let total_len = 20 + l4.len();
    let mut packet = Vec::with_capacity(total_len);
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.push(64);
    packet.push(proto);
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(l4);
    packet
}

fn ethernet(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
    ];
    frame.extend_from_slice(payload);
    frame
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::with_capacity(8 + payload.len());
    segment.extend_from_slice(&sport.to_be_bytes());
    segment.extend_from_slice(&dport.to_be_bytes());
    segment.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes());
    segment.extend_from_slice(payload);
    segment
}

fn tcp(sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend_from_slice(&sport.to_be_bytes());
    segment.extend_from_slice(&dport.to_be_bytes());
    segment.extend_from_slice(&1000u32.to_be_bytes());
    segment.extend_from_slice(&0u32.to_be_bytes());
    segment.push(0x50);
    segment.push(flags);
    segment.extend_from_slice(&0xffffu16.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes());
    segment.extend_from_slice(payload);
    segment
}

fn dns_query(domain: &str) -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    query
}

#[test]
fn process_ip_packet_matches_ethernet_entry_for_udp() {
    let l3 = ipv4(17, CLIENT, SERVER, &udp(40000, 53, &dns_query("example.com")));
    let frame = ethernet(&l3);

    let mut ethernet_detector = Detector::new();
    let mut l3_detector = Detector::new();

    let from_ethernet = ethernet_detector
        .process_packet(&frame, 1_700_000_000_000)
        .unwrap()
        .expect("ethernet path should detect DNS");
    let from_l3 = l3_detector
        .process_ip_packet(&l3, 1_700_000_000_000)
        .unwrap()
        .expect("L3 path should detect DNS");

    assert_eq!(from_ethernet.protocol, from_l3.protocol);
    assert_eq!(ethernet_detector.flow_count(), l3_detector.flow_count());

    let flow_from_ethernet = ethernet_detector.flows().next().unwrap().1;
    let flow_from_l3 = l3_detector.flows().next().unwrap().1;
    assert_eq!(flow_from_ethernet.stats.packets, flow_from_l3.stats.packets);
    assert_eq!(
        flow_from_ethernet.packets_forward,
        flow_from_l3.packets_forward
    );
    assert_eq!(
        flow_from_ethernet.packets_reverse,
        flow_from_l3.packets_reverse
    );
    // 字节统计口径不同：以太网路径含 14 字节链路头
    assert_eq!(flow_from_ethernet.stats.bytes, flow_from_l3.stats.bytes + 14);
}

#[test]
fn process_ip_packet_aggregates_tcp_flow_both_directions() {
    let mut detector = Detector::new();

    detector
        .process_ip_packet(&ipv4(6, CLIENT, SERVER, &tcp(50001, 53, 0x02, b"")), 1)
        .unwrap();
    detector
        .process_ip_packet(&ipv4(6, SERVER, CLIENT, &tcp(53, 50001, 0x12, b"")), 2)
        .unwrap();
    detector
        .process_ip_packet(&ipv4(6, CLIENT, SERVER, &tcp(50001, 53, 0x10, b"")), 3)
        .unwrap();

    assert_eq!(detector.flow_count(), 1);
    let flow = detector.flows().next().unwrap().1;
    assert_eq!(flow.stats.packets, 3);
    assert_eq!(flow.packets_forward, 2);
    assert_eq!(flow.packets_reverse, 1);
}

#[test]
fn process_ip_packet_handles_icmp() {
    let mut detector = Detector::new();
    let icmp = [8u8, 0, 0, 0, 0, 1, 0, 1];

    detector
        .process_ip_packet(&ipv4(1, CLIENT, SERVER, &icmp), 1)
        .unwrap();

    assert_eq!(detector.flow_count(), 1);
    assert_eq!(detector.flows().next().unwrap().1.stats.packets, 1);
}

#[test]
fn process_ip_packet_rejects_truncated_packet() {
    let mut detector = Detector::new();
    assert!(detector.process_ip_packet(&[0x45, 0x00], 0).is_err());
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --test test_process_ip_packet`

Expected: 编译失败，报 `no method named 'process_ip_packet' found for struct 'Detector'`。

- [ ] **Step 3: 重构 `process_packet` 并新增 L3 入口**

把 `src/lib.rs:745-769` 的 `process_packet` 替换为以下三个方法（保留原有 rustdoc 并补充交叉引用）：

```rust
    /// 处理以太网帧（内置流表；双向流）
    ///
    /// 这是 pcap/CLI 等便捷入口使用的完整引擎：解析 L2/L3（含 VLAN/QinQ、
    /// IP-in-IP）、按双向规范五元组聚合流，再交给 [`Self::process_l3_packet`]
    /// 的分类主体。非以太网链路（SLL/SLL2/RAW）请使用
    /// [`Self::process_ip_packet`]。
    ///
    /// # Arguments
    ///
    /// * `packet` - 原始以太网帧字节
    /// * `timestamp_ms` - 包到达时刻（毫秒；离线 pcap 传捕获时戳）
    pub fn process_packet(
        &mut self,
        packet: &[u8],
        timestamp_ms: u64,
    ) -> crate::error::Result<Option<DetectionResult>> {
        let parsed = parser::parse_packet(packet)?;
        self.process_parsed_with_table(&parsed, packet.len(), timestamp_ms)
    }

    /// 处理 L3 包（IPv4/IPv6 头起始，不含链路层头；内置流表）
    ///
    /// 与 [`Self::process_packet`] 共用双向流表与分类主体，区别仅在于跳过
    /// 链路层解析，用于 SLL/SLL2/RAW 等非以太网链路。
    ///
    /// 字节统计按 IP 包长度计（`process_packet` 按整帧长度计）。
    pub fn process_ip_packet(
        &mut self,
        packet: &[u8],
        timestamp_ms: u64,
    ) -> crate::error::Result<Option<DetectionResult>> {
        let parsed = parser::parse_l3_packet(packet)?;
        self.process_parsed_with_table(&parsed, packet.len(), timestamp_ms)
    }

    /// 已解析包的流表取用/放回主体（双向规范五元组）
    fn process_parsed_with_table(
        &mut self,
        parsed: &crate::parser::ParsedPacket,
        byte_len: usize,
        timestamp_ms: u64,
    ) -> crate::error::Result<Option<DetectionResult>> {
        let packet_key = FlowKey {
            src_ip: parsed.src_ip,
            dst_ip: parsed.dst_ip,
            src_port: parsed.src_port,
            dst_port: parsed.dst_port,
            transport: parsed.transport,
        };
        let mut flow = match self.flow_table.take(&packet_key.canonical().0) {
            Some(flow) => flow,
            None => {
                let mut flow = Flow::new_bidirectional(packet_key);
                flow.dpi_only = !self.default_guess;
                flow
            }
        };
        let result = self.process_parsed_l3_packet(&mut flow, parsed, byte_len, timestamp_ms);
        self.flow_table.put(flow);
        result
    }
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --test test_process_ip_packet`

Expected: `test result: ok. 4 passed`。

Run: `cargo test`

Expected: 默认 features 全绿（无回归）。

- [ ] **Step 5: 提交**

```bash
git add src/lib.rs tests/test_process_ip_packet.rs
git commit -m "Add L3 packet entry"
```

---

### Task 2: 链路层类型与 SLL/SLL2/RAW 支持

**Files:**
- Create: `src/live/link.rs`
- Modify: `src/parser/mod.rs:26-31`
- Modify: `src/live/ffi.rs:8`、`src/live/ffi.rs:314-364`、`src/live/ffi.rs:378-384`
- Modify: `src/live/mod.rs:7`、`src/live/mod.rs:69-77`、`src/live/mod.rs:221-223`
- Modify: `src/bin/rdpi.rs:325-353`、`src/bin/rdpi.rs:355-403`、`src/bin/rdpi.rs:831-857`
- Modify: `examples/live_capture.rs`

**Interfaces:**
- Consumes: Task 1 的 `Detector::process_ip_packet`；现有 `parser::ethernet::parse`。
- Produces: `pub enum LinkType { Ethernet, LinuxSll, LinuxSll2, RawIp }`；`LinkType::from_datalink(i32) -> Option<LinkType>`；`LinkType::l3_payload<'a>(&self, frame: &'a [u8]) -> Option<&'a [u8]>`；`LiveCapture::link_type() -> LinkType`；`pub(crate) fn parser::ethernet_l3_payload(data: &[u8]) -> Result<(&[u8], u16)>`。

- [ ] **Step 1: 写链路层失败测试**

创建 `src/live/link.rs`（先只放类型与测试；方法体下一步实现）：

```rust
//! 支持的链路层类型与 L3 载荷定位。
//!
//! 不伪造以太网头：SLL/SLL2/RAW 帧只剥离链路层头，返回 IPv4/IPv6 起始切片。

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

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ether_type.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4_header() -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet
    }

    fn ipv6_header() -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet
    }

    #[test]
    fn from_datalink_maps_supported_values() {
        assert_eq!(LinkType::from_datalink(1), Some(LinkType::Ethernet));
        assert_eq!(LinkType::from_datalink(113), Some(LinkType::LinuxSll));
        assert_eq!(LinkType::from_datalink(276), Some(LinkType::LinuxSll2));
        assert_eq!(LinkType::from_datalink(12), Some(LinkType::RawIp));
        assert_eq!(LinkType::from_datalink(228), Some(LinkType::RawIp));
        assert_eq!(LinkType::from_datalink(229), Some(LinkType::RawIp));
        assert_eq!(LinkType::from_datalink(0), None);
    }

    #[test]
    fn ethernet_strips_header_and_vlan_stack() {
        let ipv4 = ipv4_header();
        let frame = ethernet(0x0800, &ipv4);
        assert_eq!(LinkType::Ethernet.l3_payload(&frame), Some(ipv4.as_slice()));

        let mut vlan = Vec::new();
        vlan.extend_from_slice(&0x0001u16.to_be_bytes());
        vlan.extend_from_slice(&0x0800u16.to_be_bytes());
        vlan.extend_from_slice(&ipv4);
        let frame = ethernet(0x8100, &vlan);
        assert_eq!(LinkType::Ethernet.l3_payload(&frame), Some(ipv4.as_slice()));

        let mut qinq = Vec::new();
        qinq.extend_from_slice(&0x0001u16.to_be_bytes());
        qinq.extend_from_slice(&0x8100u16.to_be_bytes());
        qinq.extend_from_slice(&0x0002u16.to_be_bytes());
        qinq.extend_from_slice(&0x0800u16.to_be_bytes());
        qinq.extend_from_slice(&ipv4);
        let frame = ethernet(0x88a8, &qinq);
        assert_eq!(LinkType::Ethernet.l3_payload(&frame), Some(ipv4.as_slice()));
    }

    #[test]
    fn sll_strips_16_byte_header() {
        let ipv4 = ipv4_header();
        let mut frame = vec![0u8; 14];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ipv4);
        assert_eq!(LinkType::LinuxSll.l3_payload(&frame), Some(ipv4.as_slice()));
    }

    #[test]
    fn sll2_strips_20_byte_header() {
        let ipv4 = ipv4_header();
        let mut frame = Vec::new();
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 18]);
        frame.extend_from_slice(&ipv4);
        assert_eq!(
            LinkType::LinuxSll2.l3_payload(&frame),
            Some(ipv4.as_slice())
        );
    }

    #[test]
    fn sll_vlan_tag_shifts_payload() {
        let ipv4 = ipv4_header();
        let mut frame = vec![0u8; 14];
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&0x0001u16.to_be_bytes());
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ipv4);
        assert_eq!(LinkType::LinuxSll.l3_payload(&frame), Some(ipv4.as_slice()));
    }

    #[test]
    fn raw_requires_ip_version_nibble() {
        let ipv4 = ipv4_header();
        assert_eq!(LinkType::RawIp.l3_payload(&ipv4), Some(ipv4.as_slice()));
        let ipv6 = ipv6_header();
        assert_eq!(LinkType::RawIp.l3_payload(&ipv6), Some(ipv6.as_slice()));
        assert_eq!(LinkType::RawIp.l3_payload(&[0x00, 0x01]), None);
        assert_eq!(LinkType::RawIp.l3_payload(&[]), None);
    }

    #[test]
    fn non_ip_and_truncated_frames_return_none() {
        let arp = ethernet(0x0806, &[0u8; 28]);
        assert_eq!(LinkType::Ethernet.l3_payload(&arp), None);
        assert_eq!(LinkType::Ethernet.l3_payload(&[0u8; 10]), None);
        assert_eq!(LinkType::LinuxSll.l3_payload(&[0u8; 10]), None);
        assert_eq!(LinkType::LinuxSll2.l3_payload(&[0u8; 10]), None);
    }
}
```

在 `src/live/mod.rs` 顶部加入模块声明与导出：

```rust
mod ffi;
mod link;

pub use link::LinkType;
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features live live::link`

Expected: 编译失败，报 `no function or associated item named 'from_datalink'` / `'l3_payload'`。

- [ ] **Step 3: 实现 `LinkType`**

在 `src/live/link.rs` 的 `LinkType` 定义后、测试模块前加入：

```rust
/// VLAN TPID（与 `parser::ethernet` 保持一致）
const VLAN_TPIDS: [u16; 3] = [0x8100, 0x88a8, 0x9100];
/// VLAN 标签栈深度上限（防止恶意嵌套消耗解析时间）
const MAX_VLAN_TAGS: usize = 4;

impl LinkType {
    /// 从 `pcap_datalink` 值映射；不支持时返回 `None`。
    pub fn from_datalink(datalink: i32) -> Option<Self> {
        match datalink {
            1 => Some(Self::Ethernet),
            113 => Some(Self::LinuxSll),
            276 => Some(Self::LinuxSll2),
            12 | 228 | 229 => Some(Self::RawIp),
            _ => None,
        }
    }

    /// 剥离链路层头，返回 IPv4/IPv6 起始切片；非 IP 或截断返回 `None`。
    pub fn l3_payload<'a>(&self, frame: &'a [u8]) -> Option<&'a [u8]> {
        match self {
            Self::Ethernet => ethernet_payload(frame),
            Self::LinuxSll => sll_l3_payload(frame, 16, 14),
            Self::LinuxSll2 => sll_l3_payload(frame, 20, 0),
            Self::RawIp => raw_ip_payload(frame),
        }
    }
}

fn ethernet_payload(frame: &[u8]) -> Option<&[u8]> {
    let (payload, ether_type) = crate::parser::ethernet_l3_payload(frame).ok()?;
    is_ip_protocol(ether_type).then_some(payload)
}

/// SLL（16 字节头）与 SLL2（20 字节头）共用剥离逻辑。
///
/// `protocol_offset` 是协议字段在帧内的偏移：SLL 为 14，SLL2 为 0。
fn sll_l3_payload(frame: &[u8], header_len: usize, protocol_offset: usize) -> Option<&[u8]> {
    if frame.len() < header_len {
        return None;
    }
    let mut protocol =
        u16::from_be_bytes([frame[protocol_offset], frame[protocol_offset + 1]]);
    let mut offset = header_len;
    let mut tags = 0usize;

    while VLAN_TPIDS.contains(&protocol) {
        if tags == MAX_VLAN_TAGS || frame.len() < offset + 4 {
            return None;
        }
        protocol = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
        tags += 1;
    }

    is_ip_protocol(protocol).then(|| &frame[offset..])
}

fn raw_ip_payload(frame: &[u8]) -> Option<&[u8]> {
    match frame.first().map(|byte| byte >> 4) {
        Some(4 | 6) => Some(frame),
        _ => None,
    }
}

fn is_ip_protocol(protocol: u16) -> bool {
    matches!(protocol, 0x0800 | 0x86dd)
}
```

- [ ] **Step 4: 运行链路层测试确认通过**

Run: `cargo test --features live live::link`

Expected: `test result: ok. 7 passed`。

- [ ] **Step 5: 暴露 parser helper**

在 `src/parser/mod.rs` 的 `parse_packet` 之前加入：

```rust
/// 剥离以太网头（含 VLAN/QinQ 标签栈），返回 L3 载荷与最终 EtherType。
///
/// 供实时抓包链路层适配复用，避免复制 VLAN 扫描逻辑。
pub(crate) fn ethernet_l3_payload(data: &[u8]) -> Result<(&[u8], u16)> {
    let (payload, header) = ethernet::parse(data)?;
    Ok((payload, header.ether_type))
}
```

- [ ] **Step 6: 让 `LiveCapture` 接受新 DLT 并暴露 `link_type()`**

修改 `src/live/ffi.rs`：

1. 顶部 `use super::{Device, LiveError};` 改为：

```rust
use super::{Device, LinkType, LiveError};
```

2. `CaptureHandle` 增加字段：

```rust
pub(crate) struct CaptureHandle {
    api: &'static PcapApi,
    handle: *mut PcapT,
    datalink: i32,
    link_type: LinkType,
    snaplen: i32,
    backend_version: Option<String>,
}
```

3. `CaptureHandle::open` 中构造与 DLT 校验改为：

```rust
        let mut capture = Self {
            api,
            handle,
            datalink: 0,
            link_type: LinkType::Ethernet,
            snaplen,
            backend_version: None,
        };

        // SAFETY: handle 由 pcap_open_live 返回且非空。
        let datalink = unsafe { (capture.api.datalink)(capture.handle) };
        let Some(link_type) = LinkType::from_datalink(datalink) else {
            return Err(LiveError::UnsupportedDatalink(datalink));
        };
        capture.datalink = datalink;
        capture.link_type = link_type;
```

4. 在 `datalink()` 方法后加入：

```rust
    pub(crate) fn link_type(&self) -> LinkType {
        self.link_type
    }
```

修改 `src/live/mod.rs`：

1. `LiveCapture::datalink` 的 rustdoc 改为：

```rust
    /// pcap 链路层类型（1 = DLT_EN10MB，113 = SLL，276 = SLL2，12 = RAW）。
    pub fn datalink(&self) -> i32 {
        self.handle.datalink()
    }

    /// 链路层类型（Ethernet / LinuxSll / LinuxSll2 / RawIp）。
    pub fn link_type(&self) -> LinkType {
        self.handle.link_type()
    }
```

2. `LiveError::UnsupportedDatalink` 的错误文本改为：

```rust
    /// 非支持的链路层
    #[error(
        "unsupported data link type {0}; supported: DLT_EN10MB=1, DLT_LINUX_SLL=113, \
         DLT_LINUX_SLL2=276, DLT_RAW=12, DLT_IPV4=228, DLT_IPV6=229"
    )]
    UnsupportedDatalink(i32),
```

- [ ] **Step 7: 单线程 CLI 改用 `LinkType`，删除 `is_ip_ethernet_frame`**

修改 `src/bin/rdpi.rs`：

1. 删除 `is_ip_ethernet_frame` 函数（原 325-353 行）及其测试 `ip_frame_detection_handles_ethernet_and_vlan`（原 831-857 行）。

2. `run_live` 改为：

```rust
#[cfg(feature = "live")]
fn run_live(
    device: String,
    filter: Option<String>,
    count: Option<u64>,
    duration: Option<u64>,
    output: &str,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use rdpi::live::{CaptureConfig, LinkType, LiveCapture};

    let mut config = CaptureConfig::new(device);
    if let Some(filter) = filter {
        config = config.filter(filter);
    }

    let mut capture = LiveCapture::open(config)?;
    let link_type = capture.link_type();
    let mut detector = Detector::new();
    let mut sink = OutputSink::new(output, verbose);
    let start = Instant::now();
    let duration = duration.map(std::time::Duration::from_secs);

    loop {
        if let Some(limit) = count
            && sink.total() >= limit
        {
            break;
        }
        if let Some(limit) = duration
            && start.elapsed() >= limit
        {
            break;
        }

        let Some(frame) = capture.next_frame()? else {
            continue;
        };
        let Some(l3) = link_type.l3_payload(&frame.data) else {
            // ARP/LLDP 等非 IP 帧计为未识别包，继续抓取。
            sink.on_packet(frame.timestamp_us, None)?;
            continue;
        };
        let detection = match link_type {
            LinkType::Ethernet => {
                detector.process_packet(&frame.data, frame.timestamp_us / 1000)?
            }
            _ => detector.process_ip_packet(l3, frame.timestamp_us / 1000)?,
        };
        sink.on_packet(frame.timestamp_us, detection)?;
    }

    sink.finish(start.elapsed(), Some(&detector))?;
    Ok(())
}
```

- [ ] **Step 8: 更新示例**

把 `examples/live_capture.rs` 改为：

```rust
//! 实时抓包示例。
//!
//! 用法：
//! `cargo run --features live --example live_capture -- <iface> [count]`

use rdpi::Detector;
use rdpi::live::{CaptureConfig, LinkType, LiveCapture};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = std::env::args()
        .nth(1)
        .ok_or("usage: live_capture <iface> [count]")?;
    let count: usize = std::env::args()
        .nth(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or(10);

    let capture = LiveCapture::open(CaptureConfig::new(device.clone()).timeout_ms(200))?;
    let link_type = capture.link_type();
    println!(
        "capturing on {device} (link={link_type:?}, datalink={}, backend={:?})",
        capture.datalink(),
        capture.backend_version()
    );

    let mut detector = Detector::new();
    for frame in capture.take(count) {
        let frame = frame?;
        let Some(l3) = link_type.l3_payload(&frame.data) else {
            // 实时链路会混有 ARP/LLDP 等非 IP 帧；跳过。
            continue;
        };
        let detection = match link_type {
            LinkType::Ethernet => {
                detector.process_packet(&frame.data, frame.timestamp_us / 1000)
            }
            _ => detector.process_ip_packet(l3, frame.timestamp_us / 1000),
        };
        let Ok(Some(result)) = detection else {
            continue;
        };
        println!(
            "{} bytes -> {:?} [{:?}]",
            frame.original_len, result.protocol, result.confidence
        );
    }

    Ok(())
}
```

- [ ] **Step 9: 编译与测试**

Run: `cargo test --features live live::link`

Expected: `test result: ok. 7 passed`。

Run: `cargo test --features "pcap live" --bin rdpi`

Expected: 全部通过（`is_ip_ethernet_frame` 测试已删除）。

Run: `cargo build --features "pcap live" --bin rdpi`
Run: `cargo build --features live --example live_capture`

Expected: 两条构建命令成功。

- [ ] **Step 10: 提交**

```bash
git add src/parser/mod.rs src/live/link.rs src/live/ffi.rs src/live/mod.rs src/bin/rdpi.rs examples/live_capture.rs
git commit -m "Add live link type support"
```

---

### Task 3: 归一化流公共排序

**Files:**
- Modify: `src/parity.rs:173-195`
- Modify: `src/lib.rs:1824-1832`

**Interfaces:**
- Produces: `pub fn parity::sort_normalized_flows(flows: &mut [NormalizedFlow])`。
- Consumes: 现有 `NormalizedFlow::export_sort_key`。

- [ ] **Step 1: 写失败测试**

在 `src/parity.rs` 末尾加入：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn flow(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> NormalizedFlow {
        NormalizedFlow {
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            src_port,
            dst_port,
            transport: "tcp".to_string(),
            master_protocol: None,
            app_protocol: None,
            category: None,
            breed: None,
            confidence: None,
            protocol_stack: Vec::new(),
            risk_mask: Vec::new(),
        }
    }

    #[test]
    fn sort_prefers_richer_records_then_endpoints() {
        let mut rich = flow("10.0.0.9", 1, "10.0.0.10", 2);
        rich.master_protocol = Some("Http".to_string());

        let mut flows = vec![flow("10.0.0.1", 1, "10.0.0.2", 2), rich];
        sort_normalized_flows(&mut flows);

        assert_eq!(flows[0].master_protocol.as_deref(), Some("Http"));
    }

    #[test]
    fn sort_orders_equal_richness_by_endpoint() {
        let mut flows = vec![
            flow("10.0.0.3", 1, "10.0.0.4", 2),
            flow("10.0.0.1", 9, "10.0.0.2", 2),
            flow("10.0.0.1", 5, "10.0.0.2", 2),
        ];
        sort_normalized_flows(&mut flows);

        assert_eq!(flows[0].src_ip, "10.0.0.1");
        assert_eq!(flows[0].src_port, 5);
        assert_eq!(flows[1].src_port, 9);
        assert_eq!(flows[2].src_ip, "10.0.0.3");
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features json parity::tests`

Expected: 编译失败，报 `cannot find function 'sort_normalized_flows' in this scope`。

- [ ] **Step 3: 实现公共排序函数并复用**

在 `src/parity.rs` 的 `impl NormalizedFlow` 结束后加入：

```rust
/// 按“信息量优先 + 端点字典序”排序归一化流记录。
///
/// `Detector::normalized_flows` 与 CLI 多线程收尾共用该函数，保证单/多线程
/// 导出顺序同构。
pub fn sort_normalized_flows(flows: &mut [NormalizedFlow]) {
    flows.sort_by(|a, b| a.export_sort_key().cmp(&b.export_sort_key()));
}
```

把 `src/lib.rs` 中 `normalized_flows` 的排序行：

```rust
        flows.sort_by(|a, b| a.export_sort_key().cmp(&b.export_sort_key()));
```

替换为：

```rust
        parity::sort_normalized_flows(&mut flows);
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --features json parity::tests`

Expected: `test result: ok. 2 passed`。

Run: `cargo test --all-features --test parity_export`

Expected: 全部通过（flows 输出顺序无回归）。

- [ ] **Step 5: 提交**

```bash
git add src/parity.rs src/lib.rs
git commit -m "Expose normalized flow sorting"
```

---

### Task 4: Ctrl-C 中断标志

**Files:**
- Modify: `Cargo.toml:11-20`、`Cargo.toml:50`
- Create: `src/live/signal.rs`
- Modify: `src/live/mod.rs:7-9`、`src/live/mod.rs:221-227`
- Modify: `src/bin/rdpi.rs:355-403`
- Test: `tests/test_live.rs`

**Interfaces:**
- Produces: `pub struct live::InterruptFlag`（`install() -> Result<Self, LiveError>`、`is_requested() -> bool`、`Default`、`Clone`）；`LiveError::Signal(String)`。
- Consumes: `ctrlc = "3"`。

- [ ] **Step 1: 写失败测试**

在 `src/live/signal.rs` 中创建（先只放类型与测试）：

```rust
//! 跨平台 Ctrl-C 中断标志（仅 live feature）。

use super::LiveError;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// 跨平台 Ctrl-C 中断标志。
///
/// 第一次信号置位 `requested`；第二次信号直接 `std::process::exit(130)`。
#[derive(Clone)]
pub struct InterruptFlag {
    requested: Arc<AtomicBool>,
    signals: Arc<AtomicU8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_flag_is_not_requested() {
        assert!(!InterruptFlag::default().is_requested());
    }

    #[test]
    fn clones_share_the_requested_state() {
        let flag = InterruptFlag::default();
        let clone = flag.clone();
        flag.requested.store(true, Ordering::SeqCst);
        assert!(clone.is_requested());
    }
}
```

在 `tests/test_live.rs` 末尾加入：

```rust
#[test]
fn signal_error_mentions_ctrl_c() {
    let error = LiveError::Signal("already installed".to_string());
    assert!(error.to_string().contains("Ctrl-C"));
}
```

在 `src/live/mod.rs` 中加入：

```rust
mod signal;

pub use signal::InterruptFlag;
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features live live::signal`

Expected: 编译失败（`InterruptFlag` 缺少 `install`/`is_requested`/`Default`，`LiveError::Signal` 不存在，依赖 `ctrlc` 未声明）。

- [ ] **Step 3: 添加依赖并实现 `InterruptFlag`**

`Cargo.toml` 依赖区加入：

```toml
ctrlc = { version = "3", optional = true }
```

`live` feature 改为：

```toml
live = ["dep:libloading", "dep:ctrlc"]  # 实时抓包适配层（动态加载 Npcap/libpcap + Ctrl-C）
```

在 `src/live/signal.rs` 的 `InterruptFlag` 定义后加入：

```rust
impl InterruptFlag {
    /// 安装进程级 Ctrl-C 处理器；重复安装返回错误。
    pub fn install() -> Result<Self, LiveError> {
        let flag = Self::default();
        let requested = Arc::clone(&flag.requested);
        let signals = Arc::clone(&flag.signals);
        ctrlc::set_handler(move || {
            match signals.fetch_add(1, Ordering::SeqCst) {
                0 => requested.store(true, Ordering::SeqCst),
                _ => std::process::exit(130),
            }
        })
        .map_err(|error| LiveError::Signal(error.to_string()))?;
        Ok(flag)
    }

    /// 是否已收到第一次 Ctrl-C。
    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }
}

impl Default for InterruptFlag {
    fn default() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
            signals: Arc::new(AtomicU8::new(0)),
        }
    }
}
```

在 `src/live/mod.rs` 的 `LiveError` 中加入变体（放在 `Filter` 之后）：

```rust
    /// Ctrl-C 处理器安装失败
    #[error("failed to install Ctrl-C handler: {0}")]
    Signal(String),
```

- [ ] **Step 4: 接线到单线程实时循环**

修改 `src/bin/rdpi.rs` 的 `run_live`：

1. 打开抓包后安装处理器：

```rust
    let interrupt = match rdpi::live::InterruptFlag::install() {
        Ok(flag) => flag,
        Err(error) => {
            eprintln!("warning: failed to install Ctrl-C handler: {error}");
            rdpi::live::InterruptFlag::default()
        }
    };
```

2. 循环顶部增加：

```rust
        if interrupt.is_requested() {
            break;
        }
```

3. 循环结束后、`sink.finish` 前增加：

```rust
    if interrupt.is_requested() {
        eprintln!("interrupted");
    }
```

- [ ] **Step 5: 运行测试确认通过**

Run: `cargo test --features live live::signal`

Expected: `test result: ok. 2 passed`。

Run: `cargo test --features live --test test_live`

Expected: 全部通过（含新增 `signal_error_mentions_ctrl_c`）。

Run: `cargo build --features "pcap live" --bin rdpi`

Expected: 成功（首次会下载并编译 `ctrlc` 及其平台依赖）。

- [ ] **Step 6: 提交**

```bash
git add Cargo.toml Cargo.lock src/live/signal.rs src/live/mod.rs src/bin/rdpi.rs tests/test_live.rs
git commit -m "Add Ctrl-C interrupt flag"
```

---

### Task 5: 输出端序号与多 detector 收尾

**Files:**
- Modify: `src/bin/rdpi.rs:114-258`、`src/bin/rdpi.rs:260-277`、`src/bin/rdpi.rs:355-403`、`src/bin/rdpi.rs:773-829`

**Interfaces:**
- Produces: `OutputSink::on_packet_numbered(&mut self, packet_no: u64, timestamp_us: u64, detection: Option<DetectionResult>) -> Result<(), Box<dyn std::error::Error>>`；`OutputSink::finish(&mut self, elapsed: std::time::Duration, detectors: &[Detector]) -> Result<(), Box<dyn std::error::Error>>`；`#[cfg(feature = "json")] fn merged_normalized_flows(detectors: &[Detector]) -> Vec<rdpi::parity::NormalizedFlow>`。
- Consumes: Task 3 的 `parity::sort_normalized_flows`。

- [ ] **Step 1: 写失败测试**

在 `src/bin/rdpi.rs` 的 `tests` 模块中加入：

```rust
    #[test]
    fn numbered_packets_keep_capture_order_numbers() {
        use rdpi::core::types::Protocol;

        let mut sink = OutputSink::new("csv", false);
        sink.on_packet_numbered(9, 0, Some(DetectionResult::new(Protocol::Tcp)))
            .unwrap();
        sink.on_packet_numbered(3, 0, None).unwrap();

        assert_eq!(sink.total(), 2);
        assert_eq!(sink.detected(), 1);
        assert_eq!(sink.protocol_counts().get("Tcp"), Some(&1));
    }
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features "pcap live" --bin rdpi numbered_packets`

Expected: 编译失败，报 `no method named 'on_packet_numbered'`。

- [ ] **Step 3: 实现 `on_packet_numbered` 并让 `on_packet` 委托**

把 `src/bin/rdpi.rs` 中的 `on_packet`（原 114-185 行）替换为：

```rust
    fn on_packet(
        &mut self,
        timestamp_us: u64,
        detection: Option<DetectionResult>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let packet_no = self.total_packets + 1;
        self.on_packet_numbered(packet_no, timestamp_us, detection)
    }

    /// 以抓包序号记录一个包。
    ///
    /// 多线程收集端按完成顺序到达，`packet_no` 由抓包线程按抓取顺序分配，
    /// 因此可能乱序；`json` 收尾时按该序号重排恢复抓包顺序。
    fn on_packet_numbered(
        &mut self,
        packet_no: u64,
        timestamp_us: u64,
        detection: Option<DetectionResult>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(feature = "json"))]
        let _ = timestamp_us;

        self.total_packets += 1;

        match detection {
            Some(detection) => {
                self.detected_packets += 1;
                *self
                    .protocol_counts
                    .entry(format!("{:?}", detection.protocol))
                    .or_insert(0) += 1;

                if !self.verbose || self.output == "flows-jsonl" {
                    return Ok(());
                }

                #[cfg(feature = "json")]
                match self.output {
                    "jsonl" => {
                        println!(
                            "{}",
                            serde_json::to_string(&PacketRecord::new(
                                packet_no,
                                timestamp_us,
                                detection
                            ))?
                        );
                        return Ok(());
                    }
                    "json" => {
                        self.packet_records.push(PacketRecord::new(
                            packet_no,
                            timestamp_us,
                            detection,
                        ));
                        return Ok(());
                    }
                    _ => {}
                }

                print_detection(packet_no, &detection);
            }
            None => {
                if !self.verbose || self.output == "flows-jsonl" {
                    return Ok(());
                }

                #[cfg(feature = "json")]
                if self.output == "jsonl" {
                    println!(
                        "{}",
                        serde_json::to_string(&UnknownRecord {
                            r#type: "unknown",
                            packet_no,
                        })?
                    );
                    return Ok(());
                }

                println!("[{:6}] UNKNOWN", packet_no);
            }
        }

        Ok(())
    }
```

- [ ] **Step 4: 实现多 detector 收尾**

在 `impl OutputSink` 外、`run_file` 之前加入：

```rust
/// 合并多个 worker 的归一化流并全局排序（`feature: json`）。
#[cfg(feature = "json")]
fn merged_normalized_flows(detectors: &[Detector]) -> Vec<rdpi::parity::NormalizedFlow> {
    let mut flows = Vec::new();
    for detector in detectors {
        flows.extend(detector.normalized_flows());
    }
    rdpi::parity::sort_normalized_flows(&mut flows);
    flows
}
```

把 `finish`（原 187-257 行）替换为：

```rust
    fn finish(
        &mut self,
        elapsed: std::time::Duration,
        detectors: &[Detector],
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(feature = "json"))]
        let _ = detectors;

        if self.output == "flows-jsonl" {
            #[cfg(feature = "json")]
            for flow in merged_normalized_flows(detectors) {
                println!("{}", serde_json::to_string(&flow)?);
            }
            return Ok(());
        }

        match self.output {
            "json" => {
                #[cfg(feature = "json")]
                {
                    // 多线程下逐包记录按完成顺序入列；收尾按抓包序号恢复顺序。
                    self.packet_records.sort_by_key(|record| record.packet_no);
                    let summary = Summary::build(
                        self.total_packets,
                        self.detected_packets,
                        &self.protocol_counts,
                        elapsed,
                    );
                    let doc = serde_json::json!({
                        "summary": summary,
                        "packets": &self.packet_records
                    });
                    println!("{}", serde_json::to_string_pretty(&doc)?);
                }
                #[cfg(not(feature = "json"))]
                print_json_summary(
                    self.total_packets,
                    self.detected_packets,
                    &self.protocol_counts,
                    elapsed,
                );
            }
            "jsonl" => {
                #[cfg(feature = "json")]
                {
                    let summary = Summary::build(
                        self.total_packets,
                        self.detected_packets,
                        &self.protocol_counts,
                        elapsed,
                    );
                    println!(
                        "{}",
                        serde_json::to_string(&JsonlLine {
                            r#type: "summary",
                            summary: &summary,
                        })?
                    );
                }
            }
            "csv" => print_csv_summary(&self.protocol_counts),
            _ => print_text_summary(
                self.total_packets,
                self.detected_packets,
                &self.protocol_counts,
                elapsed,
            ),
        }

        Ok(())
    }
```

- [ ] **Step 5: 更新两个调用点**

`run_file` 末尾：

```rust
    sink.finish(start.elapsed(), std::slice::from_ref(iter.detector()))?;
```

单线程 `run_live` 末尾：

```rust
    sink.finish(start.elapsed(), std::slice::from_ref(&detector))?;
```

- [ ] **Step 6: 运行测试确认通过**

Run: `cargo test --features "pcap live" --bin rdpi numbered_packets`

Expected: `test result: ok. 1 passed`。

Run: `cargo test --features "pcap json" --bin rdpi`

Expected: 全部通过（`json` 模式下 `packet_records` 字段与排序逻辑可编译）。

Run: `cargo test --features "pcap live json"`

Expected: 全部通过（flows-jsonl 合并路径可编译）。

- [ ] **Step 7: 提交**

```bash
git add src/bin/rdpi.rs
git commit -m "Add numbered output sink records"
```

---

### Task 6: 并行抓包管线与 CLI `-n`

**Files:**
- Modify: `src/live/ffi.rs`（`unsafe impl Send`）
- Modify: `src/live/mod.rs`（`LiveCapture` rustdoc）
- Create: `src/bin/rdpi/live_runner.rs`
- Modify: `src/bin/rdpi.rs`（`-n` 参数、校验、委托、删除旧实时循环）
- Test: `src/bin/rdpi/live_runner.rs` 内嵌单测、`src/bin/rdpi.rs` 测试

**Interfaces:**
- Consumes: Task 1-5 的全部产出。
- Produces: `live_runner::run_live(device, filter, count, duration, output, verbose, threads) -> Result<(), Box<dyn std::error::Error>>`；`live_runner::MAX_THREADS` 与主模块共享的 `const MAX_THREADS: usize = 64`；CLI `-n/--threads`。

- [ ] **Step 1: 写失败测试**

创建 `src/bin/rdpi/live_runner.rs`，先只放管线骨架与测试（实现体下一步补齐）：

```rust
//! 实时抓包并行管线：单抓包线程 + N 个检测 worker + 主线程收集。

use rdpi::live::{
    CaptureConfig, CapturedFrame, InterruptFlag, LinkType, LiveCapture, LiveError,
};
use rdpi::{DetectionResult, Detector};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use super::{MAX_THREADS, OutputSink};

/// 每个 worker 的有界队列容量（背压上限）。
const WORKER_QUEUE_CAPACITY: usize = 1024;
/// FNV-1a 64 位偏移基数。
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64 位质数。
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// 抓包线程投递给 worker 的一帧。
struct WorkItem {
    packet_no: u64,
    timestamp_us: u64,
    data: Vec<u8>,
}

/// 抓包线程的不可变运行参数。
struct CapturePlan {
    link_type: LinkType,
    threads: usize,
    count: Option<u64>,
    duration: Option<Duration>,
}

/// worker/抓包线程发给主线程收集器的事件。
///
/// `Packet` 携带完整检测结果；为避免每包一次 `Box` 分配，接受枚举变体较大
/// （收集端串行处理，事件生命周期短）。
#[allow(clippy::large_enum_variant)]
enum LiveEvent {
    Packet {
        packet_no: u64,
        timestamp_us: u64,
        detection: Option<DetectionResult>,
    },
    Fatal(String),
    Finished(Box<Detector>),
}

/// 抓包来源抽象：生产路径为 [`LiveCapture`]，测试注入合成帧。
trait FrameSource {
    fn next_frame(&mut self) -> Result<Option<CapturedFrame>, LiveError>;
    fn link_type(&self) -> LinkType;
}

impl FrameSource for LiveCapture {
    fn next_frame(&mut self) -> Result<Option<CapturedFrame>, LiveError> {
        LiveCapture::next_frame(self)
    }

    fn link_type(&self) -> LinkType {
        LiveCapture::link_type(self)
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameSource, flow_shard, run_source};
    use crate::OutputSink;
    use rdpi::Detector;
    use rdpi::live::{CapturedFrame, InterruptFlag, LinkType, LiveError};

    fn ipv4_udp(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = 20 + 8 + payload.len();
        let mut packet = Vec::with_capacity(total_len);
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.push(64);
        packet.push(17);
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&src);
        packet.extend_from_slice(&dst);
        packet.extend_from_slice(&sport.to_be_bytes());
        packet.extend_from_slice(&dport.to_be_bytes());
        packet.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn eth_ipv4_udp(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + 20 + 8 + payload.len());
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&ipv4_udp(src, sport, dst, dport, payload));
        frame
    }

    fn ipv6_udp(
        src: [u8; 16],
        sport: u16,
        dst: [u8; 16],
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src);
        packet[24..40].copy_from_slice(&dst);
        packet.extend_from_slice(&sport.to_be_bytes());
        packet.extend_from_slice(&dport.to_be_bytes());
        packet.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn dns_query(domain: &str) -> Vec<u8> {
        let mut query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        query
    }

    fn dns_response(domain: &str) -> Vec<u8> {
        let mut response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            response.push(label.len() as u8);
            response.extend_from_slice(label.as_bytes());
        }
        response.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 10, 0, 0, 2,
        ]);
        response
    }

    fn captured(data: Vec<u8>, timestamp_us: u64) -> CapturedFrame {
        CapturedFrame {
            original_len: data.len() as u32,
            data,
            timestamp_us,
        }
    }

    fn arp_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 28]);
        frame
    }

    struct FakeSource {
        frames: std::vec::IntoIter<CapturedFrame>,
        link_type: LinkType,
    }

    impl FrameSource for FakeSource {
        fn next_frame(&mut self) -> Result<Option<CapturedFrame>, LiveError> {
            Ok(self.frames.next())
        }

        fn link_type(&self) -> LinkType {
            self.link_type
        }
    }

    #[test]
    fn live_capture_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<LiveCapture>();
    }

    #[test]
    fn flow_shard_is_direction_independent_for_ipv4() {
        let forward = eth_ipv4_udp([10, 0, 0, 1], 40_000, [10, 0, 0, 2], 53, &[]);
        let reverse = eth_ipv4_udp([10, 0, 0, 2], 53, [10, 0, 0, 1], 40_000, &[]);
        assert_eq!(
            flow_shard(&forward, LinkType::Ethernet, 16),
            flow_shard(&reverse, LinkType::Ethernet, 16)
        );
    }

    #[test]
    fn flow_shard_is_direction_independent_for_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let forward = ipv6_udp(src, 40_000, dst, 53, &[]);
        let reverse = ipv6_udp(dst, 53, src, 40_000, &[]);
        assert_eq!(
            flow_shard(&forward, LinkType::RawIp, 16),
            flow_shard(&reverse, LinkType::RawIp, 16)
        );
    }

    #[test]
    fn flow_shard_ignores_non_ip_frames() {
        assert_eq!(flow_shard(&arp_frame(), LinkType::Ethernet, 4), None);
        assert_eq!(flow_shard(&[0u8; 8], LinkType::RawIp, 4), None);
    }

    #[test]
    fn flow_shard_spreads_flows_across_workers() {
        let mut shards = std::collections::HashSet::new();
        for last in 1..=64u8 {
            let frame = eth_ipv4_udp([10, 0, 0, last], 40_000, [10, 0, 0, 200], 53, &[]);
            shards.insert(flow_shard(&frame, LinkType::Ethernet, 4).unwrap());
        }
        assert!(shards.len() > 1, "all flows mapped to {shards:?}");
    }

    #[test]
    fn parallel_pipeline_merges_bidirectional_flow() {
        let frames = vec![
            captured(
                eth_ipv4_udp(
                    [10, 0, 0, 1],
                    40_000,
                    [10, 0, 0, 2],
                    53,
                    &dns_query("example.com"),
                ),
                1,
            ),
            captured(
                eth_ipv4_udp(
                    [10, 0, 0, 2],
                    53,
                    [10, 0, 0, 1],
                    40_000,
                    &dns_response("example.com"),
                ),
                2,
            ),
            captured(arp_frame(), 3),
        ];
        let source = FakeSource {
            frames: frames.into_iter(),
            link_type: LinkType::Ethernet,
        };
        let interrupt = InterruptFlag::default();
        let mut sink = OutputSink::new("csv", false);

        let detectors = run_source(source, 2, Some(3), None, &interrupt, &mut sink).unwrap();

        assert_eq!(sink.total(), 3);
        assert_eq!(sink.detected(), 2);
        assert_eq!(detectors.iter().map(|d| d.flow_count()).sum::<usize>(), 1);
    }

    #[test]
    fn parallel_pipeline_handles_sll_frames() {
        let mut frame = vec![0u8; 16];
        frame[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ipv4_udp(
            [10, 0, 0, 1],
            40_000,
            [10, 0, 0, 2],
            53,
            &dns_query("example.com"),
        ));
        let source = FakeSource {
            frames: vec![captured(frame, 1)].into_iter(),
            link_type: LinkType::LinuxSll,
        };
        let interrupt = InterruptFlag::default();
        let mut sink = OutputSink::new("csv", false);

        let detectors = run_source(source, 2, Some(1), None, &interrupt, &mut sink).unwrap();

        assert_eq!(sink.total(), 1);
        assert_eq!(sink.detected(), 1);
        assert_eq!(detectors.iter().map(|d| d.flow_count()).sum::<usize>(), 1);
    }

    #[cfg(feature = "json")]
    #[test]
    fn merged_flows_are_sorted_across_detectors() {
        let query = dns_query("example.com");
        let mut first = Detector::new();
        let mut second = Detector::new();
        first
            .process_packet(
                &eth_ipv4_udp([10, 0, 0, 1], 40_000, [10, 0, 0, 2], 53, &query),
                0,
            )
            .unwrap();
        second
            .process_packet(
                &eth_ipv4_udp([10, 0, 0, 3], 40_001, [10, 0, 0, 4], 53, &query),
                0,
            )
            .unwrap();

        let flows = crate::merged_normalized_flows(&[first, second]);
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].src_ip, "10.0.0.1");
        assert_eq!(flows[1].src_ip, "10.0.0.3");
    }
}
```

在 `src/bin/rdpi.rs` 顶部 `use` 后加入：

```rust
/// 实时抓包 worker 线程数上限。
const MAX_THREADS: usize = 64;

#[cfg(feature = "live")]
mod live_runner;
```

在 `src/bin/rdpi.rs` 的 `tests` 模块加入：

```rust
    #[test]
    fn thread_bounds_are_validated() {
        assert!(validate_threads(1).is_ok());
        assert!(validate_threads(MAX_THREADS).is_ok());
        assert!(validate_threads(0).is_err());
        assert!(validate_threads(MAX_THREADS + 1).is_err());
    }
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --features "pcap live" --bin rdpi live_runner`

Expected: 编译失败（`flow_shard`/`run_source`/`validate_threads` 未定义）。

- [ ] **Step 3: 让 `LiveCapture` 可跨线程移动**

在 `src/live/ffi.rs` 的 `CaptureHandle` 定义之后加入：

```rust
// SAFETY: `pcap_t` 只由持有本结构体的线程访问；`open`/`poll`/`Drop` 不做跨线程
// 并发调用。实现 `Send` 以允许 `LiveCapture` 随所有权移动到抓包线程；
// 不实现 `Sync`，引用不得跨线程共享。
unsafe impl Send for CaptureHandle {}
```

把 `src/live/mod.rs` 中 `LiveCapture` 的 rustdoc 改为：

```rust
/// 实时抓包迭代器。
///
/// 每个线程必须独立 `open`；该类型不是 `Sync`，但可通过所有权移动到
/// 其他线程（`Send`）。
```

- [ ] **Step 4: 实现并行管线**

在 `src/bin/rdpi/live_runner.rs` 的 `impl FrameSource for LiveCapture` 之后、测试模块之前加入以下全部实现：

```rust
/// CLI 实时抓包入口。
pub(super) fn run_live(
    device: String,
    filter: Option<String>,
    count: Option<u64>,
    duration: Option<u64>,
    output: &str,
    verbose: bool,
    threads: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = CaptureConfig::new(device);
    if let Some(filter) = filter {
        config = config.filter(filter);
    }
    let capture = LiveCapture::open(config)?;

    let interrupt = match InterruptFlag::install() {
        Ok(flag) => flag,
        Err(error) => {
            eprintln!("warning: failed to install Ctrl-C handler: {error}");
            InterruptFlag::default()
        }
    };

    let start = Instant::now();
    let mut sink = OutputSink::new(output, verbose);
    let detectors = run_source(
        capture,
        threads,
        count,
        duration.map(Duration::from_secs),
        &interrupt,
        &mut sink,
    )?;
    if interrupt.is_requested() {
        eprintln!("interrupted");
    }
    sink.finish(start.elapsed(), &detectors)?;
    Ok(())
}

/// 运行抓包管线并返回各 worker 的检测器（用于合并导出 flows）。
fn run_source<S: FrameSource + Send + 'static>(
    mut source: S,
    threads: usize,
    count: Option<u64>,
    duration: Option<Duration>,
    interrupt: &InterruptFlag,
    sink: &mut OutputSink<'_>,
) -> Result<Vec<Detector>, Box<dyn std::error::Error>> {
    if !(1..=MAX_THREADS).contains(&threads) {
        return Err(format!("--threads must be between 1 and {MAX_THREADS}").into());
    }

    let link_type = source.link_type();
    if threads == 1 {
        return run_single(&mut source, link_type, count, duration, interrupt, sink);
    }
    run_parallel(source, link_type, threads, count, duration, interrupt, sink)
}

/// `-n 1`：保留 F47 的单线程循环（输出顺序完全一致）。
fn run_single<S: FrameSource>(
    source: &mut S,
    link_type: LinkType,
    count: Option<u64>,
    duration: Option<Duration>,
    interrupt: &InterruptFlag,
    sink: &mut OutputSink<'_>,
) -> Result<Vec<Detector>, Box<dyn std::error::Error>> {
    let mut detector = Detector::new();
    let start = Instant::now();
    let mut read_packets = 0u64;

    loop {
        if interrupt.is_requested() {
            break;
        }
        if let Some(limit) = count
            && read_packets >= limit
        {
            break;
        }
        if let Some(limit) = duration
            && start.elapsed() >= limit
        {
            break;
        }

        let Some(frame) = source.next_frame()? else {
            continue;
        };
        read_packets += 1;

        let Some(l3) = link_type.l3_payload(&frame.data) else {
            sink.on_packet(frame.timestamp_us, None)?;
            continue;
        };
        let detection = match link_type {
            LinkType::Ethernet => {
                detector.process_packet(&frame.data, frame.timestamp_us / 1000)?
            }
            _ => detector.process_ip_packet(l3, frame.timestamp_us / 1000)?,
        };
        sink.on_packet(frame.timestamp_us, detection)?;
    }

    Ok(vec![detector])
}

/// `-n > 1`：单抓包线程 + flow-hash worker + 主线程收集。
fn run_parallel<S: FrameSource + Send + 'static>(
    capture: S,
    link_type: LinkType,
    threads: usize,
    count: Option<u64>,
    duration: Option<Duration>,
    interrupt: &InterruptFlag,
    sink: &mut OutputSink<'_>,
) -> Result<Vec<Detector>, Box<dyn std::error::Error>> {
    let stop = Arc::new(AtomicBool::new(false));
    let (event_tx, event_rx) = mpsc::channel::<LiveEvent>();

    let mut workers = Vec::with_capacity(threads);
    let mut work_senders = Vec::with_capacity(threads);
    for index in 0..threads {
        let (sender, receiver) = mpsc::sync_channel::<WorkItem>(WORKER_QUEUE_CAPACITY);
        work_senders.push(sender);
        let worker_tx = event_tx.clone();
        let worker_stop = Arc::clone(&stop);
        match thread::Builder::new()
            .name(format!("rdpi-worker-{index}"))
            .spawn(move || worker_loop(receiver, worker_tx, worker_stop, link_type))
        {
            Ok(handle) => workers.push(handle),
            Err(error) => {
                stop.store(true, Ordering::SeqCst);
                drop(work_senders);
                for handle in workers {
                    let _ = handle.join();
                }
                return Err(format!("failed to spawn worker thread: {error}").into());
            }
        }
    }

    let capture_stop = Arc::clone(&stop);
    let capture_tx = event_tx.clone();
    let capture_interrupt = interrupt.clone();
    let plan = CapturePlan {
        link_type,
        threads,
        count,
        duration,
    };
    let capture_thread = thread::Builder::new()
        .name("rdpi-capture".to_string())
        .spawn(move || {
            capture_loop(
                capture,
                plan,
                &capture_interrupt,
                &capture_stop,
                work_senders,
                &capture_tx,
            );
        });

    let capture_thread = match capture_thread {
        Ok(handle) => handle,
        Err(error) => {
            stop.store(true, Ordering::SeqCst);
            drop(event_tx);
            for handle in workers {
                let _ = handle.join();
            }
            return Err(format!("failed to spawn capture thread: {error}").into());
        }
    };

    drop(event_tx);

    let mut detectors = Vec::with_capacity(threads);
    let mut fatal: Option<String> = None;
    let mut sink_error: Option<Box<dyn std::error::Error>> = None;
    for event in event_rx {
        match event {
            LiveEvent::Packet {
                packet_no,
                timestamp_us,
                detection,
            } => {
                if sink_error.is_none()
                    && let Err(error) =
                        sink.on_packet_numbered(packet_no, timestamp_us, detection)
                {
                    stop.store(true, Ordering::SeqCst);
                    sink_error = Some(error);
                }
            }
            LiveEvent::Fatal(message) => {
                if fatal.is_none() {
                    fatal = Some(message);
                }
            }
            LiveEvent::Finished(detector) => detectors.push(*detector),
        }
    }

    let capture_panicked = capture_thread.join().is_err();
    let mut worker_panicked = false;
    for handle in workers {
        worker_panicked |= handle.join().is_err();
    }

    if capture_panicked {
        return Err(LiveError::Capture("capture thread panicked".to_string()).into());
    }
    if worker_panicked {
        return Err(LiveError::Capture("worker thread panicked".to_string()).into());
    }
    if let Some(error) = sink_error {
        return Err(error);
    }
    if let Some(message) = fatal {
        return Err(message.into());
    }

    Ok(detectors)
}

/// 抓包线程：读帧、按 flow hash 投递、非 IP 帧直接发事件。
fn capture_loop<S: FrameSource>(
    mut capture: S,
    plan: CapturePlan,
    interrupt: &InterruptFlag,
    stop: &AtomicBool,
    senders: Vec<SyncSender<WorkItem>>,
    event_tx: &Sender<LiveEvent>,
) {
    let start = Instant::now();
    let mut read_packets = 0u64;

    loop {
        if stop.load(Ordering::SeqCst) || interrupt.is_requested() {
            break;
        }
        if let Some(limit) = plan.count
            && read_packets >= limit
        {
            break;
        }
        if let Some(limit) = plan.duration
            && start.elapsed() >= limit
        {
            break;
        }

        let frame = match capture.next_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => continue,
            Err(error) => {
                stop.store(true, Ordering::SeqCst);
                let _ = event_tx.send(LiveEvent::Fatal(error.to_string()));
                break;
            }
        };
        read_packets += 1;

        match flow_shard(&frame.data, plan.link_type, plan.threads) {
            Some(shard) => {
                let item = WorkItem {
                    packet_no: read_packets,
                    timestamp_us: frame.timestamp_us,
                    data: frame.data,
                };
                if senders[shard].send(item).is_err() {
                    stop.store(true, Ordering::SeqCst);
                    break;
                }
            }
            None => {
                let packet = LiveEvent::Packet {
                    packet_no: read_packets,
                    timestamp_us: frame.timestamp_us,
                    detection: None,
                };
                if event_tx.send(packet).is_err() {
                    stop.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    }
}

/// worker：独占一个 `Detector`，排空队列后发送 `Finished`。
fn worker_loop(
    receiver: Receiver<WorkItem>,
    event_tx: Sender<LiveEvent>,
    stop: Arc<AtomicBool>,
    link_type: LinkType,
) {
    let mut detector = Detector::new();
    for item in receiver {
        let detection =
            match process_item(&mut detector, link_type, &item.data, item.timestamp_us / 1000) {
                Ok(detection) => detection,
                Err(error) => {
                    stop.store(true, Ordering::SeqCst);
                    let _ = event_tx.send(LiveEvent::Fatal(error.to_string()));
                    break;
                }
            };
        if event_tx
            .send(LiveEvent::Packet {
                packet_no: item.packet_no,
                timestamp_us: item.timestamp_us,
                detection,
            })
            .is_err()
        {
            break;
        }
    }
    let _ = event_tx.send(LiveEvent::Finished(Box::new(detector)));
}

fn process_item(
    detector: &mut Detector,
    link_type: LinkType,
    data: &[u8],
    timestamp_ms: u64,
) -> Result<Option<DetectionResult>, rdpi::Error> {
    match link_type {
        LinkType::Ethernet => detector.process_packet(data, timestamp_ms),
        _ => match link_type.l3_payload(data) {
            Some(l3) => detector.process_ip_packet(l3, timestamp_ms),
            None => Ok(None),
        },
    }
}

/// 方向无关的流分片：返回 `[0, threads)` 或 `None`（非 IP/畸形）。
fn flow_shard(frame: &[u8], link_type: LinkType, threads: usize) -> Option<usize> {
    let l3 = link_type.l3_payload(frame)?;
    let hash = flow_hash(l3)?;
    Some((hash % threads as u64) as usize)
}

fn flow_hash(l3: &[u8]) -> Option<u64> {
    match l3.first()? >> 4 {
        4 => ipv4_hash(l3),
        6 => ipv6_hash(l3),
        _ => None,
    }
}

fn ipv4_hash(l3: &[u8]) -> Option<u64> {
    if l3.len() < 20 {
        return None;
    }
    let ihl = usize::from(l3[0] & 0x0f) * 4;
    if ihl < 20 || l3.len() < ihl {
        return None;
    }
    let protocol = l3[9];
    let fragment_offset = u16::from_be_bytes([l3[6], l3[7]]) & 0x1fff;
    let (src_port, dst_port) = if fragment_offset == 0
        && matches!(protocol, 6 | 17)
        && l3.len() >= ihl + 4
    {
        (
            u16::from_be_bytes([l3[ihl], l3[ihl + 1]]),
            u16::from_be_bytes([l3[ihl + 2], l3[ihl + 3]]),
        )
    } else {
        (0, 0)
    };
    Some(hash_endpoints(
        4,
        protocol,
        &l3[12..16],
        src_port,
        &l3[16..20],
        dst_port,
    ))
}

fn ipv6_hash(l3: &[u8]) -> Option<u64> {
    if l3.len() < 40 {
        return None;
    }
    let next_header = l3[6];
    // 扩展头场景不深解析：仅哈希地址与 Next Header（端口记 0）。
    let (src_port, dst_port) = if matches!(next_header, 6 | 17) && l3.len() >= 44 {
        (
            u16::from_be_bytes([l3[40], l3[41]]),
            u16::from_be_bytes([l3[42], l3[43]]),
        )
    } else {
        (0, 0)
    };
    Some(hash_endpoints(
        6,
        next_header,
        &l3[8..24],
        src_port,
        &l3[24..40],
        dst_port,
    ))
}

fn hash_endpoints(
    version: u8,
    protocol: u8,
    src: &[u8],
    src_port: u16,
    dst: &[u8],
    dst_port: u16,
) -> u64 {
    // 按（地址字节，端口）字典序规范化，保证 A→B 与 B→A 同 shard。
    let (a, a_port, b, b_port) = if (src, src_port) <= (dst, dst_port) {
        (src, src_port, dst, dst_port)
    } else {
        (dst, dst_port, src, src_port)
    };
    let mut hash = fnv1a(FNV_OFFSET, &[version, protocol]);
    hash = fnv1a(hash, a);
    hash = fnv1a(hash, &a_port.to_be_bytes());
    hash = fnv1a(hash, b);
    fnv1a(hash, &b_port.to_be_bytes())
}

fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}
```

- [ ] **Step 5: 添加 CLI `-n` 参数与校验**

修改 `src/bin/rdpi.rs`：

1. `Cli` 增加字段（放在 `--duration` 之后）：

```rust
    /// 实时抓包 worker 线程数（默认 1，范围 1..=64）
    #[arg(short = 'n', long = "threads", value_name = "N", default_value_t = 1)]
    threads: usize,
```

2. 在 `resolve_source` 之前加入：

```rust
fn validate_threads(threads: usize) -> Result<(), String> {
    if !(1..=MAX_THREADS).contains(&threads) {
        return Err(format!("--threads must be between 1 and {MAX_THREADS}"));
    }
    Ok(())
}
```

3. `main` 在 json feature 检查之后加入：

```rust
    if let Err(message) = validate_threads(cli.threads) {
        eprintln!("error: {message}");
        std::process::exit(2);
    }
```

4. `validate_file_options` 增加 `threads` 参数：

```rust
fn validate_file_options(
    filter: Option<&str>,
    count: Option<u64>,
    duration: Option<u64>,
    threads: usize,
) -> Result<(), String> {
    if filter.is_some() {
        return Err("--filter requires a live capture interface".to_string());
    }
    if count.is_some() {
        return Err("--count requires a live capture interface".to_string());
    }
    if duration.is_some() {
        return Err("--duration requires a live capture interface".to_string());
    }
    if threads != 1 {
        return Err("--threads requires a live capture interface".to_string());
    }
    Ok(())
}
```

5. 更新调用点：

```rust
        Source::Live(device) => run_live(
            device,
            cli.filter,
            cli.count,
            cli.duration,
            &cli.output,
            cli.verbose,
            cli.threads,
        ),
        Source::File(path) => {
            if let Err(message) = validate_file_options(
                cli.filter.as_deref(),
                cli.count,
                cli.duration,
                cli.threads,
            ) {
                eprintln!("error: {message}");
                std::process::exit(2);
            }
            run_file(&path, &cli.output, cli.verbose)
        }
```

- [ ] **Step 6: 用 live_runner 替换旧实时循环**

把 `src/bin/rdpi.rs` 中 `#[cfg(feature = "live")] fn run_live(...)` 的整个函数体替换为：

```rust
#[cfg(feature = "live")]
fn run_live(
    device: String,
    filter: Option<String>,
    count: Option<u64>,
    duration: Option<u64>,
    output: &str,
    verbose: bool,
    threads: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    live_runner::run_live(device, filter, count, duration, output, verbose, threads)
}
```

`#[cfg(not(feature = "live"))] fn run_live(...)` 增加 `_threads: usize` 参数：

```rust
#[cfg(not(feature = "live"))]
fn run_live(
    _device: String,
    _filter: Option<String>,
    _count: Option<u64>,
    _duration: Option<u64>,
    _output: &str,
    _verbose: bool,
    _threads: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("error: live capture requires building with --features \"pcap live\"");
    std::process::exit(2);
}
```

- [ ] **Step 7: 更新 CLI 测试**

把 `file_mode_rejects_live_options` 改为：

```rust
    #[test]
    fn file_mode_rejects_live_options() {
        assert!(validate_file_options(Some("tcp"), None, None, 1).is_err());
        assert!(validate_file_options(None, Some(1), None, 1).is_err());
        assert!(validate_file_options(None, None, Some(1), 1).is_err());
        assert!(validate_file_options(None, None, None, 2).is_err());
        assert!(validate_file_options(None, None, None, 1).is_ok());
    }
```

- [ ] **Step 8: 运行测试确认通过**

Run: `cargo test --features "pcap live" --bin rdpi live_runner`

Expected: `test result: ok. 7 passed`。

Run: `cargo test --features "pcap live" --bin rdpi`

Expected: 全部通过（含 `thread_bounds_are_validated`）。

Run: `cargo test --features "pcap live json" --bin rdpi merged_flows`

Expected: `test result: ok. 1 passed`。

- [ ] **Step 9: 提交**

```bash
git add src/live/ffi.rs src/live/mod.rs src/bin/rdpi.rs src/bin/rdpi/live_runner.rs
git commit -m "Add parallel live capture"
```

---

### Task 7: 文档回写与全量验证

**Files:**
- Modify: `README.md:90-105`
- Modify: `AGENTS.md:45`（F47 条目之后）
- Modify: `docs/architecture/ndpi-pure-rust-plan.md:359-365`
- Modify: `docs/architecture/risks.md`（末尾追加 F48）
- Modify: `docs/architecture/live-capture-design.md:462-469`
- Modify: `docs/architecture/live-capture-v2-design.md:3`

**Interfaces:**
- Consumes: Task 1-6 的全部产出。
- Produces: 文档与进度回写；最终门禁验证。

- [ ] **Step 1: 更新 README 实时抓包章节**

把 `README.md` 实时抓包章节的依赖与权限列表替换为：

```markdown
依赖与权限：

- Windows：安装 [Npcap](https://npcap.com/) 运行时；若安装时限制管理员访问驱动，请在管理员终端运行。
- Linux：安装 libpcap 运行时，抓包需要 root 或 `CAP_NET_RAW`。
- macOS：使用系统自带 libpcap。
- 支持以太网（DLT_EN10MB）、Linux SLL/SLL2（`-i any`）与 RAW IPv4/IPv6 链路层；非 IP 帧计为未识别包并跳过。
- `-n/--threads <N>` 启用 N 个检测 worker（默认 1，范围 1..=64）。`-n 1` 输出顺序与单线程一致；`-n > 1` 时逐包行按完成顺序可能乱序，汇总与 `flows-jsonl` 保持确定性。
- 运行中第一次 Ctrl-C 优雅停止并输出汇总（退出码 0）；第二次 Ctrl-C 立即退出（退出码 130）。
```

并在命令示例中追加：

```bash
cargo run --features "pcap live" --bin rdpi -- -i <iface> -n 4 --duration 10
cargo run --features "pcap live" --bin rdpi -- -i any --count 200 -o text   # Linux/WSL
```

- [ ] **Step 2: 更新 AGENTS.md**

在 F47 条目（`- **Live capture（F47，2026-11-08）**...`）之后追加：

```markdown
- **Live capture v2：多线程、Ctrl-C、链路层扩展（F48，2026-11-08）**：兑现 F47 登记的三项后续增量——`-n/--threads`（默认 1，1..=64）单抓包线程 + flow-hash 分片 worker（FNV-1a 规范五元组，双向同 shard；有界队列 1024/worker 背压；`-n 1` 保持 F47 顺序）；主线程收集端合并汇总，`json` 的 packets 按抓包序号重排、`flows-jsonl` 跨 worker 全局排序；`ctrlc`（仅 live feature）首次 Ctrl-C 优雅停止（exit 0）、第二次立即退出（130）；`LinkType` 支持 DLT_EN10MB/SLL/SLL2/RAW（`-i any`），`Detector::process_ip_packet` 为 L3 入口（字节统计按 IP 长度，以太网路径按整帧）；`unsafe` 仍仅限 `src/live/ffi.rs`（新增 `unsafe impl Send for CaptureHandle`）。
```

在常用命令代码块中追加：

```bash
cargo run --features "pcap live" --bin rdpi -- -i any -n 4 --duration 10   # Linux/WSL
```

- [ ] **Step 3: 更新 nDPI 方案 P4 进展**

在 `docs/architecture/ndpi-pure-rust-plan.md` 的 F47 条目之后追加：

```markdown
- **P4 后续切片：Live capture v2（F48，2026-11-08）**
  - `-n/--threads` 多线程检测：单抓包线程 + flow-hash 分片 worker，有界队列背压；`-n 1` 保持 F47 顺序；
  - Ctrl-C 优雅停机：首次输出汇总并 exit 0，第二次强退 130；
  - `LinkType` 支持 DLT_EN10MB/SLL/SLL2/RAW，Linux `any` 设备可用；新增 `Detector::process_ip_packet` L3 入口；
  - `-n > 1` 时逐包行按完成顺序，`json` 的 packets 收尾按抓包序号重排，`flows-jsonl` 跨 worker 全局确定性排序。
```

- [ ] **Step 4: 登记 risks.md**

在 `docs/architecture/risks.md` 末尾追加：

```markdown
## F48【中】Live capture v2：多线程、Ctrl-C 与链路层扩展（2026-11-08，新功能开发）—— ✅ 已完成

- **背景**：兑现 F47 登记的三项后续增量（`docs/architecture/live-capture-v2-design.md`、`docs/architecture/live-capture-v2-plan.md`）。
- **实现**：
  - **多线程**（`src/bin/rdpi/live_runner.rs`）：单抓包线程 + N worker（`-n/--threads`，默认 1，1..=64）；方向无关 FNV-1a 规范五元组分片（`flow_shard`，IPv4/IPv6、TCP/UDP 端口、非 IP 返回 None）；`SyncSender` 有界队列 1024/worker 提供背压；非 IP 帧由抓包线程直接发 `LiveEvent::Packet{detection:None}`。
  - **输出确定性**：`OutputSink::on_packet_numbered` 保留抓包序号；`json` 的 `packets` 收尾按 `packet_no` 排序；`flows-jsonl` 合并各 worker 的 `normalized_flows()` 后调用 `parity::sort_normalized_flows` 全局排序；汇总计数天然合并。
  - **Ctrl-C**（`src/live/signal.rs`，`ctrlc = "3"` 仅 live feature）：首次置位并优雅停止（排空队列、输出汇总、exit 0），第二次 `process::exit(130)`；安装失败打印 warning 并降级。
  - **链路层**（`src/live/link.rs`）：`LinkType{Ethernet,LinuxSll,LinuxSll2,RawIp}` + `l3_payload`（SLL 16B/协议 @14、SLL2 20B/协议 @0、RAW 首半字节 4/6；VLAN/QinQ 栈上限 4）；`LiveCapture::open` 接受对应 DLT，`link_type()` 暴露类型；`Detector::process_ip_packet` 为 L3 入口（与 `process_packet` 共用流表主体）；`CaptureHandle: Send`（非 Sync）。
  - **CLI**：`-n` 参数与文件模式校验；单线程路径改用 `LinkType`，删除 `is_ip_ethernet_frame`。
- **测试**：`src/live/link.rs` 链路层单测、`src/parity.rs` 排序单测、`src/bin/rdpi/live_runner.rs` `flow_shard`/合成帧 `-n 2` 管线单测、`tests/test_process_ip_packet.rs` 入口一致性用例；全部门禁（fmt/test/all-features/live/clippy/build）绿。
- **已知边界**：① 单抓包线程是吞吐上限，PF_RING/DPDK/fanout 不做；② `-n > 1` 时 text/jsonl 逐包行按完成顺序可能乱序；③ 每 worker 流表默认 10000 条，总量约 10000×N；④ FNV 分片极端流量可能倾斜，无动态再平衡；⑤ `ctrlc` 只处理 SIGINT（Unix 不处理 SIGTERM）；⑥ IPv6 扩展头场景仅按地址与 Next Header 分片，方向扩展链不对称时可能跨 worker；⑦ IPv4 非首片分片无端口，与首片可能落不同 worker；⑧ RAW 仅支持值 12/228/229，OpenBSD DLT_RAW 差异不覆盖；⑨ 非 IP 帧计入 `--count` 与总包数。
```

- [ ] **Step 5: 更新旧设计与 v2 设计状态**

`docs/architecture/live-capture-design.md` 的“后续增量（不在本切片）”列表前三项替换为：

```markdown
1. ~~多线程~~ 已由 [live-capture-v2-design.md](live-capture-v2-design.md) 兑现（F48：`-n`，单抓包线程 + flow-hash worker）。
2. ~~信号处理~~ 已由 v2 兑现（首次 Ctrl-C 优雅停止，第二次强退 130）。
3. ~~链路层扩展~~ 已由 v2 兑现（SLL/SLL2/RAW，Linux `any`；`Detector::process_ip_packet` L3 入口）。
```

`docs/architecture/live-capture-v2-design.md` 头部状态行改为：

```markdown
> 状态：已实施（F48，2026-11-08）
```

- [ ] **Step 6: 全量门禁验证**

Run:

```bash
cargo fmt --check
cargo test
cargo test --features live
cargo test --all-features
cargo clippy --all-features --all-targets -- -D warnings
cargo build --features "pcap live"
cargo test --features "pcap live" --bin rdpi
```

Expected: 全部通过；`cargo test --all-features` 在无 libpcap 环境下也通过（后端缺失用例走 `BackendUnavailable` 分支）；clippy 0 警告。

- [ ] **Step 7: 手工验收（Windows 本机）**

Run:

```bash
cargo run --features "pcap live" --bin rdpi -- --list-ifaces
cargo run --features "pcap live" --bin rdpi -- -i '<网卡>' -n 4 --count 200 -o jsonl -v
cargo run --features "pcap live" --bin rdpi -- -i '<网卡>' -n 4 --duration 10 -o text
cargo run --features "pcap live" --example live_capture -- '<网卡>' 20
```

Expected: `-n 4` 正常输出 200 帧/10 秒汇总；运行中第一次 Ctrl-C 输出汇总并 exit 0，第二次 Ctrl-C exit 130；`-n 1` 输出与 F47 一致；示例按链路类型识别协议。

Linux/WSL：

```bash
cargo run --features "pcap live" --bin rdpi -- -i any --count 200 -o text
cargo run --features "pcap live" --bin rdpi -- -i any -f "tcp port 443" --duration 10 -o jsonl -v
```

Expected: SLL/SLL2 路径能识别协议；BPF 过滤生效。

- [ ] **Step 8: 提交**

```bash
git add README.md AGENTS.md docs/architecture/ndpi-pure-rust-plan.md docs/architecture/risks.md docs/architecture/live-capture-design.md docs/architecture/live-capture-v2-design.md
git commit -m "Document live capture v2"
```

---

## 计划自检

### 规格覆盖

| 设计章节 | 对应任务 |
|---|---|
| §1 已确认决策 | Global Constraints + Task 4/5/6 |
| §2.1 `LinkType` 与 `LiveCapture::link_type` | Task 2 |
| §2.2 `InterruptFlag` | Task 4 |
| §2.3 `Detector::process_ip_packet` | Task 1 |
| §2.4 `parity::sort_normalized_flows` | Task 3 |
| §3 多线程管线（组件/flow_shard/生命周期） | Task 5（输出端）+ Task 6（管线） |
| §4 链路层适配与 CLI 分派 | Task 2（链路层/单线程）+ Task 6（worker 分派） |
| §5 CLI 参数、Ctrl-C、输出合并 | Task 4（信号）+ Task 5（输出）+ Task 6（`-n`） |
| §6 错误处理与退出码 | Task 6（Fatal/panic/退出码）+ Task 4（安装失败降级） |
| §7 测试策略 | 各任务 TDD 步骤 + Task 7 Step 6/7 |
| §8 文档与进度回写 | Task 7 |
| §9 风险与边界 | Task 7 Step 4（risks.md F48） |
| §10 范围外 | Global Constraints（不实现 PF_RING/DPDK、每 worker 容量参数等） |

### 占位符检查

- 无 TBD/TODO/「稍后实现」；每个代码步骤均给出完整代码。
- 所有命令均带预期结果。
- 没有引用未定义的函数或类型：Task 6 使用 Task 1-5 的 `process_ip_packet`、`sort_normalized_flows`、`on_packet_numbered`、`finish`；Task 7 仅改文档。

### 类型一致性

- `LinkType` 在 Task 2 定义，Task 2/6 使用一致；`l3_payload` 返回 `Option<&[u8]>`。
- `InterruptFlag` 在 Task 4 定义（`Clone + Default + Send + Sync`），Task 4/6 使用一致。
- `OutputSink::on_packet_numbered`/`finish` 在 Task 5 定义，Task 6 调用一致。
- `flow_shard`/`run_source`/`run_live` 在 Task 6 内部定义并只在该模块使用；`MAX_THREADS` 由主模块定义、`live_runner` 引用。
- `LiveEvent`/`WorkItem` 仅在 `live_runner` 内部使用，无跨模块类型泄漏。
