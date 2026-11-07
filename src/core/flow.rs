//! Flow management module
//!
//! This module contains flow tracking and management functionality.

use crate::core::types::*;
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

/// 流状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// 新流
    New,
    /// 已建立
    Established,
    /// 关闭中
    Closing,
    /// 已关闭
    Closed,
}

/// 流统计
#[derive(Debug, Clone)]
pub struct FlowStats {
    /// 包数
    pub packets: u64,
    /// 字节数
    pub bytes: u64,
    /// 开始时间
    pub start_time: Instant,
    /// 最后更新时间
    pub last_time: Instant,
}

impl Default for FlowStats {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            packets: 0,
            bytes: 0,
            start_time: now,
            last_time: now,
        }
    }
}

/// 每方向 TCP 重组缓冲上限（防止乱序攻击导致无界内存）
const TCP_REASSEMBLY_MAX_PENDING_BYTES: usize = 256 * 1024;

/// 单向 TCP 字节流重组器
///
/// 按序列号把乱序段暂存，连续后一次性交付；重传/重叠段裁剪为未交付部分。
/// 无 SYN 的 mid-stream 流以首个数据段为基线（更早的段按重传处理丢弃）。
#[derive(Debug, Clone, Default)]
pub struct TcpReassembler {
    next_seq: Option<u32>,
    pending: BTreeMap<u32, Vec<u8>>,
    pending_bytes: usize,
}

impl TcpReassembler {
    /// 创建空重组器
    pub fn new() -> Self {
        Self::default()
    }

    /// 推入一个 TCP 段，返回本段触发的连续可交付字节
    pub fn push(&mut self, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let syn = flags & 0x02 != 0;
        if syn {
            self.next_seq = Some(seq.wrapping_add(1));
        }
        if payload.is_empty() {
            return Vec::new();
        }

        // SYN 带载荷时，载荷从 seq+1 开始（SYN 自身消耗一个序列号）。
        let data_seq = if syn { seq.wrapping_add(1) } else { seq };
        let next = match self.next_seq {
            Some(next) => next,
            None => {
                self.next_seq = Some(data_seq);
                data_seq
            }
        };

        let mut out = Vec::new();
        let diff = data_seq.wrapping_sub(next) as i32;
        if diff == 0 {
            out.extend_from_slice(payload);
            self.next_seq = Some(next.wrapping_add(payload.len() as u32));
        } else if diff > 0 {
            self.insert_pending(data_seq, payload);
        } else {
            // 重传/重叠：跳过已交付前缀，只交付剩余新字节。
            let overlap = (-diff) as usize;
            if overlap < payload.len() {
                let fresh = &payload[overlap..];
                out.extend_from_slice(fresh);
                self.next_seq = Some(next.wrapping_add(fresh.len() as u32));
            }
        }

        self.drain_pending(&mut out);
        out
    }

    fn insert_pending(&mut self, seq: u32, payload: &[u8]) {
        if self.pending_bytes + payload.len() > TCP_REASSEMBLY_MAX_PENDING_BYTES {
            return;
        }
        if self.pending.contains_key(&seq) {
            return;
        }
        self.pending.insert(seq, payload.to_vec());
        self.pending_bytes += payload.len();
    }

    fn drain_pending(&mut self, out: &mut Vec<u8>) {
        while let Some(next) = self.next_seq {
            let Some((&seq, _)) = self.pending.iter().next() else {
                break;
            };
            let diff = seq.wrapping_sub(next) as i32;
            if diff > 0 {
                break;
            }
            let data = self.pending.remove(&seq).unwrap();
            self.pending_bytes -= data.len();
            let overlap = if diff < 0 { (-diff) as usize } else { 0 };
            if overlap >= data.len() {
                continue;
            }
            let fresh = &data[overlap..];
            out.extend_from_slice(fresh);
            self.next_seq = Some(next.wrapping_add(fresh.len() as u32));
        }
    }
}

/// 单条流
///
/// 包含流的键、协议、统计和元数据。
#[derive(Debug, Clone)]
pub struct Flow {
    /// 流键（五元组）
    pub key: FlowKey,
    /// 识别出的协议
    pub protocol: Option<Protocol>,
    /// 分类置信度（与 `protocol` 同步写入；per-flow 导出使用）
    pub confidence: Option<Confidence>,
    /// 流统计
    pub stats: FlowStats,
    /// 流状态
    pub state: FlowState,
    /// 首包方向（相对规范化后的双向流键；`Flow::new` 默认 Forward）
    pub initiator: Direction,
    /// 客户端方向（SYN 发送端；由 SYN/SYN-ACK 推断，双向 API 的 JA4 归位依据。
    /// 无握手起点时保持 None）
    pub client_direction: Option<Direction>,
    /// 分类状态（双向 API；`detect` 路径暂未使用）
    pub classification_state: ClassificationState,
    /// 已定型但继续监测元数据（P1：TLS Certificate 富化）
    pub monitoring: bool,
    /// 正向包数/字节数（相对流键方向；双向 API）
    pub packets_forward: u64,
    /// 正向字节数
    pub bytes_forward: u64,
    /// 反向包数（双向 API）
    pub packets_reverse: u64,
    /// 反向字节数
    pub bytes_reverse: u64,
    /// 首包时间戳（毫秒；双向 API，离线 pcap 可直接使用）
    pub first_seen_ms: Option<u64>,
    /// 最近包时间戳（毫秒；双向 API）
    pub last_seen_ms: Option<u64>,
    /// 协议元数据
    pub metadata: Option<Metadata>,
    /// 协议栈（P1：双向 API；`detect` 路径暂未填充）
    pub protocol_stack: ProtocolStack,
    /// 有状态 dissector 的 per-flow 状态（P1）
    pub dissector_state: DissectorState,
    /// TCP 每方向重组器（P1：乱序/重传；[Forward, Reverse]）
    pub tcp_reassembly: [TcpReassembler; 2],
    /// 已观察包计数（用于 Giveup 机制）
    pub packets_seen: u32,
    /// 仅 DPI 模式（不做猜测）
    pub dpi_only: bool,
    /// JA4T 客户端 TCP 指纹（F33：初始 SYN 包一次性计算；流级旁路字段，
    /// 不占用 protocol/metadata 的一次定型语义）
    pub ja4t: Option<String>,
    /// JA4TS 服务端 TCP 指纹 4 段基串（F34：SYN-ACK 包一次性计算；服务端方向流
    /// 的旁路字段，不占用 protocol/metadata 的一次定型语义。F40 起第 5 段重传
    /// 延迟/RST 后缀在 DetectionResult 落库时按跟踪状态组合，本字段不变）
    pub ja4ts: Option<String>,
    /// JA4TS 第 5 段跟踪：最近一次 SYN-ACK（首捕或重传）到达时刻（F40，
    /// 延迟 = 当前包时戳 - 该值，官方 zeek ja4t `last_ts` 语义）
    pub ja4ts_synack_time: Option<std::time::SystemTime>,
    /// JA4TS SYN-ACK 重传延迟序列（F40，整秒，官方 zeek ja4t `synack_delays`
    /// 语义：至多 10 项；仅在重传发生时分配，正常流零堆分配）
    pub ja4ts_delays: Vec<u32>,
    /// JA4TS RST 后缀延迟（F40，整秒；跟踪期内服务端方向 RST 到达时记录一次，
    /// 仅在存在延迟段时随第 5 段输出 `-R{n}`）
    pub ja4ts_rst_delay: Option<u32>,
    /// JA4TS 第 5 段收集是否进行中（F40：客户端方向包 / RST / 120 秒超时 /
    /// 满 10 项后关闭，官方 zeek `synack_done` 语义）
    pub ja4ts_tracking: bool,
    /// 客户端 SYN 到达时刻（F35：JA4L 的 A 时戳，TCP 客户端流记录一次）
    pub syn_time: Option<std::time::SystemTime>,
    /// 客户端 SYN 包的 IP TTL / IPv6 hop limit（F35：JA4L-C 的 TTL 段）
    pub syn_ttl: Option<u8>,
    /// 服务端 SYN-ACK 到达时刻（F35：JA4L 的 B 时戳，TCP 服务端流记录一次）
    pub synack_time: Option<std::time::SystemTime>,
    /// 服务端 SYN-ACK 包的 IP TTL / IPv6 hop limit（F35：JA4L-S 的 TTL 段）
    pub synack_ttl: Option<u8>,
    /// JA4L-S 服务端时延指纹（F35：SYN-ACK 到达时借对端 A 时戳一次算出；
    /// 服务端方向流的旁路字段，不占用 protocol/metadata 的一次定型语义）
    pub ja4ls: Option<String>,
    /// JA4L-C 客户端时延指纹（F35：SYN-ACK 后首个客户端包借对端 B 时戳
    /// 一次算出；客户端方向流的旁路字段，同上定型语义豁免）
    pub ja4lc: Option<String>,
    /// JA4SSH 当前窗口内本方向 TCP 载荷包长度序列（F36：仅 SSH 流增长，
    /// 非 SSH 流恒空、零堆分配；双向合计满 200 包后清零滚动）
    pub ssh_payload_lens: Vec<u16>,
    /// JA4SSH 当前窗口内本方向纯 ACK 包数（F36：无载荷且 flags 精确
    /// 等于 0x10；窗口产出后清零）
    pub ssh_ack_count: u32,
    /// JA4SSH 双向 API：按方向 [Forward, Reverse] 累计的载荷包长度序列
    /// （与 detect_at 路径的 `ssh_payload_lens` 分离，避免两个流模型互相污染）
    pub ssh_payload_lens_by_dir: [Vec<u16>; 2],
    /// JA4SSH 双向 API：按方向累计的纯 ACK 包数
    pub ssh_ack_count_by_dir: [u32; 2],
    /// JA4SSH 会话指纹（F36：最近完成的 200 载荷包窗口指纹，存于两个
    /// 方向流；旁路字段，不占用 protocol/metadata 的一次定型语义）
    pub ja4ssh: Option<String>,
    /// 客户端 QUIC Initial 到达时刻（F41：QUIC JA4L 的 A' 时戳，客户端流记录一次）
    pub quic_client_init_time: Option<std::time::SystemTime>,
    /// 客户端 QUIC Initial 包的 IP TTL / IPv6 hop limit（F41：QUIC JA4L-C 的 TTL 段）
    pub quic_client_init_ttl: Option<u8>,
    /// 服务端 QUIC Initial 到达时刻（F41：QUIC JA4L-S 计算基准，服务端流记录一次）
    pub quic_server_init_time: Option<std::time::SystemTime>,
    /// 服务端 QUIC Handshake 到达时刻（F41：QUIC JA4L-C 的 B' 时戳，服务端流记录一次）
    pub quic_server_hs_time: Option<std::time::SystemTime>,
    /// 客户端 TLS ClientHello 到达时刻（F42：JA4L 精化段 D 时点，客户端流记录一次）
    pub tls_client_hello_time: Option<std::time::SystemTime>,
    /// 服务端 TLS ServerHello 到达时刻（F42：JA4L 精化段 E 时点，服务端流记录一次）
    pub tls_server_hello_time: Option<std::time::SystemTime>,
    /// ServerHello 之后首个有载荷客户端包到达时刻（F42：精化段 F 时点，
    /// 客户端流记录一次；纯 ACK 等待，zeek `dl == 0` 语义）
    pub tls_first_client_data_time: Option<std::time::SystemTime>,
    /// 流关联的风险 (feature: risk)
    #[cfg(feature = "risk")]
    pub risks: Vec<crate::risk::types::RiskResult>,
}

impl Flow {
    /// 创建新流
    pub fn new(key: FlowKey) -> Self {
        Self {
            key,
            protocol: None,
            confidence: None,
            stats: FlowStats::default(),
            state: FlowState::New,
            initiator: Direction::Forward,
            client_direction: None,
            classification_state: ClassificationState::Inspecting,
            monitoring: false,
            packets_forward: 0,
            bytes_forward: 0,
            packets_reverse: 0,
            bytes_reverse: 0,
            first_seen_ms: None,
            last_seen_ms: None,
            metadata: None,
            protocol_stack: ProtocolStack::new(),
            dissector_state: DissectorState::None,
            tcp_reassembly: [TcpReassembler::new(), TcpReassembler::new()],
            packets_seen: 0,
            dpi_only: false,
            ja4t: None,
            ja4ts: None,
            ja4ts_synack_time: None,
            ja4ts_delays: Vec::new(),
            ja4ts_rst_delay: None,
            ja4ts_tracking: false,
            syn_time: None,
            syn_ttl: None,
            synack_time: None,
            synack_ttl: None,
            ja4ls: None,
            ja4lc: None,
            ssh_payload_lens: Vec::new(),
            ssh_ack_count: 0,
            ssh_payload_lens_by_dir: [Vec::new(), Vec::new()],
            ssh_ack_count_by_dir: [0, 0],
            ja4ssh: None,
            quic_client_init_time: None,
            quic_client_init_ttl: None,
            quic_server_init_time: None,
            quic_server_hs_time: None,
            tls_client_hello_time: None,
            tls_server_hello_time: None,
            tls_first_client_data_time: None,
            #[cfg(feature = "risk")]
            risks: Vec::new(),
        }
    }

    /// 创建双向流
    ///
    /// `packet_key` 为触发建流的首包五元组；流键按端点 `(ip, port)` 字典序
    /// 规范化，`initiator` 记录首包相对规范键的方向。两个方向的包用
    /// [`Self::direction_of`] 映射到同一个流。
    pub fn new_bidirectional(packet_key: FlowKey) -> Self {
        let (key, first_dir) = packet_key.canonical();
        let mut flow = Self::new(key);
        flow.initiator = first_dir;
        flow
    }

    /// 返回包相对**首包方向**（initiator）的方向
    ///
    /// 与首包同向返回 `Forward`，反向返回 `Reverse`；包不属于本流
    /// （既非同向也非反向）时返回 `None`。注意：`self.key` 可能是规范化键，
    /// 因此内部方向与 `self.key` 的对应关系需按 `initiator` 翻转。
    pub fn direction_of(&self, packet_key: &FlowKey) -> Option<Direction> {
        let direction = if packet_key == &self.key {
            Direction::Forward
        } else if packet_key == &self.key.reverse() {
            Direction::Reverse
        } else {
            return None;
        };
        Some(if self.initiator == Direction::Reverse {
            direction.opposite()
        } else {
            direction
        })
    }
}

/// 流表
///
/// 管理所有活跃流，支持自动过期。
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    max_entries: usize,
    timeout: Duration,
}

impl FlowTable {
    /// 创建流表
    ///
    /// # Arguments
    ///
    /// * `max_entries` - 最大流数（满时先清超时流，再按最久未活跃逐出；0 = 不设上限）
    /// * `timeout` - 流超时时间
    pub fn new(max_entries: usize, timeout: Duration) -> Self {
        Self {
            flows: HashMap::new(),
            max_entries,
            timeout,
        }
    }

    /// 获取活跃流数
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// 判断是否为空
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// 获取或创建流
    ///
    /// 容量控制（R2 修复，2026-11-04）：已存在的流直接命中；新流在表满时
    /// 先清理超时流，仍满则按"最久未活跃"（`stats.last_time` 最小）逐出至有空位。
    /// `max_entries == 0` 视为不设上限。
    pub fn get_or_create(&mut self, key: FlowKey) -> &mut Flow {
        if self.flows.contains_key(&key) {
            let flow = self.flows.get_mut(&key).unwrap();
            // 命中即 touch：last_time 反映最近活跃时间，是逐出策略的依据
            flow.stats.last_time = Instant::now();
            return flow;
        }
        if self.max_entries > 0 && self.flows.len() >= self.max_entries {
            self.evict_until_insertable();
        }
        self.flows
            .entry(key.clone())
            .or_insert_with(|| Flow::new(key))
    }

    /// 表满时的逐出：先清理超时流，仍满则逐出最久未活跃的流（每次 O(n) 扫描，低频路径）
    fn evict_until_insertable(&mut self) {
        self.expire_timeout();
        while self.flows.len() >= self.max_entries {
            let oldest = self
                .flows
                .iter()
                .min_by_key(|(_, f)| f.stats.last_time)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.flows.remove(&k);
                }
                None => break,
            }
        }
    }

    /// 获取指定流（只读）
    pub fn get(&self, key: &FlowKey) -> Option<&Flow> {
        self.flows.get(key)
    }

    /// 获取指定流（可写）
    pub fn get_mut(&mut self, key: &FlowKey) -> Option<&mut Flow> {
        self.flows.get_mut(key)
    }

    /// 取出流（供双向入口在调用 `Detector` 其他方法时临时持有）
    pub(crate) fn take(&mut self, key: &FlowKey) -> Option<Flow> {
        self.flows.remove(key)
    }

    /// 放回流（与 [`Self::take`] 配对；新键仍走容量控制）
    pub(crate) fn put(&mut self, flow: Flow) {
        let key = flow.key.clone();
        if !self.flows.contains_key(&key)
            && self.max_entries > 0
            && self.flows.len() >= self.max_entries
        {
            self.evict_until_insertable();
        }
        self.flows.insert(key, flow);
    }

    /// 迭代所有流
    pub fn iter(&self) -> impl Iterator<Item = (&FlowKey, &Flow)> {
        self.flows.iter()
    }

    /// 可变迭代所有流（供风险出口 drain flow.risks）
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&FlowKey, &mut Flow)> {
        self.flows.iter_mut()
    }

    /// 获取流超时时间（R5：供外部过期窗口与 expire_timeout 保持一致）
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// 清理超时流
    ///
    /// # Returns
    ///
    /// 过期的流键列表
    pub fn expire_timeout(&mut self) -> Vec<FlowKey> {
        let now = Instant::now();
        let timeout = self.timeout;

        let expired: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, flow)| now.duration_since(flow.stats.last_time) > timeout)
            .map(|(key, _)| key.clone())
            .collect();

        for key in &expired {
            self.flows.remove(key);
        }

        expired
    }

    /// 清空流表
    pub fn clear(&mut self) {
        self.flows.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;

    fn key(port: u16) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 10000 + port,
            dst_port: 80,
            transport: TransportProto::Tcp,
        }
    }

    /// R2: 表满时插入新流 → 容量不超限，最久未活跃的流被逐出
    #[test]
    fn test_max_entries_evicts_oldest() {
        let mut t = FlowTable::new(2, Duration::from_secs(120));
        t.get_or_create(key(1));
        std::thread::sleep(Duration::from_millis(5));
        t.get_or_create(key(2));
        std::thread::sleep(Duration::from_millis(5));
        t.get_or_create(key(3)); // 满载插入 → 逐出 key(1)

        assert_eq!(t.len(), 2);
        assert!(
            t.get(&key(1)).is_none(),
            "oldest (least recently active) flow must be evicted"
        );
        assert!(t.get(&key(2)).is_some());
        assert!(t.get(&key(3)).is_some());
    }

    /// R2: 被重新访问（活跃）的流不被逐出
    #[test]
    fn test_active_flow_survives_eviction() {
        let mut t = FlowTable::new(2, Duration::from_secs(120));
        t.get_or_create(key(1));
        std::thread::sleep(Duration::from_millis(5));
        t.get_or_create(key(2));
        std::thread::sleep(Duration::from_millis(5));
        // 摸一下 key(1)：模拟长连接仍在收包（lib.rs 每包更新 last_time）
        t.get_or_create(key(1));
        std::thread::sleep(Duration::from_millis(5));
        t.get_or_create(key(3)); // 满载 → 此刻最久未活跃的是 key(2)

        assert_eq!(t.len(), 2);
        assert!(
            t.get(&key(1)).is_some(),
            "recently active flow must survive"
        );
        assert!(t.get(&key(2)).is_none());
        assert!(t.get(&key(3)).is_some());
    }

    /// R2: 已存在的流满载命中时不触发逐出
    #[test]
    fn test_existing_key_no_eviction() {
        let mut t = FlowTable::new(2, Duration::from_secs(120));
        t.get_or_create(key(1));
        t.get_or_create(key(2));
        assert_eq!(t.len(), 2);
        // 命中已有流：不逐出、不新建
        t.get_or_create(key(1));
        assert_eq!(t.len(), 2);
    }

    /// R2: max_entries = 0 视为不设上限
    #[test]
    fn test_zero_capacity_means_unlimited() {
        let mut t = FlowTable::new(0, Duration::from_secs(120));
        for i in 0..10 {
            t.get_or_create(key(i));
        }
        assert_eq!(t.len(), 10);
    }

    /// R5: timeout() 访问器返回配置值（供外部过期窗口与 expire_timeout 对齐）
    #[test]
    fn test_timeout_accessor_returns_configured_value() {
        let t = FlowTable::new(10, Duration::from_secs(7));
        assert_eq!(t.timeout(), Duration::from_secs(7));
    }
}
