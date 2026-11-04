//! Flow management module
//!
//! This module contains flow tracking and management functionality.

use crate::core::types::*;
use std::collections::HashMap;
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

/// 单条流
///
/// 包含流的键、协议、统计和元数据。
#[derive(Debug, Clone)]
pub struct Flow {
    /// 流键（五元组）
    pub key: FlowKey,
    /// 识别出的协议
    pub protocol: Option<Protocol>,
    /// 流统计
    pub stats: FlowStats,
    /// 流状态
    pub state: FlowState,
    /// 协议元数据
    pub metadata: Option<Metadata>,
    /// 已观察包计数（用于 Giveup 机制）
    pub packets_seen: u32,
    /// 仅 DPI 模式（不做猜测）
    pub dpi_only: bool,
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
            stats: FlowStats::default(),
            state: FlowState::New,
            metadata: None,
            packets_seen: 0,
            dpi_only: false,
            #[cfg(feature = "risk")]
            risks: Vec::new(),
        }
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
