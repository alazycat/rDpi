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
    /// * `max_entries` - 最大流数（预留，未实现 LRU 淘汰）
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
    pub fn get_or_create(&mut self, key: FlowKey) -> &mut Flow {
        self.flows
            .entry(key.clone())
            .or_insert_with(|| Flow::new(key))
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