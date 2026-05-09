//! Flow management module
//!
//! This module contains flow tracking and management functionality.

use crate::core::types::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 流状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    New,
    Established,
    Closing,
    Closed,
}

/// 流统计
#[derive(Debug, Clone)]
pub struct FlowStats {
    pub packets: u64,
    pub bytes: u64,
    pub start_time: Instant,
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
#[derive(Debug, Clone)]
pub struct Flow {
    pub key: FlowKey,
    pub protocol: Option<Protocol>,
    pub stats: FlowStats,
    pub state: FlowState,
}

impl Flow {
    pub fn new(key: FlowKey) -> Self {
        Self {
            key,
            protocol: None,
            stats: FlowStats::default(),
            state: FlowState::New,
        }
    }
}

/// 流表
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    #[allow(dead_code)] // Reserved for future LRU eviction
    max_entries: usize,
    timeout: Duration,
}

impl FlowTable {
    pub fn new(max_entries: usize, timeout: Duration) -> Self {
        Self {
            flows: HashMap::new(),
            max_entries,
            timeout,
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn get_or_create(&mut self, key: FlowKey) -> &mut Flow {
        self.flows
            .entry(key.clone())
            .or_insert_with(|| Flow::new(key))
    }

    pub fn get(&self, key: &FlowKey) -> Option<&Flow> {
        self.flows.get(key)
    }

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

    pub fn clear(&mut self) {
        self.flows.clear();
    }
}
