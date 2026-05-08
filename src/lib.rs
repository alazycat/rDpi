//! rDpi - Rust Deep Packet Inspection Library
//!
//! 轻量级、高性能的深度包检测库，专注协议识别与流量分析。

mod error;

pub mod core;
pub mod parser;
pub mod protocols;

pub use error::Error;
pub use core::types::*;

use core::flow::FlowTable;
use protocols::Registry;
use std::time::Duration;

/// 主入口：包检测器
pub struct Detector {
    registry: Registry,
    flow_table: FlowTable,
}

impl Detector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_registry(registry: Registry) -> Self {
        Self {
            registry,
            flow_table: FlowTable::new(10000, Duration::from_secs(120)),
        }
    }

    pub fn detect(&mut self, packet: &[u8]) -> crate::error::Result<Option<core::types::DetectionResult>> {
        let parsed = parser::parse_packet(packet)?;

        let _key = core::types::FlowKey {
            src_ip: parsed.src_ip,
            dst_ip: parsed.dst_ip,
            src_port: parsed.src_port,
            dst_port: parsed.dst_port,
            transport: parsed.transport,
        };

        let result = self.registry.detect(&parsed.payload);
        Ok(result)
    }

    pub fn expire(&mut self) -> Vec<core::types::FlowKey> {
        self.flow_table.expire_timeout()
    }
}

impl Default for Detector {
    fn default() -> Self {
        Self::with_registry(Registry::default())
    }
}