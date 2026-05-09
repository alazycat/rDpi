//! rDpi - Rust Deep Packet Inspection Library
//!
//! 轻量级、高性能的深度包检测库，专注协议识别与流量分析。
//!
//! # Features
//!
//! - `dns` - DNS protocol detection (enabled by default)
//! - `http` - HTTP protocol detection with Host header extraction (enabled by default)
//! - `tls` - TLS protocol detection with SNI extraction (enabled by default)
//! - `ssh` - SSH protocol detection with version extraction
//! - `smtp` - SMTP protocol detection with banner/command detection
//!
//! # Example
//!
//! ```rust
//! use rdpi::Detector;
//!
//! let mut detector = Detector::new();
//! // Pass raw packet bytes to detect protocol
//! let packet_data: &[u8] = &[0x00; 14];
//! let result = detector.detect(packet_data);
//! ```
//!
//! # Supported Protocols
//!
//! | Protocol | Feature | Metadata |
//! |----------|---------|----------|
//! | DNS | `dns` | Domain name |
//! | HTTP | `http` | Method, Path, Host header |
//! | TLS | `tls` | SNI, TLS version |
//! | SSH | `ssh` | Protocol version, Software version |
//! | SMTP | `smtp` | Hostname, is_client flag |

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