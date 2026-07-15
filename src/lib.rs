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
//! - `quic` - QUIC protocol detection with version and DCID extraction
//! - `mail` - POP3/POP3S/IMAP/IMAPS protocol detection
//! - `infra` - NTP/DHCP protocol detection with metadata extraction
//! - `snmp` - SNMP v1/v2c protocol detection with full PDU parsing
//! - `modbus` - Modbus TCP protocol detection with function code parsing
//! - `database` - MySQL/PostgreSQL/Redis protocol detection with metadata extraction
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
//! | TLS | `tls` | SNI, TLS version, Application |
//! | SSH | `ssh` | Protocol version, Software version |
//! | SMTP | `smtp` | Hostname, is_client flag |
//! | QUIC | `quic` | SNI, version, DCID |
//! | POP3/POP3S | `mail` | None (L1 detection) |
//! | IMAP/IMAPS | `mail` | None (L1 detection) |
//! | NTP | `infra` | Version, Mode, Stratum |
//! | DHCP | `infra` | Opcode, Client MAC |
//! | SNMP | `snmp` | Version, Community, PDU type, VarBinds, Trap info |
//! | Modbus | `modbus` | Transaction ID, Function code, Data |
//! | MySQL | `database` | Server version, Auth plugin |
//! | PostgreSQL | `database` | User, Database, Application name |
//! | Redis | `database` | Command type (GET/SET/SELECT, etc.) |

mod error;

pub mod application;
pub mod asn1;
pub mod core;
pub mod parser;
pub mod protocols;
#[cfg(feature = "pcap")]
pub mod pcap;

pub use core::types::*;
pub use error::{Error, Result};

use core::flow::{Flow, FlowTable};
use core::guess::{GuessEngine, GuessContext};
use core::guess::info::DomainInfo;
use core::types::{Confidence, TransportProto};
use protocols::Registry;
use std::time::Duration;

/// TCP 流 DPI 放弃阈值（包数）
pub const DEFAULT_TCP_GIVEUP: u32 = 20;
/// UDP 流 DPI 放弃阈值（包数）
pub const DEFAULT_UDP_GIVEUP: u32 = 5;

/// 主入口：包检测器
///
/// 自动追踪流，统计每条流的协议、包数、字节数。
///
/// # Example
///
/// ```rust
/// use rdpi::Detector;
///
/// let mut detector = Detector::new();
///
/// // 获取流统计
/// let flows: Vec<_> = detector.flows().collect();
/// println!("Active flows: {}", flows.len());
/// ```
pub struct Detector {
    registry: Registry,
    flow_table: FlowTable,
    /// 新流是否默认启用猜测
    default_guess: bool,
}

impl Detector {
    /// 创建默认检测器
    ///
    /// 默认配置：
    /// - 最大流数：10000
    /// - 流超时：120 秒
    pub fn new() -> Self {
        Self::default()
    }

    /// 使用自定义配置创建检测器
    ///
    /// # Arguments
    ///
    /// * `max_flows` - 最大流数
    /// * `timeout_secs` - 流超时时间（秒）
    pub fn with_config(max_flows: usize, timeout_secs: u64) -> Self {
        Self {
            registry: Registry::default(),
            flow_table: FlowTable::new(max_flows, Duration::from_secs(timeout_secs)),
            default_guess: true,
        }
    }

    /// 使用自定义 Registry 创建检测器
    pub fn with_registry(registry: Registry) -> Self {
        Self {
            registry,
            flow_table: FlowTable::new(10000, Duration::from_secs(120)),
            default_guess: true,
        }
    }

    /// 禁用猜测（仅 DPI 模式）
    pub fn disable_guess(&mut self) {
        self.default_guess = false;
    }

    /// 检测单个包
    ///
    /// 自动更新流表：
    /// 1. 解析包，获取五元组
    /// 2. 在流表中查找或创建流，递增加包计数
    /// 3. 检测协议（首次成功后保持不变）
    /// 4. 包数超过阈值后未识别的流触发猜测引擎
    /// 5. 更新流统计
    ///
    /// # Returns
    ///
    /// - `Ok(Some(result))` - 成功检测到协议
    /// - `Ok(None)` - 无法识别协议
    /// - `Err(e)` - 解析错误
    pub fn detect(&mut self, packet: &[u8]) -> crate::error::Result<Option<DetectionResult>> {
        // 解析包
        let parsed = parser::parse_packet(packet)?;

        // 构建流键
        let key = FlowKey {
            src_ip: parsed.src_ip,
            dst_ip: parsed.dst_ip,
            src_port: parsed.src_port,
            dst_port: parsed.dst_port,
            transport: parsed.transport,
        };

        // 获取或创建流
        let flow = self.flow_table.get_or_create(key.clone());

        // 新创建的流继承 Detector 的 guess 设置
        if flow.packets_seen == 0 {
            flow.dpi_only = !self.default_guess;
        }

        // 增加包计数
        flow.packets_seen += 1;

        // 计算 giveup 阈值
        let giveup_threshold = match flow.key.transport {
            TransportProto::Tcp => DEFAULT_TCP_GIVEUP,
            TransportProto::Udp => DEFAULT_UDP_GIVEUP,
            _ => DEFAULT_UDP_GIVEUP,
        };

        // 检测协议（如果流还没有协议）
        let result = if flow.protocol.is_none() {
            if flow.packets_seen < giveup_threshold || flow.dpi_only {
                // DPI 阶段
                let detected = self.registry.detect_with_ports(
                    &parsed.payload,
                    parsed.src_port,
                    parsed.dst_port,
                );

                if let Some(ref r) = detected {
                    flow.protocol = Some(r.protocol);
                }

                detected
            } else {
                // Giveup 阶段：DPI 达到阈值仍未识别，启用猜测引擎
                let mut ctx = GuessContext::new(parsed.dst_port);
                ctx.dst_ip = Some(parsed.src_ip); // 对端 IP
                // 从流元数据中收集域名信息
                ctx.domain_info = DomainInfo {
                    sni: flow.metadata.as_ref().and_then(|m| match m {
                        Metadata::Tls(tls) => tls.sni.clone(),
                        Metadata::Quic(quic) => quic.sni.clone(),
                        _ => None,
                    }),
                    http_host: flow.metadata.as_ref().and_then(|m| match m {
                        Metadata::Http(http) => http.host.clone(),
                        _ => None,
                    }),
                    dns_query: flow.metadata.as_ref().and_then(|m| match m {
                        Metadata::Dns(dns) => dns.query_domain.clone(),
                        _ => None,
                    }),
                };
                let guess = GuessEngine::new().guess(&ctx);

                if let Some(ref r) = guess {
                    flow.protocol = Some(r.protocol);
                }

                guess
            }
        } else {
            // 流已有协议，不重复检测，但需要返回当前协议信息
            flow.protocol.map(|p| DetectionResult::new(p))
        };

        // 更新流统计
        flow.stats.packets += 1;
        flow.stats.bytes += packet.len() as u64;
        flow.stats.last_time = std::time::Instant::now();

        // 如果有检测结果，保存元数据
        if let Some(ref r) = result {
            flow.metadata = Some(r.metadata.clone());
        }

        Ok(result)
    }

    /// 获取流表（只读）
    pub fn flows(&self) -> impl Iterator<Item = (&FlowKey, &Flow)> {
        self.flow_table.iter()
    }

    /// 获取活跃流数
    pub fn flow_count(&self) -> usize {
        self.flow_table.len()
    }

    /// 获取指定流
    pub fn get_flow(&self, key: &FlowKey) -> Option<&Flow> {
        self.flow_table.get(key)
    }

    /// 清理超时流
    ///
    /// # Returns
    ///
    /// 过期的流键列表
    pub fn expire_flows(&mut self) -> Vec<FlowKey> {
        self.flow_table.expire_timeout()
    }

    /// 清空流表
    pub fn clear_flows(&mut self) {
        self.flow_table.clear();
    }
}

impl Default for Detector {
    fn default() -> Self {
        Self::with_registry(Registry::default())
    }
}
