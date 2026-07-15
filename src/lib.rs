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
#[cfg(feature = "rule")]
pub mod rule;
#[cfg(feature = "risk")]
pub mod risk;

pub use core::types::*;
pub use error::{Error, Result};

use core::flow::{Flow, FlowTable};
use core::guess::{GuessEngine, GuessContext};
use core::guess::info::DomainInfo;
use core::types::{Confidence, TransportProto};
use protocols::Registry;
use std::time::Duration;

#[cfg(feature = "rule")]
use rule::{Rule, RuleContext, RuleEngine};
#[cfg(feature = "risk")]
use risk::RiskRegistry;

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
    /// 规则引擎（可选）
    #[cfg(feature = "rule")]
    rule_engine: Option<RuleEngine>,
    /// 仅规则模式（跳过内置 DPI 和 Guess）
    #[cfg(feature = "rule")]
    rules_only: bool,
    /// 风险分析引擎
    #[cfg(feature = "risk")]
    risk_registry: RiskRegistry,
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
            #[cfg(feature = "rule")]
            rule_engine: None,
            #[cfg(feature = "rule")]
            rules_only: false,
            #[cfg(feature = "risk")]
            risk_registry: RiskRegistry::default(),
        }
    }

    /// 使用自定义 Registry 创建检测器
    pub fn with_registry(registry: Registry) -> Self {
        Self {
            registry,
            flow_table: FlowTable::new(10000, Duration::from_secs(120)),
            default_guess: true,
            #[cfg(feature = "rule")]
            rule_engine: None,
            #[cfg(feature = "rule")]
            rules_only: false,
            #[cfg(feature = "risk")]
            risk_registry: RiskRegistry::default(),
        }
    }

    /// 禁用猜测（仅 DPI 模式）
    pub fn disable_guess(&mut self) {
        self.default_guess = false;
    }

    /// 使用规则创建检测器
    #[cfg(feature = "rule")]
    pub fn with_rules(rules: Vec<Rule>) -> Self {
        Self {
            registry: Registry::default(),
            flow_table: FlowTable::new(10000, Duration::from_secs(120)),
            default_guess: true,
            rule_engine: Some(RuleEngine { rules }),
            rules_only: false,
            #[cfg(feature = "risk")]
            risk_registry: RiskRegistry::default(),
        }
    }

    /// 添加单条规则
    #[cfg(feature = "rule")]
    pub fn add_rule(&mut self, rule: Rule) {
        self.rule_engine.get_or_insert_with(RuleEngine::new).add_rule(rule);
    }

    /// 从 JSON 加载规则
    #[cfg(feature = "rule")]
    pub fn load_rules_json(&mut self, json_str: &str) -> std::result::Result<(), String> {
        let engine = RuleEngine::from_json(json_str)?;
        self.rule_engine = Some(engine);
        Ok(())
    }

    /// 从 JSON 文件加载规则
    #[cfg(feature = "rule")]
    pub fn load_rules_file(&mut self, path: &str) -> std::result::Result<(), String> {
        let engine = RuleEngine::from_file(path)?;
        self.rule_engine = Some(engine);
        Ok(())
    }

    /// 启用/禁用仅规则模式
    #[cfg(feature = "rule")]
    pub fn set_rules_only(&mut self, enabled: bool) {
        self.rules_only = enabled;
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
        let mut result = if flow.protocol.is_none() {
            #[cfg(feature = "rule")]
            if let Some(ref engine) = self.rule_engine {
                let rule_ctx = RuleContext {
                    src_port: parsed.src_port,
                    dst_port: parsed.dst_port,
                    sni: flow.metadata.as_ref().and_then(|m| match m {
                        Metadata::Tls(tls) => tls.sni.clone(),
                        Metadata::Quic(quic) => quic.sni.clone(),
                        _ => None,
                    }),
                    payload: parsed.payload.clone(),
                };
                if let Some(r) = engine.match_rule(&rule_ctx) {
                    flow.protocol = Some(r.protocol);
                    flow.metadata = Some(r.metadata.clone());
                    return Ok(Some(r));
                }
                if self.rules_only {
                    return Ok(None);
                }
            }
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

        // 风险分析（将风险附加到检测结果和流）
        #[cfg(feature = "risk")]
        {
            let risks = self.risk_registry.analyze_packet(&parsed, &*flow);
            if !risks.is_empty() {
                flow.risks.extend(risks.clone());
                if let Some(ref mut r) = result {
                    r.risks = risks;
                }
            }
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
        #[cfg(feature = "risk")]
        {
            // 在过期前对流运行 analyze_flow
            let keys: Vec<FlowKey> = self.flow_table.iter()
                .filter(|(_, f)| std::time::Instant::now().duration_since(f.stats.last_time)
                    > Duration::from_secs(120))
                .map(|(k, _)| k.clone())
                .collect();
            for key in &keys {
                if let Some(flow) = self.flow_table.get(key) {
                    let _risks = self.risk_registry.analyze_flow(flow);
                }
            }
        }
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
