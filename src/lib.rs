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
#[cfg(feature = "pcap")]
pub mod pcap;
pub mod protocols;
#[cfg(feature = "risk")]
pub mod risk;
#[cfg(feature = "rule")]
pub mod rule;

pub use core::types::*;
pub use error::{Error, Result};

use core::flow::{Flow, FlowTable};
use core::guess::info::DomainInfo;
use core::guess::{GuessContext, GuessEngine};
use protocols::Registry;
use std::time::Duration;

#[cfg(feature = "risk")]
use risk::{RiskRegistry, RiskResult};
#[cfg(feature = "rule")]
use rule::{Rule, RuleContext, RuleEngine};

/// TCP 流 DPI 放弃阈值（包数）
pub const DEFAULT_TCP_GIVEUP: u32 = 20;
/// UDP 流 DPI 放弃阈值（包数）
pub const DEFAULT_UDP_GIVEUP: u32 = 5;

/// 风险事件推送回调类型（观察者模式，见 [`Detector::set_risk_callback`]）
#[cfg(feature = "risk")]
type RiskCallback = Box<dyn Fn(FlowKey, &RiskResult) + Send + Sync>;

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
    /// 过期流的风险结果暂存（drain_risks 出口之一；流级 analyze_flow 结果此前被直接丢弃）
    #[cfg(feature = "risk")]
    pending_risks: Vec<(FlowKey, RiskResult)>,
    /// 风险事件推送回调（观察者模式，drain_risks 轮询之外的即时出口）
    #[cfg(feature = "risk")]
    risk_callback: Option<RiskCallback>,
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
            #[cfg(feature = "risk")]
            pending_risks: Vec::new(),
            #[cfg(feature = "risk")]
            risk_callback: None,
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
            #[cfg(feature = "risk")]
            pending_risks: Vec::new(),
            #[cfg(feature = "risk")]
            risk_callback: None,
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
            #[cfg(feature = "risk")]
            pending_risks: Vec::new(),
            #[cfg(feature = "risk")]
            risk_callback: None,
        }
    }

    /// 添加单条规则
    #[cfg(feature = "rule")]
    pub fn add_rule(&mut self, rule: Rule) {
        self.rule_engine
            .get_or_insert_with(RuleEngine::new)
            .add_rule(rule);
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
        // mut 仅在 risk feature 下使用（回写 r.risks）
        #[cfg_attr(not(feature = "risk"), allow(unused_mut))]
        let mut result = if flow.protocol.is_none() {
            #[cfg(feature = "rule")]
            if let Some(ref engine) = self.rule_engine {
                // R6 修复：flow.metadata 在规则分支中恒为 None（所有写 metadata 的
                // 路径都同时写了 protocol，而规则分支仅在 protocol.is_none() 时进入）
                // → sni_contains 规则原为死代码。回退到从当前包 payload 提取 SNI。
                let sni = flow.metadata.as_ref().and_then(|m| match m {
                    Metadata::Tls(tls) => tls.sni.clone(),
                    Metadata::Quic(quic) => quic.sni.clone(),
                    _ => None,
                });
                #[cfg(feature = "tls")]
                let sni = sni.or_else(|| protocols::tls::extract_sni(&parsed.payload));
                let rule_ctx = RuleContext {
                    src_port: parsed.src_port,
                    dst_port: parsed.dst_port,
                    sni,
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
                // R4 修复：两方向 IP 都交给猜测引擎——服务端可能在 dst
                // （client→server 包）或 src（server→client 包）；匹配时 dst 优先。
                ctx.dst_ip = Some(parsed.dst_ip);
                ctx.src_ip = Some(parsed.src_ip);
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
            // F3 修复：已定型 TLS 流在后续包收到 Certificate 记录时，
            // 一次性补解析证书字段（写回 flow.metadata，下方回显自动携带）
            #[cfg(feature = "tls")]
            Self::enrich_tls_cert(flow, &parsed.payload);

            // 流已有协议，不重复检测，但需要返回当前协议信息
            flow.protocol.map(|p| {
                let mut r = DetectionResult::new(p);
                // F7 修复：回显结果携带流已识别时的元数据。否则下方无条件写回
                // flow.metadata = Some(r.metadata) 会把元数据抹成 Some(Metadata::None)，
                // 导致依赖 flow.metadata 的 risk 处理器（tls/dns/http）从第二包起失效。
                if let Some(ref m) = flow.metadata {
                    r.metadata = m.clone();
                }
                r
            })
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
                // 观察者推送（逐包风险）
                if let Some(cb) = self.risk_callback.as_ref() {
                    for r in &risks {
                        cb(key.clone(), r);
                    }
                }
                flow.risks.extend(risks.clone());
                if let Some(ref mut r) = result {
                    r.risks = risks;
                }
            }
        }

        Ok(result)
    }

    /// F3：已定型 TLS 流收到 Certificate 记录时，补解析证书字段（每流至多一次）
    ///
    /// 修复前：证书解析只发生在流识别的那一个包（tls/mod.rs:66-71），而证书几乎
    /// 总是在 ClientHello 之后的独立记录到达 → 证书字段恒 None（a2/a3 实锤）。
    /// 修复后：回显路径对已定型 TLS 流做廉价预检（字段为空 + 段内任一记录形似
    /// Certificate），命中才做 ASN.1 解析并写回 flow.metadata；协议不重检
    /// （ADR-0004 一次定型语义不变），字段填充后不再重复解析。
    /// a3 修复（2026-11-04）：Certificate 不要求在段首——连体记录场景
    /// （ServerHello+Certificate 合并段等）经 iter_tls_records 逐记录定位。
    #[cfg(feature = "tls")]
    fn enrich_tls_cert(flow: &mut Flow, payload: &[u8]) {
        let needs_enrich = matches!(
            flow.metadata,
            Some(Metadata::Tls(ref tls)) if tls.cert_subject.is_none()
        );
        if !needs_enrich || flow.protocol != Some(Protocol::Tls) {
            return;
        }
        // a3 修复：连体记录场景下 Certificate 可能不在段首——遍历段内记录定位
        // （iter_tls_records 自校验记录头，非 TLS 载荷零命中直接返回）
        if let Some(cert) = protocols::tls::iter_tls_records(payload)
            .find(|r| protocols::tls::is_certificate_message(r))
            .and_then(protocols::tls::parse_certificate)
            && let Some(Metadata::Tls(ref mut tls)) = flow.metadata
        {
            tls.cert_subject = cert.subject;
            tls.cert_issuer = cert.issuer;
            tls.cert_valid_from = cert.not_before;
            tls.cert_valid_to = cert.not_after;
        }
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
            // 在过期前对流运行 analyze_flow（R5 修复：过期窗口取 FlowTable 真实
            // 超时配置，而非硬编码 120s——否则 with_config 自定义 timeout 时
            // analyze 窗口与实际过期窗口错位）。
            let timeout = self.flow_table.timeout();
            let keys: Vec<FlowKey> = self
                .flow_table
                .iter()
                .filter(|(_, f)| {
                    std::time::Instant::now().duration_since(f.stats.last_time) > timeout
                })
                .map(|(k, _)| k.clone())
                .collect();
            for key in &keys {
                if let Some(flow) = self.flow_table.get(key) {
                    // 流级风险结果收进 pending_risks（drain_risks 出口），
                    // 此前被 `let _risks = ...` 直接丢弃
                    for r in self.risk_registry.analyze_flow(flow) {
                        // 观察者推送（流级风险）
                        if let Some(cb) = self.risk_callback.as_ref() {
                            cb(key.clone(), &r);
                        }
                        self.pending_risks.push((key.clone(), r));
                    }
                }
            }
        }
        self.flow_table.expire_timeout()
    }

    /// 注册风险事件推送回调（观察者模式）
    ///
    /// 逐包风险（detect 路径）与流级风险（expire_flows 过期时）产生即推送，
    /// 适合接入告警管道等即时消费方。回调是观察者：不影响 `drain_risks`
    /// 拉取路径——同时使用两条通道会收到相同事件，消费方应择一订阅。
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut detector = Detector::new();
    /// detector.set_risk_callback(|flow_key, risk| {
    ///     eprintln!("risk {:?} on {:?}", risk.flag, flow_key);
    /// });
    /// ```
    #[cfg(feature = "risk")]
    pub fn set_risk_callback(&mut self, cb: impl Fn(FlowKey, &RiskResult) + Send + Sync + 'static) {
        self.risk_callback = Some(Box::new(cb));
    }

    /// 收集并清空累积的风险结果（风险出口）
    ///
    /// 汇总两个来源并清空：
    /// 1. 各活跃流 `flow.risks` 的逐包累积（收集后清空，避免长流无界增长）
    /// 2. `expire_flows` 过期时流级 `analyze_flow` 的结果（暂存缓冲）
    ///
    /// 逐包风险本可通过 `detect()` 返回的 `DetectionResult.risks` 即时获取；
    /// 本方法面向轮询式消费方——以流为单位批量收割风险事件。
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut detector = Detector::new();
    /// // ... detect 循环 ...
    /// for (flow_key, risk) in detector.drain_risks() {
    ///     println!("{:?}: {:?}", flow_key, risk.flag);
    /// }
    /// ```
    #[cfg(feature = "risk")]
    pub fn drain_risks(&mut self) -> Vec<(FlowKey, RiskResult)> {
        let mut out = std::mem::take(&mut self.pending_risks);
        for (key, flow) in self.flow_table.iter_mut() {
            for r in flow.risks.drain(..) {
                out.push((key.clone(), r));
            }
        }
        out
    }

    /// 清空流表
    pub fn clear_flows(&mut self) {
        self.flow_table.clear();
        #[cfg(feature = "risk")]
        {
            // 流已清空，暂存的过期风险随之无意义，一并清掉
            self.pending_risks.clear();
        }
    }
}

impl Default for Detector {
    fn default() -> Self {
        Self::with_registry(Registry::default())
    }
}
