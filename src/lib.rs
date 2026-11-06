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
    /// 猜测引擎粘性禁用（disable_guess 置位；set_guess_engine 复位）。
    /// 置位时 giveup 阶段不猜测，且惰性构建不生效。
    guess_disabled: bool,
    /// 猜测引擎（None = 尚未构建，首次 giveup 时惰性创建默认引擎——
    /// 域名表背后是 aho-corasick 自动机，不应在 Detector::new / 逐包重建）
    guess_engine: Option<GuessEngine>,
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
            guess_disabled: false,
            guess_engine: None,
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
            guess_disabled: false,
            guess_engine: None,
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
    ///
    /// 新流标记为 dpi_only；猜测引擎停用（含惰性构建——已存在流 giveup 后
    /// 也不再猜测）。[`Self::set_guess_engine`] 可重新注入引擎恢复猜测。
    pub fn disable_guess(&mut self) {
        self.default_guess = false;
        self.guess_disabled = true;
        self.guess_engine = None;
    }

    /// 替换猜测引擎（可注入自定义域名/IP 子网/端口映射，见
    /// [`GuessEngine::builder`]），并解除 disable_guess 的粘性禁用。
    ///
    /// 注意：disable_guess 之后创建的流已带 dpi_only 标记，永不进入 giveup；
    /// disable_guess 之前已存在的流在注入引擎后恢复猜测。
    ///
    /// # Examples
    ///
    /// ```
    /// use rdpi::{Detector, core::guess::GuessEngine, core::types::Protocol};
    ///
    /// let mut detector = Detector::new();
    /// detector.set_guess_engine(
    ///     GuessEngine::builder()
    ///         .with_custom_ports(vec![(9000, Protocol::Other(9000))])
    ///         .build(),
    /// );
    /// ```
    pub fn set_guess_engine(&mut self, engine: GuessEngine) {
        self.guess_disabled = false;
        self.guess_engine = Some(engine);
    }

    /// 使用规则创建检测器
    #[cfg(feature = "rule")]
    pub fn with_rules(rules: Vec<Rule>) -> Self {
        Self {
            registry: Registry::default(),
            flow_table: FlowTable::new(10000, Duration::from_secs(120)),
            default_guess: true,
            guess_disabled: false,
            guess_engine: None,
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
        self.detect_at(packet, std::time::SystemTime::now())
    }

    /// 检测单个包（携带包到达时刻，F35：JA4L 时延指纹需要真实的包间隔）
    ///
    /// [`Self::detect`] 以处理时刻计时——实时接入时即为到达时刻；离线 pcap
    /// 回放时包间处理间隔趋近于零，JA4L 数值将失去意义，应改用本入口传入
    /// pcap 记录的捕获时戳（CLI 已接入）。
    ///
    /// # Arguments
    ///
    /// * `packet` - 原始以太网帧字节
    /// * `arrival` - 包到达时刻（离线回放传捕获时戳；须单调不回退，乱序包
    ///   的时延计算自动跳过，与官方 zeek 负时长报错跳过语义一致）
    pub fn detect_at(
        &mut self,
        packet: &[u8],
        arrival: std::time::SystemTime,
    ) -> crate::error::Result<Option<DetectionResult>> {
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

        // F35：JA4L 时延观测——需跨方向流读对端握手时戳（A/B 分布在两条
        // 方向流上），在 get_or_create 之前独立完成流表读写，避免借用冲突。
        // 仅 TCP 参与（TcpHeaderInfo 携带 TTL）。
        // F36：JA4SSH 会话观测——同样需跨方向流聚合双向窗口计数，同址复用。
        // F40：JA4TS 第 5 段收集的客户端关闭观测——同址复用（服务端方向包的
        // 延迟收集在 get_or_create 之后的主流程块内完成）。
        // F41：QUIC JA4L 时延观测——UDP 分支，长包头 type 位免解密判定。
        if let Some(tcp) = parsed.tcp.as_ref() {
            Self::observe_ja4l(&mut self.flow_table, &key, arrival, tcp);
            Self::observe_ja4ssh(&mut self.flow_table, &key, tcp.flags, parsed.payload.len());
            Self::observe_ja4ts_shutdown(&mut self.flow_table, &key);
        } else if parsed.transport == TransportProto::Udp {
            Self::observe_ja4l_quic(
                &mut self.flow_table,
                &key,
                arrival,
                &parsed.payload,
                parsed.ttl,
            );
        }

        // 获取或创建流
        let flow = self.flow_table.get_or_create(key.clone());

        // 新创建的流继承 Detector 的 guess 设置
        if flow.packets_seen == 0 {
            flow.dpi_only = !self.default_guess;
        }

        // 增加包计数
        flow.packets_seen += 1;

        // F33：JA4T 客户端 TCP 指纹——仅初始 SYN（SYN 置位且 ACK 清零；
        // SYN+ECN 同样满足，SYN-ACK 不算），每流只取第一个满足的包（对齐
        // FoxIO 官方 rust/ja4 tcp.rs）。存流级旁路字段，不占用
        // protocol/metadata 的一次定型语义，不影响后续协议识别。
        if flow.ja4t.is_none()
            && parsed
                .tcp
                .is_some_and(|tcp| tcp.flags & 0x02 != 0 && tcp.flags & 0x10 == 0)
        {
            // unwrap 安全：is_some_and 已确认 tcp 存在
            let tcp = parsed.tcp.unwrap();
            flow.ja4t = Some(application::compute_ja4t(
                tcp.window,
                &tcp.option_kinds[..tcp.option_kinds_len],
                tcp.mss,
                tcp.window_scale,
            ));
        }

        // F40：JA4TS 第 5 段收集——SYN-ACK 重传延迟 / RST 后缀（官方 zeek
        // ja4t/main.zeek：距最近 SYN-ACK 超 120 秒停止；RST 记 `-R{整秒}` 后缀
        // 并停止；精确 0x12 重传记相邻间隔整秒，至多 10 项满即停；其余包不动
        // 状态）。客户端方向包的关闭在 observe_ja4ts_shutdown（get_or_create
        // 之前）完成。本块先于首个 SYN-ACK 捕获块执行，避免同一包既当基串
        // 又当重传。
        if flow.ja4ts.is_some()
            && flow.ja4ts_tracking
            && let Some(tcp) = parsed.tcp.as_ref()
            && let Some(last) = flow.ja4ts_synack_time
            && let Ok(d) = arrival.duration_since(last)
        {
            if d > application::JA4TS_TRACK_TIMEOUT {
                flow.ja4ts_tracking = false;
            } else if tcp.flags & 0x04 != 0 {
                // RST（含 RST|ACK 等）：记后缀延迟（整秒截断，官方
                // double_to_count 语义）并停止收集
                flow.ja4ts_rst_delay = Some(u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
                flow.ja4ts_tracking = false;
            } else if tcp.flags == 0x12 && flow.ja4ts_delays.len() < application::JA4TS_MAX_DELAYS {
                flow.ja4ts_delays
                    .push(u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
                flow.ja4ts_synack_time = Some(arrival);
                if flow.ja4ts_delays.len() == application::JA4TS_MAX_DELAYS {
                    flow.ja4ts_tracking = false;
                }
            }
        }

        // F34：JA4TS 服务端 TCP 指纹——服务端 SYN-ACK（flags 精确等于 SYN|ACK，
        // 对齐官方 zeek/ja4t/main.zeek），每流只取第一个满足的包。存服务端方向流
        // （FlowKey 方向性：SYN-ACK 与 SYN 属两条流）的旁路字段，不占用
        // protocol/metadata 的一次定型语义，不影响后续协议识别。
        // F40：首个 SYN-ACK 同时启动第 5 段重传延迟收集（官方 last_ts 语义）。
        if flow.ja4ts.is_none() && parsed.tcp.is_some_and(|tcp| tcp.flags == 0x12) {
            // unwrap 安全：is_some_and 已确认 tcp 存在
            let tcp = parsed.tcp.unwrap();
            flow.ja4ts = Some(application::compute_ja4ts(
                tcp.window,
                &tcp.option_kinds[..tcp.option_kinds_len],
                tcp.mss,
                tcp.window_scale,
            ));
            flow.ja4ts_synack_time = Some(arrival);
            flow.ja4ts_tracking = true;
        }

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
                    Metadata::Dtls(dtls) => dtls.sni.clone(),
                    _ => None,
                });
                #[cfg(feature = "tls")]
                let sni = sni.or_else(|| protocols::tls::extract_sni(&parsed.payload));
                #[cfg(all(feature = "quic", feature = "tls"))]
                let sni = sni.or_else(|| {
                    // QUIC Initial：解密 ClientHello 提取 SNI（非 Initial 包在
                    // parse_initial_header 处快速拒绝，无额外开销）
                    protocols::quic::decrypt_client_hello(&parsed.payload).and_then(|ch| ch.sni)
                });
                let rule_ctx = RuleContext {
                    src_port: parsed.src_port,
                    dst_port: parsed.dst_port,
                    sni,
                    payload: parsed.payload.clone(),
                };
                if let Some(mut r) = engine.match_rule(&rule_ctx) {
                    r.ja4t = flow.ja4t.clone();
                    r.ja4ts = Self::flow_ja4ts_full(flow);
                    r.ja4ls = flow.ja4ls.clone();
                    r.ja4lc = flow.ja4lc.clone();
                    r.ja4ssh = flow.ja4ssh.clone();
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
                        Metadata::Dtls(dtls) => dtls.sni.clone(),
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
                // 引擎惰性构建 + 随 Detector 复用（域名表为 aho-corasick 自动机，勿逐包重建）
                let guess = if self.guess_disabled {
                    None
                } else {
                    self.guess_engine
                        .get_or_insert_with(GuessEngine::new)
                        .guess(&ctx)
                };

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

            // JA4S：已定型 TLS 流在后续包收到 ServerHello 记录时，
            // 一次性补算服务端指纹（写回 flow.metadata，回显自动携带）
            #[cfg(feature = "tls")]
            Self::enrich_tls_ja4s(flow, &parsed.payload);

            // HTTP/2 定型流：首个请求 HEADERS 帧常在 preface 之后的独立包到达，
            // 一次性提取 :authority/:method/:path（写回 flow.metadata，回显自动携带）
            #[cfg(feature = "proto3")]
            Self::enrich_http2_headers(flow, &parsed.payload);

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

        // 如果有检测结果，保存元数据（并携带流级 JA4T/JA4TS/JA4L/JA4SSH，若此前已捕获）
        if let Some(ref mut r) = result {
            r.ja4t = flow.ja4t.clone();
            r.ja4ts = Self::flow_ja4ts_full(flow);
            r.ja4ls = flow.ja4ls.clone();
            r.ja4lc = flow.ja4lc.clone();
            r.ja4ssh = flow.ja4ssh.clone();
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

        // F42：JA4L TLS 精化段（delta）观测——D/E/F 三时点，信号取自结果
        // 元数据；仅 TCP（zeek delta 为 TCP TLS 专用路径，QUIC/DTLS 不参与）。
        // 置于流统计/回显拷贝之后：此处 flow 借用已终结，可独立借流表做跨向读。
        if parsed.transport == TransportProto::Tcp {
            Self::observe_ja4l_tls(
                &mut self.flow_table,
                &key,
                arrival,
                result.as_ref(),
                !parsed.payload.is_empty(),
            );
        }

        Ok(result)
    }

    /// 处理 L3 包（调用方持有 Flow）
    ///
    /// 输入为 IPv4/IPv6 包（不含以太网头）。与 [`Self::detect_at`] 不同：
    /// - flow 由调用方持有，Detector 不访问内部 `FlowTable`；
    /// - 双向流：反向包通过 [`Flow::direction_of`] 映射到同一 `Flow`；
    /// - 当前接入内置 DPI 与双向计数；规则/风险/JA4 富化尚未接入该入口。
    ///
    /// # Errors
    ///
    /// 包无法解析，或包不属于传入的 flow 时返回错误。
    pub fn process_l3_packet(
        &mut self,
        flow: &mut Flow,
        packet: &[u8],
        timestamp_ms: u64,
    ) -> crate::error::Result<Option<DetectionResult>> {
        let parsed = parser::parse_l3_packet(packet)?;
        let packet_key = FlowKey {
            src_ip: parsed.src_ip,
            dst_ip: parsed.dst_ip,
            src_port: parsed.src_port,
            dst_port: parsed.dst_port,
            transport: parsed.transport,
        };
        let direction = flow.direction_of(&packet_key).ok_or_else(|| {
            crate::error::Error::InvalidPacket(
                "packet does not belong to the supplied flow".to_string(),
            )
        })?;

        flow.packets_seen += 1;
        flow.stats.packets += 1;
        flow.stats.bytes += packet.len() as u64;
        flow.stats.last_time = std::time::Instant::now();
        if flow.first_seen_ms.is_none() {
            flow.first_seen_ms = Some(timestamp_ms);
        }
        flow.last_seen_ms = Some(timestamp_ms);
        match direction {
            Direction::Forward => {
                flow.packets_forward += 1;
                flow.bytes_forward += packet.len() as u64;
            }
            Direction::Reverse => {
                flow.packets_reverse += 1;
                flow.bytes_reverse += packet.len() as u64;
            }
        }

        // 已完全定型：回显协议、元数据与协议栈，不重复检测。
        if flow.classification_state == ClassificationState::Classified
            && let Some(protocol) = flow.protocol
        {
            let mut result = DetectionResult::new(protocol);
            result.protocol_stack = flow.protocol_stack;
            if let Some(ref metadata) = flow.metadata {
                result.metadata = metadata.clone();
            }
            return Ok(Some(result));
        }

        // Inspecting / Partial：继续逐包检测，允许 partial → classified 升级。
        let mut result =
            self.registry
                .detect_with_ports(&parsed.payload, parsed.src_port, parsed.dst_port);
        if let Some(ref mut detected) = result {
            flow.protocol = Some(detected.protocol);
            flow.metadata = Some(detected.metadata.clone());
            flow.protocol_stack.push(detected.protocol);
            detected.protocol_stack = flow.protocol_stack;
            flow.classification_state = match detected.confidence {
                Confidence::Dpi | Confidence::CustomRule => ClassificationState::Classified,
                _ => ClassificationState::Partial,
            };
        } else if let Some(protocol) = flow.protocol {
            // 本包没有新结果：保留并回显已有 partial 分类。
            let mut replay = DetectionResult::new(protocol);
            replay.protocol_stack = flow.protocol_stack;
            if let Some(ref metadata) = flow.metadata {
                replay.metadata = metadata.clone();
            }
            return Ok(Some(replay));
        }
        Ok(result)
    }

    /// F42：JA4L TLS 精化段（delta）观测（官方 zeek ja4l/main.zeek
    /// `ssl_client_hello`/`ssl_server_hello`/数据阈值分支语义，TCP TLS 专用）
    ///
    /// 在 DPI 之后调用（信号取自检测结果元数据的精确推断：`ja4` Some ⇔ 本段
    /// 含 ClientHello、`ja4s` Some ⇔ 含 ServerHello——TLS 检测器逐记录解析
    /// 产物，识别包与回显包同义）。三时点状态机（全部每流一次）：
    /// 1. D 记录：客户端方向含 ClientHello 的包 → 当前（客户端）流
    /// 2. E 记录 + JA4L-S 第三段：服务端方向含 ServerHello 的包 → 读对端 D，
    ///    `(E-D)/2`（微秒）以 `_` 追加至本流 ja4ls（成 `{半程}_{TTL}_{delta}`
    ///    三段；对端无 D 或时戳回退则不追加，zeek 负时长报错跳过同义）
    /// 3. F 记录 + JA4L-C 第三段：E 已记之后首个**有载荷**客户端包（zeek
    ///    `dl == 0` 等待实际数据语义，纯 ACK 不触发）→ `(F-E)/2` 追加至
    ///    本流 ja4lc
    ///
    /// 方向判定借 F35 握手时戳：本流 syn_time / 对端 synack_time = 客户端；
    /// 本流 synack_time / 对端 syn_time = 服务端（放宽于 zeek 的 is_orig——
    /// 从 SYN-ACK 起抓包仍可判定方向）；mid-stream（两侧均无握手时戳）跳过。
    fn observe_ja4l_tls(
        flow_table: &mut FlowTable,
        key: &FlowKey,
        arrival: std::time::SystemTime,
        result: Option<&DetectionResult>,
        has_payload: bool,
    ) {
        let Some(r) = result else { return };
        let Metadata::Tls(t) = &r.metadata else {
            return;
        };
        let client_hello = t.ja4.is_some();
        let server_hello = t.ja4s.is_some();
        if !client_hello && !server_hello && !has_payload {
            return;
        }

        // 对端方向流键（FlowKey 方向性）+ 自连路径保护
        let mut reverse = key.clone();
        std::mem::swap(&mut reverse.src_ip, &mut reverse.dst_ip);
        std::mem::swap(&mut reverse.src_port, &mut reverse.dst_port);
        if *key == reverse {
            return;
        }

        // 方向判定（借 F35 握手时戳，至少观测到一个握手包才参与）
        let is_client = flow_table.get(key).is_some_and(|f| f.syn_time.is_some())
            || flow_table
                .get(&reverse)
                .is_some_and(|f| f.synack_time.is_some());
        let is_server = flow_table.get(key).is_some_and(|f| f.synack_time.is_some())
            || flow_table
                .get(&reverse)
                .is_some_and(|f| f.syn_time.is_some());

        // D：客户端 ClientHello（每流一次）
        if client_hello && is_client {
            let f = flow_table.get_or_create(key.clone());
            if f.tls_client_hello_time.is_none() {
                f.tls_client_hello_time = Some(arrival);
            }
        }
        // E：服务端 ServerHello（每流一次）+ 对端 D 已记则追加 ja4ls 第三段
        if server_hello && is_server {
            let first = {
                let f = flow_table.get_or_create(key.clone());
                if f.tls_server_hello_time.is_none() {
                    f.tls_server_hello_time = Some(arrival);
                    true
                } else {
                    false
                }
            };
            if first
                && let Some(d) = flow_table
                    .get(&reverse)
                    .and_then(|p| p.tls_client_hello_time)
                && let Some(delta) = arrival.duration_since(d).ok()
                && let Some(f) = flow_table.get_mut(key)
                && let Some(s) = f.ja4ls.as_mut()
            {
                s.push_str(&format!("_{}", delta.as_micros() as u64 / 2));
            }
        }
        // F：E 之后首个有载荷客户端包（每流一次）+ 追加 ja4lc 第三段
        if has_payload && is_client {
            let e = flow_table
                .get(&reverse)
                .and_then(|p| p.tls_server_hello_time);
            if let Some(e) = e {
                let first = {
                    let f = flow_table.get_or_create(key.clone());
                    if f.tls_first_client_data_time.is_none() {
                        f.tls_first_client_data_time = Some(arrival);
                        true
                    } else {
                        false
                    }
                };
                if first
                    && let Some(delta) = arrival.duration_since(e).ok()
                    && let Some(f) = flow_table.get_mut(key)
                    && let Some(s) = f.ja4lc.as_mut()
                {
                    s.push_str(&format!("_{}", delta.as_micros() as u64 / 2));
                }
            }
        }
    }

    /// F35：JA4L 时延观测（官方 zeek ja4l/main.zeek + python ja4.py 同源语义）
    ///
    /// 在 [`Detector::detect_at`] 的 get_or_create 之前调用，独立持有流表借用：
    /// A（客户端 SYN 时戳）与 B（服务端 SYN-ACK 时戳）分布在两条方向流上，
    /// 计算时延需反查对端流。状态机（全部每流一次）：
    /// 1. A 记录：客户端 SYN（SYN 置位 ACK 清零）→ 当前（客户端）流
    /// 2. B 记录 + JA4L-S：SYN-ACK（SYN/ACK 均置位）→ 读对端 A，半程时延
    ///    `(B-A)/2`（微秒整除 2）+ SYN-ACK TTL 写当前（服务端）流
    /// 3. C 捕获 + JA4L-C：流已记录 A 之后的客户端包（纯 ACK 或数据均可，
    ///    对齐 zeek 第二发起包语义）→ 读对端 B，`(C-B)/2` + SYN TTL 写当前流
    ///
    /// 对端流不存在（mid-stream 抓包缺握手起点）或时戳回退（乱序）时跳过，
    /// 指纹保持 None（zeek 负时长报错跳过同义）。
    fn observe_ja4l(
        flow_table: &mut FlowTable,
        key: &FlowKey,
        arrival: std::time::SystemTime,
        tcp: &crate::parser::TcpHeaderInfo,
    ) {
        let syn_only = tcp.flags & 0x02 != 0 && tcp.flags & 0x10 == 0;
        let syn_ack = tcp.flags & 0x02 != 0 && tcp.flags & 0x10 != 0;

        // 对端方向流键（SYN/SYN-ACK 分属两条方向流）
        let mut reverse = key.clone();
        std::mem::swap(&mut reverse.src_ip, &mut reverse.dst_ip);
        std::mem::swap(&mut reverse.src_port, &mut reverse.dst_port);

        // 1. A：客户端 SYN 时戳 + TTL（每流一次）
        if syn_only {
            let f = flow_table.get_or_create(key.clone());
            if f.syn_time.is_none() {
                f.syn_time = Some(arrival);
                f.syn_ttl = Some(tcp.ttl);
            }
        }

        // 2. B：服务端 SYN-ACK 时戳 + TTL（每流一次），命中即算 JA4L-S
        if syn_ack {
            let b_new = {
                let f = flow_table.get_or_create(key.clone());
                if f.synack_time.is_none() {
                    f.synack_time = Some(arrival);
                    f.synack_ttl = Some(tcp.ttl);
                    true
                } else {
                    false
                }
            };
            if b_new {
                let a_time = flow_table.get(&reverse).and_then(|p| p.syn_time);
                if let Some(a) = a_time
                    && let Some(d) = arrival.duration_since(a).ok()
                {
                    let fp = application::compute_ja4ls(d.as_micros() as u64, tcp.ttl);
                    flow_table.get_or_create(key.clone()).ja4ls = Some(fp);
                }
            }
        }

        // 3. C：SYN 之后（非首包）且未算过 JA4L-C 的客户端包，对端 B 已记录
        //    即捕获（B 未到时保持 None，后续客户端包继续尝试——乱序容忍）
        let c_try = {
            let f = flow_table.get_or_create(key.clone());
            f.syn_time.is_some() && f.ja4lc.is_none() && f.packets_seen >= 1
        };
        if c_try {
            let b_time = flow_table.get(&reverse).and_then(|p| p.synack_time);
            let client_ttl = flow_table.get(key).and_then(|p| p.syn_ttl);
            if let (Some(b), Some(ct)) = (b_time, client_ttl)
                && let Some(d) = arrival.duration_since(b).ok()
            {
                let fp = application::compute_ja4lc(d.as_micros() as u64, ct);
                flow_table.get_or_create(key.clone()).ja4lc = Some(fp);
            }
        }
    }

    /// F41：QUIC JA4L 时延观测（官方 zeek ja4l/main.zeek `QUIC::initial_packet`
    /// / `QUIC::handshake_packet` 语义）
    ///
    /// 在 [`Detector::detect_at`] 的 get_or_create 之前调用，独立持有流表
    /// 借用（四时戳分布在两条方向流上，同 [`Self::observe_ja4l`]）。设计要点：
    /// 1. 免解密判定：QUIC 长包头 packet-type 位不受 header protection 保护
    ///    （RFC 9001 掩码仅异或首字节低 4 位）——首字节 `& 0xc0 == 0xc0`
    ///    （fixed + long）后 type 位 = `(首字节 >> 4) & 0x03`：
    ///    0 = Initial、2 = Handshake。
    /// 2. 版本门控：仅 QUIC v1（version 字段 == 0x00000001；草稿版/版本
    ///    协商跳过，见 risks.md F41 边界）。
    /// 3. 四时点：client Initial（A'，记时戳 + TTL）→ server Initial（记
    ///    时戳并一次算 JA4L-S = (server_init - client_init)/2 µs，三段
    ///    `{µs}_{服务端TTL}_q`）→ server Handshake（B'，记时戳）→ client
    ///    Handshake（算 JA4L-C = (client_hs - server_hs)/2 µs，`{µs}_{客户端
    ///    Initial TTL}_q`，B' 未到时后续 Handshake 包继续尝试——乱序容忍）。
    /// 4. 乱序（时戳回退）跳过；mid-stream 缺握手起点跳过（zeek 对缺失
    ///    时戳按 0 参与计算会产出巨值，此处按 F35 先例显式跳过）；重传
    ///    Initial 不覆盖（每流一次，zeek 无守卫，故意收紧）。
    fn observe_ja4l_quic(
        flow_table: &mut FlowTable,
        key: &FlowKey,
        arrival: std::time::SystemTime,
        payload: &[u8],
        ttl: u8,
    ) {
        // 长包头门：首字节 fixed+long 位 + 首字节与 4 字节 version 可读
        if payload.len() < 5 || payload[0] & 0xc0 != 0xc0 {
            return;
        }
        // 仅 QUIC v1（草稿版/版本协商不追踪，risks.md F41 边界）
        if u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) != 0x0000_0001 {
            return;
        }
        let pkt_type = (payload[0] >> 4) & 0x03;

        // 对端方向流键（FlowKey 方向性）
        let mut reverse = key.clone();
        std::mem::swap(&mut reverse.src_ip, &mut reverse.dst_ip);
        std::mem::swap(&mut reverse.src_port, &mut reverse.dst_port);
        if *key == reverse {
            return; // 自连路径保护
        }

        match pkt_type {
            // Initial：对端已有 A'（本流为服务端）→ 记时戳并一次算 JA4L-S；
            // 否则视为客户端首个 Initial，记 A'（时戳 + TTL，每流一次）
            0x00 => {
                let is_server = flow_table
                    .get(&reverse)
                    .is_some_and(|f| f.quic_client_init_time.is_some());
                if is_server {
                    let first = {
                        let f = flow_table.get_or_create(key.clone());
                        if f.quic_server_init_time.is_none() {
                            f.quic_server_init_time = Some(arrival);
                            true
                        } else {
                            false
                        }
                    };
                    if first
                        && let Some(a) = flow_table
                            .get(&reverse)
                            .and_then(|p| p.quic_client_init_time)
                        && let Some(d) = arrival.duration_since(a).ok()
                    {
                        let fp = application::compute_ja4ls_quic(d.as_micros() as u64, ttl);
                        flow_table.get_or_create(key.clone()).ja4ls = Some(fp);
                    }
                } else {
                    let f = flow_table.get_or_create(key.clone());
                    if f.quic_client_init_time.is_none() {
                        f.quic_client_init_time = Some(arrival);
                        f.quic_client_init_ttl = Some(ttl);
                    }
                }
            }
            // Handshake：本流已有 A'（客户端）→ 对端 B' 已记则一次算
            // JA4L-C；对端有 A'（本流为服务端）→ 记 B'；两侧均无 A'
            // （mid-stream）→ 跳过
            0x02 => {
                let am_client = flow_table
                    .get(key)
                    .is_some_and(|f| f.quic_client_init_time.is_some());
                if am_client {
                    let b = flow_table.get(&reverse).and_then(|p| p.quic_server_hs_time);
                    let ct = flow_table.get(key).and_then(|p| p.quic_client_init_ttl);
                    let uncalced = flow_table.get(key).is_some_and(|f| f.ja4lc.is_none());
                    if uncalced
                        && let (Some(b), Some(ct)) = (b, ct)
                        && let Some(d) = arrival.duration_since(b).ok()
                    {
                        let fp = application::compute_ja4lc_quic(d.as_micros() as u64, ct);
                        flow_table.get_or_create(key.clone()).ja4lc = Some(fp);
                    }
                } else if flow_table
                    .get(&reverse)
                    .is_some_and(|f| f.quic_client_init_time.is_some())
                {
                    let f = flow_table.get_or_create(key.clone());
                    if f.quic_server_hs_time.is_none() {
                        f.quic_server_hs_time = Some(arrival);
                    }
                }
            }
            _ => {}
        }
    }

    /// F36：JA4SSH 会话观测（官方 zeek ja4ssh/main.zeek 语义）
    ///
    /// 在 [`Detector::detect_at`] 的 get_or_create 之前调用，独立持有流表借用：
    /// 窗口聚合需要双向计数（c2s/s2c 分布在两条方向流上）。设计要点：
    /// 1. 门控：仅已定型为 SSH 的流参与（对齐 zeek 的 SSH 版本横幅确认门），
    ///    且连接须自初始 SYN 起（zeek `new_connection` 要求 flags 精确等于
    ///    TH_SYN，mid-stream 会话不追踪）——借 F35 的 syn_time 判定。
    /// 2. 本方向累计：载荷包（payload > 0）长度入序列；纯 ACK（无载荷且
    ///    flags 精确等于 0x10）计数 +1；其余（裸 SYN/FIN/RST 等）不计。
    /// 3. 窗口：双向载荷包合计 ≥ [`application::JA4SSH_WINDOW_PACKETS`] 时
    ///    产出指纹写两个方向流并清零滚动窗口（zeek 逐窗口出日志，此处保留
    ///    最近完成窗口）。方向归位：SYN 发送端为客户端（zeek orig 语义）。
    ///
    /// 定型当包不计入（横幅包错过，1-2/200，见 risks.md F36 边界）。
    fn observe_ja4ssh(
        flow_table: &mut FlowTable,
        key: &FlowKey,
        tcp_flags: u8,
        payload_len: usize,
    ) {
        // 门控 1：仅已定型 SSH 的流参与（定型前的横幅包由检测当包处理）
        if !flow_table
            .get(key)
            .is_some_and(|f| f.protocol == Some(Protocol::Ssh))
        {
            return;
        }

        // 对端方向流键（FlowKey 方向性）
        let mut reverse = key.clone();
        std::mem::swap(&mut reverse.src_ip, &mut reverse.dst_ip);
        std::mem::swap(&mut reverse.src_port, &mut reverse.dst_port);
        if *key == reverse {
            return; // 自连路径保护（reverse 借用冲突不可能发生）
        }

        // 门控 2：连接自初始 SYN 起（zeek 仅跟踪 TH_SYN 开启的连接）
        let syn_seen = flow_table.get(key).is_some_and(|f| f.syn_time.is_some())
            || flow_table
                .get(&reverse)
                .is_some_and(|f| f.syn_time.is_some());
        if !syn_seen {
            return;
        }

        // 本方向累计：载荷包长度入序列 / 纯 ACK 计数（对齐 zeek：dl==0 且
        // flags==0x10 记 ACK，dl>0 记长度，其余不计）
        {
            let f = flow_table.get_mut(key).expect("门控已确认存在");
            if payload_len > 0 {
                f.ssh_payload_lens
                    .push(u16::try_from(payload_len).unwrap_or(u16::MAX));
            } else if tcp_flags == 0x10 {
                f.ssh_ack_count += 1;
            }
        }

        // 窗口判定：双向载荷包合计
        let own_len = flow_table
            .get(key)
            .map(|f| f.ssh_payload_lens.len())
            .unwrap_or(0);
        let rev_len = flow_table
            .get(&reverse)
            .map(|f| f.ssh_payload_lens.len())
            .unwrap_or(0);
        if own_len + rev_len < application::JA4SSH_WINDOW_PACKETS {
            return;
        }

        // 方向归位：SYN 发送端为客户端（zeek orig 语义）。syn_seen 门控保证
        // 至少一方有 syn_time；对端流缺失（仅单方向累计满窗口）时对端记空窗口。
        let own_is_client = flow_table.get(key).is_some_and(|f| f.syn_time.is_some());
        let empty: &[u16] = &[];
        let (c_lens, c_ack, s_lens, s_ack);
        {
            let o = flow_table.get(key).expect("门控已确认存在");
            let r = flow_table.get(&reverse);
            let (o_lens, o_ack) = (o.ssh_payload_lens.as_slice(), o.ssh_ack_count);
            let (r_lens, r_ack) = (
                r.map(|f| f.ssh_payload_lens.as_slice()).unwrap_or(empty),
                r.map(|f| f.ssh_ack_count).unwrap_or(0),
            );
            if own_is_client {
                (c_lens, c_ack, s_lens, s_ack) = (o_lens, o_ack, r_lens, r_ack);
            } else {
                (c_lens, c_ack, s_lens, s_ack) = (r_lens, r_ack, o_lens, o_ack);
            }
        }
        let fp = application::compute_ja4ssh(c_lens, s_lens, c_ack, s_ack);

        // 写两个方向流并清零滚动窗口（zeek do_ja4ssh 后复位计数）
        if let Some(f) = flow_table.get_mut(key) {
            f.ja4ssh = Some(fp.clone());
            f.ssh_payload_lens.clear();
            f.ssh_ack_count = 0;
        }
        if let Some(f) = flow_table.get_mut(&reverse) {
            f.ja4ssh = Some(fp);
            f.ssh_payload_lens.clear();
            f.ssh_ack_count = 0;
        }
    }

    /// F40：JA4TS 第 5 段收集的客户端关闭观测（官方 zeek/ja4t/main.zeek：
    /// 任一 orig 方向包即停止 SYN-ACK 重传延迟收集——正常握手里客户端的
    /// 完成 ACK 到达后，后续 SYN-ACK 重传不再计入）
    ///
    /// 在 [`Detector::detect_at`] 的 get_or_create 之前调用，独立持有流表借用
    /// （关闭的是对端方向流）。客户端方向判定：syn_time 由 [`Self::observe_ja4l`]
    /// 记录在 SYN 发送端流——mid-stream 客户端流无 syn_time，无关闭信号
    /// （见 risks.md F40 边界）。
    fn observe_ja4ts_shutdown(flow_table: &mut FlowTable, key: &FlowKey) {
        // 仅客户端方向包参与关闭（服务端方向包走主流程的延迟收集块）
        if !flow_table.get(key).is_some_and(|f| f.syn_time.is_some()) {
            return;
        }
        let mut reverse = key.clone();
        std::mem::swap(&mut reverse.src_ip, &mut reverse.dst_ip);
        std::mem::swap(&mut reverse.src_port, &mut reverse.dst_port);
        if let Some(peer) = flow_table.get_mut(&reverse)
            && peer.ja4ts_tracking
        {
            peer.ja4ts_tracking = false;
        }
    }

    /// F40：组合 JA4TS 完整官方格式（4 段基串 + 第 5 段重传延迟 + RST 后缀）。
    ///
    /// `Flow.ja4ts` 恒为 [`application::compute_ja4ts`] 的 4 段基串（一次定型，
    /// 重传不覆盖），扩展段在结果落库时按跟踪状态组合——无重传时输出与基串
    /// 一致（官方语义），热路径零额外分配（组合仅在结果构建处发生一次）。
    fn flow_ja4ts_full(flow: &Flow) -> Option<String> {
        flow.ja4ts
            .as_ref()
            .map(|base| application::compose_ja4ts(base, &flow.ja4ts_delays, flow.ja4ts_rst_delay))
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
            tls.cert_ja4x = cert.ja4x;
        }
    }

    /// TLS 流 JA4S 一次性富化（对齐 enrich_tls_cert 先例，ADR-0004）
    ///
    /// 定型 TLS 流（服务端方向或合包场景）的载荷中定位首个 ServerHello 记录，
    /// 计算服务端指纹写回 flow.metadata。协议不重检；ja4s 已填充直接返回。
    #[cfg(feature = "tls")]
    fn enrich_tls_ja4s(flow: &mut Flow, payload: &[u8]) {
        let needs_enrich = matches!(
            flow.metadata,
            Some(Metadata::Tls(ref tls)) if tls.ja4s.is_none()
        );
        if !needs_enrich || flow.protocol != Some(Protocol::Tls) {
            return;
        }
        // 连体记录场景下 ServerHello 可能不在段首——遍历段内记录定位
        if let Some(sh) =
            protocols::tls::iter_tls_records(payload).find_map(protocols::tls::parse_server_hello)
            && let Some(Metadata::Tls(ref mut tls)) = flow.metadata
        {
            tls.ja4s = Some(crate::application::compute_ja4s(
                crate::application::Ja4Transport::Tcp,
                sh.legacy_version,
                sh.supported_version,
                sh.cipher_suite,
                &sh.extensions,
                sh.alpn.as_deref(),
            ));
        }
    }

    /// HTTP/2 元数据一次性富化（对齐 enrich_tls_cert 先例，ADR-0004）
    ///
    /// 定型 HTTP/2 流的载荷中定位首个客户端 HEADERS 帧并 HPACK 解码，
    /// 提取 `:authority`/`:method`/`:path` 写回 flow.metadata。协议不重检；
    /// 字段已填充（或非 Http2 流）直接返回，不产生额外开销。
    #[cfg(feature = "proto3")]
    fn enrich_http2_headers(flow: &mut Flow, payload: &[u8]) {
        let needs_enrich = matches!(
            flow.metadata,
            Some(Metadata::Http2(ref h2))
                if h2.authority.is_none() && h2.method.is_none() && h2.path.is_none()
        );
        if !needs_enrich || flow.protocol != Some(Protocol::Http2) {
            return;
        }
        if let Some(md) = protocols::http2::extract_request_headers(payload)
            && let Some(Metadata::Http2(ref mut h2)) = flow.metadata
        {
            *h2 = md;
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
