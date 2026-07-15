//! Core types for rDpi
//!
//! This module contains shared types used throughout the library.

use std::net::IpAddr;

/// 传输层协议类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProto {
    /// TCP 协议
    Tcp,
    /// UDP 协议
    Udp,
    /// ICMP 协议
    Icmp,
    /// 其他协议，包含协议号
    Other(u8),
}

/// 支持的协议枚举
///
/// # Feature Gates
///
/// - `dns`: DNS
/// - `http`: HTTP
/// - `tls`: TLS
/// - `ssh`: SSH
/// - `smtp`: SMTP
/// - `quic`: QUIC, HTTP/3
/// - `mail`: POP3, POP3S, IMAP, IMAPS
/// - `infra`: NTP, DHCP
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    // 传输层
    Tcp,
    Udp,
    Icmp,
    // 核心应用层（内置）
    Dns,
    Http,
    Tls,
    Ssh,
    Smtp,
    // 文件传输
    #[cfg(feature = "proto3")]
    Ftp,
    // 扩展协议
    Quic,
    Http3,
    // 邮件协议 (feature: mail)
    Pop3,
    Pop3s,
    Imap,
    Imaps,
    // 基础设施协议 (feature: infra)
    Ntp,
    Dhcp,
    // 网络管理协议 (feature: snmp)
    Snmp,
    // 工业协议 (feature: modbus)
    Modbus,
    // 数据库协议 (feature: database)
    Mysql,
    Postgresql,
    Redis,
    Mongodb,
    #[cfg(feature = "proto3")]
    Sip,
    #[cfg(feature = "proto3")]
    Rtp,
    #[cfg(feature = "proto3")]
    Rtcp,
    #[cfg(feature = "proto3")]
    Http2,
    /// IoT 协议 (feature: iot)
    #[cfg(feature = "iot")]
    Mqtt,
    /// VPN/隧道协议 (feature: vpn)
    #[cfg(feature = "vpn")]
    WireGuard,
    /// 其他协议，包含协议号
    Other(u16),
}

/// 五元组，标识一条流
///
/// 五元组包含：
/// - 源 IP 地址
/// - 目的 IP 地址
/// - 源端口
/// - 目的端口
/// - 传输层协议
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// 源 IP 地址
    pub src_ip: IpAddr,
    /// 目的 IP 地址
    pub dst_ip: IpAddr,
    /// 源端口
    pub src_port: u16,
    /// 目的端口
    pub dst_port: u16,
    /// 传输层协议
    pub transport: TransportProto,
}

/// 协议特定元数据
///
/// 包含各协议提取的元数据信息。
#[derive(Debug, Clone, Default)]
pub enum Metadata {
    /// 无元数据
    #[default]
    None,
    /// DNS 元数据
    Dns(DnsMetadata),
    /// TLS 元数据
    Tls(TlsMetadata),
    /// HTTP 元数据
    Http(HttpMetadata),
    /// SSH 元数据
    Ssh(SshMetadata),
    /// SMTP 元数据
    Smtp(SmtpMetadata),
    /// QUIC 元数据
    Quic(QuicMetadata),
    /// NTP 元数据
    Ntp(NtpMetadata),
    /// DHCP 元数据
    Dhcp(DhcpMetadata),
    /// SNMP 元数据
    Snmp(SnmpMetadata),
    /// Modbus 元数据
    Modbus(ModbusMetadata),
    /// MySQL 元数据
    Mysql(MysqlMetadata),
    /// PostgreSQL 元数据
    Postgresql(PostgresqlMetadata),
    /// Redis 元数据
    Redis(RedisMetadata),
    #[cfg(feature = "proto3")]
    Ftp(FtpMetadata),
    #[cfg(feature = "proto3")]
    Sip(SipMetadata),
    #[cfg(feature = "proto3")]
    Rtp(RtpMetadata),
    /// MongoDB 元数据 (feature: database)
    Mongodb(MongodbMetadata),
    /// MQTT 元数据 (feature: iot)
    #[cfg(feature = "iot")]
    Mqtt(MqttMetadata),
    /// WireGuard 元数据 (feature: vpn)
    #[cfg(feature = "vpn")]
    WireGuard(WireGuardMetadata),
}

/// DNS 元数据
#[derive(Debug, Clone)]
pub struct DnsMetadata {
    /// 查询域名
    pub query_domain: Option<String>,
    /// 基于查询域名识别的应用
    pub application: Option<Application>,
}

/// TLS 元数据
#[derive(Debug, Clone)]
pub struct TlsMetadata {
    /// Server Name Indication (SNI)
    pub sni: Option<String>,
    /// TLS 版本 (如 "1.2", "1.3")
    pub version: Option<String>,
    /// 识别的应用（基于 SNI）
    pub application: Option<Application>,
    /// JA4 TLS 指纹哈希
    pub ja4: Option<String>,
}

/// HTTP 元数据
#[derive(Debug, Clone)]
pub struct HttpMetadata {
    /// Host 头
    pub host: Option<String>,
    /// HTTP 方法 (GET, POST, etc.)
    pub method: Option<String>,
    /// 请求路径
    pub path: Option<String>,
    /// 基于 Host 头识别的应用
    pub application: Option<Application>,
}

/// SSH 元数据
#[derive(Debug, Clone)]
pub struct SshMetadata {
    /// 协议版本 (如 "2.0")
    pub version: Option<String>,
    /// 软件版本 (如 "OpenSSH_8.9p1")
    pub software: Option<String>,
}

/// SMTP 元数据
#[derive(Debug, Clone)]
pub struct SmtpMetadata {
    /// 主机名（来自 banner 或 EHLO）
    pub hostname: Option<String>,
    /// 是否为客户端命令
    pub is_client: bool,
}

/// QUIC 元数据
///
/// 注意：SNI 提取需要 Initial Key 派生，目前未实现。
#[derive(Debug, Clone)]
pub struct QuicMetadata {
    /// Server Name Indication (SNI) - 需要 Initial Key 派生
    pub sni: Option<String>,
    /// QUIC 版本 (如 "00000001" for v1)
    pub version: Option<String>,
    /// 目的连接 ID
    pub destination_connection_id: Option<Vec<u8>>,
    /// 识别的应用
    pub application: Option<Application>,
}

/// NTP 元数据
#[derive(Debug, Clone)]
pub struct NtpMetadata {
    /// NTP 版本 (1-4)
    pub version: u8,
    /// 模式 (3=client, 4=server)
    pub mode: u8,
    /// 时钟层级 (0-15)
    pub stratum: u8,
}

/// DHCP 元数据
#[derive(Debug, Clone)]
pub struct DhcpMetadata {
    /// 操作码 (1=request, 2=reply)
    pub opcode: u8,
    /// 客户端 MAC 地址
    pub client_mac: [u8; 6],
}

/// SNMP 元数据
#[derive(Debug, Clone)]
pub struct SnmpMetadata {
    /// SNMP 版本 (v1=0, v2c=1)
    pub version: SnmpVersion,
    /// Community String
    pub community: String,
    /// PDU 类型
    pub pdu_type: SnmpPduType,
    /// 请求 ID
    pub request_id: i32,
    /// 错误状态
    pub error_status: u8,
    /// 错误索引
    pub error_index: u8,
    /// VarBind 列表
    pub varbinds: Vec<SnmpVarBind>,
    /// v1 Trap 特殊信息（仅 Trap PDU）
    pub trap_info: Option<SnmpTrapInfo>,
}

/// SNMP 版本
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpVersion {
    /// SNMPv1
    V1,
    /// SNMPv2c
    V2c,
}

/// SNMP PDU 类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpPduType {
    /// GetRequest
    GetRequest,
    /// GetNextRequest
    GetNextRequest,
    /// GetResponse
    GetResponse,
    /// SetRequest
    SetRequest,
    /// Trap (v1)
    Trap,
    /// GetBulk (v2c)
    GetBulk,
    /// Inform (v2c)
    Inform,
    /// TrapV2 (v2c)
    TrapV2,
    /// Report
    Report,
}

/// SNMP VarBind
#[derive(Debug, Clone)]
pub struct SnmpVarBind {
    /// OID
    pub oid: String,
    /// 值（简化为字符串表示）
    pub value: String,
}

/// SNMP v1 Trap 特殊信息
#[derive(Debug, Clone)]
pub struct SnmpTrapInfo {
    /// Enterprise OID
    pub enterprise: String,
    /// Agent 地址
    pub agent_addr: [u8; 4],
    /// Generic trap 类型
    pub generic_trap: u8,
    /// Specific trap 代码
    pub specific_trap: u8,
    /// 时间戳
    pub timestamp: u32,
}

/// Modbus TCP 元数据
#[derive(Debug, Clone)]
pub struct ModbusMetadata {
    /// Transaction ID
    pub transaction_id: u16,
    /// Unit ID (Slave ID)
    pub unit_id: u8,
    /// 功能码
    pub function_code: u8,
    /// 是否为响应
    pub is_response: bool,
    /// 是否为异常响应
    pub is_exception: bool,
    /// 异常码
    pub exception_code: Option<u8>,
    /// 数据部分
    pub data: ModbusData,
}

/// Modbus 数据
#[derive(Debug, Clone)]
pub enum ModbusData {
    /// 读请求
    ReadRequest {
        /// 地址
        address: u16,
        /// 数量
        quantity: u16,
    },
    /// 读响应
    ReadResponse {
        /// 字节数
        byte_count: u8,
        /// 数据
        data: Vec<u8>,
    },
    /// 写单个请求
    WriteSingleRequest {
        /// 地址
        address: u16,
        /// 值
        value: Vec<u8>,
    },
    /// 写多个请求
    WriteMultipleRequest {
        /// 地址
        address: u16,
        /// 数量
        quantity: u16,
        /// 值
        values: Vec<u8>,
    },
    /// 写多个响应
    WriteMultipleResponse {
        /// 地址
        address: u16,
        /// 数量
        quantity: u16,
    },
    /// 读写多个请求
    ReadWriteRequest {
        /// 读地址
        read_addr: u16,
        /// 读数量
        read_qty: u16,
        /// 写地址
        write_addr: u16,
        /// 写值
        write_values: Vec<u8>,
    },
    /// 读写多个响应
    ReadWriteResponse {
        /// 字节数
        byte_count: u8,
        /// 数据
        data: Vec<u8>,
    },
    /// 异常响应
    Exception {
        /// 异常码
        exception_code: u8,
    },
}

/// 协议检测结果
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// 检测到的协议
    pub protocol: Protocol,
    /// 置信度级别
    pub confidence: Confidence,
    /// 协议元数据
    pub metadata: Metadata,
    /// 协议分类
    pub category: ProtocolCategory,
    /// 协议风险评级
    pub breed: ProtocolBreed,
    /// 应用层协议（如 YouTube, WeChat 等）
    pub app_protocol: Option<Application>,
}

impl DetectionResult {
    /// 创建新的检测结果，默认置信度为 Dpi
    pub fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            confidence: Confidence::Dpi,
            metadata: Metadata::None,
            category: protocol.category(),
            breed: protocol.breed(),
            app_protocol: None,
        }
    }

    /// 添加元数据并提取应用层协议
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.app_protocol = Self::extract_app(&metadata);
        self.metadata = metadata;
        self
    }

    /// 设置置信度
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// 从元数据中提取应用层协议
    fn extract_app(metadata: &Metadata) -> Option<Application> {
        match metadata {
            Metadata::Tls(tls) => tls.application,
            Metadata::Quic(quic) => quic.application,
            Metadata::Dns(dns) => dns.application,
            Metadata::Http(http) => http.application,
            #[cfg(feature = "proto3")]
            Metadata::Ftp(_) | Metadata::Sip(_) | Metadata::Rtp(_) => None,
            _ => None,
        }
    }
}

/// 协议分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolCategory {
    /// 网络层协议（如 TCP, UDP, ICMP）
    Network,
    /// Web 协议（如 HTTP）
    Web,
    /// 加密隧道协议（如 TLS, QUIC）
    EncryptedTunnel,
    /// 邮件协议（如 SMTP, POP3, IMAP）
    Mail,
    /// DNS 协议
    Dns,
    /// 数据库协议（如 MySQL, PostgreSQL, Redis）
    Database,
    /// 远程访问协议（如 SSH）
    RemoteAccess,
    /// 文件传输协议（如 FTP）
    FileTransfer,
    /// VoIP 信令与媒体（SIP, RTP, RTCP）
    Voip,
    /// 基础设施协议（如 NTP, DHCP）
    Infrastructure,
    /// 网络管理协议（如 SNMP）
    NetworkManagement,
    /// 工业协议（如 Modbus）
    Industrial,
    /// IoT 协议 (feature: iot)
    #[cfg(feature = "iot")]
    Iot,
    /// VPN/隧道协议 (feature: vpn)
    #[cfg(feature = "vpn")]
    Vpn,
    /// 其他协议
    Other,
}

impl Protocol {
    /// 获取协议所属分类
    pub fn category(self) -> ProtocolCategory {
        match self {
            Protocol::Tcp | Protocol::Udp | Protocol::Icmp => ProtocolCategory::Network,
            Protocol::Http => ProtocolCategory::Web,
            Protocol::Tls | Protocol::Quic | Protocol::Http3 => ProtocolCategory::EncryptedTunnel,
            Protocol::Smtp | Protocol::Pop3 | Protocol::Pop3s
                | Protocol::Imap | Protocol::Imaps => ProtocolCategory::Mail,
            Protocol::Dns => ProtocolCategory::Dns,
            Protocol::Mysql | Protocol::Postgresql | Protocol::Redis
                | Protocol::Mongodb => ProtocolCategory::Database,
            Protocol::Ssh => ProtocolCategory::RemoteAccess,
            #[cfg(feature = "proto3")]
            Protocol::Ftp => ProtocolCategory::FileTransfer,
            #[cfg(feature = "proto3")]
            Protocol::Http2 => ProtocolCategory::Web,
            #[cfg(feature = "proto3")]
            Protocol::Sip => ProtocolCategory::Voip,
            #[cfg(feature = "proto3")]
            Protocol::Rtp | Protocol::Rtcp => ProtocolCategory::Voip,
            Protocol::Ntp | Protocol::Dhcp => ProtocolCategory::Infrastructure,
            Protocol::Snmp => ProtocolCategory::NetworkManagement,
            Protocol::Modbus => ProtocolCategory::Industrial,
            #[cfg(feature = "iot")]
            Protocol::Mqtt => ProtocolCategory::Iot,
            #[cfg(feature = "vpn")]
            Protocol::WireGuard => ProtocolCategory::Vpn,
            Protocol::Other(_) => ProtocolCategory::Other,
        }
    }

    /// 获取协议的风险评级
    pub fn breed(self) -> ProtocolBreed {
        match self {
            Protocol::Dns | Protocol::Http | Protocol::Smtp
                | Protocol::Pop3 | Protocol::Pop3s | Protocol::Imap
                | Protocol::Imaps | Protocol::Ntp | Protocol::Dhcp
                | Protocol::Tls | Protocol::Quic | Protocol::Http3
                | Protocol::Ssh => ProtocolBreed::Safe,
            Protocol::Mysql | Protocol::Postgresql | Protocol::Redis
                | Protocol::Mongodb
                | Protocol::Snmp | Protocol::Modbus => ProtocolBreed::Acceptable,
            #[cfg(feature = "proto3")]
            Protocol::Ftp => ProtocolBreed::Fun,
            #[cfg(feature = "iot")]
            Protocol::Mqtt => ProtocolBreed::Safe,
            #[cfg(feature = "vpn")]
            Protocol::WireGuard => ProtocolBreed::Safe,
            #[cfg(feature = "proto3")]
            Protocol::Sip | Protocol::Rtp | Protocol::Rtcp
                | Protocol::Http2 => ProtocolBreed::Safe,
            Protocol::Tcp | Protocol::Udp | Protocol::Icmp
                | Protocol::Other(_) => ProtocolBreed::Unrated,
        }
    }

    /// 获取主协议（当前返回自身，为扩展预留）
    pub fn master(self) -> Protocol {
        #[cfg(feature = "proto3")]
        match self {
            Protocol::Ftp | Protocol::Sip | Protocol::Rtp | Protocol::Rtcp => self,
            _ => self,
        }
        #[cfg(not(feature = "proto3"))]
        self
    }
}

/// 协议风险评级
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolBreed {
    /// 未评级
    Unrated,
    /// 安全
    Safe,
    /// 可接受
    Acceptable,
    /// 有趣（存在已知问题但常用）
    Fun,
    /// 不安全
    Unsafe,
    /// 潜在危险
    PotentiallyDangerous,
    /// 危险
    Dangerous,
    /// 跟踪/广告
    TrackerAds,
}

/// 协议检测置信度级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// 未识别
    Unknown = 0,
    /// 基于端口匹配（DPI 失败后兜底）
    MatchByPort = 1,
    /// 基于 IP 子网匹配
    MatchByIp = 2,
    /// DPI 缓存匹配（同一流的后续包复用）
    DpiCache = 3,
    /// 部分 DPI 匹配（仅有部分特征）
    DpiPartial = 4,
    /// 完整 DPI 负载匹配
    Dpi = 5,
    /// 用户自定义规则匹配
    CustomRule = 6,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Unknown => write!(f, "Unknown"),
            Confidence::MatchByPort => write!(f, "MatchByPort"),
            Confidence::MatchByIp => write!(f, "MatchByIp"),
            Confidence::DpiCache => write!(f, "DpiCache"),
            Confidence::DpiPartial => write!(f, "DpiPartial"),
            Confidence::Dpi => write!(f, "Dpi"),
            Confidence::CustomRule => write!(f, "CustomRule"),
        }
    }
}

/// 检测上下文，包含端口信息
#[derive(Debug, Clone, Copy)]
pub struct DetectContext {
    /// 源端口
    pub src_port: u16,
    /// 目的端口
    pub dst_port: u16,
    /// 是否为 HTTP/3 端口 (443)
    pub is_http3_port: bool,
}

/// 应用分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplicationCategory {
    /// 流媒体
    Streaming,
    /// 即时通讯
    Im,
    /// 其他
    Other,
}

/// 应用层协议识别
///
/// 基于 TLS SNI 识别的应用平台。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Application {
    // 流媒体
    YouTube,
    Netflix,
    Bilibili,
    Douyin,
    Iqiyi,
    TencentVideo,
    Youku,
    Hulu,
    DisneyPlus,
    AmazonPrime,
    // IM
    WeChat,
    Telegram,
    WhatsApp,
    Discord,
    QQ,
    Slack,
    Line,
    Signal,
    // 云服务（用于 IP 子网/域名匹配）
    Google,
    // 通讯协作
    Zoom,
    Twitch,
    // 新增强
    // 流媒体
    HBO,
    DAZN,
    Vimeo,
    Dailymotion,
    Spotify,
    AppleTVPlus,
    ParamountPlus,
    // 社交
    Instagram,
    Snapchat,
    Facebook,
    Messenger,
    Twitter,
    LinkedIn,
    Pinterest,
    Reddit,
    // 云服务
    Microsoft,
    AmazonAWS,
    Azure,
    GitHub,
    GitLab,
    Dropbox,
    Box,
    // 通讯
    Teams,
    Webex,
    Skype,
}

impl Application {
    /// 获取应用分类
    pub fn category(&self) -> ApplicationCategory {
        match self {
            Application::YouTube
            | Application::Netflix
            | Application::Bilibili
            | Application::Douyin
            | Application::Iqiyi
            | Application::TencentVideo
            | Application::Youku
            | Application::Hulu
            | Application::DisneyPlus
            | Application::AmazonPrime
            | Application::HBO
            | Application::DAZN
            | Application::Vimeo
            | Application::Dailymotion
            | Application::Spotify
            | Application::AppleTVPlus
            | Application::ParamountPlus => ApplicationCategory::Streaming,

            Application::WeChat
            | Application::Telegram
            | Application::WhatsApp
            | Application::Discord
            | Application::QQ
            | Application::Slack
            | Application::Line
            | Application::Signal
            | Application::Google
            | Application::Zoom
            | Application::Twitch
            | Application::Instagram
            | Application::Snapchat
            | Application::Facebook
            | Application::Messenger
            | Application::Twitter
            | Application::LinkedIn
            | Application::Pinterest
            | Application::Reddit
            | Application::Teams
            | Application::Webex
            | Application::Skype => ApplicationCategory::Im,

            // 云服务
            Application::Microsoft
            | Application::AmazonAWS
            | Application::Azure
            | Application::GitHub
            | Application::GitLab
            | Application::Dropbox
            | Application::Box => ApplicationCategory::Other,
        }
    }

    /// 获取应用名称
    pub fn name(&self) -> &'static str {
        match self {
            Application::YouTube => "YouTube",
            Application::Netflix => "Netflix",
            Application::Bilibili => "Bilibili",
            Application::Douyin => "Douyin",
            Application::Iqiyi => "Iqiyi",
            Application::TencentVideo => "TencentVideo",
            Application::Youku => "Youku",
            Application::Hulu => "Hulu",
            Application::DisneyPlus => "DisneyPlus",
            Application::AmazonPrime => "AmazonPrime",
            Application::WeChat => "WeChat",
            Application::Telegram => "Telegram",
            Application::WhatsApp => "WhatsApp",
            Application::Discord => "Discord",
            Application::QQ => "QQ",
            Application::Slack => "Slack",
            Application::Line => "Line",
            Application::Signal => "Signal",
            Application::Google => "Google",
            Application::Zoom => "Zoom",
            Application::Twitch => "Twitch",
            Application::HBO => "HBO",
            Application::DAZN => "DAZN",
            Application::Vimeo => "Vimeo",
            Application::Dailymotion => "Dailymotion",
            Application::Spotify => "Spotify",
            Application::AppleTVPlus => "AppleTVPlus",
            Application::ParamountPlus => "ParamountPlus",
            Application::Instagram => "Instagram",
            Application::Snapchat => "Snapchat",
            Application::Facebook => "Facebook",
            Application::Messenger => "Messenger",
            Application::Twitter => "Twitter",
            Application::LinkedIn => "LinkedIn",
            Application::Pinterest => "Pinterest",
            Application::Reddit => "Reddit",
            Application::Microsoft => "Microsoft",
            Application::AmazonAWS => "AmazonAWS",
            Application::Azure => "Azure",
            Application::GitHub => "GitHub",
            Application::GitLab => "GitLab",
            Application::Dropbox => "Dropbox",
            Application::Box => "Box",
            Application::Teams => "Teams",
            Application::Webex => "Webex",
            Application::Skype => "Skype",
        }
    }

    /// 获取应用对应的主协议
    pub fn master_protocol(self) -> Protocol {
        match self {
            Application::YouTube | Application::Netflix | Application::Bilibili
                | Application::Douyin | Application::Iqiyi
                | Application::TencentVideo | Application::Youku
                | Application::Hulu | Application::DisneyPlus
                | Application::AmazonPrime
                | Application::HBO
                | Application::DAZN
                | Application::Vimeo
                | Application::Dailymotion
                | Application::Spotify
                | Application::AppleTVPlus
                | Application::ParamountPlus => Protocol::Http,

            Application::WeChat | Application::Telegram | Application::WhatsApp
                | Application::Discord | Application::QQ | Application::Slack
                | Application::Line | Application::Signal
                | Application::Zoom | Application::Twitch
                | Application::Google
                | Application::Instagram
                | Application::Snapchat
                | Application::Facebook
                | Application::Messenger
                | Application::Twitter
                | Application::LinkedIn
                | Application::Pinterest
                | Application::Reddit
                | Application::Microsoft
                | Application::AmazonAWS
                | Application::Azure
                | Application::GitHub
                | Application::GitLab
                | Application::Dropbox
                | Application::Box
                | Application::Teams
                | Application::Webex
                | Application::Skype => Protocol::Tls,
        }
    }
}

/// MySQL 元数据
#[derive(Debug, Clone)]
pub struct MysqlMetadata {
    /// 服务器版本 (如 "8.0.33")
    pub version: Option<String>,
    /// 认证插件名 (如 "mysql_native_password")
    pub auth_plugin: Option<String>,
}

/// PostgreSQL 元数据
#[derive(Debug, Clone)]
pub struct PostgresqlMetadata {
    /// 用户名
    pub user: Option<String>,
    /// 数据库名
    pub database: Option<String>,
    /// 应用名
    pub application_name: Option<String>,
}

/// Redis 元数据
#[derive(Debug, Clone)]
pub struct RedisMetadata {
    /// 命令类型 (如 GET, SET, SELECT)
    pub command: Option<String>,
}

/// MQTT 元数据 (feature: iot)
#[cfg(feature = "iot")]
#[derive(Debug, Clone)]
pub struct MqttMetadata {
    /// 协议名称: "MQTT" (v3.1.1/v5) 或 "MQIsdp" (v3.1)
    pub protocol_name: String,
    /// 协议级别: 3=MQTT 3.1, 4=MQTT 3.1.1, 5=MQTT 5.0
    pub protocol_level: u8,
    /// Connect 标志位
    pub connect_flags: u8,
    /// Keep Alive 间隔（秒）
    pub keep_alive: u16,
    /// 客户端标识符
    pub client_id: Option<String>,
    /// Will 主题 (如果设置了 Will Flag)
    pub will_topic: Option<String>,
}

/// MongoDB 握手响应元数据 (feature: database)
#[derive(Debug, Clone)]
pub struct MongodbMetadata {
    /// 服务器版本号 (来自 isMaster 响应)
    pub server_version: Option<String>,
    /// 最大 Wire 协议版本
    pub max_wire_version: Option<i32>,
    /// 最大消息大小 (字节)
    pub max_msg_size: Option<i32>,
}

/// WireGuard 元数据 (feature: vpn)
#[cfg(feature = "vpn")]
#[derive(Debug, Clone)]
pub struct WireGuardMetadata {
    /// 消息类型: 1=Initiation, 2=Response, 3=CookieReply, 4=Transport
    pub message_type: u8,
    /// 发送者索引
    pub sender_index: u32,
}

#[cfg(feature = "proto3")]
#[derive(Debug, Clone)]
pub struct FtpMetadata {
    pub is_client: bool,
    pub verb: Option<String>,
    pub argument: Option<String>,
    pub response_code: Option<u16>,
}

#[cfg(feature = "proto3")]
#[derive(Debug, Clone)]
pub struct SipMetadata {
    pub is_request: bool,
    pub method: Option<String>,
    pub status_code: Option<u16>,
    pub user_agent: Option<String>,
}

#[cfg(feature = "proto3")]
#[derive(Debug, Clone)]
pub struct RtpMetadata {
    pub ssrc: u32,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc_confirmed: bool,
    pub is_rtcp: bool,
}
