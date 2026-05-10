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
}

/// DNS 元数据
#[derive(Debug, Clone)]
pub struct DnsMetadata {
    /// 查询域名
    pub query_domain: Option<String>,
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
    /// 置信度 (0.0-1.0)
    pub confidence: f32,
    /// 协议元数据
    pub metadata: Metadata,
}

impl DetectionResult {
    /// 创建新的检测结果
    pub fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            confidence: 1.0,
            metadata: Metadata::None,
        }
    }

    /// 添加元数据
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// 设置置信度
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
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
            | Application::AmazonPrime => ApplicationCategory::Streaming,

            Application::WeChat
            | Application::Telegram
            | Application::WhatsApp
            | Application::Discord
            | Application::QQ
            | Application::Slack
            | Application::Line
            | Application::Signal => ApplicationCategory::Im,
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
        }
    }
}
