use std::net::IpAddr;

/// 传输层协议类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProto {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

/// 支持的协议枚举
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
    Other(u16),
}

/// 五元组，标识一条流
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub transport: TransportProto,
}

/// 协议特定元数据
#[derive(Debug, Clone, Default)]
pub enum Metadata {
    #[default]
    None,
    Dns(DnsMetadata),
    Tls(TlsMetadata),
    Http(HttpMetadata),
    Ssh(SshMetadata),
    Smtp(SmtpMetadata),
    Quic(QuicMetadata),
}

#[derive(Debug, Clone)]
pub struct DnsMetadata {
    pub query_domain: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TlsMetadata {
    pub sni: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpMetadata {
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SshMetadata {
    pub version: Option<String>,  // "2.0" or "1.99"
    pub software: Option<String>, // "OpenSSH_8.9p1", "dropbear_2022.83"
}

#[derive(Debug, Clone)]
pub struct SmtpMetadata {
    pub hostname: Option<String>, // from banner or EHLO
    pub is_client: bool,          // true = client command, false = server response
}

/// QUIC metadata - SNI extraction requires Initial key derivation (not implemented)
#[derive(Debug, Clone)]
pub struct QuicMetadata {
    pub sni: Option<String>,
    pub version: Option<String>,
    pub destination_connection_id: Option<Vec<u8>>,
}

/// 识别结果
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub protocol: Protocol,
    pub confidence: f32,
    pub metadata: Metadata,
}

impl DetectionResult {
    pub fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            confidence: 1.0,
            metadata: Metadata::None,
        }
    }

    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

/// 检测上下文，包含端口信息
#[derive(Debug, Clone, Copy)]
pub struct DetectContext {
    pub src_port: u16,
    pub dst_port: u16,
    pub is_http3_port: bool,
}

/// 应用分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplicationCategory {
    Streaming,
    Im,
    Other,
}

/// 应用层协议识别
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
