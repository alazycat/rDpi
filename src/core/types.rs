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