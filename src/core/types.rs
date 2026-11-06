//! Core types for rDpi
//!
//! This module contains shared types used throughout the library.

use std::net::IpAddr;

/// 传输层协议类型
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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

/// 流方向（相对规范化后的双向流键）
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// 与规范化键同向（src -> dst）
    Forward,
    /// 反向（dst -> src）
    Reverse,
}

impl Direction {
    /// 反转方向
    pub fn opposite(self) -> Self {
        match self {
            Self::Forward => Self::Reverse,
            Self::Reverse => Self::Forward,
        }
    }
}

/// 流分类状态（类比 nDPI classification state）
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ClassificationState {
    /// 正在识别
    #[default]
    Inspecting,
    /// 已有部分结果，后续包可能升级
    Partial,
    /// 已定型但继续监测元数据
    Monitoring,
    /// 已完全定型
    Classified,
}

/// 有状态 dissector 的单包处理结果
#[derive(Debug, Clone)]
pub enum DissectorOutcome {
    /// 已接管流，但需要更多包
    Continue,
    /// 部分分类，后续可能升级
    Partial(DetectionResult),
    /// 完全分类
    Classified(DetectionResult),
    /// 放弃（例如缓冲区超限）
    GiveUp,
}

/// HTTP 有状态 dissector 的 per-flow 状态
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpDissectorState {
    /// 跨包累积的请求/响应头缓冲（上限由 dissector 控制）
    pub buffer: Vec<u8>,
}

/// DNS over TCP 有状态 dissector 的 per-flow 状态
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsTcpDissectorState {
    /// 跨包累积的 TCP 字节流（2 字节长度前缀 + DNS 消息）
    pub buffer: Vec<u8>,
}

/// per-flow 有状态 dissector 状态
///
/// 当前只支持一个活跃的有状态协议（HTTP）；后续按协议扩展枚举。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DissectorState {
    /// 无活跃有状态协议
    #[default]
    None,
    /// HTTP 头重组
    Http(HttpDissectorState),
    /// DNS over TCP 长度前缀重组
    DnsTcp(DnsTcpDissectorState),
}

/// 协议栈最大层数（与 nDPI `NDPI_PROTOCOL_STACK_SIZE` 对齐）
pub const MAX_PROTOCOL_STACK: usize = 8;

/// 协议栈（类比 nDPI protocol stack）
///
/// 固定容量、零堆分配；`push` 追加并去重，栈满返回 `false`。
/// `master()` 返回首个（外层/基础）协议，`app()` 返回最后一个（最具体）协议。
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProtocolStack {
    protocols: [Option<Protocol>; MAX_PROTOCOL_STACK],
    len: usize,
}

impl ProtocolStack {
    /// 创建空协议栈
    pub fn new() -> Self {
        Self::default()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 层数
    pub fn len(&self) -> usize {
        self.len
    }

    /// 主协议（首个/外层协议）
    pub fn master(&self) -> Option<Protocol> {
        self.protocols[0]
    }

    /// 应用协议（最后一个/最具体协议）
    pub fn app(&self) -> Option<Protocol> {
        if self.len == 0 {
            None
        } else {
            self.protocols[self.len - 1]
        }
    }

    /// 是否已包含某协议
    pub fn contains(&self, protocol: Protocol) -> bool {
        self.iter().any(|p| p == protocol)
    }

    /// 追加协议；重复或栈满返回 `false`
    pub fn push(&mut self, protocol: Protocol) -> bool {
        if self.contains(protocol) || self.len == MAX_PROTOCOL_STACK {
            return false;
        }
        self.protocols[self.len] = Some(protocol);
        self.len += 1;
        true
    }

    /// 清空
    pub fn clear(&mut self) {
        self.protocols = [None; MAX_PROTOCOL_STACK];
        self.len = 0;
    }

    /// 按入栈顺序迭代
    pub fn iter(&self) -> impl Iterator<Item = Protocol> + '_ {
        self.protocols[..self.len].iter().filter_map(|p| *p)
    }
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
    /// DTLS（RFC 6347/9147，feature: dtls，F38）
    Dtls,
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
    #[cfg(feature = "proto3")]
    WebSocket,
    /// IoT 协议 (feature: iot)
    #[cfg(feature = "iot")]
    Mqtt,
    /// VPN/隧道协议 (feature: vpn)
    #[cfg(feature = "vpn")]
    WireGuard,
    #[cfg(feature = "vpn")]
    OpenVpn,
    #[cfg(feature = "voip")]
    Stun,
    #[cfg(feature = "auth")]
    Kerberos,
    #[cfg(feature = "auth")]
    Ldap,
    #[cfg(feature = "remote")]
    Rdp,
    #[cfg(feature = "infra")]
    Bgp,
    // Phase 11A — 简单协议
    // R7：misc feature —— TFTP/Rsync/Whois/Syslog 纳入 feature 矩阵
    #[cfg(feature = "misc")]
    Tftp,
    #[cfg(feature = "misc")]
    Rsync,
    #[cfg(feature = "misc")]
    Whois,
    #[cfg(feature = "misc")]
    Syslog,
    #[cfg(feature = "proto3")]
    Rtmp,
    #[cfg(feature = "proto3")]
    Socks,
    #[cfg(feature = "infra")]
    Netflow,
    #[cfg(feature = "infra")]
    Ike,
    #[cfg(feature = "infra")]
    Ptpv2,
    #[cfg(feature = "infra")]
    Nfs,
    // Phase 12A — 企业协议
    // R7：misc feature —— Telnet/Vnc 纳入 feature 矩阵
    #[cfg(feature = "misc")]
    Telnet,
    #[cfg(feature = "misc")]
    Vnc,
    #[cfg(feature = "infra")]
    Dhcpv6,
    #[cfg(feature = "infra")]
    Vxlan,
    #[cfg(feature = "vpn")]
    L2tp,
    #[cfg(feature = "vpn")]
    Pptp,
    #[cfg(feature = "auth")]
    Radius,
    #[cfg(feature = "voip")]
    Turn,
    #[cfg(feature = "voip")]
    Mgcp,
    #[cfg(feature = "voip")]
    H323,
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

impl FlowKey {
    /// 反转五元组方向
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            transport: self.transport,
        }
    }

    /// 规范化双向流键
    ///
    /// 按 `(ip, port)` 字典序确定端点顺序，返回规范键及原始键相对规范键的方向。
    /// 两个方向相反的 FlowKey 会得到相同的规范键，方向分别为 Forward/Reverse。
    pub fn canonical(&self) -> (Self, Direction) {
        let src = (self.src_ip, self.src_port);
        let dst = (self.dst_ip, self.dst_port);
        if src <= dst {
            (self.clone(), Direction::Forward)
        } else {
            (self.reverse(), Direction::Reverse)
        }
    }
}

/// 协议特定元数据
///
/// 包含各协议提取的元数据信息。
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
    /// HTTP/2 元数据 (feature: proto3)
    #[cfg(feature = "proto3")]
    Http2(Http2Metadata),
    /// SSH 元数据
    Ssh(SshMetadata),
    /// SMTP 元数据
    Smtp(SmtpMetadata),
    /// QUIC 元数据
    Quic(QuicMetadata),
    /// DTLS 元数据
    Dtls(DtlsMetadata),
    /// NTP 元数据
    Ntp(NtpMetadata),
    /// DHCP 元数据
    Dhcp(DhcpMetadata),
    /// DHCPv6 元数据 (feature: infra)
    #[cfg(feature = "infra")]
    Dhcpv6(Dhcpv6Metadata),
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
    /// STUN 元数据 (feature: voip)
    #[cfg(feature = "voip")]
    Stun(StunMetadata),
    /// Kerberos 元数据 (feature: auth)
    #[cfg(feature = "auth")]
    Kerberos(KerberosMetadata),
}

/// DNS 元数据
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct DnsMetadata {
    /// 查询域名
    pub query_domain: Option<String>,
    /// 基于查询域名识别的应用
    pub application: Option<Application>,
}

/// TLS 元数据
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default)]
pub struct TlsMetadata {
    /// Server Name Indication (SNI)
    pub sni: Option<String>,
    /// TLS 版本 (如 "1.2", "1.3")
    pub version: Option<String>,
    /// 识别的应用（基于 SNI）
    pub application: Option<Application>,
    /// JA4 TLS 指纹哈希
    pub ja4: Option<String>,
    /// JA4S 服务端指纹（来自 ServerHello；客户端流为 None）
    pub ja4s: Option<String>,
    /// 客户端通告的密码套件列表 (IANA IDs)
    pub cipher_suites: Vec<u16>,
    /// ALPN 协商协议 (如 "h2", "http/1.1")
    pub alpn: Option<String>,
    /// 证书主题 (CN)
    pub cert_subject: Option<String>,
    /// 证书签发者
    pub cert_issuer: Option<String>,
    /// 证书有效期起始 (Unix timestamp)
    pub cert_valid_from: Option<u64>,
    /// 证书有效期截止 (Unix timestamp)
    pub cert_valid_to: Option<u64>,
    /// JA4X 证书指纹（issuer/subject/扩展 OID 哈希，仅证书解析路径产出）
    pub cert_ja4x: Option<String>,
}

/// HTTP 元数据
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
    /// JA4H 客户端 HTTP 指纹（仅 HTTP/1.x 请求；响应与 HTTP/2 为 None）
    pub ja4h: Option<String>,
}

/// HTTP/2 元数据 (feature: proto3)
///
/// 从首个客户端 HEADERS 帧提取（HPACK 解码，RFC 7541）。
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default)]
#[cfg(feature = "proto3")]
pub struct Http2Metadata {
    /// :authority 伪头部（等价 HTTP/1.x 的 Host）
    pub authority: Option<String>,
    /// 请求方法
    pub method: Option<String>,
    /// 请求路径
    pub path: Option<String>,
}

/// SSH 元数据
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct SshMetadata {
    /// 协议版本 (如 "2.0")
    pub version: Option<String>,
    /// 软件版本 (如 "OpenSSH_8.9p1")
    pub software: Option<String>,
}

/// SMTP 元数据
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct SmtpMetadata {
    /// 主机名（来自 banner 或 EHLO）
    pub hostname: Option<String>,
    /// 是否为客户端命令
    pub is_client: bool,
}

/// QUIC Transport Parameters（RFC 9000 §18.2，feature: quic）
///
/// 来自 ClientHello 的 `quic_transport_parameters` (0x0039) 扩展，
/// 仅收录数值型（varint 值）参数用于行为指纹/风险信号；未知参数跳过。
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default)]
pub struct QuicTransportParams {
    /// 最大空闲超时（毫秒，0x01）
    pub max_idle_timeout: Option<u64>,
    /// 最大 UDP 载荷大小（字节，0x03）
    pub max_udp_payload_size: Option<u64>,
    /// 初始连接级流控上限（字节，0x04）
    pub initial_max_data: Option<u64>,
    /// 初始双向流数上限（0x08）
    pub initial_max_streams_bidi: Option<u64>,
    /// 初始单向流数上限（0x09）
    pub initial_max_streams_uni: Option<u64>,
}

/// QUIC 元数据
///
/// SNI/ALPN/JA4 来自 Initial 包解密（RFC 9001 §5，CRYPTO 帧 → TLS ClientHello），
/// 解密失败或非客户端 Initial 时为 None。
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct QuicMetadata {
    /// Server Name Indication (SNI)
    pub sni: Option<String>,
    /// ALPN 协议协商（如 "h3"）
    pub alpn: Option<String>,
    /// JA4 指纹（与 TLS 路径同源，application::compute_ja4）
    pub ja4: Option<String>,
    /// JA4S 服务端指纹（前缀 q，来自服务端 Initial 解密的 ServerHello）
    pub ja4s: Option<String>,
    /// QUIC 版本 (如 "00000001" for v1)
    pub version: Option<String>,
    /// 目的连接 ID
    pub destination_connection_id: Option<Vec<u8>>,
    /// 识别的应用
    pub application: Option<Application>,
    /// Transport Parameters（仅客户端 Initial 携带；解密失败/无扩展时为 None）
    pub transport_parameters: Option<QuicTransportParams>,
}

/// DTLS 元数据
///
/// SNI/ALPN/JA4 来自 ClientHello（合成 TLS 记录复用 tls 解析器，F38），
/// JA4S 来自 ServerHello（d 前缀）。未启用 tls feature 时仅记录层版本可用。
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Default)]
pub struct DtlsMetadata {
    /// Server Name Indication (SNI)
    pub sni: Option<String>,
    /// ALPN 协议协商（如 "h2"）
    pub alpn: Option<String>,
    /// JA4 指纹（与 TLS/QUIC 路径同源占位格式）
    pub ja4: Option<String>,
    /// JA4S 服务端指纹（d 前缀，来自 ServerHello）
    pub ja4s: Option<String>,
    /// DTLS 版本（如 "DTLS 1.2"、"DTLS 1.3"）
    pub version: Option<String>,
    /// 识别的应用（基于 SNI）
    pub application: Option<Application>,
}

/// NTP 元数据
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct DhcpMetadata {
    /// 操作码 (1=request, 2=reply)
    pub opcode: u8,
    /// 客户端 MAC 地址
    pub client_mac: [u8; 6],
    /// JA4D 指纹（FoxIO ja4d 语义，每有效 DHCP 报文必有）
    pub ja4d: String,
}

/// DHCPv6 元数据 (feature: infra)
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct Dhcpv6Metadata {
    /// 报文类型 (RFC 8415 §7.3，1-13)
    pub msg_type: u8,
    /// JA4D6 指纹（Wireshark packet-ja4.c 语义，每有效 DHCPv6 报文必有）
    pub ja4d6: String,
}

/// SNMP 元数据
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpVersion {
    /// SNMPv1
    V1,
    /// SNMPv2c
    V2c,
}

/// SNMP PDU 类型
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct SnmpVarBind {
    /// OID
    pub oid: String,
    /// 值（简化为字符串表示）
    pub value: String,
}

/// SNMP v1 Trap 特殊信息
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
    /// 协议栈（P1：双向 API / 后续分类流程使用）
    pub protocol_stack: ProtocolStack,
    /// JA4T 客户端 TCP 指纹（F33：来自流的初始 SYN 包；非 TCP / 无 SYN 时为 None）
    pub ja4t: Option<String>,
    /// JA4TS 服务端 TCP 指纹（F34：来自服务端方向的 SYN-ACK 包；非 TCP / 无
    /// SYN-ACK 时为 None。F40 起为完整官方格式——存在 SYN-ACK 重传时第 4 段
    /// 后追加 `_d1-d2-...` 整秒延迟段、跟踪期内 RST 再追加 `-R{sec}`）
    pub ja4ts: Option<String>,
    /// JA4L-S 服务端时延指纹（F35：`{半程时延µs}_{SYN-ACK TTL}`；无 TCP 握手起点时为 None）
    pub ja4ls: Option<String>,
    /// JA4L-C 客户端时延指纹（F35：`{半程时延µs}_{SYN TTL}`；无 TCP 握手起点时为 None）
    pub ja4lc: Option<String>,
    /// JA4SSH 会话指纹（F36：`c{c众数}s{s众数}_c{c载荷包数}s{s载荷包数}_c{c纯ACK数}s{s纯ACK数}`；
    /// 仅 SSH 流且首个 200 载荷包窗口完成后非 None）
    pub ja4ssh: Option<String>,
    /// 风险分析结果 (feature: risk)
    #[cfg(feature = "risk")]
    pub risks: Vec<super::super::risk::types::RiskResult>,
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
            protocol_stack: ProtocolStack::new(),
            ja4t: None,
            ja4ts: None,
            ja4ls: None,
            ja4lc: None,
            ja4ssh: None,
            #[cfg(feature = "risk")]
            risks: Vec::new(),
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
            Metadata::Dtls(dtls) => dtls.application,
            Metadata::Dns(dns) => dns.application,
            Metadata::Http(http) => http.application,
            #[cfg(feature = "proto3")]
            Metadata::Ftp(_) | Metadata::Sip(_) | Metadata::Rtp(_) => None,
            _ => None,
        }
    }
}

/// 协议分类
///
/// 共 25 个分类，涵盖网络层到应用层的业务分类。
/// 新增分类保持向后兼容，未使用的预留给未来协议扩展。
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolCategory {
    /// 网络层协议（如 TCP, UDP, ICMP）
    Network,
    /// Web 协议（如 HTTP, HTTP/2, WebSocket）
    Web,
    /// 加密 Web 隧道（TLS, QUIC, HTTP/3）
    WebTunnel,
    /// VPN 隧道协议（WireGuard, OpenVPN）
    Vpn,
    /// 通用隧道协议（GRE, IPsec — 预留）
    Tunnel,
    /// 邮件协议（如 SMTP, POP3, IMAP）
    Mail,
    /// DNS 协议
    Dns,
    /// 数据库协议（如 MySQL, PostgreSQL, Redis, MongoDB）
    Database,
    /// 远程访问协议（如 SSH, RDP）
    RemoteAccess,
    /// 文件传输协议（如 FTP）
    FileTransfer,
    /// VoIP 与实时通信（SIP, RTP, RTCP, STUN）
    Voip,
    /// 基础设施协议（如 NTP, DHCP）
    Infrastructure,
    /// 网络管理协议（如 SNMP）
    NetworkManagement,
    /// 工业/工控协议（如 Modbus）
    Industrial,
    /// IoT 协议（如 MQTT）
    Iot,
    /// 认证协议（Kerberos, LDAP）
    Authentication,
    /// 流媒体视频（预留）
    Video,
    /// 流媒体音频（预留）
    Audio,
    /// 云服务（预留）
    Cloud,
    /// 即时通讯（预留）
    Messaging,
    /// 社交网络（预留）
    Social,
    /// 在线游戏（预留）
    Gaming,
    /// 协同办公（预留）
    Collaboration,
    /// 文件共享/P2P（预留）
    FileSharing,
    /// 路由协议（BGP, OSPF — 预留）
    Routing,
    /// 其他协议
    Other,
}

impl Protocol {
    /// 获取协议所属分类
    pub fn category(self) -> ProtocolCategory {
        match self {
            // Network
            Protocol::Tcp | Protocol::Udp | Protocol::Icmp => ProtocolCategory::Network,

            // Web
            Protocol::Http => ProtocolCategory::Web,
            #[cfg(feature = "proto3")]
            Protocol::Http2 | Protocol::WebSocket => ProtocolCategory::Web,

            // WebTunnel
            Protocol::Tls | Protocol::Quic | Protocol::Http3 | Protocol::Dtls => {
                ProtocolCategory::WebTunnel
            }

            // VPN
            #[cfg(feature = "vpn")]
            Protocol::WireGuard | Protocol::OpenVpn => ProtocolCategory::Vpn,

            // Mail
            Protocol::Smtp
            | Protocol::Pop3
            | Protocol::Pop3s
            | Protocol::Imap
            | Protocol::Imaps => ProtocolCategory::Mail,

            // DNS
            Protocol::Dns => ProtocolCategory::Dns,

            // Database
            Protocol::Mysql | Protocol::Postgresql | Protocol::Redis | Protocol::Mongodb => {
                ProtocolCategory::Database
            }

            // RemoteAccess
            Protocol::Ssh => ProtocolCategory::RemoteAccess,
            #[cfg(feature = "remote")]
            Protocol::Rdp => ProtocolCategory::RemoteAccess,

            // FileTransfer
            #[cfg(feature = "proto3")]
            Protocol::Ftp => ProtocolCategory::FileTransfer,

            // VoIP
            #[cfg(feature = "proto3")]
            Protocol::Sip => ProtocolCategory::Voip,
            #[cfg(feature = "proto3")]
            Protocol::Rtp | Protocol::Rtcp => ProtocolCategory::Voip,
            #[cfg(feature = "voip")]
            Protocol::Stun => ProtocolCategory::Voip,

            // Infrastructure
            Protocol::Ntp | Protocol::Dhcp => ProtocolCategory::Infrastructure,

            // NetworkManagement
            Protocol::Snmp => ProtocolCategory::NetworkManagement,

            // Industrial
            Protocol::Modbus => ProtocolCategory::Industrial,

            // IoT
            #[cfg(feature = "iot")]
            Protocol::Mqtt => ProtocolCategory::Iot,

            // Authentication
            #[cfg(feature = "auth")]
            Protocol::Kerberos | Protocol::Ldap => ProtocolCategory::Authentication,

            // Routing
            #[cfg(feature = "infra")]
            Protocol::Bgp => ProtocolCategory::Routing,

            // Phase 12A — 企业协议
            // R7：misc feature
            #[cfg(feature = "misc")]
            Protocol::Telnet | Protocol::Vnc => ProtocolCategory::RemoteAccess,
            #[cfg(feature = "infra")]
            Protocol::Dhcpv6 | Protocol::Vxlan => ProtocolCategory::Infrastructure,
            #[cfg(feature = "vpn")]
            Protocol::L2tp | Protocol::Pptp => ProtocolCategory::Tunnel,
            #[cfg(feature = "auth")]
            Protocol::Radius => ProtocolCategory::Authentication,
            #[cfg(feature = "voip")]
            Protocol::Turn | Protocol::Mgcp | Protocol::H323 => ProtocolCategory::Voip,
            // Phase 11A — 简单协议
            #[cfg(feature = "misc")]
            Protocol::Tftp | Protocol::Rsync | Protocol::Whois => ProtocolCategory::FileTransfer,
            #[cfg(feature = "misc")]
            Protocol::Syslog => ProtocolCategory::NetworkManagement,
            #[cfg(feature = "proto3")]
            Protocol::Rtmp => ProtocolCategory::Web,
            #[cfg(feature = "proto3")]
            Protocol::Socks => ProtocolCategory::Tunnel,
            #[cfg(feature = "infra")]
            Protocol::Netflow => ProtocolCategory::NetworkManagement,
            #[cfg(feature = "infra")]
            Protocol::Ike => ProtocolCategory::Tunnel,
            #[cfg(feature = "infra")]
            Protocol::Ptpv2 => ProtocolCategory::Infrastructure,
            #[cfg(feature = "infra")]
            Protocol::Nfs => ProtocolCategory::FileTransfer,
            // Other
            Protocol::Other(_) => ProtocolCategory::Other,
        }
    }

    /// 获取协议的风险评级
    pub fn breed(self) -> ProtocolBreed {
        match self {
            Protocol::Dns
            | Protocol::Http
            | Protocol::Smtp
            | Protocol::Pop3
            | Protocol::Pop3s
            | Protocol::Imap
            | Protocol::Imaps
            | Protocol::Ntp
            | Protocol::Dhcp
            | Protocol::Tls
            | Protocol::Quic
            | Protocol::Http3
            | Protocol::Dtls
            | Protocol::Ssh => ProtocolBreed::Safe,
            Protocol::Mysql
            | Protocol::Postgresql
            | Protocol::Redis
            | Protocol::Mongodb
            | Protocol::Snmp
            | Protocol::Modbus => ProtocolBreed::Acceptable,
            #[cfg(feature = "proto3")]
            Protocol::Ftp => ProtocolBreed::Fun,
            #[cfg(feature = "iot")]
            Protocol::Mqtt => ProtocolBreed::Safe,
            #[cfg(feature = "vpn")]
            Protocol::WireGuard => ProtocolBreed::Safe,
            #[cfg(feature = "vpn")]
            Protocol::OpenVpn => ProtocolBreed::Safe,
            #[cfg(feature = "voip")]
            Protocol::Stun => ProtocolBreed::Safe,
            #[cfg(feature = "auth")]
            Protocol::Kerberos | Protocol::Ldap => ProtocolBreed::Safe,
            #[cfg(feature = "remote")]
            Protocol::Rdp => ProtocolBreed::Acceptable,
            #[cfg(feature = "infra")]
            Protocol::Bgp => ProtocolBreed::Safe,
            #[cfg(feature = "proto3")]
            Protocol::Sip
            | Protocol::Rtp
            | Protocol::Rtcp
            | Protocol::Http2
            | Protocol::WebSocket => ProtocolBreed::Safe,
            // Phase 12A
            #[cfg(feature = "misc")]
            Protocol::Telnet => ProtocolBreed::Fun,
            #[cfg(feature = "misc")]
            Protocol::Vnc => ProtocolBreed::Acceptable,
            #[cfg(feature = "infra")]
            Protocol::Dhcpv6 | Protocol::Vxlan => ProtocolBreed::Safe,
            #[cfg(feature = "vpn")]
            Protocol::L2tp | Protocol::Pptp => ProtocolBreed::Safe,
            #[cfg(feature = "auth")]
            Protocol::Radius => ProtocolBreed::Safe,
            #[cfg(feature = "voip")]
            Protocol::Turn | Protocol::Mgcp | Protocol::H323 => ProtocolBreed::Safe,
            // Phase 11A
            #[cfg(feature = "misc")]
            Protocol::Tftp | Protocol::Rsync | Protocol::Whois => ProtocolBreed::Safe,
            #[cfg(feature = "misc")]
            Protocol::Syslog => ProtocolBreed::Safe,
            #[cfg(feature = "proto3")]
            Protocol::Rtmp => ProtocolBreed::Acceptable,
            #[cfg(feature = "proto3")]
            Protocol::Socks => ProtocolBreed::Unsafe,
            #[cfg(feature = "infra")]
            Protocol::Netflow | Protocol::Ike | Protocol::Ptpv2 | Protocol::Nfs => {
                ProtocolBreed::Safe
            }
            Protocol::Tcp | Protocol::Udp | Protocol::Icmp | Protocol::Other(_) => {
                ProtocolBreed::Unrated
            }
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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

impl ProtocolCategory {
    /// 获取协议分类的人类可读名称
    pub fn display_name(&self) -> &'static str {
        match self {
            ProtocolCategory::Network => "Network",
            ProtocolCategory::Web => "Web",
            ProtocolCategory::WebTunnel => "Web Tunnel",
            ProtocolCategory::Vpn => "VPN",
            ProtocolCategory::Tunnel => "Tunnel",
            ProtocolCategory::Mail => "Mail",
            ProtocolCategory::Dns => "DNS",
            ProtocolCategory::Database => "Database",
            ProtocolCategory::RemoteAccess => "Remote Access",
            ProtocolCategory::FileTransfer => "File Transfer",
            ProtocolCategory::Voip => "VoIP",
            ProtocolCategory::Infrastructure => "Infrastructure",
            ProtocolCategory::NetworkManagement => "Network Management",
            ProtocolCategory::Industrial => "Industrial",
            ProtocolCategory::Iot => "IoT",
            ProtocolCategory::Authentication => "Authentication",
            ProtocolCategory::Video => "Video",
            ProtocolCategory::Audio => "Audio",
            ProtocolCategory::Cloud => "Cloud",
            ProtocolCategory::Messaging => "Messaging",
            ProtocolCategory::Social => "Social Network",
            ProtocolCategory::Gaming => "Gaming",
            ProtocolCategory::Collaboration => "Collaboration",
            ProtocolCategory::FileSharing => "File Sharing",
            ProtocolCategory::Routing => "Routing",
            ProtocolCategory::Other => "Other",
        }
    }

    /// 获取协议分类的简短描述
    pub fn description(&self) -> &'static str {
        match self {
            ProtocolCategory::Network => "Network layer protocols (TCP, UDP, ICMP)",
            ProtocolCategory::Web => "Web protocols (HTTP, HTTP/2, WebSocket)",
            ProtocolCategory::WebTunnel => "Encrypted web traffic (TLS, QUIC, HTTP/3)",
            ProtocolCategory::Vpn => "VPN and encrypted tunnel protocols",
            ProtocolCategory::Tunnel => "Network tunneling protocols",
            ProtocolCategory::Mail => "Email protocols (SMTP, POP3, IMAP)",
            ProtocolCategory::Dns => "Domain Name System protocols",
            ProtocolCategory::Database => "Database protocols (MySQL, PostgreSQL, Redis, MongoDB)",
            ProtocolCategory::RemoteAccess => "Remote access and administration protocols",
            ProtocolCategory::FileTransfer => "File transfer protocols (FTP)",
            ProtocolCategory::Voip => "Voice/Video over IP and real-time communication",
            ProtocolCategory::Infrastructure => "Network infrastructure protocols (NTP, DHCP)",
            ProtocolCategory::NetworkManagement => "Network management protocols (SNMP)",
            ProtocolCategory::Industrial => "Industrial control system protocols (Modbus)",
            ProtocolCategory::Iot => "Internet of Things protocols (MQTT)",
            ProtocolCategory::Authentication => "Authentication and directory protocols",
            ProtocolCategory::Video => "Video streaming protocols",
            ProtocolCategory::Audio => "Audio streaming protocols",
            ProtocolCategory::Cloud => "Cloud service platforms",
            ProtocolCategory::Messaging => "Instant messaging protocols",
            ProtocolCategory::Social => "Social network platforms",
            ProtocolCategory::Gaming => "Online gaming protocols",
            ProtocolCategory::Collaboration => "Collaboration and conferencing tools",
            ProtocolCategory::FileSharing => "File sharing and P2P protocols",
            ProtocolCategory::Routing => "Network routing protocols (BGP)",
            ProtocolCategory::Other => "Other/unknown protocols",
        }
    }

    /// 获取对应的 nDPI 分类 ID
    pub fn ndpi_category_id(&self) -> u32 {
        match self {
            ProtocolCategory::Network => 14,
            ProtocolCategory::Web => 5,
            ProtocolCategory::WebTunnel => 5,
            ProtocolCategory::Vpn => 2,
            ProtocolCategory::Tunnel => 2,
            ProtocolCategory::Mail => 3,
            ProtocolCategory::Dns => 14,
            ProtocolCategory::Database => 11,
            ProtocolCategory::RemoteAccess => 12,
            ProtocolCategory::FileTransfer => 7,
            ProtocolCategory::Voip => 10,
            ProtocolCategory::Infrastructure => 14,
            ProtocolCategory::NetworkManagement => 14,
            ProtocolCategory::Industrial => 31,
            ProtocolCategory::Iot => 31,
            ProtocolCategory::Authentication => 14,
            ProtocolCategory::Video => 26,
            ProtocolCategory::Audio => 25,
            ProtocolCategory::Cloud => 13,
            ProtocolCategory::Messaging => 9,
            ProtocolCategory::Social => 6,
            ProtocolCategory::Gaming => 8,
            ProtocolCategory::Collaboration => 15,
            ProtocolCategory::FileSharing => 29,
            ProtocolCategory::Routing => 14,
            ProtocolCategory::Other => 0,
        }
    }
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
            | Application::ParamountPlus => Protocol::Http,

            Application::WeChat
            | Application::Telegram
            | Application::WhatsApp
            | Application::Discord
            | Application::QQ
            | Application::Slack
            | Application::Line
            | Application::Signal
            | Application::Zoom
            | Application::Twitch
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct MysqlMetadata {
    /// 服务器版本 (如 "8.0.33")
    pub version: Option<String>,
    /// 认证插件名 (如 "mysql_native_password")
    pub auth_plugin: Option<String>,
}

/// PostgreSQL 元数据
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct RedisMetadata {
    /// 命令类型 (如 GET, SET, SELECT)
    pub command: Option<String>,
}

/// MQTT 元数据 (feature: iot)
#[cfg(feature = "iot")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct WireGuardMetadata {
    /// 消息类型: 1=Initiation, 2=Response, 3=CookieReply, 4=Transport
    pub message_type: u8,
    /// 发送者索引
    pub sender_index: u32,
}

/// STUN 元数据 (feature: voip)
#[cfg(feature = "voip")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct StunMetadata {
    /// 消息类型 (如 0x0001=Binding Request)
    pub message_type: u16,
    /// Transaction ID (12 bytes)
    pub transaction_id: [u8; 12],
    /// XOR-MAPPED-ADDRESS (仅 IPv4)
    pub mapped_address: Option<String>,
}

/// Kerberos 元数据 (feature: auth)
#[cfg(feature = "auth")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct KerberosMetadata {
    /// 消息类型: 10=AS-REQ, 11=AS-REP, 12=TGS-REQ, 13=TGS-REP
    pub msg_type: u8,
    /// Realm (域名)
    pub realm: Option<String>,
}

#[cfg(feature = "proto3")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct FtpMetadata {
    pub is_client: bool,
    pub verb: Option<String>,
    pub argument: Option<String>,
    pub response_code: Option<u16>,
}

#[cfg(feature = "proto3")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct SipMetadata {
    pub is_request: bool,
    pub method: Option<String>,
    pub status_code: Option<u16>,
    pub user_agent: Option<String>,
}

#[cfg(feature = "proto3")]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
#[derive(Debug, Clone)]
pub struct RtpMetadata {
    pub ssrc: u32,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc_confirmed: bool,
    pub is_rtcp: bool,
}
