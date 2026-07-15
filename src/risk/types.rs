//! Risk analysis types for rDpi
//!
//! Defines risk indicators detected during flow analysis.

/// 风险标记枚举
///
/// 对应 nDPI 的 `ndpi_risk_enum` 概念，每个变体代表一种可检测的安全/异常风险。
#[cfg(feature = "risk")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskFlag {
    // === TLS 安全 (7) ===
    /// TLS ClientHello 缺少 SNI 扩展，可能用于隐蔽隧道
    TlsMissingSni,
    /// 自签名 TLS 证书，可能为中间人攻击
    TlsSelfSignedCert,
    /// TLS 证书已过期
    TlsCertExpired,
    /// TLS 证书有效期超过 398 天（Apple/Google 限制）
    TlsCertValidityTooLong,
    /// 使用弱密码套件（RC4, DES, 3DES, EXPORT 等）
    TlsWeakCipher,
    /// TLS 版本低于 1.2（1.0/1.1 已弃用）
    TlsObsoleteVersion,
    /// ALPN 与 SNI 不匹配，可能为协议混淆
    TlsAlpnSniMismatch,

    // === DNS 异常 (3) ===
    /// DNS 响应大小超过 512 字节，可能为 DNS 隧道
    DnsLargePacket,
    /// DNS 使用 IP 分片，可能为 DNS 隧道或放大攻击
    DnsFragmented,
    /// 可疑 DNS 查询模式
    DnsSuspiciousTraffic,

    // === HTTP 安全 (4) ===
    /// HTTP 响应含可疑内容（base64 大块、混淆 JS 等）
    HttpSuspiciousContent,
    /// HTTP User-Agent 匹配已知爬虫/机器人
    HttpCrawlerBot,
    /// HTTP Server 头为过时软件版本
    HttpObsoleteServer,
    /// 明文 HTTP 传输密码字段
    ClearTextCredentials,

    // === 网络行为 (5) ===
    /// 单向流量（连接无响应）
    UnidirectionalTraffic,
    /// 流量以固定间隔定期出现（心跳/轮询）
    PeriodicFlow,
    /// TCP 探测尝试（SYN 后无数据）
    ProbingAttempt,
    /// 已知混淆协议特征
    ObfuscatedTraffic,
    /// 明文协议中传输二进制数据
    BinaryDataTransfer,

    // === 通用 (2) ===
    /// 使用不安全协议（明文协议等）
    UnsafeProtocol,
    /// 未能识别的协议
    UnknownProtocol,
}

/// 风险严重程度等级
#[cfg(feature = "risk")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskSeverity {
    /// 低风险，信息性
    Low = 1,
    /// 中等风险，需关注
    Medium = 2,
    /// 高风险，需处理
    High = 3,
    /// 严重风险，需立即处理
    Critical = 4,
}

/// 单条风险结果
#[cfg(feature = "risk")]
#[derive(Debug, Clone)]
pub struct RiskResult {
    /// 风险标记
    pub flag: RiskFlag,
    /// 风险等级
    pub severity: RiskSeverity,
    /// 风险描述
    pub description: String,
}

#[cfg(feature = "risk")]
impl RiskResult {
    /// 创建新的风险结果
    pub fn new(flag: RiskFlag, severity: RiskSeverity, description: impl Into<String>) -> Self {
        Self {
            flag,
            severity,
            description: description.into(),
        }
    }
}

#[cfg(feature = "risk")]
impl RiskFlag {
    /// 获取风险标记的默认严重程度
    pub fn default_severity(&self) -> RiskSeverity {
        match self {
            RiskFlag::TlsMissingSni => RiskSeverity::Medium,
            RiskFlag::TlsSelfSignedCert => RiskSeverity::High,
            RiskFlag::TlsCertExpired => RiskSeverity::High,
            RiskFlag::TlsCertValidityTooLong => RiskSeverity::Medium,
            RiskFlag::TlsWeakCipher => RiskSeverity::High,
            RiskFlag::TlsObsoleteVersion => RiskSeverity::High,
            RiskFlag::TlsAlpnSniMismatch => RiskSeverity::Medium,
            RiskFlag::DnsLargePacket => RiskSeverity::Medium,
            RiskFlag::DnsFragmented => RiskSeverity::Medium,
            RiskFlag::DnsSuspiciousTraffic => RiskSeverity::High,
            RiskFlag::HttpSuspiciousContent => RiskSeverity::High,
            RiskFlag::HttpCrawlerBot => RiskSeverity::Low,
            RiskFlag::HttpObsoleteServer => RiskSeverity::Medium,
            RiskFlag::ClearTextCredentials => RiskSeverity::Critical,
            RiskFlag::UnidirectionalTraffic => RiskSeverity::Medium,
            RiskFlag::PeriodicFlow => RiskSeverity::Low,
            RiskFlag::ProbingAttempt => RiskSeverity::High,
            RiskFlag::ObfuscatedTraffic => RiskSeverity::High,
            RiskFlag::BinaryDataTransfer => RiskSeverity::Medium,
            RiskFlag::UnsafeProtocol => RiskSeverity::High,
            RiskFlag::UnknownProtocol => RiskSeverity::Low,
        }
    }

    /// 获取风险标记的简短名称
    pub fn name(&self) -> &'static str {
        match self {
            RiskFlag::TlsMissingSni => "tls_missing_sni",
            RiskFlag::TlsSelfSignedCert => "tls_self_signed_cert",
            RiskFlag::TlsCertExpired => "tls_cert_expired",
            RiskFlag::TlsCertValidityTooLong => "tls_cert_validity_too_long",
            RiskFlag::TlsWeakCipher => "tls_weak_cipher",
            RiskFlag::TlsObsoleteVersion => "tls_obsolete_version",
            RiskFlag::TlsAlpnSniMismatch => "tls_alpn_sni_mismatch",
            RiskFlag::DnsLargePacket => "dns_large_packet",
            RiskFlag::DnsFragmented => "dns_fragmented",
            RiskFlag::DnsSuspiciousTraffic => "dns_suspicious_traffic",
            RiskFlag::HttpSuspiciousContent => "http_suspicious_content",
            RiskFlag::HttpCrawlerBot => "http_crawler_bot",
            RiskFlag::HttpObsoleteServer => "http_obsolete_server",
            RiskFlag::ClearTextCredentials => "clear_text_credentials",
            RiskFlag::UnidirectionalTraffic => "unidirectional_traffic",
            RiskFlag::PeriodicFlow => "periodic_flow",
            RiskFlag::ProbingAttempt => "probing_attempt",
            RiskFlag::ObfuscatedTraffic => "obfuscated_traffic",
            RiskFlag::BinaryDataTransfer => "binary_data_transfer",
            RiskFlag::UnsafeProtocol => "unsafe_protocol",
            RiskFlag::UnknownProtocol => "unknown_protocol",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_result_new() {
        let r = RiskResult::new(RiskFlag::TlsMissingSni, RiskSeverity::Medium, "missing sni");
        assert_eq!(r.flag, RiskFlag::TlsMissingSni);
        assert_eq!(r.severity, RiskSeverity::Medium);
        assert_eq!(r.description, "missing sni");
    }

    #[test]
    fn test_risk_flag_default_severity() {
        assert_eq!(RiskFlag::ClearTextCredentials.default_severity(), RiskSeverity::Critical);
        assert_eq!(RiskFlag::HttpCrawlerBot.default_severity(), RiskSeverity::Low);
        assert_eq!(RiskFlag::TlsMissingSni.default_severity(), RiskSeverity::Medium);
    }

    #[test]
    fn test_risk_flag_name() {
        assert_eq!(RiskFlag::TlsMissingSni.name(), "tls_missing_sni");
        assert_eq!(RiskFlag::ClearTextCredentials.name(), "clear_text_credentials");
        assert_eq!(RiskFlag::ProbingAttempt.name(), "probing_attempt");
    }
}
