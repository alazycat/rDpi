pub mod behavioral;
pub mod dns;
#[cfg(feature = "proto3")]
pub mod ftp;
pub mod http;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "smb")]
pub mod smb;
pub mod tls;
pub mod tls_cert;

use super::RiskRegistry;

pub fn register_defaults(registry: &mut RiskRegistry) {
    registry.register(Box::new(tls::TlsRiskProcessor::new()));
    registry.register(Box::new(dns::DnsRiskProcessor::new()));
    registry.register(Box::new(http::HttpRiskProcessor::new()));
    registry.register(Box::new(behavioral::BehavioralRiskProcessor::new()));
    registry.register(Box::new(tls_cert::TlsCertRiskProcessor::new()));
    // QUIC 处理器仅在 quic feature 下编译/注册（引用 quic 协议模块的版本常量与解析器）
    #[cfg(feature = "quic")]
    registry.register(Box::new(quic::QuicRiskProcessor::new()));
    // FTP 风险（Unsafe Protocol / Clear-Text Credentials）随 proto3 注册
    #[cfg(feature = "proto3")]
    registry.register(Box::new(ftp::FtpRiskProcessor::new()));
    // SMBv1 风险随 smb feature 注册
    #[cfg(feature = "smb")]
    registry.register(Box::new(smb::SmbRiskProcessor::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_register_defaults() {
        let mut registry = RiskRegistry::new();
        register_defaults(&mut registry);
        // quic / proto3 / smb 处理器随 feature 增量注册
        let expected = 5
            + usize::from(cfg!(feature = "quic"))
            + usize::from(cfg!(feature = "proto3"))
            + usize::from(cfg!(feature = "smb"));
        assert_eq!(registry.processor_count(), expected);
    }
}
