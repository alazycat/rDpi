pub mod behavioral;
pub mod dns;
pub mod http;
#[cfg(feature = "quic")]
pub mod quic;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_register_defaults() {
        let mut registry = RiskRegistry::new();
        register_defaults(&mut registry);
        // quic 处理器随 quic feature 增量注册
        #[cfg(feature = "quic")]
        let expected = 6;
        #[cfg(not(feature = "quic"))]
        let expected = 5;
        assert_eq!(registry.processor_count(), expected);
    }
}
