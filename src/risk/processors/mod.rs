pub mod behavioral;
pub mod dns;
pub mod http;
pub mod tls;

use super::RiskRegistry;

pub fn register_defaults(registry: &mut RiskRegistry) {
    registry.register(Box::new(tls::TlsRiskProcessor::new()));
    registry.register(Box::new(dns::DnsRiskProcessor::new()));
    registry.register(Box::new(http::HttpRiskProcessor::new()));
    registry.register(Box::new(behavioral::BehavioralRiskProcessor::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_register_defaults() {
        let mut registry = RiskRegistry::new();
        register_defaults(&mut registry);
        assert_eq!(registry.processor_count(), 4);
    }
}
