//! Built-in risk processors for rDpi

pub mod dns;
pub mod tls;

use super::RiskRegistry;

/// Register all built-in risk processors
pub fn register_defaults(registry: &mut RiskRegistry) {
    registry.register(Box::new(tls::TlsRiskProcessor::new()));
    registry.register(Box::new(dns::DnsRiskProcessor::new()));
    // HTTP processors — Phase 10.3
    // Behavioral processors — Phase 10.4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_defaults() {
        let mut registry = RiskRegistry::new();
        register_defaults(&mut registry);
        assert_eq!(registry.processor_count(), 2);
    }
}
