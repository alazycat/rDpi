//! Built-in risk processors for rDpi
//!
//! Each module implements `RiskProcessor` for a specific risk category.

pub mod tls;

use super::RiskRegistry;

/// 注册所有内置风险处理器
pub fn register_defaults(registry: &mut RiskRegistry) {
    registry.register(Box::new(tls::TlsRiskProcessor::new()));
    // DNS processors — Phase 10.2
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
        assert!(registry.processor_count() > 0);
    }
}
