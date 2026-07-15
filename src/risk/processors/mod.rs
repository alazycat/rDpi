//! Built-in risk processors for rDpi
//!
//! Each module implements `RiskProcessor` for a specific risk category.

use super::RiskRegistry;

/// 注册所有内置风险处理器
///
/// 后续 Phase 10.1-10.4 会在此添加各处理器注册。
pub fn register_defaults(_registry: &mut RiskRegistry) {
    // TLS processors — Phase 10.1
    // DNS processors — Phase 10.2
    // HTTP processors — Phase 10.3
    // Behavioral processors — Phase 10.4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_defaults_does_not_panic() {
        let mut registry = RiskRegistry::new();
        register_defaults(&mut registry);
        // No processors registered yet in base, just ensure no panic
        assert_eq!(registry.processor_count(), 0);
    }
}
