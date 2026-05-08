use rdpi::protocols::Registry;
use rdpi::core::types::*;

#[test]
fn test_registry_new() {
    let registry = Registry::new();
    assert_eq!(registry.detector_count(), 0);
}

#[test]
fn test_registry_default() {
    // Default registry should have DNS detector registered (when dns feature is enabled)
    let registry = Registry::default();
    assert_eq!(registry.detector_count(), 1);
}
