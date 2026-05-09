//! Application protocol detectors for rDpi
//!
//! This module contains protocol-specific detection logic.

use crate::core::types::*;

#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "smtp")]
pub mod smtp;

/// 协议检测器 Trait
pub trait ProtocolDetector: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, payload: &[u8]) -> Option<DetectionResult>;
}

/// 协议注册表
pub struct Registry {
    detectors: Vec<Box<dyn ProtocolDetector>>,
}

impl Registry {
    pub fn new() -> Self {
        Self { detectors: Vec::new() }
    }

    pub fn register(&mut self, detector: Box<dyn ProtocolDetector>) {
        self.detectors.push(detector);
    }

    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    pub fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        for detector in &self.detectors {
            if let Some(result) = detector.detect(payload) {
                return Some(result);
            }
        }
        None
    }
}

impl Default for Registry {
    fn default() -> Self {
        let mut registry = Self::new();
        register_defaults(&mut registry);
        registry
    }
}

/// 注册所有启用的内置协议
/// 注册顺序：TLS → SSH → SMTP → HTTP → DNS（按特异性递减）
pub fn register_defaults(_registry: &mut Registry) {
    #[cfg(feature = "tls")]
    tls::register(_registry);
    #[cfg(feature = "ssh")]
    ssh::register(_registry);
    #[cfg(feature = "smtp")]
    smtp::register(_registry);
    #[cfg(feature = "http")]
    http::register(_registry);
    #[cfg(feature = "dns")]
    dns::register(_registry);
}
