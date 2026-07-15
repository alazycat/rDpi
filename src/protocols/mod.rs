//! Application protocol detectors for rDpi
//!
//! This module contains protocol-specific detection logic.

use crate::core::types::*;

#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "mail")]
pub mod pop3;
#[cfg(feature = "mail")]
pub mod imap;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "smtp")]
pub mod smtp;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "infra")]
pub mod ntp;
#[cfg(feature = "infra")]
pub mod dhcp;
#[cfg(feature = "snmp")]
pub mod snmp;
#[cfg(feature = "modbus")]
pub mod modbus;
#[cfg(feature = "database")]
pub mod mysql;
#[cfg(feature = "database")]
pub mod postgresql;
#[cfg(feature = "database")]
pub mod redis;
#[cfg(feature = "proto3")]
pub mod ftp;
#[cfg(feature = "proto3")]
pub mod sip;
#[cfg(feature = "proto3")]
pub mod rtp;
#[cfg(feature = "iot")]
pub mod mqtt;

/// 协议检测器 Trait
pub trait ProtocolDetector: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, payload: &[u8]) -> Option<DetectionResult>;

    /// 带端口上下文的检测，默认转发到 detect()
    fn detect_with_context(&self, payload: &[u8], ctx: &DetectContext) -> Option<DetectionResult> {
        let _ = ctx;
        self.detect(payload)
    }
}

/// 协议注册表
pub struct Registry {
    detectors: Vec<Box<dyn ProtocolDetector>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
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

    /// 带端口信息的检测
    pub fn detect_with_ports(
        &self,
        payload: &[u8],
        src_port: u16,
        dst_port: u16,
    ) -> Option<DetectionResult> {
        let is_http3_port = src_port == 443 || dst_port == 443;
        let ctx = DetectContext {
            src_port,
            dst_port,
            is_http3_port,
        };

        for detector in &self.detectors {
            if let Some(result) = detector.detect_with_context(payload, &ctx) {
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
/// 注册顺序：QUIC → TLS → SSH → SNMP → Modbus → SMTP → POP3 → IMAP → NTP → DHCP → HTTP → DNS（按特异性递减）
pub fn register_defaults(_registry: &mut Registry) {
    #[cfg(feature = "quic")]
    quic::register(_registry);
    #[cfg(feature = "tls")]
    tls::register(_registry);
    #[cfg(feature = "ssh")]
    ssh::register(_registry);
    #[cfg(feature = "proto3")]
    ftp::register(_registry);
    #[cfg(feature = "snmp")]
    snmp::register(_registry);
    #[cfg(feature = "modbus")]
    modbus::register(_registry);
    #[cfg(feature = "proto3")]
    {
        sip::register(_registry);
        rtp::register(_registry);
    }
    #[cfg(feature = "database")]
    mysql::register(_registry);
    #[cfg(feature = "database")]
    postgresql::register(_registry);
    #[cfg(feature = "database")]
    redis::register(_registry);
    #[cfg(feature = "smtp")]
    smtp::register(_registry);
    #[cfg(feature = "mail")]
    {
        pop3::register(_registry);
        imap::register(_registry);
    }
    #[cfg(feature = "infra")]
    {
        ntp::register(_registry);
        dhcp::register(_registry);
    }
    #[cfg(feature = "iot")]
    mqtt::register(_registry);
    #[cfg(feature = "http")]
    http::register(_registry);
    #[cfg(feature = "dns")]
    dns::register(_registry);
}
