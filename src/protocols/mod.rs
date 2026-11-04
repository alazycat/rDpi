//! Application protocol detectors for rDpi
//!
//! This module contains protocol-specific detection logic.

use crate::core::types::*;

#[cfg(feature = "infra")]
pub mod bgp;
#[cfg(feature = "infra")]
pub mod dhcp;
#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "proto3")]
pub mod ftp;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "proto3")]
pub mod http2;
#[cfg(feature = "mail")]
pub mod imap;
#[cfg(feature = "auth")]
pub mod kerberos;
#[cfg(feature = "auth")]
pub mod ldap;
#[cfg(feature = "modbus")]
pub mod modbus;
#[cfg(feature = "database")]
pub mod mongodb;
#[cfg(feature = "iot")]
pub mod mqtt;
#[cfg(feature = "database")]
pub mod mysql;
#[cfg(feature = "infra")]
pub mod ntp;
#[cfg(feature = "vpn")]
pub mod openvpn;
#[cfg(feature = "mail")]
pub mod pop3;
#[cfg(feature = "database")]
pub mod postgresql;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "remote")]
pub mod rdp;
#[cfg(feature = "database")]
pub mod redis;
#[cfg(feature = "proto3")]
pub mod rtp;
#[cfg(feature = "proto3")]
pub mod sip;
#[cfg(feature = "smtp")]
pub mod smtp;
#[cfg(feature = "snmp")]
pub mod snmp;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "voip")]
pub mod stun;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "proto3")]
pub mod websocket;
#[cfg(feature = "vpn")]
pub mod wireguard;
// Phase 11A — 简单协议
#[cfg(feature = "infra")]
pub mod ike;
#[cfg(feature = "infra")]
pub mod netflow;
#[cfg(feature = "storage")]
pub mod nfs;
#[cfg(feature = "infra")]
pub mod ptpv2;
// R7：misc feature —— TFTP/Rsync/Whois/Syslog/Telnet/VNC 纳入 feature 矩阵
#[cfg(feature = "misc")]
pub mod rsync;
#[cfg(feature = "proto3")]
pub mod rtmp;
#[cfg(feature = "proto3")]
pub mod socks;
#[cfg(feature = "misc")]
pub mod syslog;
#[cfg(feature = "misc")]
pub mod tftp;
#[cfg(feature = "misc")]
pub mod whois;
// Phase 12A — 企业协议
#[cfg(feature = "infra")]
pub mod dhcpv6;
#[cfg(feature = "voip")]
pub mod h323;
#[cfg(feature = "vpn")]
pub mod l2tp;
#[cfg(feature = "voip")]
pub mod mgcp;
#[cfg(feature = "vpn")]
pub mod pptp;
#[cfg(feature = "auth")]
pub mod radius;
#[cfg(feature = "misc")]
pub mod telnet;
#[cfg(feature = "voip")]
pub mod turn;
#[cfg(feature = "misc")]
pub mod vnc;
#[cfg(feature = "infra")]
pub mod vxlan;

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
    #[cfg(feature = "vpn")]
    wireguard::register(_registry);
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
    #[cfg(feature = "voip")]
    stun::register(_registry);
    #[cfg(feature = "auth")]
    kerberos::register(_registry);
    #[cfg(feature = "auth")]
    ldap::register(_registry);
    #[cfg(feature = "remote")]
    rdp::register(_registry);
    #[cfg(feature = "database")]
    mongodb::register(_registry);
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
        bgp::register(_registry);
        ntp::register(_registry);
        dhcp::register(_registry);
    }
    #[cfg(feature = "iot")]
    mqtt::register(_registry);
    #[cfg(feature = "proto3")]
    http2::register(_registry);
    #[cfg(feature = "proto3")]
    websocket::register(_registry);
    #[cfg(feature = "vpn")]
    openvpn::register(_registry);
    #[cfg(feature = "http")]
    http::register(_registry);
    #[cfg(feature = "dns")]
    dns::register(_registry);
    // Phase 12A — 企业协议（低特异性）
    // R7：misc feature —— 注册相对顺序保持不变（R11 影响面）
    #[cfg(feature = "misc")]
    telnet::register(_registry);
    #[cfg(feature = "misc")]
    vnc::register(_registry);
    #[cfg(feature = "infra")]
    {
        dhcpv6::register(_registry);
        vxlan::register(_registry);
    }
    #[cfg(feature = "vpn")]
    {
        l2tp::register(_registry);
        pptp::register(_registry);
    }
    #[cfg(feature = "auth")]
    radius::register(_registry);
    #[cfg(feature = "voip")]
    {
        turn::register(_registry);
        mgcp::register(_registry);
        h323::register(_registry);
    }
    // Phase 11A — 简单协议（最低特异性，DNS/HTTP 之后检测）
    #[cfg(feature = "misc")]
    {
        syslog::register(_registry);
        tftp::register(_registry);
        rsync::register(_registry);
        whois::register(_registry);
    }
    #[cfg(feature = "infra")]
    {
        netflow::register(_registry);
        ike::register(_registry);
        ptpv2::register(_registry);
    }
    #[cfg(feature = "proto3")]
    {
        rtmp::register(_registry);
        socks::register(_registry);
    }
    #[cfg(feature = "storage")]
    nfs::register(_registry);
}
