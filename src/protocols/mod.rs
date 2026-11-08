//! Application protocol detectors for rDpi
//!
//! This module contains protocol-specific detection logic.

use crate::core::types::*;

#[cfg(feature = "storage")]
pub mod afp;
#[cfg(feature = "messaging")]
pub mod amqp;
#[cfg(feature = "infra")]
pub mod bgp;
#[cfg(feature = "database")]
pub mod cassandra;
#[cfg(feature = "infra")]
pub mod dhcp;
#[cfg(feature = "database")]
pub mod drda;
#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "dtls")]
pub mod dtls;
#[cfg(feature = "database")]
pub mod elasticsearch;
#[cfg(feature = "proto3")]
pub mod ftp;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "proto3")]
pub mod http2;
#[cfg(feature = "mail")]
pub mod imap;
#[cfg(feature = "messaging")]
pub mod kafka;
#[cfg(feature = "auth")]
pub mod kerberos;
#[cfg(feature = "auth")]
pub mod ldap;
#[cfg(feature = "database")]
pub mod memcached;
#[cfg(feature = "modbus")]
pub mod modbus;
#[cfg(feature = "database")]
pub mod mongodb;
#[cfg(feature = "iot")]
pub mod mqtt;
#[cfg(feature = "database")]
pub mod mssql;
#[cfg(feature = "database")]
pub mod mysql;
#[cfg(feature = "infra")]
pub mod ntp;
#[cfg(feature = "vpn")]
pub mod openvpn;
#[cfg(feature = "database")]
pub mod oracle;
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
#[cfg(feature = "smb")]
pub mod netbios;
#[cfg(feature = "infra")]
pub mod netflow;
#[cfg(feature = "storage")]
pub mod nfs;
#[cfg(feature = "infra")]
pub mod ptpv2;
#[cfg(feature = "smb")]
pub mod smb;
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

    /// 有状态逐包处理（P1）
    ///
    /// 返回 `None` 表示未接管该流；返回 `Some(Continue)` 表示已接管但需要更多
    /// 包；`Partial` / `Classified` 返回分类结果；`GiveUp` 放弃接管。
    /// 默认实现为无状态，直接返回 `None`。
    fn process(
        &self,
        _state: &mut DissectorState,
        _payload: &[u8],
        _direction: Direction,
        _ctx: &DetectContext,
    ) -> Option<DissectorOutcome> {
        None
    }

    /// 首字节门声明（F29 miss 路径预筛，2026-11-05）
    ///
    /// 声明 `payload[0]` 的可能取值区间（闭区间对 `&(u8, u8)` 数组）。返回
    /// `Some(ranges)` 时 Registry 在**注册期**预计算 skip 位图：miss 热路径上
    /// `payload[0]` 不在任何区间内的包直接跳过本 detector，免执行判定逻辑。
    ///
    /// **语义契约**：返回非 `None` 即承诺——`payload[0]` 不在声明区间内时，
    /// `detect()` / `detect_with_context()` 必返回 `None`。违反契约将引入假阴
    /// （真实流量被预筛跳过）。返回 `None`（默认）= 首字节任意，不参与预筛，
    /// 行为与未优化版本完全一致。
    fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
        None
    }
}

/// 由门声明区间构建 skip 位图：区间外字节对应位**置位**（跳过），区间内清零。
fn build_skip_bitmap(ranges: &[(u8, u8)]) -> [u64; 4] {
    let mut map = [!0u64; 4];
    for &(lo, hi) in ranges {
        for b in lo..=hi {
            map[(b >> 6) as usize] &= !(1u64 << (b & 63));
        }
    }
    map
}

/// Registry 条目：detector + 注册期预计算的首字节 skip 位图（构造期成本，
/// detect 路径仅一次位测试）
struct RegistryEntry {
    detector: Box<dyn ProtocolDetector>,
    /// `payload[0]=b` 时 `skip[(b >> 6) as usize] & (1u64 << (b & 63))` 置位
    /// 则本 detector 必然不命中，可安全跳过
    skip: [u64; 4],
}

impl RegistryEntry {
    fn new(detector: Box<dyn ProtocolDetector>) -> Self {
        let skip = detector
            .first_byte_gate()
            .map_or([0u64; 4], build_skip_bitmap);
        Self { detector, skip }
    }

    /// 空 payload 不参与预筛（各 detector 自行处理空载荷语义）
    #[inline]
    fn should_skip(&self, payload: &[u8]) -> bool {
        match payload.first() {
            Some(&b) => self.skip[(b >> 6) as usize] & (1u64 << (b & 63)) != 0,
            None => false,
        }
    }
}

/// 协议注册表
pub struct Registry {
    detectors: Vec<RegistryEntry>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn register(&mut self, detector: Box<dyn ProtocolDetector>) {
        self.detectors.push(RegistryEntry::new(detector));
    }

    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    pub fn detect(&self, payload: &[u8]) -> Option<DetectionResult> {
        for entry in &self.detectors {
            if entry.should_skip(payload) {
                continue;
            }
            if let Some(result) = entry.detector.detect(payload) {
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

        for entry in &self.detectors {
            if entry.should_skip(payload) {
                continue;
            }
            if let Some(result) = entry.detector.detect_with_context(payload, &ctx) {
                return Some(result);
            }
        }
        None
    }

    /// 有状态逐包检测
    ///
    /// 按注册顺序询问；首个返回 `Some` 的 detector 接管该流。**不应用首字节门**：
    /// 已接管流（如 HTTP 头跨包）后续包的 payload 首字节可能不是协议特征，
    /// 门预筛会错误跳过重组。
    pub fn process_stateful(
        &self,
        state: &mut DissectorState,
        payload: &[u8],
        direction: Direction,
        src_port: u16,
        dst_port: u16,
    ) -> Option<DissectorOutcome> {
        let ctx = DetectContext {
            src_port,
            dst_port,
            is_http3_port: src_port == 443 || dst_port == 443,
        };
        for entry in &self.detectors {
            if let Some(outcome) = entry.detector.process(state, payload, direction, &ctx) {
                return Some(outcome);
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
/// 注册顺序：QUIC → DTLS → TLS → SSH → (NetBIOS → SMB) → FTP → SNMP → Modbus → SMTP → POP3 → IMAP → NTP → DHCP → HTTP → DNS（按特异性递减）
pub fn register_defaults(_registry: &mut Registry) {
    // F50：Cassandra 必须先于 QUIC——internode magic 首字节 0xCA 落在 QUIC
    // 长包头门 0x80..=0xFF 内，未知版本 0x552DFA00 会被 QUIC 的
    // detect_other_long_header 误判为 Quic。Cassandra 门仅 0x02..=0x05 与
    // 0xCA，且要求 19 字节精确 magic 或严格 CQL STARTUP；真实 QUIC 短包头
    // 固定位要求首字节 0x40..=0x7F，长包头 0xC0..=0xFF 中只有 0xCA 落入
    // Cassandra 门，而 19 字节 internode 结构在 QUIC 中不可能出现。其余
    // detector 相对顺序不变。
    #[cfg(feature = "database")]
    cassandra::register(_registry);
    #[cfg(feature = "quic")]
    quic::register(_registry);
    // F38：DTLS 紧随 QUIC、先于 TLS——影响面复述（顺序 = 优先级语义）：
    // DTLS 仅在 legacy_record_version ∈ {0xfeff,0xfefd,0xfefc} + epoch=0 +
    // 单片段握手时命中，TLS 记录头（data[1]==0x03）与 DTLS 记录头
    // （data[1]==0xfe）互斥，DTLS 与 TLS 两 detector 顺序无相互影响；
    // 其余 detector 相对顺序不变。
    #[cfg(feature = "dtls")]
    dtls::register(_registry);
    #[cfg(feature = "tls")]
    tls::register(_registry);
    #[cfg(feature = "vpn")]
    wireguard::register(_registry);
    #[cfg(feature = "ssh")]
    ssh::register(_registry);
    #[cfg(feature = "smb")]
    {
        netbios::register(_registry);
        smb::register(_registry);
    }
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
    #[cfg(feature = "database")]
    mssql::register(_registry);
    #[cfg(feature = "database")]
    oracle::register(_registry);
    #[cfg(feature = "database")]
    drda::register(_registry);
    #[cfg(feature = "database")]
    elasticsearch::register(_registry);
    #[cfg(feature = "database")]
    memcached::register(_registry);
    #[cfg(feature = "messaging")]
    amqp::register(_registry);
    #[cfg(feature = "messaging")]
    kafka::register(_registry);
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
    // F51：AFP 必须先于 DNS——header-only DSI（16 字节，flags=0/1、其余字段
    // 为 0）会被 DNS detector 误判为 Dns（qd/an/ns/ar 均为 0，payload 尾部
    // 多余 4 字节未被校验）。AFP 门仅 0/1 且要求 16 字节 DSI 结构
    // （command 1..=8、reserved=0、长度下界）；真实 DNS 问题区从偏移 12
    // 开始，非零 qname 字节使 reserved != 0，不会落入 AFP。其余 detector
    // 相对顺序不变。
    #[cfg(feature = "storage")]
    afp::register(_registry);
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

#[cfg(test)]
mod gate_tests {
    use super::*;
    use crate::core::types::{DetectionResult, Protocol};
    use crate::protocols::ProtocolDetector;

    /// 声明了门的假 detector：任何未被预筛跳过的 payload 都返回命中。
    /// 用于验证 Registry 预筛机制本身（与真实协议判定无关）。
    struct AlwaysMatch {
        gate: Option<&'static [(u8, u8)]>,
    }
    impl ProtocolDetector for AlwaysMatch {
        fn name(&self) -> &'static str {
            "always_match"
        }
        fn detect(&self, _payload: &[u8]) -> Option<DetectionResult> {
            Some(DetectionResult::new(Protocol::Http))
        }
        fn first_byte_gate(&self) -> Option<&'static [(u8, u8)]> {
            self.gate
        }
    }

    #[test]
    fn test_skip_bitmap_boundaries() {
        let map = build_skip_bitmap(&[(0x10u8, 0x1Fu8)]);
        // 区间内全部不跳过
        for b in 0x10..=0x1Fu8 {
            assert_eq!(map[(b >> 6) as usize] & (1u64 << (b & 63)), 0);
        }
        // 区间外（前后边界 + 跨 word）全部跳过
        for b in [0x00u8, 0x0F, 0x20, 0x7F, 0xFF] {
            assert_eq!(
                map[(b >> 6) as usize] & (1u64 << (b & 63)),
                1u64 << (b & 63)
            );
        }
    }

    #[test]
    fn test_skip_bitmap_inclusive_upper_bound() {
        // 区间上界含 0xFF 时不得提前终止迭代（RangeInclusive 语义）
        let map = build_skip_bitmap(&[(0x80u8, 0xFFu8)]);
        assert_eq!(map[(0xFF >> 6) as usize] & (1u64 << (0xFF & 63)), 0);
        assert_eq!(
            map[(0x7F >> 6) as usize] & (1u64 << (0x7F & 63)),
            1u64 << (0x7F & 63)
        );
    }

    #[test]
    fn test_gate_skips_miss_and_allows_hit() {
        let mut reg = Registry::new();
        reg.register(Box::new(AlwaysMatch {
            gate: Some(&[(0x53u8, 0x53u8)]),
        }));
        // 首字节在区间内 → 正常命中
        assert!(reg.detect(b"SSH-2.0").is_some());
        // 首字节在区间外 → 被预筛跳过（detector 本可命中但被跳过）
        assert!(reg.detect(b"XYZ").is_none());
        // detect_with_ports 同样生效
        assert!(reg.detect_with_ports(b"XYZ", 1, 2).is_none());
        assert!(reg.detect_with_ports(b"SSH-2.0", 1, 2).is_some());
    }

    #[test]
    fn test_empty_payload_not_skipped() {
        let mut reg = Registry::new();
        reg.register(Box::new(AlwaysMatch {
            gate: Some(&[(0x53u8, 0x53u8)]),
        }));
        // 空 payload 不参与预筛（各 detector 自行处理空载荷语义）
        assert!(reg.detect(b"").is_some());
    }

    #[test]
    fn test_no_gate_never_skipped() {
        let mut reg = Registry::new();
        reg.register(Box::new(AlwaysMatch { gate: None }));
        assert!(reg.detect(&[0x00, 0x01, 0x02]).is_some());
        assert!(reg.detect_with_ports(&[0xFF], 1, 2).is_some());
    }
}

#[cfg(all(test, feature = "smb"))]
mod smb_registry_tests {
    use super::*;

    #[test]
    fn test_smb_detectors_registered() {
        // 子模块可访问 `Registry.detectors` 私有字段（同文件、后代模块）
        let registry = Registry::default();
        let names: Vec<&str> = registry
            .detectors
            .iter()
            .map(|entry| entry.detector.name())
            .collect();
        assert!(
            names.contains(&"netbios"),
            "netbios detector must be registered"
        );
        assert!(names.contains(&"smb"), "smb detector must be registered");
    }
}

#[cfg(all(test, feature = "database"))]
mod database_registry_tests {
    use super::*;

    #[test]
    fn test_memcached_detector_registered() {
        let registry = Registry::default();
        let names: Vec<&str> = registry
            .detectors
            .iter()
            .map(|entry| entry.detector.name())
            .collect();
        assert!(
            names.contains(&"memcached"),
            "memcached detector must be registered"
        );
    }

    #[test]
    fn test_elasticsearch_detector_registered() {
        let registry = Registry::default();
        let names: Vec<&str> = registry
            .detectors
            .iter()
            .map(|entry| entry.detector.name())
            .collect();
        assert!(
            names.contains(&"elasticsearch"),
            "elasticsearch detector must be registered"
        );
    }
}

#[cfg(all(test, feature = "messaging"))]
mod messaging_registry_tests {
    use super::*;

    #[test]
    fn test_amqp_detector_registered() {
        let registry = Registry::default();
        let names: Vec<&str> = registry
            .detectors
            .iter()
            .map(|entry| entry.detector.name())
            .collect();
        assert!(names.contains(&"amqp"), "amqp detector must be registered");
    }
}
