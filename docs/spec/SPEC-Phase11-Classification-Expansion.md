# SPEC: Phase 11 — 分类体系扩展

> 源自: `docs/prd/PRD-Phase11-Classification-Expansion.md`
> 日期: 2026-07-15

---

## 1. 变更文件清单

| 文件 | 操作 | 说明 |
|------|------|------|
| src/core/types.rs | MODIFY | ProtocolCategory 枚举 + category() 映射 + 新方法 |
| tests/test_types.rs | MODIFY | 新增分类测试 |
| tests/test_integration.rs | MODIFY | 验证分类映射完整性 |

**无新增文件** — 所有变更集中在 `types.rs`。

---

## 2. ProtocolCategory 枚举 (25 个)

```rust
pub enum ProtocolCategory {
    Network,           // TCP, UDP, ICMP
    Web,               // HTTP, HTTP/2, WebSocket
    WebTunnel,         // TLS, QUIC, HTTP/3 — 加密 Web 隧道
    Vpn,               // WireGuard, OpenVPN
    Tunnel,            // GRE, IPsec — 预留
    Mail,              // SMTP, POP3, IMAP
    Dns,               // DNS
    Database,          // MySQL, PostgreSQL, Redis, MongoDB
    RemoteAccess,      // SSH, RDP
    FileTransfer,      // FTP
    Voip,              // SIP, RTP, RTCP, STUN
    Infrastructure,    // NTP, DHCP
    NetworkManagement, // SNMP
    Industrial,        // Modbus
    Iot,               // MQTT
    Authentication,    // Kerberos, LDAP
    Video,             // 流媒体视频 — 预留
    Audio,             // 流媒体音频 — 预留
    Cloud,             // 云服务 — 预留
    Messaging,         // IM — 预留
    Social,            // 社交网络 — 预留
    Gaming,            // 游戏 — 预留
    Collaboration,     // 协同办公 — 预留
    FileSharing,       // P2P/文件共享 — 预留
    Routing,           // BGP, OSPF — 预留
    Other,
}
```

**关键变化**:
- `EncryptedTunnel` → 拆分为 `WebTunnel` + `Vpn`
- 新增 12 个预留分类（Video/Audio/Cloud/Messaging/Social/Gaming/Collaboration/FileSharing/Routing/Tunnel/WebTunnel/Authentication）
- Authentication 从 cfg-gated 改为无条件

---

## 3. category() 映射

```rust
pub fn category(self) -> ProtocolCategory {
    match self {
        // Network
        Protocol::Tcp | Protocol::Udp | Protocol::Icmp => ProtocolCategory::Network,

        // Web
        Protocol::Http | Protocol::Http2 | Protocol::WebSocket => ProtocolCategory::Web,

        // WebTunnel (加密 Web 隧道)
        Protocol::Tls | Protocol::Quic | Protocol::Http3 => ProtocolCategory::WebTunnel,

        // VPN
        #[cfg(feature = "vpn")]
        Protocol::WireGuard | Protocol::OpenVpn => ProtocolCategory::Vpn,

        // Mail
        Protocol::Smtp | Protocol::Pop3 | Protocol::Pop3s
            | Protocol::Imap | Protocol::Imaps => ProtocolCategory::Mail,

        // DNS
        Protocol::Dns => ProtocolCategory::Dns,

        // Database
        Protocol::Mysql | Protocol::Postgresql | Protocol::Redis
            | Protocol::Mongodb => ProtocolCategory::Database,

        // RemoteAccess
        Protocol::Ssh | Protocol::Rdp => ProtocolCategory::RemoteAccess,

        // FileTransfer
        #[cfg(feature = "proto3")]
        Protocol::Ftp => ProtocolCategory::FileTransfer,

        // VoIP
        #[cfg(feature = "proto3")]
        Protocol::Sip => ProtocolCategory::Voip,
        #[cfg(feature = "proto3")]
        Protocol::Rtp | Protocol::Rtcp => ProtocolCategory::Voip,
        #[cfg(feature = "voip")]
        Protocol::Stun => ProtocolCategory::Voip,

        // Infrastructure
        Protocol::Ntp | Protocol::Dhcp => ProtocolCategory::Infrastructure,
        #[cfg(feature = "infra")]
        Protocol::Bgp => ProtocolCategory::Routing,

        // NetworkManagement
        Protocol::Snmp => ProtocolCategory::NetworkManagement,

        // Industrial
        Protocol::Modbus => ProtocolCategory::Industrial,

        // IoT
        #[cfg(feature = "iot")]
        Protocol::Mqtt => ProtocolCategory::Iot,

        // Authentication
        #[cfg(feature = "auth")]
        Protocol::Kerberos | Protocol::Ldap => ProtocolCategory::Authentication,

        // Others
        Protocol::Other(_) => ProtocolCategory::Other,
    }
}
```

---

## 4. 新增方法

```rust
impl ProtocolCategory {
    /// 人类可读的显示名称
    pub fn display_name(&self) -> &'static str {
        match self {
            ProtocolCategory::Network => "Network",
            ProtocolCategory::Web => "Web",
            ProtocolCategory::WebTunnel => "Web Tunnel",
            ProtocolCategory::Vpn => "VPN",
            ProtocolCategory::Tunnel => "Tunnel",
            ProtocolCategory::Mail => "Mail",
            ProtocolCategory::Dns => "DNS",
            ProtocolCategory::Database => "Database",
            ProtocolCategory::RemoteAccess => "Remote Access",
            ProtocolCategory::FileTransfer => "File Transfer",
            ProtocolCategory::Voip => "VoIP",
            ProtocolCategory::Infrastructure => "Infrastructure",
            ProtocolCategory::NetworkManagement => "Network Management",
            ProtocolCategory::Industrial => "Industrial",
            ProtocolCategory::Iot => "IoT",
            ProtocolCategory::Authentication => "Authentication",
            ProtocolCategory::Video => "Video",
            ProtocolCategory::Audio => "Audio",
            ProtocolCategory::Cloud => "Cloud",
            ProtocolCategory::Messaging => "Messaging",
            ProtocolCategory::Social => "Social Network",
            ProtocolCategory::Gaming => "Gaming",
            ProtocolCategory::Collaboration => "Collaboration",
            ProtocolCategory::FileSharing => "File Sharing",
            ProtocolCategory::Routing => "Routing",
            ProtocolCategory::Other => "Other",
        }
    }

    /// 简短描述
    pub fn description(&self) -> &'static str {
        match self {
            ProtocolCategory::Network => "Network layer protocols",
            ProtocolCategory::Web => "Web/HTTP protocols",
            ProtocolCategory::WebTunnel => "Encrypted web traffic (TLS, QUIC)",
            // ...
        }
    }

    /// nDPI 分类 ID 映射
    pub fn ndpi_category_id(&self) -> u32 {
        match self {
            ProtocolCategory::Web => 5,
            ProtocolCategory::WebTunnel => 5,
            ProtocolCategory::Vpn => 2,
            // ...
        }
    }
}
```

---

## 5. Testing Strategy

| 测试 | 内容 |
|------|------|
| category() 完整映射 | 每个 Protocol 变体 → 期望的 category |
| display_name() | 每个分类返回非空字符串 |
| description() | 每个分类返回非空描述 |
| ndpi_category_id() | 每个分类返回有效 ID |
| 不引入 cfg 遗漏 | 所有 feature-gated protocol 都有对应分支 |

**现存 test_integration.rs 中按 category 过滤的测试需要更新**（如果有）。

---

## 6. Implementation Plan

```
Step 1: types.rs — ProtocolCategory 枚举重写（+12 新增，1 删除，1 变更）
Step 2: types.rs — category() 映射重写
Step 3: types.rs — display_name(), description(), ndpi_category_id()
Step 4: cargo build — 修复所有 match 遗漏（编译器会捕获）
Step 5: cargo test — 更新所有断言预期值
Step 6: 全 feature 编译验证
```
