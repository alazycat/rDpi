# PRD: Phase 11 — 分类体系扩展

> **版本**: 1.0 | **日期**: 2026-07-15 | **标签**: `ready-for-agent`

---

## Problem Statement

rDpi 当前 `ProtocolCategory` 仅有 13 个分类（不含 feature-gated 的 3 个），而 nDPI 有 35+ 核心分类 + 80+ 细分类别。分类过粗导致：

1. **协议归属模糊**: QUIC/TLS 都归入 `EncryptedTunnel`，无法区分"VPN"和"Web 加密"
2. **缺失重要分类**: 无 `Streaming`、`Gaming`、`Cloud`、`Messaging`、`FileSharing` 等业务分类
3. **与 nDPI 不兼容**: 无法与 nDPI 分类做映射对比
4. **策略能力受限**: 无法基于分类做阻断/限速/统计

---

## Solution

将 ProtocolCategory 从 13 个扩展到 **25 个**，重新映射所有 41 个协议，并添加 nDPI 分类映射表。

### 新旧分类对照

| 当前分类 | 新分类 (Phase 11) | 说明 |
|---------|-------------------|------|
| Network | Network | 保留 |
| Web | Web | 保留 |
| EncryptedTunnel | — | **删除**，拆为 WebTunnel + Vpn |
| — | **WebTunnel** (新增) | TLS/QUIC/HTTPS 加密 Web 流量 |
| — | **Vpn** (已有) | WireGuard/OpenVPN |
| — | **Tunnel** (新增) | GRE/IPsec/L2TP 等隧道协议 |
| Mail | Mail | 保留 |
| Dns | Dns | 保留 |
| Database | Database | 保留 |
| RemoteAccess | RemoteAccess | 保留 |
| FileTransfer | FileTransfer | 保留 |
| Voip | Voip | 保留 |
| Infrastructure | Infrastructure | 保留 |
| NetworkManagement | NetworkManagement | 保留 |
| Industrial | Industrial | 保留 |
| Iot | Iot | 保留 |
| Authentication | Authentication | 保留 |
| — | **Streaming** (新增) | RTMP/HLS/MPEG-DASH |
| — | **Cloud** (新增) | AWS/Azure/GCP |
| — | **Messaging** (新增) | WhatsApp/Telegram/Signal/WeChat |
| — | **Social** (新增) | Facebook/Twitter/Instagram |
| — | **Gaming** (新增) | Steam/Xbox/PlayStation |
| — | **Collaboration** (新增) | Zoom/Teams/Webex/Slack |
| — | **FileSharing** (新增) | BitTorrent/eDonkey/Dropbox |
| — | **Routing** (新增) | BGP/OSPF |
| — | **Audio** (新增) | Spotify/MPEG-TS/Streaming 拆细 |
| — | **Video** (新增) | YouTube/Netflix/Streaming 拆细 |
| — | **AdTracking** (新增) | 广告/跟踪 |
| — | **Cybersecurity** (新增) | AV 更新/威胁情报 |

### 与 nDPI 分类映射

每个 rDpi 分类携带 nDPI 分类 ID，便于对接：

```rust
impl ProtocolCategory {
    /// 获取对应的 nDPI 分类 ID
    pub fn ndpi_category_id(&self) -> u32 {
        match self {
            ProtocolCategory::Web => 5,      // NDPI_PROTOCOL_CATEGORY_WEB
            ProtocolCategory::Mail => 3,     // NDPI_PROTOCOL_CATEGORY_MAIL
            // ...
        }
    }
}
```

---

## User Stories

1. 作为网络管理员，我希望每个协议有精确的业务分类，以便基于分类做流量统计
2. 作为安全分析师，我希望 TLS/QUIC 归类为 `WebTunnel`，以便与 VPN 流量区分
3. 作为网络管理员，我希望新增 `Streaming`/`Video`/`Audio` 分类，以便统计流媒体带宽
4. 作为运维人员，我希望新增 `Cloud` 分类，以便监控云服务流量
5. 作为开发者，我希望分类系统提供 `name()` 和 `description()` 方法，便于 UI 展示
6. 作为迁移者，我希望分类能映射到 nDPI 分类 ID，便于工具切换

---

## Implementation Decisions

### 1. 分类枚举（25 个）

```rust
pub enum ProtocolCategory {
    /// 网络层
    Network,
    /// Web/HTTP
    Web,
    /// 加密 Web 隧道 (TLS/QUIC/HTTPS)
    WebTunnel,
    /// VPN
    Vpn,
    /// 通用隧道 (GRE/IPsec)
    Tunnel,
    /// 邮件
    Mail,
    /// DNS
    Dns,
    /// 数据库
    Database,
    /// 远程访问
    RemoteAccess,
    /// 文件传输
    FileTransfer,
    /// VoIP/会议
    Voip,
    /// 基础设施
    Infrastructure,
    /// 网络管理
    NetworkManagement,
    /// 工业/工控
    Industrial,
    /// IoT
    Iot,
    /// 认证协议
    Authentication,
    /// 流媒体视频
    Video,
    /// 流媒体音频
    Audio,
    /// 云服务
    Cloud,
    /// 即时通讯
    Messaging,
    /// 社交网络
    Social,
    /// 在线游戏
    Gaming,
    /// 协同办公
    Collaboration,
    /// 文件共享/P2P
    FileSharing,
    /// 路由协议
    Routing,
    /// 其他
    Other,
}
```

### 2. 协议重新映射

| 协议 | 当前分类 | 新分类 | 理由 |
|------|---------|--------|------|
| HTTP | Web | Web | 保持不变 |
| HTTP/2 | Web | Web | 保持不变 |
| WebSocket | Web | Web | 保持不变 |
| TLS | EncryptedTunnel | WebTunnel | 加密 Web，不是 VPN |
| QUIC | EncryptedTunnel | WebTunnel | 加密 Web |
| HTTP/3 | EncryptedTunnel | WebTunnel | 加密 Web |
| WireGuard | Vpn | Vpn | 保留 |
| OpenVPN | Vpn | Vpn | 保留 |
| BGP | Infrastructure | Routing | 路由协议专类 |
| STUN | Voip | Voip | 保留，WebRTC 底层 |
| SIP | Voip | Voip | 保留 |
| RTP/RTCP | Voip | Voip | 保留 |
| SSH | RemoteAccess | RemoteAccess | 保留 |
| RDP | RemoteAccess | RemoteAccess | 保留 |
| FTP | FileTransfer | FileTransfer | 保留 |
| SMTP | Mail | Mail | 保留 |
| POP3/IMAP | Mail | Mail | 保留 |
| DNS | Dns | Dns | 保留 |
| MySQL/PG/Redis/Mongo | Database | Database | 保留 |
| NTP/DHCP | Infrastructure | Infrastructure | 保留 |
| SNMP | NetworkManagement | NetworkManagement | 保留 |
| Modbus | Industrial | Industrial | 保留 |
| MQTT | Iot | Iot | 保留 |
| Kerberos/LDAP | Authentication | Authentication | 保留 |
| TCP/UDP/ICMP | Network | Network | 保留 |

### 3. nDPI 分类 ID 映射

```rust
impl ProtocolCategory {
    pub fn ndpi_category_id(&self) -> u32 {
        match self {
            ProtocolCategory::Network => 14,
            ProtocolCategory::Web => 5,
            ProtocolCategory::WebTunnel => 5,  // WEB
            ProtocolCategory::Vpn => 2,
            ProtocolCategory::Tunnel => 2,
            ProtocolCategory::Mail => 3,
            ProtocolCategory::Dns => 14,  // NETWORK
            ProtocolCategory::Database => 11,
            ProtocolCategory::RemoteAccess => 12,
            ProtocolCategory::FileTransfer => 7,  // DOWNLOAD_FT
            ProtocolCategory::Voip => 10,
            ProtocolCategory::Infrastructure => 14,
            ProtocolCategory::NetworkManagement => 14,
            ProtocolCategory::Industrial => 31,  // IOT_SCADA
            ProtocolCategory::Iot => 31,
            ProtocolCategory::Authentication => 14,
            ProtocolCategory::Video => 26,
            ProtocolCategory::Audio => 25,
            ProtocolCategory::Cloud => 13,
            ProtocolCategory::Messaging => 9,  // CHAT
            ProtocolCategory::Social => 6,
            ProtocolCategory::Gaming => 8,
            ProtocolCategory::Collaboration => 15,  // COLLABORATIVE
            ProtocolCategory::FileSharing => 29,
            ProtocolCategory::Routing => 14,
            ProtocolCategory::Other => 0,
        }
    }

    pub fn display_name(&self) -> &'static str {
        // "Web Tunnel", "File Sharing", etc.
    }

    pub fn description(&self) -> &'static str {
        // "Encrypted web traffic (TLS, QUIC)"
    }
}
```

### 4. Feature Gates

新增分类不加新 feature gate — 直接编译入 core，不增加条件编译。

### 5. 测试策略

- 每个分类的 category() 映射正确
- display_name()/description() 返回非空
- ndpi_category_id() 映射完整

---

## Out of Scope

- **分类聚合/层次**（父分类 → 子分类）：留待后续
- **用户自定义分类**：上层应用职责
- **分类范围阻**断（block/allow by category）：上层应用职责
- **动态分类规则**：非核心

---

## Implementation Plan

1. 扩展 ProtocolCategory 枚举（+12 新增）
2. 重写 category() 映射
3. 添加 display_name() / description() / ndpi_category_id()
4. 全量测试验证
5. 更新 DetectionResult 的 category 集成

---

## Risks

- **Breaking change**: 现有代码中所有 `match protocol.category()` 都需要更新。但 category() 返回值是 ProtocolCategory 枚举，新增变体会导致现有 match 编译失败（这是 Rust 优势 — 编译器会捕获所有遗漏的分支）
