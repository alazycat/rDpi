# rDpi

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Rust Deep Packet Inspection library - 轻量级、高性能的深度包检测库。

输入以太网帧字节，输出协议识别（49 个协议 detector）、元数据（SNI/Host/证书等）、五元组流统计，可选风险标记（`risk` feature）。

## 特性

- **传输层解析**: TCP/UDP/ICMP 协议识别
- **协议检测**: DNS、HTTP、TLS、QUIC、SSH、SMTP、POP3/IMAP、NTP/DHCP、SNMP、Modbus、MySQL/PostgreSQL/Redis、FTP/SIP/RTP、MQTT、WireGuard/OpenVPN、STUN 等 49 个 detector（见下表）
- **元数据提取**: DNS 域名、HTTP 方法/路径/Host、TLS SNI/版本/证书、QUIC 版本/连接 ID/SNI/ALPN/JA4/Transport Parameters、SSH 版本等
- **应用识别**: TLS SNI → 应用归属（反向 Trie 域名匹配）
- **流管理**: 五元组追踪、超时清理、容量上限（满载先清超时流，再按最久未活跃逐出）
- **猜测引擎**（DPI 失败后回退）: 域名 → IP 子网 → 端口 三级匹配，可配置——`GuessEngine::builder()` 开关内置表、注入自定义域名/IP 子网/端口映射（`Detector::set_guess_engine`）
- **风险分析**（`risk` feature）: TLS/DNS/HTTP/行为/证书/QUIC 风险处理器（0-RTT 观测、非标准 draft 版本、Retry 完整性校验 RFC 9001 §5.8）
- **规则引擎**（`rule` feature）: 自定义匹配规则，支持 JSON 加载
- **零拷贝设计，最小化分配**

## 安装

```toml
[dependencies]
rdpi = "0.4.2"
```

## 使用示例

```rust
use rdpi::Detector;

fn main() -> rdpi::error::Result<()> {
    let mut detector = Detector::new();

    // 检测 HTTP 流量
    let http_packet = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    if let Some(result) = detector.detect(http_packet)? {
        println!("Protocol: {:?}", result.protocol);
        if let rdpi::Metadata::Http(meta) = result.metadata {
            println!("Host: {:?}", meta.host);
            println!("Method: {:?}", meta.method);
        }
    }

    Ok(())
}
```

## Feature Gates

| Feature | 默认 | 描述 |
|---------|------|------|
| `dns` | ✅ | DNS 协议检测，提取查询域名 |
| `http` | ✅ | HTTP 协议检测，提取方法、路径、Host |
| `tls` | ✅ | TLS 协议检测，提取 SNI、版本、证书 |
| `ssh` | ❌ | SSH 协议检测，提取协议和软件版本 |
| `smtp` | ❌ | SMTP 协议检测，提取主机名 |
| `quic` | ❌ | QUIC 协议检测：长包头全类型识别（Initial/0-RTT/Handshake/Retry/VN）+ Initial 包解密提取 SNI/ALPN/JA4 + Retry 完整性校验（手写 AES-GCM/HKDF，零新增依赖） |
| `mail` | ❌ | POP3/POP3S/IMAP/IMAPS 协议检测 |
| `infra` | ❌ | NTP/DHCP/BGP/NetFlow/IKE/PTPv2/DHCPv6/VXLAN |
| `snmp` | ❌ | SNMP v1/v2c 检测，完整 PDU 解析 |
| `modbus` | ❌ | Modbus TCP 检测，功能码解析 |
| `database` | ❌ | MongoDB/MySQL/PostgreSQL/Redis 检测 |
| `proto3` | ❌ | FTP/SIP/RTP/HTTP2/WebSocket/RTMP/SOCKS（HTTP2 经 HPACK 提取 `:authority`/`:method`/`:path`） |
| `iot` | ❌ | MQTT 协议检测 |
| `vpn` | ❌ | WireGuard/OpenVPN/L2TP/PPTP 协议检测 |
| `voip` | ❌ | STUN/TURN/MGCP/H.323 协议检测 |
| `auth` | ❌ | Kerberos/LDAP/RADIUS 协议检测 |
| `remote` | ❌ | RDP 协议检测 |
| `storage` | ❌ | NFS 协议检测 |
| `misc` | ❌ | TFTP/RSYNC/Whois/Syslog/Telnet/VNC 协议检测 |
| `pcap` | ❌ | pcap 文件读取 CLI |
| `rule` | ❌ | 自定义规则引擎（JSON 规则加载） |
| `risk` | ❌ | 风险分析引擎（TLS/DNS/HTTP/行为/证书风险） |

禁用默认 features:

```toml
[dependencies]
rdpi = { version = "0.4.2", default-features = false, features = ["http", "tls", "ssh"] }
```

## 支持的协议

| 协议 | Feature | 元数据 |
|------|---------|--------|
| DNS | `dns` | 查询域名 |
| HTTP | `http` | 方法、路径、Host 头 |
| TLS | `tls` | SNI、TLS 版本、应用、证书 |
| SSH | `ssh` | 协议版本、软件版本 |
| SMTP | `smtp` | 主机名、客户端标识 |
| QUIC | `quic` | 版本、连接 ID、SNI、ALPN、JA4、应用、Transport Parameters |
| POP3/POP3S、IMAP/IMAPS | `mail` | - |
| NTP、DHCP、BGP、NetFlow、IKE、PTPv2、DHCPv6、VXLAN | `infra` | NTP 版本/模式、DHCP Opcode/MAC 等 |
| SNMP | `snmp` | 版本、Community、PDU、VarBinds |
| Modbus | `modbus` | 事务 ID、功能码 |
| MongoDB、MySQL、PostgreSQL、Redis | `database` | 服务端版本、认证插件、用户/库名等 |
| HTTP/2 | `proto3` | `:authority`、方法、路径（首个请求 HEADERS 帧，HPACK 解码） |
| FTP、SIP、RTP/RTCP、WebSocket、RTMP、SOCKS | `proto3` | SIP 方法、RTP 编码等 |
| MQTT | `iot` | 消息类型、QoS |
| WireGuard、OpenVPN、L2TP、PPTP | `vpn` | WireGuard 握手参数等 |
| STUN、TURN、MGCP、H.323 | `voip` | STUN 消息类型等 |
| Kerberos、LDAP、RADIUS | `auth` | Kerberos 域/用户等 |
| RDP | `remote` | - |
| NFS | `storage` | - |
| TFTP、RSYNC、Whois、Syslog、Telnet、VNC | `misc` | Syslog 设备/级别等 |

## 性能

- 单核吞吐量: 500 Mbps - 1 Gbps (完整功能)
- 内存: 每万并发流约 10-20 MB
- 零拷贝设计，最小化分配
- 流表容量上限（默认 10000），满载时自动逐出超时/最久未活跃的流

## 开发状态

### 已完成（截至 v0.4.2）

- [x] Phase 1-3: 核心基础设施 + DNS/HTTP/TLS/SSH/SMTP 检测
- [x] Phase 4: QUIC 协议检测
- [x] Phase 5: 基于 SNI 的应用识别（反向 Trie 域名匹配）
- [x] Phase 5.1/5.2: POP3/IMAP/NTP/DHCP/SNMP/Modbus + MySQL/PostgreSQL/Redis
- [x] Phase 8: MQTT、MongoDB、WireGuard、HTTP/2、WebSocket、STUN/OpenVPN/RDP/Kerberos/LDAP/BGP
- [x] Phase 10: 风险分析引擎（TLS/DNS/HTTP/行为风险处理器）
- [x] Phase 11A/12A: 扩展至 49 个协议 detector（TFTP/RSYNC/Whois/Syslog/RTMP/SOCKS/NetFlow/IKE/PTPv2/NFS、DHCPv6/Telnet/VNC/L2TP/PPTP/VXLAN/RADIUS/TURN/MGCP/H.323 等）
- [x] Phase 12B: TLS 证书解析 + 证书风险处理器（自签名/过期/有效期过长/ALPN-SNI 不一致）
- [x] Phase 13: QUIC Initial 解密补全（SNI/ALPN/JA4 + 风险信号 + 长包头全类型识别，RFC 9001 官方向量验证）
- [x] 库打包、规则引擎（`rule`）、pcap CLI（`pcap`）

### 规划中

- 持续扩展协议覆盖与元数据深度（完整 API 见 `cargo doc`）

## 技术栈

- **语言**: Rust 2024 Edition
- **协议解析**: 手写以太网/IP/TCP/UDP 解析器与各协议 detector（无解析库依赖）
- **错误处理**: thiserror
- **序列化**（可选）: serde / serde_json（`rule`、`risk` feature）
- **CLI**（可选）: clap + pcap-file（`pcap` feature）

## 许可证

MIT License
