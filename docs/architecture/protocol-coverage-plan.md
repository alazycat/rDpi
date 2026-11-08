# rDpi 协议/应用覆盖候选清单

> 生成时间：2026-11-06
> 目标：类比 nDPI，纯 Rust 实现；用于确定首批 Top-N 协议/应用
> 数据来源：
> - rDpi：`src/protocols/mod.rs`、`src/core/types.rs`
> - nDPI 5.0：`src/lib/protocols/*.c`（258 个解析器）、`src/include/ndpi_protocol_ids.h`（468 个协议/应用 ID）、`doc/protocols.rst`
> 说明：nDPI 的“应用协议”很多不是独立 `.c` 文件，而是通过 host/SNI 匹配表识别；因此 `.c` 数量（258）小于协议/应用 ID 数量（468）。

---

## 1. rDpi 现有覆盖（50 个 detector）

| 类别 | 协议 | 数量 |
|---|---|---:|
| Web / 加密隧道 | HTTP、HTTP/2、WebSocket、TLS、QUIC、DTLS、RTMP、SOCKS | 8 |
| DNS | DNS | 1 |
| 邮件 | SMTP、POP3、IMAP | 3 |
| 远程访问 | SSH、RDP、Telnet、VNC | 4 |
| 文件传输 | FTP、TFTP、Rsync、NFS、Whois | 5 |
| 数据库 | MySQL、PostgreSQL、Redis、MongoDB | 4 |
| 基础设施 | NTP、DHCP、DHCPv6、BGP、VXLAN、NetFlow、IKE、PTPv2 | 8 |
| 网络管理 | SNMP、Syslog | 2 |
| 工业 | Modbus | 1 |
| IoT | MQTT | 1 |
| VoIP | SIP、RTP（含 RTCP）、STUN、TURN、MGCP、H.323 | 6 |
| 认证 | Kerberos、LDAP、RADIUS | 3 |
| VPN / 隧道 | WireGuard、OpenVPN、L2TP、PPTP | 4 |
| **合计** |  | **50** |

补充：
- HTTP/3 由 QUIC 检测路径覆盖，没有独立 detector。
- RTCP 由 RTP detector 覆盖，`Protocol` 枚举中有独立变体。

---

## 2. rDpi 现有应用识别（46 个 `Application`）

| 类别 | 应用 |
|---|---|
| 流媒体（17） | YouTube、Netflix、Bilibili、Douyin、iQiyi、TencentVideo、Youku、Hulu、DisneyPlus、AmazonPrime、HBO、DAZN、Vimeo、Dailymotion、Spotify、AppleTVPlus、ParamountPlus |
| IM（8） | WeChat、Telegram、WhatsApp、Discord、QQ、Slack、Line、Signal |
| 通讯协作（5） | Zoom、Twitch、Teams、Webex、Skype |
| 社交（8） | Instagram、Snapchat、Facebook、Messenger、Twitter、LinkedIn、Pinterest、Reddit |
| 云服务（8） | Google、Microsoft、AmazonAWS、Azure、GitHub、GitLab、Dropbox、Box |
| **合计** | **46** |

识别方式：TLS SNI / DNS 域名 → 反向 Trie → `Application`；域名表 `src/application/mappings.rs` 约 477 条，编译期固定。

---

## 3. nDPI 覆盖地图（468 个协议/应用 ID）

> 下表为代表性协议，不是全量；全量见 `src/include/ndpi_protocol_ids.h` 与 `doc/protocols.rst`。

| 类别 | nDPI 代表性协议/应用 | rDpi 差距 |
|---|---|---|
| Web / 云 / CDN | HTTP、HTTP2、TLS、QUIC、WebSocket、DoH/DoT/DoQ、HTTP CONNECT、HTTP Proxy、SOAP、JSON-RPC、WebDAV、AWS（Cognito/API Gateway/Kinesis/EC2/EMR/S3/CloudFront/DynamoDB）、Azure、Google Cloud、阿里云、Cloudflare、Akamai、DigitalOcean、Salesforce、GitHub、GitLab | SOAP/JSON-RPC/WebDAV、AWS 细分、Akamai 等缺失（DoH/DoT/DoQ、HTTP CONNECT/Proxy 已于 F44 补齐） |
| 邮件 | SMTP/SMTPS、POP/POPS、IMAP/IMAPS、Outlook、Gmail、Yandex Mail | 基本覆盖，缺应用级细分 |
| DNS / 基础设施 | DNS、mDNS、DoH/DoT、DNSCrypt、NTP、DHCP、DHCPv6、SNMP、Syslog、NetFlow、sFlow、BGP、OSPF、LDP、BFD、VRRP、HSRP、GLBP、PTPv2、LLMNR、SSDP、WSD、NetBIOS、NAT-PMP | DNSCrypt、OSPF/LDP/BFD/VRRP/HSRP/GLBP、LLMNR/SSDP/WSD 缺失（DoH/DoT 已于 F44 补齐、NetBIOS 已于 F45 补齐） |
| 远程访问 | SSH、RDP、VNC、Telnet、TeamViewer、AnyDesk、Citrix、GoTo、NoMachine、Radmin、RSH、XDMCP | TeamViewer/AnyDesk/Citrix/GoTo/NoMachine 等缺失 |
| 文件 / 存储 | FTP Control/Data、FTPS、TFTP、SMBv1/v2/v3、NFS、AFP、Rsync、Dropbox、Google Drive、OneDrive、iCloud、Ceph、Lustre、Syncthing | AFP、Google Drive/OneDrive/iCloud、Ceph/Lustre/Syncthing 缺失（SMB 已于 F45 补齐） |
| 数据库 / 数据 | MySQL、PostgreSQL、MSSQL_TDS、Oracle、RESP（Redis）、MongoDB、Cassandra、Memcached、Elasticsearch、ClickHouse、DRDA | ClickHouse、DRDA 缺失（MSSQL/Cassandra 已于 F49/F50 补齐） |
| 消息 / 数据管道 | Kafka、AMQP、MQTT、NATS、STOMP、OpenWire、ZeroMQ、Gearman、Thrift、Protobuf、JSON-RPC、SOAP | 除 MQTT 外基本缺失 |
| VoIP / 流媒体 | SIP、RTP、RTCP、SRTP、RTSP、H.323、MGCP、Megaco、Skinny、IAX、STUN、Icecast、MPEGTS、MPEGDASH、HLS、RTMP、RTPS、BFCP | RTSP、SRTP、MPEGTS/MPEGDASH/HLS、RTPS、BFCP、Megaco/Skinny/IAX 缺失 |
| IM / 社交 | Facebook、Messenger、Instagram、WhatsApp（含 Call/Files）、Telegram（含 VOIP）、Signal（含 VOIP）、Discord、Slack、Teams（含 Call）、WeChat、QQ、OICQ、TikTok、Snapchat（含 Call）、Twitter、Threads、Mastodon、Bluesky、LinkedIn、Reddit、Pinterest、Tumblr、Viber、Line、KakaoTalk、DingTalk、Threema、IMO、Sina Weibo、VK、Yandex | rDpi 有部分 SNI 映射，但缺协议级识别与大量应用 |
| 游戏 | Steam、Valve SDR、EpicGames、RiotGames、Blizzard、ElectronicArts、Xbox、PlayStation、Nintendo、Roblox、Genshin Impact、Among Us、Crossfire、Dofus、Guild Wars 2、World of Warcraft、Heroes of the Storm、Dota2、Path of Exile、TESO、LOL Wild Rift、Tencent Games、NetEase Games、Gaijin | 基本缺失 |
| 工业 / IoT | Modbus、S7comm、S7comm+、OPC-UA、BACnet、DNP3、IEC60870、IEC62056、HART-IP、Profinet IO、EtherNet/IP、CIP、MELSEC、FINS、C1222、KNXnet/IP、SOME/IP、TRDP、ISO9506-1-MMS、DICOM、HL7、Matter、TUYA、TP-Link SHP | 除 Modbus 外基本缺失 |
| VPN / 隧道 | WireGuard、OpenVPN、IPsec（AH/ESP）、IKE、L2TP、PPTP、GRE、VXLAN、GTP/GTP-U/GTP-C/GTP'、Teredo、SoftEther、Tailscale、Cloudflare WARP、ProtonVPN、NordVPN、Surfshark、Windscribe、Hotspot Shield、Psiphon、UltraSurf、Tor、Opera VPN、Mullvad、PIA、TunnelBear | IPsec、GRE、GTP 系列、Teredo、SoftEther/Tailscale、商业 VPN 识别缺失 |
| P2P / 挖矿 / 其他 | BitTorrent、eDonkey、Gnutella、Usenet、Ethereum、Monero、Bitcoin、Mining、Avast、Avast SecureDNS、CyberSecurity | 基本缺失 |

---

## 4. rDpi 缺失的高价值协议（建议优先）

### P0：通用/企业高频

| 协议 | 类别 | 价值 | 实现难度 |
|---|---|---|---|
| DoH / DoT / DoQ | DNS / Web | 加密 DNS 识别，现代网络必备 | 中 |（✅ F44 完成）
| HTTP CONNECT / HTTP Proxy | Web | 代理/隧道识别 | 低 |（✅ F44 完成）
| SMBv1 / SMBv2 / SMBv3 | 文件 | 企业内网最大流量之一 | 中 |（✅ F45 完成，2026-11-07）
| NetBIOS | 基础设施 | Windows 内网发现 | 低 |（✅ F45 完成，2026-11-07）
| MSSQL / TDS | 数据库 | 企业数据库 | 中 |（✅ F49 完成，2026-11-08）
| Oracle | 数据库 | 企业数据库 | 中 |（✅ F50 完成，2026-11-08）
| Cassandra | 数据库 | 分布式数据库 | 中 |（✅ F50 完成，2026-11-08）
| Memcached | 数据库/缓存 | 缓存服务 | 低 |
| Elasticsearch | 数据库/搜索 | 企业搜索 | 低 |
| Kafka | 消息 | 数据管道 | 中 |（✅ F49 完成，2026-11-08）
| AMQP | 消息 | 企业消息队列 | 低 |
| HLS / MPEG-DASH / MPEG-TS | 流媒体 | 视频流识别 | 中 |
| RTSP | 流媒体 | 摄像头/流媒体 | 低 |
| SRTP / RTPS | VoIP | 加密 RTP/工业实时 | 中 |
| TeamViewer / AnyDesk / Citrix / GoTo | 远程访问 | 企业远程办公 | 低–中 |
| GTP / GTP-U / GTP-C / GTP' | 隧道 | 移动核心网 | 中 |
| IPsec ESP / AH | VPN | 企业 VPN | 中 |
| GRE | 隧道 | 通用隧道 | 低 |
| Tor | 匿名网络 | 风控/合规 | 中 |

### P1：垂直/行业

| 协议 | 类别 | 价值 | 实现难度 |
|---|---|---|---|
| OPC-UA | 工业 | 工控主流 | 中 |
| S7comm / S7comm+ | 工业 | 西门子 PLC | 中 |
| BACnet | 工业/楼宇 | 楼宇自动化 | 低 |
| DNP3 | 工业/电力 | 电力 SCADA | 低 |
| IEC 60870-5-104 | 工业/电力 | 电力 SCADA | 低 |
| HART-IP | 工业 | 过程自动化 | 低 |
| Profinet IO | 工业 | 西门子工业以太网 | 中 |
| EtherNet/IP / CIP | 工业 | 罗克韦尔 | 中 |
| MELSEC | 工业 | 三菱 PLC | 中 |
| FINS | 工业 | 欧姆龙 PLC | 中 |
| C1222 | 工业/电力 | 电表 | 低 |
| KNXnet/IP | 工业/楼宇 | 楼宇自动化 | 低 |
| SOME/IP | 工业/汽车 | 车载以太网 | 中 |
| TRDP | 工业/轨交 | 列车通信 | 中 |
| ISO9506-1-MMS | 工业 | IEC 61850 | 中 |
| DICOM | 医疗 | 医学影像 | 中 |
| HL7 | 医疗 | 医疗信息 | 低 |
| Matter | IoT | 智能家居 | 中 |
| CoAP | IoT | 低功耗 IoT | 低 |
| AFP | 文件 | macOS 文件共享 | 低 |
| Ceph / Lustre | 存储 | 分布式存储 | 中 |
| Syncthing | 文件 | P2P 同步 | 低 |
| ClickHouse | 数据库 | OLAP | 低 |
| NATS / STOMP / OpenWire / ZeroMQ / Thrift / Protobuf | 消息/序列化 | 数据管道 | 低–中 |

### P2：长尾/低优先级

- P2P：BitTorrent、eDonkey、Gnutella、Usenet
- 挖矿：Ethereum、Monero、Bitcoin、Mining
- 安全软件：Avast、Avast SecureDNS、CyberSecurity
- 游戏/长尾应用：Steam、Epic、Riot、Blizzard、EA、Xbox、PlayStation、Nintendo、Roblox 等（若目标环境不是游戏场景）

---

## 5. 应用识别候选

### 5.1 rDpi 已有的 46 个应用

见第 2 节。

### 5.2 nDPI 有、rDpi 没有的常见应用（示例）

| 类别 | 应用 |
|---|---|
| 流媒体 | TikTok、Amazon Video、Apple TV+（已有）、Paramount+（已有）、Peacock、Roku、Kick、Rumble、ESPN、DirecTV、Showtime、Vudu、Zattoo、Ifix、SoundCloud、Deezer、Tidal、iHeartRadio、TuneIn、SiriusXM、Last.fm |
| IM / 社交 | Google Chat、Google Meet、Google Call、Microsoft 365、Outlook、OneDrive、iCloud、iCloud Private Relay、Line Call、KakaoTalk、KakaoTalk Voice、Viber VOIP、Telegram VOIP、Signal VOIP、WhatsApp Call/Files、Facebook VOIP/Reel/Story、Snapchat Call、Threads、Mastodon、Bluesky、Tumblr、Sina Weibo、VK、Yandex、DingTalk、Threema、IMO、Likee |
| 云 / 企业 | Google Services、Google Maps、Gmail、Google Drive、Google Docs、Google Cloud、Google Classroom、Google Play Store、Microsoft Azure、Microsoft 365、OneDrive、AWS 细分（Cognito/API Gateway/Kinesis/EC2/EMR/S3/CloudFront/DynamoDB）、阿里云、腾讯云、华为云、Salesforce、SAP、DigitalOcean、Cloudflare、Akamai |
| 游戏 | Steam、Valve SDR、EpicGames、RiotGames、Blizzard、ElectronicArts、Xbox、PlayStation、Nintendo、Roblox、Genshin Impact、Among Us、Crossfire、Dofus、Guild Wars 2、World of Warcraft、Heroes of the Storm、Dota2、Path of Exile、TESO、LOL Wild Rift、Tencent Games、NetEase Games、Gaijin |
| 远程 / VPN | TeamViewer、AnyDesk、Citrix、GoTo、NoMachine、Radmin、ProtonVPN、NordVPN、Surfshark、Windscribe、Hotspot Shield、Psiphon、UltraSurf、Opera VPN、Mullvad、PIA、TunnelBear、Tailscale、Cloudflare WARP |
| 文件 / 存储 | Dropbox（已有）、Google Drive、OneDrive、iCloud、Box（已有）、Syncthing、Ceph、Lustre |

---

## 6. 推荐的 Top-N 组合

### A. Web / Cloud 核心（已确认首批）

**协议**：TLS、HTTP/1.x、HTTP/2、HTTP/3/QUIC、DNS、DoH/DoT/DoQ、WebSocket、HTTP CONNECT/Proxy

**应用**：Google/YouTube、Facebook/Instagram/WhatsApp、Microsoft 365/Outlook、Teams、Apple/iCloud、Amazon/AWS、Netflix、Cloudflare、Akamai、GitHub/GitLab、Zoom、TikTok、Telegram、Discord、Twitter/X、Reddit、LinkedIn、Spotify、WeChat

### B. 企业协议（已确认首批）

**协议**：SMBv1/v2/v3、NetBIOS、LDAP、Kerberos、RDP、SSH、NFS、AFP、MSSQL、Oracle、PostgreSQL、MySQL、Redis/RESP、MongoDB、Cassandra、Memcached、Elasticsearch、Kafka、AMQP、MQTT、NATS、STOMP、OpenWire

**应用**：Microsoft 365、Outlook/Exchange、Teams、Salesforce、SAP、Webex、Zoom、AnyDesk、TeamViewer、Citrix、GoTo

### C. 流媒体 / IM / 游戏（建议第二优先）

**协议**：RTP/RTCP/SRTP、RTSP、SIP、HLS、MPEG-DASH、MPEG-TS、RTMP、WebRTC（STUN/TURN）、RTPS

**应用**：YouTube、Netflix、Twitch、Disney+、HBO、Amazon Prime Video、Apple TV+、Hulu、DAZN、Spotify、TikTok、Instagram、Facebook、WhatsApp、Telegram、Discord、WeChat、QQ、Zoom、Teams、Google Meet、Steam、Epic Games、Riot Games、Blizzard、Xbox、PlayStation、Nintendo、Roblox

### D. 工业 / IoT（垂直场景，按需）

**协议**：Modbus、S7comm/S7comm+、OPC-UA、BACnet、DNP3、IEC 60870-5-104、HART-IP、Profinet IO、EtherNet/IP、CIP、MELSEC、FINS、C1222、KNXnet/IP、SOME/IP、TRDP、MMS、DICOM、HL7、Matter、CoAP、MQTT

### E. VPN / 隧道（按需）

**协议**：WireGuard、OpenVPN、IPsec/IKE、L2TP、PPTP、GRE、VXLAN、GTP/GTP-U/GTP-C/GTP'、Teredo、SoftEther、Tailscale、Cloudflare WARP、Tor、SOCKS

**应用**：ProtonVPN、NordVPN、Surfshark、Windscribe、Hotspot Shield、Psiphon、UltraSurf、Opera VPN、Mullvad、PIA、TunnelBear

---

## 7. 建议的首批默认组合

已确认首批为 **A + B**；C（流媒体/IM/游戏）与 D/E（工业、VPN）后续按目标环境排期。

### 首批 Top 20 协议（默认）

1. TLS
2. HTTP/1.x
3. HTTP/2
4. HTTP/3 / QUIC
5. DNS
6. DoH / DoT / DoQ
7. WebSocket
8. SSH
9. SMTP
10. IMAP
11. POP3
12. FTP
13. ~~SMBv2/v3~~（✅ F45 完成，含 SMBv1 风险旗标）
14. ~~NetBIOS~~（✅ F45 完成）
15. LDAP
16. Kerberos
17. RDP
18. NTP
19. DHCP
20. SNMP

### 首批 Top 20 应用（默认）

1. Google / YouTube
2. Facebook / Instagram
3. WhatsApp
4. Microsoft 365 / Outlook
5. Microsoft Teams
6. Apple / iCloud
7. Amazon / AWS
8. Netflix
9. Cloudflare
10. Akamai
11. GitHub / GitLab
12. Zoom
13. TikTok
14. Telegram
15. Discord
16. WeChat
17. Spotify
18. Twitter / X
19. Reddit
20. Steam

---

## 8. 优先级方法

建议用下面的公式排序，而不是按 nDPI 的协议编号或文件顺序：

```text
优先级 = (目标流量占比 × 业务价值 × 差距程度) / 实现成本
```

每项 1–5 分，用目标环境的 pcap 语料估算“流量占比”，用业务/合规需求估算“业务价值”，用代码/数据/测试工作量估算“实现成本”。

示例：

| 协议/应用 | 流量占比 | 业务价值 | 差距 | 成本 | 优先级 |
|---|---:|---:|---:|---:|---|
| TLS / HTTP / DNS | 5 | 5 | 2 | 1 | 高 |
| SMB / NetBIOS | 4 | 5 | 5 | 3 | 高 |
| DoH / DoT | 3 | 5 | 5 | 3 | 高 |
| S7comm / OPC-UA | 1 | 5（工业场景） | 5 | 3 | 中 |
| BitTorrent / 挖矿 | 1 | 2 | 5 | 2 | 低 |

---

## 9. 下一步

1. 首批范围已确认：**A（Web/Cloud 核心）+ B（企业协议）**。
2. 按第 10 节顺序推进：先做 P1 分类核心，再补协议/数据。
3. 为选中的协议建立状态机模板与 pcap 测试样本。
4. 将实施进度写回 `docs/architecture/ndpi-pure-rust-plan.md` 的路线图。

---

## 10. 首批 A+B 实施顺序（已确认）

### 10.1 阶段 1：分类核心 + 现有协议迁移（P1）

- 双向流、公开 `Flow`、逐包状态机、protocol stack。
- 迁移 A/B 已有协议：TLS、HTTP/1.x、HTTP/2、QUIC/HTTP3、DNS、WebSocket、LDAP、Kerberos、RDP、SSH、NFS、PostgreSQL、MySQL、Redis/RESP、MongoDB、MQTT。
- 新增 A 组缺口：DoH/DoT/DoQ、HTTP CONNECT/Proxy。
- 验收：A+B 已有协议 flow 级一致率 ≥ 95%。

### 10.2 阶段 2：企业协议补齐（P2 Wave 1B）

- SMBv1/v2/v3、NetBIOS（✅ F45 完成）、Memcached（✅ F46 完成）、Elasticsearch（✅ F46 完成）、AMQP（✅ F46 完成）、MSSQL/TDS（✅ F49 完成）、Kafka（✅ F49 完成）、Oracle（✅ F50 完成）、Cassandra（✅ F50 完成）、AFP、NATS、STOMP、OpenWire。
- 验收：每个协议有正/负样本；Top-20 协议 precision/recall ≥ 0.95。

### 10.3 阶段 3：应用数据管线（P2 Wave 1C）

- host/SNI/IP/ASN 数据、PSL、DNS cache、运行期加载、自定义 category/protocol。
- 补齐 A/B 应用：Microsoft 365、Outlook/Exchange、Salesforce、SAP、AnyDesk、TeamViewer、Citrix、GoTo。
- 验收：Top-20 应用准确率 ≥ 0.9。

### 10.4 阶段 4：差分与性能（P0/P5）

- `tests/parity/` 差分脚本、20–50 个 pcap 基线。
- 同机性能基线（nDPI ndpiReader vs rDpi CLI）。
- 验收：A+B 语料 diff 可解释；性能达到既定目标。
