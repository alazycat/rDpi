# AGENTS.md — rDpi 项目认知库（供人与 AI 共享）

> 生成时间：2026-11-04，基于 commit `34cc561`（v0.4.1）的 legacy-takeover 体检产出。
> 事实均有源码出处（文件:行号），代码变更后须同步更新对应章节。腐化的知识库比没有更危险。

## 1. 项目背景

`rdpi`：Rust 深度包检测（DPI）库 + CLI。输入以太网帧字节，输出协议识别（约 49 个协议模块）、元数据（SNI/Host/JA4/JA4S/证书等）、五元组流统计、风险标记（feature=risk）。

- 主入口：`Detector::detect()`（[src/lib.rs:221](file:///d:/rust_code/rDpi/src/lib.rs#L221)）
- CLI：`cargo run --features pcap -- -i file.pcap`（[src/bin/rdpi.rs](file:///d:/rust_code/rDpi/src/bin/rdpi.rs)）
- 开发按 Phase 推进（git log），Phase 12B（TLS 证书 + 证书风险）已完成；README 的开发状态章节**已过期**（risks.md R3）。

## 2. 架构速览

```text
lib.rs (Detector 编排) → parser (以太网/IP/TCP/UDP) → core (FlowTable/guess/types)
                       → protocols (Registry, 顺序遍历首个命中即返回 protocols/mod.rs:134-141)
                       → application (SNI→应用, 反向 Trie) / asn1 (BER/OID)
                       → rule (feature, DPI 之前) / risk (feature, DPI 之后)
```

关键机制（改代码前必读）：
- **Registry 顺序即优先级**：`register_defaults` 按特异性递减注册（protocols/mod.rs:174-276）；新增 detector 的插入位置决定误判面（risks.md R11）。
- **Giveup 机制**：TCP 20 包 / UDP 5 包未识别 → GuessEngine（域名→IP→端口回退，lib.rs:80-82, 288-315）。
- **流表容量**：max_entries 生效（flow.rs:127-155，R2 修复）——满载先清超时流，再按最久未活跃逐出；命中即 touch last_time；0 = 不设上限。
- **流协议只写一次**：识别后不再重检协议（lib.rs:316-328）；回显结果携带已保存元数据（F7 修复，2026-11-04），且已定型 TLS 流在后续 Certificate 记录上做一次性证书富化（F3 修复，lib.rs enrich_tls_cert——协议不重检，ADR-0004）。
- **JA4S 服务端指纹（F30，2026-11-05）**：TLS detector 识别 ServerHello 记录（`parse_server_hello`，tls/parser.rs）→ 纯 ServerHello 的服务端流自此可定型为 Tls（此前服务端流靠 cert 或 guess 回退）；JA4S 格式对齐 FoxIO 官方 ja4.py to_ja4s（`application::compute_ja4s`，application/ja4.rs：扩展不排序/不过滤 GREASE、服务端选定 cipher 明文 4hex、hash 输入 0x%04x 逗号串）；QUIC 走服务端 Initial 解密产出 q 前缀 JA4S（quic/parser.rs decrypt_server_hello_meta）；TCP 回显路径一次性富化（lib.rs enrich_tls_ja4s，对齐 ADR-0004）。
- **JA4H 客户端 HTTP 指纹（F31，2026-11-05）**：`application::compute_ja4h`（官方 ja4h.py to_ja4h 语义：头序敏感+原始大小写、cookie/referer 仅作 c/r 标志、cookie 字段/值按名排序哈希、语言 4 位右补 0、header_len 与 lang 间无分隔符）；`http::parse_header_lines` 提供头行输入；仅 HTTP/1.x 请求路径产出（响应与 h2 为 None）。
- **JA4X X.509 证书指纹（F32，2026-11-05）**：`application::compute_ja4x`（官方 rust/ja4x hash12 语义：`{issuer12}_{subject12}_{扩展12}`，OID DER 内容字节 hex 逗号拼接哈希、不排序，空列表记 12 个 0）；`tls/certificate.rs` `extract_dn` 返回 OID 列表 + `extract_extension_oids`（`[3] EXPLICIT` 双层解封装）；CertInfo.ja4x 解析期一次算好，经 tls detector 识别路径与 enrich_tls_cert 富化路径双接入，`TlsMetadata.cert_ja4x`。
- **JA4T 客户端 TCP 指纹（F33，2026-11-05）**：`application::compute_ja4t`（官方 rust/ja4 tcp.rs `to_ja4t` 语义：`{window}_{options}_{mss}_{wscale}`，选项 kind 序列含 NOP/EOL 终止、空记 "00"、mss 最少两位、wscale=0 记 "00"）；`parser::tcp::TcpHeaderInfo` 固定容量栈结构零堆分配提取 flags/window/选项 kind/MSS/wscale（ParsedPacket.tcp）；detect 主流程初始 SYN（SYN 置位且 ACK 清零）每流一次写入 `Flow.ja4t` 流级旁路字段——**不占用 protocol/metadata 一次定型语义**；DetectionResult.ja4t 随回显/规则分支携带。
- **JA4TS 服务端 TCP 指纹（F34，2026-11-06）**：`application::compute_ja4ts`（格式与 JA4T 完全一致，规格权威为官方 zeek/ja4t/main.zeek——rust/ja4 未实现）；detect 主流程 SYN-ACK（flags **精确等于** 0x12，带额外标志位不触发）每流一次写入服务端方向流 `Flow.ja4ts` 旁路字段（FlowKey 方向性：与客户端 SYN 属两条流，互不干扰）；DetectionResult.ja4ts 随回显/规则分支携带。
- **JA4L TLS 精化段 delta（F42，2026-11-06）**：兑现 F35 边界②，官方 zeek ja4l/main.zeek TLS delta 语义（仅 TCP，QUIC/DTLS 无 delta）——D（ClientHello）/E（ServerHello）/F（E 后首个**有载荷**客户端包，纯 ACK 不触发，zeek `dl==0` 等待数据语义）三时点每流一次，信号取自检测结果元数据精确推断（`ja4` Some ⇔ 含 ClientHello、`ja4s` Some ⇔ 含 ServerHello——TLS detector 逐记录解析产物，识别包与回显包同义）；E 首记时 `(E-D)/2` µs 追加至本流 ja4ls 第三段、F 首记时 `(F-E)/2` 追加至 ja4lc（成 `{半程}_{TTL}_{delta}` 三段，微秒整除 2 与基指纹同源）；方向判定借 F35 握手时戳放宽（本流 syn_time / 对端 synack_time = 客户端、本流 synack_time / 对端 syn_time = 服务端——从 SYN-ACK 起抓包仍可判向，但基指纹缺 A 仍不产出）；调用点在 detect 主流程 DPI 之后（flow 借用终结后独立借流表）；zeek `ja4l_delta`/`ja4ls_delta` 比值字段不实现（需 ack_time 新字段，登记 risks.md F42）；Flow 新增 `tls_client_hello_time/tls_server_hello_time/tls_first_client_data_time` 旁路字段。
- **SMTP/IMAP/POP3 有状态会话 + WebSocket 升级握手（F43，2026-11-06）**：推广既有 `process()` + `DissectorState` 框架（SSH/HTTP/DNS-TCP/TLS/HTTP2 先例）至邮件三协议与 WebSocket——邮件协议为**服务端先发 banner**，接管点选服务端响应前缀（SMTP 数字 2-5、POP3 `+`/`-`、IMAP `*`）而非客户端命令前缀，避免抢占 HTTP 流；SMTP/FTP 共有 `220` 语法靠端口门控对称让位（SMTP 在非 SMTP 端口让位 FTP，FTP 在 SMTP 端口让位 SMTP，F10）；WebSocket 仅在 payload 含 `upgrade` 子串（不区分大小写）时接管，头缓冲至 `\r\n\r\n` 判定。多命令元数据：SMTP 提取 `MAIL FROM`/`RCPT TO` → `SmtpMetadata.sender`/`recipient`、POP3 提取 `USER` → `Pop3Metadata.username`、IMAP 提取 `LOGIN` → `ImapMetadata.username`；Smtp/Pop3/Imap 进入 `flow.monitoring`（同 TLS），定型后后续命令持续经有状态路径富化；`merge_detected_metadata` 增三协议逐字段非 None 合并。
- **JA4TS 第 5 段重传延迟 + RST 后缀（F40，2026-11-06）**：兑现 F34 登记边界，官方 zeek/ja4t/main.zeek（commit 27f0cbf9）状态机全量复刻——首个精确 0x12 启动收集（Flow.ja4ts 恒为 4 段基串一次定型）；收集期内超 **120 秒**停止（F34 登记"10 秒"系笔误）/ RST 记 `-R{整秒}` 后缀并停止 / 精确 0x12 重传记相邻间隔整秒至多 **10 项**；**任一客户端方向包即停止**（`observe_ja4ts_shutdown` 于 get_or_create 前借流表反查对端关闭，mid-stream 无关闭信号）；输出由 `application::compose_ja4ts` 落库时组合 `{基串}_{d1-d2-...}-R{n}`，**RST 后缀仅在存在延迟段时追加**；`Flow` 新增 `ja4ts_synack_time/ja4ts_delays/ja4ts_rst_delay/ja4ts_tracking` 旁路字段（仅重传发生时分配）。
- **QUIC JA4L-C/S 时延指纹（F41，2026-11-06）**：兑现 F35 登记边界①，官方 zeek/ja4l/main.zeek（commit 27f0cbf9）QUIC 事件语义——**免解密**：长包头 packet-type 位不受 header protection 保护（RFC 9001 掩码仅异或首字节低 4 位），首字节 `& 0xc0 == 0xc0` + type 位 `(首字节>>4)&0x03`（0=Initial、2=Handshake）+ **版本门控仅 QUIC v1**；四时点状态机 `observe_ja4l_quic`（lib.rs，detect_at UDP 分支 get_or_create 前借流表，observe_ja4l 先例）：client Initial（A'）→ server Initial（一次算 JA4L-S）→ server Handshake（B'）→ client Handshake（一次算 JA4L-C，B' 未到由后续 Handshake 包重试）；输出**三段 `{µs}_{TTL}_q` 格式（字面 "q" 后缀，与 TCP 两段不同）**——`application::compute_ja4ls_quic/ja4lc_quic`；结果复用 F35 既有 `Flow.ja4ls/ja4lc` 与 `DetectionResult.ja4ls/ja4lc`（types/CLI 零改动）；`ParsedPacket` 新增顶层 `ttl: u8`（UDP 路径 TTL 传递，ICMP/Other 同补）；重传 Initial 不覆盖 A'、乱序/mid-stream 跳过（zeek 按 0 参与计算产巨值，故意收紧）；Flow 新增 4 个 quic_* 旁路字段（正常流零堆分配）。
- **JA4L-C/S 时延指纹（F35，2026-11-06）**：`application::compute_ja4ls/ja4lc`（官方 zeek ja4l/main.zeek + python ja4.py 同源：`{半程时延µs}_{TTL}`，半程时延 = 包间总微秒**整除 2**）；A（SYN 时戳+TTL）/B（SYN-ACK 时戳+TTL）记录在两方向流（`Flow.syn_time/syn_ttl/synack_time/synack_ttl`），JA4L-S 在 SYN-ACK 到达时反查对端 A 算出（写服务端流）、JA4L-C 在其后首个客户端包到达时反查对端 B 算出（写客户端流）——跨流计算在 `Detector::observe_ja4l`（lib.rs）于 get_or_create 之前独立借流表完成；时延需真实包间隔，新增 `Detector::detect_at(packet, SystemTime)` 时间戳入口（detect 以处理时刻委托），CLI pcap 路径已传捕获时戳；乱序时戳回退/mid-stream 缺握手起点跳过；TLS 精化段（delta）已由 F42 兑现，QUIC 变体已由 F41 兑现（risks.md F35/F41/F42）。
- **JA4SSH 会话指纹（F36，2026-11-06）**：`application::compute_ja4ssh`（官方 FoxIO ja4 仓库 zeek/ja4ssh/main.zeek 语义：`c{c众数}s{s众数}_c{c载荷包数}s{s载荷包数}_c{c纯ACK数}s{s纯ACK数}`，众数平局取较小值，纯 ACK = 无载荷且 flags 精确等于 0x10，窗口 = 双向载荷包合计 200 滚动）；`Flow.ssh_payload_lens/ssh_ack_count/ja4ssh` 流级旁路字段（非 SSH 流零堆分配）；`Detector::observe_ja4ssh`（lib.rs，get_or_create 之前独立借流表）门控两级——流已定型 Ssh + 连接自初始 SYN 起（借 syn_time）；方向归位 SYN 发送端为客户端；指纹写两方向流，保留**最近完成窗口**（zeek 逐窗口出日志、尾窗冲刷不实现，见 risks.md F36 边界）。
- **JA4D/JA4D6 DHCP 指纹（F37，2026-11-06）**：`application::compute_ja4d/ja4d6`（格式 `{类型助记符5}{尺寸4}{i|n}{d|n}_{选项列表}_{参数列表}`；v4 权威 zeek/ja4d/main.zeek + Wireshark packet-ja4.c 终版 commit d21d63f9/11ae927f——选项列表剔除 {0/53/50/81}、尺寸 = option 57、未知类型 %05d、缺 53 记 "00000"；v6 权威仅 Wireshark 插件——尺寸 = option 1/2 首个 DUID 长度、选项列表不剔除、ORO = option 6 大端项）；**per-message 指纹放 metadata**（同 JA4H）：`dhcp/parser.rs parse_dhcp_options`（offset 240 单遍 TLV）→ `DhcpMetadata.ja4d`；`dhcpv6/parser.rs parse_dhcpv6_info`（is_dhcpv6 同门控识别语义不变，Relay 12/13 起始偏移 34）→ 新增 `Dhcpv6Metadata{msg_type, ja4d6}` + `Metadata::Dhcpv6`（cfg(infra)）；relay 只解析外层选项不递归 option 9（risks.md F37 边界）。
- **DTLS 识别 + d 前缀 JA4/JA4S（F38，2026-11-06）**：新 detector（feature `dtls`，`DtlsDetector` 首字节门 [0x16,0x16]）——13B DTLS 记录头（epoch @payload[3..5] 须 0）+ 12B 握手头（fragment_offset @19..22 / fragment_length @22..25，单片段校验）；ClientHello（msg_type 1，1.3 无 cookie / 1.2 剥 cookie 两种布局试解）/ ServerHello（msg_type 2）剥离 DTLS 握手头后**合成 TLS 记录零改动复用 tls 解析器**（QUIC 先例）；HVR（msg_type 3）等不返回定型；JA4S 新增 d 前缀——`compute_ja4s` 首参重构为 `Ja4Transport{Tcp,Quic,Dtls}`，版本码补 d1/d2/d3 映射（JA4.md 权威：proto 字符与版本段独立，DTLS 1.3 输出 "dd3..." 为字面正确；zeek 基线 "td1..." 系实现局限，分歧登记 risks.md F38）；JA4 沿用占位格式（"DTLS x.y" 落 tls10 桶，登记边界）；注册于 QUIC 之后 TLS 之前——DTLS 版本字节 0xfe 与 TLS 记录头 data[1]==0x03 互斥，相对顺序无影响（R11 影响面已复述）；分片握手/epoch>0/重传序列不解析（risks.md F38 边界）。
- **JA4 客户端指纹官方格式（F39，2026-11-06）**：`compute_ja4` 重写为官方 ja4.py `to_ja4` 格式 `{t|q|d}{版本2}{d|i}{密码数2}{扩展数2}{alpn2}_{密码哈希12}_{扩展哈希12}`（36 字符）——版本取 supported_versions 非 GREASE 最大值回退握手头 client_version（`ClientHelloInfo.negotiated_version`，JA4 恒可计算）、计数剔 GREASE 且扩展计数含 SNI/ALPN、密码升序排序哈希、扩展哈希剔除 SNI/ALPN 并追加原始顺序 sig_algs（0x000d）、ALPN 首尾字符非 ASCII 逐位 '9'（`alpn_code` 为 JA4/JA4S 共用，JA4S 行为同步变化）；TLS/QUIC/DTLS 三路径共用一处计算；官方黄金向量 `t13d1516h2_8daaf6152771_e5627efa2ab1` 直证；F38 边界③（DTLS 版本落 tls10 桶）消除（risks.md F39）。
- **DNS 家族与 HTTP 代理子分类 + FTP 传输元数据（F44，2026-11-07）**：Phase 1 收尾——`Protocol` 新增 `Doh`/`Dot`/`Doq`（DNS 类）与 `HttpConnect`/`HttpProxy`（Web 类）+ 规则名映射；TLS 子分类（ALPN `dot` 优先 → SNI 命中 DoH 解析器域名表 → 853 端口 DpiPartial 回退，`tls/doh.rs`）；QUIC 子分类（ALPN `doq` 前缀 → Doq，`select_quic_protocol`）；HTTP 子分类（CONNECT 方法 / `http://` 绝对 URI）；FTP 有状态会话（推广 F43 框架，USER→username、RETR/STOR→filename，进入 monitoring）；parity 导出 nDPI 兼容名（DNSoverHTTPS 等）与分类映射；语料 +6 pcap（golden 待生成，runner 跳过报告）。
- **NetBIOS + SMBv1/v2/3 识别与 SMBv1 风险（F45，2026-11-07）**：阶段 2 第一批（`docs/architecture/phase2-smb-netbios-plan.md`）——新 `smb` feature：`Protocol::NetBios/Smb1/Smb23` + `NetBiosMetadata{service,name,suffix}`/`SmbMetadata{command,status}` + `DissectorState::NetBios/Smb`；NetBIOS 模块（NBNS UDP137 RFC 1002 名解码 + NBDS UDP138 长度自洽 + NBSS TCP139 会话请求 34 字节名字段 + `process()` 头部重组 4096B，首字节门 None）；SMB 模块（TCP445 门控，SMB1 Negotiate 0x72 无状态跳过 + `process()` NBSS 跨段重组并循环消费被跳过消息 64KiB，首字节门 `Some([(0x00,0x00)])`）；注册于 SSH 之后 FTP 之前；`RiskFlag::SmbInsecureVersion`（Smb1 流、Trans 0x25 豁免）+ UnsafeProtocol（对齐 nDPI），处理器 SmbRiskProcessor；parity：SMB 流 master 恒 NetBIOS + app SMBv1/SMBv23（真实 nDPI 5.0 golden `NetBIOS.SMBv1`=10.16/`NetBIOS.SMBv23`=10.41 修正计划假设 `SMBv1.NetBIOS`）、三协议 System 分类、risk 名 smb_insecure_version→smb_insecure_vers；语料 +6 pcap + WSL golden 差分全绿；连带修复 behavioral 处理器对 NBSS+SMB 签名载荷的混淆流量误报（Negotiate 打字占比 ~35% 落 mixed 区间）。
- **Memcached + Elasticsearch + AMQP 识别（F46，2026-11-07）**：阶段 2 第二批子批次 A（`docs/architecture/phase2-database-messaging-design.md`）——`database` feature 新增 `Protocol::Memcached/Elasticsearch` + `MemcachedMetadata{command,is_response}`/`ElasticsearchMetadata{message_length,source}`；新 `messaging` feature：`Protocol::Amqp` + `AmqpMetadata{version,frame_type,channel,class_id,method}`；`DissectorState::Memcached` 命中计数（端口 11211 单包定型 / 非标端口 2 次匹配 / >5 包 GiveUp）；Memcached 26 签名 + UDP 8 字节头；Elasticsearch 二进制 `ES`+BE u32 + HTTP `X-elastic-product` 响应头子分类（rDpi 超集，仅响应先到）；AMQP 0-9-1 帧头 + 1.0 协议头；注册于 Redis 后 SMTP 前；parity：Memcached Network/Acceptable、Elasticsearch System/Acceptable、AMQP RPC/Acceptable（`Amqp` 显式映射 "AMQP"）；语料 +3 pcap + WSL golden 差分全绿。
- **Live capture（F47，2026-11-08）**：新 `live` feature + `rdpi::live`——运行时动态加载 `wpcap.dll`/`libpcap`（`libloading`，无 Npcap SDK 编译依赖）；`devices()`/`CaptureConfig`/`LiveCapture`（`next_frame` 超时语义 + `Iterator` 跳过超时）/`CapturedFrame`/`LiveError`；仅接受 DLT_EN10MB；CLI `-i` 自动区分 pcap 文件与网卡、`--iface`、`--list-ifaces`、`-f`、`--count`、`--duration`；实时路径按 EtherType（含 VLAN/QinQ）跳过 ARP/LLDP 等非 IP 帧；实时帧复用 `Detector::process_packet` 与现有输出；`unsafe` 仅限 `src/live/ffi.rs`。
- **Live capture v2：多线程、Ctrl-C、链路层扩展（F48，2026-11-08）**：兑现 F47 登记的三项后续增量——`-n/--threads`（默认 1，1..=64）单抓包线程 + flow-hash 分片 worker（FNV-1a 规范五元组，双向同 shard；有界队列 1024/worker 背压；`-n 1` 保持 F47 顺序）；主线程收集端合并汇总，`json` 的 packets 按抓包序号重排、`flows-jsonl` 跨 worker 全局排序；`ctrlc`（仅 live feature）首次 Ctrl-C 优雅停止（exit 0）、第二次立即退出（130）；`LinkType` 支持 DLT_EN10MB/SLL/SLL2/RAW（`-i any`），`Detector::process_ip_packet` 为 L3 入口（字节统计按 IP 长度，以太网路径按整帧）；`unsafe` 仍仅限 `src/live/ffi.rs`（新增 `unsafe impl Send for CaptureHandle`）。
- **MSSQL/TDS + Kafka 识别（F49，2026-11-08）**：阶段 2 第三批（`docs/architecture/phase2-mssql-kafka-design.md`）——`database` feature 新增 `Protocol::Mssql` + `MssqlMetadata{packet_type,status,length,channel,packet_id}`，`messaging` feature 新增 `Protocol::Kafka` + `KafkaMetadata{api_key,api_version,correlation_id,client_id}`；MSSQL detector 严格校验 TDS 8 字节头（type 1..=8 要求 packet_id>0 或 type 14..=18、status 白名单、length==载荷长度、window==0），`detect_with_context` 任一端 102 端口排除 TPKT，首字节门 `[(1,8),(14,18)]`；Kafka detector 校验 BE u32 长度前缀自洽、api_key<75、api_version<16、client_id 长度自洽且全可打印 ASCII，首字节门 `None`；两者均为无状态 detector，不新增 `DissectorState`；注册位置：MSSQL 在 database 块 redis 之后、Kafka 在 messaging 块 amqp 之后；端口回退 1433/1434/9092；parity `MsSQL-TDS`→Database/Acceptable、`Kafka`→RPC/Acceptable。
- **Oracle + Cassandra 识别（F50，2026-11-08）**：阶段 2 第四批（`docs/architecture/phase2-oracle-cassandra-design.md`）——`database` feature 新增 `Protocol::Oracle` + `OracleMetadata{packet_length,packet_type}` 与 `Protocol::Cassandra` + `CassandraMetadata{source,version,stream_id,opcode,cql_version}`，无新增 `DissectorState`。Oracle detector 严格校验 TNS Connect 8 字节头（长度精确相等、包/头校验和为 0、type=1、reserved=0），`detect_with_context` 要求任一端 1521 端口，首字节门 None；Cassandra detector 识别 19 字节 internode magic（`0xCA552DFA`，不限端口）与严格 CQL STARTUP 帧（版本 0x02..=0x05、opcode=0x01、长度精确相等、string map 含 CQL_VERSION），首字节门 `[(2,5),(0xCA,0xCA)]`。**Cassandra 注册在 QUIC 之前**（internode magic 首字节 0xCA 与 QUIC 长包头冲突）；Oracle 注册在 database 块 mssql 之后、elasticsearch 之前。端口回退 1521/7000/9042；规则名 `oracle`/`cassandra`；parity Oracle/Cassandra→Database/Acceptable；语料 +3 pcap + 真实 golden 差分全绿。
- **AFP + DRDA 识别（F51，2026-11-08）**：阶段 2 第五批（`docs/architecture/phase2-afp-drda-design.md`）——`storage` feature 新增 `Protocol::Afp` + `AfpMetadata{flags,command,request_id,length}`，`database` feature 新增 `Protocol::Drda` + `DrdaMetadata{message_count,message_length}`，无新增 `DissectorState`。AFP detector 严格校验 16 字节 DSI 头（flags<=1、command 1..=8、reserved=0、payload>=16+length），>128 字节载荷不判定；首字节门 `[(0,1)]`；detect 不检查端口，548 仅端口回退。DRDA detector 严格校验 10 字节 DSS/DDM 头（length==length2+6、magic==0xD0、length>=10）并精确消费多消息；首字节门 None；无端口回退。**AFP 注册在 DNS 之前**（header-only DSI 会被 DNS detector 误判为 Dns）；DRDA 注册在 database 块 oracle 之后。连带修复 `Protocol::Nfs` 的 cfg 从 `infra` 改为 `storage`，使 `storage` feature 可单独编译。规则名 `afp`/`drda`；parity AFP→DataTransfer/Acceptable、DRDA→Database/Acceptable；语料 +2 pcap + 真实 golden 差分全绿。
- **首字节门预筛（F29，2026-11-05）**：detector 可声明 `first_byte_gate()`（payload[0] 允许区间），Registry 注册期预计算 skip 位图、detect 循环内位测试跳过（miss 路径 36/49 已声明门，同机 A/B -12.3%）；14 个首字节任意的 detector 保持 `None`（dns/mongodb/postgresql/stun/modbus/l2tp/pptp/ike/nfs/whois/websocket/pop3/imap/memcached，证据见 risks.md F29/F46）。
- **feature gate**：全部协议有 gate（R7 已修复 2026-11-04：tftp/rsync/whois/syslog/telnet/vnc 挂在 `misc` feature，risks.md R7）。

## 3. 常用命令

```bash
cargo test                    # 默认 features (dns+http+tls)，393 测试全绿（2026-11-08 F51 实测）
cargo test --all-features     # 1542 测试全绿（10 ignored = test_regression 存量）；F51 golden 差分闭环后实测
cargo test --features risk    # 439 测试全绿（含风险处理器相关探针 a1_risk/a6/r5）
cargo test --features smb     # 415 测试全绿（F45 NetBIOS/SMB 模块 + 语料差分）
cargo test --features "database messaging"  # 491 测试全绿（F46 Memcached/Elasticsearch/AMQP 模块 + 语料差分）
cargo test --features database       # 532 测试全绿（F50 Oracle/Cassandra 模块 + 语料差分；4 ignored）
cargo test --features "storage database"  # 568 测试全绿（F51 AFP/DRDA 模块 + 语料差分；4 ignored）
cargo test --features "risk smb"  # 471 测试全绿（SMBv1 风险处理器 + parity 风险差分）
cargo build --features pcap   # 构建 CLI
cargo test --features live          # 实时抓包类型/加载器测试（无后端时走 BackendUnavailable）
cargo build --features "pcap live"  # 构建实时抓包 CLI
cargo run --features "pcap live" --bin rdpi -- -i any -n 4 --duration 10   # Linux/WSL（SLL/SLL2）
cargo bench                   # criterion 基准（benches/bench_detect.rs）；基线见 docs/architecture/performance.md
cargo bench --features quic   # 全量 9 项（含 QUIC 头部判定/Initial 解密冷+稳态）
cargo fmt ; cargo clippy      # 提交前（lib+bins 门槛 0 警告；验证须用 --message-format=short，R12 教训）
```

## 4. 编码规范（从现有代码归纳）

- 错误处理：库内用 `thiserror` 定义的 `Error/Result`（error.rs:1）；解析失败对畸形输入返回 `None`/空 Vec 而非 panic。
- 协议模块三件套：`mod.rs`（detector + register）+ `parser.rs`（元数据提取）+ 可选 `detector.rs`；参考 `protocols/http/`、`protocols/tls/`。
- 新协议 checklist：① protocols/mod.rs 加 `#[cfg(feature)] pub mod x;` ② Protocol/Metadata 枚举加变体（types.rs）③ category()/breed() 补 match 分支（types.rs:598,695）④ register_defaults 注册 ⑤ tests/test_x.rs 用 `#[cfg(feature)]` 包裹。
- 中文 doc 注释为主，公开 API 带示例（lib.rs 风格）。
- edition 2024；不引入新重量级依赖（TLS 等解析均手写）。

## 5. 禁止事项

1. **禁止修改 Registry 注册顺序**而不在改动说明中复述影响面（顺序 = 优先级语义）。
2. **禁止在 detect 路径引入分配密集逻辑**——库声称零拷贝/低分配（README.md:84）。
3. **禁止绕过 feature gate 直接引用协议模块**。
4. **禁止"顺手修复"** risks.md 中登记的问题：改动前先复述影响面、带测试、改后回写文档。
5. 不确定的事情**禁止根据类名/文件名猜测**业务语义，必须沿源码验证。
6. **禁止违反首字节门契约（F29）**：detector 声明的 `first_byte_gate()` 区间必须覆盖其全部可命中 payload 的首字节（`None` = 显式声明首字节任意）。违反即假阴（真实流量被预筛跳过）；新增/修改 detector 判定逻辑时必须同步维护门声明，并保留 `test_first_byte_gate_covers_valid_sample` 门覆盖样本测试。

## 6. 已知问题索引（详见 docs/architecture/risks.md）

| ID | 摘要 | 级别 | 状态 |
|---|---|---|---|
| R1 | `--all-features` 编译失败（snmp asn1 导入路径） | 高 | ✅ 已修复 2026-11-04 |
| R2 | FlowTable 无 LRU，max_entries 不生效，无界内存 | 高 | ✅ 已修复 2026-11-04（满载先清超时流再逐出最久未活跃） |
| R3 | README 开发状态/依赖描述过期 | 高 | ✅ 已修复 2026-11-04（全面回写对照 Cargo.toml/git log） |
| R4 | guess 引擎 dst_ip 赋 src_ip——反向包漏判服务端 IP | 中 | ✅ 已修复 2026-11-04（GuessContext 增 src_ip，两方向匹配 dst 优先） |
| R5 | expire_flows 硬编码 120s 绕过 with_config | 中 | ✅ 已修复 2026-11-04（FlowTable::timeout() 访问器，analyze 窗口与真实超时一致） |
| R6 | sni_contains 规则永不命中（规则分支中 flow.metadata 恒 None） | 中 | ✅ 已修复 2026-11-04（SNI 回退从当前包 payload 提取，rule+tls） |
| R7 | 六协议（tftp/rsync/whois/syslog/telnet/vnc）无 feature gate | 中 | ✅ 已修复 2026-11-04（新增 `misc` feature，六协议全量纳入） |
| F1 | TlsObsoleteVersion 永不触发（格式断裂） | 高 | ✅ 已修复 2026-11-04 |
| F2 | TlsAlpnSniMismatch 死旗标（提交声称已实现） | 中 | ✅ 已修复 2026-11-04（实现启发式：ALPN=h3 over TCP 触发） |
| F3 | 证书字段几乎不可能填充（识别短路） | 中 | ✅ 已修复 2026-11-04（回显路径 enrich_tls_cert 一次性富化，协议仍一次定型） |
| F6 | DNS detector 对二进制载荷误报 Dns | 中 | ✅ 已修复 2026-11-04（问题区可行性 + qname 合法性校验） |
| F7 | 流识别后回显包把 flow.metadata 覆盖为 None，risk 第二包起失效 | 高 | ✅ 已修复 2026-11-04（回显携带元数据） |
| F8 | FTP detector 抢答 POP3 `USER` 命令 | 中 | ✅ 已修复 2026-11-04（端口上下文让位） |
| F9 | OpenVpn detector 对 HTTP 文本误报（vpn feature，b2/b4 在该 feature 下 ignored） | 中 | ✅ 已修复 2026-11-04（拒绝高可打印占比 payload） |
| F10 | all-features 下 test_integration 7 个存量失败（低特异性误报+计数不同步） | 中 | ✅ 已修复 2026-11-04（Ftp 端口让位 + Ptpv2/Tftp 判定收紧 + 计数表修正） |
| R9 | CLI 版本号硬编码 0.2.0 与 crate 0.4.1 不一致 | 低 | ✅ 已修复 2026-11-04（改 env!("CARGO_PKG_VERSION")） |
| R12 | clippy --all-targets 测试目标约 40 处历史 lint（lib+bins 门槛已 0 警告） | 信息 | 登记备查（risks.md R12） |
| F11 | 流级风险双重死路（flow_processors 恒空 + analyze_flow 结果丢弃） | 中 | ✅ 已修复 2026-11-04（双注册 + pending_risks + drain_risks 出口） |
| F12-F27 | 误报面审计：16 个低特异性 detector（pptp/whois/socks/rtmp/ldap/telnet/h323/vxlan/syslog/turn/radius/netflow/bgp/postgresql/dhcpv6/websocket）判定收紧，含 pptp/radius/dhcpv6 三个假阴修复与 websocket 热路径去分配 | 高×5/中×11 | ✅ 已修复 2026-11-05（注册顺序未动，逐模块误报探针固化，详见 risks.md F12-F27） |
| F28 | QUIC Initial 解密优化：InitialKeyCache 密钥缓存 + 候选解密分层（候选 0 直通全量 GHASH，miss 才启动预检） | 信息 | ✅ 已完成 2026-11-05（冷解密 25.6→23.3µs；首版预检无条件启用曾致 +10.7% 回归，基准驱动修正，详见 risks.md F28） |
| F29 | miss 路径首字节门预筛：detector 声明 payload[0] 区间，Registry 注册期预计算 skip 位图 | 中 | ✅ 已完成 2026-11-05（36/49 声明门，13 个首字节任意保持 None；同机 A/B miss 190.6→167.1µs/100 包；门契约入禁止事项 #6，详见 risks.md F29） |
| F30 | JA4S 服务端 TLS 指纹：TLS detector 识别 ServerHello + FoxIO ja4.py 格式 + QUIC q 前缀变体 + 回显一次性富化 | 中 | ✅ 已完成 2026-11-05（纯 ServerHello 服务端流自此可定型；golden 向量经 PowerShell .NET SHA256 交叉验证；默认 274 / all-features 1076 / risk 319 全绿，详见 risks.md F30） |
| F31 | JA4H 客户端 HTTP 指纹：HTTP/1.x 请求头集合指纹，对齐官方 ja4h.py（头序敏感/cookie 排序/语言编码） | 中 | ✅ 已完成 2026-11-05（http parser 增 parse_header_lines + compute_ja4h；HttpMetadata.ja4h 仅请求路径；golden 向量独立实现交叉验证；默认 288 / all-features 1090 / risk 333 全绿，详见 risks.md F31） |
| F32 | JA4X X.509 证书指纹：issuer/subject/扩展 OID 哈希，对齐官方 rust/ja4x（空列表全零、DER 内容字节 hex 输入） | 中 | ✅ 已完成 2026-11-05（certificate.rs OID 收集 + compute_ja4x + cert 富化双路径；官方 hash12 黄金向量交叉验证；默认 296 / all-features 1098 / risk 341 全绿，详见 risks.md F32） |
| F33 | JA4T 客户端 TCP 指纹：初始 SYN 头部字段指纹（window/选项 kind/MSS/wscale），对齐官方 rust/ja4 tcp.rs（流级旁路字段，不占用协议定型语义） | 中 | ✅ 已完成 2026-11-05（TcpHeaderInfo 栈结构零堆分配提取 + compute_ja4t + Flow.ja4t/DetectionResult.ja4t；官方 3 向量直证；默认 310 / all-features 1112 / risk 355 全绿，详见 risks.md F33） |
| F34 | JA4TS 服务端 TCP 指纹：SYN-ACK 头部字段指纹，格式与 JA4T 同源、权威为官方 zeek/ja4t/main.zeek（flags 精确等于 0x12，服务端方向流旁路字段） | 中 | ✅ 已完成 2026-11-06（compute_ja4ts 委托 compute_ja4t + Flow.ja4ts/DetectionResult.ja4ts + CLI；重传延迟第 5 段不实现已登记边界；默认 315 / all-features 1117 / risk 360 全绿，详见 risks.md F34） |
| F35 | JA4L-C/S 时延指纹：TCP 握手三包时戳的半程时延（总微秒整除 2）+ TTL，官方 zeek ja4l/python ja4.py 同源；新增 detect_at 时间戳入口（离线 pcap 传捕获时戳） | 中 | ✅ 已完成 2026-11-06（compute_ja4ls/lc + Flow 4 个握手时戳字段 + observe_ja4l 跨流计算 + pcap CLI 接入；乱序/缺起点跳过；QUIC 变体与 TLS 精化段不实现已登记边界；默认 322 / all-features 1124 / risk 367 全绿，详见 risks.md F35） |
| F36 | JA4SSH 会话指纹：SSH 流 200 载荷包滚动窗口（双向包长众数/载荷包数/纯 ACK 数六段格式），官方 FoxIO zeek/ja4ssh 语义；非 SSH 流零分配；保留最近完成窗口 | 中 | ✅ 已完成 2026-11-06（compute_ja4ssh + Flow.ssh_payload_lens/ssh_ack_count/ja4ssh + observe_ja4ssh 双门控（Ssh 定型 + SYN 起）+ CLI；逐窗口日志/尾窗冲刷不实现已登记边界；默认 322 / all-features 1130 / risk 367 全绿，详见 risks.md F36） |
| F37 | JA4D/JA4D6 DHCP 指纹：per-message 指纹放 metadata（DhcpMetadata.ja4d / 新增 Dhcpv6Metadata.ja4d6），v4 对齐 zeek ja4d + Wireshark 终版（选项剔除 {0/53/50/81}）、v6 对齐 Wireshark 插件（DUID 长度尺寸段、选项不剔除）；识别语义不变 | 中 | ✅ 已完成 2026-11-06（parse_dhcp_options/parse_dhcpv6_info + compute_ja4d/ja4d6 + CLI；官方黄金向量 + 博客样例直证；relay 不递归等边界登记；默认 322 / all-features 1156 / risk 367 全绿，详见 risks.md F37） |
| F38 | DTLS 识别（新 detector，feature dtls）+ d 前缀 JA4/JA4S（compute_ja4s 重构 Ja4Transport + 版本码 d1/d2/d3）；合成 TLS 记录复用 tls 解析器（QUIC 先例）；"JA4DS" 独立指纹名不存在，官方规格即 DTLS 变体 | 中 | ✅ 已完成 2026-11-06（dtls 模块 + Ja4Transport + 443 端口表/rule/CLI/behavioral 接入；JA4.md 与 zeek 基线 proto 字符分歧登记；分片/epoch>0 等边界登记；默认 324 / all-features 1171 / risk 369 全绿，详见 risks.md F38） |
| F39 | 客户端 JA4 对齐官方 ja4.py to_ja4（计数/sni/alpn 段 + 升序排序双哈希段 + sig_algs 追加；协商版本回退 client_version，JA4 恒可计算；alpn_code 逐位 '9' 同改 JA4S） | 中 | ✅ 已完成 2026-11-06（ClientHelloInfo 增 negotiated_version/client_version/signature_algorithms；官方黄金向量直证；F38 边界③消除、test_pin_rules a5 语义更新；默认 328 / all-features 1175 / risk 373 全绿，详见 risks.md F39） |
| F40 | JA4TS 第 5 段重传延迟 + RST 后缀：兑现 F34 边界，官方 zeek/ja4t 状态机全量复刻（120 秒超时更正/至多 10 项/客户端包即停/纯 RST 无后缀）；compose_ja4ts 落库组合，Flow.ja4ts 恒为 4 段基串 | 中 | ✅ 已完成 2026-11-06（compose_ja4ts + JA4TS_MAX_DELAYS/JA4TS_TRACK_TIMEOUT + Flow 4 旁路字段 + observe_ja4ts_shutdown；故意分歧：基串产出宽松于 zeek；默认 335 / all-features 1182 / risk 380 全绿，详见 risks.md F40） |
| F41 | QUIC JA4L-C/S 时延指纹：兑现 F35 边界①，免解密长包头 type 位判定 + 仅 QUIC v1 门控 + 四时点状态机；三段 `{µs}_{TTL}_q` 官方格式；ParsedPacket.ttl 顶层字段 + Flow 4 个 quic_* 旁路字段，结果复用 F35 出口 | 中 | ✅ 已完成 2026-11-06（compute_ja4ls_quic/ja4lc_quic + observe_ja4l_quic UDP 分支；重传 Initial 不覆盖/乱序/mid-stream 跳过为故意收紧；默认 341 / all-features 1188 / risk 386 全绿，详见 risks.md F41） |
| F42 | JA4L TLS 精化段 delta：兑现 F35 边界②，官方 zeek ja4l TLS delta 语义（仅 TCP）——D/E/F 三时点每流一次，`(E-D)/2`/`(F-E)/2` µs 追加 ja4ls/ja4lc 第三段（F 需有载荷，纯 ACK 不触发）；信号取自元数据 ja4/ja4s Some 精确推断；方向判定借 F35 握手时戳放宽 | 中 | ✅ 已完成 2026-11-06（observe_ja4l_tls 于 DPI 之后调用 + Flow 3 个 tls_* 时戳旁路字段；zeek ja4l_delta 比值字段不实现等边界登记；默认 347 / all-features 1194 / risk 392 全绿，详见 risks.md F42） |
| F43 | SMTP/IMAP/POP3 有状态会话 + WebSocket 升级握手：推广 process()/DissectorState 框架，跨段行/头重组 + 多命令元数据（SMTP sender/recipient、POP3/IMAP username）；邮件协议服务端响应前缀接管避免抢 HTTP，SMTP/FTP 220 共有语法端口门控对称让位；WebSocket 需 upgrade 子串才接管 | 中 | ✅ 已完成 2026-11-06（4 个 DissectorState 变体 + SmtpMetadata 增字段 + 新增 Pop3/ImapMetadata；merge_detected_metadata 增三协议合并 + flow.monitoring 含 Smtp/Pop3/Imap；默认 376 / all-features 1279 / risk 424 全绿，详见 risks.md F43） |
| F44 | DNS 家族与 HTTP 代理子分类 + FTP 传输元数据：Protocol 增 Doh/Dot/Doq/HttpConnect/HttpProxy + 规则名映射；TLS（ALPN dot/SNI DoH 域名表/853 端口回退）、QUIC（ALPN doq）、HTTP（CONNECT/绝对 URI）子分类；FTP 有状态会话（USER→username、RETR/STOR→filename，进入 monitoring）；parity nDPI 兼容导出（真实 golden 验证：DoH/DoQ→TLS.DoH_DoT、DoT 在 nDPI 5.0 不子分类→导出纯 TLS）；语料 +6 pcap + 真实 golden 差分全绿；连带修复 Tls/Http 风险处理器对子分类流的门控遗漏 | 中 | ✅ 已完成 2026-11-07（DoQ pcap 需加密构造不语料化等边界登记；默认 389 / all-features 1312 / risk 439 全绿，详见 risks.md F44） |
| F45 | NetBIOS（NBNS/NBDS/NBSS）+ SMBv1/v2/3 识别 + SMBv1 风险：新 smb feature，两独立模块 detector（注册 SSH 后 FTP 前）；SMB1 Negotiate 跳过 + NBSS 头部重组；RiskFlag::SmbInsecureVersion + UnsafeProtocol；parity 真实 golden 修正计划假设（master 恒 NetBIOS，`NetBIOS.SMBv1/SMBv23`）；语料 +6 pcap + WSL golden 差分全绿；连带修复 behavioral 对 SMB 帧的混淆误报 | 中 | ✅ 已完成 2026-11-07（纯 Negotiate 流不定型等 6 项边界登记；默认 389 / smb 415 / all-features 1347 / risk+smb 471 全绿，详见 risks.md F45） |
| F46 | Memcached + Elasticsearch + AMQP 识别：database 复用 + 新 messaging feature；Memcached 有状态匹配计数、Elasticsearch 二进制/HTTP 双路径、AMQP 0-9-1/1.0；parity 三协议分类映射；语料 +3 pcap 差分全绿 | 中 | ✅ 已完成 2026-11-07（HTTP-ES 仅响应先到、AMQP 1.0 仅协议头等边界见 risks.md F46） |
| F49 | MSSQL/TDS + Kafka 识别：database 复用 + messaging 复用；TDS 8 字节头严格校验（长度/窗口/类型/状态，102 端口排除 TPKT）；Kafka 请求长度前缀 + client_id 校验；端口回退/规则名/parity/CLI 接入；语料 +2 pcap + 真实 golden 差分 | 中 | ✅ 已完成 2026-11-08（跨段/粘连单报文语义等边界见 risks.md F49） |
| F50 | Oracle + Cassandra 识别：Oracle TNS Connect 8 字节头 + 1521 端口门控；Cassandra internode magic + 严格 CQL STARTUP 解析；Cassandra 前置 QUIC 避免长包头冲突；端口回退/规则名/parity/CLI 接入；语料 +3 pcap + 真实 golden 差分 | 中 | ✅ 已完成 2026-11-08（弱启发式不兼容等边界见 risks.md F50） |
| F51 | AFP + DRDA 识别：AFP 16 字节 DSI 头 + >128 字节拒绝；DRDA 10 字节 DSS/DDM 头 + 多消息精确消费；AFP 前置 DNS 避免误判；连带修复 Nfs cfg；端口回退/规则名/parity/CLI 接入；语料 +2 pcap + 真实 golden 差分 | 中 | ✅ 已完成 2026-11-08（DRDA 多消息与 nDPI 循环差异等边界见 risks.md F51） |

## 7. 文档索引

| 文档 | 内容 |
|---|---|
| [docs/architecture/overview.md](file:///d:/rust_code/rDpi/docs/architecture/overview.md) | 技术栈/入口/构建测试实测 |
| [docs/architecture/modules.md](file:///d:/rust_code/rDpi/docs/architecture/modules.md) | 模块清单、协议×feature 全量对照 |
| [docs/architecture/dependencies.md](file:///d:/rust_code/rDpi/docs/architecture/dependencies.md) | 依赖方向、外部 crate 审计（etherparse/rustls 死依赖已于 2026-11-04 移除） |
| [docs/architecture/business-flows.md](file:///d:/rust_code/rDpi/docs/architecture/business-flows.md) | 五条高层业务流 |
| [docs/architecture/risks.md](file:///d:/rust_code/rDpi/docs/architecture/risks.md) | 风险清单 R1-R11 + 探针 P1-P5 |
| [docs/architecture/ndpi-comparison-and-roadmap.md](file:///d:/rust_code/rDpi/docs/architecture/ndpi-comparison-and-roadmap.md) | 与 nDPI 5.0 的能力对比与替换路线（历史版，2026-11-06） |
| [docs/architecture/ndpi-pure-rust-plan.md](file:///d:/rust_code/rDpi/docs/architecture/ndpi-pure-rust-plan.md) | 类比 nDPI 的纯 Rust 实现方案与路线（2026-11-06） |
| [docs/architecture/protocol-coverage-plan.md](file:///d:/rust_code/rDpi/docs/architecture/protocol-coverage-plan.md) | 协议/应用覆盖候选清单与首批 Top-N 建议（2026-11-06） |
| [docs/business/tls-sni-application.md](file:///d:/rust_code/rDpi/docs/business/tls-sni-application.md) | TLS SNI→应用→风险 全链路深挖（F1-F5, P6-P10） |
| [docs/decisions/](file:///d:/rust_code/rDpi/docs/decisions) | ADR（追溯记录的历史决策） |

注：docs/ 已随仓库入库（2026-11-04 起取消 .gitignore 忽略）；AGENTS.md 位于仓库根目录、可提交。
