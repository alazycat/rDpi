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
- **JA4TS 第 5 段重传延迟 + RST 后缀（F40，2026-11-06）**：兑现 F34 登记边界，官方 zeek/ja4t/main.zeek（commit 27f0cbf9）状态机全量复刻——首个精确 0x12 启动收集（Flow.ja4ts 恒为 4 段基串一次定型）；收集期内超 **120 秒**停止（F34 登记"10 秒"系笔误）/ RST 记 `-R{整秒}` 后缀并停止 / 精确 0x12 重传记相邻间隔整秒至多 **10 项**；**任一客户端方向包即停止**（`observe_ja4ts_shutdown` 于 get_or_create 前借流表反查对端关闭，mid-stream 无关闭信号）；输出由 `application::compose_ja4ts` 落库时组合 `{基串}_{d1-d2-...}-R{n}`，**RST 后缀仅在存在延迟段时追加**；`Flow` 新增 `ja4ts_synack_time/ja4ts_delays/ja4ts_rst_delay/ja4ts_tracking` 旁路字段（仅重传发生时分配）。
- **JA4L-C/S 时延指纹（F35，2026-11-06）**：`application::compute_ja4ls/ja4lc`（官方 zeek ja4l/main.zeek + python ja4.py 同源：`{半程时延µs}_{TTL}`，半程时延 = 包间总微秒**整除 2**）；A（SYN 时戳+TTL）/B（SYN-ACK 时戳+TTL）记录在两方向流（`Flow.syn_time/syn_ttl/synack_time/synack_ttl`），JA4L-S 在 SYN-ACK 到达时反查对端 A 算出（写服务端流）、JA4L-C 在其后首个客户端包到达时反查对端 B 算出（写客户端流）——跨流计算在 `Detector::observe_ja4l`（lib.rs）于 get_or_create 之前独立借流表完成；时延需真实包间隔，新增 `Detector::detect_at(packet, SystemTime)` 时间戳入口（detect 以处理时刻委托），CLI pcap 路径已传捕获时戳；乱序时戳回退/mid-stream 缺握手起点跳过；QUIC 变体与 zeek 的 TLS 精化段（delta）不实现（risks.md F35 边界）。
- **JA4SSH 会话指纹（F36，2026-11-06）**：`application::compute_ja4ssh`（官方 FoxIO ja4 仓库 zeek/ja4ssh/main.zeek 语义：`c{c众数}s{s众数}_c{c载荷包数}s{s载荷包数}_c{c纯ACK数}s{s纯ACK数}`，众数平局取较小值，纯 ACK = 无载荷且 flags 精确等于 0x10，窗口 = 双向载荷包合计 200 滚动）；`Flow.ssh_payload_lens/ssh_ack_count/ja4ssh` 流级旁路字段（非 SSH 流零堆分配）；`Detector::observe_ja4ssh`（lib.rs，get_or_create 之前独立借流表）门控两级——流已定型 Ssh + 连接自初始 SYN 起（借 syn_time）；方向归位 SYN 发送端为客户端；指纹写两方向流，保留**最近完成窗口**（zeek 逐窗口出日志、尾窗冲刷不实现，见 risks.md F36 边界）。
- **JA4D/JA4D6 DHCP 指纹（F37，2026-11-06）**：`application::compute_ja4d/ja4d6`（格式 `{类型助记符5}{尺寸4}{i|n}{d|n}_{选项列表}_{参数列表}`；v4 权威 zeek/ja4d/main.zeek + Wireshark packet-ja4.c 终版 commit d21d63f9/11ae927f——选项列表剔除 {0/53/50/81}、尺寸 = option 57、未知类型 %05d、缺 53 记 "00000"；v6 权威仅 Wireshark 插件——尺寸 = option 1/2 首个 DUID 长度、选项列表不剔除、ORO = option 6 大端项）；**per-message 指纹放 metadata**（同 JA4H）：`dhcp/parser.rs parse_dhcp_options`（offset 240 单遍 TLV）→ `DhcpMetadata.ja4d`；`dhcpv6/parser.rs parse_dhcpv6_info`（is_dhcpv6 同门控识别语义不变，Relay 12/13 起始偏移 34）→ 新增 `Dhcpv6Metadata{msg_type, ja4d6}` + `Metadata::Dhcpv6`（cfg(infra)）；relay 只解析外层选项不递归 option 9（risks.md F37 边界）。
- **DTLS 识别 + d 前缀 JA4/JA4S（F38，2026-11-06）**：新 detector（feature `dtls`，`DtlsDetector` 首字节门 [0x16,0x16]）——13B DTLS 记录头（epoch @payload[3..5] 须 0）+ 12B 握手头（fragment_offset @19..22 / fragment_length @22..25，单片段校验）；ClientHello（msg_type 1，1.3 无 cookie / 1.2 剥 cookie 两种布局试解）/ ServerHello（msg_type 2）剥离 DTLS 握手头后**合成 TLS 记录零改动复用 tls 解析器**（QUIC 先例）；HVR（msg_type 3）等不返回定型；JA4S 新增 d 前缀——`compute_ja4s` 首参重构为 `Ja4Transport{Tcp,Quic,Dtls}`，版本码补 d1/d2/d3 映射（JA4.md 权威：proto 字符与版本段独立，DTLS 1.3 输出 "dd3..." 为字面正确；zeek 基线 "td1..." 系实现局限，分歧登记 risks.md F38）；JA4 沿用占位格式（"DTLS x.y" 落 tls10 桶，登记边界）；注册于 QUIC 之后 TLS 之前——DTLS 版本字节 0xfe 与 TLS 记录头 data[1]==0x03 互斥，相对顺序无影响（R11 影响面已复述）；分片握手/epoch>0/重传序列不解析（risks.md F38 边界）。
- **JA4 客户端指纹官方格式（F39，2026-11-06）**：`compute_ja4` 重写为官方 ja4.py `to_ja4` 格式 `{t|q|d}{版本2}{d|i}{密码数2}{扩展数2}{alpn2}_{密码哈希12}_{扩展哈希12}`（36 字符）——版本取 supported_versions 非 GREASE 最大值回退握手头 client_version（`ClientHelloInfo.negotiated_version`，JA4 恒可计算）、计数剔 GREASE 且扩展计数含 SNI/ALPN、密码升序排序哈希、扩展哈希剔除 SNI/ALPN 并追加原始顺序 sig_algs（0x000d）、ALPN 首尾字符非 ASCII 逐位 '9'（`alpn_code` 为 JA4/JA4S 共用，JA4S 行为同步变化）；TLS/QUIC/DTLS 三路径共用一处计算；官方黄金向量 `t13d1516h2_8daaf6152771_e5627efa2ab1` 直证；F38 边界③（DTLS 版本落 tls10 桶）消除（risks.md F39）。
- **首字节门预筛（F29，2026-11-05）**：detector 可声明 `first_byte_gate()`（payload[0] 允许区间），Registry 注册期预计算 skip 位图、detect 循环内位测试跳过（miss 路径 36/49 已声明门，同机 A/B -12.3%）；13 个首字节任意的 detector 保持 `None`（dns/mongodb/postgresql/stun/modbus/l2tp/pptp/ike/nfs/whois/websocket/pop3/imap，证据见 risks.md F29）。
- **feature gate**：全部协议有 gate（R7 已修复 2026-11-04：tftp/rsync/whois/syslog/telnet/vnc 挂在 `misc` feature，risks.md R7）。

## 3. 常用命令

```bash
cargo test                    # 默认 features (dns+http+tls)，335 测试全绿（2026-11-06 F40 JA4TS 第 5 段轮实测）
cargo test --all-features     # 1182 测试全绿（10 ignored = test_regression 存量）；F40 后实测
cargo test --features risk    # 380 测试全绿（含风险处理器相关探针 a1_risk/a6/r5）
cargo build --features pcap   # 构建 CLI
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

## 7. 文档索引

| 文档 | 内容 |
|---|---|
| [docs/architecture/overview.md](file:///d:/rust_code/rDpi/docs/architecture/overview.md) | 技术栈/入口/构建测试实测 |
| [docs/architecture/modules.md](file:///d:/rust_code/rDpi/docs/architecture/modules.md) | 模块清单、协议×feature 全量对照 |
| [docs/architecture/dependencies.md](file:///d:/rust_code/rDpi/docs/architecture/dependencies.md) | 依赖方向、外部 crate 审计（etherparse/rustls 死依赖已于 2026-11-04 移除） |
| [docs/architecture/business-flows.md](file:///d:/rust_code/rDpi/docs/architecture/business-flows.md) | 五条高层业务流 |
| [docs/architecture/risks.md](file:///d:/rust_code/rDpi/docs/architecture/risks.md) | 风险清单 R1-R11 + 探针 P1-P5 |
| [docs/business/tls-sni-application.md](file:///d:/rust_code/rDpi/docs/business/tls-sni-application.md) | TLS SNI→应用→风险 全链路深挖（F1-F5, P6-P10） |
| [docs/decisions/](file:///d:/rust_code/rDpi/docs/decisions) | ADR（追溯记录的历史决策） |

注：docs/ 已随仓库入库（2026-11-04 起取消 .gitignore 忽略）；AGENTS.md 位于仓库根目录、可提交。
