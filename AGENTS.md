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
- **首字节门预筛（F29，2026-11-05）**：detector 可声明 `first_byte_gate()`（payload[0] 允许区间），Registry 注册期预计算 skip 位图、detect 循环内位测试跳过（miss 路径 36/49 已声明门，同机 A/B -12.3%）；13 个首字节任意的 detector 保持 `None`（dns/mongodb/postgresql/stun/modbus/l2tp/pptp/ike/nfs/whois/websocket/pop3/imap，证据见 risks.md F29）。
- **feature gate**：全部协议有 gate（R7 已修复 2026-11-04：tftp/rsync/whois/syslog/telnet/vnc 挂在 `misc` feature，risks.md R7）。

## 3. 常用命令

```bash
cargo test                    # 默认 features (dns+http+tls)，274 测试全绿（2026-11-05 F30 JA4S 轮实测）
cargo test --all-features     # 1076 测试全绿（10 ignored = test_regression 存量）；F30 后实测
cargo test --features risk    # 319 测试全绿（含风险处理器相关探针 a1_risk/a6/r5）
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
