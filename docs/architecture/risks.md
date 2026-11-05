# rDpi 风险清单（risks，第一步产出）

> 生成时间：2026-11-04；证据规则同 [overview.md](file:///d:/rust_code/rDpi/docs/architecture/overview.md)。
> 按铁律：体检阶段只记录不修复。每项标注三分类与建议处理阶段。

## R1【高】`--all-features` 构建失败：SNMP 模块无法编译 —— ✅ 已修复（2026-11-04，第五步 #1）

- **分类**：[代码明确实现]
- **证据**：原错误 `E0432: unresolved imports crate::asn1::{BerReader, Asn1Value, Asn1Class}`，源自 [src/protocols/snmp/parser.rs:5](file:///d:/rust_code/rDpi/src/protocols/snmp/parser.rs#L5)。
- **修复**：改为 `crate::asn1::ber::BerReader` + `crate::asn1::types::{Asn1Class, Asn1Value}`（对照正确用法 src/protocols/tls/certificate.rs:6）。
- **验证**：`cargo test --all-features` 从编译失败 → **636 测试全绿**（540 lib + 72 test_integration + 24 其他套件，1 ignored=F8）。

## R2【高】流表无界增长：max_entries 从未生效 —— ✅ 已修复（2026-11-04，用户批准）

- **分类**：[代码明确实现]
- **证据**：原 [src/core/flow.rs:102](file:///d:/rust_code/rDpi/src/core/flow.rs#L102) 注释自述"预留，未实现 LRU 淘汰"；`get_or_create` 无容量检查直接插入。默认 10000 上限（lib.rs:120）仅为配置占位。
- **修复**：[src/core/flow.rs:127-155](file:///d:/rust_code/rDpi/src/core/flow.rs#L127-L155) `get_or_create` 实施容量控制——已存在流命中即 touch `last_time`（LRU 活跃依据）；新流在表满时先 `expire_timeout` 清超时流，仍满则按 `stats.last_time` 最小（最久未活跃）逐出至有空位；`max_entries == 0` 视为不设上限（防御误配）。逐出为低频路径 O(n) 扫描、无批量分配（detect 热路径分配语义不变，铁律 2）。
- **验证**：flow.rs +4 单测（满载逐出最旧 / 活跃流存活 / 命中不逐出 / 0=不设限）；默认全量 259 绿、all-features 855 绿。

## R3【高】README 与代码严重脱节 —— ✅ 已修复（2026-11-04，用户批准）

- **分类**：[代码明确实现]
- **证据**：原 README.md:94-101 声称"Phase 4 QUIC 开发中，规划 Phase 5/6"，但 git 历史（61ffab3/57ff856/34cc561）显示已完成 Phase 11A/12A/12B，协议模块 49 个；README 协议表仅 6 项（README.md:69-78）；README.md:106 声称使用 etherparse（实为零引用死依赖，Cargo.toml:11）。
- **修复**：README.md 全面回写——特性/安装版本（0.1.0→0.4.1）/Feature Gates 表（6→20 项，对照 Cargo.toml:22-44）/支持协议表（6→49 detector 按 feature 分组）/开发状态（Phase 1-12B 实况，据 git log）/技术栈（移除 etherparse，如实描述手写解析器 + serde/clap/pcap-file 可选依赖）；流管理特性补充 R2 容量上限。纯文档改动，零代码变更。
- **验证**：内容逐项对照 Cargo.toml 与 register_defaults（protocols/mod.rs:174-276）；全量测试不受影响。

## R4【中】猜测引擎疑似取错 IP：dst_ip 被赋为 src_ip —— ✅ 已修复（2026-11-04，用户批准）

- **分类**：[代码明确实现]（探针实锤后升级）
- **证据**：原 [src/lib.rs:291](file:///d:/rust_code/rDpi/src/lib.rs#L291) `ctx.dst_ip = Some(parsed.src_ip)`（注释"对端 IP"）；[guess/mod.rs:56](file:///d:/rust_code/rDpi/src/core/guess/mod.rs#L56) 只匹配该单一 IP。探针双向实测：src=8.8.8.8 命中 Dns(MatchByIp)、dst=8.8.8.8 漏判（端口 9999 无回退，port.rs:59）——服务端在 dst 方向（client→server 包）时 IP 猜测完全失效。
- **修复**：① `GuessContext` 新增 `src_ip` 字段（[core/guess/info.rs:24](file:///d:/rust_code/rDpi/src/core/guess/info.rs#L24)，additive）；② [guess/mod.rs:53-60](file:///d:/rust_code/rDpi/src/core/guess/mod.rs#L53-L60) `match_ip` 两方向尝试，dst 优先；③ lib.rs:293-296 两方向 IP 均传入。猜测链路顺序（域名→IP→端口）、Registry 注册顺序（R11）、detect 热路径分配语义均未动。
- **验证**：guess/mod.rs +2 单测（dst 优先 / dst 未命中回退 src）；探针 a4 保留为回归（src 方向命中）、a4b 由探针翻转为回归（dst 方向命中）。默认 262 / risk 267 / all-features 855 全绿。

## R5【中】expire_flows 内硬编码 120s，绕过 with_config 配置 —— ✅ 已修复（2026-11-04，用户批准）

- **分类**：[代码明确实现]
- **证据**：原 [src/lib.rs:370-373](file:///d:/rust_code/rDpi/src/lib.rs#L370-L373) 过期过滤直接写 `Duration::from_secs(120)`，而 `with_config(max_flows, timeout_secs)` 的自定义 timeout 只传给了 FlowTable。
- **修复**：[core/flow.rs:175-178](file:///d:/rust_code/rDpi/src/core/flow.rs#L175-L178) 新增 `FlowTable::timeout()` 访问器；lib.rs expire_flows 的 risk 过期窗口改取 `self.flow_table.timeout()`——analyze 窗口与 `expire_timeout` 共用同一配置值，单一事实来源。
- **验证**：flow.rs +1 单测（访问器返回配置值）；test_pin_rules.rs 新增 risk 门控回归 `r5_expire_window_uses_configured_timeout`（timeout=1s 配置下静默 1.2s → 流按配置过期）。risk 全量 268 绿。

## R6【中】规则引擎首包 SNI 恒为 None —— ✅ 已修复（2026-11-04，用户批准）

- **分类**：[代码明确实现]（P3 探针实锤后升级，且比预期更严重：不止首包，sni_contains 规则**永不命中**）
- **证据**：规则分支仅在 `flow.protocol.is_none()` 时进入（[lib.rs:255-276](file:///d:/rust_code/rDpi/src/lib.rs#L255-L276)），而所有写 `flow.metadata` 的路径（DPI/规则/猜测/回显）都同时写了 protocol → 规则分支中 `flow.metadata` 恒 None → `RuleContext.sni` 恒 None。P3 探针：首包 ClientHello 自带 SNI "evil.example.com" + sni_contains 规则 → 不命中，DPI 抢先返回 Tls(Dpi)。
- **修复**：[lib.rs:258-267](file:///d:/rust_code/rDpi/src/lib.rs#L258-L267) 规则上下文的 SNI 增加回退——从当前包 payload 经 `protocols::tls::extract_sni` 提取（`#[cfg(feature = "tls")]`，即需 rule+tls 同时启用；无 tls feature 行为不变）。规则先于 DPI 的优先级语义未动；QUIC SNI 不在覆盖范围（已文档化，[rule/mod.rs](file:///d:/rust_code/rDpi/src/rule/mod.rs) 模块注释）。
- **验证**：探针 p3 翻转为回归（断言规则命中 Http/CustomRule）；--features rule 全量 279 绿（含 test_rule 8 项）。

## R7【中】六个协议无 feature gate，特性矩阵不一致 —— ✅ 已修复（2026-11-04，用户批准）

- **分类**：[代码明确实现]
- **证据**：tftp/rsync/whois/syslog（原 [protocols/mod.rs:66-69](file:///d:/rust_code/rDpi/src/protocols/mod.rs#L66-L69)）、telnet/vnc（mod.rs:83-84）无条件编译并注册（mod.rs:238-239,259-262）；Protocol 枚举变体同样无 gate（types.rs:96-99,113-114）。`default-features=false` 的使用方仍被迫编译进这 6 个协议。
- **修复**：新增 `misc` feature（Cargo.toml:45）——六协议的模块声明（protocols/mod.rs:75-86,100-105）、注册调用（mod.rs:246-249,269-275）、Protocol 枚举变体（types.rs:97-104,119-122）、category()/breed() match 分支（types.rs:678-692,755-771）全部纳入 `#[cfg(feature = "misc")]`。test_integration.rs 计数表同步（misc → +6）。**注册相对顺序未动**（R11 影响面）；README Feature Gates/协议表同步更新。
- **验证**：默认构建 229 绿（六协议单测随 gate 移出默认构建）、`--features misc` 绿、all-features 561+72 绿（misc 自动包含，detector 计数 49 不变）。
- **注意**：`default-features=false` 使用方行为变化——如需六协议须显式加 `features = ["misc"]`（breaking，见 AGENTS.md 特性矩阵）。

## R8【低】测试空壳：7 个测试文件在默认 features 下运行 0 个测试 —— ✅ 已澄清：误诊（2026-11-04，用户批准"开始空壳测试补全"时实测纠正）

- **分类**：[代码明确实现]（原判断的错误部分同样有实测证据）
- **原证据**：默认 `cargo test` 输出 test_ftp/test_quic/test_rtp/test_rule/test_sip/test_smtp/test_ssh 各 "running 0 tests"（属实，但这些协议均非默认 feature，Cargo.toml:21,25-27,34-35，0 tests 是 feature gate 的**预期结果**）。
- **纠正**：7 个文件**并非空壳**——均为完整的功能门控测试套件，`proto3` gate（test_ftp/test_rtp/test_sip 的 `#![cfg(feature = "proto3")]`）对应 Cargo.toml:35 真实 feature。实测 `cargo test --all-features` 七套件全部运行且通过，共 **81 用例**（ftp 4 / quic 18 / rtp 5 / rule 8 / sip 3 / smtp 27 / ssh 16，2026-11-04 实测）。"测试从未在本机验证"不成立——历次 `--all-features` 回归（含 R1 修复后全部轮次）它们都在运行。
- **残余事实（非缺陷，记录备查）**：默认 features 的 CI 绿灯确实不覆盖非默认协议的测试——这是 feature 矩阵的固有语义；需要全量保障时以 `cargo test --all-features` 为准（本项目铁律之一，见 AGENTS.md 常用命令）。
- **结论**：无代码改动；本条从风险清单实质问题降级为体检误诊记录。

## R9【低】CLI 版本号与 crate 版本不一致 —— ✅ 已修复（2026-11-04，用户批准）

- **分类**：[代码明确实现]
- **证据**：原 [src/bin/rdpi.rs:14](file:///d:/rust_code/rDpi/src/bin/rdpi.rs#L14) `version = "0.2.0"` 硬编码，Cargo.toml:3 为 0.4.1。
- **修复**：改为 `env!("CARGO_PKG_VERSION")`——与 crate 版本单一事实来源，后续版本号不再漂移。
- **验证**：`cargo build --features pcap` 通过。

## R12【信息】clippy --all-targets（测试目标）存在历史 lint —— ✅ 已清零（2026-11-04，用户批准"先处理 R12"）

- **分类**：[代码明确实现]
- **证据**：`--all-targets` 实测 **84 处警告 / 约 35 个文件**（比原登记的"约 40 处"多）——且不止测试代码，**lib 生产代码同样有**（ftp/detector、tls/certificate、kerberos、modbus、redis、stun、ntp、wireguard、nfs、mqtt、quic、netflow、rsync、rtmp、socks、syslog、whois 等的 collapsible_if / manual_is_ascii_check / manual_range_contains / single_char_pattern / len_zero 等）。
- **勘误**：此前多轮"clippy 0 警告"的验证结论**不成立**——验证用的 PowerShell `Select-String "^warning"` 模式被 cargo 输出的 ANSI 色码（`ESC[1m…mwarning:`）绕过，从未真正匹配过。教训：CLI 输出校验须用 `--message-format=short` 或落盘后按内容行匹配。
- **修复**：① `cargo clippy --fix --all-features --all-targets`（自动机修，72 处）；② 手工 12 处：redis `find_crlf` 改 `windows(2).position`、tls `parse_client_hello_fields` 提取 `ClientHelloFields` 类型别名、lib.rs 提取 `RiskCallback` 别名、nfs 删除从未被引用的测试辅助 `rpc_reply`、behavioral 3 处 `for` 索引循环改 `slice::fill`、mongodb 5 个测试辅助函数 `isMaster` → `is_master` 重命名（含 detector.rs）。
- **验证**：`cargo clippy --all-features --all-targets` **0 警告**（--message-format=short 落盘复核）；默认 + all-features 全量回归 **0 失败**（22 套件全 ok）；`cargo fmt` 已跑。
- **残留（a3 修复时新发现，2026-11-04）**：默认 features 下 `cargo test` 编译 integration_test 报 1 条 dead_code——[integration_test.rs:307](file:///d:/rust_code/rDpi/tests/integration_test.rs#L307) `build_tcp_packet` 仅被 iot/database 等 feature-gated 测试使用，默认 features 下 unused（R12 清债当时只扫了 `--all-features`）。信息级，暂不修。

## R13【信息】QUIC Initial 解密的能力边界与性能注意（2026-11-04，QUIC 补全功能开发；2026-11-05 服务端方向扩展）

- **背景**：quic feature 下 QuicDetector 对 Initial 包做全手写解密（[src/protocols/quic/crypto.rs](file:///d:/rust_code/rDpi/src/protocols/quic/crypto.rs)，AES-128-GCM + HKDF-SHA256，零新增依赖；RFC 9001 A.1/A.2 官方向量 + 独立 Python 交叉核对的服务端向量验证）。客户端 Initial → ClientHello（QuicMetadata.sni/alpn）；服务端 Initial → ServerHello（仅 alpn，ServerHello 无 SNI）。密钥材料恒取自包头 DCID 字段（客户端包 DCID = ODCID；服务端包 DCID 也是 ODCID——服务端 Initial 的接收方是客户端，DCID 即客户端所选 CID），故 Retry 前后、任一方向均可解。
- **能力边界**：① 仅解密 **Initial** 包（0-RTT/Handshake/1-RTT 密钥不可推导，永不解密）；② 解密失败不产生任何标记，`sni=None` 且 `alpn=None` 即为降级信号；③ QUIC SNI 已覆盖 rule 引擎 `sni_contains`（2026-11-05，[src/lib.rs](file:///d:/rust_code/rDpi/src/lib.rs) 规则分支在 TLS 回退后追加 QUIC Initial 解密回退，需 `rule` + `tls` + `quic` 三 feature）；④ CLI 域名列已支持 `Metadata::Quic`（2026-11-05，QUIC SNI 可打印）。
- **性能注意**：GHASH 已从无查表逐位实现（每块 128 次移位+条件异或）升级为 Shoup 式 4-bit 查表（2026-11-05，[src/protocols/quic/crypto.rs](file:///d:/rust_code/rDpi/src/protocols/quic/crypto.rs) `GhashTable`，8 KiB 栈上表，每块乘法 32 次查表异或，无移位无数据依赖分支）；release 实测 **150 倍加速**（262144 块 339ms → 2.26ms，对照基准 `test_ghash_table_benchmark`，`cargo test --lib --features tls,quic -- --ignored --nocapture` 可复现）。逐位实现保留为测试 oracle（`gf128_mul_reference`，与查表版 200 对伪随机交叉验证）。detect 路径最坏 2 方向 × 4 个 pn 候选 = 8 次 AES 尝试（pn_len=4 时每方向仅 1 个）。

## R10【低】Git 历史存在 9 个内容相同的重复提交

- **分类**：[代码明确实现]
- **证据**：git log 显示 34cc561/11c704e/f877629/d3fb92c/e3272b5/e79df30/e654981/a2a5511/1925b0b/f47da35 均为 "Add TLS certificate parsing … (#38) (#54/#52/…)"，标题相同仅尾号不同。
- **影响**：提示发布流程有重复 PR/merge 操作，历史噪音大，bisect 与回溯成本高。无需处理，记录备查。

## R11【信息】Registry 顺序遍历、首个命中即返回

- **分类**：[代码明确实现]
- **证据**：protocols/mod.rs:134-141,157-161。register_defaults 的顺序即优先级（mod.rs:174-176 注释"按特异性递减"）。
- **影响**：新增 detector 时插入位置直接决定误判/漏判行为——第五步任何"加协议"类改动都必须先复述此影响面。

## F11【中】流级风险双重死路：flow_processors 恒空 + analyze_flow 结果被丢弃 —— ✅ 已修复（2026-11-04，功能开发"风险结果出口"）

- **分类**：[代码明确实现]
- **证据**：① [risk/mod.rs:54-58](file:///d:/rust_code/rDpi/src/risk/mod.rs#L54-L62) `register` 只 push 到 `packet_processors`（注释"也注册到 flow 列表 — 稍后优化"），`flow_processors` 永远为空 → `analyze_flow` 恒返回空；② 唯一调用点 [lib.rs](file:///d:/rust_code/rDpi/src/lib.rs#L443-L451) `let _risks = self.risk_registry.analyze_flow(flow)` 丢弃。结果：BehavioralRiskProcessor 实现的流级风险（UnidirectionalTraffic/ProbingAttempt）从未产出。
- **修复**：① register 同一处理器注册到两个列表（字段改 `Arc<dyn RiskProcessor>`，Box 不可克隆；未实现的方法走 trait 默认空实现，无重复产出）；② `expire_flows` 把流级结果收进 `Detector.pending_risks` 暂存；③ 新增公开 API `Detector::drain_risks() -> Vec<(FlowKey, RiskResult)>`——收割并清空逐包累积 `flow.risks`（顺带解决 a6 无界增长）+ 返回过期流风险；`clear_flows` 同步清暂存。`expire_flows` 返回签名不变（3 个调用方零改动）。
- **验证**：risk/mod.rs 新增双注册单测；test_pin_rules 新增 2 个端到端测试（drain 收割+清空、过期流 ProbingAttempt 可达）；默认与 all-features 全量 0 失败、clippy 0 警告。
- **扩展（2026-11-04，用户批准）**：新增 `Detector::set_risk_callback(Fn(FlowKey, &RiskResult))` 观察者推送模式——逐包/流级风险产生即回调，作为 drain_risks 轮询之外的即时出口（适合告警管道）。回调为观察者语义：不影响拉取路径，两条通道投递相同事件，消费方择一订阅。测试 +2（逐包推送、过期流推送）。探针附带确认：单包未识别流在过期时**同时**命中 UnidirectionalTraffic + ProbingAttempt 两条流级风险（behavioral.rs 阈值叠加，属预期行为，已用断言钉住）。

## 待验证清单（第四步探针测试结果回写，2026-11-04）

> 探针测试落位：[tests/test_pin_rules.rs](file:///d:/rust_code/rDpi/tests/test_pin_rules.rs)（B 类不变量 8 项 + A 类探针/回归 11 项；2026-11-04 第七轮修复后：默认 233 通过、--features risk 273 通过、--all-features 867 通过（7 ignored = test_regression 存量））

| # | 待验证项 | 结果 |
|---|---|---|
| P1 | SNMP use 路径修复后可编译 | ✅ R1 修复时覆盖（all-features 全绿） |
| P2 | IP 猜测方向语义 | ✅ **实锤**：猜测使用【当前包 src_ip】（a4）→ R4 升级为**[代码明确实现]**；**✅ 已修复**（两方向匹配，a4/a4b 均为回归） |
| P3 | sni_contains 规则首包永不命中 | ✅ **实锤且比预期严重**：规则分支中 flow.metadata 恒 None → 规则**永不命中**（p3）→ R6 升级为**[代码明确实现]**；**✅ 已修复**（SNI 回退从当前包提取，p3 为回归） |
| P4 | max_entries 超限行为 | ✅ R2 修复时以 flow.rs 单测覆盖（满载逐出最旧/活跃流存活/命中不逐出/0=不设限） |
| P5 | Confidence::DpiCache/DpiPartial 赋值点 | 未执行（信息级，R4 期间确认 match_domain 用 DpiPartial；仍待做） |
| P6 | 证书字段多包流是否恒 None | ✅ 钉死：恒 None（a2）→ **✅ F3 已修复（2026-11-04）**：回显路径 enrich_tls_cert 一次性富化，a2 翻转为回归；F7 元数据被抹问题亦已修复 |
| P7 | TlsObsoleteVersion 对真实 "TLS 1.0" 是否触发 | ✅ 钉死：不触发（a1/a1_risk），F1 成立 |
| P8 | 连体 ClientHello+Certificate 能否解析证书 | ✅ 钉死：SNI 可解析、证书不可解析（a3）→ **✅ a3 已修复（2026-11-04）**：iter_tls_records 逐记录解析，a3/a3b/a3c 三个回归钉住（ClientHello 连体、ServerHello+Certificate 连体新流、回显富化） |
| P9 | flow.risks 是否逐包无界累计 | ✅ 实测：F7 修复前每包只有 1 条（元数据被抹）；**F7 修复后（2026-11-04）逐包累计**（a6 实测 missing_sni==3），无去重 |
| P10 | version=None 时 JA4 为 None | ✅ 确认（a5） |

### 探针新发现（第四步新增，F9/F10 为第五步修复验证时暴露）

> 更正：R1 修复时"--all-features 636 全绿"的记录不准确——当时验证命令的输出被截断（Select-Object -First 40），掩盖了 test_integration 的存量失败。all-features 的真实基线以 F10 为准。

## F9【中】OpenVpn detector 对 HTTP 文本误报并抢先于 Http —— ✅ 已修复（2026-11-04，用户批准）

- **分类**：[代码明确实现]（实测复现）
- **证据**：`--all-features` 下 `GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n` 被 [src/protocols/openvpn/detector.rs:17-22](file:///d:/rust_code/rDpi/src/protocols/openvpn/detector.rs#L17-L22) 判为 `OpenVpn`（DpiPartial，端口 80 也认领）；注册顺序 openvpn（mod.rs:232）早于 http（234）。根因：`'G'=0x47`，`0x47>>3=8` 恰好命中 P_CONTROL_HARD_RESET_SERVER_V2 的 opcode 判定。
- **修复**：[src/protocols/openvpn/parser.rs](file:///d:/rust_code/rDpi/src/protocols/openvpn/parser.rs) `parse_openvpn` 增加可打印 ASCII 占比校验——占比 ≥ 90% 的 payload 直接拒绝（真实控制消息 bytes 1-8 为 8 字节随机 session_id，可打印占比极低）。**注册顺序未动**（R11 影响面）。
- **验证**：parser 新增 2 个拒绝测试（HTTP GET/POST 文本）；探针 a8 翻转为回归测试 `a8_http_text_not_misdetected_as_openvpn`（断言 Http）；b2/b4 移除 `#[cfg_attr(feature = "vpn", ignore)]`，vpn 下全绿。

## F10【中】all-features 下 test_integration 7 个存量失败：低特异性误报 + 测试计数不同步 —— ✅ 已修复（2026-11-04，用户批准）

- **分类**：[代码明确实现]（实测）；抢答者已逐个定位（临时探针 tests/tmp_probe_f10.rs，用后即删）
- **根因与修复**（三处，均未动注册顺序，R11 影响面）：
  1. **Ftp 抢答 SMTP banner**（3 例失败：test_detection_priority_smtp_vs_http / test_registry_detects_smtp_banner / test_smtp_metadata_through_pipeline / 复合 test_all_protocols_detected）：`220 mail.example.com ESMTP` 以数字开头命中 [ftp/detector.rs:51](file:///d:/rust_code/rDpi/src/protocols/ftp/detector.rs#L51) 的响应判定（`220` 问候码为 FTP/SMTP 共有语法），FTP 注册在 SMTP 之前。修复：F8 同款**端口上下文让位**——ftp/detector.rs `detect_with_context` 对数字响应在 SMTP 端口（25/465/587）返回 None 让位给 SmtpDetector；无上下文 `detect()` 保持默认 FTP（+3 单测）。4 个测试改用 `detect_with_ports(payload, 25, 12345)`。
  2. **Ptpv2 认领 `[0x30,0x02,0x02,0x01]`**（test_snmp_too_short）：[ptpv2/parser.rs](file:///d:/rust_code/rDpi/src/protocols/ptpv2/parser.rs) 旧实现仅看 `data[1] & 0x0f == 2`。修复：增加 messageType 合法值（0x0-0x3 / 0x8-0xD）与 messageLength 自洽校验（≥ 公共头保守下界 32 且 ≤ payload 实际长度）；valid_sample 更新为自洽的 Sync 形态（+3 单测）。
  3. **Tftp 认领 `[0x00,0x01,0x00,0x00,0x00,0x01]`**（test_modbus_too_short）：[tftp/parser.rs](file:///d:/rust_code/rDpi/src/protocols/tftp/parser.rs) 旧实现仅看 opcode ∈ 1..=5。修复：RRQ/WRQ（opcode 1/2）要求可打印非空 filename\0 + mode\0；DATA/ACK/ERROR 结构固定维持 opcode 判定（+3 单测）。
  4. **test_registry_default_detector_count 41≠49**：测试的 cfg 计数表漏记 Phase 12A/11A 后补的 8 个 detector（DHCPv6/VXLAN→infra、L2TP/PPTP→vpn、RADIUS→auth、TURN/MGCP/H323→voip），按 register_defaults 实况修正为 49。
- **验证**：`cargo test --all-features --test test_integration` **72 passed / 0 failed**（此前 65/7）；默认全量与 all-features 全量回归绿。

## F8【中】FTP detector 抢答 POP3 流量：`USER test@example.com` 被识别为 Ftp 而非 Pop3

- **分类**：[代码明确实现]（实测）
- **证据**：`tests/integration_test.rs:119` `test_end_to_end_pop3_client_command` 断言 Pop3，实测返回 Ftp（left: Ftp, right: Pop3）。`USER` 命令为 FTP 与 POP3 共有语法；FTP detector 在 POP3 之前注册（protocols/mod.rs register_defaults 顺序）。
- **首次暴露时间**：2026-11-04 R1 修复后——此前 `--all-features` 编不过，mail/pop3 测试从未运行。
- **修复**：✅ 已修复（2026-11-04，用户批准）。方案：**端口上下文让位**——[src/protocols/ftp/detector.rs](file:///d:/rust_code/rDpi/src/protocols/ftp/detector.rs) 新增 `detect_with_context`：FTP/POP3 共有命令（`FTP_POP3_AMBIGUOUS_VERBS` = USER/PASS/QUIT/RETR/DELE/STAT/NOOP/LIST）出现在端口 110/995 时返回 None 让位给 Pop3Detector；FTP 独有命令不受影响；**注册顺序未动**（R11 影响面）。无端口上下文的 `detect()` 保持默认 FTP（钉住现状语义）。
- **验证**：ftp/detector.rs +4 单测（让位/FTP端口保持/独有命令/无上下文默认）；integration_test.rs pop3_user 与 test_integration.rs:875 改用 `detect_with_ports`；新增正面钉住 `test_end_to_end_ftp_user_command_on_ftp_port`（端口 21 → Ftp）。默认全量 272 绿；all-features test_integration 65 过。

## F6【中】DNS detector 误报：非 DNS 二进制载荷被判为 Dns —— ✅ 已修复（2026-11-04，用户批准）

- **分类**：[代码明确实现]（探针实测）；根因定位：**[代码明确实现]**
- **证据**：`a7_pure_certificate_record_misdetected_as_dns`：payload `16 03 03 00 0c 0b ...`（TLS Certificate 记录头 + 假 DER，17 字节）被判 `Some(Dns)`。根因三连：① 原检测仅有 opcode/rcode 范围检查（dns/detector.rs:37），载荷的 TLS record 长度字段 `0x0c0b` 被读成 qdcount=3083；② 问题区可行性从未校验；③ qname 为空/含二进制也被接受（parse_name 返回 ""）。
- **修复**：[dns/detector.rs:41-67,75-78](file:///d:/rust_code/rDpi/src/protocols/dns/detector.rs#L41-L67) ① 问题区可行性校验——每条 question 至少 5 字节（≥1 字符标签 + \0 + qtype 2 + qclass 2），`12 + qdcount*5 > payload.len()` 即拒绝；② qdcount>0 但 qname 不可解析/为空/含不可打印 ASCII → 整体拒绝（真实 DNS 的问题区总是可解析）。opcode/rcode 判定与 qdcount=0 响应路径未动（不在证据范围）。
- **验证**：detector +4 单测（假 Certificate 拒绝/空 qname 拒绝/合法查询保留/非打印 qname 拒绝）；探针 a7 翻转为回归（断言 None）。默认 233 / risk 273 / all-features 867 全绿。

## F7【高】流已识别后每个后续包把 flow.metadata 覆盖为 None，风险处理器从第二包起全部失效 —— ✅ 已修复（2026-11-04，用户批准）

- **分类**：[代码明确实现]
- **证据**：流已识别时回显结果 `flow.protocol.map(...)`（原 [lib.rs:316-319](file:///d:/rust_code/rDpi/src/lib.rs#L316-L319)），`DetectionResult::new` 的 metadata 默认 `Metadata::None`（[types.rs:500](file:///d:/rust_code/rDpi/src/core/types.rs#L500)）；随后 [lib.rs:327-329](file:///d:/rust_code/rDpi/src/lib.rs#L327-L329) 无条件 `flow.metadata = Some(r.metadata.clone())` → 长流第二包起元数据被抹成 `Some(Metadata::None)`。
- **修复**：[lib.rs:316-328](file:///d:/rust_code/rDpi/src/lib.rs#L316-L328) 回显分支携带 `flow.metadata`（`r.metadata = m.clone()`）。效果：① risk 处理器（tls/dns/http，依赖 flow.metadata）从第二包起恢复逐包生效；② `Detector::flows()` 读到的长流元数据持久。**协议一次定型语义未动**（ADR-0004，已同步）。
- **验证**：b4 改断言元数据随回显持久（Http host 保留）；a2 改断言 Some(Tls) 且 F3 证书字段仍 None（F3 未修，另案）；a6 risk 计数 1→3（P9 原断言恢复）；ADR-0004/0006 已更新。`--features risk` 15 测试 + all-features 全量回归绿。
