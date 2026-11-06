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

## R14【信息】HTTP/2 元数据提取的能力边界（2026-11-05，HTTP/2 元数据功能开发）

- **背景**：proto3 feature 下 Http2Detector 在 preface 命中时顺带提取首个请求 HEADERS 帧（HPACK 解码，RFC 7541），提取 `:authority`/`:method`/`:path` 写入 `Metadata::Http2`；preface 包内无 HEADERS 时由定型流富化路径补齐（[src/lib.rs](file:///d:/rust_code/rDpi/src/lib.rs) `enrich_http2_headers`，对齐 enrich_tls_cert / ADR-0004 一次定型语义）。Huffman 解码（257 符号码表，nghttp2 与 Go x/net 双源逐项交叉验证 + Kraft 精确和 + 前缀无冲突）、静态表 61 项、前缀整数解码均为手写，零新增依赖。
- **能力边界**：① **无状态设计**——只解码首个客户端 HEADERS 帧（连接级动态表在该帧解码时必为空，帧内自洽），不维护跨包 HPACK 状态；后续请求帧不再提取。② **CONTINUATION 跨帧不重组**——头块若被拆分到 CONTINUATION 帧（type=0x09），解码失败返回 None，元数据保持为空。③ **帧截断即放弃**——HEADERS 帧体被 TCP 分段切开时（[src/protocols/http2/parser.rs](file:///d:/rust_code/rDpi/src/protocols/http2/parser.rs) `pos + len > body.len()`）返回 None，等后续包（同流富化路径每包重试直至填充）。④ 服务端响应帧（仅 `:status` 伪头部）不提取。⑤ 单包最多扫描 8 帧（MAX_FRAMES）防热路径拖慢。
- **验证**：`cargo test --features proto3 --test test_http2`（9 测试：分包富化、回显保持、响应帧不误写）+ hpack 单元 12 测试（RFC C.4.1 官方向量）全绿；三配置回归（默认 / --all-features / --features risk）0 失败。

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

## F12-F27【高×5 / 中×11】误报面审计：16 个低特异性 detector 判定收紧 —— ✅ 全部已修复（2026-11-05，用户批准"全部 16 项"）

> 背景：F6/F8/F9/F10 修复先例的系统性推广。通读全部 49 个协议 detector 源码后汇总（高风险 5 + 中风险 11），**注册顺序一律未动**（R11 影响面），均为单 detector payload 判定收紧 + 误报探针测试固化（每模块 2-5 个"旧判定命中、新判定拒绝"探针）。已达标未动的协议：dns/tftp/ptpv2（F6/F10 已收紧）、stun/dhcp/snmp/modbus/mongodb/rdp/ssh/mysql/nfs/ntp/mgcp/rsync/vnc/rtp。

| ID | Detector | 原判定缺陷 | 修复后判定 | 证据 |
|---|---|---|---|---|
| F12【高】 | pptp | `data[0..2]==0x0001`：真 PPTP 控制报文首 2 字节是长度字段，**永远匹配不到真报文**（假阴），同时任意 0x0001 前缀二进制被认领（假阳） | RFC 2637：`len>=8 && data[2..6]==0x1A2B3C4D`（Magic Cookie） | [pptp/parser.rs](file:///d:/rust_code/rDpi/src/protocols/pptp/parser.rs) |
| F13【高】 | whois | payload 全可打印 ASCII 即命中——任何幸存到尾部的文本流量全被认领 | `5..=1000` 全可打印 + 末字节 `\n` + 首行 ≤255 | [whois/parser.rs](file:///d:/rust_code/rDpi/src/protocols/whois/parser.rs) |
| F14【高】 | socks | 首字节 0x04/0x05 即命中（1/256 二进制误报面） | v5：`nmethods>=1 && 2+nmethods<=len`；v4：`len>=8 && cmd∈1..=4` | [socks/parser.rs](file:///d:/rust_code/rDpi/src/protocols/socks/parser.rs) |
| F15【高】 | rtmp | 首字节 0x03 即命中；真握手 C0+C1 共 1537 字节 | `data[0]==0x03 && len>=1537` | [rtmp/parser.rs](file:///d:/rust_code/rDpi/src/protocols/rtmp/parser.rs) |
| F16【高】 | ldap | `data[0]==0x30 && contains(0x60)`——任意含 0x60 的 BER 系二进制命中；LDAP 注册在 mysql/postgresql 之前会抢答数据库流量 | RFC 4511 BindRequest 结构逐字段：SEQUENCE 长度自洽 + msgID INTEGER + 0x60 tag + version INTEGER | [ldap/parser.rs](file:///d:/rust_code/rDpi/src/protocols/ldap/parser.rs) |
| F17【中】 | telnet | 仅首字节 0xFF | `data[1]∈0xFA..=0xFE`（IAC 协商命令 SB/WILL/WONT/DO/DONT） | [telnet/parser.rs](file:///d:/rust_code/rDpi/src/protocols/telnet/parser.rs) |
| F18【中】 | h323 | 仅首字节 0x08（1/256） | TPKT 形态（长度自洽 + data[4]==0x08）或裸 Q.931（call-ref 长度 ≤2） | [h323/parser.rs](file:///d:/rust_code/rDpi/src/protocols/h323/parser.rs) |
| F19【中】 | vxlan | 仅 flags==0x0800 | 保留位 3 字节必须全 0 | [vxlan/parser.rs](file:///d:/rust_code/rDpi/src/protocols/vxlan/parser.rs) |
| F20【中】 | syslog | `<PRI>` 接受任意位数数字 | PRI 1-3 位且 ≤191（RFC 3164） | [syslog/parser.rs](file:///d:/rust_code/rDpi/src/protocols/syslog/parser.rs) |
| F21【中】 | turn | 仅 channel 码范围（1/8 二进制命中面） | RFC 5766 长度自洽：`4+msg_len<=len && msg_len>=1` | [turn/parser.rs](file:///d:/rust_code/rDpi/src/protocols/turn/parser.rs) |
| F22【中】 | radius | `data[1]==0x01` 为 bogus 约束（packet id 是随机的，**99.6% 真实流量漏判**）且无长度校验 | `code∈1..=50 && pkt_len==len && len>=20`（删除 bogus 约束） | [radius/parser.rs](file:///d:/rust_code/rDpi/src/protocols/radius/parser.rs) |
| F23【中】 | netflow | 仅版本前缀 0x0005 | v5 结构自洽：`count∈[1,30] && len>=24+count×48`（RFC 3954） | [netflow/parser.rs](file:///d:/rust_code/rDpi/src/protocols/netflow/parser.rs) |
| F24【中】 | bgp | 16×0xFF marker + type，长度字段未自洽 | `msg_len>=19 && msg_len<=len` | [bgp/parser.rs](file:///d:/rust_code/rDpi/src/protocols/bgp/parser.rs) |
| F25【中】 | postgresql | 长度字段未自洽 | `pg_len==len && pg_len>=9` | [postgresql/parser.rs](file:///d:/rust_code/rDpi/src/protocols/postgresql/parser.rs) |
| F26【中】 | dhcpv6 | `data[1]==0x01` 为 bogus 约束（事务 ID 是随机的，**99.6% 真实流量漏判**） | RFC 8415 结构下界：type 1-11→len≥10、12→≥40、13→≥23 | [dhcpv6/parser.rs](file:///d:/rust_code/rDpi/src/protocols/dhcpv6/parser.rs) |
| F27【中】 | websocket | `to_lowercase()` 在 detect 热路径堆分配（违反铁律 2，存量问题） | 零分配 `contains_case_insensitive` 字节级 ASCII 折叠扫描，语义不变 | [websocket/parser.rs](file:///d:/rust_code/rDpi/src/protocols/websocket/parser.rs) |

- **验证**：三配置全量回归绿（默认 104 lib 套件全绿 / risk 142 / all-features 677 lib + test_integration 72 + test_regression 8 全绿，0 failed）；`cargo clippy --all-features --all-targets` 0 警告（顺带清掉 netflow 本轮引入 + hpack.rs:568 上轮遗留两处）；`cargo fmt --check` 干净。
- **注意**：F22/F26 属"假阴修复"（删除 bogus 约束后真实流量检出率大幅提升），但 F26 的 len≥10 下界对 4-9 字节的畸形 DHCPv6 极端样本仍会漏判（真实 DHCPv6 至少含 Client-ID option，实际影响趋近于零）。

## F28【信息】QUIC Initial 解密路径优化：密钥缓存 + GHASH 线性候选比对（2026-11-05，性能优化功能开发）—— ✅ 已完成

- **背景**：performance.md 基线显示 `detect_quic_initial_decrypt` 25.6µs 是唯一显著开销项（R13）。开销构成：每包 × 每方向 × 每 pn 候选（pn_len<4 时最多 4 个，最坏 8 次 AES 尝试）都完整重做 HKDF-SHA256 密钥派生 + AES key expansion + GHASH 表构建 + 全量 GHASH/CTR。
- **修复**（两层次，[src/protocols/quic/crypto.rs](file:///d:/rust_code/rDpi/src/protocols/quic/crypto.rs)）：
  1. **密钥缓存**：`InitialKeyCache`（`Mutex<HashMap<CacheKey, PreparedInitialKeys>>`，CacheKey = 版本+方向+DCID 拼接 23B 数组）——HKDF 派生、AES 轮密钥（key_rk/hp_rk 各 176B）、GHASH 前置准备每 (version, side, DCID) 只做一次；上限 1024 条超限整体 `clear()` 防无界内存；锁中毒降级 `poisoned.into_inner()`。QuicDetector 实例持有缓存（[src/protocols/quic/mod.rs](file:///d:/rust_code/rDpi/src/protocols/quic/mod.rs)），流内命中即免派生；无缓存公开 API 保留（rule 引擎 QUIC SNI 回退等调用方不变）。
  2. **候选解密分层**：**候选 0（raw pn）直接对真实 pn 字节做全量 GHASH + tag 比对**——握手期 raw pn 几乎恒为真实 pn，该路径与旧实现同价（还省掉旧实现 aes128_gcm_decrypt 内的第三次 key_expansion）。仅候选 0 miss 且 pn_len<4 时才启动预检机制：利用 GF(2^128) 线性性预计算"pn 置零 GHASH 和 + H^w 权重表"，pn 字段（≤4B）至多横跨最后两个 AAD 块，候选 1-3 各仅 1 次 GF 乘 + 1 次 AES 块完成 tag 预检，命中才全量 CTR——最坏 4 候选从 4 次全量解密降为 1 次全量 + 3 次轻量预检。AAD 跨块边界逐字节归块（pn 横跨两 AAD 块时用双权重表）。
- **实测教训（基准驱动修正）**：首版设计把预检机制无条件用于全部候选，权重链 H^w_last 需 w≈74 次表乘 + 两张 8KiB 权重表构建，在候选 0 恒命中的常见路径上纯属白付——冷解密 25.6→28.5µs（**+10.7% 回归**，criterion 实测抓获）。改为"候选 0 直通 + miss 才预计算"后冷解密 **23.3µs（较旧基线 -9%）**。教训：性能优化的预计算成本必须放在低频分支。
- **影响面复述**：注册顺序未动（R11）；解密结果与旧路径逐字节一致（RFC 8439/9001 官方向量 + 往返测试覆盖）；detect 路径无新增堆分配（缓存条目按值克隆，仅首次派生时分配）。
- **验证**：crypto 单元 16 测试全绿（含缓存命中一致性/异键隔离/容量上界/缓存与无缓存解密一致/pn_len 1-3 候选往返 5 个新测试）；quic lib 161 + test_quic 集成 29 全绿。基准（`detect_quic` 过滤，本机）：冷解密 25.6→23.3µs（-9%）；新增稳态基准 `detect_quic_initial_decrypt_steady_100` 0.574µs/包（第 1 包解密、其余回显）；`detect_quic_header_only` 4.12→5.24µs 为合成最坏情形（pn_len<4 永久解密失败包付候选 0 miss 预计算成本，真实流第 1 包即定型不再触发，已接受），详见 [performance.md](file:///d:/rust_code/rDpi/docs/architecture/performance.md)。

## F29【中】miss 路径全 Registry 遍历：首字节门预筛（2026-11-05，性能优化功能开发）—— ✅ 已完成

- **背景**：performance.md 基线显示 `detect_unknown_tcp_miss_100` 1.737µs/包为最坏路径——DPI 阶段每包线性遍历 49 个 detector（[protocols/mod.rs](file:///d:/rust_code/rDpi/src/protocols/mod.rs) `register_defaults`，R11 顺序语义）。绝大多数 detector 对 `payload[0]` 的取值有硬约束（如 TLS 0x16、MQTT 0x10-0x1F、BGP 0xFF），却仍要逐个执行判定逻辑。
- **机制**：`ProtocolDetector` 新增默认方法 `first_byte_gate() -> Option<&'static [(u8, u8)]>`（含区间闭区间对，`None` = 首字节任意、不参与预筛）；`Registry::register` 在**注册期**预计算每 detector 的 `[u64; 4]` skip 位图（256 位，区间外字节置位）；`detect()` / `detect_with_ports()` 循环内对非空 payload 做一次位测试跳过（零分配）。检测结果语义、回显路径、R11 注册顺序全部未动。
- **审计覆盖**：49 个 detector 全量实锤逐文件核验（36 个声明门 / 13 个保持 `None`）。保持 `None` 的均有硬证据：dns/mongodb/postgresql/stun/modbus（首字段任意）、l2tp/pptp/ike/nfs（长度/cookie/xid 任意）、whois/websocket（自由文本/子串匹配）、pop3/imap（端口 995/993 下空载荷也无条件命中——[pop3/detector.rs](file:///d:/rust_code/rDpi/src/protocols/pop3/detector.rs)、[imap/detector.rs](file:///d:/rust_code/rDpi/src/protocols/imap/detector.rs) `detect_with_context`，跳过会引入假阴）。审计中纠正了三处规划期错误：modbus 首字节是 Transaction ID（任意，不可门）、ntp 门区间为 VN 字段非零（每 64 块 0x08-0x27）、turn 上界 0x7F（ChannelData 0x7FFE 可达）。
- **语义契约（铁律）**：声明非 `None` 即承诺「`payload[0]` 不在区间内 ⇒ detect 必返回 None」。违反将产生**假阴**（真实流量被预筛跳过）。新增 detector 必须显式声明门或有意返回 `None` 并说明原因。
- **影响面复述**：注册顺序未动（R11）；detect 路径零新增分配（位图注册期构建、循环内仅位测试）；空 payload 不参与预筛（各 detector 空载荷语义不变）；默认门全 `None` 的第三方 detector 行为不变。
- **验证**：机制测试 5 项（位图边界/上界含 0xFF/门跳过与放行/空载荷不跳过/无门不跳过）+ 每 detector `test_first_byte_gate_covers_valid_sample` 36 项（合法样本首字节必须落在自声明门内，假阴防护）共 41 项新增，默认 263 / all-features 1064 / risk 308 全绿；clippy --all-features --all-targets 0 警告。基准（同机紧凑 A/B，`cargo bench --features quic -- detect_unknown_tcp_miss_100`）：门 OFF 190.6µs → ON 167.1µs/100 包（**-12.3%**）；新增平均场景基准 `detect_unknown_tcp_miss_varied_100`（100 互异首字节）175.4µs。注意该基准 100 包中仅前 ~19 包走 DPI 扫描（giveup=20 后 GuessEngine 接管，[lib.rs:352](file:///d:/rust_code/rDpi/src/lib.rs#L352)），扫描段实际收益约 -55%（折算每扫描包省 ~1.24µs）；跨 criterion 调用的机器噪声 ±7%，结论以同机 A/B 为准。

## F30【中】JA4S 服务端 TLS 指纹（2026-11-05，新功能开发）—— ✅ 已完成

- **背景**：JA4 客户端指纹已有（application/ja4.rs），但服务端无对应指纹。FoxIO JA4+ 家族的 JA4S 基于 ServerHello（服务端对 ClientHello 的应答：从客户端列表中**选定**的一个 cipher + 服务端自己的扩展集合），与 JA4 配对可定位「客户端软件 ↔ 服务端软件」组合。
- **规格来源**：FoxIO 官方 [ja4.py](https://github.com/FoxIO-LLC/ja4) `to_ja4s` + common.py（BSD-3/FoxIO 许可），格式 `{t|q}{版本2位}{扩展数2位}{alpn 2字符}_{cipher 4hex}_{sha256扩展串前12hex}`。与客户端 JA4 的关键差异：扩展按服务端发送顺序哈希**不排序**、**不过滤 GREASE**（官方 to_ja4s 路径无 GREASE 过滤，区别于 to_ja4；flowscope 参考实现过滤 GREASE，此处以官方 ja4.py 为准）；版本优先 supported_versions 扩展（GREASE 防御性忽略）回退 legacy_version；无 ALPN 记 `00`、>2 字符取首尾（`http/1.1`→`h1`）、首字符非 ASCII 记 `99`；空扩展列表哈希为固定 12 个 0。
- **实现**：
  - [tls/parser.rs](file:///d:/rust_code/rDpi/src/protocols/tls/parser.rs) `parse_server_hello` → `ServerHelloInfo{legacy_version, cipher_suite, extensions, alpn, supported_version}`（RFC 8446 §4.1.3 结构自洽校验；`parse_server_hello_alpn` 改为其 ALPN 单字段视图）。
  - [tls/mod.rs](file:///d:/rust_code/rDpi/src/protocols/tls/mod.rs) TLS detector 记录循环新增 ServerHello 分支：提取协商版本/ALPN/JA4S。**影响面**：纯 ServerHello 的服务端流自此可定型为 Tls（此前服务端明文首包无 CH/Certificate 时返回 None，TLS 1.3 下证书已加密、服务端流实际永远无法 DPI 定型——此为补识别缺口非扩大误报面：0x16 + msg_type=2 + 结构校验，特异性极高）；注册顺序未动（R11）；TLS 门 0x16 已覆盖 ServerHello（门契约不变）。
  - [application/ja4.rs](file:///d:/rust_code/rDpi/src/application/ja4.rs) `compute_ja4s`（与客户端 compute_ja4 同文件同风格）。
  - [quic/parser.rs](file:///d:/rust_code/rDpi/src/protocols/quic/parser.rs) `decrypt_server_hello_meta[_with_cache]`：服务端 Initial 解密后从 CRYPTO 帧还原 ServerHello 全字段（复用 F28 密钥缓存）；`try_extract_tls_meta` 元组扩至 6 项（sni/alpn/ja4/application/tp/ja4s），QUIC 服务端方向产出 q 前缀 JA4S。
  - [lib.rs](file:///d:/rust_code/rDpi/src/lib.rs) `enrich_tls_ja4s`：已定型 TLS 流回显路径对 ServerHello 记录做一次性富化（对齐 enrich_tls_cert 先例，ADR-0004 协议不重检）。
  - Metadata：`TlsMetadata.ja4s` / `QuicMetadata.ja4s`（types.rs）。
- **测试**：compute_ja4s 6 项（TCP/QUIC golden 向量、顺序敏感性、版本全表、ALPN 编码、GREASE 回退+空列表）；parse_server_hello 2 项（字段/拒绝）；Detector 全链路 2 项（反向服务端流定型+回显持久、一次性富化不覆盖 SNI）；QUIC 2 项（decrypt_server_hello_meta 字段、检测级 ja4s=q1302h3_1301_…）。**golden 向量 SHA-256 前缀经 PowerShell .NET SHA256 独立实现交叉验证**（同 QUIC Retry 向量做法）。共 12 项新增，默认 274 / all-features 1076 / risk 319 全绿；clippy --all-features --all-targets 0 警告。
- **已知边界**：TCP ServerHello 跨 TCP 分段无重组支持（尽力而为，与 ClientHello 同策略）；QUIC 服务端 Initial 在服务端→客户端方向为独立流（FlowKey 按五元组方向），JA4 落客户端流、JA4S 落服务端流，与 FoxIO 方向语义一致。

## F31【中】JA4H 客户端 HTTP 指纹（2026-11-05，新功能开发）—— ✅ 已完成

- **背景**：JA4 家族第三个成员（JA4 客户端 TLS + JA4S 服务端 TLS 已有，F30）。JA4H 基于 HTTP 请求行 + 头部集合指纹化客户端软件，纯热路径、零解密、无新依赖。
- **规格来源**：FoxIO 官方 [ja4h.py](https://github.com/FoxIO-LLC/ja4) `to_ja4h`（FoxIO License 1.1），格式 `{方法小写前2位}{版本2位}{c|n}{r|n}{头部数2位}{语言4位}_{头部哈希12hex}_{cookie字段哈希}_{cookie值哈希}`。与 TLS 侧指纹的关键差异：头部名按**发送顺序**哈希（不排序）、保留原始大小写；Cookie/Referer 头不参与计数与哈希（仅作 c/r 标志）；cookie 字段/值按字段名**排序**后哈希（无 cookie 记 12 个 0）；语言取 Accept-Language 首项（去 `-`、截 `;q=`、小写、4 位右补 0），缺省 `0000`；空头部哈希为 sha256("") 而非固定 0。**header_len 与 lang 之间无分隔符**（实测易错点）。
- **实现**：
  - [http/parser.rs](file:///d:/rust_code/rDpi/src/protocols/http/parser.rs) `parse_header_lines` → `HeaderLine{name, value}`（原始大小写保留、去空白、空行终止、畸形行跳过）。
  - [application/ja4.rs](file:///d:/rust_code/rDpi/src/application/ja4.rs) `compute_ja4h(method, version, headers)`（与 ja4/ja4s 同文件）。
  - [http/detector.rs](file:///d:/rust_code/rDpi/src/protocols/http/detector.rs) 请求分支计算 JA4H；响应分支恒 None。HTTP/2 请求（proto3 路径）不产出 JA4H——h2 需 HPACK 全量头部解码，超出现有解析器范围（官方版本码 "20" 预留，compute_ja4h 支持 h2 输入）。
  - Metadata：`HttpMetadata.ja4h`（types.rs）。
- **测试**：compute_ja4h 7 项（基础 GET/POST+cookie+referer+语言 golden 向量、cookie 顺序不敏感、头序敏感、版本编码、语言补齐、伪头部排除）；parse_header_lines 3 项；Detector 级 4 项（请求携带/响应 None/cookie 语义/全链路回显持久）。**golden 向量经 PowerShell .NET SHA256 独立实现交叉验证**（同 F30 做法）。共 14 项新增，默认 288 / all-features 1090 / risk 333 全绿；clippy --all-features --all-targets 0 警告。
- **已知边界**：头部区域跨 TCP 分段仅解析当前包内完整行（与 SNI 同策略）；识别仅在流首请求包发生（流协议一次定型），中间流已定型后新请求不再重算——与流模型语义一致。

## F32【中】JA4X X.509 证书指纹（2026-11-05，新功能开发）—— ✅ 已完成

- **背景**：JA4 家族第四个成员（JA4 客户端 TLS + JA4S 服务端 TLS（F30）+ JA4H 客户端 HTTP（F31）已有）。JA4X 基于证书内 issuer/subject DN 的 OID 序列与扩展 OID 序列指纹化证书本身，复用既有 asn1 BER 解析与 F3 证书富化路径，无新依赖。
- **规格来源**：FoxIO 官方 [rust/ja4x](https://github.com/FoxIO-LLC/ja4)（权威实现，ja4x.py 语义等价），格式 `{issuer哈希12hex}_{subject哈希12hex}_{扩展哈希12hex}`。每段为 SHA-256 前 12 位，输入为 OID **DER 内容字节**的小写 hex 逗号拼接（如 commonName 2.5.4.3 → "550403"），按证书 DER 出现顺序不排序；issuer/subject 取 Name 全部 AttributeTypeAndValue（含国家/组织，不过滤）；扩展取 TBSCertificate `[3]` 中各 Extension 的 extnID；**空列表记 12 个 0**（官方 hash12 语义，区别于 JA4/JA4S 的 sha256("")）。
- **实现**：
  - [application/ja4.rs](file:///d:/rust_code/rDpi/src/application/ja4.rs) `compute_ja4x(issuer_oids, subject_oids, extension_oids)` + `hash12_oids`（与 ja4/ja4s/ja4h 同文件）。
  - [tls/certificate.rs](file:///d:/rust_code/rDpi/src/protocols/tls/certificate.rs) `extract_dn` 扩展为同时返回 OID 内容字节列表（单次遍历）；新增 `extract_extension_oids`（`[3] EXPLICIT` 双层解封装：A3 → SEQUENCE OF → Extension → extnID）；`CertInfo.ja4x` 解析期一次算好。
  - 接入：tls detector 识别路径（tls/mod.rs，`cert_ja4x` 计入非空判定）+ [lib.rs](file:///d:/rust_code/rDpi/src/lib.rs) `enrich_tls_cert` 回显一次性富化（对齐 ADR-0004，协议不重检）。
  - Metadata：`TlsMetadata.cert_ja4x`（types.rs，json feature 随 derive 序列化）。
- **测试**：compute_ja4x 4 项（**官方 FoxIO rust/ja4x hash12 黄金向量** `hash12("551d0f,551d25,551d11")="aae71e8db6d7"`、空列表全零、DN OID 编码、顺序敏感）；certificate.rs 2 项（CN-only golden 向量、v3 扩展证书）；tests/test_tls.rs 2 项（纯 Certificate 记录定型 TLS + cert_ja4x、enrich 一次性富化 + SNI 保持 + 回显持久）。golden 向量经 PowerShell .NET SHA256 独立交叉验证。共 8 项新增，默认 296 / all-features 1098 / risk 341 全绿；clippy --all-features --all-targets 0 警告。
- **已知边界**：扩展 OID 跨包分段随整个证书解析失败而放弃（与既有证书解析同策略）；QUIC 证书在加密握手包内，本路径不覆盖（QUIC 侧无证书解析）；多值 RDN（SET 内多属性）按属性顺序逐个收集，与官方 tshark 抽取的计数口径一致。测试构造器教训：DER 长度 ≥ 0x80 必须用长格式（`0x81` 前缀），单字节直写 0x8x 会被解码器按 long-form 误读（`0x8a` = 长 10 字节）。

## F33【中】JA4T 客户端 TCP 指纹（2026-11-05，新功能开发）—— ✅ 已完成

- **背景**：JA4 家族第五个成员（JA4/JA4S TLS（F30）+ JA4H HTTP（F31）+ JA4X 证书（F32）已有）。JA4T 基于 TCP 初始 SYN 头部字段（窗口/选项序列/MSS/缩放因子）指纹化客户端操作系统/协议栈，纯传输层、零解密、无新依赖，且不依赖任何协议 feature。
- **规格来源**：FoxIO 官方 [rust/ja4 tcp.rs](https://github.com/FoxIO-LLC/ja4) 的 `to_ja4t`，格式 `{window}_{options}_{mss}_{window_scale}`（官方示例 `64240_2-1-3-1-1-4_1460_8`）。触发语义：仅**初始 SYN**（flags SYN=0x02 置位且 ACK=0x10 清零；SYN+ECN 0xC2 满足，SYN-ACK 0x12 不满足），每流只取第一个满足的包。字段语义：window 为 TCP 头原始值（不按缩放因子换算）；options 为选项 kind 序列按序 dash 连接（含 NOP=1，EOL=0 终止，空记 "00"）；mss 缺省 0、`%02` 最少两位（9→"09"）；wscale 为 0（含缺省）记 "00"、非 0 记原值。
- **实现**：
  - [parser/tcp.rs](file:///d:/rust_code/rDpi/src/parser/tcp.rs) 新增 `TcpHeaderInfo`（flags/window/option_kinds[40]/mss/window_scale，手写 Default——`[u8;40]` 超 derive 上限）：选项区逐选项单遍走查，畸形长度立即终止，EOL 填充不计 kind；固定容量栈结构，解析零堆分配（热路径铁律 2）。`ParsedPacket.tcp: Option<TcpHeaderInfo>`（parser/mod.rs，`pub use tcp::TcpHeaderInfo`）。
  - [application/ja4.rs](file:///d:/rust_code/rDpi/src/application/ja4.rs) `compute_ja4t(window, option_kinds, mss, window_scale)`（与 ja4/ja4s/ja4h/ja4x 同文件，应用模块重导出）。
  - [lib.rs](file:///d:/rust_code/rDpi/src/lib.rs) detect 主流程：`flow.ja4t.is_none()` 且当前包为初始 SYN 时一次性计算写入 `Flow.ja4t`（core/flow.rs 新字段）——**流级旁路字段，不占用 protocol/metadata 一次定型语义**（若 SYN 写 protocol 会阻断后续 TLS ClientHello 识别）；`DetectionResult.ja4t`（types.rs 新字段）在结果落库处统一携带（回显/规则/DPI/guess 全分支覆盖）。
  - CLI：文本输出追加 ` ja4t=...`（rdpi.rs print_detection）；json feature 随 DetectionResult derive 自动序列化。
- **测试**：compute_ja4t 3 项（官方 3 向量 `8192_00_00_00`/`5744_2-4-8-1-3_1436_00`/`8192_2_09_00` 直证 + Windows 11 形态 + 补零语义）；parser/tcp.rs 5 项（字段提取/无选项/EOL 填充/畸形长度/截断）；tests/test_ja4t.rs 6 项（SYN 捕获、回显携带且不覆盖、SYN-ACK 不触发但后续 SYN 捕获、SYN+ECN、无 SYN 不产出、每流取第一个 SYN）。JA4T 无哈希段（纯格式化），无需 SHA256 交叉验证。共 14 项新增，默认 310 / all-features 1112 / risk 355 全绿；clippy --all-features --all-targets 0 警告。
- **已知边界**：官方 rust/ja4 仅实现 JA4T（客户端 SYN），JA4TS（服务端 SYN-ACK）官方未实现——本轮对齐官方只做 JA4T，服务端指纹留待官方规格落地；窗口缩放后实际窗口（window << wscale）不在指纹内（与官方一致，用原始值）；IP 分片 TCP 头仅首个分片含选项，重组层不感知（parse_packet 不做 IP 重组，分片包按独立处理）；测试教训：FlowKey 为方向性五元组，SYN 与 SYN-ACK 属不同流（tests/test_ja4t.rs 按方向断言）。

## F34【中】JA4TS 服务端 TCP 指纹（2026-11-06，新功能开发）—— ✅ 已完成

- **背景**：F33 已知边界兑现——JA4T 之外补齐服务端指纹 JA4TS（服务端 SYN-ACK 头部字段指纹化服务器操作系统/协议栈）。与 JA4T 同为纯传输层、零解密、无新依赖、不依赖任何协议 feature。
- **规格来源**：FoxIO 官方 rust/ja4 至今未实现 JA4TS（F33 已登记）；本轮以官方 [zeek/ja4t/main.zeek](https://github.com/FoxIO-LLC/ja4)（JA4TS_enabled 分支）为权威：格式与 JA4T **完全一致** `{window}_{options}_{mss}_{window_scale}`，差异仅在触发语义——`flags` **精确等于** `SYN|ACK`（0x12；SYN|ACK|PSH 等带额外标志位的包不触发，区别于 JA4T 的位测试判定），取第一个满足的 SYN-ACK。
- **实现**：
  - [application/ja4.rs](file:///d:/rust_code/rDpi/src/application/ja4.rs) `compute_ja4ts(window, option_kinds, mss, window_scale)`：直接委托 `compute_ja4t`（格式同源，命名独立以固定语义锚点），应用模块重导出。
  - [lib.rs](file:///d:/rust_code/rDpi/src/lib.rs) detect 主流程：JA4T 捕获块之后并列 JA4TS 捕获块——`flow.ja4ts.is_none()` 且 `tcp.flags == 0x12` 时一次性计算写入 `Flow.ja4ts`（core/flow.rs 新字段）。FlowKey 方向性：SYN-ACK 落在服务端方向流（与客户端 SYN 属两条流），互不干扰；**流级旁路字段，不占用 protocol/metadata 一次定型语义**。复用 F33 的 `TcpHeaderInfo`，本轮未改 ParsedPacket。
  - `DetectionResult.ja4ts`（types.rs 新字段）：规则分支与结果落库处统一携带（回显/DPI/guess 全分支覆盖）。
  - CLI：文本输出追加 ` ja4ts=...`（rdpi.rs print_detection）；json feature 随 derive 自动序列化。
- **测试**：tests/test_ja4t.rs 扩至 11 项（新增 5：SYN-ACK 捕获、首个 SYN-ACK 优先/重传不覆盖、SYN 不触发 JA4TS 且 SYN-ACK 不触发 JA4T 双向互斥、flags 精确等于门（0x1A 不触发、同流后续精确 0x12 仍捕获）、无握手不产出）。JA4TS 无哈希段（纯格式化，格式经 F33 官方 3 向量直证），无需交叉验证。三配置全绿：默认 315 / all-features 1117（10 ignored）/ risk 360；clippy --all-features --all-targets 0 警告。
- **已知边界**：官方 JA4TS 在 SYN-ACK 重传时追加第 5 段重传延迟序列（及 RST 后缀 `-R{sec}`，10 秒窗口、至多 10 项）——需跨包计时状态（last_ts/delays 向量），超出每流旁路字段语义，本库不实现（无重传时官方输出恰为本库 4 字段格式，前缀语义无损）；窗口缩放后实际窗口、IP 分片重组不感知等边界与 F33 相同。

## F35【中】JA4L-C/S 时延指纹（2026-11-06，新功能开发）—— ✅ 已完成

- **背景**：JA4+ 家族传输层最后一块——TCP 握手三包时戳度量半程时延（RTT/2，"光距"）+ TTL 指纹化客户端/服务端到观测点的网络距离。与 JA4T/TS 同为纯传输层、零解密、无新依赖；但**需要真实包间时戳**（区别于 F33/F34 的纯头部字段指纹）。
- **规格来源**：官方 [zeek-zeek-scripts ja4l/main.zeek](https://github.com/FoxIO-LLC/ja4-zeek-scripts)（TCP 路径全文）+ python ja4.py `calculate_ja4_latency`（2 字段格式权威）+ python common.py `epoch_diff`（`(t2-t1) // timedelta(microseconds=2)` = 总微秒**整除 2**）+ [官方博客](https://foxio.io/blog/ja4-network-fingerprinting)：
  - JA4L-S = `{(B-A)/2}_{server_ttl}`：A=客户端 SYN 时戳，B=SYN-ACK 时戳（SYN/ACK 位测试），TTL 取 SYN-ACK 包（IPv4 TTL / IPv6 hop limit）
  - JA4L-C = `{(C-B)/2}_{client_ttl}`：C=SYN-ACK 之后首个客户端包（纯 ACK 或数据均可，zeek 第二发起包语义），TTL 取 SYN 包
- **实现**：
  - [application/ja4.rs](file:///d:/rust_code/rDpi/src/application/ja4.rs) `compute_ja4ls/ja4lc(diff_micros, ttl)`：`{diff/2}_{ttl}` 纯格式化；应用模块重导出。
  - [core/flow.rs](file:///d:/rust_code/rDpi/src/core/flow.rs)：`Flow` 新增 6 个字段——握手时戳 `syn_time/syn_ttl`（A，客户端流）、`synack_time/synack_ttl`（B，服务端流，`SystemTime`）+ 结果 `ja4ls`（服务端流）/`ja4lc`（客户端流），均为流级旁路字段，不占用 protocol/metadata 一次定型语义。
  - [lib.rs](file:///d:/rust_code/rDpi/src/lib.rs) `Detector::observe_ja4l`：A/B/C 三步状态机（全部每流一次），**在 get_or_create 之前独立借流表调用**——JA4L 需反查对端方向流（A/B 分布在两条 FlowKey 流上），主流程的 `flow` 可变借用无法容纳第二次流表访问；对端流不存在（mid-stream）或时戳回退（乱序）跳过，指纹保持 None。C 捕获在 B 未到时保持 None 并由后续客户端包继续尝试（乱序容忍，比 zeek 一次性阈值更鲁棒）。
  - **时间戳入口**：新增 `Detector::detect_at(packet, arrival: SystemTime)`——`detect()` 以 `SystemTime::now()` 委托（实时接入语义不变，非破坏性 API 扩展）；离线 pcap 回放包间处理间隔趋近于零，JA4L 必须用捕获时戳，[pcap.rs](file:///d:/rust_code/rDpi/src/pcap.rs) legacy/pcapng 路径已传 `UNIX_EPOCH + packet.timestamp`（Simple Packet 无时戳退化用处理时刻，已注释数值不可信）。
  - TTL 提取：`parser::ip::IpInfo.ttl`（IPv4 data[8] / IPv6 data[7]）→ `tcp::parse` 新增参数写入 `TcpHeaderInfo.ttl`——**未改 ParsedPacket**（复用 F33 教训，避开 12 处 risk 测试字面量波及）。
  - `DetectionResult.ja4ls/ja4lc` 全分支携带（回显/DPI/guess/规则分支）；CLI 文本输出 ` ja4ls=... ja4lc=...`；json feature 随 derive 序列化。
- **测试**：tests/test_ja4l.rs 新增 7 项（完整握手双向数值直证 5000_57/10000_128、C 为数据包、首包优先/重传与后续包不覆盖、mid-stream 缺起点、无 SYN-ACK、时戳回退跳过、UDP 流不参与）。三配置全绿：默认 322 / all-features 1124（10 ignored）/ risk 367；clippy --all-features --all-targets 0 警告。
- **已知边界**：① QUIC 变体（q 前缀，client Initial/server Initial/client Handshake 时戳）不实现——需 QUIC 包类型跟踪；python 另有 TLS 精化第 3 段（zeek 的 ja4l_delta：`(first_client_data-server_hello)/2`、`(server_hello-client_hello)/2`）依赖 TLS 事件，本库 2 字段格式取 python 语义（对任意 TCP 流可用，不依赖 TLS）；② 时戳回退（乱序）时 zeek 报错跳过、本库静默跳过；③ JA4L-C 在 B 未及时到达时由后续客户端包重试捕获（zeek 为一次性阈值，错过即放弃）——多包场景数值可能与 zeek 略偏；④ detect_at 调用方须保证时戳单调不回退，否则对应指纹跳过（不 panic）。
