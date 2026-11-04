# rDpi 项目体检总览（overview）

> 生成时间：2026-11-04
> 证据规则：每条结论附 `文件路径:行号`；标注三分类：**[代码明确实现]** / **[根据代码推断]** / **[目前无法确认]**
> 本文档基于工作区 commit `34cc561`，只读体检产出，未修改任何业务代码。

## 1. 项目定位

Rust 深度包检测（DPI）库 + CLI 工具，crate 名 `rdpi`，版本 0.4.1，edition 2024（[Cargo.toml:1-4](file:///d:/rust_code/rDpi/Cargo.toml#L1-L4)）。
核心能力：以以太网帧为输入，识别应用层协议（49 个协议模块），提取元数据（SNI/Host/域名等），追踪五元组流并做风险分析。

## 2. 技术栈（实际使用验证）

| 依赖 | 声明位置 | 实际使用 | 结论 |
|---|---|---|---|
| thiserror 1.0 | Cargo.toml:12 | src/error.rs:1 | **[代码明确实现]** 使用中 |
| aho-corasick 1.1 | Cargo.toml:13 | src/core/guess/domain.rs:6 | **[代码明确实现]** 使用中 |
| rustls 0.23 | Cargo.toml:14 | src/ 无任何引用（全库 grep 零命中） | **[代码明确实现]** 死依赖 |
| serde / serde_json | Cargo.toml:15-16 | src/rule/parser.rs:3、src/rule/mod.rs:151 | **[代码明确实现]** 使用中（rule feature） |
| pcap-file 2.0 | Cargo.toml:17 | src/pcap.rs:26-28 | **[代码明确实现]** 使用中（pcap feature） |
| clap 4.5 | Cargo.toml:18 | src/bin/rdpi.rs:5 | **[代码明确实现]** 使用中（CLI） |
| sha2 0.10 / hex 0.4 | Cargo.toml:19-20 | src/application/ja4.rs:8,57-58 | **[代码明确实现]** 使用中（JA4 指纹） |
| etherparse 0.15 | Cargo.toml:11 | src/ 无任何引用（全库 grep 零命中） | **[代码明确实现]** 死依赖；README.md:106 声称"协议解析: etherparse"与代码不符 |

注：README.md:108 声称"TLS 解析：手动实现（无外部依赖）"——src/protocols/tls/ 目录确无 TLS 库引用，**[代码明确实现]** 一致；但 rustls 作为依赖被引入却未使用。

## 3. 启动入口

| 入口 | 位置 | 说明 | 证据 |
|---|---|---|---|
| 库主入口 `Detector` | src/lib.rs:99 | 单包检测 + 流表追踪 + 规则/风险编排 | lib.rs:221-344 |
| CLI 二进制 `rdpi` | src/bin/rdpi.rs:13-27 | 读取 pcap/pcapng，输出 text/json/csv 汇总；需 `pcap` feature（Cargo.toml:50-52） | bin/rdpi.rs:29-66 |
| 基准 bench_detect | benches/bench_detect.rs（Cargo.toml:54-56, harness=false → criterion） | 性能基准 | Cargo.toml:46-48 |
| fuzz fuzz_detect | fuzz/fuzz_targets/fuzz_detect.rs | 模糊测试 detect 入口 | 文件存在，**[目前无法确认]** 是否在 CI 中运行 |
| examples | examples/basic.rs、metadata.rs、pcap.rs | 使用示例 | 文件存在 |

无 Web 服务/定时任务/消息消费者；纯库 + 离线 CLI。**[代码明确实现]**

## 4. 构建与测试现状（本机实测，2026-11-04，cargo 1.99.0 / rustc 1.99.0）

### 默认 features（dns+http+tls，Cargo.toml:23）
- `cargo test`：**259 测试全部通过，0 失败**。分布：lib 单元测试 109、integration_test 2、test_dns 6、test_flow 3、test_guess 13、test_http 18、test_integration 26、test_ja4 4、test_parser 1、test_regression 8、test_tls 20、test_types 25、doc-tests 4。
- **空壳测试文件**：test_ftp / test_quic / test_rtp / test_rule / test_sip / test_smtp / test_ssh 各运行 0 个测试——这些文件的测试体被 `#[cfg(feature)]` 包裹，默认 features 下不编译。**[代码明确实现]**（cargo test 输出："running 0 tests"）
- `cargo test --all-features`：**编译失败**。`error[E0432]: unresolved imports crate::asn1::BerReader, crate::asn1::Asn1Value, crate::asn1::Asn1Class`，源自 src/protocols/snmp/parser.rs:5（正确路径应为 `crate::asn1::ber::BerReader` 与 `crate::asn1::types::{Asn1Value, Asn1Class}`，对照 src/asn1/ber.rs:9、src/asn1/types.rs:7,48、src/asn1/mod.rs:1-3，以及正确用法的 src/protocols/tls/certificate.rs:6）。**含义：snmp 协议模块当前无法编译，说明 CI/开发流程未覆盖 --all-features。** **[代码明确实现]**

### Git 状态
- 工作区干净（git status 无未提交变更）。
- 近期提交按 Phase 推进：Phase 10.4 行为风险处理器（cd22187）→ Phase 11 分类扩展 13→25（4e80da8）→ Phase 11A 十个简单协议（61ffab3）→ 0.4.0（c75f49b）→ Phase 12A 十个企业协议（57ff856）→ Phase 12B TLS 证书解析 + 4 个证书风险处理器（34cc561，存在 9 个内容相同的重复提交 #38~#58）。**[代码明确实现]**
- docs/ 整体被 .gitignore:19 忽略（含本知识库目录），另有 commit 9ef79e8 "Exclude docs/ directory from git tracking"。**[代码明确实现]**

## 5. 高层架构一句话

`Detector::detect()`（lib.rs:221）→ `parser::parse_packet`（以太网→IP→TCP/UDP，parser/mod.rs:8-51）→ `FlowTable` 五元组流追踪（core/flow.rs:123-127）→ 未识别流走 `Registry::detect_with_ports`（protocols/mod.rs:144-163，detector 链首个命中即返回）→ 达到 giveup 阈值（TCP 20 包 / UDP 5 包，lib.rs:80-82）转 `GuessEngine`（域名→IP→端口回退，core/guess/mod.rs:15-37）→ 统计更新 + 可选 risk 分析（lib.rs:322-341）。

详细分解见 [modules.md](file:///d:/rust_code/rDpi/docs/architecture/modules.md)、[dependencies.md](file:///d:/rust_code/rDpi/docs/architecture/dependencies.md)、[business-flows.md](file:///d:/rust_code/rDpi/docs/architecture/business-flows.md)、[risks.md](file:///d:/rust_code/rDpi/docs/architecture/risks.md)。

## 6. 文档与代码的一致性风险（摘要，详见 risks.md）

- README 严重过期：声称"Phase 4 QUIC 开发中"、协议表仅 6 项（README.md:94-101），实际已有 49 个协议模块、Phase 12B 已完成。**[代码明确实现]**
- Cargo.toml:37 注释 `proto3 = []  # FTP, SIP, RTP/RTCP`，实际 proto3 还包含 http2/websocket/rtmp/socks（protocols/mod.rs:46-48,71-73）。**[代码明确实现]**
