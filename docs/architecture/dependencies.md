# rDpi 模块依赖关系（dependencies）

> 生成时间：2026-11-04；证据规则同 [overview.md](file:///d:/rust_code/rDpi/docs/architecture/overview.md)。

## 1. 模块间依赖方向（依据 use 语句实测）

```text
lib.rs (Detector, 编排层)
  ├── parser            (lib.rs:223)
  ├── core::flow        (lib.rs:67)
  ├── core::guess       (lib.rs:68-69)
  ├── core::types       (lib.rs:70, 64)
  ├── protocols         (lib.rs:71)
  ├── rule   [feature]  (lib.rs:74-75)
  └── risk   [feature]  (lib.rs:76-77, 332-341)

parser → core::types            (五元组/传输层类型)
protocols → core::types          (Protocol/DetectionResult, protocols/mod.rs:5)
protocols → asn1                 (snmp/parser.rs:5 错误路径; tls/certificate.rs:6 正确路径)
protocols::tls → application     (SNI → Application 识别, TlsMetadata.application types.rs:230)
core::guess → aho_corasick       (domain.rs:6)
application → sha2/hex           (ja4.rs:8,57-58)
risk → core (parsed/flow)        (lib.rs:334 analyze_packet(&parsed, &*flow))
rule → core::types               (rule/mod.rs:17)
pcap → Detector + pcap-file      (pcap.rs:23-28)
bin/rdpi → pcap + clap           (bin/rdpi.rs:5-6)
```

### 依赖方向评估
- 分层清晰：parser/core 为底层，protocols 依赖它们，lib.rs 为唯一编排点；未发现 protocols 反向依赖 lib.rs 或 core 依赖 protocols 的反向引用（全库 use 检查）。**[代码明确实现]**
- `application` 被 protocols/tls 与 core/types（Metadata 各结构体持 `application` 字段，types.rs:219,230,257,290）共同引用，属于被两层共享的横切模块。**[代码明确实现]**
- 循环依赖：`core::types` 无 use crate::protocols；`Protocol.category()` 的 nDPI 映射内聚于 types.rs:867-896，无环。**[代码明确实现]**

## 2. 外部 crate 依赖审计（Cargo.toml:10-20）

| crate | 状态 | 证据 |
|---|---|---|
| thiserror | ✅ 使用 | error.rs:1 |
| aho-corasick | ✅ 使用 | core/guess/domain.rs:6 |
| serde + serde_json | ✅ 使用（rule feature） | rule/parser.rs:3；rule/mod.rs:151 |
| pcap-file | ✅ 使用（pcap feature + dev-deps） | pcap.rs:26-28 |
| clap | ✅ 使用 | bin/rdpi.rs:5 |
| sha2、hex | ✅ 使用 | application/ja4.rs:8,57-58 |
| **etherparse** | ✅ **已移除（2026-11-04，用户批准）** | 原为零引用死依赖；移除时发现 tests/test_regression.rs:38 残留 `use etherparse::*;`（函数内手工构造字节、未用任何符号），已删 |
| **rustls** | ✅ **已移除（2026-11-04，用户批准）** | 原为零引用死依赖（TLS 为手写解析） |

> etherparse/rustls 已从 Cargo.toml 移除——编译时间与供应链面同步缩减；外部依赖仅剩 thiserror/aho-corasick + optional（serde/serde_json/pcap-file）+ clap/sha2/hex。

## 3. Feature 矩阵与一致性

- Cargo.toml:22-44 定义 20 个 feature；默认 = dns+http+tls（Cargo.toml:23）。
- `rule`/`risk` feature 传递引入 serde/serde_json（Cargo.toml:36,43）。
- **不一致点 1**：tftp/rsync/whois/syslog/telnet/vnc 六个协议在 protocols/mod.rs:66-69,83-84 与 Protocol 枚举 types.rs:96-99,113-114 均无 feature gate，任何构建都包含它们——与"模块化按需启用"的设计（README.md:20）矛盾。**[代码明确实现]**
- **不一致点 2**：`Nfs` 变体挂在 `infra` feature 下（types.rs:110-111、mod.rs:80-81），而 Cargo.toml:44 注释 `storage = []  # NFS`——注释与实际 gating 不符（storage feature 目前不 gate 任何模块，**[根据代码推断]** 为遗漏）。**[代码明确实现]**（对注释与代码不符而言）
- **不一致点 3**：`Confidence::DpiCache/DpiPartial/MatchByIp`（types.rs:789-794）在检测主链路中未见赋值点（Registry 只返回 detector 给定的 confidence；GuessEngine 三级回退对应 MatchByPort/MatchByIp）——DpiCache 的实际赋值处 **[目前无法确认]**，待第四步探针测试验证。
