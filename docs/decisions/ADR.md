# 架构决策记录（ADR）

> 追溯记录（retroactive）：以下决策在接管前已存在于代码中，本文记录其现状、证据与影响，供后续变更评审时对照。推翻任一决策前须先更新本文件。

## ADR-0001：FlowTable 不做 LRU 淘汰（现状：已决策，代价已知）

- **状态**：已实现（且未实现容量上限）
- **证据**：[src/core/flow.rs:102](file:///d:/rust_code/rDpi/src/core/flow.rs#L102) 注释"max_entries - 最大流数（预留，未实现 LRU 淘汰）"；get_or_create 无容量检查（flow.rs:123-127）
- **背景**：HashMap + 超时过期（flow.rs:149-165）足够简单；过期依赖调用方主动调 `expire_flows`（lib.rs:366-382）
- **影响**：长期运行场景内存无上界（risks.md R2）
- **后续若推翻**：须处理 `get_or_create` 返回 `&mut Flow` 的借用语义与满载时新流的取舍策略，并补测试。

## ADR-0002：协议解析全部手写，不使用解析库

- **状态**：已实现
- **证据**：TLS 为纯手写状态解析（protocols/tls/parser.rs:42-333）；etherparse 与 rustls 在 Cargo.toml:11,14 声明但全库零引用（死依赖，dependencies.md）
- **背景**：README.md:108 自述"TLS 解析：手动实现（无外部依赖）"；控制分配与体积
- **影响**：协议字段覆盖靠手写演进（如 SNI 只取第一个 entry，parser.rs:240-241）；死依赖应在第五步清理

## ADR-0003：Registry 顺序遍历、首个命中即返回

- **状态**：已实现
- **证据**：protocols/mod.rs:134-141（detect）、157-161（detect_with_ports）；注册顺序注释"按特异性递减"（mod.rs:174-176）
- **背景**：避免打分/投票的复杂度；QUIC→TLS→…→HTTP→DNS→低特异性协议
- **影响**：任何新 detector 的**插入位置即语义**；顺序回归必须有测试钉住

## ADR-0004：流协议一次定型、不重复检测

- **状态**：已实现（2026-11-04 F7 修复后，回显结果携带 flow.metadata；F3 修复后回显路径允许证书元数据一次性富化，协议本身仍一次定型）
- **证据**：lib.rs:253（`flow.protocol.is_none()` 才检测）、lib.rs:316-328（已识别直接回显，**携带已保存的元数据**）、lib.rs:327-331 与 371-398（F3 证书富化）、lib.rs:283-285 与 310-312（两处写入点）
- **背景**：性能（每流只解析一次）；元数据仅在定型包上提取，随后随回显持久
- **影响**：TLS 证书字段已可填充（F3 已修，2026-11-04）；修复前回显会把 flow.metadata 抹成 Some(Metadata::None)（F7），现已钉住：b4/a2 测试断言元数据随回显持久

## ADR-0005：docs/ 目录不入版本库

- **状态**：已实现
- **证据**：.gitignore:19 `docs/`；commit 9ef79e8 "Exclude docs/ directory from git tracking"
- **背景**：历史 PRD/SPEC（commit 3662a65）曾被移出跟踪
- **影响**：本知识库仅存于本地；AGENTS.md 特意放在根目录（不受 ignore 影响）作为可提交的入口索引

## ADR-0006：风险分析挂在 Detector 主循环内、逐包执行

- **状态**：已实现（2026-11-04 F7 修复后逐包语义真正成立）
- **证据**：lib.rs:332-341（每包 analyze_packet）；lib.rs:367-380（过期前 analyze_flow）；5 处理器注册 risk/processors/mod.rs:2-15
- **背景**：与 DPI 同生命周期，无需单独管线；修复前 F7 使元数据第二包被抹，风险实际只在识别包生效一次
- **影响**：同一风险在流内逐包重复累计（flow.risks 无去重，lib.rs:335-337，探针 P9/a6 实测 missing_sni==3）；过期窗口硬编码 120s 与配置脱节（R5）
