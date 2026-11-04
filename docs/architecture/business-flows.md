# rDpi 业务流总览（business-flows，第一步：高层版）

> 生成时间：2026-11-04；证据规则同 [overview.md](file:///d:/rust_code/rDpi/docs/architecture/overview.md)。
> 本文档为第一步的高层流图；第二步将对其中一条业务做逐行深挖并产出三分类标注。

## 流程 A：单包检测主链路（核心业务）

入口：`Detector::detect(&mut self, packet: &[u8])`（lib.rs:221-344）

```text
① parse_packet(packet)                      parser/mod.rs:8-51（失败 → Err 向上传播）
② 构造 FlowKey 五元组                        lib.rs:226-232
③ FlowTable::get_or_create                  lib.rs:235；flow.rs:123-127
④ 新流继承 guess 开关（packets_seen==0 时）   lib.rs:238-240
⑤ packets_seen += 1                         lib.rs:243
⑥ giveup 阈值：TCP=20 / UDP=5               lib.rs:246-250（常量 lib.rs:80-82）
⑦ 流无协议时三选一：
   a. 规则引擎优先（feature=rule 且已加载）    lib.rs:254-274（命中即 return，含 rules_only 短路 lib.rs:271-273）
   b. DPI 阶段（包数 < 阈值 或 dpi_only）     lib.rs:275-287 → Registry::detect_with_ports（protocols/mod.rs:144-163）
   c. Giveup 阶段 → GuessEngine              lib.rs:288-315（域名→IP→端口，guess/mod.rs:15-37）
⑧ 流已有协议：直接回显，不重复检测            lib.rs:316-319
⑨ 统计更新 packets/bytes/last_time           lib.rs:322-324
⑩ 元数据保存（仅当有检测结果）                lib.rs:327-329
⑪ 风险分析（feature=risk），附加到流与结果     lib.rs:332-341
```

关键不变量（**[代码明确实现]**）：
- 流协议一旦确定不再重检（⑧），DPI 只发生在协议为 None 的包上。
- DPI 首个命中的 detector 决定协议（protocols/mod.rs:134-141,157-161 顺序遍历短路）。
- 猜测结果的置信度低于 DPI（Confidence 顺序 types.rs:784-799）。

## 流程 B：pcap 离线分析（CLI）

`bin/rdpi.rs`：解析参数（rdpi.rs:30）→ `PcapProcessor::process_file`（rdpi.rs:33-34，pcap.rs 自动识别 pcap/pcapng，pcap.rs:46-49）→ 逐包调用 Detector::detect → 协议计数 HashMap（rdpi.rs:36-47）→ text/json/csv 汇总（rdpi.rs:59-63）。

## 流程 C：流生命周期与过期

- 创建：首个包触发（lib.rs:235）。
- 复用：后续包按五元组命中（flow.rs:130-137）。
- 过期：`expire_timeout` 按 `last_time + timeout`（默认 120s，lib.rs:149）清理（flow.rs:149-165）；需要调用方主动调用 `Detector::expire_flows`（lib.rs:366-382，risk feature 下过期前会先跑 analyze_flow）。
- **无主动淘汰**：流数超过 `max_entries`（默认 10000，lib.rs:120）时 `get_or_create` 照常插入（flow.rs:123-127 无容量检查）→ 无界内存增长，见 risks.md R4。

## 流程 D：风险分析（feature=risk）

```text
每包: RiskRegistry::analyze_packet(&parsed, &flow)   lib.rs:334 → risk/mod.rs:32-90
      └── 5 处理器: tls / dns / http / behavioral / tls_cert   risk/processors/mod.rs:2-15
      └── RiskResult{flag,severity,description}        risk/types.rs:78-88
      └── 命中 → flow.risks 追加 + result.risks 赋值    lib.rs:335-340
过期: expire_flows 先对将过期流跑 analyze_flow 再清理    lib.rs:367-380
```

## 流程 E：自定义规则（feature=rule）

加载：`load_rules_json`/`load_rules_file`（lib.rs:187-199）→ RuleEngine。
执行：优先于内置 DPI（lib.rs:254-270），条件 AND 语义（rule/mod.rs:64-70），特异性评分决定匹配顺序（rule/mod.rs:44-59；RuleEngine::match_rule 的排序细节 **[目前无法确认]**，第二步深挖候选）。

## 第二步候选业务（供选择）

1. **TLS SNI → 应用识别全链路**（TLS detector → TlsMetadata.sni/ja4 → application.identify → app_protocol）——贯穿 protocols/application/asn1 三模块，且与 Phase 12B 证书风险处理器衔接。
2. **Giveup 猜测链路**（DPI 失败 → 域名/IP/端口回退）——存在 lib.rs:291 疑似 bug（dst_ip 赋 src_ip），深挖价值高。
3. **规则引擎优先级语义**（rule vs DPI vs guess 的先后与短路）——lib.rs:254-274 行为微妙（规则命中后 metadata 直接覆盖流）。
