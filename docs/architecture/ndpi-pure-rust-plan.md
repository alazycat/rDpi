# rDpi 类比 nDPI 的纯 Rust 实现方案

> 生成时间：2026-11-06
> 目标：功能类比 nDPI 5.0，核心纯 Rust 实现
> 关联文档：
> - [nDPI 对比与替换路线（历史版）](ndpi-comparison-and-roadmap.md)
> - [协议/应用覆盖候选清单](protocol-coverage-plan.md)

---

## 0. 已确认的目标约束

| 问题 | 决策 | 影响 |
|---|---|---|
| 目标形态 | **类比 nDPI**，不是 drop-in 替换 | 不要求 nDPI C ABI/结构布局兼容 |
| 纯 Rust 边界 | 核心纯 Rust；**live capture 允许 OS API / Npcap / libpcap FFI** | 核心零 C/C++ 依赖；capture 作为可选适配层 |
| C ABI | **不需要** | 从关键路径移除，节省 4–6 周；后续如需要再加 |
| Breaking change | **接受** | 可以直接做双向流、公开 `Flow`、重构 API |
| 首批范围 | **A. Web/Cloud 核心 + B. 企业协议** | P2 Wave 1 锁定为 A+B；C/D/E 后续按目标环境排期 |

结论：本方案按“**Rust 原生 API + 功能类比**”设计，不追求 `ndpi_flow_struct` 字段级兼容；C ABI 只在未来出现宿主集成需求时作为可选项。

---

## 1. 对比框架

### 1.1 对比维度与权重（建议）

| 维度 | 权重 | 关注点 | 主要证据/指标 |
|---|---:|---|---|
| 协议覆盖 | 20% | 能识别多少协议/子协议 | 协议数、目标流量覆盖率 |
| 应用识别 | 20% | SNI/DNS/HTTP/IP/ASN 多信号 | Top-N 应用准确率、host 数据规模 |
| 流模型/状态机 | 15% | 双向流、逐包状态、partial/monitoring | 与 nDPI 的 flow 级一致率 |
| 元数据深度 | 10% | HTTP/TLS/DNS/RTP/STUN 等字段 | 字段覆盖率、字段正确率 |
| 风险/加密分析 | 15% | 风险位、DGA、恶意指纹、启发式 | risk 位对齐率、误报/漏报 |
| 性能/资源 | 10% | 吞吐、延迟、内存/流 | 同机 Mpps、µs/包、内存/流 |
| 部署/工具链 | 5% | live capture、线程、序列化、CLI | 功能清单、端到端可用性 |
| API/生态 | 5% | Rust API、绑定、文档 | API 完整度、集成成本 |

> C ABI 已确认不需要，因此 API/生态权重只反映 Rust 原生 API 与文档/绑定。

### 1.2 成熟度分级（L0–L5）

| 级别 | 能力定义 | nDPI 5.0 | rDpi 现状 | 目标 |
|---|---|---|---|---|
| L0 | L3/L4 + 基础协议识别 | 完成 | 部分完成（约 50 detector） | 目标场景完成 |
| L1 | 分类体系：category/breed/confidence/protocol stack | 完成 | 部分完成（无真正 protocol stack） | 完成 |
| L2 | 多包状态 + 协议元数据 | 完成 | 少量旁路字段 | Top 协议完成 |
| L3 | 应用数据：host/IP/ASN/PSL/动态缓存 | 完成 | 477 条编译期域名 + 46 个应用 | 数据管线 + Top 100 应用 |
| L4 | 风险/加密流量分析 | 完成（56 risks） | 部分（24 risks，JA4 强） | 对齐 56 risks + ET |
| L5 | 部署/性能/生态 | 完成 | 弱（离线 pcap/单线程） | live/threads/serializer |

**判断：rDpi 目前大约在 L0–L1 之间；JA4 相关能力局部达到 L4，但整体不是线性差距，而是“核心模型缺失 + 数据规模不足”。**

### 1.3 差分测试方案

**语料**
- nDPI 自带 460 个 pcap（注意许可/分发限制）；
- 目标环境自有 pcap（按业务场景分层：Web、流媒体、企业、工控、VPN）。

**统一输出格式**

```json
{
  "flow": {
    "src_ip": "...", "dst_ip": "...",
    "src_port": 0, "dst_port": 0, "l4": "tcp"
  },
  "classification": {
    "master_protocol": "...",
    "app_protocol": "...",
    "protocol_stack": ["..."],
    "category": "...",
    "breed": "...",
    "confidence": "..."
  },
  "risk_mask": ["..."],
  "metadata": {}
}
```

**对比指标**

| 指标 | 说明 | 建议验收 |
|---|---|---|
| Flow 级协议一致率 | 同一 flow 的 master protocol 是否一致 | L1 ≥ 95%（选定语料） |
| 协议 precision/recall | 按协议统计误报/漏报 | Top-20 协议 ≥ 0.95 |
| 应用识别准确率 | app protocol 是否一致 | Top-50 应用 ≥ 0.9 |
| category/breed 一致率 | 分类体系对齐 | ≥ 0.9 |
| 元数据字段覆盖率 | 关键字段是否提取 | Top-20 协议 ≥ 80% |
| risk precision/recall | 风险位对齐 | Top-20 risk ≥ 0.8 |
| 吞吐/延迟/内存 | 同机、同语料、同线程模型 | 达到 nDPI 的 80% 以上 |

**工具方式**
- nDPI：`ndpiReader -i corpus.pcap -k out.json -K json`
- rDpi：`rdpi -i corpus.pcap -o jsonl`
- 归一化脚本：对齐 flow key（双向归一化）、协议名、category、breed、confidence、risk mask；
- 输出差异报告：按协议/应用/风险维度聚合，而不是只给一个总准确率。

---

## 2. nDPI 能力 → 纯 Rust 实现映射

| nDPI 能力/概念 | 纯 Rust 实现方案 | rDpi 现有基础 | 优先级 |
|---|---|---|---|
| `ndpi_detection_module_struct` | `Arc<Config>` + `Detector`，配置不可变、可共享 | `Detector` 已有 | 高 |
| `ndpi_flow_struct` | `Flow`（双向、含 client/server/direction/每方向计数） | 单向 `FlowKey` + `FlowTable` | 高 |
| 调用方持有 flow | `process_packet(&mut Flow, l3_pkt, ts, input_info)` + `giveup(&mut Flow)` | 只有 `detect(&[u8])` | 高 |
| 逐包 dissector | `trait Dissector { fn process(&mut self, flow: &mut Flow, ...) -> Outcome }` | `ProtocolDetector::detect(payload)` 一次性 | 高 |
| 分类状态机 | `Inspecting/Partial/Monitoring/Classified` | 无 | 高 |
| `ndpi_protocol` | `Classification { stack, category, breed, confidence, state }` | `DetectionResult` 近似 | 高 |
| protocol stack | `SmallVec<[ProtocolId; 4]>` + master/app/sub | `master()` 返回自身 | 中 |
| category/breed/confidence | 枚举 + nDPI ID 映射表 | 已有 26/8/7 级 + category ID 映射 | 中 |
| `ndpi_risk` bitmask | `RiskSet(u64)` + severity/score/accountability 表 | 24 个 `RiskFlag` | 中 |
| `ndpi_automa` | `aho-corasick` | 已用于 guess 域名 | 中 |
| `ndpi_domain_classify` | 反向 Trie + `aho-corasick`/`fst` | 反向 Trie + 477 条映射 | 中 |
| `ndpi_address_cache` | `HashMap`/LRU + 超时 | 无（静态子网） | 中 |
| host/ASN/IP 数据 | `build.rs` 生成表或运行期加载 | 编译期枚举/静态表 | 高 |
| `ndpi_serializer` | `serde` + `Serializer` trait（JSON/CSV/TLV） | JSON/JSONL/CSV 汇总 | 中 |
| `ndpi_set_config` | `serde` 配置 + `Detector::with_config` | 部分配置 | 中 |
| 自定义协议/规则 | 运行期 registry + `serde` 规则 | feature gate + JSON 规则 | 中 |
| `ndpiReader` | `clap` + `pcap-file`（离线）；live capture 另做适配层 | 已有离线 CLI | 中 |
| 多线程 | `std::thread` + flow 分片；热路径不用 async | 无 | 中 |
| `ndpi_bitmap`/分析结构 | `bitvec`/自定义 `u64` + `VecDeque` 统计 | 少量 | 低 |
| fuzz/CI | `cargo-fuzz` + GitHub Actions | 1 个 fuzz target，无 CI | 高 |

---

## 3. 协议/应用覆盖

完整候选清单见 [protocol-coverage-plan.md](protocol-coverage-plan.md)。建议：

- **A. Web / Cloud 核心**：TLS、HTTP/1.x、HTTP/2、HTTP/3/QUIC、DNS、DoH/DoT/DoQ、WebSocket、HTTP CONNECT/Proxy + Top 20 应用；
- **B. 企业协议**：SMB、NetBIOS、LDAP、Kerberos、RDP、NFS、MSSQL、Oracle、Cassandra、Memcached、Elasticsearch、Kafka、AMQP 等；
- **C. 流媒体/IM/游戏**：RTP/RTCP/SRTP、RTSP、HLS、MPEG-DASH、MPEG-TS、WebRTC、Steam 等；
- **D. 工业/IoT**：S7comm、OPC-UA、BACnet、DNP3、IEC 60870、HART-IP、Profinet、EtherNet/IP 等；
- **E. VPN/隧道**：IPsec、GRE、GTP、Teredo、SoftEther、Tailscale、Tor 等。

**已确认首批：A + B**；C（流媒体/IM/游戏）和 D/E（工业、VPN）后续按目标环境排期。

首批默认 Top 20 协议/应用见 [protocol-coverage-plan.md 第 7 节](protocol-coverage-plan.md#7-建议的首批默认组合)。

---

## 4. 调整后的路线图

### P0 — 基线与对比框架（1–2 周）

1. 固定对比维度/权重、L0–L5 分级、差分输出 schema。
2. 选定 20–50 个 nDPI pcap + 目标环境 pcap。
3. 写 `tests/parity/` 骨架：nDPI JSON vs rDpi JSONL 归一化与差异报告。
4. 同机性能基线：nDPI ndpiReader vs rDpi CLI（pcap 回放、单线程）。

**验收**：差分脚本可运行；基线报告产出；协议/应用候选清单确认。

### P1 — 分类核心重构（4–8 周，最高优先级）

1. **双向流**：client/server 归一化、direction、每方向计数器。
2. **公开 `Flow` + 调用方持有**：`process_packet(&mut Flow, l3_pkt, ts, input_info)`、`giveup(&mut Flow)`；内部 `FlowTable` 变为可选 convenience。
3. **逐包状态机**：`Inspecting/Partial/Monitoring/Classified`；`Dissector::process` 返回 `Continue/Classified/Partial/GiveUp`。
4. **per-flow 协议状态**：状态放 `Flow` 内，不放在共享 detector 中。
5. **L3 入口 + L2 适配**：以太网 wrapper；VLAN/QinQ、IP-in-IP；GTP/TZSP 后续。
6. **protocol stack**：master/app/sub；现有 `Protocol`/`Application` 映射。
7. 迁移现有 50 个 detector：先包旧接口，再逐个 stateful 化。

**验收**：一条双向流只产生一个 `Flow`；选定 pcap 上与 nDPI flow 级一致率 ≥ 95%；现有测试不回归；breaking change 记录。

### P2 — 协议与数据覆盖（3–6 个月，按波次）

1. 状态机模板 + 协议测试框架。
2. Wave 1（已确认）：A 组（Web/Cloud）+ B 组（企业）核心协议。
3. Wave 2：C 组（流媒体/IM/游戏）。
4. Wave 3：D/E 组按目标环境补充。
5. 数据管线：host/IP/ASN、PSL、自定义 category/protocol、运行期加载、DNS cache、未解析 hostname 检测。
6. 应用识别：SNI/DNS/HTTP Host/IP/ASN 多信号；Top 100 应用。

**验收**：目标环境 Top-50 流量识别率 ≥ nDPI 95%；协议覆盖 ≥ 150；新增协议不改核心代码。

### P3 — 风险与加密流量分析（4–6 周）

1. 与 nDPI 56 个风险位做映射：severity、score、accountability、risk params。
2. risk masks/exceptions、per-host/IP risk masks。
3. 补齐：DGA、punycode、URL risk、malicious JA4/SHA1、risky ASN/domain、suspicious entropy、exploit、error code、anonymous subscriber、unresolved hostname、malware host、obfuscated traffic。
4. TLS heuristics/blocks analysis、DoH analysis、OpenVPN heuristics。
5. nDPI 5.0 combined fingerprint（TCP + JA4 + TLS SHA1 cert）与 raw TCP fingerprint/OS hint。

**验收**：Top-20 risk F1 ≥ 0.8；误报审计记录。

### P4 — 部署形态与工具链（4–6 周）

1. **Live capture 适配层**（允许 FFI）：Linux AF_PACKET/libpcap、Windows Npcap；核心保持纯 Rust。
2. **多线程**：flow hash 分片、每线程 `Detector`、统计聚合。
3. **CLI**：`-i device`、`-f BPF`、`-n threads`、`-k/-K`（JSON/CSV/TLV）、`-C`、`-F`、`-a`、`-B`、`-T/-U`、`--cfg`。
4. **序列化**：per-flow 记录、schema 版本、JSON/CSV/TLV。
5. 可选：Wireshark extcap。

**验收**：Linux/Windows live capture 可用；多线程近线性扩展；与 ndpiReader 输出 diff 通过；同机吞吐 ≥ nDPI 80%。

### P5 — 验证、性能与生态（持续）

1. nDPI pcap 语料差分 + golden output。
2. 所有解析器 fuzz；CI 矩阵（Linux/macOS/Windows）；Miri/ASan。
3. 性能：零拷贝、批处理、避免热路径分配；SIMD；DPDK 可选。
4. 文档：迁移指南、协议矩阵、配置参考、API 文档。
5. 绑定：Python/Go（纯 Rust 核心 + FFI 绑定，非 C ABI 兼容层）。

**验收**：CI 三平台绿；语料/fuzz 无崩溃；性能回归门禁。

---

## 5. 纯 Rust 边界

| 部分 | 纯 Rust 可行性 | 建议 |
|---|---|---|
| 核心解析/检测/风险 | 完全可行 | 保持零 C/C++ 依赖 |
| 离线 pcap/pcapng | 可行（`pcap-file`） | 保持 |
| 加密/哈希 | 可行（手写或 RustCrypto） | 保持；避免 OpenSSL |
| 域名/PSL/ASN 数据 | 可行（生成表/运行期文件） | 用 `build.rs`、`include_str!` 或运行期加载 |
| 序列化 | 可行（`serde`） | JSON/CSV；TLV 手写 |
| 多线程 | 可行（`std::thread`） | flow 分片，热路径不用 async |
| live capture | 不完全可行 | 可选适配层：Linux AF_PACKET/libpcap、Windows Npcap（FFI） |
| C ABI | 可行但不需要 | 不做；未来需要时再加 `cbindgen` |

建议在 README/文档中明确：

> **核心 crate 纯 Rust、零 C/C++ 依赖；live capture 作为可选 feature/独立 crate，允许平台 API 或 Npcap/libpcap FFI。**

---

## 6. 里程碑建议

| 版本 | 内容 |
|---|---|
| v0.5 | P0 + P1：双向流、caller-owned flow、逐包状态机、L3 入口（breaking） |
| v0.6 | P2 Wave 1：A + B 组协议/数据管线 |
| v0.7 | P2 Wave 2 + P3：流媒体/IM 组 + 风险/ET |
| v0.8 | P4：live capture、多线程、序列化、CLI |
| v1.0 | P5：差分验证 + 文档 + 性能门禁 |

粗略估计：聚焦“某个明确场景”的可用类比实现约 **9–15 个月**；追求 nDPI 全量协议/风险对等是多年工程。

---

## 7. 风险与不建议做的事

| 风险 | 影响 | 应对 |
|---|---|---|
| 兼容/对齐范围失控 | 高 | 固定目标场景 + 差分测试验收 |
| 双向流重构引发大面积回归 | 高 | 保留单向兼容层，分阶段迁移 detector |
| 协议数据维护成本爆炸 | 高 | 数据管线 + 生成代码 + 运行期加载，不手写枚举 |
| 状态机拖慢热路径 | 中 | 快路径（首包识别）+ 慢路径（状态机/监测）分层，bench 门禁 |
| live capture FFI 破坏“纯 Rust”卖点 | 中 | 核心与 capture 适配层分 crate；文档明确边界 |
| 代码/数据许可 | 高 | clean-room 实现，不复制 nDPI 源码；确认 pcap/列表许可 |

**现在不要做**：

- 不要先移植 258 个协议；
- 不要在流模型/API 未定时做 SIMD/DPDK；
- 不要追求完全复刻 `ndpi_flow_struct` 的 C 结构布局；
- 不要做 C ABI（已确认不需要）；
- 不要做 GUI/可视化；
- 不要为长尾协议投入过多元数据深度。

---

## 8. 下一步

1. ~~从 A–E 组选择首批组合~~ 已完成：A + B。
2. ~~确认首批 Top-N~~ 已完成：见 [protocol-coverage-plan.md](protocol-coverage-plan.md) 第 7 节。
3. `tests/parity/` 骨架已建立；下一步接 nDPI JSON 适配器、rDpi per-flow 输出与 20 个 pcap。
4. ~~双向流 + `Flow` API + 逐包 dissector~~ 已完成首个切片；下一步迁移更多有状态协议（DNS over TCP/TLS 跨包）。
5. 协议状态机模板：从 A 组 DoH/DoT 或 B 组 SMB 开始。

---

## 9. 实施进展（2026-11-06）

### 已完成

- **P0 差分测试骨架**
  - `tests/parity/mod.rs`：`NormalizedFlow` + `compare_flows`（双向规范键、字段级差异、missing/extra）。
  - `tests/test_parity_harness.rs`：6 个用例（一致、反向、协议差异、缺失/多出、risk 顺序、协议栈顺序）。
  - `tests/parity/README.md`：schema、nDPI/rDpi 输出方式、指标与 TODO。
- **P1 首个垂直切片**
  - `FlowKey::canonical/reverse` + `Direction`；
  - `Flow::new_bidirectional/direction_of`（方向相对首包 initiator，而非任意规范键）；
  - `Flow` 双向计数（`packets_forward/reverse`、`bytes_forward/reverse`）与 `first_seen_ms/last_seen_ms`；
  - `ClassificationState`（Inspecting/Partial/Monitoring/Classified）；
  - `ProtocolStack`（固定 8 层、去重、零堆分配）；
  - `parser::parse_l3_packet`（L3 入口，L2 `parse_packet` 复用）；
  - `Detector::process_l3_packet`（caller-owned Flow、双向、partial → classified 升级）。
- **P1 有状态 dissector 框架**
  - `DissectorOutcome`（Continue/Partial/Classified/GiveUp）；
  - `DissectorState`（per-flow 状态枚举，当前 `Http` 变体）；
  - `ProtocolDetector::process`（默认无状态）+ `Registry::process_stateful`；
  - HTTP 头跨包重组（`HTTP_MAX_HEADER_BYTES = 8 KiB`，`\r\n\r\n` 边界，首包方向门控）；
  - `Detector::process_l3_packet` 优先走有状态 disector，`Continue` 不回退、`GiveUp` 清状态后回退无状态。
- **验证**：`tests/test_p1_flow.rs` 10 个用例；`cargo test` 与 `cargo test --all-features` 全绿；clippy lib+bins 0 警告。

### 待办

- **P0**：nDPI JSON → 归一化适配器；rDpi per-flow JSONL 输出；20–50 个 pcap 语料；CI（Linux runner 跑 nDPI）。
- **P1**：迁移更多有状态协议（DNS over TCP、TLS 跨包、HTTP/2）；VLAN/QinQ/IP-in-IP；规则/风险/JA4 接入新入口；迁移现有 50 个 detector；L2 与双向流整合。
