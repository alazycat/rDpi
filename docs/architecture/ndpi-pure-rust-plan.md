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
- **B. 企业协议**：SMB、NetBIOS（✅ 已于 F45 完成，2026-11-07）、LDAP、Kerberos、RDP、NFS、MSSQL、Oracle、Cassandra、Memcached（✅ F46）、Elasticsearch（✅ F46）、Kafka、AMQP（✅ F46）等；
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
3. ~~rDpi per-flow 输出~~、~~nDPI JSON 适配器~~、~~20 个自生成 pcap + golden~~、~~nDPI 兼容分类映射~~、~~CI~~ 已完成；语料已扩至 44 个（含 13 个企业协议）；下一步补目标环境真实 pcap。
4. ~~双向流 + `Flow` API + 逐包 dissector~~ 已完成；HTTP / DNS-over-TCP / TLS / HTTP2 状态机 + TCP 序列号重组已落地。
5. ~~VLAN/QinQ/IP-in-IP~~、~~规则/风险/JA4 接入新入口~~、~~L2 与双向流整合（pcap/CLI 走 `process_packet`）~~ 已完成；下一步：迁移剩余无状态 detector、补充有状态协议覆盖。

---

## 9. 实施进展（2026-11-07）

### 已完成

- **P0 差分测试骨架**
  - `tests/parity/mod.rs`：`NormalizedFlow` + `compare_flows`（双向规范键、字段级差异、missing/extra）。
  - `tests/test_parity_harness.rs`：6 个用例（一致、反向、协议差异、缺失/多出、risk 顺序、协议栈顺序）。
  - `tests/parity/README.md`：schema、nDPI/rDpi 输出方式、指标与 TODO。
- **P0 rDpi per-flow 输出**
  - `src/parity.rs`：`NormalizedFlow` schema 与 `from_flow`（`feature: json`），比较器复用库内定义；
  - `Detector::normalized_flows()`：按“信息量优先 + 端点字典序”稳定排序；
  - CLI `-o flows-jsonl`：每行一条归一化流记录（需 `--features "pcap json"`）；
  - `Flow.confidence` 与 `detect_at` 路径的 `protocol_stack` 填充，供导出使用；
  - `tests/test_flow_export.rs`：4 个用例（字段映射、已分类/未分类导出、risk_mask）。
- **P0 nDPI JSON 适配器**
  - `NormalizedFlow::from_ndpi_json` / `parse_ndpi_jsonl`（`feature: json`）；
  - 字段映射对齐 nDPI 5.0 `ndpi_flow2json`/`ndpi_protocol2name`：`dest_ip`、L4 `proto`、`ndpi.proto` 的 `MASTER.APP` 拆分、数字置信度对象、`flow_risk` 风险名归一化；
  - `tests/test_ndpi_adapter.rs`：5 个用例（真实 ndpiReader 夹具、master/app 拆分、缺省字段、JSONL、错误输入）；
  - `tests/test_parity_harness.rs` 新增适配器输出与 rDpi 记录的端到端比较用例。
- **P0 语料与 golden**
  - `tests/parity/gen_corpus.py`：确定性生成 44 个 pcap（DNS/HTTP/TLS × 主机/方法/SNI 变体 + 13 个企业协议 + 9 个跨段拆分 + 6 个多流混合）；
  - 企业协议语料：SSH / SMTP / FTP / MySQL / PostgreSQL / Redis(RESP) / DHCP / NTP / SNMP / Modbus / MQTT / SIP / DNS-over-TCP；
  - `tests/parity/corpus/` 与 `tests/parity/golden/` 随仓库提交（nDPI 5.0 真实输出，CI 无需安装 nDPI）；
  - `tests/test_parity_corpus.rs`：逐 pcap 跑 rDpi 库内检测并与 golden 比较。
- **P0 nDPI 兼容分类映射**
  - `src/parity.rs`：`ndpi_compat_classification` / `ndpi_compat_app_name` / `protocol_name`；
  - 基础协议：DNS → Network/Acceptable、HTTP → Web/Acceptable、TLS → Web/Safe；
  - 应用层（HTTP/TLS）：YouTube → Media/Fun、Facebook → SocialNetwork/Fun、GitHub → Collaborative/Acceptable、Google → Web/Acceptable（app 名 `GoogleServices`）；
  - 企业协议（真实 ndpiReader 5.0 验证）：SSH → RemoteAccess/Acceptable、SMTP → Email/Acceptable、NTP → System/Acceptable、DHCP/SNMP → Network/Acceptable、Modbus → IoT-Scada/Acceptable、MySQL/PostgreSQL/Redis → Database/Acceptable、FTP → Download/Unsafe、SIP → VoIP/Acceptable、MQTT → RPC/Acceptable；
  - 协议名差异：Redis → `RESP`、FTP → `FTP_CONTROL`（其余按大小写不敏感比较）；
  - DNS 保持 master taxonomy（nDPI 不对 DNS 查询做 app 分类），rDpi 仍保留应用识别结果；
  - 未覆盖组合回退原生名称并在 diff 中暴露；
  - 语料测试 gate master/app/category/breed/confidence/risk_mask：44/44 用例全部一致；nDPI `Match by port` 或 `DPI (partial)` 与 rDpi `Dpi` 视为“rDpi 置信度更强”放行。
- **P0 risk_mask 映射与门禁**
  - `src/parity.rs`：rDpi 风险名 → nDPI 5.0 风险名映射（已验证差异：`tls_missing_sni` → `missing_sni_tls_extn`、`tls_weak_cipher` → `weak_tls_cipher`、`tls_obsolete_version` → `obsolete_tls_version`、`tls_alpn_sni_mismatch` → `alpn_sni_mismatch`、`tls_self_signed_cert` → `self_signed_certificate`），导出前排序去重；
  - FTP 风险处理器（`proto3`）：`unsafe_protocol`（明文命令/数据）+ `clear_text_credentials`（USER/PASS/ACCT），与真实 ndpiReader 5.0 输出对齐；
  - 行为风险启发式仅分析未定型流量，修复 DHCP `binary_data_transfer`、MySQL/PostgreSQL `obfuscated_traffic` 误报；
  - 语料门禁剔除 nDPI 专有启发式（`malicious_fingerprint`、`mismatching_protocol_with_server_ip_address`、`tls_probably_not_carrying_https`、`malformed_packet`、`unidirectional_traffic`）后要求风险集合完全一致：rDpi 不得漏报已建模风险，也不得产出 nDPI 未报告的风险；
  - 新增测试：FTP 风险处理器 5 个、行为启发式门控 2 个、风险名映射导出 1 个、门禁策略 2 个。
- **P0 CI 接入**
  - `.github/workflows/ci.yml`：Ubuntu + Windows 矩阵；
  - `cargo fmt --check`、`cargo clippy --all-features --all-targets -D warnings`、默认 features 测试、全 features 测试（含 44 个语料的差分测试）；
  - 语料与 golden 已提交，CI 不依赖 nDPI 可执行文件；
  - `Cargo.toml` 声明 `rust-version = "1.88"`（edition 2024 + let-chains）。
- **P1 首个垂直切片**
  - `FlowKey::canonical/reverse` + `Direction`；
  - `Flow::new_bidirectional/direction_of`（方向相对首包 initiator，而非任意规范键）；
  - `Flow` 双向计数（`packets_forward/reverse`、`bytes_forward/reverse`）与 `first_seen_ms/last_seen_ms`；
  - `ClassificationState`（Inspecting/Partial/Monitoring/Classified）；
  - `ProtocolStack`（固定 8 层、去重、零堆分配）；
  - `parser::parse_l3_packet`（L3 入口，L2 `parse_packet` 复用）；
  - VLAN/QinQ：以太网解析剥离 802.1Q（0x8100）、802.1ad（0x88A8）与 legacy 0x9100 标签栈（上限 4 层）；
  - IP-in-IP：逐层剥离 IPv4-in-IP（协议 4）与 IPv6-in-IP（协议 41）；保留最外层端点作为流身份，传输层取自内层；解封装深度上限 4 层，超限按不透明载荷处理；
  - `Detector::process_l3_packet`（caller-owned Flow、双向、partial → classified 升级）。
- **P1 有状态 dissector 框架**
  - `DissectorOutcome`（Continue/Partial/Classified/GiveUp）；
  - `DissectorState`（per-flow 状态枚举：`Http` / `DnsTcp` / `Tls` / `Http2`）；
  - `ProtocolDetector::process`（默认无状态）+ `Registry::process_stateful`；
  - HTTP 头跨包重组（`HTTP_MAX_HEADER_BYTES = 8 KiB`，`\r\n\r\n` 边界，首包方向门控）；
  - DNS over TCP 长度前缀重组（RFC 1035 §4.2.2；长度前缀与消息体均可跨包；仅端口 53 + 客户端方向）；
  - TLS record 跨包重组 + handshake 消息跨 record 重组（每方向独立缓冲；5 字节记录头 + `record_len`；合成单条 record 解析）；
  - TLS Certificate 富化（定型后 `monitoring` 路径合并后续 Certificate 元数据，已有 SNI/版本保留）；
  - HTTP/2 preface + HEADERS 帧跨包重组（24 字节 preface 可跨包；首个完整 HEADERS 经 HPACK 提取伪头部）；
  - TCP 序列号重组（每方向独立；乱序暂存、重传/重叠裁剪、SYN 基线；`TcpReassembler`）；
  - 有状态路径仅对 TCP 生效（HTTP / DNS-over-TCP / TLS / HTTP/2 均为 TCP 专用，避免 UDP DNS 被误接管）；
  - `Detector::process_l3_packet` 优先走有状态 disector，`Continue` 不回退、`GiveUp` 清状态后回退无状态。
- **P1 新入口：规则 / 风险 / JA4**
  - 规则优先：`rule_engine.match_rule` 在 DPI/有状态解析之前执行；`rules_only` 未命中直接返回，不回退 DPI；规则上下文构建与 `detect_at` 共用 `rule_context`（SNI 取流元数据，回退当前包）；
  - 逐包风险：`RiskRegistry::analyze_packet` 结果同时写入 `DetectionResult.risks` 与 `flow.risks`，并触发 `risk_callback`；
  - JA4 观测：`Flow.client_direction`（SYN/SYN-ACK 推断客户端方向）、JA4T/JA4TS（含第 5 段重传延迟/RST）、JA4L-S/JA4L-C、JA4SSH 200 包窗口；
  - TLS JA4L 精化段（D/E/F 三时点）复用 `Flow` 内时戳字段，与 `detect_at` 路径同语义；
  - `tests/test_p1_entry_features.rs`：默认 3 个用例，`rule`/`risk`/`ssh` feature 下共 7 个用例。
- **P1 pcap/CLI 双向整合**
  - `Detector::process_packet`（以太网入口，内置流表）：L2/L3 解析 + 双向规范五元组聚合，一条连接只产生一个 `Flow`；
  - `FlowTable::take/put`：双向入口临时持有 caller-owned `Flow` 后再放回，容量逐出策略复用；
  - `PcapProcessor` / CLI 改用 `process_packet`，pcap 回放与差分导出不再产生单向重复记录，HTTP / DNS-over-TCP / TLS / HTTP2 状态机在 pcap 路径生效；
  - Giveup 猜测回退抽取为 `Detector::guess_flow`，`detect_at` 与双向入口共用（端口 → IP 子网 → 域名三级匹配）；
  - 每方向 TCP 起始字节缓冲（`Flow::tcp_prefix`，上限 2 KiB）：无状态检测只针对流前缀，续段不单独参与，既支持跨段协议头，也避免续段被低特异性 detector 误判；
  - 有状态 dissector 只在方向起始包或已接管后运行，防止二进制前缀之后的协议片段另起炉灶；
  - SSH 有状态版本标识行重组（`SshDissectorState`）：行未结束时接管，避免被 IKE/Whois 抢占；
  - MySQL 检测支持真实 4 字节包头（3 字节长度 + 1 字节序号），并校验长度字段；修复合成语料中 MySQL 被 NTP 抢先误判；
  - `tests/test_pcap_bidirectional.rs`：双向聚合、pcap 入口有状态 DNS-over-TCP、giveup 猜测回退、SSH 跨段/行中断分片、续段非独立负载 6 个用例。
- **验证**：`tests/test_p1_flow.rs` 20 个用例、`tests/test_p1_entry_features.rs` 7 个用例、`tests/test_parser.rs` 9 个用例、`tests/test_pcap_bidirectional.rs` 6 个用例；`cargo test` 与 `cargo test --all-features` 全绿；clippy 0 警告。
- **P4 首个切片：Live capture（F47，2026-11-08）**
  - `live` feature + `rdpi::live`：运行时动态加载 Npcap/libpcap（`libloading`，无编译期 C 依赖）；
  - `devices()` / `CaptureConfig` / `LiveCapture` / `CapturedFrame` / `LiveError`；仅 DLT_EN10MB；
  - CLI `-i` 自动区分 pcap 文件与网卡、`--iface`、`--list-ifaces`、`-f`、`--count`、`--duration`；
  - 实时路径按 EtherType（含 VLAN/QinQ）跳过 ARP/LLDP 等非 IP 帧；
  - 实时帧经 `Detector::process_packet` 复用现有输出与 flows-jsonl；
  - `unsafe` 仅限 `src/live/ffi.rs`。
- **P4 后续切片：Live capture v2（F48，2026-11-08）**
  - `-n/--threads` 多线程检测：单抓包线程 + flow-hash 分片 worker，有界队列背压；`-n 1` 保持 F47 顺序；
  - Ctrl-C 优雅停机：首次输出汇总并 exit 0，第二次强退 130；
  - `LinkType` 支持 DLT_EN10MB/SLL/SLL2/RAW，Linux `any` 设备可用；新增 `Detector::process_ip_packet` L3 入口；
  - `-n > 1` 时逐包行按完成顺序，`json` 的 packets 收尾按抓包序号重排，`flows-jsonl` 跨 worker 全局确定性排序。

### 待办

- **P0**：目标环境真实 pcap 扩充（44 个自生成用例已就绪，其中 13 个企业协议）；映射表随语料扩展继续补充；其余 rDpi 风险（证书过期、弱密码套件、DNS 隧道等）待真实语料验证后纳入门禁。
- **P1**：迁移剩余无状态 detector 到逐包框架（按需有状态化）；补充 SMTP/IMAP/POP3/FTP 多包会话、WebSocket 升级等有状态场景。
- **P1 边界**：QUIC JA4L 与流级风险分析（`analyze_flow`）在 `process_packet` 路径尚未接入（`detect_at`/`drain_risks` 仍保留）；HTTP/2 CONTINUATION/HPACK 动态表跨帧；TLS 大 Certificate（>64 KiB）分片；TCP FIN/RST 与窗口跟踪；多活跃有状态协议（当前一个 flow 只允许一个 `DissectorState` 变体）。
