# rDpi 与 nDPI 5.0 对比及替换路线

> 生成时间：2026-11-06
> 对比版本：rDpi 0.4.2（commit `002870b`） / nDPI 5.0（本地 `D:\c_code\nDPI-5.0`）
> 文档性质：研究/规划产出，不含代码改动
> 结论口径：以“替换 nDPI”为目标，但替换形态（嵌入式 C ABI / 独立引擎）尚待确认

---

## 0. 结论先行

**rDpi 目前不是 nDPI 的替代品，而是一个“协议识别 + 指纹”能力更突出的 Rust 库。** 两者最大的差距不在协议数量，而在：

1. **流模型**：nDPI 是双向流 + 调用方持有 flow；rDpi 是单向五元组 + 内部流表。
2. **检测模型**：nDPI 逐包回调、`inspecting → partial → classified → monitoring`；rDpi 是 detector 顺序遍历、首个命中即定型。
3. **部署形态**：nDPI 是 C ABI + live capture + 多线程 + 序列化 + 生态；rDpi 是 Rust API + 离线 pcap CLI。
4. **数据规模**：nDPI 有生成式 host/IP/ASN 数据和 56 个风险位；rDpi 是 477 条编译期域名映射和 24 个风险位。

因此，替换路线应当是：**先兼容层/流模型/部署，再验证，再覆盖协议/数据，最后风险与性能**。先堆协议数量会返工。

---

## 1. 能力对比

### 1.1 总体定位

| 维度 | rDpi 0.4.2 | nDPI 5.0 |
|---|---|---|
| 语言 / 许可 | Rust 2024 / MIT | C / LGPLv3 |
| 代码规模 | `src` 约 2.8 万行；约 50 个 detector | 258 个协议解析 `.c`；468 个协议/应用 ID |
| 产品形态 | Rust 库 + 离线 pcap CLI | C 库 + ndpiReader + 生态 |
| 输入 | 以太网帧 | L3 IP 包 |
| 流所有权 | Detector 内部 `FlowTable` | 调用方持有 `ndpi_flow_struct` |
| 成熟度 | 0.4.2，个人/小团队项目 | 5.0，十余年积累，6–9 个月发布周期 |

### 1.2 协议与应用分类

| 维度 | rDpi | nDPI 5.0 |
|---|---|---|
| 协议识别 | 约 50 个 detector（README 写 49） | 258 个解析源文件 / 468 个协议 ID |
| 分类数 | 26 个 `ProtocolCategory` | 95 个 category |
| Breed | 8 级 `ProtocolBreed` | 8 级，已基本对齐 |
| Confidence | 7 级 | 10 级 |
| 应用识别 | 49 个 `Application` 枚举 + 477 条域名后缀映射，编译期固定 | app/subprotocol + 约 4.75 万行生成匹配表 + 1.6 万行 Public Suffix List + ASN/IP 列表 + 运行期文件 |
| 协议栈 | 单个 `Protocol` + `Application`；`master()` 返回自身 | master/app + protocol stack（可超过两层） |
| 自定义协议 | 编译期 feature gate + JSON 规则（端口/SNI/payload） | 运行期无限自定义协议；规则支持 JA4、指纹、HTTP URL、category/breed；nBPF |

### 1.3 流模型与检测状态

| 维度 | rDpi | nDPI 5.0 |
|---|---|---|
| 流方向 | **单向五元组**，`FlowKey` 不做地址归一化（`src/core/types.rs:156`） | **双向流**，内建 client/server、direction |
| 流表 | Detector 内部 `FlowTable`，默认 1 万流 / 120 秒 | nDPI 不提供流表，由宿主管理 flow |
| 检测模型 | Registry 顺序遍历，首个命中即返回（`src/protocols/mod.rs:243`） | 每包回调，分类状态 `inspecting/partial/monitoring/classified`（`ndpi_typedefs.h:1305`） |
| 多包状态 | 仅少量旁路字段（TLS 证书、HTTP/2、JA4 系列） | 每协议状态（HTTP/TLS/DNS/RTP/STUN/SMB…） |
| Giveup | TCP 20 包 / UDP 5 包后进入 GuessEngine | `ndpi_detection_giveup()` + 端口/IP 猜测 |
| 方向判定 | 无显式方向，靠 SYN/JA4 逻辑推断 | 内建方向 + `ndpi_flow_input_info` 可由宿主提供 |

### 1.4 元数据、风险与加密流量分析

| 维度 | rDpi | nDPI 5.0 |
|---|---|---|
| 元数据 | 24 类 `Metadata`，SNI/Host/JA4/证书/QUIC TP 等 | 大量协议字段：HTTP URL/UA/Server/Content-Type、DNS 响应地址/TTL、RTP、STUN 等 |
| 风险 | 24 个 flag / 4 级 severity / 描述字符串 | 56 个 flag / 6 级 severity / score / accountability / risk params / masks / exceptions / per-host-IP masks |
| 加密流量 | JA4、JA4S、JA4H、JA4X、JA4T、JA4TS、JA4L-C/S、JA4SSH、JA4D/D6；QUIC Initial 解密 | JA4/JA3S、TLS 证书 SHA1、nDPI combined fingerprint、TLS/OpenVPN heuristics、obfuscated traffic、DoH analysis、DGA、malicious JA4/SHA1 lists |
| 数据规模 | 477 条域名映射；静态子网/端口表 | 4.75 万行生成表 + 1.6 万行 PSL + ASN/IP 列表 + 动态 address/hostname cache |

### 1.5 部署与工程能力

| 维度 | rDpi | nDPI 5.0 |
|---|---|---|
| API | Rust API | C API |
| Live capture | 无，只读 pcap 文件 | libpcap/npcap + BPF |
| 多线程 | 无 | `-n` 线程、per-thread module、DPDK 示例 |
| 序列化 | text/json/jsonl/csv 汇总 | JSON/CSV/TLV，per-flow 输出，extcap |
| 测试 | all-features 1194 个用例；1 个 fuzz target；仓库无 CI 配置 | 460 个 pcap 回归语料；60+ fuzz target；多平台 CI |
| 隧道 | 识别 VXLAN/L2TP/PPTP，但不解封装；代码库未见 VLAN/GTP/TZSP/流重组 | VLAN、GTP/TZSP 解封装、IP-in-IP 等 |
| 生态 | 无 | ntopng / nProbe / nDPId / nfstream / Wireshark |

### 1.6 性能口径

rDpi 的 bench 是**进程内单线程**：稳态约 0.41 µs/包（≈2.4 Mpps），miss 路径约 1.67 µs/包（≈0.6 Mpps），QUIC 首包解密约 23.3 µs。nDPI 的目标是多线程/多 Gbps/DPDK，仓库里没有同机可比数据。

**两者不能直接比较。** 替换验收必须用同一台机器、同一批 pcap、同一线程模型做基线，否则“rDpi 2.4 Mpps”对“nDPI 多 Gbps”没有意义。

---

## 2. 五个关键差异（为什么不能直接替换）

### 2.1 流模型是单向的，nDPI 是双向的

rDpi 的 `FlowKey` 直接使用 `(src_ip, dst_ip, src_port, dst_port, transport)`，客户端 SYN 和服务器 SYN-ACK 会被视为两条流。代码里 JA4L/JA4TS 等功能需要靠“对端流反查”来绕过这个限制（`src/lib.rs` 中多处 `FlowKey 方向性` 注释）。

nDPI 的一条 `ndpi_flow_struct` 是双向的，内建 `c_address/s_address`、`client_packet_direction`、`packet_direction` 和每方向计数器。**这会直接影响流统计、风险归属、阈值、元数据和所有按方向的风控逻辑。**

### 2.2 flow 所有权相反

rDpi 的 `Detector` 自己持有 `FlowTable`，调用方只能通过 `flows()` 遍历；nDPI 由宿主分配/持有 flow，nDPI 只处理传入的 `ndpi_flow_struct`。

这意味着：

- 无法接入已有流管理器（ntopng 的 LRU、超时、双向归一化）；
- 无法按宿主的生命周期回收 flow；
- 无法做 nDPI 那种“同一 flow 对象跨包累积状态”的语义。

### 2.3 一次性 detector vs 逐包状态机

rDpi 的 `ProtocolDetector::detect(payload)` 只拿当前 payload 做一次判断，Registry 首个命中即定型，之后不再重检。nDPI 的 dissector 是每包回调，可以：

- 先给 partial 分类，后续包再升级；
- 分类完成后进入 monitoring，继续提取元数据；
- 多个协议共享 flow 状态（HTTP 子协议、TLS 证书、DNS 响应、RTP/RTCP 关联等）。

rDpi 有 `Confidence::DpiPartial` 枚举，但只用于少数 detector 的单包判定，**没有形成 per-flow 的 partial → classified 状态机**。

### 2.4 输入层与部署形态不同

nDPI 的主 API 接收 **L3 IP 包**，由宿主或 `ndpiReader` 处理以太网/VLAN/隧道；rDpi 直接接收**以太网帧**，且 CLI 只做离线 pcap 回放。

要替换 nDPI：

- 需要 L3 入口 + L2 适配；
- 需要 VLAN/QinQ、IP-in-IP、GTP/TZSP 等解封装；
- 需要 live capture、BPF、多线程、序列化。

这些不是“锦上添花”，而是嵌入现有采集链路的必要条件。

### 2.5 应用/风险覆盖是数据工程

nDPI 的识别能力很大一部分来自生成数据：

- `src/lib/inc_generated` 约 4.75 万行匹配表；
- 1.6 万行 Public Suffix List；
- ASN/IP 列表、malware/ads/gambling 等列表；
- 运行期加载的自定义 category/protocol 文件；
- 动态 address/hostname cache。

rDpi 是 477 条编译期域名映射 + 49 个 `Application` 枚举。**每加一个应用都要改 Rust 枚举并重新编译**，无法支撑 nDPI 级别的长尾覆盖。

---

## 3. 替换 nDPI 的路线图

### 3.0 战略选择：先确定“替换形态”

| 方案 | 含义 | 优先级 |
|---|---|---|
| A. nDPI 兼容层 | 提供 C ABI / 调用方持有 flow / 类似 nDPI 的语义，嵌入 ntopng、nProbe 等宿主 | 真正“替换”必须做 |
| B. 独立 DPI 引擎 | 替代 ndpiReader + 自建采集：live capture、多线程、CLI、序列化 | 可作为第一阶段产品形态 |
| C. 混合 | 共享核心，先做 B 验证能力，再做 A 做嵌入 | **推荐** |

> 关键判断：如果目标是嵌入 ntopng 这类宿主，**不要试图完全复刻 `ndpi_flow_struct` 的 C 结构布局**；应提供干净的新 C ABI，再为目标宿主写薄适配层。否则会被 nDPI 的内部结构永久绑死。

### 3.1 P0 — 基线与兼容性定义（1–2 周）

**目标**：把“替换”变成可验收的工程目标，而不是一句口号。

关键任务：

1. 确定替换形态（A/B/C）、目标宿主、必须兼容的 nDPI API/字段子集。
2. 建立差分测试基线：先选 20–50 个 nDPI pcap，统一输出 `flow key / master protocol / app protocol / category / breed / confidence / risk mask / 元数据子集`。
3. 写 `docs/architecture/ndpi-compat.md`：必须对齐、允许差异、明确不实现。
4. 同机性能基线：nDPI ndpiReader vs rDpi CLI，pcap 回放、单线程，记录 pps、µs/包、内存。

**验收**：

- [ ] 一页纸替换范围 + API 子集清单
- [ ] 差分脚本可本地运行并输出差异报告
- [ ] 基线准确率/性能报告

### 3.2 P1 — 流模型与 API 重构（最高优先级，4–8 周）

**这是整个替换路线的前置条件，必须先做。**

关键任务：

1. **双向流**：client/server 归一化、direction、每方向计数器；保留单向视图作为兼容层。
2. **调用方持有 flow**：公开 `Flow`，新增 `Detector::process_packet(&mut Flow, l3_pkt, ts, input_info)` 与 `giveup(&mut Flow)`；内部 `FlowTable` 退化为可选 convenience。
3. **逐包状态机框架**：`Inspecting/Partial/Monitoring/Classified`；detector 返回 `Continue/Classified/Partial/GiveUp`。
4. **per-flow 协议状态**：状态放在 `Flow` 内（类似 nDPI 的 per-protocol union/state），不要放在共享 detector 里。
5. **L3 入口 + L2 适配**：以太网解析作为 wrapper；补 VLAN/QinQ、IP-in-IP。
6. **协议栈**：master/app/sub protocol；现有 `Protocol`/`Application` 映射进去。
7. 迁移现有约 50 个 detector：先包一层旧接口，再逐个改为 stateful。

**验收**：

- [ ] 一条双向流只产生一个 `Flow`，方向/计数正确
- [ ] 选定 pcap 上 flow key/分类与 nDPI 对齐 ≥ 95%
- [ ] 现有 1194 用例全绿（或明确迁移清单）
- [ ] 新 API 文档 + 迁移指南

### 3.3 P2 — C ABI 与嵌入式兼容层（4–6 周）

关键任务：

1. cbindgen + `rdpi.h`；opaque `rdpi_detection_module` / `rdpi_flow`。
2. 核心函数：`rdpi_process_packet`、`rdpi_giveup`、flow getters、protocol/category/risk name、serializer。
3. 线程模型：全局 context + per-thread module；`Send/Sync` 审计；可选自定义分配器。
4. 可选 `ndpi-compat` feature：只覆盖目标子集，clean-room 实现，不复制 LGPL 代码。
5. C/C++ 示例 + ABI 兼容性检查。

**验收**：

- [ ] C 示例程序完成 pcap 回放并输出 flow 分类
- [ ] ABI 稳定性检查（cbindgen diff / semver）
- [ ] 与 nDPI API 子集的差分测试通过

### 3.4 P3 — 部署形态与工具链（4–6 周）

关键任务：

1. **Live capture**：libpcap/npcap、BPF、网卡列表、抓包时长。
2. **多线程**：按 flow hash 分片，每线程独立 `Detector`，统计聚合。
3. **CLI 对齐 ndpiReader**：`-i device`、`-f BPF`、`-n threads`、`-k/-K`（JSON/CSV/TLV）、`-C`、`-F` flow stats、`-a` 列出协议/分类/风险、`-B` 禁用协议、`-T/-U` giveup、`--cfg`。
4. **序列化**：per-flow 记录、schema 版本、JSON/CSV/TLV。
5. 可选：Wireshark extcap。

**验收**：

- [ ] Linux/Windows live capture 可用
- [ ] 多线程近线性扩展
- [ ] 与 ndpiReader 输出 diff 通过

### 3.5 P4 — 协议覆盖与数据驱动识别（持续，按波次）

**不要按 nDPI 的 258 个列表逐项移植。** 按目标环境流量占比分波次：

- **Wave 1（核心/企业）**：HTTP/S、DNS over TCP/DoH/DoT、QUIC/HTTP3、TLS/DTLS、SMB/CIFS、NetBIOS、LDAP、Kerberos、RTP/RTCP、RTSP、SIP、MQTT/AMQP/Kafka、Redis/Memcached/MongoDB/Cassandra、MSSQL/Oracle、S7comm/OPC-UA/BACnet/DNP3/IEC 60870。
- **Wave 2（应用层）**：SNI/DNS/HTTP Host/IP/ASN 多信号识别；Top 100 应用；流媒体/游戏/IM；运行期域名列表。
- **Wave 3（长尾）**：按目标环境补充。

同时建立：

- 状态机模板 + 协议测试框架；
- hostname/IP/ASN 数据管线（生成表或运行期加载）；
- Public Suffix List；
- 自定义 category/protocol 文件；
- DNS cache 与“未解析 hostname”检测；
- master/app/sub protocol 分类。

**验收**：

- [ ] 目标环境 Top-50 流量识别率 ≥ nDPI 的 95%
- [ ] 协议覆盖 ≥ 150–200（按目标环境取舍）
- [ ] 新增协议不改核心代码（模板/数据驱动）

### 3.6 P5 — 风险与加密流量分析对等（4–6 周）

关键任务：

1. 与 nDPI 56 个风险位做映射：severity、score、accountability、risk params。
2. risk masks/exceptions、per-host/IP risk masks。
3. 补齐：DGA、punycode、URL risk、malicious JA4/SHA1、risky ASN/domain、suspicious entropy、exploit、error code、anonymous subscriber、unresolved hostname、malware host、obfuscated traffic。
4. TLS heuristics/blocks analysis、DoH analysis、OpenVPN heuristics。
5. nDPI 5.0 的 combined fingerprint（TCP + JA4 + TLS SHA1 cert）与 raw TCP fingerprint/OS hint。

**验收**：

- [ ] 语料上 risk diff 可解释
- [ ] Top 20 风险与 nDPI 的 score/severity 对齐
- [ ] 误报审计记录

### 3.7 P6 — 验证、性能与生态（持续）

关键任务：

1. 导入 nDPI pcap 语料（注意许可/分发限制），做差分测试与 golden output。
2. 对所有解析器做 fuzz；补 CI 矩阵（Linux/macOS/Windows）；Miri/ASan。
3. 性能：零拷贝批处理、避免热路径分配、SIMD；DPDK 可选；性能回归门禁。
4. 文档：迁移指南、协议矩阵、配置参考、API 文档。
5. 绑定/生态：Python/Go bindings、C 示例、目标宿主集成。

**验收**：

- [ ] CI 三平台绿
- [ ] 语料/fuzz 无崩溃
- [ ] 达到既定吞吐目标，且有回归门禁

---

## 4. 里程碑建议

| 版本 | 内容 |
|---|---|
| v0.5 | P0 + P1：双向流、caller-owned flow、逐包状态机、L3 入口（breaking） |
| v0.6 | P2 + P3：C ABI、live capture、多线程、序列化、ndpiReader 风格 CLI |
| v0.7 | P4 Wave 1 + 数据管线 + 协议栈 |
| v0.8 | P5 风险/加密分析对等 |
| v1.0 | P6 差分验证 + 文档 + 迁移指南 + 性能门禁 |

粗略估计：**聚焦“某个明确宿主/场景”的可用替代约 9–15 个月；追求 nDPI 全量功能/协议/风险对等是多年工程。** 这个预期需要先对齐。

---

## 5. 近期可立即执行的 6 个任务

1. **写兼容性矩阵**：`docs/architecture/ndpi-compat.md`，列出目标宿主实际使用的 nDPI API/字段、rDpi 对应能力、差距、验收方式。
2. **写差分测试脚本**：先 20 个 pcap，nDPI ndpiReader JSON vs rDpi JSONL，比较 flow key、protocol、category、breed、confidence、risk mask。
3. **写双向流设计 RFC**：归一化规则、方向判定、JA4L/JA4TS/risk/CLI 的迁移影响、兼容层策略。
4. **原型新 API**：`process_packet(&mut Flow, l3_pkt, ts, input_info)`，feature-gated，保持现有 `detect()` 不变。
5. **补 L3 + VLAN/QinQ 解析**：`parse_l3` + Ethernet wrapper，先支持 IPv4/IPv6/VLAN/QinQ。
6. **C ABI 骨架**：cbindgen + `rdpi.h` + opaque module/flow + 一个 `rdpi_process_packet` + C 示例。

---

## 6. 风险与不建议做的事

| 风险 | 影响 | 应对 |
|---|---|---|
| 兼容范围失控 | 高 | 固定目标宿主/API 子集，以差分测试验收 |
| 双向流重构引发大面积回归 | 高 | 保留单向兼容层，分阶段迁移 detector |
| 协议数据维护成本爆炸 | 高 | 数据管线 + 生成代码 + 运行期加载，不手写枚举 |
| 状态机拖慢热路径 | 中 | 快路径（首包识别）+ 慢路径（状态机/监测）分层，bench 门禁 |
| LGPL 污染 | 高 | clean-room 实现，只参考公开 API 文档/行为，不复制 nDPI 源码 |
| 语料/列表许可 | 中 | 使用前确认 nDPI pcap 与列表的分发许可 |

**现在不要做**：

- 不要先移植 258 个协议；
- 不要在流模型/API 未定时做 SIMD/DPDK；
- 不要追求完全复刻 `ndpi_flow_struct` 的 C 结构布局；
- 不要做 GUI/可视化；
- 不要为长尾协议投入过多元数据深度。

另外需要指出：项目现有定位（“只做协议识别，不做性能优化、流重组、语言绑定、嵌入式部署”）与“替换 nDPI”是**直接冲突**的。替换目标要求 C ABI、live capture、多线程、流重组、序列化、绑定都进入范围，这份边界需要正式重写，否则路线会自相矛盾。

---

## 7. 需要确认的三件事

1. **替换形态**：是 drop-in C ABI（嵌入 ntopng/nProbe 等），还是独立引擎（替代 ndpiReader + 自建采集）？
2. **首批目标**：目标环境的 Top-N 协议/应用清单是什么？这决定 P4 的波次，而不是按 nDPI 的完整列表推进。
3. **兼容策略**：是否允许 breaking change（双向流、公开 `Flow` API）？如果必须保持 0.4.x API 不变，需要长期维护单向兼容层，成本会显著增加。

---

## 附录：关键证据索引

> 行号基于 2026-11-06 工作区快照，代码变更后需复核。

### rDpi

| 事实 | 证据 |
|---|---|
| `FlowKey` 为单向五元组 | `src/core/types.rs:156` |
| `Detector::detect` 主入口 | `src/lib.rs:284` |
| Registry 顺序遍历/首个命中 | `src/protocols/mod.rs:243` |
| 内部 `FlowTable` | `src/core/flow.rs:91` |
| 协议分类/breed/confidence 枚举 | `src/core/types.rs:680`、`:923`、`:955` |
| nDPI category ID 映射（仅分类） | `src/core/types.rs:1039` |
| Application 枚举与域名映射 | `src/core/types.rs:1114`、`src/application/mappings.rs` |
| 风险 flag 定义 | `src/risk/types.rs:11` |
| CLI 仅 pcap 文件 + text/json/jsonl/csv | `src/bin/rdpi.rs` |

### nDPI 5.0

| 事实 | 证据 |
|---|---|
| L3 主处理 API | `src/include/ndpi_api.h:349` |
| 调用方持有 flow | `src/include/ndpi_typedefs.h:1414` |
| 双向流字段/方向 | `src/include/ndpi_typedefs.h:1414` 起 |
| 分类状态机 | `src/include/ndpi_typedefs.h:1305` |
| `ndpi_protocol`（master/app/stack/category/breed） | `src/include/ndpi_typedefs.h:1315` |
| 风险位定义（56 个） | `src/include/ndpi_typedefs.h:112` |
| 协议 ID 枚举（468 个） | `src/include/ndpi_protocol_ids.h` |
| 协议解析源文件（258 个） | `src/lib/protocols/*.c` |
| 生成匹配数据（约 4.75 万行） | `src/lib/inc_generated/*.inc` |
| Public Suffix List（1.6 万行） | `lists/public_suffix_list.dat` |
| pcap 回归语料（460 个） | `tests/**/*.pcap` |
| fuzz target（60+） | `fuzz/` |
| nDPI 5.0 新特性（无限自定义协议、JA4/指纹/URL 规则、combined fingerprint、hostname DNS check、protocol stack） | `CHANGELOG.md` 顶部 nDPI 5.0 章节 |
