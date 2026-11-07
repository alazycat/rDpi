# P0 差分测试骨架（nDPI vs rDpi）

> 状态：骨架（2026-11-06）
> 目标：用同一批 pcap 对比 nDPI 5.0 与 rDpi 的 flow 级分类结果，量化差距。

---

## 1. 文件

| 文件 | 用途 |
|---|---|
| `src/parity.rs` | 库内归一化 schema 与 nDPI JSON 适配器（`feature: json`） |
| `tests/parity/mod.rs` | 流比较器（复用库内 `NormalizedFlow`） |
| `tests/test_parity_harness.rs` | 比较器单元测试（需 `--all-features`） |
| `tests/test_flow_export.rs` | per-flow 导出测试（需 `--features json`） |
| `tests/test_ndpi_adapter.rs` | nDPI JSON 适配器测试（真实 ndpiReader 夹具） |
| `tests/test_parity_corpus.rs` | 20 个 pcap 的语料差分 runner |
| `tests/parity/corpus/` + `golden/` | 语料 pcap 与 nDPI golden JSONL |
| `tests/parity/README.md` | 本文档：语料生成与运行方式 |

---

## 2. 归一化 schema

nDPI 与 rDpi 的输出先转换成每行一条 JSON（JSONL）：

```json
{
  "src_ip": "10.0.0.1",
  "dst_ip": "10.0.0.2",
  "src_port": 12345,
  "dst_port": 80,
  "transport": "tcp",
  "master_protocol": "TLS",
  "app_protocol": "YouTube",
  "category": "Web",
  "breed": "Safe",
  "confidence": "DPI",
  "protocol_stack": ["TLS", "HTTP"],
  "risk_mask": ["TLS_MISSING_SNI"]
}
```

字段说明：

| 字段 | 说明 |
|---|---|
| `src_ip` / `dst_ip` / ports / `transport` | 原始五元组；比较时按双向规范键匹配 |
| `master_protocol` | 主协议（nDPI `master_protocol`） |
| `app_protocol` | 应用协议（nDPI `app_protocol`） |
| `category` | 分类名 |
| `breed` | 风险评级 |
| `confidence` | 置信度 |
| `protocol_stack` | 协议栈（顺序敏感） |
| `risk_mask` | 风险位列表（顺序不敏感） |

---

## 3. 生成 nDPI 输出

在 Linux/WSL 中构建并运行 nDPI：

```bash
cd /path/to/nDPI
./autogen.sh && ./configure && make
./example/ndpiReader -i corpus.pcap -k ndpi.json -K json
```

nDPI JSON 的字段名与归一化 schema 不同，适配器已内置在库中
（`feature: json`）：

```rust
use rdpi::parity::{NormalizedFlow, parse_ndpi_jsonl};

let text = std::fs::read_to_string("ndpi.json")?;
let flows = parse_ndpi_jsonl(&text)?;       // Vec<NormalizedFlow>
// 或逐行：NormalizedFlow::from_ndpi_json(line)
```

映射规则（对齐 nDPI 5.0 `ndpi_flow2json` / `ndpi_protocol2name`）：

| nDPI JSON | 归一化字段 |
|---|---|
| `src_ip` / `dest_ip` / `src_port` / `dst_port` | 同名字段（`dest_ip` → `dst_ip`） |
| `proto`（L4 名称） | `transport`（小写） |
| `ndpi.proto`（`MASTER.APP` 或单协议名） | `master_protocol` / `app_protocol` / `protocol_stack` |
| `ndpi.category` / `ndpi.breed` | 同名字段 |
| `ndpi.confidence`（数字键对象） | `confidence`（取首个值） |
| `ndpi.flow_risk`（数字键对象） | `risk_mask`（取 `risk` 名，归一化为 snake_case） |

> 真实 ndpiReader 输出示例见 `tests/test_ndpi_adapter.rs` 夹具；风险名归一化
> 将 `Unidirectional Traffic` 映射为 `unidirectional_traffic`，与 rDpi
> `RiskFlag::name()` 对齐。

---

## 4. 生成 rDpi 输出

per-flow 归一化输出已落地（方案 A）：

```bash
rdpi -i corpus.pcap -o flows-jsonl > rdpi.jsonl
```

需要构建时启用 `--features "pcap json"`。输出每行一条 `NormalizedFlow`，
字段与第 2 节 schema 一致；库内亦可直接调用
`Detector::normalized_flows()`（`feature: json`）。

已知边界：`detect_at` 仍为单向流模型，同一条连接的两个方向各导出一条
记录。导出按“信息量优先 + 端点字典序”稳定排序；比较器按双向规范五元组
归并时，靠前的记录（元数据更完整）优先。双向流统一后将消除该重复。

---

## 5. 比较规则

`tests/parity/mod.rs` 的 `compare_flows()`：

- **流匹配**：双向规范五元组（`a <-> b`，与方向无关）；
- **协议/应用/category/breed/confidence**：大小写不敏感；
- **protocol_stack**：大小写不敏感、**顺序敏感**；
- **risk_mask**：大小写不敏感、顺序不敏感、去重；
- 输出 `diffs`（字段级差异）、`missing`（期望有、实际无）、`extra`（实际多出）。

---

## 6. 语料与 golden

| 目录 | 内容 |
|---|---|
| `tests/parity/corpus/` | 20 个自生成 pcap（DNS / HTTP / TLS × 主机变体 + 4 个多流混合） |
| `tests/parity/golden/` | 同语料上的真实 ndpiReader 5.0 JSONL（每条流一行） |
| `tests/parity/gen_corpus.py` | 确定性语料生成脚本 |

语料与 golden 均随仓库提交，CI 不需要安装 nDPI 即可回归。重新生成：

```bash
python -I tests/parity/gen_corpus.py
# 在 Linux/WSL 中，对每个 pcap 运行：
ndpiReader -i tests/parity/corpus/<name>.pcap \
  -k tests/parity/golden/<name>.ndpi.json -K json
```

运行语料差分：

```bash
cargo test --all-features --test test_parity_corpus -- --nocapture
```

当前验收口径：

- flow 集合一致（无 missing/extra）；
- master protocol 一致（大小写不敏感）；
- category / breed / risk 的语义差异只报告，暂不判失败（映射表待补）；
- app protocol 差异只报告（nDPI 对 DNS 查询不产出 app；命名差异如
  `GoogleServices` vs `Google` 待映射）。

语料目标 20–50 个：当前 20 个自生成用例已覆盖基础协议与应用变体；
下一批补目标环境真实 pcap（Web / 流媒体 / 企业网）。

---

## 7. 指标与验收

| 指标 | 说明 | 建议验收 |
|---|---|---|
| Flow 级协议一致率 | master protocol 一致 | ≥ 95%（选定语料） |
| 协议 precision/recall | 按协议统计 | Top-20 ≥ 0.95 |
| 应用准确率 | app protocol 一致 | Top-50 ≥ 0.9 |
| category/breed 一致率 | 分类体系对齐 | ≥ 0.9 |
| 元数据字段覆盖率 | 关键字段提取 | Top-20 ≥ 80% |
| risk precision/recall | 风险位对齐 | Top-20 ≥ 0.8 |

---

## 8. TODO

1. ~~nDPI JSON → 归一化 schema 适配器~~ 已完成（`parse_ndpi_jsonl`）；
2. ~~rDpi per-flow JSONL 输出~~ 已完成（`-o flows-jsonl` / `Detector::normalized_flows()`）；
3. ~~20 个自生成 pcap + golden output~~ 已完成；目标环境真实 pcap 待补；
4. 纳入 CI（Linux runner；语料与 golden 已提交，无需运行时依赖 nDPI）；
5. category/breed/app protocol 映射表（使差异报告可判定）。
