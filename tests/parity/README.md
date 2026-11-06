# P0 差分测试骨架（nDPI vs rDpi）

> 状态：骨架（2026-11-06）
> 目标：用同一批 pcap 对比 nDPI 5.0 与 rDpi 的 flow 级分类结果，量化差距。

---

## 1. 文件

| 文件 | 用途 |
|---|---|
| `tests/parity/mod.rs` | 归一化流记录 + 比较器（当前可运行） |
| `tests/test_parity_harness.rs` | 比较器单元测试（需 `--all-features`） |
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

nDPI JSON 的字段名与归一化 schema 不同，需要一个轻量适配器（TODO）：

| nDPI JSON | 归一化字段 |
|---|---|
| `src` / `dst` / `sport` / `dport` / `proto` | `src_ip` / `dst_ip` / `src_port` / `dst_port` / `transport` |
| `ndpi.master_protocol` | `master_protocol` |
| `ndpi.app_protocol` | `app_protocol` |
| `ndpi.category` | `category` |
| `ndpi.breed` | `breed` |
| `ndpi.confidence` | `confidence` |
| `ndpi.risk` | `risk_mask` |
| — | `protocol_stack`（nDPI 5.0 可导出，按实际字段映射） |

> 适配器可以是一个小脚本（`jq`/Python）或 Rust 工具；当前骨架只定义 schema 和比较器。

---

## 4. 生成 rDpi 输出

当前 `rdpi -i corpus.pcap -o jsonl` 输出的是**逐包**记录，不含 flow key；需要新增 per-flow 输出（TODO）：

- 方案 A：扩展 CLI `-o flows-jsonl`，输出 `Detector::flows()` 的每条流；
- 方案 B：新增 `rdpi-flows` 二进制，用 `process_l3_packet` + 外部 flow 表输出双向流。

在 per-flow 输出落地前，可用库的 `Detector::flows()` 在测试/工具里直接导出。

---

## 5. 比较规则

`tests/parity/mod.rs` 的 `compare_flows()`：

- **流匹配**：双向规范五元组（`a <-> b`，与方向无关）；
- **协议/应用/category/breed/confidence**：大小写不敏感；
- **protocol_stack**：大小写不敏感、**顺序敏感**；
- **risk_mask**：大小写不敏感、顺序不敏感、去重；
- 输出 `diffs`（字段级差异）、`missing`（期望有、实际无）、`extra`（实际多出）。

---

## 6. 运行

```bash
cargo test --all-features --test test_parity_harness
```

后续接入真实语料后，建议增加：

```bash
cargo test --all-features --test test_parity_corpus -- --ignored
```

（需要环境变量 `NDPI_READER` / `RDPI_BIN` 指向可执行文件。）

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

1. nDPI JSON → 归一化 schema 适配器；
2. rDpi per-flow JSONL 输出；
3. 选定 20–50 个 pcap 作为首批语料；
4. 生成 golden output 并纳入 CI（nDPI 侧在 Linux runner 运行）。
