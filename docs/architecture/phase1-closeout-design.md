# 阶段 1 收尾设计：DoH/DoT/DoQ、HTTP CONNECT/Proxy、FTP 有状态会话

> 生成时间：2026-11-07
> 状态：设计已确认，待实现
> 关联文档：
> - [nDPI 纯 Rust 实现方案](ndpi-pure-rust-plan.md)（§9 待办、§10 首批 A+B 实施顺序）
> - [协议/应用覆盖候选清单](protocol-coverage-plan.md)（§10.1 阶段 1）
> - [风险与已知问题](risks.md)（F43 有状态框架先例）
> - [AGENTS.md](../../AGENTS.md)（F43 及测试基线）

---

## 1. 背景与目标

`ndpi-pure-rust-plan.md` 的阶段 1 要求补齐 A 组（Web/Cloud）缺口，并把已确认的有状态框架推广到剩余高频协议。当前状态：

- A 组已有 TLS、HTTP/1.x、HTTP/2、HTTP/3/QUIC、DNS、WebSocket；
- 缺口为 **DoH/DoT/DoQ** 与 **HTTP CONNECT/Proxy**；
- F43 已完成 SMTP/POP3/IMAP/WebSocket 有状态化，但 **FTP 仍是无状态单包 detector**；
- 现有 `DissectorState` 框架（SSH/HTTP/DNS-TCP/TLS/HTTP2/邮件/WebSocket）可直接复用。

本轮目标：

1. 在同一批 detector 内完成 DoH/DoT/DoQ 与 HTTP CONNECT/Proxy 子分类，不新增 detector、不改 Registry 注册顺序；
2. FTP 支持跨 TCP 段的命令/响应重组，并提取 `username`、`filename` 多命令元数据；
3. 保持与 nDPI 5.0 的差分输出兼容：新增协议在 parity 导出中映射到 `TLS.DoH_DoT` / `QUIC.DoH_DoT` / `HTTP_Connect` / `HTTP_Proxy`；
4. 扩展自生成语料与 golden，验证 flow 级分类一致。

---

## 2. 协议模型

`Protocol` 枚举新增 5 个变体。与现有 `Tls`/`Quic`/`Http` 一致，变体本身**无条件编译**；只有对应 detector feature 开启时才可能产出。

| 变体 | 内部 category | breed | 产出位置 |
|---|---|---|---|
| `Doh` | `ProtocolCategory::Dns` | `ProtocolBreed::Acceptable` | TLS detector |
| `Dot` | `ProtocolCategory::Dns` | `ProtocolBreed::Acceptable` | TLS detector |
| `Doq` | `ProtocolCategory::Dns` | `ProtocolBreed::Acceptable` | QUIC detector |
| `HttpConnect` | `ProtocolCategory::Web` | `ProtocolBreed::Acceptable` | HTTP detector |
| `HttpProxy` | `ProtocolCategory::Web` | `ProtocolBreed::Acceptable` | HTTP detector |

同步修改：

- `src/core/types.rs`：`Protocol::category()`、`Protocol::breed()` 补 match 分支；
- `src/rule/parser.rs`：增加 `doh` / `dot` / `doq` / `http_connect` / `http_proxy` 名称映射（未知名称原本回退 `Protocol::Other(0)`，不破坏兼容）；
- `src/parity.rs`：新增 nDPI 兼容映射（见第 6 节）。

---

## 3. DoH / DoT（TLS 路径）

### 3.1 解析器域名表

新增 `src/protocols/tls/doh.rs`：

- 静态域名表（约 15–20 条公开 DoH 解析器域名）：
  `dns.google`、`dns.google.com`、`mozilla.cloudflare-dns.com`、`cloudflare-dns.com`、
  `dns.adguard.com`、`dns.adguard-dns.com`、`dns.quad9.net`、`dns9.quad9.net`、
  `dns10.quad9.net`、`dns11.quad9.net`、`doh.opendns.com`、`doh.powerdns.org`、
  `dns.nextdns.io`、`doh.cleanbrowsing.org`、`doh.libredns.gr`、
  `dns.dns-over-https.com`、`doh.dns.sb`、`dns.mullvad.net`、`doh.mullvad.net`；
- `pub(crate) fn is_doh_resolver(host: &str) -> bool`：全等或“`.` + 表项”后缀匹配，大小写不敏感；
- 单测覆盖：精确命中、子域命中、非命中、大小写、相似但不匹配的域名（如 `notdns.google`）。

### 3.2 TLS detector 分类

`TlsDetector::detect` 在解析完所有 record 后，按优先级选择协议：

1. **ALPN 精确等于 `dot`**（ClientHello 或 ServerHello）→ `Protocol::Dot`；
2. **SNI 命中 DoH 解析器表** → `Protocol::Doh`；
3. 其余 → `Protocol::Tls`。

ALPN 优先于 SNI：解析器同时提供 DoT 和 DoH 时，`dot` ALPN 表示 DoT 连接。

### 3.3 端口 853 回退

- 新增 `TlsDetector::detect_with_context`：
  - 调用 `self.detect(payload)`；
  - 若结果为 `Protocol::Tls` 且任一端端口为 853（TCP），升级为 `Protocol::Dot`，置信度 `Confidence::DpiPartial`；
  - ALPN/SNI 已给出的 `Dot`/`Doh` 不被覆盖。
- 有状态 `process()` 的 `Classified` 出口复用同一端口回退函数（抽取 `apply_dot_port_hint(result, ctx)`）。
- 无 ALPN/SNI 且非 853 的 TLS 流保持 `Tls`。

### 3.4 边界

- 仅 SNI 域名表，不识别明文 HTTP 的 `application/dns-message` / `/dns-query`；
- 无 SNI 的 DoH 漏判（nDPI 还可通过证书 SAN 命中，本轮未扩展证书 SAN 提取）；
- 端口 853 回退置信度为 `DpiPartial`，与 ALPN `dot` 的 `Dpi` 区分；
- DoT 可在非 853 端口运行，只要 ALPN 为 `dot` 仍可识别。

---

## 4. DoQ（QUIC 路径）

`QuicDetector` 从 Initial 解出 ALPN 后选择协议：

- `alpn.starts_with("doq")`（覆盖 `doq`、`doq-i00` 等）→ `Protocol::Doq`，`Confidence::Dpi`；
- 否则沿用现有逻辑：
  - `ctx.is_http3_port && 标准版本` → `Protocol::Http3`，`Confidence::DpiPartial`；
  - 其余 → `Protocol::Quic`，`Confidence::Dpi`。

抽取纯函数便于表驱动测试：

```rust
fn select_quic_protocol(
    alpn: Option<&str>,
    is_http3_port: bool,
    is_standard_version: bool,
) -> (Protocol, Confidence)
```

`detect` 与 `detect_with_context` 都调用该函数，避免两处逻辑漂移。

边界：

- DoQ 依赖 QUIC Initial 解密（`tls` feature）；未启用 `tls` 时无 ALPN，不产出 `Doq`；
- 前缀匹配与 nDPI 的 `strncmp(..., "doq", 3)` 行为一致，`doqfoo` 也会命中；
- 仅 Initial 包可解密；mid-stream 无 Initial 的流不会分类为 `Doq`。

---

## 5. HTTP CONNECT / Proxy

`HttpDetector::detect` 请求分支：

1. 方法为 `CONNECT`（大小写不敏感）→ `Protocol::HttpConnect`；
2. 请求目标以 `http://` 开头（大小写不敏感，按字节比较避免 UTF-8 切片 panic）→ `Protocol::HttpProxy`；
3. 其余请求 → `Protocol::Http`。

响应分支保持 `Protocol::Http`；有状态 HTTP 头重组路径自动继承新分类。

边界：

- CONNECT 的 authority（`host:port`）不映射到 `HttpMetadata.host`，也不触发应用识别；
- HTTP Proxy 仅识别绝对 URI `http://`；`https://` 代理通常走 CONNECT；
- 不解析代理认证头、CONNECT 之后的隧道内容。

---

## 6. FTP 有状态会话

### 6.1 状态与元数据

- `src/core/types.rs` 新增：

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FtpDissectorState {
    /// 跨包累积的行字节
    pub buffer: Vec<u8>,
    /// 已提取的用户名（USER 命令，首个非空值）
    pub username: Option<String>,
    /// 已提取的文件名（RETR/STOR 命令，首个非空值）
    pub filename: Option<String>,
}
```

- `DissectorState` 新增 `Ftp(FtpDissectorState)` 变体；
- `FtpMetadata` 新增 `username: Option<String>`、`filename: Option<String>`；
- 所有 `FtpMetadata` 构造点同步补字段。

### 6.2 `FtpDetector::process()`

接管条件（仅 `state == None` 时）：

- 服务端数字响应前缀：首字节 `0x32..=0x36`（ASCII `2`–`6`，覆盖 FTP 200–600 响应码）；
- 且不是 SMTP 端口（25/465/587），与 SMTP/FTP 共有 `220` 语法对称让位（F10）；
- 不接管大写客户端命令，避免抢占 HTTP 等客户端前缀协议；FTP 为 server-first 协议，正常抓包从 banner 开始。

处理流程：

1. 缓冲上限 `FTP_LINE_MAX_BYTES = 4096`，超限 `GiveUp`；
2. 追加 payload，按 `\n` 切分，处理**所有完整行**，尾部半行保留；
3. 每条完整行：
   - 数字响应 → `parse_ftp_response`，记录 `response_code`；
   - 大写命令 → `parse_ftp_command`：
     - `USER <name>` → `username`（首个非空值）；
     - `RETR <file>` / `STOR <file>` → `filename`（首个非空值）；
4. 首条完整行无法解析 → `GiveUp`，回退无状态路径；
5. 解析成功 → `Classified(DetectionResult::new(Protocol::Ftp).with_metadata(...))`，元数据注入累积的 username/filename；
6. 已定型后继续接收双向数据：缓冲区中存在完整行 → 返回 `Classified` 触发监测合并；只有半行 → 返回 `Continue` 等待后续段。

### 6.3 监测与合并

- `src/lib.rs` 的 `flow.monitoring` 匹配新增 `DissectorState::Ftp(_)`；
- `merge_detected_metadata` 新增 `Metadata::Ftp` 分支：
  - `username` / `filename`：首个非 None 值保留；
  - `verb` / `argument` / `response_code` / `is_client`：随最新消息更新（新值存在时覆盖）；
- `src/protocols/http/detector.rs` 的显式 `DissectorState` match 增加 `Ftp(_) => return None`；
- `src/bin/rdpi.rs` 主元数据显示：FTP 优先 `username`，回退 `filename`。

### 6.4 边界

- 仅 server-first 接管；mid-stream 缺 banner、客户端先发的 FTP 流保持无状态；
- username/filename 仅保留首个非空值，不枚举多文件传输；
- 不保存 `PASS` 密码（风险处理器仍按需检测明文凭据）；
- 不建模 `PORT`/`PASV` 数据通道、不解析 FTP 数据连接；
- 不支持 FTPS（TLS 加密后的 FTP 命令不可见）；
- 单 flow 仍只允许一个活跃 `DissectorState`。

---

## 7. Parity 导出映射

`NormalizedFlow::from_flow` 增加特殊映射，保证与 nDPI 5.0 输出一致：

| rDpi 协议 | master | app | protocol_stack |
|---|---|---|---|
| `Doh` / `Dot` | `TLS` | `DoH_DoT` | `["TLS","DoH_DoT"]` |
| `Doq` | `QUIC` | `DoH_DoT` | `["QUIC","DoH_DoT"]` |
| `HttpConnect` | `HTTP_Connect` | — | `["HTTP_Connect"]` |
| `HttpProxy` | `HTTP_Proxy` | — | `["HTTP_Proxy"]` |

`ndpi_compat_classification` 增加：

- `Doh` / `Dot` / `Doq` → `("Network", "Acceptable")`；
- `HttpConnect` / `HttpProxy` → `("Web", "Acceptable")`。

`HttpConnect` / `HttpProxy` 固定 `app_protocol = None`（不做应用识别）；`Doh`/`Dot`/`Doq` 固定 `app_protocol = "DoH_DoT"`（覆盖可能的 SNI 应用识别结果）。普通协议路径保持原逻辑：`master_protocol = protocol_name(flow.protocol)`，`app_protocol` 取 `metadata.application()`。

`protocol_name` 增加 `HttpConnect → "HTTP_Connect"`、`HttpProxy → "HTTP_Proxy"` 映射；DoH/DoT/DoQ 由特殊分支处理，不依赖该函数。

---

## 8. 文件改动清单

| 文件 | 改动 |
|---|---|
| `src/core/types.rs` | 5 个 `Protocol` 变体、`FtpDissectorState`、`DissectorState::Ftp`、`FtpMetadata` 字段、category/breed 分支 |
| `src/protocols/tls/doh.rs` | 新建：DoH 解析器域名表 + `is_doh_resolver` |
| `src/protocols/tls/mod.rs` | `mod doh`、协议选择、`detect_with_context`、端口 853 回退 |
| `src/protocols/quic/mod.rs` | `select_quic_protocol`、DoQ 判定 |
| `src/protocols/http/detector.rs` | CONNECT/Proxy 分类、`DissectorState::Ftp` match 分支 |
| `src/protocols/ftp/detector.rs` | `process()`、接管/缓冲/多行解析/元数据富化、单测 |
| `src/protocols/ftp/parser.rs` | 按行切分/多行解析辅助函数 |
| `src/lib.rs` | `flow.monitoring` 增加 `Ftp`、`merge_detected_metadata` 增加 `Metadata::Ftp` |
| `src/rule/parser.rs` | 新协议名称映射 |
| `src/parity.rs` | nDPI 兼容 master/app/stack 与 category/breed 映射 |
| `src/bin/rdpi.rs` | FTP 元数据显示 |
| `tests/test_flow_export.rs` / `tests/test_ndpi_adapter.rs` | parity 映射测试 |
| `tests/parity/gen_corpus.py` | 新增 5 个语料用例 |
| `tests/parity/corpus/`、`tests/parity/golden/` | 新语料与 ndpiReader 5.0 golden |
| `AGENTS.md`、`docs/architecture/*.md` | F44 记录、模块/覆盖/路线图更新 |

---

## 9. 测试计划

### 9.1 单元测试

- **TLS**：
  - ClientHello ALPN `dot` → `Dot`；
  - SNI `dns.google` → `Doh`；
  - 普通 SNI → `Tls`；
  - ServerHello ALPN `dot` → `Dot`；
  - 853 端口回退 → `Dot` + `DpiPartial`；
  - ALPN `dot` + DoH SNI 同时命中 → `Dot`（优先级）。
- **QUIC**：`select_quic_protocol` 表驱动：`doq`、`doq-i00`、`h3` + 443、`h3` + 非 443、`None`。
- **HTTP**：`CONNECT` → `HttpConnect`；绝对 URI `http://` → `HttpProxy`；普通请求 → `Http`；大小写。
- **FTP**：
  - banner 跨段（`220 FTP ser` + `ver ready\r\n`）；
  - USER 跨段（`US` + `ER alice\r\n`）；
  - RETR/STOR 提取 filename；
  - 单段多命令（`USER a\r\nRETR f.txt\r\n`）全部解析；
  - SMTP 端口不接管；FTP 端口正常接管；
  - 缓冲溢出 `GiveUp`；
  - 监测模式元数据合并（username 保留、最新命令覆盖）；
  - `first_byte_gate` 覆盖合法样本。
- **Parity**：5 个新变体的 `from_flow` master/app/stack/category/breed 映射。

### 9.2 语料差分

扩展 `tests/parity/gen_corpus.py`，新增：

1. `tls_dot.pcap`：TCP 853，TLS ClientHello，ALPN `dot`；
2. `tls_doh_sni.pcap`：TCP 443，TLS ClientHello，SNI `dns.google`；
3. `http_connect.pcap`：TCP 8080，`CONNECT example.com:443 HTTP/1.1`；
4. `http_proxy.pcap`：TCP 8080，`GET http://example.com/ HTTP/1.1`；
5. `ftp_split_session.pcap`：TCP 21，banner + USER + RETR 跨段。

用 WSL 中的 ndpiReader 5.0 生成 golden，现有 `test_parity_corpus.rs` 自动纳入。若 nDPI 输出与映射预期不一致，先修正映射再提交。

### 9.3 门禁

```bash
cargo test
cargo test --all-features
cargo test --features risk
cargo fmt --check
cargo clippy --all-features --all-targets -- -D warnings
```

验收：

- 新增单测全部通过；
- 新增语料在 master/app/category/breed/confidence/risk gate 上一致；
- 现有 44 个语料用例与全部存量测试无回归。

---

## 10. 文档更新

- `AGENTS.md`：新增 F44 条目（实现摘要、测试基线、模块说明）；
- `docs/architecture/modules.md`：tls/quic/http/ftp 模块说明；
- `docs/architecture/risks.md`：F44 实现细节与已知边界；
- `docs/architecture/ndpi-pure-rust-plan.md` §9：标记 DoH/DoT/DoQ、HTTP CONNECT/Proxy、FTP 有状态化完成，更新待办；
- `docs/architecture/protocol-coverage-plan.md`：更新缺口表与“下一步”。

---

## 11. 实施顺序

1. `Protocol` 枚举 + category/breed + rule 名称映射（先让新变体可编译）；
2. TLS DoH/DoT（域名表、协议选择、端口回退）；
3. QUIC DoQ（纯函数 + detector 接入）；
4. HTTP CONNECT/Proxy；
5. FTP 状态/元数据/`process()`/monitoring/CLI；
6. parity 映射 + 单测；
7. 语料生成 + golden + 差分测试；
8. 文档回写、全量门禁、提交。

---

## 12. 风险与注意事项

| 风险 | 应对 |
|---|---|
| TLS 分类改动影响现有 44 个语料 | 只在新信号（ALPN `dot` / DoH 域名）出现时改变协议；普通 TLS 保持 `Tls`；差分测试兜底 |
| DoH 域名表误报 | 仅收录公开解析器域名；纯 SNI 全等/子域匹配；语料与单测覆盖负样本 |
| FTP 接管抢占其他数字响应协议 | 仅 server-first 数字前缀 + 非 SMTP 端口；完整行解析失败即 `GiveUp` 回退 |
| FTP 多行缓冲热路径分配 | 复用 F43 的 `Vec<u8>` 缓冲模式；正常流只分配一次；超限快速 `GiveUp` |
| parity 映射与 nDPI 版本差异 | 用本地 ndpiReader 5.0 生成 golden，映射以真实输出为准 |
| `Protocol` 变体增加导致 match 不穷尽 | 编译期暴露，逐处补齐；`category()`/`breed()` 为唯一穷尽匹配点 |
