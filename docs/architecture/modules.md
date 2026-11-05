# rDpi 模块清单与分层（modules）

> 生成时间：2026-11-04；证据规则同 [overview.md](file:///d:/rust_code/rDpi/docs/architecture/overview.md)。

## 1. 顶层模块（src/lib.rs:50-62）

| 模块 | 职责 | 关键证据 |
|---|---|---|
| `error` | thiserror 错误定义，导出 `Error`/`Result` | src/error.rs:1；lib.rs:65 |
| `core` | 核心类型、流管理、猜测引擎、统计 | src/core/mod.rs:5-8 |
| `parser` | 链路层/网络层/传输层解析 | src/parser/（ethernet/ip/tcp/udp） |
| `protocols` | 49 个协议 detector + Registry | src/protocols/mod.rs |
| `application` | JA4 指纹、域名→应用映射、反向 Trie | src/application/mod.rs:17-20 |
| `asn1` | ASN.1 BER 解码、OID、类型 | src/asn1/mod.rs:1-3 |
| `pcap`（feature=pcap） | pcap/pcapng 批量处理迭代器 | src/pcap.rs:39-49 |
| `rule`（feature=rule） | JSON 自定义规则引擎，DPI 之前执行 | src/rule/mod.rs:1-13 |
| `risk`（feature=risk） | 风险分析注册表 + 5 个处理器 | src/risk/processors/mod.rs:2-15 |

## 2. core 子模块

- **types.rs**（1263 行）：`TransportProto`（types.rs:9-18）、`Protocol` 枚举约 55 个变体 + `Other(u16)`（types.rs:33-133）、`Metadata` 枚举 23 个变体（types.rs:161-211）、`DetectionResult`（types.rs:476-492，含 confidence/category/breed/app_protocol/risks）、`ProtocolCategory` 26 分类（types.rs:541-594，含 nDPI 兼容 ID 映射 types.rs:867-896）、`ProtocolBreed` 8 级风险评级（types.rs:763-780）、`Confidence` 7 级置信度（types.rs:784-799）、`Application` 41 个应用枚举（types.rs:939-995）。
- **flow.rs**：`Flow`（flow.rs:51-69，含 packets_seen/dpi_only/risks）、`FlowTable`（flow.rs:91-171，HashMap 存储，`max_entries` 明确注释"预留，未实现 LRU 淘汰" flow.rs:102；超时清理 flow.rs:149-165）。
- **guess/**：`GuessEngine` 按 match_domain → match_ip → match_port 顺序回退（guess/mod.rs:15-37）；域名匹配基于 aho-corasick（guess/domain.rs:6）；端口匹配返回 `Confidence::MatchByPort`（guess/port.rs:7-45）。
- **stats.rs**：流统计辅助（具体消费方 **[目前无法确认]**，FlowTable 内部使用 FlowStats，flow.rs:24-33）。

## 3. parser 子模块

解析链：`parse_packet` → `ethernet::parse` → `ip::parse` → 按 IP 协议号分发 `tcp::parse` / `udp::parse`；ICMP 及其他协议返回零端口 + 原始 payload；失败经 `?` 向上传播 `Result`（parser/mod.rs:8-51）。**全部手写解析，未用 etherparse**（全库 grep 零命中）。

## 4. protocols 模块（49 个协议目录）

### 检测器架构
- trait `ProtocolDetector`：`name()` + `detect(payload)` + 可选 `detect_with_context(payload, ctx)`（protocols/mod.rs:103-112）。
- `Registry`：`Vec<Box<dyn ProtocolDetector>>` 顺序遍历，**首个命中即返回**（mod.rs:134-141）；`detect_with_ports` 构造 `DetectContext{src_port,dst_port,is_http3_port}`（mod.rs:144-163）。
- `register_defaults`：注册顺序注释"按特异性递减"：QUIC → TLS → SSH → SNMP → … → HTTP → DNS → Phase 12A/11A 低特异性协议（mod.rs:174-276）。
- 目录模式：detector.rs（识别）+ parser.rs（元数据提取）+ mod.rs（组装/注册），如 http/mod.rs:1-11、tls/mod.rs:37-83。

### 协议 × Feature 对照（依据 protocols/mod.rs:7-100 与 Cargo.toml:22-44）

| Feature | 协议模块 |
|---|---|
| 默认 dns | dns |
| 默认 http | http |
| 默认 tls | tls（含 certificate.rs 证书解析） |
| quic | quic（crypto.rs Initial 解密 + parser.rs，无 detector.rs 目录结构） |
| ssh | ssh |
| smtp | smtp |
| mail | pop3, imap |
| infra | ntp, dhcp, bgp, dhcpv6, vxlan, netflow, ike, ptpv2 |
| snmp | snmp（R1 已修复 2026-11-04） |
| modbus | modbus |
| database | mysql, postgresql, redis, mongodb |
| proto3 | ftp, sip, rtp, http2（HPACK 元数据，2026-11-05）, websocket, rtmp, socks |
| iot | mqtt |
| vpn | wireguard, openvpn, l2tp, pptp |
| voip | stun, turn, mgcp, h323 |
| auth | kerberos, ldap, radius |
| remote | rdp |
| storage | nfs |
| misc | tftp, rsync, whois, syslog, telnet, vnc（R7 已修复 2026-11-04，mod.rs `#[cfg(feature = "misc")]`） |

注：quic/snmp/modbus/ntp/dhcp 目录无 detector.rs，通过 `register()` 暴露的 detector 完成检测，与 http/tls 的三分文件模式不同（**[根据代码推断]**：各 mod.rs 内含 detector 实现，未逐一核对行号）。

### quic 模块（2026-11-04 扩展：Initial 解密；2026-11-05 扩展：服务端方向 / Retry 完整性校验）

- **crypto.rs**：全手写密码学（零新增依赖）——AES-128 核心（仅加密方向，FIPS-197 向量）、GCM/GHASH（NIST SP 800-38D 向量；GHASH 为 Shoup 式 4-bit 查表乘法 `GhashTable`，8 KiB 栈上表，release 实测较逐位实现 150 倍加速，逐位版保留为测试 oracle）、HMAC-SHA256/HKDF（RFC 4231/5869 向量）、QUIC Initial 密钥派生 + 头保护移除 + 载荷 AEAD 解密（RFC 9001 §A.1 客户端方向向量 + §5.2 服务端方向经独立 Python 实现交叉核对）；支持 QUIC v1/v2/draft-29/draft-28 四套 salt；`Side::{Client,Server}` 双方向（server secret = "server in" label，密钥材料均取自包头 DCID 字段）。
- **parser.rs**：`decrypt_initial`（客户端方向）、`decrypt_initial_server`（服务端方向，DCID 字段即 ODCID）、`parse_crypto_frames`（提取 CRYPTO 帧拼接）、`decrypt_client_hello`（feature=tls，套假 record 头复用 `tls::parse_client_hello`）、`decrypt_server_alpn`（feature=tls，复用 `tls::parse_server_hello_alpn`）。
- **tls/parser.rs**：新增 `parse_server_hello_alpn`（msg_type 0x02 校验 + 字段布局自洽校验 + ALPN 扩展提取，复用私有 `parse_alpn_extension`）。
- **mod.rs**：detect/detect_with_context 接线解密富化——先客户端方向（ClientHello → sni/alpn/**ja4** + SNI 应用识别），失败再服务端方向（ServerHello → 仅 alpn，无 SNI/JA4）；解密失败静默降级为仅头部信息。QuicMetadata 增 `alpn`/`ja4` 字段（types.rs），JA4 与 TLS 路径同源（application::compute_ja4）。
- **rule / CLI 消费**（2026-11-05）：rule 引擎 `sni_contains` 覆盖 QUIC SNI（lib.rs 规则分支追加 Initial 解密回退，`rule`+`tls`+`quic` 三 feature）；CLI 域名列识别 `Metadata::Quic`（rdpi.rs）。
- **Transport Parameters 提取**（2026-11-05）：tls/parser.rs 增 `extract_quic_transport_parameters`（通用 `find_client_hello_extension` 遍历器按类型取扩展值，0x0039）；quic/parser.rs 增 `parse_transport_parameters`（RFC 9000 §18.2：varint ID + varint 长度 + 值，仅收录数值型参数 max_idle_timeout/max_udp_payload_size/initial_max_data/initial_max_streams_bidi/initial_max_streams_uni → `QuicTransportParams`，字节值参数跳过）；`decrypt_client_meta` 与 `decrypt_client_hello` 共用单次解密链路（前者多返回 TP）；QuicMetadata 增 `transport_parameters` 字段（types.rs）。无扩展/解析失败/解密失败时该字段为 None，不影响其余元数据。注意：RFC 9000 varint 仅 1/2/4/8 字节形式、最大值 2⁶²−1（首字节前缀占 2 位）。A.2 官方样例自带 0x0039 扩展（50 字节），全链路断言官方值。
- **非 Initial 长包头识别**（2026-11-05）：`detect_other_long_header`（mod.rs）覆盖 0-RTT（0xD0）/Handshake（0xE0）/Retry（0xF0）/VN（version=0，不要求 Fixed Bit）——仅提取 version+DCID（`is_quic_long_header`/`parse_long_header_dcid`，parser.rs），无解密富化；version≠0 时要求 Fixed Bit=1，DCID 长度上限 20 校验。此前这些包全部漏判落入 guess 兜底。
- **CLI/bench 消费**（2026-11-05）：CLI 域名列 QUIC 分支 SNI→ALPN 回退（rdpi.rs:77）；`cargo bench` 增 `detect_quic_header_only`（~5µs）/`detect_quic_initial_decrypt`（~29µs，A.2 样本全解密+CH+JA4），bench 文件 cfg(quic) 双 criterion_group。
- **Retry 完整性校验**（2026-11-05，RFC 9001 §5.8）：crypto.rs 增 v1/v2 固定常数 key+nonce（经 quic-go retry.go 与 aioquic packet.py **双独立实现逐字节交叉核对**）+ `retry_integrity_tag`（AES-128-GCM 空明文，AAD = 伪包 `odcid_len || odcid || retry_without_tag`；`aes128_gcm_encrypt` 解除测试门控复用）；parser.rs 增 `parse_retry_packet`（结构自洽 + token/tag 切分；类型位按版本区分——v1 `(b&0x30)==0x30` / v2 `==0x00`（RFC 9369 映射重排，draft 版本不解析））与 `verify_retry_integrity`（ODCID = 客户端 Initial 的 DCID；`None`=无法判定、`Some(false)`=校验失败）。风险接线见 §6 quic 处理器第三判定。Golden 向量经 Node.js OpenSSL（`crypto.createCipheriv aes-128-gcm`）独立生成内嵌于测试（v1/v2 各一组 + 篡改/错误 ODCID/截断/draft 拒绝路径，quic/parser.rs 测试 12 项）。
- 测试：crypto.rs 内单测（各 RFC 官方向量 + 服务端向量）+ parser.rs 单测（A.2 端到端、服务端 Initial 构造/解密/ALPN、detect 级 alpn 富化、SH 独立解析与拒绝、Retry 解析与校验）+ tests/test_quic.rs 集成（RFC 9001 A.2 1200 字节样本 → SNI "example.com"/ALPN "alpn"，篡改 1 字节降级）。

### http2 模块（2026-11-05 扩展：HPACK 元数据提取）

- **hpack.rs**（新增）：全手写 HPACK 解码（RFC 7541，零新增依赖）——Huffman 解码（257 符号码表，运行时 OnceLock 构建 trie；码表经 nghttp2 与 Go x/net 双源逐项交叉验证 + Kraft 精确和 Σ2^(30-bits)=2³⁰ + 前缀无冲突）、静态表 61 项（Appendix A）、前缀整数/字符串字面量解码、帧内动态表（索引 ≥62）。上限防护：MAX_HEADERS=64 / MAX_STRING_LEN=4096 / MAX_DYN_ENTRIES=64，畸形输入返回 None。
- **parser.rs**：新增 `extract_request_headers`——preface 后按 9 字节帧头扫描（MAX_FRAMES=8），首个 HEADERS 帧按 flags 跳过 PADDED/PRIORITY 后解码头块，提取 `:authority`/`:method`/`:path`；帧截断/解码失败/无请求伪头部返回 None。无 preface 时直接按帧流扫描（定型流富化路径）。
- **detector.rs**：preface 命中即尝试同包提取，元数据起步 `Http2Metadata::default()`；返回 `Metadata::Http2`（types.rs 新变体）。
- **lib.rs**：`enrich_http2_headers`（feature=proto3）——定型流回显路径一次性富化（字段全空时对后续包提取并写回，协议不重检，对齐 enrich_tls_cert / ADR-0004）。能力边界与验证见 risks.md R14；测试 tests/test_http2.rs（9 测试）。

## 5. application 模块

- `identify(sni)`：惰性初始化 `ReverseTrie` 查域名后缀（application/mod.rs:17-20）。
- `mappings.rs`：域名后缀→`Application` 映射表（mappings.rs:5-220，覆盖 YouTube/Netflix/Bilibili/抖音/微信/Telegram 等）。
- `ja4.rs`：JA4 TLS 指纹 `tlsNN.{ciphers12}.{extensions12}.{groups6}` + SHA256 截断（ja4.rs:18-48, 57-58）。

## 6. risk 模块（feature=risk）

- `RiskRegistry::analyze_packet` / `analyze_flow` 统一入口（risk/mod.rs:32-90），Default 注册 5+1 个处理器：tls、dns、http、behavioral、tls_cert（risk/processors/mod.rs:2-15）+ quic（挂 quic+risk 双 feature，risk/processors/quic.rs）。
- 结果类型 `RiskResult{flag,severity,description}`（risk/types.rs:78-88），由 Detector 附加到流与检测结果（lib.rs:332-341）。
- tls_cert 处理器依赖 Phase 12B 的证书解析（src/protocols/tls/certificate.rs，TlsMetadata 证书字段 types.rs:237-244）。
- quic 处理器（Phase 13，2026-11-05）：逐包判定 QUIC 长包头（不依赖解密）——0-RTT 包（首字节 0xD0）→ `QuicZeroRtt`（Medium，0-RTT 数据可重放）、Initial 携带 draft-28/29 版本 → `QuicNonStandardVersion`（Low）、Retry 完整性校验失败（RFC 9001 §5.8，ODCID 取自流元数据中客户端 Initial 的 DCID；无 ODCID/版本不支持/校验无法判定时不报警）→ `QuicRetryIntegrityFail`（Medium，疑似伪造/注入）。按流去重（flow.risks 已含同 flag 则不重复产出）；仅 UDP 流生效。RiskFlag 的 QUIC 分节现有 3 个变体（risk/types.rs:45-51，default_severity/name 同步）。

## 7. rule 模块（feature=rule）

`Rule{id,protocol,condition,metadata}`（rule/mod.rs:21-26）；条件：dst_port/src_port/sni_contains/payload_contains，AND 语义（mod.rs:64-70+），特异性评分端口 1 分、SNI/payload 各 2 分（mod.rs:44-59）；JSON 反序列化经 serde（rule/parser.rs:3, rule/mod.rs:151）。执行时机：内置 DPI 之前（lib.rs:254-274），`rules_only` 模式可跳过内置 DPI 与 Guess（lib.rs:107-109, 271-273）。

## 8. asn1 模块

`ber.rs`（`BerReader` ber.rs:9）、`types.rs`（`Asn1Class` types.rs:7、`Asn1Value` types.rs:48）、`oid.rs`（encode/decode，含 doctest）。消费方：snmp/parser.rs:5（**路径错误导致编译失败**）与 tls/certificate.rs:6（路径正确）。

## 9. CLI（src/bin/rdpi.rs）

参数：`-i/--input` pcap 路径、`-o/--output`（text/json/csv）、`-v/--verbose`（rdpi.rs:15-27）。流程：`PcapProcessor::process_file` → 逐包统计协议计数 → 汇总输出（rdpi.rs:29-66）。注意：`#[command(version = "0.2.0")]`（rdpi.rs:14）与 crate 版本 0.4.1 不一致（**[代码明确实现]**）。
