# 业务追踪：TLS SNI → 应用识别 → 风险分析 全链路

> 生成时间：2026-11-04；证据规则同 [overview.md](file:///d:/rust_code/rDpi/docs/architecture/overview.md)。
> 三分类标注：**[代码明确实现]** / **[根据代码推断]** / **[目前无法确认]**。

## 0. 业务一句话

一个 TCP 443 端口上的 TLS ClientHello 包进入 `Detector::detect` 后：识别为 TLS 协议 → 提取 SNI/版本/JA4/ALPN/证书字段 → 用 SNI 域名后缀反查应用（YouTube/微信等）→ 对流附加 TLS 风险标记（弱密码套件、缺失 SNI、自签证书等）。

## 1. 完整调用链

```text
Detector::detect(packet)                                   lib.rs:221
 ├─ parser::parse_packet → ParsedPacket(payload=TCP载荷)     parser/mod.rs:8-51
 ├─ FlowTable::get_or_create(五元组)                         lib.rs:235, flow.rs:123-127
 ├─ flow.protocol.is_none() → Registry::detect_with_ports    lib.rs:277-281
 │   └─ 顺序遍历 detectors，QUIC 在 TLS 之前注册              protocols/mod.rs:177-180
 │   └─ TlsDetector::detect(payload)                         tls/mod.rs:42-83
 │       ├─ is_tls_record: len≥5 && data[0]==0x16 && data[1]==0x03   parser.rs:42-44
 │       ├─ parse_client_hello(payload)                      parser.rs:79-105
 │       │   ├─ parse_client_hello_fields                    parser.rs:108-222
 │       │   │   ├─ 跳过 record(5B)+handshake(4B)+version(2B)+random(32B)
 │       │   │   ├─ session_id → cipher_suites → compression 逐段边界检查
 │       │   │   ├─ SNI 扩展 0x0000 → parse_sni_extension     parser.rs:202-204, 231-256
 │       │   │   ├─ supported_versions 0x002b → "TLS 1.3"     parser.rs:205-209, 286-300
 │       │   │   └─ supported_groups 0x000a → Vec<u16>        parser.rs:210-214, 307-322
 │       │   └─ version = supported_version 优先,否则 record 层  parser.rs:93, 86
 │       ├─ application::identify(sni)                       tls/mod.rs:57-58
 │       │   └─ OnceLock<ReverseTrie> 全局惰性单例            application/mod.rs:15-21
 │       │       └─ 反向 Trie + label 边界规则               trie.rs:28-31, 51-72
 │       ├─ compute_ja4(version, ciphers, extensions, groups) tls/mod.rs:59-62 → ja4.rs:18-48
 │       ├─ certificate::parse_certificate → cert 四字段      tls/mod.rs:66-71
 │       ├─ 守卫: sni/version/cert 全空 → 返回 None           tls/mod.rs:74-76
 │       └─ DetectionResult::new(Tls).with_metadata.with_confidence(Dpi)  tls/mod.rs:78-82
 ├─ flow.protocol = Some(Tls)；metadata 存入流               lib.rs:283-285, 327-329
 ├─ 流已识别后: 后续包直接回显 Tls，不再解析                   lib.rs:316-319
 └─ RiskRegistry::analyze_packet(&parsed, &flow)             lib.rs:332-341
     ├─ TlsRiskProcessor（要求 flow.protocol==Tls 且 metadata 为 Tls）  risk/processors/tls.rs:32-39
     │   ├─ TlsMissingSni: sni 为 None/空串                   tls.rs:62-68
     │   ├─ TlsObsoleteVersion: ver=="1.0"||"1.1"             tls.rs:71-79  ⚠ 见 F1
     │   └─ TlsWeakCipher: 命中 36 个弱套件 ID                 tls.rs:82-94, 12-22
     └─ TlsCertRiskProcessor                                 risk/processors/tls_cert.rs:24-57
         ├─ TlsSelfSignedCert: subject == issuer             tls_cert.rs:30-35
         ├─ TlsCertExpired: cert_valid_to < now              tls_cert.rs:38-43
         └─ TlsCertValidityTooLong: 有效期 > 398 天           tls_cert.rs:8, 46-54
```

## 2. 数据状态变化

| 阶段 | flow.protocol | flow.metadata | result |
|---|---|---|---|
| ClientHello 首包 | None → Tls（lib.rs:283-285） | None → Metadata::Tls（lib.rs:327-329） | Some(TLS, Confidence::Dpi, tls/mod.rs:81) |
| 同流后续包 | Tls 不变 | 已有（不再更新） | Some(TLS)（lib.rs:316-319，**新元数据不再解析**） |
| 非 TLS 流 DPI 期内 | None | None | None |
| DPI 20 包未识别 | → 猜测结果（lib.rs:308-314） | → 猜测 metadata | 置信度 MatchByPort/MatchByIp |

**[代码明确实现]** 证书字段只在该流**首个被识别的包**里解析——若 ClientHello 与 ServerHello/Certificate 在同一 TCP 段（payload 同时含两者，tls/mod.rs:65-71 有意支持），或证书帧晚于识别帧到达，后者**不会被解析**（流已识别，走 lib.rs:316-319 短路）。**[根据代码推断]** 实际影响：TLS 服务端证书帧通常在识别后的包里到达 → cert 字段大概率**永远为 None** → TlsCertRiskProcessor 三个证书风险几乎不可能触发。⚠ 此推断需第四步探针测试 P6 验证（高价值）。

## 3. 事务边界 / 锁与并发

- 无事务概念：单线程 `&mut self` API（lib.rs:221），无内部锁。
- 全局共享状态仅一处：`static TRIE: OnceLock<ReverseTrie>`（application/mod.rs:15），首次 identify 时初始化，之后只读。线程安全性依赖 `ReverseTrie: Sync`（内部为 HashMap 只读，成立）。**[代码明确实现]**
- `Detector` 非 Sync 非 Clone（内含 HashMap），多线程需外部分片。**[根据代码推断]**

## 4. 异常处理与补偿

- 解析全程边界检查，畸形包返回 None/空 Vec，不 panic（parser.rs:138-196, 249-251 等）。**[代码明确实现]**
- 无重试/补偿机制：识别失败流在 giveup 前每包重试 DPI，之后永久交给猜测。**[代码明确实现]**
- `String::from_utf8(...).ok()`：非 UTF-8 SNI 静默丢弃（parser.rs:255）。**[代码明确实现]**

## 5. 幂等性

- detect 天然幂等于"流协议唯一确定"不变量：协议只写一次（lib.rs:253 条件 + lib.rs:283-285, 310-312）。重复喂同一包不会改变协议。**[代码明确实现]**
- 风险结果非幂等：每包 analyze_packet 都会重新产生 RiskResult 并追加到 `flow.risks`（lib.rs:335-337）——同一风险在 N 个包上重复累计 N 次。**[代码明确实现]**（影响下游统计语义，**[目前无法确认]** 是否有去重消费方）

## 6. 外部依赖与降级

- 无网络/磁盘 IO；纯内存计算。
- 降级路径：SNI 缺失 → application 为 None（tls/mod.rs:57-58 and_then）；版本缺失 → JA4 为 None（tls/mod.rs:59-62 map 于 Option）。**[代码明确实现]**

## 7. 发现的问题（新增，编号接 risks.md）

### F1【高】TlsObsoleteVersion 永不触发：版本字符串格式跨模块断裂 —— ✅ 已修复（2026-11-04，第五步 #2）

- **分类**：[代码明确实现]
- **证据**：解析器产出 `"TLS 1.0"`/`"TLS 1.1"`（带前缀，[tls/parser.rs:327-330](file:///d:/rust_code/rDpi/src/protocols/tls/parser.rs#L327-L330)）；风险处理器原比较 `ver == "1.0" || ver == "1.1"`（无前缀，[risk/processors/tls.rs:72](file:///d:/rust_code/rDpi/src/risk/processors/tls.rs#L72)）。两者永不相等。
- **为何测试没抓住**：risk 单元测试自造数据 `Some("1.0")`（tls.rs:150,167），绕过了真实解析器输出格式；test_tls.rs:601,615 断言的是 `"TLS 1.2"`/`"TLS 1.3"` 带前缀格式——两组测试各自正确，集成面无人钉住。
- **旁证**：TlsMetadata.version 的 doc 注释写 `"1.2", "1.3"` 格式（types.rs:228），与实际产出格式也不一致。
- **修复内容**：tls.rs:73 比较改为 `"TLS 1.0" || "TLS 1.1"` + 格式来源注释；处理器单测数据同步为 `"TLS 1.0"`；探针 a1_risk 翻转为"必须触发"（test_pin_rules.rs:306）。验证：默认 272 绿 + --all-features 636 绿。

### F2【中】TlsAlpnSniMismatch 是死旗标：提交信息声称已实现，代码只有占位注释

- **分类**：[代码明确实现]
- **证据**：flag 定义于 [risk/types.rs:25](file:///d:/rust_code/rDpi/src/risk/types.rs#L25)（severity/display 齐备 types.rs:113,140）；唯一生产点应是 [risk/processors/tls.rs:96-98](file:///d:/rust_code/rDpi/src/risk/processors/tls.rs#L96-L98)，但那里只有注释"这是一个简化的启发式检测"，无任何 push。全库 grep 无第二个生产点。
- **对照**：git 提交 34cc561 标题声称 "4 cert risk processors (SelfSignedCert, Expired, ValidityTooLong, AlpnSniMismatch)"——第 4 个未实现。
- **✅ 已修复（2026-11-04，用户批准）**：[risk/processors/tls.rs:104-117](file:///d:/rust_code/rDpi/src/risk/processors/tls.rs#L104-L117) 实现——启发式判定为「ALPN 通告 "h3"（HTTP/3 仅存在于 QUIC/UDP）但流承载于 TCP」→ 触发 TlsAlpnSniMismatch（Medium，维持原定义）。flag 名保留（公开枚举，删除即 breaking）；severity/文档同步。+2 单测（h3-over-TCP 触发 / h2-over-TCP 与 h3-over-UDP 不触发）。risk lib 122 绿。

### F3【中】证书字段几乎不可能被填充 —— ✅ 已修复（2026-11-04，用户批准）

- **分类**：[代码明确实现]（P6/a2 探针实锤）
- **证据链**：tls/mod.rs:66-71 只在"该流尚未识别时的那一个包"里运行；证书通常在后续包 → a2 钉死证书字段恒 None。
- **修复**：[lib.rs:327-331,371-398](file:///d:/rust_code/rDpi/src/lib.rs#L327-L331) 回显路径新增 `enrich_tls_cert`——已定型 TLS 流对后续包做廉价预检（cert_subject 为空 + `is_certificate_message` 6 字节检查），命中才做 ASN.1 解析并写回 flow.metadata；字段填充后不再重复解析。协议不重检（ADR-0004 一次定型语义不变）；detect 热路径分配语义不变（预检失败零分配）。
- **验证**：探针 a2 翻转为回归（真实 DER 证书记录构造器入 test_pin_rules.rs；断言回显包 cert_subject 填充且 SNI 保持）。默认 229 / all-features 563+72 全绿。
- **残留**：a3 连体 ClientHello+Certificate 场景仍未覆盖（is_certificate_message 检查 data[5] 为 ClientHello 类型）——属低频场景，不在本次范围。

### F4【低】SNI 解析只取第一个 ServerName，且类型不符即放弃

- **分类**：[代码明确实现]
- **证据**：[tls/parser.rs:240-241](file:///d:/rust_code/rDpi/src/protocols/tls/parser.rs#L240-L241) 首个 entry 非 hostname 类型直接返回 None，不遍历后续 entries。实际流量几乎总是单 hostname，**[根据代码推断]** 影响极小。

### F5【信息】应用识别的 label 边界规则

- **分类**：[代码明确实现]
- **证据**：[trie.rs:60-66](file:///d:/rust_code/rDpi/src/application/trie.rs#L60-L66) 只在 `.` 边界或串尾接受匹配（防 `notyoutube.com` 误判 youtube.com，application/mod.rs:43-47 有测试）；匹配沿反向串继续走以实现最长后缀优先（application/mod.rs:50-53）。
- **注意**：DOMAIN_MAPPINGS 表内容（mappings.rs:5-220）的覆盖面与正确性**[目前无法确认]**（需人工抽验，非代码可证）。

## 8. 「目前无法确认」清单 → 第四步探针测试

| # | 待验证项 | 方法 |
|---|---|---|
| P6 | 证书字段在多包流中是否永远为 None | 构造 ClientHello(包1) + Certificate(包2) 序列喂 Detector，断言 cert_subject |
| P7 | TlsObsoleteVersion 对真实 "TLS 1.0" ClientHello 是否确实不触发 | 构造 record 版本 0x0301 的 ClientHello 喂完整 Detector+risk，断言无 ObsoleteVersion（钉住 F1） |
| P8 | 同一 TCP 段内 ClientHello+Certificate 连体时证书字段能否解析 | 构造连体 payload，断言 cert 字段 |
| P9 | flow.risks 是否随包数无界重复累计 | 同一 TLS 流喂 10 包，数 flow.risks.len() |
| P10 | JA4 在 version=None 时为 None、在 TLS1.3 时非空 | 单元断言 |
