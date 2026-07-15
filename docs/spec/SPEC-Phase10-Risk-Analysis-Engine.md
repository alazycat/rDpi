# SPEC: Phase 10 — 风险分析引擎

> 源自: `docs/prd/PRD-Phase10-Risk-Analysis-Engine.md`
> 日期: 2026-07-15 | 累计协议数: ~41

---

## 1. Architecture

### 1.1 新增组件

```
src/
├── risk/                          [NEW]
│   ├── mod.rs                     — RiskRegistry, RiskProcessor trait
│   ├── types.rs                   — RiskFlag, RiskSeverity, RiskResult 枚举
│   └── processors/                [NEW]
│       ├── mod.rs                 — register_default_processors()
│       ├── tls.rs                 — TLS 相关风险检测器
│       ├── dns.rs                 — DNS 相关风险检测器
│       ├── http.rs                — HTTP 相关风险检测器
│       └── behavioral.rs          — 网络行为风险检测器
├── core/
│   ├── flow.rs                    [MODIFY: Flow.risks 字段]
│   └── types.rs                   [MODIFY: DetectionResult.risks 字段]
└── lib.rs                         [MODIFY: Detector.risk_registry]
```

### 1.2 检测管道扩展

```
Detector::detect(packet)
  │
  ├─ 1. 包解析
  ├─ 2. 协议检测 (现有)
  │     └─ Registry.detect_with_ports()
  │
  ├─ 3. 风险分析 [NEW]
  │     └─ RiskRegistry.analyze(packet, flow)
  │         ├─ TLS processors:   SNI/证书/密码/版本
  │         ├─ DNS processors:   大包/碎片
  │         ├─ HTTP processors:  可疑内容/爬虫
  │         └─ Behavioral proc:  单向/定期/探测
  │
  ├─ 4. 结果合并 [NEW]
  │     └─ risks → DetectionResult.risks + Flow.risks
  │
  └─ 5. 返回 DetectionResult
```

### 1.3 风险累积策略

```
每个包独立分析:
  analyze_packet()  → 返回该包触发的风险 → 追加到 Flow.risks

流关闭时触发:
  analyze_flow()    → 返回整个流期间累积的风险
                      (如 UnidirectionalTraffic 需要流生命周期判断)
```

---

## 2. Data Model

### 2.1 Cargo.toml

```toml
[features]
risk = ["serde", "serde_json"]   # 新增
```

### 2.2 RiskFlag 枚举

```rust
#[cfg(feature = "risk")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskFlag {
    // TLS (7)
    TlsMissingSni,
    TlsSelfSignedCert,
    TlsCertExpired,
    TlsCertValidityTooLong,
    TlsWeakCipher,
    TlsObsoleteVersion,
    TlsAlpnSniMismatch,
    // DNS (3)
    DnsLargePacket,
    DnsFragmented,
    DnsSuspiciousTraffic,
    // HTTP (4)
    HttpSuspiciousContent,
    HttpCrawlerBot,
    HttpObsoleteServer,
    ClearTextCredentials,
    // Behavioral (5)
    UnidirectionalTraffic,
    PeriodicFlow,
    ProbingAttempt,
    ObfuscatedTraffic,
    BinaryDataTransfer,
    // General (2)
    UnsafeProtocol,
    UnknownProtocol,
}
```

### 2.3 RiskSeverity

```rust
#[cfg(feature = "risk")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}
```

### 2.4 RiskResult

```rust
#[cfg(feature = "risk")]
#[derive(Debug, Clone)]
pub struct RiskResult {
    pub flag: RiskFlag,
    pub severity: RiskSeverity,
    pub description: String,
}
```

### 2.5 Flow 变更

```rust
pub struct Flow {
    pub key: FlowKey,
    pub protocol: Option<Protocol>,
    pub stats: FlowStats,
    pub state: FlowState,
    pub metadata: Option<Metadata>,
    pub packets_seen: u32,
    pub dpi_only: bool,
    #[cfg(feature = "risk")]
    pub risks: Vec<RiskResult>,   // 新增
}
```

### 2.6 DetectionResult 变更

```rust
pub struct DetectionResult {
    pub protocol: Protocol,
    pub confidence: Confidence,
    pub metadata: Metadata,
    pub category: ProtocolCategory,
    pub breed: ProtocolBreed,
    pub app_protocol: Option<Application>,
    #[cfg(feature = "risk")]
    pub risks: Vec<RiskResult>,   // 新增，默认空
}
```

### 2.7 RiskRegistry

```rust
#[cfg(feature = "risk")]
pub struct RiskRegistry {
    proc_packet: Vec<Box<dyn RiskProcessor>>,  // 逐包分析
    proc_flow: Vec<Box<dyn RiskProcessor>>,    // 流结束时分析
}

#[cfg(feature = "risk")]
impl RiskRegistry {
    pub fn new() -> Self;
    pub fn register(&mut self, proc: Box<dyn RiskProcessor>);
    pub fn analyze_packet(&self, parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult>;
    pub fn analyze_flow(&self, flow: &Flow) -> Vec<RiskResult>;
}
```

### 2.8 RiskProcessor trait

```rust
#[cfg(feature = "risk")]
pub trait RiskProcessor: Send + Sync {
    fn name(&self) -> &'static str;
    fn analyze_packet(&self, _parsed: &ParsedPacket, _flow: &Flow) -> Vec<RiskResult> {
        vec![]
    }
    fn analyze_flow(&self, _flow: &Flow) -> Vec<RiskResult> {
        vec![]
    }
}
```

---

## 3. Detector 集成

```rust
pub struct Detector {
    registry: Registry,
    flow_table: FlowTable,
    default_guess: bool,
    #[cfg(feature = "rule")]
    rule_engine: Option<RuleEngine>,
    #[cfg(feature = "rule")]
    rules_only: bool,
    #[cfg(feature = "risk")]
    risk_registry: RiskRegistry,      // 新增
}
```

### detect() 方法变更

在协议检测完成后、返回结果前，插入风险分析步骤：

```rust
pub fn detect(&mut self, packet: &[u8]) -> crate::error::Result<Option<DetectionResult>> {
    // ... 现有协议检测逻辑 ...

    // 3. 风险分析 (新增, feature = risk)
    #[cfg(feature = "risk")]
    {
        if let Some(ref mut result) = result {
            let risks = self.risk_registry.analyze_packet(&parsed, flow);
            result.risks.extend(risks.clone());
            flow.risks.extend(risks);
        }
    }

    Ok(result)
}
```

### 新增 expire_flows 风险回调

在流过期时触发 analyze_flow：

```rust
pub fn expire_flows(&mut self) -> Vec<FlowKey> {
    let expired = self.flow_table.expire_timeout();
    #[cfg(feature = "risk")]
    {
        for key in &expired {
            if let Some(flow) = self.flow_table.get(key) {
                let _risks = self.risk_registry.analyze_flow(flow);
                // risks 可输出到日志或回调
            }
        }
    }
    expired
}
```

---

## 4. 内置风险检测器

### 4.1 TLS — TlsMissingSni

```rust
fn analyze_packet(&self, parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
    if flow.protocol != Some(Protocol::Tls) { return vec![]; }
    match &flow.metadata {
        Some(Metadata::Tls(tls)) => {
            if tls.sni.is_none() || tls.sni.as_deref() == Some("") {
                vec![RiskResult::new(RiskFlag::TlsMissingSni, RiskSeverity::Medium, "TLS ClientHello missing SNI extension")]
            } else { vec![] }
        }
        _ => vec![],
    }
}
```

### 4.2 TLS — TlsObsoleteVersion

```rust
fn analyze_packet(&self, parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
    if flow.protocol != Some(Protocol::Tls) { return vec![]; }
    match &flow.metadata {
        Some(Metadata::Tls(tls)) => {
            match tls.version.as_deref() {
                Some("1.0") | Some("1.1") => {
                    vec![RiskResult::new(RiskFlag::TlsObsoleteVersion, RiskSeverity::High, 
                        format!("TLS version {} is obsolete", tls.version.as_deref().unwrap_or("")))])
                }
                _ => vec![],
            }
        }
        _ => vec![],
    }
}
```

### 4.3 TLS — TlsWeakCipher

依赖 TLS 解析器提取密码套件信息。检测已知弱密码（RC4、DES、3DES、NULL、EXPORT 等）。

### 4.4 TLS — TlsCertValidityTooLong

检测 TLS 证书有效期是否超过当前最佳实践（398 天 / Apple/Google 限制）。需要 Rustls 或 TLS 解析器提取证书。

### 4.5 TLS — TlsSelfSignedCert / TlsCertExpired

需要 TLS 证书链解析，rDpi 目前只有 SNI 提取。这些风险检测器需要在 **TLS 解析器增强**之后才能实现。初始版本可标记为 `NotImplemented` 或跳过。

### 4.6 DNS — DnsLargePacket

```rust
fn analyze_packet(&self, parsed: &ParsedPacket, flow: &Flow) -> Vec<RiskResult> {
    if flow.protocol != Some(Protocol::Dns) { return vec![]; }
    if parsed.payload.len() > 512 {
        vec![RiskResult::new(RiskFlag::DnsLargePacket, RiskSeverity::Medium, 
            format!("DNS response size {} bytes exceeds 512", parsed.payload.len()))]
    } else { vec![] }
}
```

### 4.7 DNS — DnsFragmented

需要检查 IP 头的 MF 标志。依赖 parser/ip.rs 的扩展。

### 4.8 Behavioral — UnidirectionalTraffic

```rust
fn analyze_flow(&self, flow: &Flow) -> Vec<RiskResult> {
    // 如果流只有单向数据包（所有包来自同一方向）
    // 需要 Flow 中存储方向信息
    vec![] // 初始占位
}
```

### 4.9 Behavioral — ProbingAttempt

```rust
fn analyze_flow(&self, flow: &Flow) -> Vec<RiskResult> {
    // TCP: SYN 发送后无数据交换
    // 需要 Flow 中存储 TCP 状态信息
    vec![] // 初始占位
}
```

---

## 5. 实现顺序

### 批次 1: 基础 + TLS (4-8 Issues)

| Issue | 内容 | 文件 |
|-------|------|------|
| 10.0 | 基础架构: RiskFlag/RiskSeverity/RiskResult + RiskRegistry + RiskProcessor trait | risk/types.rs, risk/mod.rs, flow/types modify |
| 10.1 | TlsMissingSni + TlsObsoleteVersion | risk/processors/tls.rs |
| 10.2 | TlsWeakCipher + TlsAlpnSniMismatch | risk/processors/tls.rs 扩展 |
| 10.3 | TlsCertValidityTooLong + SelfSigned + Expired | risk/processors/tls.rs 扩展 (依赖 TLS 解析器增强) |

### 批次 2: DNS + HTTP (2-3 Issues)

| Issue | 内容 |
|-------|------|
| 10.4 | DnsLargePacket + DnsFragmented |
| 10.5 | HttpSuspiciousContent + HttpCrawlerBot + ClearTextCredentials |

### 批次 3: 网络行为 (2-3 Issues)

| Issue | 内容 |
|-------|------|
| 10.6 | UnidirectionalTraffic + ProbingAttempt |
| 10.7 | PeriodicFlow + ObfuscatedTraffic + BinaryDataTransfer |

---

## 6. Testing Strategy

### 6.1 测试场景

| Risk | 正例测试 | 反例测试 |
|------|---------|---------|
| TlsMissingSni | ClientHello 无 SNI 扩展 | ClientHello 含 SNI |
| TlsObsoleteVersion | TLS 1.0 ClientHello | TLS 1.2/1.3 ClientHello |
| DnsLargePacket | DNS 响应 1024 字节 | DNS 响应 200 字节 |
| UnidirectionalTraffic | 仅 SYN 无数据交换 | 完整 TCP 握手+数据 |

### 6.2 测试架构

```rust
#[cfg(test)]
mod tests {
    fn test_risk_detection() {
        let mut detector = Detector::new();
        // 构造缺失 SNI 的 TLS ClientHello
        let packet = build_tls_clienthello_no_sni();
        let result = detector.detect(&packet).unwrap().unwrap();
        assert!(result.risks.iter().any(|r| r.flag == RiskFlag::TlsMissingSni));
    }
}
```

---

## 7. Security Considerations

- 风险分析不应影响协议检测结果
- 风险处理器不应 panic（使用 Result 或防御性编程）
- 风险数据可能包含敏感信息（域名、IP），需注意日志脱敏
- 风险引擎应可禁用（feature gate），不影响核心检测性能
- Flow.risks 无上限可能导致内存增长 → 建议每个 Flow 使用固定容量或 LRU

---

## 8. Open Questions

| # | Question | Impact |
|---|----------|--------|
| 1 | 自签名证书检测需要 TLS 证书解析 — rDpi 当前无此能力。是增强 TLS 解析器还是延迟实现？ | 影响 Batch1 范围 |
| 2 | 证书过期检测需要系统时钟 + 证书 valid_from/valid_to。如何获取？Rustls 提供吗？ | 影响实现方案 |
| 3 | DnsFragmented 需要 IP 层 MF 标志 — parser 当前未暴露此信息。需扩展 ParsedPacket？ | 影响 Batch2 |
| 4 | UnidirectionalTraffic 需要流方向信息 — Flow 当前无此字段。如何追踪？ | 影响 Batch3 |
