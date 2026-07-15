# PRD: Phase 10 — 风险分析引擎

> **版本**: 1.0 | **日期**: 2026-07-15 | **标签**: `ready-for-agent`

---

## Problem Statement

rDpi 目前只能回答"这是什么协议"，无法回答"这个流量是否有风险"。nDPI 的 55+ 风险标记（Risk Indicator）是其最核心的高级功能之一，被 ntopng、Security Onion 等安全平台广泛使用。缺少风险分析能力是 rDpi 替换 nDPI 的关键架构级缺口。

### 具体不足

1. 无法检测 TLS 证书异常（过期/自签/SNI 缺失）
2. 无法检测 DNS 可疑行为（大包/碎片/隧道）
3. 无法检测明文凭据传输
4. 无法检测扫描行为（单向流量/探测）
5. 无法输出风险评分用于告警/排障

---

## Solution

为 rDpi 新增**风险分析引擎**，作为与协议检测平行的第二分析管道。

### 架构变更

```
当前: packet → 协议检测 → DetectionResult
Phase 10: packet → 协议检测 → RiskProcessor 链 → EnrichedResult (带 risks)
                                                ↓
                                          Flow.risks 累积
```

### 概念

| 概念 | 说明 | 示例 |
|------|------|------|
| RiskFlag | 风险标记枚举 | TlsMissingSni, DnsLargePacket |
| RiskSeverity | 风险等级 | Low, Medium, High, Critical |
| RiskProcessor | 风险检测器 trait | impl RiskProcessor for TlsRiskDetector |
| RiskResult | 单个风险实例 | { flag, severity, description, flow_key } |

---

## User Stories

1. 作为安全分析师，我希望 TLS 连接缺少 SNI 时被标记，以便发现潜在的隐蔽隧道
2. 作为安全分析师，我希望 TLS 证书有效期过长时被标记，以便发现证书管理问题
3. 作为网络管理员，我希望检测到 DNS 大包时被标记，以便发现 DNS 隧道
4. 作为网络管理员，我希望检测到明文凭据传输时被标记，以便推动加密迁移
5. 作为安全分析师，我希望检测到单向流量时被标记，以便发现扫描行为
6. 作为运维人员，我希望每条流能关联风险列表，以便统一告警
7. 作为开发者，我希望风险检测器可插拔，以便按需启用

---

## Implementation Decisions

### 1. RiskFlag 枚举（首批 21 个）

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskFlag {
    // === TLS 安全 (7) ===
    TlsMissingSni,              // TLS ClientHello 无 SNI 扩展
    TlsSelfSignedCert,          // 自签名证书
    TlsCertExpired,             // 证书已过期
    TlsCertValidityTooLong,     // 证书有效期 > 398 天
    TlsWeakCipher,              // 使用弱密码套件
    TlsObsoleteVersion,         // TLS 版本 < 1.2
    TlsAlpnSniMismatch,         // ALPN 与 SNI 不匹配

    // === DNS 异常 (3) ===
    DnsLargePacket,             // DNS 响应 > 512 字节
    DnsFragmented,              // DNS 碎片
    DnsSuspiciousTraffic,       // 可疑 DNS 查询模式

    // === HTTP 安全 (4) ===
    HttpSuspiciousContent,      // HTTP 可疑内容
    HttpCrawlerBot,             // 爬虫/机器人
    HttpObsoleteServer,         // 过时的 HTTP 服务器
    ClearTextCredentials,       // 明文凭据

    // === 网络行为 (5) ===
    UnidirectionalTraffic,      // 单向流量
    PeriodicFlow,               // 定期流量（心跳/轮询）
    ProbingAttempt,             // 探测尝试
    ObfuscatedTraffic,          // 混淆流量
    BinaryDataTransfer,         // 二进制数据传输

    // === 通用 (2) ===
    UnsafeProtocol,             // 使用不安全协议
    UnknownProtocol,            // 未能识别的协议
}
```

### 2. RiskSeverity 等级

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}
```

### 3. RiskResult 结构

```rust
#[derive(Debug, Clone)]
pub struct RiskResult {
    pub flag: RiskFlag,
    pub severity: RiskSeverity,
    pub description: String,
}
```

### 4. RiskProcessor trait

```rust
pub trait RiskProcessor: Send + Sync {
    fn name(&self) -> &'static str;
    fn analyze_packet(&self, packet: &ParsedPacket, flow: &Flow) -> Vec<RiskResult>;
    fn analyze_flow(&self, flow: &Flow) -> Vec<RiskResult>;
}
```

### 5. Flow 变更

```rust
pub struct Flow {
    // ... 现有字段 ...
    pub risks: Vec<RiskResult>,  // 新增
}
```

### 6. DetectionResult 变更

```rust
pub struct DetectionResult {
    // ... 现有字段 ...
    pub risks: Vec<RiskResult>,  // 新增，默认空 Vec
}
```

### 7. Detector 变更

```rust
pub struct Detector {
    registry: Registry,
    risk_registry: RiskRegistry,   // 新增
    flow_table: FlowTable,
    // ...
}
```

### 8. Feature Gate

`risk` 新增 feature gate，将所有风险代码可选编译。

```toml
risk = ["serde", "serde_json"]  # 新增
```

---

## Testing Decisions

### 三层测试

| 层级 | 内容 | 数量 |
|------|------|------|
| Parser/Detector 单测 | 每个风险场景的单元测试 | ≥3 每个 Processor |
| 集成测试 | 完整包链路 → 触发风险 | ≥1 每个 Processor |
| 回归测试 | 无风险流量不应误报 | ≥1 |

---

## Out of Scope

- **风险评分聚合算法**（总风险分/归一化）：留待 Phase 10 后期
- **基于风险自动动作**（丢弃/告警/限流）：上层应用职责
- **ML 风险检测**（基于模型分类风险）：超出范围
- **风险时间线/历史趋势**：可视化层职责
- **风险导出格式**（CEF/LEEF）：上层应用职责

---

## Implementation Order

### 批次 1: 基础架构 + TLS 风险 (7 个 Processor)
| # | Risk | 依赖 | 复杂度 |
|---|------|------|--------|
| — | RiskFlag 枚举 + RiskRegistry + Flow/Result 扩展 | — | ⭐⭐ |
| — | TlsMissingSni | Batch1 | ⭐ |
| — | TlsSelfSignedCert | Batch1 | ⭐⭐ |
| — | TlsCertExpired | Batch1 | ⭐⭐ |
| — | TlsCertValidityTooLong | Batch1 | ⭐ |
| — | TlsWeakCipher | Batch1 | ⭐⭐ |
| — | TlsObsoleteVersion | Batch1 | ⭐ |
| — | TlsAlpnSniMismatch | Batch1 | ⭐ |

### 批次 2: DNS + HTTP 风险 (7 个 Processor)
| # | Risk | 依赖 | 复杂度 |
|---|------|------|--------|
| — | DnsLargePacket | Batch2 | ⭐ |
| — | DnsFragmented | Batch2 | ⭐ |
| — | DnsSuspiciousTraffic | Batch2 | ⭐⭐ |
| — | HttpSuspiciousContent | Batch2 | ⭐⭐ |
| — | HttpCrawlerBot | Batch2 | ⭐ |
| — | HttpObsoleteServer | Batch2 | ⭐ |
| — | ClearTextCredentials | Batch2 | ⭐⭐ |

### 批次 3: 网络行为风险 (7 个 Processor)
| # | Risk | 依赖 | 复杂度 |
|---|------|------|--------|
| — | UnidirectionalTraffic | Batch3 | ⭐ |
| — | PeriodicFlow | Batch3 | ⭐⭐⭐ |
| — | ProbingAttempt | Batch3 | ⭐⭐ |
| — | ObfuscatedTraffic | Batch3 | ⭐⭐ |
| — | BinaryDataTransfer | Batch3 | ⭐ |
| — | UnsafeProtocol | Batch3 | ⭐ |
| — | UnknownProtocol | Batch3 | ⭐ |
