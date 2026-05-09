# rDpi

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Rust Deep Packet Inspection library - 轻量级、高性能的深度包检测库。

## 特性

- **传输层解析**: TCP/UDP/ICMP 协议识别
- **应用层检测**: DNS、HTTP、TLS、SSH、SMTP、QUIC 协议
- **元数据提取**:
  - DNS: 查询域名
  - HTTP: 方法、路径、Host 头
  - TLS: SNI、版本信息
  - SSH: 协议版本、软件版本
  - SMTP: 主机名、客户端标识
  - QUIC: 版本、连接 ID
- **流管理**: 五元组追踪、超时清理
- **模块化设计**: Feature gates 按需启用

## 安装

```toml
[dependencies]
rdpi = "0.1.0"
```

## 使用示例

```rust
use rdpi::Detector;

fn main() -> rdpi::error::Result<()> {
    let mut detector = Detector::new();
    
    // 检测 HTTP 流量
    let http_packet = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    if let Some(result) = detector.detect(http_packet)? {
        println!("Protocol: {:?}", result.protocol);
        if let rdpi::Metadata::Http(meta) = result.metadata {
            println!("Host: {:?}", meta.host);
            println!("Method: {:?}", meta.method);
        }
    }
    
    Ok(())
}
```

## Feature Gates

| Feature | 默认 | 描述 |
|---------|------|------|
| `dns` | ✅ | DNS 协议检测，提取查询域名 |
| `http` | ✅ | HTTP 协议检测，提取方法、路径、Host |
| `tls` | ✅ | TLS 协议检测，提取 SNI 和版本 |
| `ssh` | ❌ | SSH 协议检测，提取协议和软件版本 |
| `smtp` | ❌ | SMTP 协议检测，提取主机名 |
| `quic` | ❌ | QUIC 协议检测，提取版本和连接 ID |

禁用默认 features:

```toml
[dependencies]
rdpi = { version = "0.1.0", default-features = false, features = ["http", "tls", "ssh"] }
```

## 支持的协议

| 协议 | Feature | 元数据 |
|------|---------|--------|
| DNS | `dns` | 查询域名 |
| HTTP | `http` | 方法、路径、Host 头 |
| TLS | `tls` | SNI、TLS 版本 |
| SSH | `ssh` | 协议版本、软件版本 |
| SMTP | `smtp` | 主机名、客户端标识 |
| QUIC | `quic` | 版本、连接 ID |

## 性能

- 单核吞吐量: 500 Mbps - 1 Gbps (完整功能)
- 内存: 每万并发流约 10-20 MB
- 零拷贝设计，最小化分配

## 开发状态

### 已完成

- [x] Phase 1: 核心基础设施 + DNS 检测
- [x] Phase 2: HTTP + TLS 协议检测
- [x] Phase 3: SSH + SMTP 协议检测

### 进行中

- [ ] Phase 4: QUIC 协议检测 (开发中)

### 规划中

- [ ] Phase 5: 流媒体/IM 协议（基于 SNI）
- [ ] Phase 6: 自定义规则引擎

## 技术栈

- **语言**: Rust 2024 Edition
- **协议解析**: etherparse
- **错误处理**: thiserror
- **TLS 解析**: 手动实现（无外部依赖）

## 许可证

MIT License
