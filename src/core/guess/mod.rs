//! 检测猜测引擎
//!
//! 当 DPI 无法识别协议时，依次尝试域名匹配 → IP 子网 → 端口回退。
//!
//! 引擎可配置：[`GuessEngine::builder()`] 可按开关保留/关闭内置表、注入
//! 自定义域名/IP 子网/端口映射（自定义条目优先于内置表）。典型用法见
//! [`GuessEngineBuilder`] 文档示例。

pub mod domain;
pub mod info;
pub mod ip;
pub mod port;

pub use info::DomainInfo;
pub use info::GuessContext;

use crate::core::types::{Application, Confidence, DetectionResult, Protocol};

/// 猜测引擎
///
/// 默认（[`GuessEngine::new`]）启用全部内置表。通过 [`GuessEngine::builder()`]
/// 可关闭内置表或注入自定义映射；引擎构建为一次性成本，Detect 层长期持有复用
/// （域名表背后是 aho-corasick 自动机，不应逐包重建）。
pub struct GuessEngine {
    ip_matcher: Option<ip::IpMatcher>,
    domain_matcher: Option<domain::DomainMatcher>,
    /// 自定义端口映射（优先于内置端口表）
    custom_ports: Vec<(u16, Protocol)>,
    /// 是否启用内置端口表
    builtin_ports: bool,
}

impl GuessEngine {
    /// 创建默认猜测引擎（含内置 IP 子网表和域名映射表）
    pub fn new() -> Self {
        Self {
            ip_matcher: Some(ip::IpMatcher::new(ip::builtin_subnets())),
            domain_matcher: Some(domain::DomainMatcher::from_entries(
                &domain::domain_protocol_entries(),
            )),
            custom_ports: Vec::new(),
            builtin_ports: true,
        }
    }

    /// 创建可配置的猜测引擎构建器
    pub fn builder() -> GuessEngineBuilder {
        GuessEngineBuilder::default()
    }

    /// 执行猜测链路：域名 → IP → 端口
    pub fn guess(&self, ctx: &GuessContext) -> Option<DetectionResult> {
        self.match_domain(ctx)
            .or_else(|| self.match_ip(ctx))
            .or_else(|| self.match_port(ctx.dst_port))
    }

    fn match_domain(&self, ctx: &GuessContext) -> Option<DetectionResult> {
        let matcher = self.domain_matcher.as_ref()?;
        let domain = ctx
            .domain_info
            .sni
            .as_deref()
            .or(ctx.domain_info.http_host.as_deref())
            .or(ctx.domain_info.dns_query.as_deref())?;

        matcher
            .match_domain(domain)
            .map(|m| DetectionResult::new(m.protocol).with_confidence(Confidence::DpiPartial))
    }

    fn match_ip(&self, ctx: &GuessContext) -> Option<DetectionResult> {
        let matcher = self.ip_matcher.as_ref()?;
        // R4：服务端 IP 可能在当前包的 dst（client→server）或 src（server→client）
        // 任一方向，两方向都尝试；同时命中时 dst 优先。
        ctx.dst_ip
            .and_then(|ip| matcher.match_ip(ip))
            .or_else(|| ctx.src_ip.and_then(|ip| matcher.match_ip(ip)))
    }

    fn match_port(&self, port: u16) -> Option<DetectionResult> {
        // 自定义端口表优先（线性表条目数很小）
        if let Some((_, p)) = self.custom_ports.iter().find(|(pt, _)| *pt == port) {
            return Some(DetectionResult::new(*p).with_confidence(Confidence::MatchByPort));
        }
        if self.builtin_ports {
            port::match_port(port)
        } else {
            None
        }
    }
}

impl Default for GuessEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// 猜测引擎构建器
///
/// 三级匹配链（域名 → IP → 端口）均可独立关闭或扩展：
/// - `with_builtin_*`：开关内置表（默认全部启用）
/// - `with_custom_*`：注入自定义条目。语义：
///   - 域名：与内置表合并构建，**相同域名字符串时自定义覆盖内置**；
///   - IP 子网：与内置表合并，参与最长前缀匹配；
///   - 端口：自定义表先于内置表查询。
///
/// # Examples
///
/// ```
/// use rdpi::core::guess::GuessEngine;
/// use rdpi::core::types::Protocol;
///
/// // 仅保留内置端口回退，注入自定义端口映射
/// let engine = GuessEngine::builder()
///     .with_builtin_domains(false)
///     .with_builtin_ips(false)
///     .with_custom_ports(vec![(9000, Protocol::Other(9000))])
///     .build();
///
/// let ctx = rdpi::core::guess::GuessContext::new(9000);
/// let r = engine.guess(&ctx).expect("custom port matches");
/// assert_eq!(r.confidence, rdpi::core::types::Confidence::MatchByPort);
/// ```
#[derive(Default)]
pub struct GuessEngineBuilder {
    builtin_domains: bool,
    builtin_ips: bool,
    builtin_ports: bool,
    custom_domains: Vec<(&'static str, Protocol, Option<Application>)>,
    custom_subnets: Vec<ip::IpSubnetEntry>,
    custom_ports: Vec<(u16, Protocol)>,
}

impl GuessEngineBuilder {
    /// 是否启用内置域名映射表（默认 true）
    pub fn with_builtin_domains(mut self, enabled: bool) -> Self {
        self.builtin_domains = enabled;
        self
    }

    /// 是否启用内置 IP 子网表（默认 true）
    pub fn with_builtin_ips(mut self, enabled: bool) -> Self {
        self.builtin_ips = enabled;
        self
    }

    /// 是否启用内置端口表（默认 true）
    pub fn with_builtin_ports(mut self, enabled: bool) -> Self {
        self.builtin_ports = enabled;
        self
    }

    /// 追加自定义域名映射（相同域名字符串覆盖内置条目）
    pub fn with_custom_domains(
        mut self,
        entries: Vec<(&'static str, Protocol, Option<Application>)>,
    ) -> Self {
        self.custom_domains.extend(entries);
        self
    }

    /// 追加自定义 IP 子网条目（与内置表合并，最长前缀优先）
    pub fn with_custom_subnets(mut self, entries: Vec<ip::IpSubnetEntry>) -> Self {
        self.custom_subnets.extend(entries);
        self
    }

    /// 注入自定义端口映射（先于内置端口表查询）
    pub fn with_custom_ports(mut self, entries: Vec<(u16, Protocol)>) -> Self {
        self.custom_ports.extend(entries);
        self
    }

    /// 构建猜测引擎
    pub fn build(self) -> GuessEngine {
        // 域名：内置 + 自定义合并，自定义按域名字符串覆盖内置
        let domain_matcher = if self.builtin_domains || !self.custom_domains.is_empty() {
            let mut entries: Vec<(&'static str, Protocol, Option<Application>)> =
                if self.builtin_domains {
                    domain::domain_protocol_entries()
                } else {
                    Vec::new()
                };
            for (dom, proto, app) in self.custom_domains {
                // 覆盖同名内置条目（线性查找，表很小且仅构建一次）
                if let Some(slot) = entries.iter_mut().find(|(d, _, _)| *d == dom) {
                    *slot = (dom, proto, app);
                } else {
                    entries.push((dom, proto, app));
                }
            }
            if entries.is_empty() {
                None
            } else {
                Some(domain::DomainMatcher::from_entries(&entries))
            }
        } else {
            None
        };

        // IP：内置 + 自定义合并（IpMatcher::new 内部按最长前缀排序）
        let ip_matcher = if self.builtin_ips || !self.custom_subnets.is_empty() {
            let mut subnets = if self.builtin_ips {
                ip::builtin_subnets()
            } else {
                Vec::new()
            };
            subnets.extend(self.custom_subnets);
            if subnets.is_empty() {
                None
            } else {
                Some(ip::IpMatcher::new(subnets))
            }
        } else {
            None
        };

        GuessEngine {
            ip_matcher,
            domain_matcher,
            custom_ports: self.custom_ports,
            builtin_ports: self.builtin_ports,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// R4：dst_ip 命中时优先于 src_ip
    #[test]
    fn dst_ip_takes_priority_over_src_ip() {
        let engine = GuessEngine::new();
        let mut ctx = GuessContext::new(9999);
        ctx.dst_ip = Some("1.1.1.1".parse::<IpAddr>().unwrap()); // Dns
        ctx.src_ip = Some("8.8.8.8".parse::<IpAddr>().unwrap()); // Dns
        let r = engine.guess(&ctx).expect("dst_ip 1.1.1.1 matches");
        assert_eq!(r.protocol, crate::core::types::Protocol::Dns);
    }

    /// R4：dst_ip 不在 IP 表时回退到 src_ip（服务端在 src 方向）
    #[test]
    fn src_ip_used_when_dst_ip_misses() {
        let engine = GuessEngine::new();
        let mut ctx = GuessContext::new(9999);
        ctx.dst_ip = Some("10.0.0.1".parse::<IpAddr>().unwrap()); // 不在表内
        ctx.src_ip = Some("8.8.8.8".parse::<IpAddr>().unwrap()); // Dns
        let r = engine.guess(&ctx).expect("src_ip 8.8.8.8 matches");
        assert_eq!(r.protocol, crate::core::types::Protocol::Dns);
    }

    // ==== 可配置化测试 ====

    #[test]
    fn builder_custom_port_matches() {
        let engine = GuessEngine::builder()
            .with_custom_ports(vec![(9000, Protocol::Other(9000))])
            .build();
        let r = engine.guess(&GuessContext::new(9000)).expect("custom port");
        assert_eq!(r.protocol, Protocol::Other(9000));
        assert_eq!(r.confidence, Confidence::MatchByPort);
    }

    #[test]
    fn builder_custom_port_takes_priority_over_builtin() {
        // 自定义条目先于内置表：同一端口返回自定义协议
        let engine = GuessEngine::builder()
            .with_custom_ports(vec![(80, Protocol::Other(1))])
            .build();
        let r = engine.guess(&GuessContext::new(80)).expect("port 80");
        assert_eq!(r.protocol, Protocol::Other(1));
    }

    #[test]
    fn builder_disable_builtin_ports() {
        let engine = GuessEngine::builder().with_builtin_ports(false).build();
        assert!(engine.guess(&GuessContext::new(80)).is_none());
        assert!(engine.guess(&GuessContext::new(22)).is_none());
    }

    #[test]
    fn builder_disable_builtin_domains_keeps_custom() {
        let engine = GuessEngine::builder()
            .with_builtin_domains(false)
            .with_custom_domains(vec![("myapp.internal", Protocol::Mysql, None)])
            .build();
        let mut ctx = GuessContext::new(1);
        ctx.domain_info.sni = Some("myapp.internal".to_string());
        let r = engine.guess(&ctx).expect("custom domain");
        assert_eq!(r.protocol, Protocol::Mysql);
        assert_eq!(r.confidence, Confidence::DpiPartial);

        // 内置域名表已关闭
        let mut ctx2 = GuessContext::new(1);
        ctx2.domain_info.sni = Some("www.google.com".to_string());
        assert!(engine.guess(&ctx2).is_none());
    }

    #[test]
    fn builder_custom_domain_overrides_builtin() {
        // 相同域名字符串：自定义覆盖内置（google.com 内置为 Http/Google）
        let engine = GuessEngine::builder()
            .with_custom_domains(vec![("google.com", Protocol::Mysql, None)])
            .build();
        let mut ctx = GuessContext::new(1);
        ctx.domain_info.sni = Some("www.google.com".to_string());
        let r = engine.guess(&ctx).expect("override entry");
        assert_eq!(r.protocol, Protocol::Mysql);
    }

    #[test]
    fn builder_disable_builtin_ips_keeps_custom() {
        let engine = GuessEngine::builder()
            .with_builtin_ips(false)
            .with_custom_subnets(vec![ip::IpSubnetEntry {
                network: "10.77.0.0".parse::<IpAddr>().unwrap(),
                prefix_len: 16,
                protocol: Protocol::Mysql,
                application: None,
            }])
            .build();
        let mut ctx = GuessContext::new(1);
        ctx.dst_ip = Some("10.77.1.2".parse::<IpAddr>().unwrap());
        let r = engine.guess(&ctx).expect("custom subnet");
        assert_eq!(r.protocol, Protocol::Mysql);
        assert_eq!(r.confidence, Confidence::MatchByIp);

        // 内置子网表已关闭（1.1.1.1 内置为 Dns）
        let mut ctx2 = GuessContext::new(1);
        ctx2.dst_ip = Some("1.1.1.1".parse::<IpAddr>().unwrap());
        assert!(engine.guess(&ctx2).is_none());
    }

    #[test]
    fn builder_all_disabled_yields_no_match() {
        let engine = GuessEngine::builder()
            .with_builtin_domains(false)
            .with_builtin_ips(false)
            .with_builtin_ports(false)
            .build();
        let mut ctx = GuessContext::new(12345);
        ctx.dst_ip = Some("1.1.1.1".parse::<IpAddr>().unwrap());
        ctx.domain_info.sni = Some("google.com".to_string());
        assert!(engine.guess(&ctx).is_none());
    }
}
