//! 检测猜测引擎
//!
//! 当 DPI 无法识别协议时，依次尝试域名匹配 → IP 子网 → 端口回退。

pub mod domain;
pub mod info;
pub mod ip;
pub mod port;

pub use info::DomainInfo;
pub use info::GuessContext;

use crate::core::types::{Confidence, DetectionResult};

/// 猜测引擎
pub struct GuessEngine {
    ip_matcher: Option<ip::IpMatcher>,
    domain_matcher: Option<domain::DomainMatcher>,
}

impl GuessEngine {
    /// 创建默认猜测引擎（含内置 IP 子网表和域名映射表）
    pub fn new() -> Self {
        Self {
            ip_matcher: Some(ip::IpMatcher::new(ip::builtin_subnets())),
            domain_matcher: Some(domain::DomainMatcher::from_entries(
                &domain::domain_protocol_entries(),
            )),
        }
    }

    /// 执行猜测链路：域名 → IP → 端口
    pub fn guess(&self, ctx: &GuessContext) -> Option<DetectionResult> {
        self.match_domain(ctx)
            .or_else(|| self.match_ip(ctx))
            .or_else(|| port::match_port(ctx.dst_port))
    }

    fn match_domain(&self, ctx: &GuessContext) -> Option<DetectionResult> {
        let matcher = self.domain_matcher.as_ref()?;
        let domain = ctx
            .domain_info
            .sni
            .as_deref()
            .or_else(|| ctx.domain_info.http_host.as_deref())
            .or_else(|| ctx.domain_info.dns_query.as_deref())?;

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
}

impl Default for GuessEngine {
    fn default() -> Self {
        Self::new()
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
}
