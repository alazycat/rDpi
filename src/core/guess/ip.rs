//! IP 子网匹配
//!
//! 通过已知服务 IP 段推断协议，适用于云服务和 CDN 流量。

use std::net::{IpAddr, Ipv4Addr};
use crate::core::types::{Application, Confidence, DetectionResult, Protocol};

/// IP 子网条目
#[derive(Debug, Clone)]
pub(crate) struct IpSubnetEntry {
    pub network: IpAddr,
    pub prefix_len: u8,
    pub protocol: Protocol,
    pub application: Option<Application>,
}

/// IP 子网匹配器
pub(crate) struct IpMatcher {
    /// 按 (network ASC, prefix_len DESC) 排序
    entries: Vec<IpSubnetEntry>,
}

impl IpMatcher {
    /// 从条目构建匹配器（自动排序）
    pub fn new(entries: Vec<IpSubnetEntry>) -> Self {
        let mut entries = entries;
        entries.sort_by(|a, b| match a.network.cmp(&b.network) {
            std::cmp::Ordering::Equal => b.prefix_len.cmp(&a.prefix_len),
            other => other,
        });
        Self { entries }
    }

    /// 匹配 IP 地址，返回最长前缀匹配的协议
    pub fn match_ip(&self, ip: IpAddr) -> Option<DetectionResult> {
        match ip {
            IpAddr::V4(v4) => self.match_v4(v4),
            IpAddr::V6(_) => None, // IPv6 暂不实现
        }
    }

    fn match_v4(&self, ip: Ipv4Addr) -> Option<DetectionResult> {
        let ip_bits = u32::from(ip);
        let idx = self
            .entries
            .partition_point(|e| match e.network {
                IpAddr::V4(net) => u32::from(net) <= ip_bits,
                IpAddr::V6(_) => true,
            });

        for i in (0..=idx.saturating_sub(1)).rev() {
            let entry = &self.entries[i];
            if let IpAddr::V4(net) = entry.network {
                let mask = if entry.prefix_len == 0 {
                    0u32
                } else {
                    !0u32 << (32 - entry.prefix_len)
                };
                if (u32::from(ip) & mask) == (u32::from(net) & mask) {
                    let result = DetectionResult::new(entry.protocol)
                        .with_confidence(Confidence::MatchByIp);
                    return Some(result);
                }
            }
        }
        None
    }
}

fn entry_v4(
    ip_str: &str,
    prefix_len: u8,
    protocol: Protocol,
    app: Option<Application>,
) -> IpSubnetEntry {
    let ip: Ipv4Addr = ip_str.parse().expect("valid IPv4");
    IpSubnetEntry {
        network: IpAddr::V4(ip),
        prefix_len,
        protocol,
        application: app,
    }
}

/// 内置 IP 子网映射表（第一阶段：主要云/CDN 服务）
pub(crate) fn builtin_subnets() -> Vec<IpSubnetEntry> {
    vec![
        // Google
        entry_v4("142.250.0.0", 15, Protocol::Http, Some(Application::Google)),
        entry_v4("172.217.0.0", 16, Protocol::Http, Some(Application::Google)),
        entry_v4("74.125.0.0", 16, Protocol::Http, Some(Application::Google)),
        entry_v4("64.233.160.0", 19, Protocol::Http, Some(Application::Google)),
        entry_v4("8.8.8.0", 24, Protocol::Dns, None),
        entry_v4("8.8.4.0", 24, Protocol::Dns, None),
        // Cloudflare
        entry_v4("104.16.0.0", 12, Protocol::Tls, None),
        entry_v4("1.1.1.0", 24, Protocol::Dns, None),
        // Microsoft
        entry_v4("13.64.0.0", 11, Protocol::Tls, None),
        // Amazon CloudFront
        entry_v4("52.84.0.0", 15, Protocol::Tls, None),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_matcher() -> IpMatcher {
        IpMatcher::new(builtin_subnets())
    }

    #[test]
    fn test_match_google_ip() {
        let matcher = test_matcher();
        let ip: IpAddr = "142.250.80.1".parse().unwrap();
        let result = matcher.match_ip(ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, Protocol::Http);
    }

    #[test]
    fn test_match_google_dns() {
        let matcher = test_matcher();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let result = matcher.match_ip(ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, Protocol::Dns);
    }

    #[test]
    fn test_no_match() {
        let matcher = test_matcher();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(matcher.match_ip(ip).is_none());
    }

    #[test]
    fn test_ip_confidence() {
        let matcher = test_matcher();
        let ip: IpAddr = "142.250.80.1".parse().unwrap();
        let result = matcher.match_ip(ip).unwrap();
        assert_eq!(result.confidence, Confidence::MatchByIp);
    }

    #[test]
    fn test_different_subnet() {
        let matcher = test_matcher();
        let ip: IpAddr = "13.64.100.1".parse().unwrap(); // Microsoft
        let result = matcher.match_ip(ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, Protocol::Tls);
    }
}
